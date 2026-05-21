"""
Orchestrates the full Lakera Guard flow:

  CP0 → system prompt scan  → called once when prompt is uploaded (not per-message)
  CP1 → user input          → BLOCK if flagged, else continue
  CP2 → each RAG document   → REDACT flagged docs, continue with clean ones
  CP3 → LLM output          → BLOCK if flagged, else deliver to user
"""

from backend import lakera, llm, rag
from backend.config import settings

async def scan_system_prompt(text: str) -> dict:
    """
    CP0: run Lakera Guard on a candidate system prompt before it is activated.
    Returns the full Lakera response plus a summary for the UI.
    """
    result = await lakera.check(text, settings.lakera_guard_api_key)
    return {
        "flagged": lakera.is_flagged(result),
        "categories": lakera.flagged_categories(result),
        "latency_ms": result["latency_ms"],
    }


FALLBACK_CP1 = (
    "I'm unable to process this request. "
    "Our safety layer (Lakera Guard) flagged your message "
    "before any processing occurred."
)

FALLBACK_CP3 = (
    "I'm unable to deliver this response. "
    "Our safety layer (Lakera Guard) detected a policy violation "
    "in the generated reply before it reached you."
)


def _empty_trace() -> dict:
    return {
        "cp1": {"status": "pending", "flagged": None, "categories": [], "latency_ms": None},
        "cp2": {
            "status": "pending",
            "flagged": None,
            "categories": [],
            "latency_ms": None,
            "docs_checked": 0,
            "docs_flagged": [],
            "docs_passed": [],
        },
        "cp3": {"status": "pending", "flagged": None, "categories": [], "latency_ms": None},
    }


async def process(
    message: str,
    doc_mode: str,
    simulate_output: str | None = None,
    system_prompt: str | None = None,
) -> dict:
    trace = _empty_trace()

    # ── Checkpoint 1: user input ────────────────────────────────────────────
    cp1 = await lakera.check(message, settings.lakera_guard_api_key)
    trace["cp1"]["latency_ms"] = cp1["latency_ms"]

    if lakera.is_flagged(cp1):
        trace["cp1"].update(status="blocked", flagged=True, categories=lakera.flagged_categories(cp1))
        trace["cp2"]["status"] = "skipped"
        trace["cp3"]["status"] = "skipped"
        return _blocked(1, FALLBACK_CP1, trace)

    trace["cp1"].update(status="passed", flagged=False)

    # ── Checkpoint 2: RAG documents ─────────────────────────────────────────
    docs = rag.retrieve(message, mode=doc_mode)
    clean_docs: list[str] = []
    cp2_latency = 0
    flagged_names: list[str] = []
    passed_names: list[str] = []
    all_cp2_categories: list[str] = []

    for doc in docs:
        cp2 = await lakera.check(doc["content"], settings.lakera_guard_api_key)
        cp2_latency += cp2["latency_ms"]
        if lakera.is_flagged(cp2):
            flagged_names.append(doc["filename"])
            all_cp2_categories.extend(lakera.flagged_categories(cp2))
        else:
            clean_docs.append(doc["content"])
            passed_names.append(doc["filename"])

    trace["cp2"].update(
        latency_ms=cp2_latency,
        docs_checked=len(docs),
        docs_flagged=flagged_names,
        docs_passed=passed_names,
        categories=list(set(all_cp2_categories)),
    )

    if not docs:
        trace["cp2"]["status"] = "skipped"
    elif flagged_names:
        trace["cp2"].update(status="redacted", flagged=True)
    else:
        trace["cp2"].update(status="passed", flagged=False)

    # ── LLM call ────────────────────────────────────────────────────────────
    if simulate_output:
        response_text = simulate_output
    else:
        response_text = await llm.complete(
            message, clean_docs, settings.openrouter_api_key, settings.openrouter_model,
            system_prompt=system_prompt,
        )

    # ── Checkpoint 3: LLM output ────────────────────────────────────────────
    cp3 = await lakera.check(response_text, settings.lakera_guard_api_key)
    trace["cp3"]["latency_ms"] = cp3["latency_ms"]

    if lakera.is_flagged(cp3):
        trace["cp3"].update(status="blocked", flagged=True, categories=lakera.flagged_categories(cp3))
        return _blocked(3, FALLBACK_CP3, trace)

    trace["cp3"].update(status="passed", flagged=False)

    return {
        "message": response_text,
        "blocked": False,
        "blocked_at": None,
        "fallback_used": False,
        "trace": trace,
    }


def _blocked(checkpoint: int, message: str, trace: dict) -> dict:
    return {
        "message": message,
        "blocked": True,
        "blocked_at": checkpoint,
        "fallback_used": True,
        "trace": trace,
    }
