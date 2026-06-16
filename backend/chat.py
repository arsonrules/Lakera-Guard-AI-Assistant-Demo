"""
Orchestrates the full Lakera Guard flow:

  CP0 → system prompt scan  → called once when prompt is uploaded (not per-message)
  CP1 → user input          → BLOCK if flagged, else continue
  CP2 → each RAG document   → REDACT flagged docs, continue with clean ones
  CP3 → LLM output          → BLOCK if flagged, else deliver to user
"""

from backend import lakera, llm, rag
from backend.config import settings


class LakeraNotConfigured(RuntimeError):
    """Raised when a checkpoint is reached but no Lakera Guard key is set."""


async def scan_system_prompt(text: str, lakera_key: str) -> dict:
    """
    CP0: run Lakera Guard on a candidate system prompt before it is activated.
    Returns the full Lakera response plus a summary for the UI.
    """
    if not lakera_key:
        raise LakeraNotConfigured()
    result = await lakera.check(text, lakera_key)
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


async def _call_llm(
    message: str,
    context_docs: list[str],
    simulate_output: str | None,
    system_prompt: str | None,
    llm_config: dict | None,
) -> str:
    if simulate_output:
        return simulate_output
    cfg = llm_config or {}
    return await llm.complete(
        message, context_docs,
        provider=cfg.get("provider", llm.DEFAULT_PROVIDER),
        base_url=cfg.get("base_url", llm.preset(llm.DEFAULT_PROVIDER)["base_url"]),
        api_key=cfg.get("api_key", settings.openrouter_api_key),
        model=cfg.get("model", settings.openrouter_model),
        system_prompt=system_prompt,
    )


async def process_unguarded(
    message: str,
    doc_mode: str,
    simulate_output: str | None = None,
    system_prompt: str | None = None,
    llm_config: dict | None = None,
) -> dict:
    """
    The SAME request with Lakera Guard switched OFF: no CP1/CP2/CP3, all retrieved
    documents (including poisoned ones) reach the model unredacted. Used by the
    one-shot "Guard ON vs OFF" comparison to show what the model does on its own.
    """
    trace = _empty_trace()
    for cp in ("cp1", "cp2", "cp3"):
        trace[cp]["status"] = "off"

    docs = rag.retrieve(message, mode=doc_mode)
    context = [d["content"] for d in docs]
    trace["cp2"].update(docs_checked=len(docs), docs_passed=[d["filename"] for d in docs])

    response_text = await _call_llm(message, context, simulate_output, system_prompt, llm_config)
    return {
        "message": response_text,
        "blocked": False,
        "blocked_at": None,
        "fallback_used": False,
        "guard_enabled": False,
        "trace": trace,
        "raw_response": response_text,
    }


async def process(
    message: str,
    doc_mode: str,
    simulate_output: str | None = None,
    system_prompt: str | None = None,
    llm_config: dict | None = None,
    lakera_key: str = "",
) -> dict:
    if not lakera_key:
        raise LakeraNotConfigured()
    trace = _empty_trace()

    # ── Checkpoint 1: user input ────────────────────────────────────────────
    cp1 = await lakera.check(message, lakera_key)
    trace["cp1"]["latency_ms"] = cp1["latency_ms"]

    if lakera.is_flagged(cp1):
        trace["cp1"].update(status="blocked", flagged=True, categories=lakera.flagged_categories(cp1))
        trace["cp2"]["status"] = "skipped"
        trace["cp3"]["status"] = "skipped"
        # raw_response stays None: the model never ran, so the attack was prevented
        # before it could reach (or compromise) the LLM.
        return _blocked(1, FALLBACK_CP1, trace, raw_response=None)

    trace["cp1"].update(status="passed", flagged=False)

    # ── Checkpoint 2: RAG documents ─────────────────────────────────────────
    docs = rag.retrieve(message, mode=doc_mode)
    clean_docs: list[str] = []
    cp2_latency = 0
    flagged_names: list[str] = []
    passed_names: list[str] = []
    all_cp2_categories: list[str] = []

    for doc in docs:
        cp2 = await lakera.check(doc["content"], lakera_key)
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
    response_text = await _call_llm(message, clean_docs, simulate_output, system_prompt, llm_config)

    # ── Checkpoint 3: LLM output ────────────────────────────────────────────
    cp3 = await lakera.check(response_text, lakera_key)
    trace["cp3"]["latency_ms"] = cp3["latency_ms"]

    if lakera.is_flagged(cp3):
        trace["cp3"].update(status="blocked", flagged=True, categories=lakera.flagged_categories(cp3))
        # The model DID produce this response; CP3 caught it before delivery.
        # Surface it (internally) so a judge can tell whether it was a "guard save".
        return _blocked(3, FALLBACK_CP3, trace, raw_response=response_text)

    trace["cp3"].update(status="passed", flagged=False)

    return {
        "message": response_text,
        "blocked": False,
        "blocked_at": None,
        "fallback_used": False,
        "trace": trace,
        "raw_response": response_text,
    }


def _blocked(checkpoint: int, message: str, trace: dict, raw_response: str | None = None) -> dict:
    return {
        "message": message,
        "blocked": True,
        "blocked_at": checkpoint,
        "fallback_used": True,
        "trace": trace,
        "raw_response": raw_response,
    }
