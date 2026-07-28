"""
Orchestrates the full Lakera Guard flow:

  CP0 → system prompt scan  → called once when prompt is uploaded (not per-message)
  CP1 → user input          → BLOCK if flagged, else continue
  CP2 → each RAG document   → REDACT flagged docs, continue with clean ones
  CP3 → LLM output          → BLOCK if flagged, else deliver to user
"""

import asyncio

from backend import lakera, llm, rag
from backend.config import settings


class LakeraNotConfigured(RuntimeError):
    """Raised when a checkpoint is reached but no Lakera Guard key is set."""


def _cp_flags(checkpoints: dict | None) -> dict:
    """Normalize the per-checkpoint enablement config (all on by default)."""
    return {"cp1": True, "cp2": True, "cp3": True, **(checkpoints or {})}


def _cp_projects(project_id: str, overrides: dict | None) -> dict:
    """Resolve the Lakera Project ID each checkpoint scans under. A per-checkpoint
    override (when given) wins; otherwise the checkpoint uses the run-level
    `project_id`. Lets one run route CP1/CP2/CP3 to different Guard policies."""
    o = overrides or {}
    return {c: o.get(c, project_id) for c in ("cp1", "cp2", "cp3")}


async def scan_system_prompt(text: str, lakera_key: str, lakera_project_id: str = "") -> dict:
    """
    CP0: run Lakera Guard on a candidate system prompt before it is activated.
    Returns the full Lakera response plus a summary for the UI.
    """
    if not lakera_key:
        raise LakeraNotConfigured()
    result = await lakera.check(text, lakera_key, lakera_project_id)
    summary = lakera.results_summary(result)
    return {
        "flagged": lakera.is_flagged(result),
        "categories": lakera.flagged_categories(result),
        "detectors": summary["detectors"],          # L1–L5 per fired detector
        "flagged_count": summary["flagged_count"],
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
        "cp1": {"status": "pending", "flagged": None, "categories": [], "detectors": [],
                "flagged_count": 0, "latency_ms": None},
        "cp2": {
            "status": "pending",
            "flagged": None,
            "categories": [],
            "detectors": [],
            "flagged_count": 0,
            "latency_ms": None,
            "docs_checked": 0,
            "docs_flagged": [],
            "docs_passed": [],
        },
        "cp3": {"status": "pending", "flagged": None, "categories": [], "detectors": [],
                "flagged_count": 0, "latency_ms": None},
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
    lakera_project_id: str = "",
    checkpoints: dict | None = None,
    checkpoint_projects: dict | None = None,
    extra_context: list[str] | None = None,
) -> dict:
    if not lakera_key:
        raise LakeraNotConfigured()
    # Per-checkpoint enablement (all on by default). A disabled checkpoint is
    # skipped so the demo can show what gets through without that protection.
    cp = _cp_flags(checkpoints)
    proj = _cp_projects(lakera_project_id, checkpoint_projects)
    trace = _empty_trace()

    # ── Checkpoint 1: user input ────────────────────────────────────────────
    if not cp["cp1"]:
        trace["cp1"]["status"] = "disabled"
    else:
        cp1 = await lakera.check(message, lakera_key, proj["cp1"])
        s1 = lakera.results_summary(cp1)
        trace["cp1"].update(latency_ms=cp1["latency_ms"],
                            detectors=s1["detectors"], flagged_count=s1["flagged_count"])

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
    if not cp["cp2"]:
        # Skipped: every retrieved doc reaches the model unredacted.
        clean_docs = [doc["content"] for doc in docs]
        trace["cp2"].update(
            status="disabled",
            docs_checked=len(docs),
            docs_passed=[doc["filename"] for doc in docs],
        )
    else:
        clean_docs = []
        cp2_latency = 0
        flagged_names: list[str] = []
        passed_names: list[str] = []
        all_cp2_categories: list[str] = []
        all_cp2_detectors: list[dict] = []

        # Scan the retrieved documents concurrently — they're independent, and
        # doing them serially put one Guard round trip per document on the
        # critical path. gather preserves input order, so results still line up
        # with `docs` and the trace stays deterministic.
        results = await asyncio.gather(
            *(lakera.check(doc["content"], lakera_key, proj["cp2"]) for doc in docs)
        )
        for doc, cp2 in zip(docs, results):
            # Wall-clock, not the sum: these ran in parallel, so summing would
            # over-report the time CP2 actually added to the request.
            cp2_latency = max(cp2_latency, cp2["latency_ms"])
            all_cp2_detectors.extend(lakera.detector_results(cp2))   # L1–L5 across docs
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
            detectors=all_cp2_detectors,
            flagged_count=len(all_cp2_detectors),
        )

        if not docs:
            trace["cp2"]["status"] = "skipped"
        elif flagged_names:
            trace["cp2"].update(status="redacted", flagged=True)
        else:
            trace["cp2"].update(status="passed", flagged=False)

    # Append any CLI-supplied knowledge base as extra RAG context (clean mode when
    # None → clean_docs is unchanged, so the existing execution path is preserved).
    if extra_context:
        clean_docs = clean_docs + list(extra_context)

    # ── LLM call ────────────────────────────────────────────────────────────
    response_text = await _call_llm(message, clean_docs, simulate_output, system_prompt, llm_config)

    # ── Checkpoint 3: LLM output ────────────────────────────────────────────
    if not cp["cp3"]:
        trace["cp3"]["status"] = "disabled"
    else:
        cp3 = await lakera.check(response_text, lakera_key, proj["cp3"])
        s3 = lakera.results_summary(cp3)
        trace["cp3"].update(latency_ms=cp3["latency_ms"],
                            detectors=s3["detectors"], flagged_count=s3["flagged_count"])

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


# ── Agentic (tool-using) requests ────────────────────────────────────────────
# The model is offered fake tools; we record which it tries to call but never run
# them. Lakera scans the text (CP1 input, CP3 output) — it is blind to the
# structured tool call, which is exactly the defense-in-depth gap LLM06 is about.

async def process_agentic(
    message: str,
    tools: list[dict],
    doc_mode: str,
    system_prompt: str | None = None,
    llm_config: dict | None = None,
    lakera_key: str = "",
    lakera_project_id: str = "",
    checkpoints: dict | None = None,
    checkpoint_projects: dict | None = None,
) -> dict:
    if not lakera_key:
        raise LakeraNotConfigured()
    cp = _cp_flags(checkpoints)
    proj = _cp_projects(lakera_project_id, checkpoint_projects)
    trace = _empty_trace()

    if not cp["cp1"]:
        trace["cp1"]["status"] = "disabled"
    else:
        cp1 = await lakera.check(message, lakera_key, proj["cp1"])
        trace["cp1"]["latency_ms"] = cp1["latency_ms"]
        if lakera.is_flagged(cp1):
            trace["cp1"].update(status="blocked", flagged=True, categories=lakera.flagged_categories(cp1))
            trace["cp2"]["status"] = "skipped"
            trace["cp3"]["status"] = "skipped"
            return {**_blocked(1, FALLBACK_CP1, trace, raw_response=None), "tool_calls": []}
        trace["cp1"].update(status="passed", flagged=False)

    docs = rag.retrieve(message, mode=doc_mode)
    if not cp["cp2"]:
        clean = [doc["content"] for doc in docs]
        trace["cp2"].update(status="disabled", docs_checked=len(docs),
                            docs_passed=[doc["filename"] for doc in docs])
    else:
        clean, flagged_names, passed_names, cp2_lat = [], [], [], 0
        for doc in docs:
            cp2 = await lakera.check(doc["content"], lakera_key, proj["cp2"])
            cp2_lat += cp2["latency_ms"]
            (flagged_names if lakera.is_flagged(cp2) else passed_names).append(doc["filename"])
            if not lakera.is_flagged(cp2):
                clean.append(doc["content"])
        trace["cp2"].update(latency_ms=cp2_lat, docs_checked=len(docs),
                            docs_flagged=flagged_names, docs_passed=passed_names,
                            status=("skipped" if not docs else ("redacted" if flagged_names else "passed")))

    cfg = llm_config or {}
    messages = llm.build_messages([{"role": "user", "content": message}], clean, system_prompt)
    out = await llm.complete_with_tools(
        messages, tools,
        provider=cfg.get("provider", llm.DEFAULT_PROVIDER),
        base_url=cfg.get("base_url", llm.preset(llm.DEFAULT_PROVIDER)["base_url"]),
        api_key=cfg.get("api_key", settings.openrouter_api_key),
        model=cfg.get("model", settings.openrouter_model),
    )
    content, tool_calls = out["content"], out["tool_calls"]

    if not cp["cp3"]:
        trace["cp3"]["status"] = "disabled"
    else:
        cp3 = await lakera.check(content or "", lakera_key, proj["cp3"])
        trace["cp3"]["latency_ms"] = cp3["latency_ms"]
        if lakera.is_flagged(cp3):
            trace["cp3"].update(status="blocked", flagged=True, categories=lakera.flagged_categories(cp3))
            return {**_blocked(3, FALLBACK_CP3, trace, raw_response=content), "tool_calls": tool_calls}
        trace["cp3"].update(status="passed", flagged=False)

    return {"message": content, "blocked": False, "blocked_at": None, "fallback_used": False,
            "trace": trace, "raw_response": content, "tool_calls": tool_calls}


# ── Multi-turn (Crescendo-style) conversations ───────────────────────────────
# An attack spread across several turns: each escalates until the payload lands.
# Lakera CP1/CP3 run on EVERY turn, so the guard can catch the escalation at any
# point. The "delivered" response judged for compromise is the final turn's reply.

async def _llm_with_history(history: list[dict], context_docs: list[str],
                            system_prompt: str | None, llm_config: dict | None) -> str:
    cfg = llm_config or {}
    messages = llm.build_messages(history, context_docs, system_prompt)
    return await llm.complete_chat(
        messages,
        provider=cfg.get("provider", llm.DEFAULT_PROVIDER),
        base_url=cfg.get("base_url", llm.preset(llm.DEFAULT_PROVIDER)["base_url"]),
        api_key=cfg.get("api_key", settings.openrouter_api_key),
        model=cfg.get("model", settings.openrouter_model),
    )


async def process_multiturn(
    turns: list[str],
    doc_mode: str,
    system_prompt: str | None = None,
    llm_config: dict | None = None,
    lakera_key: str = "",
    lakera_project_id: str = "",
    checkpoints: dict | None = None,
    checkpoint_projects: dict | None = None,
) -> dict:
    """Run a multi-turn conversation through the full guard pipeline, turn by turn.
    A disabled checkpoint is skipped on every turn."""
    if not lakera_key:
        raise LakeraNotConfigured()
    cp = _cp_flags(checkpoints)
    proj = _cp_projects(lakera_project_id, checkpoint_projects)
    trace = _empty_trace()
    turn_log: list[dict] = []
    cp1_lat = cp2_lat = cp3_lat = 0
    docs_checked = 0
    history: list[dict] = []
    last_response: str | None = None

    for i, user_turn in enumerate(turns, 1):
        if cp["cp1"]:
            cp1 = await lakera.check(user_turn, lakera_key, proj["cp1"])
            cp1_lat += cp1["latency_ms"]
            if lakera.is_flagged(cp1):
                trace["cp1"].update(status="blocked", flagged=True,
                                    categories=lakera.flagged_categories(cp1), latency_ms=cp1_lat)
                trace["cp2"]["status"] = "skipped"
                trace["cp3"]["status"] = "skipped"
                turn_log.append({"turn": i, "user": user_turn, "blocked_at": "cp1"})
                trace["turns"] = turn_log
                return {"message": FALLBACK_CP1, "blocked": True, "blocked_at": 1,
                        "fallback_used": True, "trace": trace, "raw_response": None,
                        "blocked_turn": i}

        docs = rag.retrieve(user_turn, mode=doc_mode)
        clean: list[str] = []
        for d in docs:
            docs_checked += 1
            if not cp["cp2"]:
                clean.append(d["content"])          # unredacted — CP2 off
                continue
            cp2 = await lakera.check(d["content"], lakera_key, proj["cp2"])
            cp2_lat += cp2["latency_ms"]
            if not lakera.is_flagged(cp2):
                clean.append(d["content"])

        history.append({"role": "user", "content": user_turn})
        resp = await _llm_with_history(history, clean, system_prompt, llm_config)

        if cp["cp3"]:
            cp3 = await lakera.check(resp, lakera_key, proj["cp3"])
            cp3_lat += cp3["latency_ms"]
            if lakera.is_flagged(cp3):
                trace["cp3"].update(status="blocked", flagged=True,
                                    categories=lakera.flagged_categories(cp3), latency_ms=cp3_lat)
                trace["cp1"].update(status=("disabled" if not cp["cp1"] else "passed"), latency_ms=cp1_lat)
                turn_log.append({"turn": i, "user": user_turn,
                                 "assistant": resp[:600], "blocked_at": "cp3"})
                trace["turns"] = turn_log
                return {"message": FALLBACK_CP3, "blocked": True, "blocked_at": 3,
                        "fallback_used": True, "trace": trace, "raw_response": resp,
                        "blocked_turn": i}

        history.append({"role": "assistant", "content": resp})
        last_response = resp
        turn_log.append({"turn": i, "user": user_turn, "assistant": resp[:600]})

    trace["cp1"].update(status=("disabled" if not cp["cp1"] else "passed"),
                        flagged=False, latency_ms=(cp1_lat or None))
    if not cp["cp2"]:
        trace["cp2"].update(status="disabled", docs_checked=docs_checked)
    else:
        trace["cp2"].update(status="passed" if docs_checked else "skipped",
                            flagged=False, latency_ms=cp2_lat, docs_checked=docs_checked)
    trace["cp3"].update(status=("disabled" if not cp["cp3"] else "passed"),
                        flagged=False, latency_ms=(cp3_lat or None))
    trace["turns"] = turn_log
    return {"message": last_response, "blocked": False, "blocked_at": None,
            "fallback_used": False, "trace": trace, "raw_response": last_response,
            "blocked_turn": None}


async def process_multiturn_unguarded(
    turns: list[str],
    doc_mode: str,
    system_prompt: str | None = None,
    llm_config: dict | None = None,
) -> dict:
    """The same conversation with Lakera OFF — the model alone, all turns delivered."""
    trace = _empty_trace()
    for cp in ("cp1", "cp2", "cp3"):
        trace[cp]["status"] = "off"
    history: list[dict] = []
    turn_log: list[dict] = []
    last_response = None
    for i, user_turn in enumerate(turns, 1):
        docs = rag.retrieve(user_turn, mode=doc_mode)
        history.append({"role": "user", "content": user_turn})
        resp = await _llm_with_history(history, [d["content"] for d in docs],
                                       system_prompt, llm_config)
        history.append({"role": "assistant", "content": resp})
        last_response = resp
        turn_log.append({"turn": i, "user": user_turn, "assistant": resp[:600]})
    trace["turns"] = turn_log
    return {"message": last_response, "blocked": False, "blocked_at": None,
            "fallback_used": False, "guard_enabled": False, "trace": trace,
            "raw_response": last_response, "blocked_turn": None}
