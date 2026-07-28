"""Offline tests for per-checkpoint enablement in chat.process — Lakera/LLM mocked."""
import backend.chat as chat


def _lakera(marker):
    """Async lakera.check stub that flags any text containing `marker`."""
    async def _check(text, key, project_id="", endpoint=""):
        flagged = marker in text
        return {"flagged": flagged, "latency_ms": 1,
                "breakdown": [{"detector_type": "prompt_attack", "detected": True}] if flagged else []}
    return _check


def _doc(name, content):
    return {"filename": name, "content": content}


async def test_all_checkpoints_on_by_default(monkeypatch):
    monkeypatch.setattr(chat.lakera, "check", _lakera("ATTACK"))
    monkeypatch.setattr(chat.rag, "retrieve", lambda *a, **k: [])
    monkeypatch.setattr(chat, "_call_llm", lambda *a, **k: _coro("clean reply"))
    out = await chat.process("hello", "clean", lakera_key="k")
    assert out["trace"]["cp1"]["status"] == "passed"
    assert out["trace"]["cp3"]["status"] == "passed"


async def test_cp1_disabled_lets_attack_input_through(monkeypatch):
    monkeypatch.setattr(chat.lakera, "check", _lakera("ATTACK"))
    monkeypatch.setattr(chat.rag, "retrieve", lambda *a, **k: [])
    monkeypatch.setattr(chat, "_call_llm", lambda *a, **k: _coro("clean reply"))
    out = await chat.process("this is an ATTACK", "clean", lakera_key="k",
                             checkpoints={"cp1": False})
    assert out["blocked"] is False
    assert out["trace"]["cp1"]["status"] == "disabled"
    assert out["trace"]["cp1"]["latency_ms"] is None      # no scan happened


async def test_cp1_enabled_blocks_attack_input(monkeypatch):
    monkeypatch.setattr(chat.lakera, "check", _lakera("ATTACK"))
    monkeypatch.setattr(chat.rag, "retrieve", lambda *a, **k: [])
    monkeypatch.setattr(chat, "_call_llm", lambda *a, **k: _coro("clean reply"))
    out = await chat.process("this is an ATTACK", "clean", lakera_key="k",
                             checkpoints={"cp1": True})
    assert out["blocked"] is True and out["blocked_at"] == 1


async def test_cp2_disabled_passes_docs_unredacted(monkeypatch):
    monkeypatch.setattr(chat.lakera, "check", _lakera("POISON"))
    monkeypatch.setattr(chat.rag, "retrieve",
                        lambda *a, **k: [_doc("bad.txt", "POISON here"), _doc("ok.txt", "fine")])
    captured = {}

    async def fake_llm(message, context_docs, *a, **k):
        captured["docs"] = context_docs
        return "reply"
    monkeypatch.setattr(chat, "_call_llm", fake_llm)

    out = await chat.process("q", "poisoned", lakera_key="k", checkpoints={"cp2": False})
    assert out["trace"]["cp2"]["status"] == "disabled"
    # Both docs (including the poisoned one) reached the model unredacted.
    assert captured["docs"] == ["POISON here", "fine"]


async def test_cp3_disabled_delivers_unscanned_output(monkeypatch):
    monkeypatch.setattr(chat.lakera, "check", _lakera("ATTACK"))
    monkeypatch.setattr(chat.rag, "retrieve", lambda *a, **k: [])
    monkeypatch.setattr(chat, "_call_llm", lambda *a, **k: _coro("ATTACK payload leaks"))
    out = await chat.process("hi", "clean", lakera_key="k", checkpoints={"cp3": False})
    assert out["blocked"] is False
    assert out["trace"]["cp3"]["status"] == "disabled"
    assert out["message"] == "ATTACK payload leaks"       # delivered despite the marker


async def test_extra_context_appended_to_llm_docs(monkeypatch):
    # --knowledge-base injection: extra_context is appended AFTER the retrieved
    # docs, and its absence (None) leaves the doc list exactly as before (clean path).
    monkeypatch.setattr(chat.lakera, "check", _lakera("NOPE"))
    monkeypatch.setattr(chat.rag, "retrieve", lambda *a, **k: [_doc("kb.txt", "retrieved doc")])
    captured = {}

    async def fake_llm(message, context_docs, *a, **k):
        captured["docs"] = context_docs
        return "reply"
    monkeypatch.setattr(chat, "_call_llm", fake_llm)

    # No extra_context → unchanged (only the retrieved doc).
    await chat.process("q", "clean", lakera_key="k")
    assert captured["docs"] == ["retrieved doc"]

    # With extra_context → appended after the retrieved doc.
    await chat.process("q", "clean", lakera_key="k",
                       extra_context=["KNOWLEDGE BASE CONTENT"])
    assert captured["docs"] == ["retrieved doc", "KNOWLEDGE BASE CONTENT"]


async def _coro(value):
    return value


# ── CP2 scans documents concurrently ─────────────────────────────────────────

async def test_cp2_scans_documents_in_parallel(monkeypatch):
    """Documents are independent; scanning them serially put one Guard round
    trip per document on the critical path."""
    import asyncio
    state = {"inflight": 0, "peak": 0}

    async def slow_check(text, key, project_id="", endpoint=""):
        state["inflight"] += 1
        state["peak"] = max(state["peak"], state["inflight"])
        await asyncio.sleep(0.02)
        state["inflight"] -= 1
        return {"flagged": False, "latency_ms": 20, "breakdown": []}

    monkeypatch.setattr(chat.lakera, "check", slow_check)
    monkeypatch.setattr(chat.rag, "retrieve",
                        lambda *a, **k: [_doc(f"d{i}.txt", f"doc {i}") for i in range(4)])
    monkeypatch.setattr(chat, "_call_llm", lambda *a, **k: _coro("reply"))

    out = await chat.process("q", "clean", lakera_key="k")
    assert state["peak"] == 4, f"CP2 ran serially (peak={state['peak']})"
    assert out["trace"]["cp2"]["docs_checked"] == 4


async def test_cp2_preserves_document_order_and_redaction(monkeypatch):
    """gather returns in input order — flagged/passed lists must still line up
    with the retrieved documents."""
    monkeypatch.setattr(chat.lakera, "check", _lakera("POISON"))
    monkeypatch.setattr(chat.rag, "retrieve", lambda *a, **k: [
        _doc("a.txt", "clean one"), _doc("b.txt", "POISON here"),
        _doc("c.txt", "clean two"), _doc("d.txt", "POISON again"),
    ])
    captured = {}

    async def fake_llm(message, context_docs, *a, **k):
        captured["docs"] = context_docs
        return "reply"
    monkeypatch.setattr(chat, "_call_llm", fake_llm)

    out = await chat.process("q", "poisoned", lakera_key="k")
    cp2 = out["trace"]["cp2"]
    assert cp2["docs_flagged"] == ["b.txt", "d.txt"]
    assert cp2["docs_passed"] == ["a.txt", "c.txt"]
    assert captured["docs"] == ["clean one", "clean two"]     # only clean docs reach the LLM
    assert cp2["status"] == "redacted"


async def test_cp2_latency_is_wall_clock_not_sum(monkeypatch):
    """Parallel scans must not report summed latency — that would over-state the
    time CP2 actually added to the request."""
    async def check(text, key, project_id="", endpoint=""):
        return {"flagged": False, "latency_ms": 30, "breakdown": []}

    monkeypatch.setattr(chat.lakera, "check", check)
    monkeypatch.setattr(chat.rag, "retrieve",
                        lambda *a, **k: [_doc(f"d{i}.txt", "x") for i in range(5)])
    monkeypatch.setattr(chat, "_call_llm", lambda *a, **k: _coro("reply"))

    out = await chat.process("q", "clean", lakera_key="k")
    assert out["trace"]["cp2"]["latency_ms"] == 30           # not 150
