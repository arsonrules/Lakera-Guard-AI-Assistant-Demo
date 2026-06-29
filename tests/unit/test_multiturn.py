"""Offline tests for the multi-turn (Crescendo) runner — Lakera + LLM mocked."""
import backend.chat as chat


def _lakera(flag_on_text=None, flag_kind="cp1"):
    """Return an async lakera.check stub that flags when text contains a marker."""
    async def _check(text, key):
        flagged = bool(flag_on_text and flag_on_text in text)
        return {"flagged": flagged, "latency_ms": 1,
                "breakdown": [{"detector_type": "prompt_attack", "detected": True}] if flagged else []}
    return _check


def _llm(responses):
    it = iter(responses)
    async def _complete_chat(messages, **kw):
        return next(it)
    return _complete_chat


async def test_all_turns_pass_returns_final_reply(monkeypatch):
    monkeypatch.setattr(chat.lakera, "check", _lakera())              # nothing flagged
    monkeypatch.setattr(chat.rag, "retrieve", lambda *a, **k: [])
    monkeypatch.setattr(chat.llm, "complete_chat", _llm(["r1", "r2", "r3 final"]))
    out = await chat.process_multiturn(["t1", "t2", "t3"], "clean", None, {}, "key")
    assert out["blocked"] is False
    assert out["raw_response"] == "r3 final"
    assert len(out["trace"]["turns"]) == 3


async def test_cp1_blocks_mid_conversation(monkeypatch):
    # The 2nd user turn trips CP1 → conversation stops, model never sees turn 2.
    monkeypatch.setattr(chat.lakera, "check", _lakera(flag_on_text="PAYLOAD"))
    monkeypatch.setattr(chat.rag, "retrieve", lambda *a, **k: [])
    monkeypatch.setattr(chat.llm, "complete_chat", _llm(["r1", "r2"]))
    out = await chat.process_multiturn(["benign", "PAYLOAD now", "t3"], "clean", None, {}, "key")
    assert out["blocked"] is True
    assert out["blocked_at"] == 1
    assert out["blocked_turn"] == 2
    assert out["raw_response"] is None          # model never ran on the blocked turn


async def test_cp3_blocks_on_output(monkeypatch):
    # CP1 clean, but the model's reply on turn 1 trips CP3.
    async def check(text, key):
        flagged = "LEAK" in text
        return {"flagged": flagged, "latency_ms": 1,
                "breakdown": [{"detector_type": "pii", "detected": True}] if flagged else []}
    monkeypatch.setattr(chat.lakera, "check", check)
    monkeypatch.setattr(chat.rag, "retrieve", lambda *a, **k: [])
    monkeypatch.setattr(chat.llm, "complete_chat", _llm(["here is the LEAK"]))
    out = await chat.process_multiturn(["t1"], "clean", None, {}, "key")
    assert out["blocked"] is True
    assert out["blocked_at"] == 3
    assert out["raw_response"] == "here is the LEAK"   # surfaced for the judge


async def test_unguarded_runs_all_turns(monkeypatch):
    monkeypatch.setattr(chat.rag, "retrieve", lambda *a, **k: [])
    monkeypatch.setattr(chat.llm, "complete_chat", _llm(["a", "b"]))
    out = await chat.process_multiturn_unguarded(["t1", "t2"], "clean", None, {})
    assert out["blocked"] is False and out["guard_enabled"] is False
    assert out["raw_response"] == "b"
