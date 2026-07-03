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


async def _coro(value):
    return value
