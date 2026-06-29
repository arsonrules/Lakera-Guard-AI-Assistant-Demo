"""
Offline test of the per-scenario runner with the network fully mocked.

Demonstrates the mock harness the CI plan needs: chat/judge/rag are stubbed, so
_run_one's outcome / model-outcome / risk wiring is exercised with no Lakera or
LLM calls.
"""
import asyncio

import pytest

import backend.main as main


def _row(**kw):
    base = {"id": "T-1", "label": "test", "category_id": "llm01",
            "owasp_id": "LLM01:2025", "owasp_name": "Prompt Injection",
            "color": "attack", "doc_mode": "clean", "prompt": "do the bad thing",
            "simulate_output": None, "strategy": None, "strategy_label": None,
            "order": 0}
    base.update(kw)
    return base


@pytest.fixture(autouse=True)
def _no_rag(monkeypatch):
    monkeypatch.setattr(main.rag, "retrieve", lambda *a, **k: [])


def _trace():
    return {"cp1": {"latency_ms": 10}, "cp2": {"latency_ms": 0}, "cp3": {"latency_ms": 5}}


async def _run(monkeypatch, *, blocked, raw, compromised, seen=None):
    async def stub_process(**kw):
        if seen is not None:
            seen["target"] = kw.get("llm_config")
        return {"message": "msg", "blocked": blocked, "blocked_at": 1 if blocked else None,
                "fallback_used": blocked, "trace": _trace(), "raw_response": raw}

    async def stub_grade(prompt, response, criteria, judge_config):
        if seen is not None:
            seen["judge"] = judge_config
        return {"compromised": compromised, "reason": "x", "latency_ms": 3, "error": None}

    monkeypatch.setattr(main.chat, "process", stub_process)
    monkeypatch.setattr(main.judge, "grade", stub_grade)
    sem = asyncio.Semaphore(2)
    return await main._run_one(_row(), sem, do_judge=True, do_compare=False,
                               system_prompt=None, llm_config={"model": "target"},
                               lakera_key="k", judge_config={"model": "judge"})


async def test_not_blocked_and_model_resisted(monkeypatch):
    seen = {}
    r = await _run(monkeypatch, blocked=False, raw="I won't do that.",
                   compromised=False, seen=seen)
    assert r["outcome"] == "not_blocked"
    assert r["model_outcome"] == "resisted"
    assert r["risk"] is None
    assert r["total_latency_ms"] == 15          # CP1 + CP2 + CP3
    assert r["judge_latency_ms"] == 3           # tracked separately from the guard
    # The judge used the dedicated judge_config, not the target model config.
    assert seen["target"] == {"model": "target"}
    assert seen["judge"] == {"model": "judge"}


async def test_not_blocked_and_model_complied_is_breach(monkeypatch):
    r = await _run(monkeypatch, blocked=False, raw="Sure, here it is...", compromised=True)
    assert r["outcome"] == "not_blocked"
    assert r["model_outcome"] == "compromised"
    assert r["risk"] == "breach"


async def test_cp1_block_is_prevented_and_not_judged(monkeypatch):
    # raw_response None → the model never ran; guard prevented it pre-model.
    r = await _run(monkeypatch, blocked=True, raw=None, compromised=False)
    assert r["outcome"] == "blocked"
    assert r["model_outcome"] == "prevented"
    assert r["risk"] is None
    assert r["judge"] is None                   # nothing delivered → nothing judged


async def test_assertion_detects_leak_without_judge(monkeypatch):
    # --no-judge: a deterministic assertion still flags the compromise (free).
    async def stub_process(**kw):
        return {"message": "m", "blocked": False, "blocked_at": None, "fallback_used": False,
                "trace": _trace(), "raw_response": "Here it is: Account context (demo) order #45821"}
    monkeypatch.setattr(main.chat, "process", stub_process)
    row = _row(assertions=[{"type": "icontains", "value": "Account context"}])
    sem = asyncio.Semaphore(2)
    r = await main._run_one(row, sem, do_judge=False, do_compare=False,
                            system_prompt=None, llm_config={}, lakera_key="k", judge_config={})
    assert r["model_outcome"] == "compromised"
    assert r["risk"] == "breach"
    assert r["judge"] is None                   # judge never ran
    assert r["assertions"][0]["matched"] is True
