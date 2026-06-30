"""Offline tests for transient-error classification + per-scenario retry."""
import asyncio

import httpx
import pytest

import backend.main as main


def _http_error(status: int) -> httpx.HTTPStatusError:
    req = httpx.Request("POST", "http://x/api")
    resp = httpx.Response(status, request=req)
    return httpx.HTTPStatusError("boom", request=req, response=resp)


def test_is_transient_classification():
    assert main._is_transient(_http_error(429)) is True
    assert main._is_transient(_http_error(503)) is True
    assert main._is_transient(_http_error(404)) is False     # config error → don't retry
    assert main._is_transient(_http_error(401)) is False
    assert main._is_transient(httpx.ConnectTimeout("t")) is True
    assert main._is_transient(ValueError("nope")) is False


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    async def nosleep(*a, **k):
        return None
    monkeypatch.setattr(main.asyncio, "sleep", nosleep)   # keep retries instant


def _seq(outcomes):
    it = iter(outcomes)
    async def stub(*a, **k):
        o = next(it)
        if o == "transient":
            return {"outcome": "error", "error_transient": True, "error": "429"}
        if o == "permanent":
            return {"outcome": "error", "error_transient": False, "error": "404"}
        return {"outcome": "blocked"}
    return stub


async def _resilient(monkeypatch, outcomes):
    monkeypatch.setattr(main, "_run_one", _seq(outcomes))
    sem = asyncio.Semaphore(1)
    return await main._run_one_resilient({}, sem, True, False, None,
                                         llm_config={}, lakera_key="k", judge_config={})


async def test_transient_then_success(monkeypatch):
    r = await _resilient(monkeypatch, ["transient", "blocked"])
    assert r["outcome"] == "blocked"
    assert r["attempts"] == 2


async def test_gives_up_after_retries(monkeypatch):
    r = await _resilient(monkeypatch, ["transient"] * (main.ONESHOT_RETRIES + 2))
    assert r["outcome"] == "error"
    assert r["attempts"] == main.ONESHOT_RETRIES + 1     # initial + all retries


async def test_permanent_error_not_retried(monkeypatch):
    r = await _resilient(monkeypatch, ["permanent", "blocked"])
    assert r["outcome"] == "error"
    assert r["attempts"] == 1                            # no retry on a config error


async def test_success_first_try(monkeypatch):
    r = await _resilient(monkeypatch, ["blocked"])
    assert r["attempts"] == 1
