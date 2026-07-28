"""Offline tests for the shared, connection-pooled LLM HTTP client.

A judged one-shot run makes 2+ model calls per scenario, so a fresh
`httpx.AsyncClient()` per call would mean a TLS handshake per call. These tests
lock in the pooling that `llm.py` shares with `lakera.py`.
"""
import asyncio

import backend.main as main
from backend import llm


async def test_shared_client_is_reused():
    await llm.aclose()                          # clean slate
    c1 = await llm._get_client()
    c2 = await llm._get_client()
    assert c1 is c2                             # same pooled client across calls
    assert not c1.is_closed
    # Pool sized comfortably above the max requestable concurrency.
    assert llm._LIMITS.max_connections >= main.MAX_CONCURRENCY
    await llm.aclose()
    assert llm._client is None


async def test_get_client_recreates_after_close():
    await llm.aclose()
    c1 = await llm._get_client()
    await llm.aclose()
    assert llm._client is None
    c2 = await llm._get_client()                # transparently reopened
    assert c2 is not c1 and not c2.is_closed
    await llm.aclose()


async def test_concurrent_first_use_creates_one_client():
    # The lock must stop a burst of concurrent first-callers each building a client.
    await llm.aclose()
    clients = await asyncio.gather(*[llm._get_client() for _ in range(20)])
    assert len({id(c) for c in clients}) == 1
    await llm.aclose()


async def test_aclose_is_idempotent():
    await llm.aclose()
    await llm.aclose()                          # must not raise on an already-closed pool
    assert llm._client is None


def test_no_per_call_clients_remain():
    """Regression: every request path must use the pooled client."""
    src = (main.pathlib.Path(llm.__file__)).read_text(encoding="utf-8")
    # Ignore comments — the module explains the anti-pattern in prose.
    code = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    # The only allowed construction is the one inside _get_client().
    assert code.count("httpx.AsyncClient(") == 1
    assert "async with httpx.AsyncClient()" not in code
