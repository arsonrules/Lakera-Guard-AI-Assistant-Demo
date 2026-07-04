"""Offline tests for the shared, connection-pooled Lakera HTTP client + the
raised one-shot concurrency cap."""
import backend.main as main
from backend import lakera


async def test_shared_client_is_reused():
    await lakera.aclose()                       # clean slate
    c1 = await lakera._get_client()
    c2 = await lakera._get_client()
    assert c1 is c2                             # same pooled client across calls
    assert not c1.is_closed
    # Pool sized comfortably above the max requestable concurrency.
    assert lakera._LIMITS.max_connections >= main.MAX_CONCURRENCY
    await lakera.aclose()
    assert lakera._client is None


async def test_get_client_recreates_after_close():
    await lakera.aclose()
    c1 = await lakera._get_client()
    await lakera.aclose()
    assert lakera._client is None
    c2 = await lakera._get_client()             # transparently reopened
    assert c2 is not c1 and not c2.is_closed
    await lakera.aclose()


def test_concurrency_cap_is_100():
    assert main.MAX_CONCURRENCY == 100
    assert main.OneShotRequest(concurrency=100).concurrency == 100


def test_concurrency_over_cap_is_rejected():
    import pytest
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        main.OneShotRequest(concurrency=main.MAX_CONCURRENCY + 1)
