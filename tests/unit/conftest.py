"""Shared fixtures for the offline unit suite."""
import httpx
import pytest

from backend import main


@pytest.fixture
async def client():
    """HTTP client bound straight to the ASGI app — exercises routing, request
    validation, and middleware with no server and no network."""
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest.fixture(autouse=True)
def _no_access_token():
    """The token gate is opt-in; keep it off unless a test switches it on, and
    always restore it so one test can't leak a 401 into the next."""
    from backend.config import settings
    original = settings.demo_access_token
    settings.demo_access_token = ""
    yield
    settings.demo_access_token = original


@pytest.fixture(autouse=True)
def _no_ingest_scan():
    """
    Ingest scanning calls the LIVE Guard API, and conftest.py loads a real key
    from .env — so leaving it on would make this offline suite hit the network,
    which pytest.ini explicitly promises it never does.

    Off by default; the tests that exercise ingest scanning turn it on with a
    stubbed `lakera.check`.
    """
    original = main._scan_on_ingest
    main._scan_on_ingest = False
    yield
    main._scan_on_ingest = original
