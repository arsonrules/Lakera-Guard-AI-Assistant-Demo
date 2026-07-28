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
