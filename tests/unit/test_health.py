"""HTTP-layer tests for the health probes, driven through the ASGI app itself
(httpx ASGITransport — no server, no network).

These are also the reference pattern for further endpoint tests: build a client
over `main.app` and assert on real status codes / payloads.
"""
import httpx
import pytest

from backend import main


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_healthz_is_always_ok(client, monkeypatch):
    """Liveness must not depend on configuration — an unconfigured process is
    still alive, and a probe that fails here would restart-loop the container."""
    monkeypatch.setattr(main, "_lakera_key", "")
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


async def test_readyz_ok_when_guard_key_present(client, monkeypatch):
    monkeypatch.setattr(main, "_lakera_key", "sk-secret-value")
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True and body["lakera_key_set"] is True


async def test_readyz_503_when_unconfigured(client, monkeypatch):
    """Readiness gates traffic: without a Guard key every checkpoint fails, so
    the orchestrator should keep the instance out of rotation."""
    monkeypatch.setattr(main, "_lakera_key", "")
    resp = await client.get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["ok"] is False


async def test_readyz_never_leaks_key_material(client, monkeypatch):
    secret = "sk-lakera-super-secret-do-not-leak"
    monkeypatch.setattr(main, "_lakera_key", secret)
    resp = await client.get("/readyz")
    assert secret not in resp.text


async def test_health_probes_bypass_csrf_middleware(client):
    """Probes are GETs, so the POST/DELETE origin check must not apply."""
    for path in ("/healthz", "/readyz"):
        resp = await client.get(path, headers={"Origin": "http://evil.example"})
        assert resp.status_code in (200, 503)      # never 403
