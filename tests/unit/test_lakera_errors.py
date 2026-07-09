"""Guard-vs-LLM error attribution: a Lakera Guard HTTP error must surface as a
LakeraAPIError with an actionable message (region/key), not be mistaken for an
LLM-provider error."""
import httpx
import pytest

import backend.main as main
from backend import lakera


def _resp(status, *, json_body=None, text=None,
          url="https://eu-west-1.api.lakera.ai/v2/guard"):
    req = httpx.Request("POST", url)
    if json_body is not None:
        return httpx.Response(status, request=req, json=json_body)
    return httpx.Response(status, request=req, text=text or "")


def test_invalid_region_message_points_to_guard_settings():
    err = lakera._api_error(
        _resp(400, json_body={"error": "ErrInvalidRegion", "message": "invalid region"}),
        "https://eu-west-1.api.lakera.ai/v2/guard")
    assert isinstance(err, lakera.LakeraAPIError)
    assert err.status_code == 400
    s = str(err)
    assert s.startswith("Lakera Guard error (400):")     # attributed to the guard, not the LLM
    assert "invalid region" in s
    assert "region" in s.lower() and "Settings" in s
    assert "https://api.lakera.ai" in s                   # tells them the Community fallback


def test_bad_key_message_mentions_key():
    err = lakera._api_error(_resp(401, json_body={"message": "unauthorized"}),
                            lakera.COMMUNITY_ENDPOINT)
    assert err.status_code == 401
    assert "API key" in str(err)


def test_non_json_body_falls_back_to_text():
    err = lakera._api_error(_resp(400, text="Bad Request"), lakera.COMMUNITY_ENDPOINT)
    assert "Bad Request" in str(err)


def test_is_transient_treats_lakera_5xx_429_as_retryable():
    assert main._is_transient(lakera.LakeraAPIError(503, "x")) is True
    assert main._is_transient(lakera.LakeraAPIError(429, "x")) is True
    assert main._is_transient(lakera.LakeraAPIError(400, "x")) is False   # config error → don't retry
    assert main._is_transient(lakera.LakeraAPIError(401, "x")) is False


async def test_check_raises_lakera_api_error_on_4xx(monkeypatch):
    class FakeClient:
        async def post(self, url, **kw):
            return _resp(400, url=url,
                         json_body={"error": "ErrInvalidRegion", "message": "invalid region"})

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(lakera, "_get_client", fake_get_client)
    with pytest.raises(lakera.LakeraAPIError) as ei:
        await lakera.check("hi", "key", endpoint="https://eu-west-1.api.lakera.ai/v2/guard")
    assert ei.value.status_code == 400
    assert "invalid region" in str(ei.value)


async def test_check_returns_data_on_success(monkeypatch):
    class FakeClient:
        async def post(self, url, **kw):
            return _resp(200, url=url, json_body={"flagged": False, "breakdown": []})

    async def fake_get_client():
        return FakeClient()

    monkeypatch.setattr(lakera, "_get_client", fake_get_client)
    data = await lakera.check("hi", "key")
    assert data["flagged"] is False
    assert "latency_ms" in data                            # success path still annotates latency
