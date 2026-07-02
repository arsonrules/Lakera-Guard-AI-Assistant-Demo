"""Offline tests for the Lakera project-id + Guard region: body + config endpoint."""
import pytest
from fastapi import HTTPException

import backend.main as main
from backend import lakera
from backend.main import LakeraKeyRequest, api_get_lakera_config, api_set_lakera_config


def test_build_body_includes_project_id_only_when_set():
    assert "project_id" not in lakera._build_body("hi")
    assert "project_id" not in lakera._build_body("hi", "")
    body = lakera._build_body("hi", "proj-123")
    assert body["project_id"] == "proj-123"
    assert body["messages"][0]["content"] == "hi"
    assert body["breakdown"] is True


async def test_config_endpoint_roundtrip(monkeypatch):
    monkeypatch.setattr(main, "_lakera_key", "")
    monkeypatch.setattr(main, "_lakera_project_id", "")

    out = await api_set_lakera_config(LakeraKeyRequest(api_key="secret-key", project_id="proj-abc"))
    assert out["project_id"] == "proj-abc"
    assert main._lakera_project_id == "proj-abc"
    assert (await api_get_lakera_config())["project_id"] == "proj-abc"

    # A null project_id leaves it unchanged; a blank string clears it.
    await api_set_lakera_config(LakeraKeyRequest(api_key="secret-key", project_id=None))
    assert main._lakera_project_id == "proj-abc"
    await api_set_lakera_config(LakeraKeyRequest(api_key="secret-key", project_id=""))
    assert main._lakera_project_id == ""


def test_control_chars_stripped_from_project_id():
    # _clean strips control chars (env / header injection defense).
    assert main._clean("proj\n-123") == "proj-123"


# ── Guard region / endpoint ──────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _restore_endpoint():
    # Region is module-global on lakera; restore the default after each test.
    saved = lakera.current_endpoint()
    yield
    lakera.set_endpoint(saved)


def test_normalize_endpoint_variants():
    # Blank → Community default.
    assert lakera.normalize_endpoint("") == lakera.COMMUNITY_ENDPOINT
    # A bare region host gets the Guard path appended.
    assert lakera.normalize_endpoint("https://eu-west-1.api.lakera.ai") == \
        "https://eu-west-1.api.lakera.ai/v2/guard"
    # A trailing slash is tolerated.
    assert lakera.normalize_endpoint("https://us.api.lakera.ai/") == \
        "https://us.api.lakera.ai/v2/guard"
    # A full URL with a path is left as-is.
    assert lakera.normalize_endpoint("https://api.lakera.ai/v2/guard") == \
        "https://api.lakera.ai/v2/guard"
    # Non-http schemes are rejected.
    with pytest.raises(ValueError):
        lakera.normalize_endpoint("ftp://api.lakera.ai")


async def test_config_endpoint_sets_region(monkeypatch):
    monkeypatch.setattr(main, "_lakera_key", "k")
    monkeypatch.setattr(main, "_lakera_project_id", "")

    # GET exposes the current endpoint plus the selectable region catalogue.
    got = await api_get_lakera_config()
    assert got["endpoint"] == lakera.COMMUNITY_ENDPOINT
    assert any(r["id"] == "eu-west-1" for r in got["regions"])

    # A region host is normalized and applied to the module used by every check.
    out = await api_set_lakera_config(
        LakeraKeyRequest(endpoint="https://ap-southeast-1.api.lakera.ai"))
    assert out["endpoint"] == "https://ap-southeast-1.api.lakera.ai/v2/guard"
    assert lakera.current_endpoint() == "https://ap-southeast-1.api.lakera.ai/v2/guard"

    # null endpoint leaves it unchanged; "" resets to Community.
    await api_set_lakera_config(LakeraKeyRequest(endpoint=None))
    assert lakera.current_endpoint() == "https://ap-southeast-1.api.lakera.ai/v2/guard"
    await api_set_lakera_config(LakeraKeyRequest(endpoint=""))
    assert lakera.current_endpoint() == lakera.COMMUNITY_ENDPOINT


async def test_config_endpoint_rejects_bad_scheme():
    with pytest.raises(HTTPException) as exc:
        await api_set_lakera_config(LakeraKeyRequest(endpoint="ftp://api.lakera.ai"))
    assert exc.value.status_code == 400
