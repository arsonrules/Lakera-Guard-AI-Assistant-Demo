"""Offline tests for the Lakera project-id: request body + config endpoint."""
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
