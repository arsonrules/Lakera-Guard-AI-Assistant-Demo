"""Offline tests for the SSRF guard on the operator-supplied LLM/judge base URL."""
import pytest
from fastapi import HTTPException

import backend.main as main
from backend.main import (
    JudgeConfigRequest,
    LLMConfigRequest,
    _reject_metadata_url,
    api_set_judge_config,
    api_set_llm_config,
    api_test_llm_config,
)

BLOCKED = [
    "http://169.254.169.254/latest/meta-data/",     # AWS/Azure/GCP IMDS
    "http://169.254.169.254",
    "https://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.goog/",
    "http://[fd00:ec2::254]/latest/meta-data/",      # AWS IPv6 metadata
    "http://[fe80::1]/v1",                            # IPv6 link-local
    "http://instance-data/latest/",
]

ALLOWED = [
    "http://localhost:1234/v1",       # local LLM servers must keep working
    "http://127.0.0.1:11434/v1",
    "http://192.168.1.50:8000/v1",    # LAN on-prem server
    "https://openrouter.ai/api/v1",
    "http://host.docker.internal:1234/v1",
]


@pytest.mark.parametrize("url", BLOCKED)
def test_reject_metadata_url_blocks(url):
    with pytest.raises(HTTPException) as exc:
        _reject_metadata_url(url)
    assert exc.value.status_code == 400


@pytest.mark.parametrize("url", ALLOWED)
def test_reject_metadata_url_allows(url):
    # Should not raise (localhost / LAN / normal hosts stay usable).
    _reject_metadata_url(url)


async def test_llm_config_endpoints_block_metadata(monkeypatch):
    monkeypatch.setattr(main, "_llm_config",
                        {"provider": "custom", "base_url": "", "api_key": "", "model": "m"})
    req = LLMConfigRequest(provider="custom",
                           base_url="http://169.254.169.254/v1", model="m")
    with pytest.raises(HTTPException) as exc:
        await api_set_llm_config(req)
    assert exc.value.status_code == 400
    # The provider must be left untouched when the URL is rejected.
    assert main._llm_config["base_url"] == ""

    with pytest.raises(HTTPException):
        await api_test_llm_config(req)


async def test_judge_config_endpoint_blocks_metadata(monkeypatch):
    monkeypatch.setattr(main, "_judge_config", None)
    req = JudgeConfigRequest(enabled=True, provider="custom",
                             base_url="http://metadata.google.internal/", model="m")
    with pytest.raises(HTTPException) as exc:
        await api_set_judge_config(req)
    assert exc.value.status_code == 400
    assert main._judge_config is None
