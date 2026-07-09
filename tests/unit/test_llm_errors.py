"""Offline tests for actionable request-error messages (llm.describe_error) and
the connection hints — the CLI shows these instead of raw httpx tracebacks."""
import httpx

from backend import llm


def _req(url):
    return httpx.Request("POST", url)


def test_describe_connect_error_host_docker_internal_on_host(monkeypatch):
    # The exact failure mode of a base-url copied from a Docker setup, run on the host.
    monkeypatch.setattr(llm, "_in_container", lambda: False)
    exc = httpx.ConnectError(
        "refused", request=_req("http://host.docker.internal:8100/v1/chat/completions"))
    msg = llm.describe_error(exc)
    assert "cannot connect to http://host.docker.internal:8100" in msg
    assert "only resolves" in msg          # explains the Docker-only DNS name
    assert "localhost:8100" in msg         # tells the user exactly what to use instead


def test_describe_connect_error_localhost(monkeypatch):
    monkeypatch.setattr(llm, "_in_container", lambda: False)
    exc = httpx.ConnectError("refused", request=_req("http://localhost:1234/v1/chat/completions"))
    msg = llm.describe_error(exc)
    assert "Nothing is listening on 'localhost:1234'" in msg


def test_describe_http_status_401_mentions_key():
    req = _req("https://openrouter.ai/api/v1/chat/completions")
    resp = httpx.Response(401, request=req, text="unauthorized")
    msg = llm.describe_error(httpx.HTTPStatusError("401", request=req, response=resp))
    assert "HTTP 401" in msg and "check the API key" in msg


def test_describe_http_status_429_mentions_rate_limit():
    req = _req("https://openrouter.ai/api/v1/chat/completions")
    resp = httpx.Response(429, request=req, text="slow down")
    msg = llm.describe_error(httpx.HTTPStatusError("429", request=req, response=resp))
    assert "HTTP 429" in msg and "rate limited" in msg


def test_describe_timeout():
    exc = httpx.ConnectTimeout("timeout", request=_req("http://x:9999/v1/chat/completions"))
    msg = llm.describe_error(exc)
    assert "timed out" in msg and "http://x:9999" in msg


def test_describe_generic_non_httpx():
    assert "ValueError: boom" in llm.describe_error(ValueError("boom"))


def test_connection_hint_docker_internal_is_correct_inside_container(monkeypatch):
    # Inside a container, host.docker.internal IS the right name → no "use localhost" swap.
    monkeypatch.setattr(llm, "_in_container", lambda: True)
    hint = llm._connection_hint("http://host.docker.internal:8100/v1")
    assert "only resolves" not in hint
