"""
Offline tests for WebSocket targets — the same Target Test, over a socket.

The transport goes through exactly one seam (`llm._ws_connect`), which these
stub, so nothing here opens a real socket. What they pin down is the part that
differs from HTTP and would otherwise only surface against a live endpoint:
credentials must ride on the handshake, an ack frame must not be graded as the
assistant's answer, and a socket that never sends a matching frame has to fail
with something a user can act on.
"""
import json

import pytest
import websockets.exceptions as ws_exc

import backend.main as main
from backend import llm
from backend.main import OneShotRequest, TargetConfig, TargetTestRequest


WS_SPEC = {
    "url": "wss://api.example.com/assistant",
    "auth": {"type": "bearer", "token": "sk-socket-secret-value"},
    "body": '{"question": {{prompt}}}',
    "response_path": "data.answer",
    "timeout": 5,
}


class _FakeSocket:
    """A scripted socket: records what was sent, replays `frames`, then closes."""

    def __init__(self, frames):
        self.frames = list(frames)
        self.sent: list[str] = []

    async def send(self, body):
        self.sent.append(body)

    async def recv(self):
        if not self.frames:
            raise ws_exc.ConnectionClosed(None, None)
        f = self.frames.pop(0)
        if isinstance(f, Exception):
            raise f
        return f

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


@pytest.fixture
def ws_endpoint(monkeypatch):
    """Install a scripted socket; returns the record of connects + sends."""
    calls: dict = {"kwargs": [], "sockets": []}

    def install(frames, error=None):
        def _connect(spec):
            calls["kwargs"].append(spec)
            if error is not None:
                raise error
            sock = _FakeSocket(frames)
            calls["sockets"].append(sock)
            return sock

        monkeypatch.setattr(llm, "_ws_connect", _connect)
        return calls

    return install


# ── the spec accepts a socket ────────────────────────────────────────────────

@pytest.mark.parametrize("url,expected", [
    ("wss://api.example.com/ws", True),
    ("ws://localhost:9000", True),
    ("WSS://API.EXAMPLE.COM", True),
    ("https://api.example.com", False),
    ("http://localhost:9000", False),
])
def test_ws_targets_are_recognised_by_their_scheme(url, expected):
    assert llm.is_ws_target(url) is expected


def test_a_wss_url_is_accepted_and_labelled_as_a_socket():
    cfg = main._target_llm_config(TargetConfig(**WS_SPEC))
    assert cfg["base_url"] == WS_SPEC["url"]
    assert cfg["model"] == "ws:api.example.com"     # the readout says it's a socket
    assert cfg["target"]["method"] == "WS"          # a frame has no HTTP verb


def test_an_http_target_is_still_labelled_http():
    cfg = main._target_llm_config(TargetConfig(url="https://api.example.com/v1/x"))
    assert cfg["model"] == "http:api.example.com" and cfg["target"]["method"] == "POST"


def test_a_method_is_not_validated_for_a_socket():
    """The picker's verb is meaningless here — it must not become a 400."""
    cfg = main._target_llm_config(TargetConfig(**{**WS_SPEC, "method": "GET"}))
    assert cfg["target"]["method"] == "WS"


@pytest.mark.parametrize("url,needle", [
    ("ftp://api.example.com/x", "ws://"),
    ("api.example.com/x", "ws://"),
])
def test_an_unsupported_scheme_names_the_ones_that_work(url, needle):
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        main._target_llm_config(TargetConfig(url=url))
    assert needle in exc.value.detail


def test_the_ssrf_guard_covers_sockets_too():
    """A metadata host is no less reachable over wss:// than over https://."""
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc:
        main._target_llm_config(TargetConfig(url="wss://169.254.169.254/ws"))
    assert "not allowed" in exc.value.detail


# ── credentials ride on the handshake ────────────────────────────────────────

@pytest.mark.parametrize("auth,header,value", [
    ({"type": "bearer", "token": "tok-123"}, "Authorization", "Bearer tok-123"),
    ({"type": "api_key", "header": "X-Acme-Key", "key": "k-456"}, "X-Acme-Key", "k-456"),
    ({"type": "basic", "username": "u", "password": "p"}, "Authorization", "Basic dTpw"),
])
async def test_every_auth_scheme_reaches_the_handshake(ws_endpoint, auth, header, value):
    calls = ws_endpoint(['{"data": {"answer": "hi"}}'])
    cfg = main._target_llm_config(TargetConfig(**{**WS_SPEC, "auth": auth}))
    out = await llm.complete_chat([{"role": "user", "content": "ping"}],
                                  provider="http", base_url="", api_key="", model="",
                                  target=cfg["target"])
    assert out == "hi"
    assert calls["kwargs"][0]["headers"][header] == value


async def test_extra_headers_reach_the_handshake(ws_endpoint):
    calls = ws_endpoint(['{"data": {"answer": "hi"}}'])
    cfg = main._target_llm_config(TargetConfig(**{**WS_SPEC, "headers": {"X-Tenant": "acme"}}))
    await llm.complete_chat([{"role": "user", "content": "ping"}], provider="http",
                            base_url="", api_key="", model="", target=cfg["target"])
    assert calls["kwargs"][0]["headers"]["X-Tenant"] == "acme"


def test_a_socket_credential_is_registered_for_redaction():
    main._target_llm_config(TargetConfig(**WS_SPEC))
    assert "sk-socket-secret-value" in main._target_secrets


# ── the exchange ─────────────────────────────────────────────────────────────

async def test_the_body_template_is_sent_as_one_frame(ws_endpoint):
    calls = ws_endpoint(['{"data": {"answer": "hi"}}'])
    await llm._complete_target([{"role": "user", "content": 'say "hi"\nnow'}],
                               {**WS_SPEC, "headers": {}})
    sent = calls["sockets"][0].sent
    assert len(sent) == 1
    # JSON-encoded, exactly as over HTTP — a prompt full of quotes and newlines
    # must not break the frame.
    assert json.loads(sent[0])["question"] == 'say "hi"\nnow'


async def test_extra_fields_are_merged_into_the_frame(ws_endpoint):
    calls = ws_endpoint(['{"data": {"answer": "hi"}}'])
    await llm._complete_target([{"role": "user", "content": "p"}],
                               {**WS_SPEC, "headers": {},
                                "extra_fields": {"model": "acme-1", "stream": False}})
    body = json.loads(calls["sockets"][0].sent[0])
    assert body["model"] == "acme-1" and body["stream"] is False


async def test_frames_that_are_not_the_answer_are_skipped(ws_endpoint):
    """An ack or a status envelope must not be graded as the assistant's reply."""
    ws_endpoint(['{"type": "ack"}', '{"event": "typing"}',
                 '{"data": {"answer": "the real answer"}}'])
    out = await llm._complete_target([{"role": "user", "content": "p"}],
                                     {**WS_SPEC, "headers": {}})
    assert out == "the real answer"


async def test_a_plain_text_socket_needs_no_response_path(ws_endpoint):
    ws_endpoint(["just text back"])
    out = await llm._complete_target([{"role": "user", "content": "p"}],
                                     {**WS_SPEC, "headers": {}, "response_path": ""})
    assert out == "just text back"


async def test_a_json_frame_with_no_response_path_says_so(ws_endpoint):
    """Waiting this one out to a timeout would hide a fixable misconfiguration."""
    ws_endpoint(['{"data": {"answer": "hi"}}'])
    with pytest.raises(ValueError) as exc:
        await llm._complete_target([{"role": "user", "content": "p"}],
                                   {**WS_SPEC, "headers": {}, "response_path": ""})
    assert "response path is required" in str(exc.value)


async def test_no_matching_frame_reports_what_did_arrive(ws_endpoint):
    ws_endpoint(['{"type": "ack"}', '{"event": "done"}'])
    with pytest.raises(ValueError) as exc:
        await llm._complete_target([{"role": "user", "content": "p"}],
                                   {**WS_SPEC, "headers": {}})
    msg = str(exc.value)
    assert "data.answer" in msg and "2 frame(s)" in msg and "done" in msg


async def test_binary_frames_are_decoded(ws_endpoint):
    ws_endpoint([b'{"data": {"answer": "from bytes"}}'])
    out = await llm._complete_target([{"role": "user", "content": "p"}],
                                     {**WS_SPEC, "headers": {}})
    assert out == "from bytes"


# ── the probe ────────────────────────────────────────────────────────────────

async def test_the_probe_reports_the_frames_and_the_extracted_value(ws_endpoint):
    ws_endpoint(['{"type": "ack"}', '{"data": {"answer": "hello there"}}'])
    out = await llm.probe_target({**WS_SPEC, "headers": {}}, "ping")
    assert out["ok"] is True and out["status"] == 101
    assert out["extracted"] == "hello there"
    assert "ack" in out["raw_body_preview"]      # so a path can be picked from it


async def test_the_probe_gives_up_sooner_than_a_run_would(ws_endpoint):
    """A person is waiting on this one; a 300s socket timeout is not their budget."""
    calls = ws_endpoint(['{"data": {"answer": "hi"}}'])
    await llm.probe_target({**WS_SPEC, "headers": {}, "timeout": 300}, "ping")
    assert calls["kwargs"][0]["timeout"] == llm.WS_PROBE_TIMEOUT


async def test_the_probe_flags_a_bad_response_path_without_raising(ws_endpoint):
    ws_endpoint(['{"data": {"reply": "wrong key"}}'])
    out = await llm.probe_target({**WS_SPEC, "headers": {}}, "ping")
    assert out["ok"] is False and out["path_error"] is True
    assert "wrong key" in out["raw_body_preview"]


async def test_the_probe_never_echoes_a_configured_credential(ws_endpoint, monkeypatch):
    monkeypatch.setattr(main, "_target_secrets", main._target_secrets)
    cfg = main._target_llm_config(TargetConfig(**WS_SPEC))
    ws_endpoint(['{"data": {"answer": "your token is sk-socket-secret-value"}}'])
    out = await llm.probe_target(cfg["target"], "ping")
    assert "sk-socket-secret-value" not in json.dumps(out)


async def test_a_rejected_handshake_is_reported_as_an_http_status(ws_endpoint):
    class _Resp:
        status_code = 401
    ws_endpoint([], error=ws_exc.InvalidStatus(_Resp()))
    out = await llm.probe_target({**WS_SPEC, "headers": {}}, "ping")
    assert out["ok"] is False
    assert "401" in out["error"] and "API key" in out["error"]


# ── a whole run over a socket ────────────────────────────────────────────────

async def test_a_full_target_run_goes_over_the_socket(ws_endpoint, monkeypatch):
    monkeypatch.setattr(main, "_lakera_key", "")     # no guard, no key (Target Test)
    ws_endpoint(['{"data": {"answer": "a socket reply"}}'] * 200)
    req = OneShotRequest(category_id="llm01", judge=False, compare=False,
                         max_scenarios=3, include_safe=False, target=WS_SPEC)
    cfg, judge_cfg, pub, _ = main._oneshot_llm(req)
    out = await main.run_oneshot(req, llm_config=cfg, lakera_key="", judge_config=judge_cfg)
    assert out["results"] and all(r["error"] is None for r in out["results"])
    assert pub["base_url"] == WS_SPEC["url"]
    assert out["summary"]["guarded"] is False


async def test_a_socket_failure_errors_the_row_not_the_run(ws_endpoint, monkeypatch):
    monkeypatch.setattr(main, "_lakera_key", "")
    ws_endpoint([], error=ws_exc.ConnectionClosed(None, None))
    req = OneShotRequest(category_id="llm01", judge=False, compare=False,
                         max_scenarios=2, include_safe=False, target=WS_SPEC)
    cfg, judge_cfg, _, _ = main._oneshot_llm(req)
    out = await main.run_oneshot(req, llm_config=cfg, lakera_key="", judge_config=judge_cfg)
    assert out["results"]
    assert all(r["outcome"] == "error" and "WebSocket" in r["error"]
               for r in out["results"])


# ── the endpoint the UI probes with ──────────────────────────────────────────

async def test_the_target_test_endpoint_probes_a_socket(client, ws_endpoint):
    ws_endpoint(['{"data": {"answer": "hi"}}'])
    resp = await client.post("/api/target/test", json={**WS_SPEC, "prompt": "ping"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["ok"] is True and body["extracted"] == "hi"
    assert body["url"] == WS_SPEC["url"]


def test_the_request_model_accepts_a_socket_spec():
    req = TargetTestRequest(**{**WS_SPEC, "prompt": "ping"})
    assert req.url == WS_SPEC["url"] and req.prompt == "ping"
