"""
Configured API keys must never leave the process.

The demo holds three secrets a user types into the UI — the Lakera Guard key,
the LLM provider key, and the judge key — and it has no per-user auth, so the
blast radius of leaking one is the user's whole provider account. Masking them
in the settings panel is not enough: the same values flow into run payloads,
exported reports, saved history, log lines, and upstream error bodies, and any
one of those is an exfiltration path.

The approach here is deliberately empirical rather than a code read. Each key is
set to a unique sentinel, every reachable surface is exercised, and the raw
bytes are searched for the sentinel. A new endpoint or export format that echoes
a key fails these tests without anyone remembering to audit it.

`api_key_masked` is expected and fine — it is a prefix+suffix fingerprint, never
enough to authenticate.
"""
import json
import logging

import pytest

from backend import chat, history, lakera, llm, main, oneshot, report_html

# Distinctive, structurally realistic, and impossible to produce by accident.
LAKERA_SENTINEL = "lak-SENTINEL0000ffffdeadbeefcafe1111LEAKCANARY"
LLM_SENTINEL = "sk-or-v1-SENTINEL1111aaaabbbbccccdddd2222LEAKCANARY"
JUDGE_SENTINEL = "sk-judge-SENTINEL2222eeeeffff33334444LEAKCANARY"
ALL_SENTINELS = (LAKERA_SENTINEL, LLM_SENTINEL, JUDGE_SENTINEL)


def assert_clean(blob, where: str) -> None:
    """Fail with the offending surface named, not just a bare assert."""
    text = blob if isinstance(blob, str) else (
        blob.decode("utf-8", "replace") if isinstance(blob, bytes) else json.dumps(blob, default=str)
    )
    for sentinel in ALL_SENTINELS:
        assert sentinel not in text, f"API KEY LEAKED via {where}"
    # Catch a partial leak too: everything after the masked prefix must be absent.
    for sentinel in ALL_SENTINELS:
        assert sentinel[6:] not in text, f"API KEY BODY LEAKED via {where}"


@pytest.fixture(autouse=True)
def configured_keys(monkeypatch):
    """Set every key the way a user would, then restore."""
    monkeypatch.setattr(main, "_lakera_key", LAKERA_SENTINEL)
    monkeypatch.setattr(main, "_llm_config", {**main._llm_config, "api_key": LLM_SENTINEL})
    monkeypatch.setattr(main, "_judge_config", {
        "provider": "openrouter", "base_url": "https://openrouter.ai/api/v1",
        "model": "test/model", "api_key": JUDGE_SENTINEL,
    })
    yield


# ── Every GET surface ────────────────────────────────────────────────────────

GET_ROUTES = [
    "/", "/openapi.json", "/healthz", "/readyz",
    "/api/llm-config", "/api/judge-config", "/api/lakera-config",
    "/api/scenarios", "/api/scenario-categories", "/api/strategies",
    "/api/datasets", "/api/docs/custom", "/api/docs-mode",
    "/api/docs/scan-settings", "/api/frameworks", "/api/history",
    "/api/session/risks", "/api/system-prompt",
]


@pytest.mark.parametrize("path", GET_ROUTES)
async def test_no_get_endpoint_returns_a_key(client, path):
    resp = await client.get(path)
    assert resp.status_code < 500, f"{path} errored: {resp.text[:200]}"
    assert_clean(resp.text, f"GET {path}")


async def test_the_settings_panel_gets_a_fingerprint_not_the_key(client):
    """The UI must be able to show *which* key is set without receiving it."""
    d = (await client.get("/api/lakera-config")).json()
    assert d["api_key_set"] is True
    assert d["api_key_masked"] and d["api_key_masked"] != LAKERA_SENTINEL
    assert LAKERA_SENTINEL not in d["api_key_masked"]
    # A fingerprint that reveals most of the key is not a fingerprint.
    assert len(d["api_key_masked"].replace("…", "")) <= 12


async def test_openapi_schema_exposes_no_key_defaults(client):
    """A schema default is an easy place for a live value to end up."""
    assert_clean((await client.get("/openapi.json")).text, "openapi.json")


# ── Exports: the report in all three formats ─────────────────────────────────

def _payload() -> dict:
    return {
        "summary": {"total": 1, "blocked": 1, "security": {
            "posture": {"level": "secure", "headline": "ok"}, "categories": [], "findings": []},
            "run_config": main._run_config(main.OneShotRequest())},
        "results": [{"id": "S1", "label": "s", "owasp_id": "LLM01", "category_id": "llm01",
                     "expected": "blocked", "outcome": "blocked", "blocked": True,
                     "total_latency_ms": 5, "color": "attack"}],
        "llm": main._public_llm_config(),
        "judge": main._public_judge_config(),
        "generated_at": "2026-01-01T00:00:00Z",
    }


def test_exported_html_report_carries_no_key():
    assert_clean(report_html.render(_payload()), "exported HTML report")


def test_exported_json_report_carries_no_key():
    assert_clean(json.dumps(_payload(), default=str), "exported JSON report")


def test_exported_csv_report_carries_no_key():
    assert_clean(oneshot.results_to_csv(_payload()["results"]), "exported CSV report")


def test_run_config_records_settings_but_not_credentials():
    """run_config deliberately captures how a run was configured — the one place
    a key could ride along under the banner of reproducibility."""
    assert_clean(main._run_config(main.OneShotRequest()), "summary.run_config")


# ── Persistence: saved history on disk ───────────────────────────────────────

async def test_saved_history_carries_no_key(client, tmp_path, monkeypatch):
    """History is written to disk and re-served; a key there outlives the session."""
    monkeypatch.setattr(main, "RUN_HISTORY_DIR", tmp_path)
    saved = await client.post("/api/history", json={**_payload(), "label": "run"})
    assert saved.status_code == 200, saved.text
    for f in tmp_path.rglob("*"):
        if f.is_file():
            assert_clean(f.read_bytes(), f"history file {f.name}")
    assert_clean((await client.get("/api/history")).text, "GET /api/history")


# ── Error paths: where upstream bodies get echoed ────────────────────────────

async def test_a_failed_guard_call_does_not_echo_the_key(client, monkeypatch):
    """Guard errors quote the upstream response; the key is in the request
    header and must not be reflected back into the detail string."""
    async def boom(*a, **k):
        raise lakera.LakeraAPIError(401, f"Unauthorized for key {LAKERA_SENTINEL}")
    monkeypatch.setattr(chat.lakera, "check", boom)
    resp = await client.post("/api/chat", json={"message": "hi", "category_id": "llm01"})
    assert_clean(resp.text, "chat error body (guard)")


async def test_a_failed_llm_call_does_not_echo_the_key(client, monkeypatch):
    async def ok(*a, **k):
        return {"latency_ms": 1}
    monkeypatch.setattr(chat.lakera, "check", ok)
    monkeypatch.setattr(chat.lakera, "is_flagged", lambda r: False)
    monkeypatch.setattr(chat.lakera, "flagged_categories", lambda r: [])
    monkeypatch.setattr(chat.lakera, "detector_results", lambda r, only_detected=True: [])
    monkeypatch.setattr(chat.lakera, "results_summary", lambda r: {"detectors": [], "flagged_count": 0})

    async def boom(*a, **k):
        raise RuntimeError(f"401 from provider: bad key {LLM_SENTINEL}")
    monkeypatch.setattr(chat, "_call_llm", boom)
    resp = await client.post("/api/chat", json={"message": "hi", "category_id": "llm01"})
    assert_clean(resp.text, "chat error body (llm)")


async def test_connection_test_failure_does_not_echo_the_key(client, monkeypatch):
    """
    The highest-risk path: Test Connection runs right after a user types a key,
    against a base_url they control. It reports up to 200 characters of the
    upstream body — and returns HTTP 200 doing so, so the error-response
    scrubber never sees it. Models the real shape: the probe CATCHES the
    failure and returns it as data.
    """
    async def upstream_echoes_the_key(*a, **k):
        return {"ok": False, "latency_ms": 12, "models": [],
                "error": f"HTTP 401: {{\"error\":\"invalid_api_key: {LLM_SENTINEL}\"}}"}
    monkeypatch.setattr(llm, "_probe_connection", upstream_echoes_the_key)
    resp = await client.post("/api/llm-config/test", json={
        "provider": "openrouter", "base_url": "https://openrouter.ai/api/v1",
        "model": "test/model", "api_key": None})
    assert_clean(resp.text, "POST /api/llm-config/test")


# ── Logs ─────────────────────────────────────────────────────────────────────

async def test_keys_are_never_written_to_the_log(client, caplog, monkeypatch):
    """Logs get shipped to collectors and pasted into bug reports."""
    async def boom(*a, **k):
        raise lakera.LakeraAPIError(401, f"Unauthorized {LAKERA_SENTINEL}")
    monkeypatch.setattr(chat.lakera, "check", boom)
    with caplog.at_level(logging.DEBUG):
        await client.post("/api/chat", json={"message": "hi", "category_id": "llm01"})
        for path in ("/api/lakera-config", "/api/llm-config", "/api/judge-config"):
            await client.get(path)
    assert_clean(caplog.text, "application log")


# ── Write-only semantics ─────────────────────────────────────────────────────

async def test_a_key_cannot_be_read_back_after_being_set(client):
    """Round-trip: setting a key must not make it retrievable."""
    resp = await client.post("/api/lakera-config", json={"api_key": LAKERA_SENTINEL})
    assert_clean(resp.text, "POST /api/lakera-config response")
    assert_clean((await client.get("/api/lakera-config")).text, "GET after POST")


async def test_project_id_can_be_updated_without_resurfacing_the_key(client):
    """`api_key: null` leaves the key alone — verify that path stays silent too."""
    resp = await client.post("/api/lakera-config", json={"project_id": "project-123"})
    assert resp.status_code == 200
    assert_clean(resp.text, "POST /api/lakera-config (project only)")


# ── At rest: the .env the app writes ─────────────────────────────────────────

async def test_saved_env_file_is_not_readable_by_other_users(client, tmp_path, monkeypatch):
    """
    save-env writes all three keys to disk in plaintext. Under the default umask
    that file lands 0644 — readable by every local account and every process on
    the host, which is a credential disclosure on any shared or multi-tenant box.
    """
    env = tmp_path / ".env"
    monkeypatch.setattr(main, "ENV_PATH", env)
    resp = await client.post("/api/config/save-env")
    assert resp.status_code == 200, resp.text

    mode = env.stat().st_mode & 0o777
    assert mode == 0o600, f".env is {oct(mode)}; secrets are readable by other users"
    assert LAKERA_SENTINEL in env.read_text(), "sanity: the key really is in there"


async def test_a_preexisting_world_readable_env_gets_tightened(client, tmp_path, monkeypatch):
    """O_CREAT does not re-apply the mode to a file that already exists, so the
    common case — a .env written before this fix — must still be fixed on save."""
    env = tmp_path / ".env"
    env.write_text("LAKERA_GUARD_API_KEY=old\n")
    env.chmod(0o644)
    monkeypatch.setattr(main, "ENV_PATH", env)
    await client.post("/api/config/save-env")
    assert env.stat().st_mode & 0o777 == 0o600


async def test_save_env_response_lists_names_not_values(client, tmp_path, monkeypatch):
    monkeypatch.setattr(main, "ENV_PATH", tmp_path / ".env")
    resp = await client.post("/api/config/save-env")
    assert "LAKERA_GUARD_API_KEY" in resp.json()["keys"]     # names are fine
    assert_clean(resp.text, "POST /api/config/save-env")


# ── Client side: keys must not be persisted in the browser ───────────────────

def test_the_browser_never_persists_a_key_to_localstorage():
    """
    localStorage survives the tab, is readable by any script on the origin, and
    shows up in browser profile backups. appstate.js keeps the two keys in memory
    only; this pins that, because the leak would be a one-word edit to a map.
    """
    js = (main.FRONTEND_DIR / "appstate.js").read_text(encoding="utf-8")
    assert "var SECRET = { lakeraKey: 1, providerKey: 1 };" in js, \
        "the SECRET denylist changed — confirm no key became persistable"
    # Both write paths must consult it.
    assert js.count("if (!SECRET[") >= 2
