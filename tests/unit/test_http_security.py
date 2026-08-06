"""
HTTP-layer tests for the security middleware and the guarded endpoints.

Everything here runs through the real ASGI app (see the `client` fixture), so it
covers routing, request validation, and middleware — the layer the rest of the
offline suite skips by calling functions directly.
"""
import re
from pathlib import Path

import pytest

from backend import main
from backend.config import settings


# ── CSRF / cross-origin guard ────────────────────────────────────────────────

async def test_cross_origin_post_is_rejected(client):
    resp = await client.post(
        "/api/docs-mode", json={"mode": "clean"},
        headers={"Origin": "http://evil.example", "Host": "testserver"},
    )
    assert resp.status_code == 403
    assert "Cross-origin" in resp.json()["detail"]


async def test_cross_origin_delete_is_rejected(client):
    resp = await client.delete(
        "/api/datasets/anything", headers={"Origin": "http://evil.example", "Host": "testserver"}
    )
    assert resp.status_code == 403


async def test_same_origin_post_is_allowed(client):
    """The guard must not block the app's own UI."""
    resp = await client.post(
        "/api/docs-mode", json={"mode": "clean"},
        headers={"Origin": "http://testserver", "Host": "testserver"},
    )
    assert resp.status_code != 403


async def test_no_origin_header_is_allowed(client):
    """Non-browser clients (curl, CI) send no Origin and must still work."""
    resp = await client.post("/api/docs-mode", json={"mode": "clean"})
    assert resp.status_code != 403


async def test_cross_origin_get_is_allowed(client):
    """Only state-changing verbs are guarded; GET is safe and must not 403."""
    resp = await client.get("/api/scenarios", headers={"Origin": "http://evil.example"})
    assert resp.status_code == 200


# ── Security response headers ────────────────────────────────────────────────

@pytest.mark.parametrize("header,expected", [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
])
async def test_security_headers_present(client, header, expected):
    resp = await client.get("/api/scenarios")
    assert resp.headers.get(header) == expected


async def test_csp_locks_down_dangerous_sinks(client):
    csp = (await client.get("/api/scenarios")).headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp


# ── Request correlation ──────────────────────────────────────────────────────

async def test_request_id_is_returned(client):
    rid = (await client.get("/api/scenarios")).headers.get("X-Request-ID")
    assert rid and len(rid) >= 8


async def test_inbound_request_id_is_preserved(client):
    """A proxy-supplied id must survive so traces join across hops."""
    resp = await client.get("/api/scenarios", headers={"X-Request-ID": "trace-abc-123"})
    assert resp.headers["X-Request-ID"] == "trace-abc-123"


async def test_request_ids_are_unique_per_request(client):
    a = (await client.get("/api/scenarios")).headers["X-Request-ID"]
    b = (await client.get("/api/scenarios")).headers["X-Request-ID"]
    assert a != b


# ── Optional access-token gate ───────────────────────────────────────────────

async def test_api_is_open_when_no_token_configured(client):
    assert (await client.get("/api/scenarios")).status_code == 200


async def test_api_requires_token_when_configured(client):
    settings.demo_access_token = "s3cret"
    assert (await client.get("/api/scenarios")).status_code == 401


@pytest.mark.parametrize("headers", [
    {"X-Demo-Token": "s3cret"},
    {"Authorization": "Bearer s3cret"},
])
async def test_valid_token_is_accepted_in_either_form(client, headers):
    settings.demo_access_token = "s3cret"
    assert (await client.get("/api/scenarios", headers=headers)).status_code == 200


@pytest.mark.parametrize("headers", [
    {"X-Demo-Token": "wrong"},
    {"Authorization": "Bearer wrong"},
    {"Authorization": "s3cret"},          # missing the Bearer scheme
])
async def test_invalid_token_is_rejected(client, headers):
    settings.demo_access_token = "s3cret"
    assert (await client.get("/api/scenarios", headers=headers)).status_code == 401


async def test_health_probes_stay_open_when_gated(client):
    """Orchestrator probes have no secret — gating them would break restarts."""
    settings.demo_access_token = "s3cret"
    assert (await client.get("/healthz")).status_code == 200
    assert (await client.get("/readyz")).status_code in (200, 503)


# ── Custom-doc upload / delete guards (previously untested) ──────────────────

async def test_delete_custom_doc_rejects_non_txt(client):
    resp = await client.delete("/api/docs/custom/evil.sh")
    assert resp.status_code == 400


async def test_delete_custom_doc_strips_path_traversal(client):
    """`../../.env` must resolve to a bare filename inside the docs dir, never escape it."""
    resp = await client.delete("/api/docs/custom/..%2F..%2F.env")
    assert resp.status_code in (400, 404)          # never 200
    assert main.ENV_PATH.exists()                  # the real .env is untouched


async def test_upload_rejects_non_txt(client):
    files = {"file": ("evil.sh", b"#!/bin/sh\nrm -rf /", "application/x-sh")}
    resp = await client.post("/api/docs/upload", files=files)
    assert resp.status_code == 400


async def test_upload_rejects_oversize_file(client):
    big = b"x" * (main.MAX_FILE_SIZE_BYTES + 1024)
    files = {"file": ("big.txt", big, "text/plain")}
    resp = await client.post("/api/docs/upload", files=files)
    assert resp.status_code == 413


# ── Request validation ───────────────────────────────────────────────────────

async def test_invalid_docs_mode_is_rejected(client):
    assert (await client.post("/api/docs-mode", json={"mode": "nonsense"})).status_code == 400


async def test_oneshot_rejects_concurrency_over_cap(client):
    resp = await client.post("/api/oneshot", json={"concurrency": main.MAX_CONCURRENCY + 1})
    assert resp.status_code == 422                 # pydantic bound


# ── Asset caching (DEPLOYMENT_REVIEW.md §6.2) ────────────────────────────────
# The hand-bumped `?v=2` query strings were removed; revalidation is now what
# keeps a deploy from serving stale JS against a new backend.

async def test_app_shell_and_assets_always_revalidate(client):
    for path in ("/", "/assets/onboarding.css"):
        r = await client.get(path)
        assert r.status_code == 200, path
        assert r.headers.get("cache-control") == "no-cache", path
        # no-cache is only cheap because a validator makes the 304 possible
        assert r.headers.get("etag") or r.headers.get("last-modified"), path


async def test_api_responses_are_not_forced_to_revalidate(client):
    """Scoped to static paths on purpose — blanketing /api would be noise."""
    r = await client.get("/healthz")
    assert "cache-control" not in {k.lower() for k in r.headers}


# ── No third-party origins (DEPLOYMENT_REVIEW.md §3.6) ───────────────────────
# Fonts were vendored so the demo makes ZERO third-party requests: a security
# product that phones home to a CDN on every page load undercuts its own pitch,
# and the CDN broke air-gapped deploys outright. The easy regression is someone
# pasting a CDN <link> back in, so pin both halves.

async def test_csp_allows_no_remote_origin_at_all(client):
    csp = (await client.get("/")).headers["content-security-policy"]
    assert "http://" not in csp and "https://" not in csp, csp
    assert "font-src 'self' data:" in csp     # data: is for the exported report


def test_the_page_loads_no_external_stylesheet_or_font():
    html = (Path(__file__).resolve().parents[2] / "frontend" / "index.html").read_text(encoding="utf-8")
    head = html[:html.index("</head>")]
    assert "fonts.googleapis.com" not in head and "fonts.gstatic.com" not in head
    assert 'href="/assets/fonts.css"' in head


async def test_vendored_fonts_are_actually_served(client):
    """A stylesheet referencing files that 404 is worse than the CDN was."""
    css = await client.get("/assets/fonts.css")
    assert css.status_code == 200
    refs = re.findall(r"url\('([^']+)'\)", css.text)
    assert refs, "no @font-face src rules"
    for ref in refs:
        r = await client.get(f"/assets/{ref}")
        assert r.status_code == 200, ref
        assert r.content[:4] == b"wOF2", ref
