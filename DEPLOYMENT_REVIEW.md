# Deployment Readiness Review

A full read-through of the project — **architecture, features, mechanism, UI/UX** — with
prioritised improvements and concrete steps.

Scope note: this is *complementary* to [`IMPROVEMENT_PLAN.md`](IMPROVEMENT_PLAN.md), which
tracks **feature** parity vs promptfoo (mostly delivered). This document covers everything
else: **how the thing runs, scales, is observed, and is maintained** when deployed.

Reviewed at ~18.7k LOC · 271 passing unit tests · commit `cadc42e`.

---

## 0. Executive summary

The project is in **good shape**. The security posture is genuinely thoughtful (CSRF origin
checks, CSP, COOP/CORP, Permissions-Policy, SSRF metadata-host blocking with an honest
docstring about its DNS-rebinding limit, correct `esc()` XSS discipline, secrets never in
`localStorage`). Test coverage is broad. Docs are unusually complete (888-line README).

It is, however, built as a **single-process, single-user demo**, and several sharp edges only
bite at deployment time. Nothing here is a rewrite — the highest-value fixes are small and
mostly mirror patterns the codebase *already* uses correctly elsewhere.

**The five things that matter most:**

| # | Issue | Impact | Effort |
|---|---|---|---|
| 1 | Module-level mutable global state | Caps deploy at **1 worker**; config bleeds across users | Doc it (S) / fix (L) |
| 2 | No auth on 33 endpoints (incl. file write + `.env` write) | Anyone who reaches the port controls the box | S–M |
| 3 | `llm.py` opens a new TLS connection per LLM call | Dominant cost in large runs | **S** |
| 4 | No health endpoint / unpinned deps / no log config | Can't orchestrate or debug it | **S** |
| 5 | `history.list_runs()` fully parses every run file | Listing 10 big runs reads ~GBs | **S** |

Items 3–5 are a few hours total and give the biggest return.

---

## 1. Architecture

### 1.1 — Module-level mutable global state ⚠️ **the defining constraint**

`backend/main.py` holds runtime config in module globals:

```
_doc_mode, _custom_system_prompt, _cli_knowledge_base,
_llm_config, _judge_config, _lakera_key, _lakera_project_id, _datasets
```

**Consequences**
- **Single worker only.** `uvicorn --workers 2` silently breaks: each worker has its own
  copy, so a config write lands in one worker and later reads hit another. The current
  `Dockerfile` CMD happens to be correct (no `--workers`), but nothing *enforces* it.
- **No horizontal scale.** Two replicas behind a load balancer diverge the same way.
- **Multi-user cross-talk.** It's a global config, not a session: if two people open the
  demo, one changing the model/provider/Guard key changes it for the other, mid-run.
- Restart loses all imported datasets and the custom system prompt.

**Steps — pick the tier that matches the deployment**

- **Tier A (recommended for a demo — 30 min).** Accept the constraint, make it explicit:
  1. Add a startup assert/warn if more than one worker is detected.
  2. Document "single worker, single tenant" in the README's new Deployment section (§5.2).
  3. Pin `--workers 1` explicitly in `Dockerfile`/compose so nobody "optimises" it later.
  4. If >1 concurrent user is expected, put it behind per-user instances, not per-user state.
- **Tier B (real multi-user — 1–2 days).** Introduce a `RunConfig` object resolved per
  request (from a signed session cookie or an explicit `X-Session-Id`), with the globals as
  the *default* fallback. Thread it through `chat.process` / `run_oneshot`, both of which
  **already take config as parameters** — the plumbing exists; only `main.py`'s handlers
  need to stop reading globals. Move `_datasets` to Redis or a small SQLite table.

> The pipeline itself is already well-factored for this: `run_oneshot(req, *, llm_config,
> lakera_key, judge_config, ...)` takes an explicit snapshot. The coupling is confined to
> the HTTP handlers.

### 1.2 — Duplicated report renderer (drift risk, already bitten)

The one-shot HTML report is implemented **twice**:
- `backend/report_html.py` (Python, for the CLI), and
- `buildHtmlReport()` in `frontend/index.html` (JS, for the browser export).

They must emit structurally identical output. `report_html.py` even *scrapes the frontend's
`<style>` blocks* to stay in sync — and that coupling already caused a real bug this cycle
(the scraper captured the JS exporter's `'<style>'` **string literals** as CSS, silently
dropping the report's scroll rule). Every future report change must be made in both places.

**Steps**
1. Short term (done): keep the regression test that asserts the extracted CSS contains no JS.
2. Medium (½ day): make the **Python** renderer the single source of truth and have the
   browser "Export HTML" call a `GET /api/oneshot/report.html` endpoint instead of rebuilding
   the document client-side. Deletes ~250 lines of duplicated JS and removes the drift class
   entirely. The browser already has the payload; it just needs to POST it and download.
3. Move the report's CSS into its own `report.css` consumed by both, instead of scraping.

### 1.3 — In-memory dataset store is unbounded in practice

`_datasets` caps at `MAX_DATASETS = 12` *slots*, but each slot holds up to
`MAX_ROWS = 100_000` rows → **up to 1.2M rows resident**, never evicted, lost on restart.
The CLI path (`oneshot._store_cli_dataset`) bypasses the cap entirely by design.

**Steps**
1. Add a **total row budget** (e.g. 250k across all slots) alongside the slot cap, rejecting
   the import that would exceed it with a clear message.
2. Report memory in `/api/datasets` (`rows`, approx bytes) so the UI can show pressure.
3. For anything long-lived, spill to SQLite (`prompt`, `category`, `tactics`) — it's already
   the shape of a table, and it removes the restart-loss problem.

---

## 2. Mechanism — correctness & performance

### 2.1 — 🔴 `llm.py` creates a new `httpx.AsyncClient` per call — **top perf fix**

`backend/llm.py` lines **201**, **228**, **271**:

```python
async with httpx.AsyncClient() as client:   # ← new pool + TLS handshake, every call
    resp = await client.post(endpoint, ...)
```

Meanwhile `backend/lakera.py` does exactly the right thing, with a comment explaining why:

> *"reusing keep-alive connections (instead of a fresh `httpx.AsyncClient()`) is what makes
> 100-way parallelism fast."*

So the LLM path has the precise problem the Guard path already solved. With judging enabled
that's **2 LLM calls per scenario** — a 30k-scenario run pays ~60k TLS handshakes.

**Steps (~1 hour, low risk — copy the proven local pattern)**
1. Port `lakera.py`'s `_LIMITS` / `_get_client()` / `aclose()` trio into `llm.py`.
2. Replace the three `async with httpx.AsyncClient()` blocks with `client = await _get_client()`.
3. Call `llm.aclose()` from the FastAPI `lifespan` shutdown and the CLI's `finally` block
   (both already call `lakera.aclose()` — add one line each).
4. Keep the per-call `timeout=` argument; it works fine on a shared client.
5. Verify: time a `--max-scenarios 50` run before/after.

> ⚠️ One nuance: the client must **not** be bound to a base URL, since users switch providers
> at runtime. `lakera.py` already documents this exact pattern ("isn't bound to a host — every
> call passes the full URL"), so follow it.

### 2.2 — 🔴 `history.list_runs()` parses every run file to list metadata

`backend/history.py:49` — the docstring promises *"no heavy results payload"*, which is true
of the **return value** but not the **cost**: it `json.loads()` the entire file, including the
full `results` array, for every run, then throws it away.

A saved 30,350-scenario run is **~100 MB**. Listing 10 of them parses ~1 GB and can stall the
event loop for seconds (`GET /api/history` is `async`, so this blocks *all* requests).

**Steps (~1 hour)**
1. In `history.save()`, also write a sidecar `{id}.meta.json` containing only
   `{id, saved_at, label, metrics, posture}`.
2. `list_runs()` reads `*.meta.json` only; fall back to the full parse **once** for legacy
   files and write the sidecar as a lazy migration.
3. Drop `indent=2` from the big payload (`history.py:45`) — it roughly doubles the file size
   on large runs. Keep it for the sidecar.
4. Add a retention policy (keep N newest, or prune > X days) — nothing prunes `runs/` today.

### 2.3 — `rag.retrieve()` re-reads and re-lowercases documents on every call

`backend/rag.py:20-23` globs the folder, `read_text()`s each doc, and calls
`content.lower()` **per scenario**. In a 30k-row run that's ~60k file reads and 60k
full-document string allocations for two documents that never change.

**Steps (~1 hour)**
1. Extract `_load_docs(mode)` returning `[(filename, content, content_lower)]`.
2. Cache it — but key on the folder's **mtime**, because `docs_custom` is user-writable:
   ```python
   @lru_cache(maxsize=8)
   def _load_docs(mode: str, _stamp: float): ...
   def _folder_stamp(folder): return max((p.stat().st_mtime for p in folder.glob("*.txt")), default=0)
   ```
3. Or simpler and equally lazy: keep the cache and call `_load_docs.cache_clear()` from the
   three custom-doc mutation endpoints (upload / delete / activate).
4. Guard with a test that uploading a custom doc is visible to the very next retrieval.

### 2.4 — CP2 scans RAG documents sequentially

`backend/chat.py:191` — `for doc in docs: await lakera.check(...)`. With 2 docs that's two
serial round trips on every guarded message, inside the latency-critical path.

**Step:** replace with `asyncio.gather(*(lakera.check(d["content"], ...) for d in docs))` and
zip the results back. ~20 lines. Keeps ordering (gather preserves input order), halves CP2
latency, and the shared rate limiter still bounds throughput. Note the trace's `cp2_latency`
should then become `max()` (wall time) rather than `sum()`, or be relabelled.

### 2.5 — Broad exception handling (12 sites)

12 `except Exception` blocks. Most are deliberate and *correct* (e.g. `_run_one`'s
"record, don't abort the whole batch"). Worth a pass to confirm each either re-raises,
logs with `exc_info`, or is documented as intentional — a couple currently swallow silently.

---

## 3. Deployment & operations

### 3.1 — 🔴 No health endpoint, no container healthcheck

Nothing for Docker `HEALTHCHECK`, k8s liveness/readiness, or a load balancer to probe.

**Steps (~30 min)**
1. Add to `main.py`:
   ```python
   @app.get("/healthz")          # liveness — process is up
   async def healthz(): return {"ok": True}

   @app.get("/readyz")           # readiness — can actually serve
   async def readyz():
       return {"ok": bool(_lakera_key), "lakera_key_set": bool(_lakera_key),
               "provider": _llm_config.get("provider")}
   ```
   Keep them unauthenticated and free of secrets.
2. `Dockerfile`: `HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
   CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/healthz')"`
3. `docker-compose.yml`: add the equivalent `healthcheck:` block.

### 3.2 — 🔴 Unpinned dependencies → non-reproducible builds

`requirements.txt` uses `>=` for everything (`fastapi>=0.111.0`, …). Two builds a week apart
can ship different FastAPI/pydantic majors. There is no lockfile.

**Steps (~30 min)**
1. Generate a pinned lock: `pip freeze > requirements.lock` (or adopt `uv`/`pip-tools`).
2. `Dockerfile` installs from the **lock**; keep the loose `requirements.txt` for local dev.
3. Add Dependabot/Renovate to bump the lock deliberately.
4. Pin the base image by digest (`python:3.12-slim@sha256:…`) for real reproducibility.

### 3.3 — 🔴 Logging is created but never configured

`main.py:17` creates `logger = logging.getLogger("lakera_demo")` — with **no**
`basicConfig`, no handler, no formatter. Total log volume across the entire backend is
**8 statements** (1 debug / 4 warning / 3 exception). `logger.debug` output is invisible.

**Steps (~2 hours)**
1. Configure logging on startup (respect `LOG_LEVEL` env), or hand off to uvicorn's
   `log_config` so app logs share its format.
2. Emit JSON lines in container mode so logs are ingestible.
3. Add a request-ID middleware and include it on every log line + error response, so a user
   can quote an ID from a failure.
4. Log the events that actually matter operationally: run started/finished (with scope +
   row count), Guard/LLM error rates, rate-limit saturation, dataset imports.
5. Do **not** log prompts/responses by default — this app handles adversarial content and
   PII fixtures. Gate that behind an explicit `LOG_PROMPTS=1`.

### 3.4 — No authentication on any endpoint

All 33 endpoints are unauthenticated, including genuinely powerful ones:
`POST /api/config/save-env` (**writes the host `.env`**), `POST /api/docs/upload`,
`DELETE /api/docs/custom/{filename}`, `POST /api/lakera-config` (sets the Guard key).

This is *deliberate and fine* for a loopback demo — `docker-compose.yml` binds `127.0.0.1`
and says so. The risk is that someone deploys it to a shared host or a cloud VM.

**Steps**
1. **Document the boundary loudly** (§5.2) — it's currently one line buried at README:358.
2. Add an opt-in shared-secret gate for non-loopback use: if `DEMO_ACCESS_TOKEN` is set,
   require it via header/cookie on all `/api/*` routes (~40 lines of middleware).
3. Refuse to start with a clear error if bound to `0.0.0.0` **and** no token is set —
   turns a silent exposure into a loud one.
4. Consider disabling `save-env` entirely when `DEMO_READONLY=1`, for shared demos.

### 3.5 — Container & compose hardening

- ✅ Already good: non-root `appuser`, `.dockerignore` excludes `.env`/`.git`/`.venv`.
- **No resource limits** in compose → a 100k-row run can consume all host memory.
  Add `deploy.resources.limits` (e.g. `memory: 2g`) and `mem_limit` for compose v2.
- **`.env` bind-mount is fragile**: mounting a *file* requires it to pre-exist or Docker
  creates a directory. Already documented, but prefer mounting a `./config/` **directory**
  and writing `config/.env` inside it — removes the sharp edge.
- `COPY . .` pulls in `tests/`, `datasets/`, docs. Consider copying only `backend/`,
  `frontend/`, `requirements*.txt` for a leaner, less-attack-surface image.
- Multi-stage build isn't needed (no compile step) — **skip it**, it would add complexity
  for ~no gain here.

### 3.6 — External CDN dependency (Google Fonts)

`index.html:7-9` preconnects and loads Lexend / Source Sans 3 / JetBrains Mono from
`fonts.googleapis.com`, and the CSP explicitly allows those hosts.

Breaks in air-gapped/enterprise deployments and adds a third-party request on every load
(a consideration for a *security* product demo).

**Steps (~1 hour):** vendor the three fonts into `frontend/assets/fonts/`, serve locally with
`font-display: swap`, and tighten the CSP by dropping the two Google hosts. Bonus: removes
two DNS+TLS round trips from first paint.

---

## 4. Testing & CI

**Current state is solid**: 271 offline unit tests, `pytest.ini` correctly defaults to the
offline suite so a bare `pytest` never spends API budget, CI runs unit tests + a `--dry-run`
suite validation before the gated live run. That's a good design.

### 4.1 — Zero HTTP-layer tests

Every test calls functions directly; **no test exercises a FastAPI route**. All 33 endpoints
— request validation, status codes, error mapping, the security middleware — are untested.
A broken Pydantic model or a changed status code ships silently.

**Steps (~½ day, high value per line)**
1. Add `httpx.ASGITransport` + `AsyncClient(app=app)` fixture in `tests/unit/conftest.py`
   (no server needed, no network).
2. Cover the highest-risk routes first: `/api/chat`, `/api/oneshot`, `/api/config/save-env`,
   `/api/docs/upload`, `/api/lakera-config`.
3. Explicitly test the **security middleware**: a cross-origin `POST` must 403; responses
   must carry CSP/`X-Frame-Options`. That behaviour is a selling point and is currently
   unverified.
4. Lock in the **existing** upload/delete guards as regression tests — these are already
   implemented correctly (`DELETE /api/docs/custom/{filename}` strips path components via
   `pathlib.Path(filename).name`; uploads are size- and extension-checked), but nothing
   currently proves they stay that way: oversize → 413, non-`.txt` → rejected, traversal
   attempt → rejected.

### 4.2 — Integration tests fail noisily by default

`tests/integration/` (49 tests) requires a live Lakera key and fails when absent — which
looks like breakage during any full-suite run.

**Step:** add a module-level
`pytestmark = pytest.mark.skipif(not os.getenv("LAKERA_GUARD_API_KEY"), reason="live key")`
so they **skip** rather than fail. One line, removes real confusion.

### 4.3 — No frontend tests

4,691 lines of JS with zero tests. Full framework-based testing is **not** worth it here.

**Step (proportionate):** add a handful of Playwright smoke tests for the flows that break
silently — language switch renders Korean, one-shot modal opens and filters rows, onboarding
completes. Skip unit-testing individual JS functions.

---

## 5. Documentation

The README is genuinely strong (888 lines, architecture diagram, OWASP mapping, provider
setup). Two gaps:

### 5.1 — `CLI_ONESHOT_GUIDE.md` is current ✅ (kept up to date this cycle)

### 5.2 — 🔴 Missing a "Deployment & Security Boundary" section

The security posture exists only as scattered lines (README:358, a compose comment, an SSRF
docstring). Someone deploying this has no single place to learn the rules.

**Step (~1 hour):** add one README section covering:
- **Single worker / single tenant** — why, and what breaks otherwise (§1.1).
- **No authentication** — bind to loopback; use the token gate for anything else (§3.4).
- **Secrets** — `.env` on disk, never in `localStorage`, masked in API responses.
- **What the demo intentionally does not defend against** (DNS rebinding, a hostile operator
  supplying the base URL). The SSRF docstring is admirably honest — surface that honesty.
- A **production-hardening checklist** for anyone adapting it beyond a demo.

---

## 6. UI/UX

Baseline is good — dark-mode OLED palette matched to a data-dense security dashboard, global
`:focus-visible`, global `prefers-reduced-motion` reset, correct `esc()` XSS discipline,
sensible 920/640px breakpoints, 5-language i18n with graceful English fallback.

### 6.1 — One-shot results table has no responsive treatment
The 8-column `.os-table` (Scenario · OWASP · Variant · Expected · Checkpoints · Guard ·
Model · Latency) lives in a `min(1080px, 100%)` modal and gets **no** adaptation at either
breakpoint — the 920/640px blocks touch header/main/chat only.

**Steps:** wrap the table in an `overflow-x: auto` container (prevents *page* overflow — the
skill's rule is no horizontal scroll on the **body**, a contained scroll region is fine);
below 640px hide the lower-value columns (Variant, Expected, Latency) via CSS, keeping
Scenario / Guard / Model; the row-detail reveal already carries the full data.

### 6.2 — Smaller polish items
- **Filter state isn't reflected in a count.** After filtering the exported report, add
  "showing N of M" so an empty result doesn't read as a broken table.
- **`?v=2` manual cache-busting** on the three JS/CSS assets — easy to forget on deploy.
  Generate the query string from file mtime/hash at render time.
- **Dense data labels remain < 12px** (badges, codes, table meta). This is a deliberate
  density trade-off for a dashboard — **leave it**; only raise a label if it's reported
  unreadable. (Prose help text was already raised to 12px.)
- **Empty/error states** for the one-shot table (no results, run failed) are worth a pass.

---

## 7. Deliberately NOT recommended

Being explicit about what to skip is as useful as the list above:

- ❌ **Frontend framework migration (React/Vue).** The vanilla app works, is fast, and has no
  build step. Migrating is weeks of risk for zero user-visible gain.
- ❌ **Multi-stage Docker build.** No compile step — pure ceremony here.
- ❌ **Splitting `main.py` into routers *purely* for line count.** Only worth it if §1.1
  Tier B happens, and then the refactor should follow the state change, not precede it.
- ❌ **A general-purpose plugin/eval framework.** Already correctly ruled out in
  `IMPROVEMENT_PLAN.md`.
- ❌ **Exhaustive JS unit tests.** A few Playwright smoke tests give ~90% of the value.
- ❌ **Kubernetes manifests / Helm chart** unless there's a real multi-tenant requirement —
  §1.1 means it can't scale horizontally today anyway.

---

## 8. Suggested execution order

**Sprint 1 — "deployable" — ✅ DONE.** Highest value per hour; all low-risk.
1. ✅ `llm.py` connection pooling (§2.1) — shared pooled client mirroring `lakera.py`;
   `aclose()` wired into the FastAPI lifespan and the CLI's `finally`. +5 tests, incl. a
   regression test that fails if a per-call client is ever reintroduced.
2. ✅ `/healthz` + `/readyz` (§3.1) — liveness always 200; readiness 503 until a Guard key
   is set, secret-free payload. Dockerfile `HEALTHCHECK` + compose `healthcheck` (stdlib
   urllib, no curl needed). +5 HTTP-layer tests — these also establish the **ASGI test
   fixture** §4.1 asks for.
3. ✅ Pinned deps (§3.2) — `requirements.lock`, 28 packages, hash-pinned, resolved against
   **Python 3.12** to match the image (local is 3.14). Verified by a clean-room
   `--require-hashes` install + app boot. Dockerfile and CI now install from it.
   Bonus: the image previously `COPY . .`-ed **338 MB** of `datasets/` + `reports/` (the
   latter containing run outputs); now an explicit allow-list, with `.dockerignore` as
   backstop.
4. ✅ `history.list_runs()` sidecar (§2.2) — `<id>.meta.json` written on save, legacy runs
   back-filled once, `delete()` cleans both, `indent=2` dropped. Listing an 8.5 MB run went
   from a full parse to **0.3 ms**. +5 tests, incl. one asserting the payload is never read.
5. ✅ Integration tests (§4.2) — now **49 skipped in 0.04 s** without a key. Fixed two real
   bugs found while doing it (see below).

> **Two live bugs found and fixed during item 5.** The suite wasn't merely "failing without
> a key" — it was **broken outright on Python 3.12+**: `asyncio.get_event_loop()
> .run_until_complete()` raises `RuntimeError: There is no current event loop`
> (→ `asyncio.run()`). It also **hardcoded the Community endpoint**, which a region-scoped
> key rejects with HTTP 400 (→ honour `LAKERA_ENDPOINT`). Result with a key:
> **49 failed → 42 passed / 7 failed**.
>
> The remaining **7 are live-policy expectation drift, not code**: 6 assert
> `is_flagged(...)` on fixtures the current Guard policy no longer flags, and 1 safe
> baseline is now flagged (false positive). Deliberately **not** "fixed" by loosening the
> assertions — that would delete the signal. Triage separately: re-baseline the fixtures
> against the target project's policy, or scope them to a project whose policy asserts them.

Unit suite after Sprint 1: **286 passing** (was 271).

**Sprint 2 — "operable" — ✅ DONE.**
6. ✅ Logging + request IDs (§3.3) — new `backend/logging_setup.py`: configured handler
   honouring `LOG_LEVEL`, optional `LOG_JSON` for collectors, and a `contextvar` request id
   stamped on every log line. The id is echoed as `X-Request-ID` and an **inbound** id is
   preserved so traces join across proxies. Startup/shutdown now log the effective config.
   `LOG_PROMPTS` defaults **off** — this app handles adversarial content and PII fixtures.
7. ✅ HTTP-layer tests (§4.1) — **+28 tests** over the real ASGI app, with the `client`
   fixture promoted to `tests/unit/conftest.py`. Covers the CSRF origin guard (reject
   cross-origin POST/DELETE, allow same-origin, allow no-Origin clients, don't touch GET),
   all five security headers + CSP, request-id behaviour, the token gate, and the
   upload/delete guards that had **no** coverage. Mutation-checked: disabling the CSRF
   check or dropping a header makes exactly the right tests fail.
8. ✅ README **Deployment & Security Boundary** (§5.2) — the three constraints
   (single-worker/single-tenant, no-auth default, secrets handling), an explicit
   *"what this does not defend against"* table (DNS rebinding, hostile operator, denial of
   wallet, no multi-user isolation), the ops/env-var reference, health-probe semantics, and
   a production-hardening checklist.
9. ✅ `DEMO_ACCESS_TOKEN` gate + refuse-to-start-exposed (§3.4) — opt-in shared secret on
   `/api/*` accepting `Authorization: Bearer` or `X-Demo-Token`, compared with
   `secrets.compare_digest` (no timing leak). Health probes stay open so orchestrators keep
   working. The app **refuses to boot** on a non-loopback bind with no token — detecting the
   host from `UVICORN_HOST`/`HOST` *and* the `--host` CLI flag, while exempting containers
   (binding `0.0.0.0` there is required; the published port is the real boundary).
10. ✅ Compose hardening (§3.5) — `mem_limit: 2g` (Sprint 1) plus the `.env` **file** mount
    replaced by a `./config` **directory** mount, removing the "you must `touch .env` first
    or Docker creates a directory" footgun. `ENV_FILE` makes the write target configurable;
    the default path is unchanged for non-Docker users.

Unit suite after Sprint 2: **314 passing** (271 → 286 → 314).

**Sprint 3 — "efficient & polished" (≈2 days).**
11. `rag.retrieve()` caching (§2.3) · CP2 `gather` (§2.4)
12. Dataset row budget (§1.3)
13. Responsive results table + filter counts (§6.1, §6.2)
14. Self-hosted fonts (§3.6)

**Backlog — architectural, only if the requirement is real.**
15. Per-session config (§1.1 Tier B)
16. Single-source report renderer (§1.2)
17. Playwright smoke tests (§4.3)

---

*Generated from a full read-through of backend (14 modules), frontend (4 files), tests
(19 files), docs, and deployment config.*
