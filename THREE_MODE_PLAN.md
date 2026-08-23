# Three-Function Split — Implementation Plan

Split the demo into three named functions that share one shell:

| # | Mode | Route | Purpose | Backend today |
|---|------|-------|---------|---------------|
| 1 | **Demo** (chat) | `#/chat` | OWASP LLM Top 10 scenario walkthrough, live checkpoint trace | `/api/chat` + friends — complete |
| 2 | **Benchmark** (one-shot) | `#/bench` | Fire a built-in category or an imported/uploaded dataset at *our* pipeline | `/api/oneshot*` — complete |
| 3 | **Target Test** | `#/target` | Fire a custom dataset at *someone else's* API endpoint, scanned by Guard | **does not exist** |

Modes 1 and 2 are a UI reorganisation of code that already works. Mode 3 is the only
real feature build.

---

## 0. What exists today (verified)

**Frontend** is one page, `frontend/index.html` (7,156 lines: 1,440 lines of inline
`<style>`, an SVG sprite, the markup, then a 5,100-line inline `<script>`), plus
`scenarios.js`, `appstate.js`, `onboarding.js`, `onboarding.css`, `fonts.css` served
from `/assets` ([main.py:2430](backend/main.py:2430)).

Layout: `<header>` control strip → scenarios bar → `.main` (chat panel + Security Trace
inspector) → two modal overlays (`#riskmap-overlay`, `#oneshot-overlay`).

The whole of function 2 currently lives **inside a modal toolbar** — eight `<details>`
drawers (Checkpoints/Projects, Strategies, Limits, History, Datasets, System prompt,
Knowledge base) crammed above `#os-body` ([index.html:1834-1975](frontend/index.html:1834)).

There is already a two-level view switch: `Onboarding.applyEnvironment()` toggles
`body.env-basic` / `body.env-advanced`, and one CSS rule hides the advanced controls —
`body.env-basic [data-adv] { display: none !important; }`
([onboarding.css:193](frontend/onboarding.css:193)). Mode switching reuses this exact
mechanism, not a second one.

**Backend** is already cleanly split by endpoint family — `/api/chat` →
`chat.process*`, `/api/oneshot`, `/api/oneshot/stream` → `_prepare_oneshot_rows` +
`_run_one_resilient`. Nothing needs restructuring for modes 1–2.

**The blocker for mode 3:** the target LLM is a single process-global,
`_llm_config`, set by `POST /api/llm-config`. Both one-shot endpoints snapshot it
(`llm_config=dict(_llm_config)`, [main.py:2151](backend/main.py:2151)). Good news:
`llm_config` is already threaded as a plain dict through `chat.process*` →
`chat._call_llm` → `llm.complete*`, so a per-run override is a parameter change, not
a refactor.

Also relevant: `_reject_metadata_url()` ([main.py:212](backend/main.py:212)) already
does SSRF filtering on operator-supplied URLs, with tests in
[test_ssrf.py](tests/unit/test_ssrf.py). Mode 3 reuses it rather than writing a second one.

---

## 1. UI contract — read before touching any markup

**Rule: no new visual language.** Every new screen is assembled from classes and
tokens that already exist. If a new class is needed, it borrows an existing rule
rather than inventing values.

### 1.1 Tokens (already defined at [index.html:15](frontend/index.html:15))
Surfaces `--bg` → `--bg-soft` → `--panel` → `--panel-2`; lines `--border`,
`--border-soft`; text `--heading` / `--text` / `--muted`; accent `--brand`,
`--brand-bg`, `--brand-br`. Semantics **must** stay on their meaning:
`--pass` green = allowed/clean, `--block` red = blocked/breach, `--redact` amber =
redacted/warning, `--skip` grey = disabled/not-applicable.
Shape: `--radius` (12px) for panels, `--radius-sm` (8px) for controls/inputs.
Motion: `0.15s var(--ease)`.

### 1.2 Type roles
- `'Lexend'` — every label, button, section title. Uppercase, `0.66–0.82rem`,
  `letter-spacing: 0.04–0.12em`, weight 600–700.
- `'Source Sans 3'` — prose, hints, descriptions.
- `'JetBrains Mono'` — all data: inputs, URLs, model ids, counts, table cells,
  JSON. Numeric readouts already get `font-variant-numeric: tabular-nums`
  ([index.html:1130](frontend/index.html:1130)) — new numeric readouts join that list.

### 1.3 Components to reuse (do not re-create)
| Need | Use | Defined |
|---|---|---|
| Header button / toggle | `.ctl`, active state `.ctl.on` (copy `#sp-mode-badge.custom`) | [:139](frontend/index.html:139) |
| Panel button | `.sp-btn`, `+.primary` / `.safe` / `.danger` | [:246](frontend/index.html:246) |
| Config group card | `.os-ds-panel` + `.os-ds-row` + `.os-ds-label` | [:889](frontend/index.html:889) |
| Text / number input | `.os-ds-panel input[type=text|number]` (mono, `--bg` fill) | [:892](frontend/index.html:892) |
| Checkbox + label | `.os-judge-toggle` | [:856](frontend/index.html:856) |
| Collapsible drawer | `.os-strats > summary` | [:867](frontend/index.html:867) |
| Warning note | `.os-ds-allnote` (amber) | [:914](frontend/index.html:914) |
| Inline status line | `.cp0-result` | used by sp / cdocs / ds panels |
| List of items w/ delete | `.os-ds-list` / `.os-ds-item` / `.os-ds-del` | [:907](frontend/index.html:907) |
| Result stats / hero / compare / table / legend | `.os-summary`, `.os-stat`, `.os-hero`, `.os-compare`, `.os-legend`, `.os-table*` | [:1032](frontend/index.html:1032)+ |
| Scrolling side column | `.inspector-panel` rule (bg-soft, `overflow-y:auto`, `padding:18px 16px`, `gap:12px`) | [:541](frontend/index.html:541) |

### 1.4 Responsive
Two breakpoints exist and both stay authoritative: **920px** collapses every
two-column grid to one and lets the body scroll ([:1420](frontend/index.html:1420));
**640px** stacks the header ([:1428](frontend/index.html:1428)). New grids must be
listed in the 920px rule; new header items inherit the 640px rule automatically by
living inside `.header-controls`.

### 1.5 Accessibility (match what's already there)
Mode nav is `role="tablist"` / `role="tab"` with `aria-selected`; each
`<section class="mode">` is `role="tabpanel"` with `aria-labelledby`. Progress and
status regions use `aria-live="polite"` like `#rm-stats`. Touch targets stay ≥44px
as the 640px rule already enforces for `#clear-chat-btn`. Focus keeps the global
`:focus-visible` outline — never remove it on a new control.

---

## 2. Shell: one page, three modes

**Decision: keep one HTML page.** Three separate pages would need three copies of the
1,440-line stylesheet, the icon sprite, the i18n table, the API helpers and the
onboarding wizard — or a build step this project doesn't have. A mode attribute on
`<body>` costs ~40 lines of CSS.

### 2.1 Mode nav — a segmented control in the header
First element inside `.header-controls`, before the language switch:

```html
<nav class="mode-nav" role="tablist" aria-label="Application mode">
  <button class="ctl" role="tab" id="tab-chat"   aria-selected="true"
          onclick="setMode('chat')"><svg class="ic"><use href="#i-send"></use></svg><span data-i18n="mode.chat">Demo</span></button>
  <button class="ctl" role="tab" id="tab-bench"  aria-selected="false"
          onclick="setMode('bench')"><svg class="ic"><use href="#i-play"></use></svg><span data-i18n="mode.bench">Benchmark</span></button>
  <button class="ctl" role="tab" id="tab-target" aria-selected="false"
          onclick="setMode('target')"><svg class="ic"><use href="#i-plug"></use></svg><span data-i18n="mode.target">Target Test</span></button>
</nav>
```

All three icons already exist in the sprite (`#i-send`, `#i-play`, `#i-plug`).

```css
/* Segmented control — same skin as .ctl, joined into one pill */
.mode-nav { display: inline-flex; }
.mode-nav .ctl { border-radius: 0; margin-left: -1px; }
.mode-nav .ctl:first-child { border-radius: var(--radius-sm) 0 0 var(--radius-sm); margin-left: 0; }
.mode-nav .ctl:last-child  { border-radius: 0 var(--radius-sm) var(--radius-sm) 0; }
.mode-nav .ctl[aria-selected="true"] {
  color: var(--brand); border-color: var(--brand-br); background: var(--brand-bg); z-index: 1;
}
@media (max-width: 640px) { .mode-nav { width: 100%; } .mode-nav .ctl { flex: 1; justify-content: center; } }
```

### 2.2 Visibility — one attribute, three rules
Mirrors `body.env-basic [data-adv]`. `data-only` lists the modes an element belongs
to; the rules only ever *hide*, so a visible element keeps its natural `display`:

```css
body[data-mode="chat"]   [data-only]:not([data-only~="chat"]),
body[data-mode="bench"]  [data-only]:not([data-only~="bench"]),
body[data-mode="target"] [data-only]:not([data-only~="target"]) { display: none !important; }

.mode { display: none; flex: 1; overflow: hidden; }
body[data-mode="chat"]   #mode-chat,
body[data-mode="bench"]  #mode-bench,
body[data-mode="target"] #mode-target { display: grid; }
```

This composes with `[data-adv]`: an element can be both mode-scoped and
advanced-only, and either rule can hide it.

### 2.3 `setMode`
```js
var MODES = ['chat', 'bench', 'target'];
function setMode(m) {
  if (MODES.indexOf(m) < 0) m = 'chat';
  document.body.dataset.mode = m;
  MODES.forEach(function (x) {
    document.getElementById('tab-' + x).setAttribute('aria-selected', String(x === m));
  });
  if (location.hash !== '#/' + m) location.hash = '#/' + m;
  localStorage.setItem('ai-demo-mode', m);
}
window.addEventListener('hashchange', function () { setMode(location.hash.replace('#/', '')); });
// boot: hash wins, then localStorage, then 'chat'
```
Deep-linkable and back/forward-safe, so a demo script can jump straight to a mode.

### 2.4 Element ownership
| Element | chat | bench | target |
|---|:--:|:--:|:--:|
| Brand, language, Setup, LLM badge | ✓ | ✓ | ✓ |
| Basic/Advanced switch (`#env-switch`) | ✓ | — | — |
| System-prompt badge, Guard toggle, Knowledge Base group, Risk Map | ✓ | — | — |
| `#pipeline-tutorial`, `.scenarios-bar`, `#sp-panel`, `#cdocs-panel` | ✓ | — | — |
| `#oneshot-btn` | **deleted** — it is a mode now | | |
| Target badge `#target-badge` (new) | — | — | ✓ |

Mark each chat-only node `data-only="chat"`. Risk Map stays a **modal**: it reads out
the chat session, it is not a workspace.

### 2.5 Shared two-column geometry
Both work modes use the same primitive — a fixed config rail plus a fluid results
pane — mirroring the chat's `1fr 384px`:

```css
#mode-bench, #mode-target { grid-template-columns: 340px 1fr; }
/* the rail reuses the inspector's skin */
.cfg-rail { display:flex; flex-direction:column; overflow-y:auto; padding:18px 16px; gap:12px;
            background: var(--bg-soft); border-right: 1px solid var(--border); }
.run-pane { overflow-y: auto; padding: 18px 20px; }
@media (max-width: 920px) {
  #mode-bench, #mode-target { grid-template-columns: 1fr; }
  .cfg-rail { border-right: none; border-bottom: 1px solid var(--border); }
}
```
Add both ids to the existing 920px block rather than writing a new media query.

### 2.6 Numbered step groups — the "simple to execute" bit
Every rail group is a numbered step, so the order of operations is visible without
reading docs. Built from `.os-ds-panel`, plus 12 lines:

```html
<section class="cfg-step" data-step="1">
  <h3><span class="cfg-num">1</span><span data-i18n="bench.step.scope">Scope</span>
      <span class="cfg-sum" id="bench-scope-sum">Built-in · 42 scenarios</span></h3>
  <div class="os-ds-panel"> … existing inputs, unchanged ids … </div>
</section>
```
```css
.cfg-step > h3 { display:flex; align-items:center; gap:8px; font-family:'Lexend',sans-serif;
  font-size:0.72rem; font-weight:600; letter-spacing:0.08em; text-transform:uppercase;
  color: var(--heading); margin-bottom: 8px; }
.cfg-num { display:grid; place-items:center; width:20px; height:20px; border-radius:50%;
  background: var(--brand-bg); border:1px solid var(--brand-br); color: var(--brand);
  font-size:0.68rem; font-weight:700; }
.cfg-sum { margin-left:auto; font-family:'JetBrains Mono',monospace; font-size:0.68rem;
  color: var(--muted); text-align:right; }
.cfg-step.done .cfg-num { background: var(--pass-bg); border-color: var(--pass-br); color: var(--pass); }
.cfg-step.todo .cfg-num { background: var(--block-bg); border-color: var(--block-br); color: var(--block); }
```
`.cfg-sum` always shows the group's current value ("42 scenarios", "CP1+CP3",
"100 × 3 strategies"), so a collapsed rail still reads as a run recipe.

---

## 3. Mode 1 — Demo (chat bot, OWASP Top 10)

Layout is unchanged; only ownership and copy change.

```
┌ header ── [Demo|Benchmark|Target] ·· lang · setup · prompt · LLM · guard · KB · risk map ┐
├ pipeline tutorial (details, Basic mode) ─────────────────────────────────────────────────┤
├ scenarios bar: Categories ▸ pills ·· Scenarios ▸ buttons ────────────────────────────────┤
│ ┌ chat panel (1fr) ───────────────────────┬ Security Trace (384px) ──────────────────┐   │
│ │ guard-off banner                        │ pipeline flow  Input›CP1›CP2›LLM›CP3›Rep │   │
│ │ messages …                              │ CP0 card / category card                 │   │
│ │ [textarea] [Clear] [Send]               │ CP1 / CP2 / CP3 cards                    │   │
└─┴─────────────────────────────────────────┴──────────────────────────────────────────┘   │
```

- **P1-1** Wrap the chat-only header controls and the three chat-only strips with
  `data-only="chat"`. No node moves.
- **P1-2** Audit `[data-adv]`: the ones on `#oneshot-btn` and its panels disappear
  with the button. Basic/Advanced now gates chat controls only.
- **P1-3** Mode intro strip above the scenarios bar — one `.sp-inner`-style line
  ("One message · four checkpoints · watch each one fire"), dismissible, remembered in
  localStorage. Sits alongside the existing `#pipeline-tutorial`.
- **P1-4** i18n keys for the mode names + intro (§7).

---

## 4. Mode 2 — Benchmark (custom dataset against our pipeline)

The capability is complete (HF import with streaming progress, file upload
`.csv/.json/.jsonl/.txt`, multi-dataset select, seeded sampling, strategies,
per-checkpoint project routing, judge, Guard ON-vs-OFF, history diff, HTML/JSON/CSV
export). This phase turns a cramped modal toolbar into a workspace.

```
┌ header ── [Demo|**Benchmark**|Target] ·· lang · setup · LLM ─────────────────────────┐
│ ┌ cfg-rail 340px ─────────────┬ run-pane 1fr ─────────────────────────────────────┐  │
│ │ ① Scope        42 scenarios │ ┌ run bar (sticky) ───────────────────────────┐   │  │
│ │   ▸ built-in / datasets     │ │ ▶ Run Test   ⣾ 37/300   Save  HTML JSON CSV │   │  │
│ │ ② Target       claude-3-opus│ └─────────────────────────────────────────────┘   │  │
│ │   (read-only, → LLM panel)  │  os-hero · os-compare · os-summary                │  │
│ │ ③ Guard        CP1+CP2+CP3  │  os-judge-info · os-lakera-summary · os-legend    │  │
│ │ ④ Attack       3 strategies │  os-table (filter, variants, evaded rows)         │  │
│ │ ⑤ Context      default SP   │                                                    │  │
│ │ ⑥ Limits       100 · conc 4 │                                                    │  │
│ │ ⑦ History      6 runs       │                                                    │  │
└─┴─────────────────────────────┴────────────────────────────────────────────────────┘  │
```

- **P2-1** Move each existing `<details class="os-strats">` body into a numbered
  `.cfg-step`. **Keep every id and every handler name** (`#os-scope`, `#os-judge`,
  `#os-max`, `#os-cp1`, `runOneShot()`, `importHfDataset()` …) so no JS changes in
  this phase. Groups in run order: Scope → Target → Guard → Attack → Context →
  Limits → History.
- **P2-2** Results pane keeps `#os-body` and the renderer verbatim.
- **P2-3** Sticky run bar at the top of `.run-pane`:
  `position: sticky; top: 0; z-index: 2; background: var(--bg); border-bottom: 1px solid var(--border);`
  holding `#os-run-btn`, `#os-running`/`#os-progress`, `#hist-save-btn` and the three
  export buttons. Progress keeps `aria-live="polite"`.
- **P2-4** Empty state in `.run-pane` before the first run: reuse `.os-empty`, add a
  one-line recipe of what will run, from the same `.cfg-sum` values.
- **P2-5** Dataset rows get count + a 3-row preview (`.os-ds-item` expands into a
  `.os-table`), so a wrong column mapping is visible *before* a 10,000-row run.
  Needs `GET /api/datasets/{slug}/preview` (or a `sample` field on `/api/datasets`) —
  ~15 lines, the rows are already in `_datasets`.
- **P2-6** Row maths before running: "12,043 available → 100 sampled × 3 strategies =
  300 rows", rendered from the `scope` dict `_prepare_oneshot_rows` already returns.
  Show it in `.cfg-sum` of ⑥ and in the empty state.

No other backend change.

---

## 5. Mode 3 — Target Test (custom endpoint + custom dataset) — the real build

**Goal:** point the harness at a third-party assistant API — a customer's chatbot, an
internal service, a gateway — feed it a custom dataset, and report what Lakera Guard
sees on the way in and on the way back.

### 5.0 Semantics — read this before building anything
A third-party endpoint is a **black box**: it owns its own system prompt and its own
RAG. So in mode 3:

- **CP1 (input scan)** applies — we scan each dataset prompt before forwarding.
- **CP3 (output scan)** applies — we scan whatever the endpoint returns.
- **CP0 / CP2 do not apply** — there is no system prompt and no knowledge base of
  ours in the loop. Force them off, render them `.cp-card.disabled-card` with the
  one-line reason. Reporting "CP2: 0 blocked" would be a lie about coverage.
- **Guard ON-vs-OFF is the headline output here** — it quantifies what Guard adds in
  front of an endpoint that is already in production. Default it **on** in this mode.
- **The judge must never be the target.** `_effective_judge_config()` falls back to
  `_llm_config`; under a per-run target override that would make the system under test
  grade its own answers. Mode 3 resolves the judge from the *global* config only and
  refuses the run (clear 400) if judging is requested with no judge configured.

### 5.1 `backend/llm.py` — an `http` target kind
A fifth provider kind alongside the presets:

```json
{
  "kind": "http",
  "url": "https://api.example.com/v1/assistant",
  "method": "POST",
  "headers": {"Authorization": "Bearer …", "X-Tenant": "acme"},
  "body": "{\"question\": {{prompt}}, \"session\": \"guard-test\"}",
  "response_path": "data.answer",
  "timeout": 60
}
```

- `{{prompt}}` substitutes the **JSON-encoded** text (`json.dumps`), so quotes and
  newlines cannot break the body — raw substitution would emit invalid JSON on the
  first prompt containing a `"`, which for an attack corpus is immediate. Also support
  `{{history}}` (JSON array) for multi-turn.
- `response_path` is a dotted path with numeric indices
  (`choices.0.message.content`), resolved by a ~10-line `_dig()`. Empty path → the
  whole body if it is a string, else a clear error.
- Dispatch at the top of `complete_chat()`: `kind == "http"` → `_complete_http()`,
  otherwise the existing OpenAI path runs unchanged. Every caller
  (`chat._call_llm`, `judge`, `attacker`, one-shot) then works with no edit.
- `complete_with_tools()` raises "tool-calling is not supported for HTTP targets" —
  the agentic scenarios are not runnable against a black box.
- Reuse `ratelimit.acquire()` and `describe_error()` so a failure lands in the existing
  per-row `error` field instead of killing the run.

### 5.2 Security
- `_reject_metadata_url(spec.url)` on every accept path: config, probe, run.
- Register the target's header values with `redact.register()` for the run's lifetime,
  so a bearer token cannot surface in an error body, a log line or a report — the same
  treatment `_lakera_key` and `llm_api_key` already get.
- Cap header count/size and body-template size in the pydantic model.
- Never persist the target to `.env`; per-run, in memory only.
- README note: this deliberately fetches an operator-supplied URL server-side; the
  existing DNS-rebinding caveat applies.

### 5.3 API
- `TargetConfig(BaseModel)` mirroring 5.1, `max_length` on every field.
- `OneShotRequest.target: TargetConfig | None = None`. When set, `/api/oneshot` and
  `/api/oneshot/stream` pass it as `llm_config` **instead of** `dict(_llm_config)`.
  The global is never written.
- `POST /api/target/test` — one sample prompt, returns
  `{ok, status, latency_ms, extracted, raw_body_preview}` (scrubbed, truncated) so the
  user can see the real response shape and pick `response_path` without guessing.
  **This is the highest-value piece of the mode**; without it every misconfiguration
  looks identical to "all rows errored".
- Reject `target` on `/api/chat` — mode 3 is batch-only, and the chat path's RAG/CP2
  semantics stay untouched.

### 5.4 CLI parity
`backend/oneshot.py` already has `--provider/--base-url/--model/--api-key`. Add
`--target-file target.json` loading the same spec, resolved in
`resolve_llm_config()`. The judge guard from 5.0 applies identically — the CLI is
where a CI gate will run this.

### 5.5 Frontend — same rail, three steps

```
┌ header ── [Demo|Benchmark|**Target Test**] ·· lang · setup · ⬤ endpoint OK ───────────┐
│ ┌ cfg-rail 340px ─────────────┬ run-pane 1fr ─────────────────────────────────────┐  │
│ │ ① Endpoint      ⬤ verified  │ ┌ run bar (sticky) ───────────────────────────┐   │  │
│ │   name  [ ShopEase prod  ]  │ │ ▶ Run Test  ⣾ 12/500  Save  HTML JSON CSV   │   │  │
│ │   POST ▾ [ https://…     ]  │ └─────────────────────────────────────────────┘   │  │
│ │   headers  k [ ] v [ ]  +   │  ⚠ CP0 & CP2 not applicable — this endpoint owns  │  │
│ │   body  {"q": {{prompt}}}   │    its own prompt and knowledge base.             │  │
│ │   path  [ data.answer    ]  │  os-hero · os-compare (Guard OFF vs ON) ·         │  │
│ │   timeout [60] [Test ▷]     │  os-summary · os-judge-info · os-table            │  │
│ │   ┌ probe result ────────┐  │                                                    │  │
│ │   │ 200 · 412 ms         │  │                                                    │  │
│ │   │ extracted: "Hi! …"   │  │                                                    │  │
│ │   │ ▸ raw body           │  │                                                    │  │
│ │   └──────────────────────┘  │                                                    │  │
│ │ ② Dataset      salad · 500  │                                                    │  │
│ │ ③ Run          judge · A/B  │                                                    │  │
└─┴─────────────────────────────┴────────────────────────────────────────────────────┘  │
```

- **P3c-1 Endpoint form** — all inputs are `.os-ds-panel` inputs (mono, `--bg` fill).
  `{{prompt}}` is highlighted in the body textarea's hint line, not in the textarea
  (no editor library). Header rows are `.os-ds-row` pairs with a `+`/`×` using
  `.sp-btn` / `.os-ds-del`.
- **P3c-2 Probe states** on `#target-badge` (header) and `.cp0-result` (rail),
  reusing semantic tokens exactly:
  | State | Chip | Colour |
  |---|---|---|
  | not tested | `Endpoint: untested` | `--skip` |
  | testing | `Endpoint: testing…` spinner (`#i-loader`, existing `spin` keyframe) | `--muted` |
  | 2xx + path resolved | `Endpoint: OK · 412 ms` | `--pass` |
  | 2xx + path missing | `Endpoint: path not found` | `--redact` |
  | non-2xx / unreachable | `Endpoint: HTTP 401` | `--block` |
  The Run button is `disabled` until the state is green — the single biggest saver of
  wasted 500-row runs.
- **P3c-3 Raw body viewer** — a `<details>` (`.os-legend` skin) showing the truncated
  scrubbed body in mono, with the extracted value highlighted in `--pass-bg`. Clicking
  a JSON leaf fills `response_path`. *(If click-to-fill is more than ~20 lines, ship
  the viewer without it; the path input stays typed.)*
- **P3c-4 Dataset step** reuses mode 2's dataset list/upload/import components — same
  ids, rendered into this rail. No second implementation.
- **P3c-5 Run step**: Guard ON/OFF (default **on**), judge, max scenarios,
  concurrency. CP0/CP2 rendered `.cp-card.disabled-card` with the 5.0 reason.
- **P3c-6 Results** reuse mode 2's renderer and all three exports untouched. Add one
  banner line naming the tested endpoint host at the top of the report — the report is
  the evidence artifact and must say *what* was tested.
- **P3c-7 Persistence**: URL, method, body template, response path and timeout in
  localStorage. **Headers are never persisted** — they hold credentials. Show that as
  a hint under the header rows so their disappearance on reload is expected, not a bug.

### 5.6 Tests (new `tests/unit/test_http_target.py`)
- `{{prompt}}` substitution stays valid JSON for prompts containing `"`, `\n`, `\\`.
- `_dig` on nested and indexed paths; missing path → an errored row, not a 500.
- Non-200 and timeout → one errored row, run completes.
- `_reject_metadata_url` applied to the target URL (extend the parametrised SSRF test).
- A run with `target` set does not mutate `_llm_config`.
- Judge resolves from the global config, never the target; judge requested with no
  global judge → 400.

---

## 6. Docs
- README: three-function table, one section each, a mode-3 walkthrough with a real
  `curl`-shaped endpoint example.
- `CLI_ONESHOT_GUIDE.md`: `--target-file` + a worked example.
- `.env.example`: note that a target endpoint is per-run and never stored.

---

## 7. Copy deck + i18n keys
One key per string, added to all five locales (`en`, `zh-TW`, `zh-CN`, `ja`, `ko`).

| Key | English |
|---|---|
| `mode.chat` / `.bench` / `.target` | Demo / Benchmark / Target Test |
| `mode.chat.intro` | One message, four checkpoints — watch each one fire. |
| `mode.bench.intro` | Run a whole dataset through this app's guarded pipeline. |
| `mode.target.intro` | Run a dataset against your own API endpoint, scanned by Guard. |
| `bench.step.scope` … `bench.step.history` | Scope / Target / Guard / Attack / Context / Limits / History |
| `tgt.step.endpoint` / `.dataset` / `.run` | Endpoint / Dataset / Run |
| `tgt.url` / `.method` / `.headers` / `.body` / `.path` / `.timeout` | URL / Method / Headers / Request body / Response path / Timeout (s) |
| `tgt.test` | Test endpoint |
| `tgt.state.untested/testing/ok/nopath/failed` | Untested / Testing… / OK / Path not found / Failed |
| `tgt.headersNotSaved` | Headers are never saved — re-enter them after a reload. |
| `tgt.cpNote` | CP0 and CP2 don't apply: this endpoint owns its own system prompt and knowledge base. |
| `tgt.bodyHint` | Use `{{prompt}}` where the user message goes. It is inserted JSON-encoded. |

---

## 8. Sequencing

| Phase | Content | Depends on | Size |
|---|---|---|---|
| P0 | Mode shell: nav, `data-only`, routing, one-shot out of the modal | — | S |
| P1 | Mode 1 scoping + intro + i18n | P0 | S |
| P2 | Mode 2 rail, sticky run bar, dataset preview, row maths | P0 | M |
| P3a | `llm.py` HTTP target kind + `_dig` + tests | — (parallel with P0) | M |
| P3b | `TargetConfig`, per-run override, `/api/target/test`, judge guard | P3a | M |
| P3c | Mode 3 UI | P0, P3b | M |
| P4 | CLI `--target-file` | P3a | S |
| P5 | Docs | all | S |

P3a has no dependency on the UI work and is the risky part — start it first or in
parallel.

### Per-phase done checks
- **P0** — every existing flow behaves identically: chat, scenario buttons, one-shot
  run + stream progress + all three exports, history save/diff, onboarding. Reload on
  `#/bench` lands on Benchmark. This phase is pure DOM relocation; any behaviour change
  is a bug.
- **P1** — Basic mode hides only chat controls; no dead `[data-adv]` nodes remain.
- **P2** — a full one-shot run works end to end from the rail with zero JS renames;
  the run recipe in `.cfg-sum` matches what the run actually executed.
- **P3** — `pytest tests/unit/test_http_target.py` green; a probe against a local
  stub server shows the correct chip colour for 200 / 401 / bad-path / unreachable;
  a 20-row run against that stub produces a report naming the endpoint.

## 9. Non-goals
- No framework, no build step, no component library. The page stays hand-written.
- No new colours, radii or fonts — §1 tokens only.
- No auth flows for the target beyond static headers (no OAuth dance, no cookie jar).
- No streaming (SSE/chunked) target responses — request/response only.
- No persistence of target credentials.
- No splitting `index.html` into modules here; if it happens it is a separate
  mechanical change, not tangled with the mode split.
