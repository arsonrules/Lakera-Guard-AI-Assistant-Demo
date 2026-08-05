# Feature Merge Plan — ARKO + Secure AI Chat

A review of two reference applications and a prioritised plan for the capabilities
this demo lacks.

**Reviewed 2026-08-06:**

| Source | What it is |
|---|---|
| [chat.procybersec.com](https://chat.procybersec.com/risk-map) | "Secure AI Chat — Powered by Lakera AI" (v1.1.13). A **runtime** product: guarded chat + RAG file upload, with a live OWASP risk map and an operations dashboard. Closest direct comparator to this demo. |
| [arko-airisk.tw](https://arko-airisk.tw/) | **ARKO — AI Risk Knowledge Base.** A **governance** corpus: 208 risk scenarios across 8 AI-lifecycle stages and 7 risk domains, each cross-referenced to international frameworks. |

They sit on opposite sides of the same problem. Secure AI Chat answers *"what is
happening in my AI right now?"*; ARKO answers *"which risks and obligations exist,
and what controls address them?"*. This demo currently does the first well, per-run,
and the second not at all.

---

## 1. What each reference app has

### 1.1 Secure AI Chat (chat.procybersec.com)

Navigation: **Chat · Dashboard · Risk Map · Files · Settings · Release Notes**

- **Risk Map** — the OWASP Top 10 for LLMs 2025 as ten cards with fixed severity
  (2 Critical / 3 High / 4 Medium / 1 Low) plus an **Active Risks** counter.
  Explicitly "based on your session activity". Each card opens a detail pane with:
  category (e.g. *Injection*), description, **Related Events**, **Flagged**,
  **% of Total**, a **Related Session Activity** list, and a link to the OWASP page.
  The key idea: **live chat activity accumulates into a standing OWASP view.**
- **Dashboard** — an operations log. Counters for Total Requests, Chat Requests,
  File Scans, Blocked, Allowed, Scanned, Flagged, Application Errors, System Errors,
  and Check Point TE Errors; tab filters (All / Chat / File Scans / Errors); a
  per-event log including **IP addresses** and security decisions; Clear All Logs.
- **Files** — RAG upload of **PDF, TXT, MD, JSON, CSV, DOCX up to 50 MB, 10 files**,
  stored persistently server-side, with three independent toggles: *Lakera Scan*,
  *Lakera after upload* (scan on ingest **and** on each retrieved snippet), and
  *File Sandboxing (Check Point Threat Emulation)*.

### 1.2 ARKO (arko-airisk.tw)

- **208 risk scenarios** (`S0001`–`S0208`) over **8 lifecycle stages** — Initiation 25,
  Design & Development 34, Validation & Verification 41, Deployment 11,
  Operation & Monitoring 70, Continuous Validation 12, Reassessment 11, Retirement 4.
- **7 risk domains** (RS1–RS7): Accountability & Transparency, Data & Model,
  Privacy & Security, Fairness & Discrimination, Reliability & Safety,
  AI Interaction & Application, Sustainability & Wellbeing.
- **8 impact dimensions** (IA-01…IA-08): Accountability, Transparency, Fairness,
  Privacy, Reliability, Security & Safety, Explainability, Environmental — presented
  as a **risk-domain × impact-dimension cross-matrix** with counts and drill-down.
- **Per-risk record** (verified on `S0001`): code, title, domain › category, scenario
  description, **framework mappings**, and **concrete controls**. S0001 maps to
  EU AI Act Art. 49 / Art. 71 · ISO/IEC 42001 §4.1–4.2 + Annex A.6.2.5 ·
  NIST AI RMF GOVERN 1.1 · ISO/IEC 23894 §6.3 · ISO/IEC 5338 Deployment ·
  MIT AI Risk Repository Domain 6 — and prescribes three controls (maintain an AI
  inventory; verify registration pre-deployment; enforce registration as a release gate).
- Standards referenced overall: ISO/IEC 22989, 38507, 42001, 23894, 42005, 5338, 8183;
  NIST AI RMF, CSF 2.0, AI 600/100, ARIA; EU AI Act; AIDEFEND; MIT AI Risk Repository;
  MAESTRO (agentic threat modelling).
- Filter/search UX over the corpus: stage × domain × impact × keyword, paginated,
  bilingual (中/EN).
- No public likelihood/severity scoring — it is a **qualitative** corpus, not a scorer.

---

## 2. Gap analysis

✅ have · ⚠️ partial · ❌ missing

| Capability | Us | Note |
|---|---|---|
| OWASP LLM Top 10 (2025) coverage | ✅ | 56 scenarios / 14 categories, incl. Agentic, multi-turn, adaptive — **deeper than either reference** |
| Per-run vulnerability dashboard by OWASP category | ✅ | `backend/report.py`, with severity + remediation |
| Guard ON vs OFF risk-reduction measurement | ✅ | Neither reference has this |
| LLM-as-judge (did the attack actually land?) | ✅ | Neither reference has this |
| Obfuscation-strategy evasion testing | ✅ | Neither reference has this |
| Headless CLI + CI gate + run history/diff | ✅ | Neither reference has this |
| HTML/JSON/CSV export | ✅ | |
| **Live session risk map** (activity → standing OWASP view) | ❌ | We aggregate **per one-shot run** only; live chat has no memory |
| **Operations dashboard / activity log** | ❌ | `/api/chat` returns and forgets — verified, no record kept |
| **Rich file formats for RAG** (PDF/DOCX/CSV/JSON/MD) | ❌ | We allow `.txt` only, 50 **KB**, 5 files |
| **Persistent uploaded-file store** | ⚠️ | Files persist on disk but there is no managed library/metadata |
| **Scan-on-retrieval as an explicit toggle** | ⚠️ | CP2 always scans retrieved docs; can only be turned off wholesale |
| **Compliance framework mapping** (EU AI Act / ISO / NIST) | ❌ | We map to OWASP + Agentic only — **no regulatory mapping anywhere** (verified) |
| **Impact-dimension taxonomy** (privacy/fairness/explainability…) | ❌ | We classify by attack technique, never by harm type |
| **Reusable risk library with controls** | ⚠️ | Remediation text exists per OWASP category, not as a queryable corpus |
| AI-lifecycle framing (8 stages) | ❌ | We are runtime-only (stages 4–5) |
| File sandboxing / Threat Emulation | ❌ | No malware detonation path |

**The headline gap is compliance mapping.** Today the report says *"LLM01 detection
82%, 3 breaches"*. An auditor cannot act on that. ARKO's model would let the same run
say *"this evidences EU AI Act Art. 15 (accuracy/robustness) and ISO/IEC 42001
Annex A.6.2.4; residual risk: 3 breaches."* That converts a demo artifact into an
audit artifact, and it is the one thing neither we nor Secure AI Chat currently do.

---

## 3. The plan

### P0-1 — Compliance framework mapping layer 🥇

*The highest-value item. Reuses everything we already compute.*

Every scenario already carries an OWASP id (`llm01`…`llm10`, `agentic`) and every
imported prompt gets a tactic from `backend/classify.py`. Attach a framework mapping
to those **existing** keys — no re-classification, no new taxonomy to maintain.

**Steps**

1. **New `backend/frameworks.py`** — a pure static mapping module (no I/O, no deps),
   mirroring how `backend/classify.py` is structured:
   ```python
   # owasp_id -> list of control references
   MAPPINGS = {
     "llm01": [
       {"framework": "EU AI Act",    "ref": "Art. 15",        "title": "Accuracy, robustness and cybersecurity"},
       {"framework": "ISO/IEC 42001","ref": "Annex A.6.2.4",  "title": "AI system verification and validation"},
       {"framework": "NIST AI RMF",  "ref": "MEASURE 2.7",    "title": "Security and resilience evaluated"},
       {"framework": "MITRE ATLAS",  "ref": "AML.T0051",      "title": "LLM Prompt Injection"},
     ],
     ...
   }
   def for_owasp(owasp_id: str) -> list[dict]: ...
   def coverage(summary: dict) -> list[dict]:   # frameworks touched by a run + pass/fail
   ```
2. **`GET /api/frameworks`** — expose the table so the UI and CLI share one source.
3. **Report integration** (`backend/report.py`) — add a `frameworks` block to the
   run summary: per framework control, which OWASP categories evidence it, the
   detection rate observed, and a verdict (`evidenced` / `gap`).
4. **HTML report + modal** — a "Compliance mapping" section under the existing
   vulnerability dashboard. Reuse `_os_acc()` collapsibles; **render it in
   `report_html.py` only** and let the browser export call the server (see §5) so
   we do not deepen the dual-renderer drift.
5. **CLI** — `--framework eu-ai-act|iso-42001|nist-ai-rmf` to filter the report, and
   a `frameworks` column in the CSV.
6. **i18n** — 5 languages for section labels only; keep clause titles in English
   (they are legal citations and should not be paraphrased).
7. **Tests** — every OWASP id has ≥1 mapping; no unknown framework names;
   `coverage()` marks a category with 0 attacks as `not-evidenced`, not `pass`.

**Effort** ~1.5 days. **Risk** low — additive, no existing logic touched.

> ⚠️ Accuracy caveat: these citations are a **triage aid, not legal advice**, and the
> report must say so in the same breath (ARKO carries a similar disclaimer). Have
> someone with compliance ownership review the table before it ships; a wrong clause
> reference is worse than none.

### P0-2 — Live session risk map

Bridges the gap between the live chat (currently amnesiac) and the one-shot report.

**Steps**

1. **Session ledger, in memory, bounded.** In `backend/main.py`, append one record per
   guarded chat turn: `{ts, request_id, owasp_id, blocked, blocked_at, flagged_categories, latency_ms}`.
   Cap with `collections.deque(maxlen=500)` so it cannot grow unbounded — consistent
   with the dataset row budget already added in `DEPLOYMENT_REVIEW.md` §1.3.
   **Do not store prompts or responses** (this app handles adversarial content and PII
   fixtures; `LOG_PROMPTS=false` is the existing default and must be honoured here too).
2. **Reuse the existing `X-Request-ID`** from the logging middleware as the event id, so
   a risk-map row can be traced to a log line.
3. **`GET /api/session/risks`** → per-OWASP-category counts: events, flagged, share of
   total, plus `active` (any event) — matching the reference's Related/Flagged/% shape.
   **`DELETE /api/session/risks`** to clear (their "Clear All Logs").
4. **UI** — a "Risk Map" view reusing the existing `.os-dash-*` category dashboard CSS.
   **Use the SVG sprite, not emoji** for card icons: the reference uses 💬📊🛡️📁⚙️ as
   structural icons, which is a documented anti-pattern (font-dependent, unstyleable) and
   we already have `#i-shield`, `#i-activity` etc.
5. **Severity** must come from our own `backend/report.py` severity model, not be
   hard-coded per category as the reference does — ours is derived from observed
   outcomes, which is more defensible.
6. **Tests** — ledger caps at maxlen; clearing empties it; a blocked turn increments
   `flagged`; no prompt text ever appears in the response.

**Effort** ~2 days. ⚠️ **Constraint:** this is per-process state and inherits the
single-worker limit in `DEPLOYMENT_REVIEW.md` §1.1 — document it as session-scoped,
not an audit log.

### P1-3 — Rich RAG file formats

Our CP2 poisoning demo is limited to `.txt`. A poisoned **PDF or DOCX** is far more
convincing, and it is what real RAG pipelines ingest.

**Steps**

1. Extend `ALLOWED_DOC_EXT` to `.txt .md .csv .json .pdf .docx`; raise
   `MAX_FILE_SIZE_BYTES` 50 KB → 2 MB (not the reference's 50 MB — we scan the whole
   text through Guard, and Lakera has request-size limits; 2 MB is a defensible cap)
   and `MAX_CUSTOM_FILES` 5 → 10.
2. **Text extraction** in a new `backend/extract.py`: stdlib `csv`/`json` for those;
   add `pypdf` and `python-docx` — the only new runtime dependencies, both pure-Python
   and small. Pin them in `requirements.lock`.
3. **Fail closed**: if extraction fails or yields no text, reject the upload with a
   clear message rather than indexing an empty document.
4. **Guard the extractor** — cap extracted characters, and reject encrypted/malformed
   PDFs. Parsing untrusted files is itself attack surface; keep the parser bounded.
5. Ship one **poisoned PDF fixture** so the demo has a story: indirect injection hidden
   in a PDF that CP2 redacts.
6. Tests: each format extracts; oversize → 413; unsupported → 400; unparseable → 400;
   extracted text still flows through CP2.

**Effort** ~1.5 days.

### P1-4 — Scan-on-retrieval toggle

The reference separates *scan on upload* from *scan on retrieval*. We only have
"CP2 on/off". Exposing the split makes a sharp teaching point: **scanning at ingest is
not enough if the store can be poisoned afterwards.**

**Steps** — add `scan_on_ingest` / `scan_on_retrieval` to the docs settings; scan at
upload time in `api_upload_custom_doc`; keep CP2 as the retrieval scan. Default both ON.
Surface in the Knowledge Base panel with a one-line explanation of why both matter.
**Effort** ~0.5 day.

### P2-5 — Operations dashboard

The reference's counters (requests / blocked / allowed / flagged / errors) and filter
tabs. Once P0-2's ledger exists this is mostly presentation.

**Steps** — derive counters from the ledger; tabs All / Chat / Errors; reuse the
one-shot results-table styles (already responsive after `DEPLOYMENT_REVIEW.md` §6.1).
**Deliberately omit IP-address logging** — the reference records it; we are a
loopback single-tenant demo (§1.1) and logging client IPs adds personal data for no
demo value. **Effort** ~1 day.

### P2-6 — Impact-dimension tagging (ARKO IA-01…IA-08)

A second axis on existing findings: harm type (privacy / fairness / explainability /
environmental) alongside attack technique. Enables ARKO's category × impact cross-matrix.

**Steps** — add an `impact` field to each catalogue category (static, curated); render a
cross-matrix in the report. **Effort** ~1 day. Do this **after** P0-1 — the framework
mapping delivers most of the governance value on its own, and this adds a taxonomy we
must then maintain.

---

## 4. Explicitly NOT merging

Being clear about what to skip is as important as the list above.

- ❌ **Cloning ARKO's 208-risk corpus.** That is a knowledge-base product with its own
  editorial lifecycle. We would be maintaining a stale copy of someone else's research.
  Map to frameworks (P0-1) and **link out** to ARKO instead.
- ❌ **The 8-stage AI lifecycle model.** We are a runtime demo — stages 4–5 only.
  Presenting Initiation/Design/Retirement we cannot exercise would be theatre.
- ❌ **Check Point Threat Emulation / file sandboxing.** A separate product and API key;
  malware detonation is orthogonal to prompt-level guardrails. Revisit only if the
  demo is explicitly asked to cover file-borne malware — and then as an opt-in
  integration, not a default.
- ❌ **IP-address logging** — see P2-5.
- ❌ **Emoji as structural icons** — the reference uses them throughout its nav; we have
  an SVG sprite and should keep using it.
- ❌ **A separate "Release Notes" page.** `git log` and the README already cover it.
- ❌ **Hard-coded per-category severity.** The reference fixes LLM01 = Critical always.
  Ours is computed from observed detection/breach data, which is the more honest signal
  for a testing tool.

---

## 5. Sequencing

| Order | Item | Effort | Why here |
|---|---|---|---|
| 1 | **P0-1 Framework mapping** | 1.5 d | Biggest differentiator; purely additive; unlocks the audit-artifact story |
| 2 | **P0-2 Session risk map** | 2 d | Makes the live chat cumulative; also builds the ledger P2-5 needs |
| 3 | **P1-3 Rich file formats** | 1.5 d | Materially better CP2 demo (poisoned PDF) |
| 4 | **P1-4 Scan-on-retrieval toggle** | 0.5 d | Small, sharp teaching point; trivial once §3 lands |
| 5 | **P2-5 Ops dashboard** | 1 d | Mostly presentation over P0-2's ledger |
| 6 | **P2-6 Impact dimensions** | 1 d | Only if the framework mapping proves it is wanted |

≈ 7.5 days total; the first two (3.5 days) capture most of the value.

### Prerequisite

**P0-1 step 4 depends on resolving the dual report renderer** (`report_html.py` vs
`buildHtmlReport()` in `index.html`) — already logged as `DEPLOYMENT_REVIEW.md` §1.2.
Adding a compliance section to both by hand doubles the drift risk that has already
caused one real bug this cycle. Do that consolidation (~½ day) first, or scope P0-1's
UI to the server-rendered report only.

---

*Reference material was read as source material for gap analysis only. Framework
citations in P0-1 must be verified by someone with compliance ownership before release.*

---

# 6. UI design plan

## 6.0 Design foundation — reuse, don't reinvent

The app already has a coherent dark **OLED** system and a mature component library.
Every surface below is **composed from existing classes**. No new colour, font, radius,
or shadow is introduced — a new visual language would make the additions read as
bolted on, and the existing one already matches the recommended direction for a
data-dense security dashboard.

**Tokens (already defined, use as-is)**

| Purpose | Token | Meaning in these views |
|---|---|---|
| Success / blocked-as-intended | `--pass` `#34D399` | control evidenced, attack blocked |
| Warning / partial | `--redact` `#FBBF24` | partially evidenced, redacted |
| Failure / breach | `--block` `#F87171` | gap, real breach |
| Not applicable | `--skip` `#94A3B8` | not exercised by this run |
| Accent / identity | `--brand` `#818CF8` | framework refs, links, focus ring |

Surfaces `--panel` / `--panel-2`, borders `--border` / `--border-soft`, text
`--text` / `--muted` / `--heading`, radii `--radius` / `--radius-sm`, motion `--ease`.

**Components to compose from**

| Need | Existing class |
|---|---|
| Metric tile / hero number | `.os-hero`, `.os-stat` |
| Labelled progress bar row | `.os-catbarrow` + `.os-catbar` + `.seg.blk/.amb/.brc` |
| Collapsible section | `.os-acc` + `.os-acc-body`, `.os-dash-collapsible` |
| Data table (responsive) | `.os-table-wrap` + `.os-table` |
| Status chip | `.os-outcome`, `.os-model`, `.lk-badge` |
| Filter bar + result count | `.os-tfilter`, `.os-tfilter-count` |
| Click-to-explain popover | `.os-popover` + `data-info` |
| Buttons | `.sp-btn` (`.primary` / `.danger` / `.safe`), `.ctl` |
| Empty state | `.os-empty` |
| Posture banner | `.sec-posture` |

**Rules applied throughout**

- **SVG sprite icons only** (`#i-shield`, `#i-activity`, `#i-file-text`, …). No emoji as
  structural icons — the reference app uses 💬📊🛡️ and that is a documented anti-pattern.
- **Never colour alone.** Every severity/status carries an icon *and* a text label; every
  chart cell carries its numeral. (Both references lean on colour + emoji; we shouldn't.)
- **Contrast** ≥ 4.5:1 body, ≥ 3:1 large/graphical. Current muted-on-panel measures 6.51:1.
- **Focus**: inherits the global `:focus-visible` 2px `--brand` ring. Nothing suppresses it.
- **Motion** 150–300 ms with `--ease`; the global `prefers-reduced-motion` reset already
  neutralises it.
- **Density**: dense data labels may stay < 12px (deliberate, as today); **prose stays ≥ 12px**.
- **i18n**: every new label gets keys in all 5 languages. **Legal clause text stays in
  English** (citations must not be paraphrased) — only surrounding labels translate.

---

## 6.1 (P0-1) Compliance framework mapping

**Placement** — a new collapsed `<details class="os-dash-collapsible">` section in the
one-shot report **and** the results modal, directly below the existing *Vulnerability
dashboard*, above *Findings & recommendations*. It answers "so what?" about the
dashboard immediately above it, so it belongs there rather than in a separate tab.

**Layout**

```
┌ COMPLIANCE MAPPING  ▸ (collapsed by default)  ───── 4 frameworks · 12 controls ┐
│  [ All ▾ ]  [ EU AI Act ▾ ]              showing 12 of 12         ← .os-tfilter │
│                                                                                │
│  EU AI ACT                                                    3/4 evidenced    │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │ Art. 15   Accuracy, robustness & cybersecurity                           │  │
│  │           via LLM01 · LLM05        ████████████░░░░  82%   ✓ Evidenced    │  │
│  │ Art. 10   Data governance                                                │  │
│  │           via LLM04 · LLM08        ██████░░░░░░░░░░  41%   ⚠ Partial      │  │
│  │ Art. 12   Record-keeping           not exercised     —      ○ No evidence │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│  ISO/IEC 42001 …                                                               │
└────────────────────────────────────────────────────────────────────────────────┘
```

- One `.os-acc` block per framework; inside it one `.os-catbarrow` per control —
  a three-column grid `[label | bar | value]` that is effectively a **bullet chart**
  (the recommended form for several KPIs side by side, and AAA-accessible because the
  value is always rendered as text, never hover-only).
- **Verdict chip** reuses `.os-outcome` semantics with the existing palette:
  `✓ Evidenced` `--pass` · `⚠ Partial` `--redact` · `○ No evidence` `--skip`.
  **"No evidence" must never be green** — a control the run didn't exercise is unknown,
  not passing. This is the single most important correctness detail in the whole view.
- Clause ids in `JetBrains Mono` (they're identifiers); clause titles in body font.
- "via LLM01 · LLM05" chips reuse `.os-owasp`, and click through to filter the results
  table to those categories — the audit trail from control → evidence.

**States**

| State | Treatment |
|---|---|
| Loading | not applicable — computed server-side with the run |
| Empty (no attacks run) | `.os-empty`: "No attack scenarios were executed, so no controls were exercised." |
| Partial run | banner: "Based on N of M categories — coverage is partial." |

**Disclaimer** — a persistent `.os-clsnote`-styled line inside the section:
*"Framework references are a triage aid, not legal advice or a certification."*
Non-dismissible; it must travel with the exported HTML.

**Responsive** — `.os-catbarrow` collapses from `[58px | 1fr | auto]` to a two-row
stack below 640px (label above bar) so clause titles never truncate.

---

## 6.2 (P0-2) Live session risk map

**Placement** — a **new modal**, opened from a header `.ctl` button (`#i-shield`,
label "Risk Map"), matching how One-Shot Test opens. Not a nav rewrite: the app's
top-level surface is the chat, and the risk map is a lens on it.

> Deliberately **not** a persistent left sidebar like the reference. That would push
> the chat + inspector two-pane layout into three panes and break the 920 px
> breakpoint that currently works.

**Layout** — reuses the one-shot modal shell (`.modal-overlay` → `.modal` →
`.modal-header` / `.modal-toolbar` / body).

```
┌ RISK MAP ─────────────────────────────────────────────────── [×] ┐
│ Session · 24 messages · started 14:02        [ Clear session ]   │  ← .modal-toolbar
│                                                                  │
│   ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐                    │
│   │   3    │ │   1    │ │  12    │ │  24    │   ← .os-stat tiles │
│   │ ACTIVE │ │BREACHES│ │BLOCKED │ │ TOTAL  │                    │
│   └────────┘ └────────┘ └────────┘ └────────┘                    │
│                                                                  │
│  OWASP LLM TOP 10 · THIS SESSION                                 │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐                    │
│  │ LLM01      │ │ LLM02      │ │ LLM03      │  ← 2-col ≥640px    │
│  │ Prompt Inj │ │ Sens. Info │ │ Supply Ch. │     1-col below    │
│  │ ●  8 events│ │ ○ no activity│ ● 2 events │                    │
│  │ 6 blocked  │ │            │ │ 0 blocked  │                    │
│  └────────────┘ └────────────┘ └────────────┘                    │
│                                                                  │
│  ▸ SESSION ACTIVITY (24)                    ← .os-table-wrap     │
└──────────────────────────────────────────────────────────────────┘
```

- **Cards** reuse `.cp-card` shape. **Severity is computed, not fixed** — derived from
  what actually happened this session (breach → `--block`, blocked → `--pass`, no
  activity → `--skip`), unlike the reference which hard-codes LLM01 = Critical forever.
  A card with no activity is muted and de-emphasised, not alarming.
- Selecting a card filters the activity table beneath it (same interaction as the
  report's filter bar) and sets `aria-pressed`.
- **Activity table** columns: Time · Category · Guard verdict · Checkpoint · Latency.
  **No prompt text column** — the ledger deliberately stores none.

**Empty state** (fresh session — the *default* first impression, so it must teach):
`.os-empty` with "No activity yet. Send a message or fire a scenario to populate the
map." plus a "Try an attack →" button reusing the existing `.cat-cta` pattern.

**Live updates** — the map is refreshed on modal open and after each chat turn while
open. The counter row is an `aria-live="polite"` region so screen readers hear
"3 active risks" without focus theft. No polling.

**Accessibility** — cards are `<button>` with `aria-pressed`; the ● / ○ status dot is
paired with text ("8 events" / "no activity"), never colour alone.

---

## 6.3 (P1-3) Rich RAG file upload

**Placement** — extends the existing **Custom RAG Docs** panel; no new surface.

**Changes**

- Accepted-formats hint updates to `PDF · DOCX · TXT · MD · CSV · JSON · max 2 MB · up to 10`.
- Each row in `.cdocs-file-list` gains a **format chip** (`.os-variant` styling, mono)
  and an **extraction result**: `12,481 chars extracted` or a `--block` error.
- **Drag-and-drop** onto the panel with a dashed `--brand-br` outline on `dragover`,
  plus the existing click-to-upload button — never gesture-only.
- **Per-file progress** while parsing: `.os-running` spinner → result. PDF/DOCX parsing
  is not instant, so a >300 ms operation must show progress rather than freeze.

**Error states must be specific and recoverable** (not "Upload failed"):

| Cause | Message |
|---|---|
| Too large | "sales.pdf is 4.2 MB — the limit is 2 MB." |
| Unsupported | "report.xlsx isn't supported. Use PDF, DOCX, TXT, MD, CSV or JSON." |
| Encrypted PDF | "policy.pdf is password-protected and can't be read." |
| No text found | "scan.pdf contains no extractable text (image-only PDF?)." |

---

## 6.4 (P1-4) Scan-on-ingest vs scan-on-retrieval

**Placement** — two toggles in the Knowledge Base panel, reusing `.os-judge-toggle`.

The teaching point *is* the UI: show them as **two stages of one pipeline**, not two
unrelated switches —

```
Upload ──[ Scan on ingest  ●ON ]──▶ Store ──[ Scan on retrieval ●ON ]──▶ LLM
```

reusing the `.pipeline-flow` / `.pf-node` component already used for CP1→CP3. Turning
*retrieval* off shows an inline `--redact` hint: *"Documents poisoned after upload will
reach the model unscanned."* That single sentence is the whole lesson.

---

## 6.5 (P2-5) Operations dashboard

**Placement** — a tab **inside the Risk Map modal** (segmented control: `Risk Map` /
`Activity`), not a separate modal. Both read the same ledger; splitting them into two
surfaces would duplicate navigation for one dataset.

- Counter row: `.os-summary` + `.os-stat` tiles — Total · Blocked · Allowed · Flagged · Errors.
- Filter tabs reuse `.os-tfilter` with the `showing N of M` counter added this cycle.
- Table reuses `.os-table-wrap` (already responsive).
- **No IP-address column** — see §4.
- `Clear session` is destructive → `.sp-btn.danger` + confirm dialog, placed **away**
  from the filter controls.

---

## 6.6 (P2-6) Impact-dimension cross-matrix

**Placement** — inside the compliance section (§6.1), collapsed.

A 7 domains × 8 impacts grid = **56 cells**, which is above the ~20-cell threshold where
a heat map beats a bar chart. But heat maps grade **B** for accessibility, so:

- **Every cell shows its integer count as text.** Colour intensity is a *secondary* cue
  only; `·` for zero, matching ARKO's own presentation.
- Intensity via `--brand-bg` alpha steps (4 steps), not a rainbow ramp — a
  colour-blind-safe single-hue scale.
- Row/column headers are `<th scope>`; the grid is a real `<table>` so screen readers
  announce "Privacy & Security, Reliability: 3".
- Cells are focusable buttons that filter the results table.
- Below 720 px the matrix is **replaced** — not scrolled — by a ranked bar list
  ("Privacy & Security ██████ 54"), since a 56-cell grid is unreadable on a phone.

---

## 6.7 Cross-cutting checklist

Before any of these ship:

- [ ] Contrast verified in-browser, not assumed (the audit tooling from the last UI pass)
- [ ] Keyboard: full tab order, focus ring visible, Escape closes modals
- [ ] `prefers-reduced-motion` honoured (global reset already covers it)
- [ ] 375 / 768 / 1280 px checked; **no horizontal page scroll** (contained scroll is fine)
- [ ] Touch targets ≥ 44 × 44 px — the Clear Chat button failed this at 38 px last cycle
- [ ] All five languages render without truncation (German-length strings aren't a risk,
      but CJK line-breaking is)
- [ ] Empty, loading, partial and error states designed — not just the happy path
- [ ] No emoji icons; no colour-only meaning; no hover-only information

### Suggested build order (UI)

1. **§6.1 compliance section** — pure server-render, no new interaction model, lands with P0-1.
2. **§6.2 risk map modal shell + cards** — the one genuinely new surface.
3. **§6.5 activity tab** — drops into the shell from step 2.
4. **§6.3 / §6.4 knowledge-base changes** — self-contained in an existing panel.
5. **§6.6 matrix** — last, and only if §6.1 proves the appetite.
