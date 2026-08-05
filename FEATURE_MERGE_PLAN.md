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
