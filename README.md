# Lakera Guard — AI Assistant Security Demo

An interactive single-page application that demonstrates how [Lakera Guard](https://www.lakera.ai/) protects a production-style AI customer-service assistant against a wide range of LLM security threats. Every request flows through four scanning checkpoints before a response reaches the user, and the browser UI visualises each checkpoint result in real time.
<img width="1508" height="857" alt="截圖 2026-06-16 下午5 25 30" src="https://github.com/user-attachments/assets/d60f3b24-298c-4cad-a77b-b2e6e0500024" />


---

## Table of Contents

1. [What This Application Does](#what-this-application-does)
2. [Security Architecture](#security-architecture)
   - [The Four Checkpoints](#the-four-checkpoints)
   - [OWASP LLM Top 10 Coverage](#owasp-llm-top-10-coverage)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
   - [Option A — Python virtual environment](#option-a--python-virtual-environment)
   - [Option B — Docker Compose](#option-b--docker-compose)
5. [Configuration](#configuration)
6. [Running the Application](#running-the-application)
7. [Using the UI](#using-the-ui)
   - [Chat panel](#chat-panel)
   - [Security Trace inspector](#security-trace-inspector)
   - [Scenario categories](#scenario-categories)
   - [Knowledge Base mode](#knowledge-base-mode)
   - [Custom RAG documents](#custom-rag-documents)
   - [Custom system prompt](#custom-system-prompt)
8. [LLM Provider Configuration](#llm-provider-configuration)
9. [One-Shot Testing](#one-shot-testing)
10. [Report Generation](#report-generation)
11. [Running Integration Tests](#running-integration-tests)
12. [Project Structure](#project-structure)
13. [Notes on Intentional Demo Data](#notes-on-intentional-demo-data)

---

## What This Application Does

The demo simulates a fictional online retailer (**ShopEase**) whose customer-service chatbot is powered by a configurable LLM (Claude via OpenRouter by default, or an on-prem / local model) and protected by Lakera Guard. Visitors can:

- **Chat freely** with the assistant to observe normal, helpful responses.
- **Fire pre-built attack scenarios** organised by OWASP LLM Top 10 (2025) category and watch Lakera Guard intercept them at the appropriate checkpoint.
- **Upload poisoned or custom documents** to the RAG knowledge base and see CP2 redact dangerous content before it reaches the LLM.
- **Inject a custom system prompt** — benign or malicious — and observe CP0 accepting or rejecting it before it is ever activated.
- **Simulate malicious LLM outputs** to test whether CP3 catches injected instructions before they reach the browser.
- **Choose any LLM backend** — OpenRouter (cloud) or an on-prem / local server such as LM Studio, Ollama, or oMLX — and switch live from the header without restarting.
- **Run a One-Shot Test** that fires every scenario at once and reports, per checkpoint, what Lakera blocked, allowed, or let through.
- **Export a report** (standalone HTML or JSON) of a One-Shot run for sharing or compliance evidence.

The goal is to give security engineers, developers, and product teams a hands-on understanding of *where* and *how* LLM guardrails fire in a realistic pipeline.

---

## Security Architecture

```
User message
     │
     ▼
┌─────────────┐     flagged → BLOCK (return fallback message)
│  CP1        │  Lakera Guard scans the raw user input for
│  User Input │  prompt injection, jailbreaks, PII extraction
└──────┬──────┘  attempts, encoding tricks, and similar attacks.
       │ clean
       ▼
┌─────────────┐     flagged docs → REDACT (remove from context)
│  CP2        │  Each document retrieved from the knowledge base
│  RAG Docs   │  is individually scanned. Poisoned or PII-laden
└──────┬──────┘  docs are silently dropped; clean ones proceed.
       │ clean docs only
       ▼
   LLM Call (Claude via OpenRouter)
       │
       ▼
┌─────────────┐     flagged → BLOCK (return fallback message)
│  CP3        │  The generated response is scanned before it
│  LLM Output │  is sent to the browser. Catches injected
└──────┬──────┘  instructions, PII leakage, and chained attacks.
       │ clean
       ▼
  Response delivered to user
```

### The Four Checkpoints

| ID | When it runs | What it catches | On detection |
|----|-------------|-----------------|--------------|
| **CP0** | Once, when a system prompt is uploaded | Injection instructions hidden inside a system prompt | Rejects the prompt; keeps the previous (default) prompt active |
| **CP1** | Every user message | Prompt injection, jailbreaks, encoding obfuscation (Base64, XML tags), PII extraction, system-prompt leakage | Blocks the request; no LLM call is made |
| **CP2** | Each RAG document retrieved | Indirect injection embedded in knowledge-base articles, PII (SSNs, card numbers) in retrieved docs | Redacts the flagged document; clean documents still reach the LLM |
| **CP3** | Every LLM response | Injection instructions inside the model's output, PII leakage, chained jailbreak propagation | Blocks the response; the user receives a safe fallback message |

### OWASP LLM Top 10 Coverage

The built-in scenario library maps directly to the OWASP LLM Top 10 (2025):

The built-in library now spans **all ten** OWASP LLM Top 10 (2025) entries plus an agentic-threats group — **50 scenarios across 12 categories**:

| Category | OWASP ID | Checkpoint(s) | Notes |
|---|---|---|---|
| Safe Baselines | — | All pass | Regression baseline; should never be blocked |
| Prompt Injection | LLM01:2025 | CP1 | Direct overrides, DAN, Base64, XML tags, separator tricks |
| Sensitive Info Disclosure | LLM02:2025 | CP1 | Bulk PII dumps, API key extraction, repeat-back, context window dumps |
| Supply Chain | LLM03:2025 | CP1/CP3 (partial) | Backdoor trigger phrases, typosquatted package output, untrusted adapter loads, provenance probing — mostly **not** caught by Lakera; needs SBOM/SCA & signed artifacts |
| Data & Model Poisoning | LLM04:2025 | CP1/CP2 (partial) | Poisoned feedback loops, sleeper-trigger implants, biased-memory writes, poisoned KB — needs data governance & provenance |
| Improper Output Handling | LLM05:2025 | CP3 | Simulated outputs containing hidden instructions or jailbreak propagation |
| Excessive Agency | LLM06:2025 | CP1 (partial) | Delete records, mass emails, privilege escalation — shows limits of injection-focused guards |
| System Prompt Leakage | LLM07:2025 | CP1 | Verbatim extraction, debug-mode tricks, translation bypass, summarisation |
| Vector & RAG Poisoning | LLM08:2025 | CP2 | Hidden HTML comments, competitor diversion, PII-containing case studies |
| Misinformation | LLM09:2025 | CP1 (partial) | False policy premises, fabricated authority — highlights need for output validation beyond Lakera |
| Unbounded Consumption | LLM10:2025 | none (by design) | Token floods, recursive amplification, model extraction, denial-of-wallet, oversized input — **not** a content problem; needs rate limits, quotas, length caps & cost monitoring |
| Agentic Threats | AGENTIC | CP1 | SQL injection in tool calls, forged tool results, multi-turn escalation, context window poisoning |

> Categories that Lakera does **not** reliably block (LLM03, LLM04, LLM06, LLM09, LLM10) are intentional teaching cases: they show where a prompt/output scanner ends and defence-in-depth (provenance, governance, rate limiting, human review) must begin. The [One-Shot Test](#one-shot-testing) surfaces these as `NOT BLOCKED` rows.

---

## Prerequisites

| Requirement | Minimum version | Purpose |
|---|---|---|
| **Python** | 3.11 | Backend runtime |
| **pip** | 23+ | Package installation |
| **Lakera Guard API key** | — | Scanning all four checkpoints |
| **An LLM endpoint** | — | OpenRouter key *or* a local server (LM Studio / Ollama / oMLX) for completions |
| **Docker + Docker Compose** *(optional)* | Docker 24 / Compose v2 | Containerised deployment |

### Getting API Keys

**Lakera Guard**
1. Sign up at [platform.lakera.ai](https://platform.lakera.ai).
2. Navigate to **API Keys** and create a new key.
3. The demo uses the `v2/guard` endpoint — ensure your plan includes it.

**OpenRouter**
1. Sign up at [openrouter.ai](https://openrouter.ai).
2. Go to **Keys** and create a key with credits loaded.
3. The default model is `anthropic/claude-sonnet-4.5`. Any OpenRouter-compatible Claude model works; update `OPENROUTER_MODEL` in `.env` to change it.

---

## Installation

### Option A — Python virtual environment

```bash
# 1. Clone / download the project
cd "AI assistant demo"

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows

# 3. Install dependencies
pip install -r requirements.txt
```

### Option B — Docker Compose

```bash
# No Python installation needed — Docker handles everything
cd "AI assistant demo"
# .env is optional — configure keys in the UI after start. For "Save to .env" to
# persist back to the host, make sure a .env file exists first (a bind mount of a
# missing file would create a directory):
touch .env
docker compose up --build
```

---

## Configuration

**No `.env` is required.** The app boots without any configuration and prompts you to
enter your **Lakera Guard key** (and pick an LLM provider) in the **Settings** panel —
opened from the key/`LLM:` button in the header, which turns **red** until the
(required) Lakera key is set. Click **Save to .env** to persist the current keys +
provider so they load automatically next time.

If you prefer, you can still pre-seed everything with a `.env` file in the project root
(it's read at startup if present, never committed):

```dotenv
LAKERA_GUARD_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Default LLM backend (also switchable live in the UI)
LLM_PROVIDER=openrouter
LLM_API_KEY=sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
LLM_MODEL=anthropic/claude-sonnet-4.6
```

All of these are **optional** — anything left unset can be configured in the UI. The
keys below seed the *startup* config; the UI is the source of truth at runtime.

| Variable | Required | Default | Description |
|---|---|---|---|
| `LAKERA_GUARD_API_KEY` | No* | — | Lakera Guard key for all checkpoint scans (*required to run scans — set here or in the UI) |
| `LLM_PROVIDER` | No | `openrouter` | Startup provider: `openrouter`, `lmstudio`, `ollama`, `omlx`, or `custom` |
| `LLM_BASE_URL` | No | preset per provider | OpenAI-compatible base URL (blank → provider preset) |
| `LLM_MODEL` | No | preset per provider | Model id to request |
| `LLM_API_KEY` | No | — | API key for the LLM provider (not needed for most local servers) |
| `OPENROUTER_API_KEY` | No | — | Back-compat: seeds `LLM_API_KEY` when it is blank |
| `OPENROUTER_MODEL` | No | `anthropic/claude-sonnet-4.6` | Back-compat: seeds `LLM_MODEL` when it is blank |

> The original `OPENROUTER_API_KEY` / `OPENROUTER_MODEL` variables still work unchanged — if you only set those, the demo behaves exactly as before. See [LLM Provider Configuration](#llm-provider-configuration) for on-prem / local setups.

---

## Running the Application

### Virtual environment

```bash
source .venv/bin/activate
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Then open [http://localhost:8000](http://localhost:8000) in your browser.

The `--reload` flag restarts the server automatically on code changes. Remove it for production.

### Docker Compose

```bash
docker compose up
```

The app is available at [http://localhost:8000](http://localhost:8000).

---

## Using the UI

### Chat panel

Type any message in the text box at the bottom-left and press **Enter** or click **SEND**. The assistant responds as a ShopEase customer-service agent. While processing, a pulsing "LAKERA GUARD PROCESSING…" indicator appears.

**Blocked messages** are displayed with a red speech bubble and a `🛡 BLOCKED BY LAKERA GUARD` badge. The fallback message explains which checkpoint fired.

#### Guard ON/OFF toggle

The **Guard: ON/OFF** button in the header flips Lakera Guard for the chat. With it
**OFF**, your next messages go **straight to the model** with no CP1/CP2/CP3 scanning
(no Lakera key required), a red banner warns that responses are unscanned, and the
Security Trace shows every checkpoint as `OFF`. Toggle it on and resend the same
prompt to watch the guard intercept it — a quick way to demo the difference with your
own manual inputs. (This is the live, single-message switch; the one-shot modal's
*Guard ON vs OFF* runs the same comparison across the whole scenario set.)

### Security Trace inspector

The right-hand panel updates after every message and shows the result of each checkpoint:

| Badge | Meaning |
|---|---|
| `✅ PASSED` | Lakera scanned the content and found no issues |
| `🚫 BLOCKED` | Lakera flagged the content; the pipeline was halted |
| `⚠ REDACTED` | One or more RAG documents were removed (CP2 only) |
| `— SKIPPED` | The checkpoint was not reached because an earlier one blocked |
| `PENDING` | The checkpoint has not run yet |

Each card shows the **Lakera API latency**, flagged **detector categories** (e.g. `PROMPT ATTACK`, `PII`), and for CP2 the names of flagged vs. clean documents.

### Scenario categories

The bar beneath the header contains two rows:

1. **Category pills** — nine groups colour-coded by type (green = safe, red = attack). Each pill shows the OWASP ID (e.g. `LLM01`) and activates that group's scenarios. The inspector displays the category description and OWASP mapping.

2. **Scenario buttons** — the individual attack or safe prompts within the selected category. Clicking a button auto-populates the chat and fires the request immediately. The inspector shows a description of what the scenario tests.

### Knowledge Base mode

The **KNOWLEDGE BASE** button in the header controls which set of documents the RAG retriever uses:

| Mode | Button label | Documents used |
|---|---|---|
| `clean` | `CLEAN DOCS` | Legitimate FAQ and product manual |
| `poisoned` | `☠ POISONED DOCS` | Documents with embedded injection instructions and real-format PII (SSNs, card numbers) |
| `custom` | `☁ CUSTOM DOCS` | Your own uploaded `.txt` files |

Click the button to cycle between `clean` and `poisoned`. Custom mode is activated from the Custom RAG Docs panel.

The **LLM08 — Vector & RAG Poisoning** scenarios automatically switch to `poisoned` mode when clicked.

### Custom RAG documents

Click **📁 UPLOAD DOCS** in the header to open the custom document panel.

**Uploading a document**
1. Click **UPLOAD .TXT** and select a file.
2. The client validates format and size before sending; the server enforces the same rules independently.
3. Uploaded files appear in the list with their size. Upload as many as the slot limit allows.

**Activating custom docs**
1. Click **USE CUSTOM DOCS** — the header button changes to `☁ CUSTOM DOCS`.
2. From this point, all RAG retrieval uses your uploaded files. Lakera CP2 still scans them on every query.
3. Click **RESET TO CLEAN** (or click the header button) to switch back.

**Constraints enforced at both client and server:**

| Rule | Limit |
|---|---|
| File format | `.txt` only |
| File encoding | Valid UTF-8 |
| Maximum file size | 50 KB per file |
| Maximum number of files | 5 files |

Deleting the last custom file while custom mode is active automatically resets the knowledge base to `clean`.

### Custom system prompt

Click **PROMPT: DEFAULT** in the header to open the system prompt panel.

| Action | Description |
|---|---|
| **✅ CLEAN EXAMPLE** | Loads a safe, description-style prompt that passes CP0 |
| **🚫 MALICIOUS EXAMPLE** | Loads a prompt containing override instructions that CP0 blocks |
| **📂 UPLOAD .TXT** | Load a prompt from a local text file |
| **LOAD DEFAULT** | Populates the textarea with the current active prompt (useful to inspect the built-in default) |
| **SCAN & ACTIVATE** | Sends the prompt to Lakera CP0; if clean, activates it immediately; if flagged, the default is kept and the rejection reason is shown |
| **RESET DEFAULT** | Discards any custom prompt and reverts to the built-in ShopEase prompt |

The inspector's **CP0** card updates to show the scan result, latency, and any flagged categories.

**Why CP0 matters:** Without scanning the system prompt on upload, an attacker with access to the prompt-configuration interface could silently inject instructions that persist across all future conversations — bypassing CP1 entirely because the attack is already inside the system context.

---

## LLM Provider Configuration

The assistant's completions can come from any **OpenAI-compatible** Chat Completions endpoint, so you can demo the exact same Lakera pipeline against a cloud model or a model running entirely on your own hardware.

Click the **LLM:** button in the header to open the provider panel. Pick a provider, adjust the base URL / model / API key as needed, **Test Connection**, then **Save Provider**. Changes take effect immediately for the next message — no restart.

| Provider | Preset base URL | API key | Typical use |
|---|---|---|---|
| **OpenRouter** | `https://openrouter.ai/api/v1` | Required | Cloud gateway to Claude, GPT, etc. |
| **LM Studio** | `http://localhost:1234/v1` | Not required | On-prem GUI server; load a model and start its local server |
| **Ollama** | `http://localhost:11434/v1` | Not required | Local CLI runtime (`ollama pull <model>`) |
| **oMLX** | `http://localhost:10240/v1` | Not required | `mlx-omni-server` / Apple-MLX OpenAI-compatible server |
| **Custom** | *(you provide)* | Optional | Any other OpenAI-compatible `/v1` endpoint |

**Test Connection** (and the **Load models** button) call `GET {base_url}/models` and report reachability, latency, and the model ids the server advertises. The returned models populate both the **Model** text field's autocomplete **and** a *"from provider"* dropdown — so you can either **type a model id manually** or **pick one the endpoint actually serves**. If the field is empty, the first model is filled in for you.

> **Running the demo in Docker?** A container's `localhost` / `127.0.0.1` is the *container itself*, not your host. To reach an LLM server running on your machine (LM Studio, Ollama, oMLX), use **`http://host.docker.internal:<port>/v1`** instead of `localhost`. The bundled `docker-compose.yml` maps `host.docker.internal` for you (works on Docker Desktop and Linux). If a Test Connection fails from inside the container, the error message tells you this explicitly.

Notes:
- A **model id is required** to save a provider. Local servers (LM Studio, oMLX, Custom) have no built-in default, so run **Test Connection** / **Load models** first and pick one of the listed models — saving with an empty model is rejected.
- If a chat fails, the assistant bubble shows the **real reason** from the provider (e.g. `LLM provider error (404): Model '…' not found. Available models: …`, or `Could not reach the LLM provider … Is the server running?`) instead of a generic error.
- The API key is stored only in server memory and is **never** returned to the browser (the UI shows a masked value and whether a key is set).
- Leaving the API-key field blank on save keeps the currently stored key **for the same provider**; switching providers requires entering that provider's key (a stale key is never sent to a different endpoint).
- Because the base URL is operator-supplied, only run this demo in a trusted environment — it is bound to loopback by default (see `docker-compose.yml`).

## One-Shot Testing

The **One-Shot Test** button in the header opens a modal that fires an entire scenario set through the full CP1→CP2→CP3 pipeline in one click (run concurrently, server-side).

1. Choose a **scope** — *All categories* or a single OWASP category.
2. Click **Run Test**. Each scenario is executed against the currently configured LLM provider and Lakera checkpoints.
3. The results matrix shows, per scenario: OWASP id, expected outcome, the CP1/CP2/CP3 status badges, the actual outcome, and total Lakera latency.
4. **Click any row to reveal its inputs** (collapsed by default): the exact **user prompt**, any **simulated LLM output** (for LLM05 scenarios), the **model's actual response**, the **judge verdict**, and the **RAG documents** that query retrieved — each tagged with what the pipeline did (`passed to LLM`, `redacted by CP2`, or `not reached` when CP1 blocked first) and a preview of the document content.

A short **legend** above the table explains what CP1 / CP2 / CP3 mean and the status colours.

#### LLM-as-judge: did the attack *actually* succeed?

A `NOT BLOCKED` guard verdict is ambiguous on its own — the model may have refused
anyway. With the **LLM judge** toggle on (default), the judge grades **only the
response the Guard-ON pipeline actually delivered to the user**, against a
per-category success criterion, producing a **Model (judge)** column and a risk
summary:

| Model outcome | Meaning |
|---|---|
| `BREACH` (red) | The response reached the user **and** the model complied — a real breach |
| `RESISTED` | The response was delivered but the model refused / answered safely |
| `PREVENTED` | The guard blocked it (CP1 before the model ran, **or** CP3 caught the output) — a safe fallback was delivered, so the blocked content is not judged |

This is the honest defense-in-depth picture: the judge only counts a compromise
when something actually reached the user — anything the guard blocked (CP1 or CP3)
is `PREVENTED`. The summary reports **Real breaches**, **Model resisted**, and
**Guard prevented**. (To see what the model would have done *without* the guard,
use **Guard ON vs OFF** below — that's where the "model would have complied"
signal lives.)

> **Judge quality tracks the judge model.** The judge uses your configured LLM
> provider, out-of-band of Lakera. A small local model (e.g. a 4B) is an unreliable
> grader — point the provider at a capable model (Claude/GPT-class via OpenRouter)
> when you rely on the judge. Untrustworthy verdicts surface as `Judge unclear`.
> The judge adds one LLM call per attack that reaches the model; untick **LLM judge**
> to skip it.

#### Guard ON vs OFF: how much risk does Lakera remove?

Tick **Guard ON vs OFF** (implies the judge) to run every attack twice — once
through the normal pipeline and once with **Lakera disabled** (no CP1/CP2/CP3, RAG
docs unredacted) — and judge both. A headline banner quantifies the difference:

> **Model alone: 33% of attacks succeeded → With Lakera: 0% reached the user → −100% risk.**

`Model alone (no guard)` = the model's own attack-success rate; `Reached user (with
Lakera)` = attacks that still landed despite the guard (the `BREACH` rows); `Risk
reduced` = the drop between them. Each row also shows a **Model alone** verdict, and
the Guard-OFF response is in the click-to-reveal panel. This doubles model calls, so
it's opt-in. (All of this is included in the exported HTML report.)

#### Attack strategies: is the guard robust to obfuscation?

The **Strategies** picker wraps each attack in obfuscation variants — `Base64`,
`Hex`, `ROT13`, `Homoglyph` (look-alike Unicode), `Leetspeak`, `Roleplay` (DAN) —
and runs them alongside the plaintext base. Each variant gets a **Variant** column
tag; a variant that **slips past a guard which caught the plaintext** is flagged
`EVADED` (red) and counted in the **Guard evasions** stat. This answers "does
base64-encoding a known-blocked prompt bypass CP1?" — 0 evasions means the guard
held. Transforms are pure/deterministic (no extra LLM cost) and are included in
the exported report.

Outcomes are colour-coded:

| Outcome | Meaning |
|---|---|
| `BLOCKED` | An attack scenario was correctly stopped |
| `PASSED` | A safe scenario was correctly allowed |
| `NOT BLOCKED` | An attack scenario got through — expected for defence-in-depth categories (LLM03/04/06/09/10) |
| `FALSE POSITIVE` | A safe scenario was wrongly blocked |
| `ERROR` | The scenario failed to run (e.g. LLM endpoint unreachable) |

The summary strip reports totals and an attack **detection rate** (`blocked ÷ attack scenarios run`).

#### External datasets (HuggingFace & upload)

The **Datasets** panel in the One-Shot toolbar lets you test against external attack
corpora instead of (or alongside) the built-in catalogue:

- **HuggingFace** — enter a dataset id (one-click **Salad-Data** / **ALERT** buttons) and **Import**. Rows are fetched server-side through the public [datasets-server](https://huggingface.co/docs/datasets-server) API (paginated, no full download). The **prompt column is auto-detected** (`prompt`, `question`, `baseq`/`augq`, `instruction`, …); override it with the **column** field if needed. The first config/split is used by default.
- **Upload** — a `.csv` / `.json` / `.jsonl` / `.txt` file (prompt column auto-detected; `.txt` = one prompt per line).

Imported datasets appear in the **scope** dropdown as *"Dataset: … (N)"* and run as `external` attack scenarios through the full pipeline (CP1/CP2/CP3 + optional judge / Guard ON-OFF / strategies), graded against a generic "complied with the harmful request" criterion.

**Limits & notes:**

| Limit | Value | Why |
|---|---|---|
| Imported datasets kept at once | **12** | In-memory cap (`MAX_DATASETS`); delete one to add more |
| Rows imported per dataset | **100,000 max** (default **25**) | Each prompt that passes CP1 makes a real LLM call, so large imports are slow/costly — raise deliberately |
| Upload file size | **16 MB** | — |
| Auth | **public datasets only** | No HF token is sent; gated/private datasets and datasets with the HF *Dataset Viewer* disabled won't import |
| Persistence | **in-memory** | Imported datasets are cleared on server restart — re-import after a rebuild |

> There is **no limit on which** public dataset you import — any with the Dataset Viewer enabled works. The caps above are on **how many** you keep (12) and **how many rows** each holds (100,000). For large corpora, keep the row count modest or point the LLM provider at a local model to avoid cost/latency — fetching 100k rows is ~1,000 paginated API calls and runs a full pipeline pass per prompt.

> **Multi-config datasets:** many datasets are split into *configs* (e.g. SALAD-Data → `base_set` 21,318, `attack_enhanced_set` 5,000, `defense_enhanced_set` 200, `mcq_set` 3,840 ≈ 30,358 total). **Import** (with a row count) defaults to the **largest** config; **All** spans **every** config + split to pull the whole dataset, streaming live progress against the combined total. Because the pull is paginated and HuggingFace rate-limits the free API, a very large **All** may finish as a (large) **partial** sample within the time budget — re-run for more, or use a local model.

#### Custom system prompt (per run)

The **System prompt** panel lets you supply a system prompt that applies **only to that
run**, overriding the active one — handy for evaluating a candidate prompt against any
scope (built-in, dataset, with strategies/judge/compare) without changing the global
prompt. Leave it blank to use the currently active prompt, or tick **No system prompt at
all** to send the model nothing but the attack (and any RAG context) — useful for probing
raw model behaviour with no guardrail instructions.

#### Knowledge base override + custom RAG upload (per run)

The **Knowledge base** panel forces the RAG source for the whole run — **Default**
(each scenario's own setting), **None** (no RAG file at all), **Clean**, **Poisoned**, or
**Custom**. **Upload .txt** adds your own document(s) and selects **Custom**, so every
scenario retrieves from (and CP2 scans) your file — test the guard against your real
knowledge base or a crafted poisoned doc.

#### Run configuration in the report

Every run records exactly what fed the model, shown in a **Run configuration** panel
(modal + HTML report):

- **System prompt** — *Used* (with its source — built-in default, active custom, or per-run override — **and the full text**) or *Not used* when **No system prompt** is selected.
- **Knowledge base (RAG)** — *Used* with the **document contents** for the chosen mode (clean/poisoned/custom), *per scenario* when no override is set (content is in each row's reveal), or *Not used* when **None** is selected.

So if you leave both at their defaults, the report makes clear a system prompt **and** a RAG knowledge base were in effect — and shows precisely what they were.

#### Security posture dashboard & recommendations

Every run is analysed into a **security report** (shown in the modal and the exported
HTML report, and carried in the JSON):

- **Posture banner** — an overall rating from `Secure` → `Critical` based on the worst finding.
- **Findings & recommendations** — an ordered, severity-tagged narrative of *what happened* and *how to fix it* (e.g. real breaches → keep CP3 + strip context; obfuscation evasions → normalise/decode inputs; attacks that passed the guard → add defence-in-depth; false positives → tune sensitivity; plus the guard-ON/OFF risk reduction when compared).
- **Vulnerability dashboard** — a per-OWASP table with attacks, detection rate, a severity chip (`critical`/`high`/`medium`/`low`/`secure`), and a one-line remediation for each category.

Severity is derived from the run: a **real breach** (guard missed × model complied) is `critical`, an **obfuscation evasion** is `high`, an attack the guard simply missed is `medium` (or `low` if the model resisted it), and a fully-blocked category is `secure`.

> Attack scenarios that block at CP1 never reach the LLM, so a One-Shot run over injection-heavy categories is cheap. Running *All categories* will make real LLM calls for the scenarios that pass CP1 — point the provider at a local model (LM Studio / Ollama / oMLX) to run the full sweep at zero cost.

## Report Generation

After a One-Shot run, two export buttons become active in the modal toolbar:

- **HTML Report** — a self-contained, styled `.html` file (no external assets) with the summary cards, checkpoint legend, and full results table, stamped with the timestamp, provider, model, and endpoint. Each row has a native **"Show prompt & RAG documents"** disclosure (click-to-reveal, collapsed by default) carrying the prompt, simulated output, and retrieved docs. Open it in any browser or attach it to a ticket.
- **JSON** — the raw run payload (summary + per-scenario traces + provider metadata) for programmatic analysis or diffing across runs.

Files are named `lakera-oneshot-<timestamp>.{html,json}` and download directly from the browser.

---

## Running Integration Tests

The `tests/integration/` suite calls the Lakera Guard API directly (no LLM call) and asserts expected outcomes for every fixture scenario.

```bash
# Run all integration tests
pytest tests/integration/test_lakera_scenarios.py -v

# Run only Checkpoint 1 tests
pytest tests/integration/test_lakera_scenarios.py -v -k "checkpoint_1"

# Run only RAG document tests (Checkpoint 2)
pytest tests/integration/test_lakera_scenarios.py -v -k "checkpoint_2"

# Run only output tests (Checkpoint 3)
pytest tests/integration/test_lakera_scenarios.py -v -k "checkpoint_3"
```

Tests auto-skip if `LAKERA_GUARD_API_KEY` is not set in the environment. Export it or use a `.env`-aware test runner.

```bash
export LAKERA_GUARD_API_KEY=your_key_here
pytest tests/integration/ -v
```

---

## Project Structure

```
AI assistant demo/
├── backend/
│   ├── main.py          # FastAPI app, API routes, global state
│   ├── chat.py          # Checkpoint orchestration (CP0–CP3 flow)
│   ├── lakera.py        # Lakera Guard v2 API client
│   ├── llm.py           # OpenAI-compatible LLM client, provider presets + default system prompt
│   ├── judge.py         # LLM-as-judge: did the attack actually compromise the model?
│   ├── strategies.py    # Attack-obfuscation transforms (base64, homoglyph, …)
│   ├── report.py        # Security posture: vulnerability dashboard + findings/recommendations
│   ├── datasets.py      # External dataset import (HuggingFace API + CSV/JSON/JSONL/TXT upload)
│   ├── rag.py           # Keyword-based document retrieval
│   ├── scenarios.py     # OWASP-mapped scenario catalogue (50 scenarios, 12 categories)
│   └── config.py        # pydantic-settings: reads .env
│
├── frontend/
│   └── index.html       # Single-page UI (ligne-claire comic aesthetic, no build step)
│
├── tests/
│   ├── fixtures/
│   │   ├── docs_clean/           # Legitimate RAG documents
│   │   │   ├── faq_returns_clean.txt
│   │   │   └── product_manual_clean.txt
│   │   ├── docs_poisoned/        # Documents with injections and PII (intentional)
│   │   │   ├── faq_returns_poisoned.txt
│   │   │   ├── product_manual_poisoned.txt
│   │   │   └── customer_cases_poisoned.txt
│   │   ├── docs_custom/          # Uploaded custom documents (runtime, gitignored)
│   │   ├── prompts_attack.json   # Attack prompt fixtures for integration tests
│   │   └── prompts_safe.json     # Safe prompt fixtures for integration tests
│   └── integration/
│       └── test_lakera_scenarios.py  # pytest suite against live Lakera API
│
├── .env                 # API keys (not committed)
├── requirements.txt     # Python dependencies
├── Dockerfile
└── docker-compose.yml
```

### Key API endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/chat` | Send a message; returns response + full checkpoint trace |
| `GET` | `/api/system-prompt` | Get the current system prompt and mode |
| `POST` | `/api/system-prompt` | CP0-scan and (if clean) activate a new system prompt |
| `DELETE` | `/api/system-prompt` | Reset to the built-in default prompt |
| `GET` | `/api/docs-mode` | Get current knowledge base mode |
| `POST` | `/api/docs-mode` | Switch mode: `"clean"`, `"poisoned"`, or `"custom"` |
| `POST` | `/api/docs/upload` | Upload a custom `.txt` document (multipart/form-data) |
| `GET` | `/api/docs/custom` | List uploaded custom documents |
| `DELETE` | `/api/docs/custom/{filename}` | Delete a custom document |
| `GET` | `/api/scenario-categories` | Return the full OWASP scenario catalogue |
| `GET` | `/api/llm-config` | Current LLM provider config (key masked) + provider presets |
| `POST` | `/api/llm-config` | Switch / update the LLM provider |
| `POST` | `/api/llm-config/test` | Probe an endpoint (`GET /models`) without saving it |
| `POST` | `/api/oneshot` | Run a category, dataset, or all scenarios through the pipeline; optional LLM-judge grading, guard ON/OFF comparison, obfuscation strategies, and a per-run system-prompt override; returns results + summary |
| `POST` | `/api/oneshot/stream` | Same run as `/api/oneshot` but streams NDJSON progress (one event per finished scenario) so the UI counter ticks live |
| `GET` | `/api/strategies` | List available attack-obfuscation strategies |
| `GET` | `/api/datasets` | List imported external datasets |
| `POST` | `/api/datasets/import-hf` | Import a public HuggingFace dataset (`dataset_id`, optional `config`/`split`/`column`/`limit`) |
| `POST` | `/api/datasets/upload` | Upload a `.csv` / `.json` / `.jsonl` / `.txt` dataset (multipart) |
| `DELETE` | `/api/datasets/{slug}` | Delete an imported dataset |
| `GET` | `/api/lakera-config` | Whether the Lakera Guard key is set (masked) |
| `POST` | `/api/lakera-config` | Set/clear the Lakera Guard key (runtime) |
| `POST` | `/api/config/save-env` | Persist the current keys + LLM provider to `.env` |

---

## Notes on Intentional Demo Data

Several pieces of sensitive-looking data in this project are **deliberate and synthetic** — they exist specifically to trigger Lakera Guard's PII and injection detectors for demonstration purposes:

- **`backend/llm.py` — system prompt**: Contains **no personal data** — only the ShopEase role description and a non-sensitive order reference. (The CP3 PII-leakage scenarios provide their own synthetic PII via simulated LLM output, so none needs to live in the system context.)

- **`tests/fixtures/docs_poisoned/`**: Three documents with embedded injection instructions and fake SSN/card number patterns. These are the RAG documents that CP2 is designed to intercept.

- **None of these values are real.** They follow realistic formats to be detectable by Lakera Guard's PII models, but are entirely fabricated.

Do not replace them with actual personal data or real credentials.
