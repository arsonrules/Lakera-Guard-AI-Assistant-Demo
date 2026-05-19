# Lakera Guard — AI Assistant Security Demo

An interactive single-page application that demonstrates how [Lakera Guard](https://www.lakera.ai/) protects a production-style AI customer-service assistant against a wide range of LLM security threats. Every request flows through four scanning checkpoints before a response reaches the user, and the browser UI visualises each checkpoint result in real time.
<img width="1512" height="854" alt="截圖 2026-05-20 凌晨12 52 27" src="https://github.com/user-attachments/assets/868fab70-93ce-4dad-83a7-9d01da63acd1" />

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
8. [Running Integration Tests](#running-integration-tests)
9. [Project Structure](#project-structure)
10. [Notes on Intentional Demo Data](#notes-on-intentional-demo-data)

---

## What This Application Does

The demo simulates a fictional online retailer (**ShopEase**) whose customer-service chatbot is powered by Claude (via OpenRouter) and protected by Lakera Guard. Visitors can:

- **Chat freely** with the assistant to observe normal, helpful responses.
- **Fire pre-built attack scenarios** organised by OWASP LLM Top 10 (2025) category and watch Lakera Guard intercept them at the appropriate checkpoint.
- **Upload poisoned or custom documents** to the RAG knowledge base and see CP2 redact dangerous content before it reaches the LLM.
- **Inject a custom system prompt** — benign or malicious — and observe CP0 accepting or rejecting it before it is ever activated.
- **Simulate malicious LLM outputs** to test whether CP3 catches injected instructions before they reach the browser.

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

| Category | OWASP ID | Checkpoint(s) | Notes |
|---|---|---|---|
| Safe Baselines | — | All pass | Regression baseline; should never be blocked |
| Prompt Injection | LLM01:2025 | CP1 | Direct overrides, DAN, Base64, XML tags, separator tricks |
| Sensitive Info Disclosure | LLM02:2025 | CP1 | Bulk PII dumps, API key extraction, repeat-back, context window dumps |
| Improper Output Handling | LLM05:2025 | CP3 | Simulated outputs containing hidden instructions or jailbreak propagation |
| Excessive Agency | LLM06:2025 | CP1 (partial) | Delete records, mass emails, privilege escalation — shows limits of injection-focused guards |
| System Prompt Leakage | LLM07:2025 | CP1 | Verbatim extraction, debug-mode tricks, translation bypass, summarisation |
| Vector & RAG Poisoning | LLM08:2025 | CP2 | Hidden HTML comments, competitor diversion, PII-containing case studies |
| Misinformation | LLM09:2025 | CP1 (partial) | False policy premises, fabricated authority — highlights need for output validation beyond Lakera |
| Agentic Threats | AGENTIC | CP1 | SQL injection in tool calls, forged tool results, multi-turn escalation, context window poisoning |

---

## Prerequisites

| Requirement | Minimum version | Purpose |
|---|---|---|
| **Python** | 3.11 | Backend runtime |
| **pip** | 23+ | Package installation |
| **Lakera Guard API key** | — | Scanning all four checkpoints |
| **OpenRouter API key** | — | LLM completions via Claude |
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
# Ensure .env is populated (see Configuration below)
docker compose up --build
```

---

## Configuration

Create a `.env` file in the project root (never commit this file):

```dotenv
OPENROUTER_API_KEY=sk-or-v1-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
LAKERA_GUARD_API_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
OPENROUTER_MODEL=anthropic/claude-sonnet-4.5
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `OPENROUTER_API_KEY` | Yes | — | OpenRouter key for LLM completions |
| `LAKERA_GUARD_API_KEY` | Yes | — | Lakera Guard key for all checkpoint scans |
| `OPENROUTER_MODEL` | No | `anthropic/claude-sonnet-4.5` | Any model available on your OpenRouter plan |

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
│   ├── llm.py           # OpenRouter LLM client + default system prompt
│   ├── rag.py           # Keyword-based document retrieval
│   ├── scenarios.py     # OWASP-mapped scenario catalogue (37 scenarios, 9 categories)
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

---

## Notes on Intentional Demo Data

Several pieces of sensitive-looking data in this project are **deliberate and synthetic** — they exist specifically to trigger Lakera Guard's PII and injection detectors for demonstration purposes:

- **`backend/llm.py` — system prompt**: Contains a fake SSN (`234-56-7890`) and payment card (`Visa ending 4242`) for the fictitious customer Alice Johnson. These values make it possible to demonstrate CP3 catching PII leakage in LLM output.

- **`tests/fixtures/docs_poisoned/`**: Three documents with embedded injection instructions and fake SSN/card number patterns. These are the RAG documents that CP2 is designed to intercept.

- **None of these values are real.** They follow realistic formats to be detectable by Lakera Guard's PII models, but are entirely fabricated.

Do not replace them with actual personal data or real credentials.
