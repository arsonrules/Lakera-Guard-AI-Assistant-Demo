# Running the One-Shot Test from the CLI — a manual walkthrough

The **one-shot test** fires attack (and safe) prompts through the full Lakera Guard
pipeline (CP1 user input → CP2 RAG documents → CP3 LLM output) and reports, per
scenario, what the guard blocked, redacted, or let through. The **headless CLI**
(`python -m backend.oneshot`) runs that exact pipeline without the web UI — ideal
for scripting, large dataset sweeps, and CI gates.

This guide walks through a clean manual setup end to end: dependencies →
environment → verification → running. Everything runs locally; secrets come from
your shell environment only.

---

## 1. Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| **Python** | **3.11+** | `python3 --version` to check. |
| **git** | any | To clone the repo (skip if you already have it). |
| **Network access** | — | To reach Lakera Guard, your LLM provider, and (optionally) HuggingFace. |
| **A Lakera Guard API key** | — | Required — the checkpoints call the Guard API. Get one at <https://platform.lakera.ai>. |
| **An LLM provider** | — | A cloud key (e.g. OpenRouter) **or** a local server (LM Studio / Ollama / oMLX) — see step 3. |

> A per-turn note on cost: attack prompts that block at **CP1** never reach the
> model, so injection-heavy runs are cheap. Prompts that pass CP1 make a real LLM
> call — use a local model (step 3) to run large corpora at zero cost.

---

## 2. Get the code and install dependencies

From a terminal:

```bash
# 1. Get the project (skip if you already have it) and enter it
git clone <your-repo-url> ai-assistant-demo
cd ai-assistant-demo

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate          # macOS/Linux
# .venv\Scripts\activate           # Windows (PowerShell: .venv\Scripts\Activate.ps1)

# 3. Install the runtime dependencies
pip install -r requirements.txt

# 4. (Optional) dev dependencies — only if you want to run the test suite
pip install -r requirements-dev.txt
```

**Runtime dependencies** (`requirements.txt`): `fastapi`, `uvicorn[standard]`,
`httpx`, `pydantic-settings`, `python-multipart`, `pyyaml`. Just install the whole
file — it gives you one environment for both the CLI and the web app.

> **Always run the CLI from the project root** (the directory containing the
> `backend/` folder) with the venv activated, so the `backend` package is
> importable and relative paths (`.env`, `runs/`) resolve.

---

## 3. Choose and prepare an LLM provider

The one-shot test needs a model to generate the "assistant" responses that CP3
scans. Pick one:

### Option A — Cloud (OpenRouter, default)
Get a key at <https://openrouter.ai/keys>. You'll set `OPENROUTER_API_KEY` (or
`LLM_API_KEY`) in step 4. Default model: `anthropic/claude-sonnet-4.6`.

### Option B — Local model (no LLM key, zero cost)
Run a local OpenAI-compatible server, then pass `--provider`:

| Provider flag | Default base URL | Needs a key? |
|---|---|---|
| `--provider lmstudio` | `http://localhost:1234/v1` | No |
| `--provider ollama` | `http://localhost:11434/v1` | No |
| `--provider omlx` | `http://localhost:10240/v1` | No |
| `--provider custom --base-url <url>` | you provide | optional |

Override the model with `--model <id>` and the endpoint with `--base-url <url>`.

---

## 4. Set the environment variables

**The CLI reads secrets from your shell environment — it does not auto-load
`.env`.** Set them one of two ways:

**Option 1 — export directly (per shell session):**
```bash
export LAKERA_GUARD_API_KEY="your-lakera-key"      # required
export OPENROUTER_API_KEY="your-openrouter-key"    # required for cloud LLM (Option A)
# export LLM_API_KEY="..."                         # alternative to OPENROUTER_API_KEY
# export JUDGE_API_KEY="..."                        # only if you use a separate judge provider
```

**Option 2 — keep them in `.env` and load it into the shell:**
```bash
cp .env.example .env      # then edit .env and fill in your keys
set -a; source .env; set +a   # export every var from .env into this shell
```

Variables the CLI uses:

| Variable | Required? | Purpose |
|---|---|---|
| `LAKERA_GUARD_API_KEY` | **Yes** | Authenticates every CP1/CP2/CP3 Guard scan. |
| `OPENROUTER_API_KEY` *or* `LLM_API_KEY` | Yes for cloud LLM | Target-model key (not needed for local providers). |
| `JUDGE_API_KEY` | Optional | Only when using a dedicated `--judge-provider`. |
| `LAKERA_ENDPOINT` | Optional | Regional Guard host, e.g. `https://eu-west-1.api.lakera.ai` (from `.env`; default is Community). |

> For a **`--dry-run`** (validate + print the plan, no API calls) you need **no
> keys at all** — great for a first smoke test.

---

## 5. Verify the setup

```bash
# See every flag
python -m backend.oneshot --help

# Validate config and preview the run WITHOUT calling any API (no keys needed)
python -m backend.oneshot --all-categories --dry-run
```

A successful dry-run prints a plan like:
```
Run plan (dry-run — no API calls):
  provider     : openrouter · anthropic/claude-sonnet-4.6
  judge model  : same as target
  scope        : all categories
  scenarios    : 56 of 56
  strategies   : none
  total rows   : 56 (incl. variants)
  judge/compare: True / False
```

---

## 6. Run your first real test

With the environment set (step 4):

```bash
# One OWASP category, judge off for speed, 8 workers in parallel
python -m backend.oneshot --category llm01 --no-judge --concurrency 8
```

You'll get a summary ending in `GATE PASS` / `GATE FAIL`. Scope options:

```bash
# The whole built-in catalogue (56 scenarios across LLM01–LLM10, agentic, multi-turn, dynamic)
python -m backend.oneshot --all-categories

# A single category (ids: safe, llm01…llm10, agentic, multiturn, dynamic)
python -m backend.oneshot --category llm06
```

---

## 7. Run your own / imported datasets

The CLI runs local files, a whole directory, or public HuggingFace datasets —
several **together** in one graded run.

### Local files (repeatable) and directories
```bash
# Multiple local files together (.csv/.json/.jsonl/.txt; .txt = one prompt per line)
python -m backend.oneshot \
  --dataset-file attacks/prompt_injection.csv \
  --dataset-file attacks/pii_leak.jsonl \
  --no-judge --concurrency 32 --csv results.csv

# Every supported file in a directory
python -m backend.oneshot --dataset-dir ./attack_corpora --concurrency 64
```

### HuggingFace datasets — e.g. `OpenSafetyLab/Salad-Data`
```bash
# Import 500 rows of Salad-Data and run them, 100 workers in parallel
python -m backend.oneshot \
  --hf-dataset OpenSafetyLab/Salad-Data \
  --hf-limit 500 --concurrency 100 \
  --out salad_report.json --csv salad_results.csv

# Several HuggingFace datasets together
python -m backend.oneshot \
  --hf-dataset OpenSafetyLab/Salad-Data --hf-dataset Babelscape/ALERT \
  --hf-limit 200
```

- **`--hf-dataset OWNER/NAME`** (repeatable) — imported server-side via the public
  HuggingFace datasets API (no token). The prompt column is auto-detected
  (Salad-Data's `baseq`/`augq` are found automatically); override with
  **`--hf-column`**.
- **`--hf-limit N`** — rows per dataset (default **100**). Salad-Data is large
  (~30k), so keep a limit unless you use **`--hf-all`** (every row, up to 100,000
  — slow; HuggingFace may rate-limit and keep a partial sample).
- HuggingFace datasets are **not** imported during `--dry-run` (that stays
  network-free); the plan lists them as `hf (at run)`.

> The prompts you import run as `external` **attack** scenarios and are graded
> against a generic "did the model comply?" criterion, and each imported prompt is
> classified into an OWASP LLM/Agentic tactic in the report.

---

## 8. Make it fast (concurrency)

`--concurrency N` runs **N scenarios in parallel** (1–100, default 4). The guard
checkpoints share a keep-alive connection pool, so high concurrency scans in
parallel without a fresh TLS handshake per checkpoint.

```bash
python -m backend.oneshot --hf-dataset OpenSafetyLab/Salad-Data --hf-limit 2000 --concurrency 100
```

Dial it back if your Lakera/LLM provider rate-limits (429s are retried with
backoff, but heavy throttling slows the run). `--max-scenarios N` (default 100,
max 100,000) caps the base scenarios; larger datasets are randomly **sampled**
down (reproducibly with `--seed`).

---

## 9. Read and save the results

The stdout summary shows posture, blocked / not-blocked counts, base detection
rate, a per-OWASP line, the imported-dataset tactic classification, and the gate
verdict. Save machine-readable output:

```bash
python -m backend.oneshot --all-categories \
  --out report.json \      # full JSON payload (results + summary + security report)
  --csv results.csv \      # one row per scenario
  --format md              # emit a Markdown summary to stdout (e.g. a CI step summary)
python -m backend.oneshot --all-categories --quiet --out report.json   # suppress stdout summary
```

---

## 10. Use it as a CI gate

Add thresholds; the process exits non-zero when one is violated, so a pipeline
fails the build:

```bash
python -m backend.oneshot --all-categories \
  --min-detection 0.9 \            # base (plaintext) detection ≥ 90%
  --max-breaches 0 \               # no attack may reach the user with the model complying
  --max-effective-evasions 0 \     # no obfuscated payload may land
  --strategies base64,homoglyph    # also test obfuscated variants
```

**Exit codes:** `0` all gates passed · `1` a gate was violated · `2` configuration
error (bad flags/suite, missing key) · `3` execution error (LLM/Lakera
unreachable — nothing evaluated). A ready-to-use GitHub workflow is in
[`.github/workflows/redteam.yml`](.github/workflows/redteam.yml).

### Config-as-code with a suite file
Instead of long flag lists, declare scope/options/provider/gate in a YAML suite
(any flag still overrides its suite value):

```bash
python -m backend.oneshot --suite suite.yaml
```
See [`suite.yaml`](suite.yaml) for the format.

### Regression tracking
```bash
python -m backend.oneshot --suite suite.yaml \
  --save-history \                                  # append this run to runs/
  --baseline runs/20250101-030000.json \            # diff against a saved run
  --fail-on-regression                              # exit 1 if a metric regressed
```

---

## 11. Full flag reference

| Group | Flag | Meaning |
|---|---|---|
| **Scope** | `--category ID` | One OWASP category (`llm01`…`llm10`, `agentic`, `multiturn`, `dynamic`, `safe`). |
| | `--all-categories` | The whole built-in catalogue. |
| | `--dataset SLUG` | An already-imported dataset slug (mainly for suites). |
| | `--dataset-file PATH` | Local `.csv/.json/.jsonl/.txt` — **repeatable**. |
| | `--dataset-dir DIR` | Every supported file in a directory. |
| | `--hf-dataset OWNER/NAME` | Import a public HuggingFace dataset — **repeatable**. |
| | `--hf-limit N` / `--hf-column C` / `--hf-all` | Rows per HF dataset / prompt column override / import everything. |
| | `--max-scenarios N` | Cap base scenarios (default 100, ≤100,000; larger datasets sampled). |
| | `--seed N` | Reproducible sampling. |
| **Options** | `--judge` / `--no-judge` | Grade responses with the LLM judge (default on). |
| | `--compare` | Also run each attack with Lakera OFF (risk-reduction; doubles model calls). |
| | `--strategies a,b` | Obfuscation variants: `base64, hex, rot13, homoglyph, leetspeak, roleplay, reverse, zero_width, morse`. |
| | `--doc-mode clean\|poisoned\|custom\|none` | Force the RAG knowledge base for the run. |
| | `--concurrency N` | Parallel workers (1–100, default 4). |
| | `--max-rounds N` | Round budget for dynamic (adaptive attacker) scenarios (1–10). |
| **Provider** | `--provider` / `--base-url` / `--model` | Target LLM (`openrouter`, `lmstudio`, `ollama`, `omlx`, `custom`). |
| **Judge** | `--judge-provider` / `--judge-base-url` / `--judge-model` | Optional stronger judge model (key from `JUDGE_API_KEY`). |
| **Gate** | `--min-detection 0..1` · `--max-breaches` · `--max-evasions` · `--max-effective-evasions` · `--max-false-positives` | CI thresholds (a `null`/unset threshold isn't enforced). |
| **Output** | `--out PATH` · `--csv PATH` · `--format text\|md` · `--quiet` | JSON / CSV / stdout format. |
| | `--dry-run` | Validate + print the plan, **no API calls**. |
| **History** | `--save-history` · `--history-dir DIR` · `--baseline RUN.json` · `--fail-on-regression` | Save & diff runs over time. |

---

## 12. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `config error: LAKERA_GUARD_API_KEY is not set.` | Export it (step 4) — the CLI reads the **shell environment**, not `.env` unless you `source` it. |
| `config error: OpenRouter (cloud) requires an API key …` | Set `OPENROUTER_API_KEY`/`LLM_API_KEY`, or use a local `--provider` (step 3B). |
| `No module named backend` | Run from the **project root** with the venv activated. |
| `config error: HuggingFace '…': …` | Dataset id must be `owner/name`, public, and have the Dataset Viewer enabled; try `--hf-column` if no prompt column is detected. |
| `execution error: every scenario failed …` (exit 3) | The LLM/Lakera endpoint was unreachable, or the model/base-URL is wrong — verify keys, `--provider`, `--base-url`. |
| Run is slow / lots of retries | Provider rate-limiting at high `--concurrency`; lower it, or reduce `--hf-limit`/`--max-scenarios`, or use a local model. |
| `This run would execute N scenarios (limit 100000) …` | `base × (1 + strategies)` exceeded the row cap; lower `--max-scenarios` or pick fewer `--strategies`. |

---

## Quick reference — copy/paste starters

```bash
# 0) one-time setup
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
export LAKERA_GUARD_API_KEY="..."; export OPENROUTER_API_KEY="..."

# 1) smoke test (no keys, no API calls)
python -m backend.oneshot --all-categories --dry-run

# 2) run the built-in catalogue
python -m backend.oneshot --all-categories --no-judge --concurrency 16

# 3) import & run Salad-Data from HuggingFace, save results
python -m backend.oneshot --hf-dataset OpenSafetyLab/Salad-Data \
  --hf-limit 500 --concurrency 100 --out report.json --csv results.csv

# 4) CI gate
python -m backend.oneshot --all-categories --min-detection 0.9 --max-breaches 0
```
