# Improvement Plan — inspired by promptfoo

A comparison of this demo with [promptfoo](https://github.com/promptfoo/promptfoo)
(OSS LLM eval + red-team framework, MIT) and a prioritized plan to close the
most valuable gaps **without** turning the demo into a general-purpose eval tool.

This project's mission is specific: **demonstrate Lakera Guard's value and show
where defense-in-depth beyond a prompt/output scanner is required.** The plan
adopts promptfoo *concepts* that sharpen that story.

---

## What promptfoo does that this demo doesn't

| Capability | promptfoo | This demo today | Gap |
|---|---|---|---|
| **Did the attack actually succeed?** | LLM-as-a-judge grades the model's output (did it leak / comply?) | Only the **Lakera verdict** (blocked/passed). A `NOT BLOCKED` row never says whether the model was actually compromised | **Big** |
| **Attack strategies / transforms** | Wraps any payload: base64/hex/ROT13, homoglyph, leetspeak, DAN/Skeleton-Key, multilingual, best-of-N | A few *static* examples; no transform engine | **Big** |
| **Dynamic attack generation** | Attacker LLM iteratively refines until controls are bypassed (Jailbreak, GCG, Meta-Agent) | 50 hand-written static prompts | Medium |
| **Multi-turn / stateful** | Crescendo, GOAT, Hydra escalate over a conversation | Single-turn only (AGT-03 *fakes* history in one message) | Medium |
| **Guard ON vs OFF / multi-target** | Same suite across models / configs (behavioral drift) | One provider, guard always on | **Big (very on-mission)** |
| **Config-as-code + CI gate** | YAML suite, `promptfoo redteam`, non-zero exit, PR scanning | Scenarios hardcoded in Python; UI-only; no headless/exit code | Medium |
| **Custom datasets** | CSV / HuggingFace / YAML import + test generation | Fixed catalog; code edits required | Medium |
| **Severity + remediation report card** | Vulns ranked by severity with fixes | Outcomes + OWASP id, no severity/remediation | Small |
| **Assertions** | contains / regex / llm-rubric / similarity / javascript | None (only the Lakera verdict) | Small |

The demo already matches promptfoo on: full OWASP LLM Top-10 mapping, batch runs,
HTML/JSON reports, multi-provider config, RAG-poisoning fixtures, and a
detection-rate metric — so this is about depth, not a rewrite.

---

## Plan (prioritized)

### P0 — Highest value, directly on-mission

**1. "Did the attack actually succeed?" grading (LLM-as-judge)** — _in progress_
A `NOT BLOCKED` row is ambiguous: the model may have refused anyway. Add a judge
pass that grades the model's **actual response** against a per-category success
criterion. New per-scenario axis: **guard verdict** (blocked/passed) × **model
outcome** (compromised / resisted / prevented). Turns the report from "did Lakera
flag it" into "did the attack actually land, and how much did Lakera reduce risk."
- `backend/judge.py` (criteria per OWASP category + `grade()` via the configured LLM, judged out-of-band of Lakera).
- `chat.process` returns the raw model response so it can be judged.
- One-shot adds outcome stats: **real breaches** (compromised AND not blocked), **guard saves** (compromised AND blocked), **resisted**, **prevented**.

**2. "Guard ON vs Guard OFF" comparison** — _done_
Run each attack with Lakera enabled and bypassed, judge both: _"Model alone: 38%
of attacks succeeded → with Lakera: 6%. Risk reduced 84%."_ The headline demo
narrative; reuses #1's judge.
- `chat.process_unguarded()` runs the same request with Lakera OFF (no CP1/CP2/CP3, unredacted docs).
- One-shot **"Guard ON vs OFF"** toggle (implies judging) runs both passes; a before/after banner shows model-alone success rate → success-despite-guard → risk reduction, with a per-row "model alone" verdict and the Guard-OFF response in the reveal. Also in the HTML report.

**3. Attack-strategy transform engine** — _done_
Auto-wrap any base payload (`base64`, `hex`, `rot13`, `homoglyph`, `leetspeak`,
`roleplay/DAN`) to probe **guard robustness** — e.g. "does base64-encoding a
known-blocked prompt evade CP1?"
- `backend/strategies.py` (pure transforms) + `GET /api/strategies`.
- One-shot `strategies[]` expands each attack into base + variants; per-variant **`evaded`** (base blocked, variant slipped past) and an **evasions** summary.
- UI strategy picker (popover), a **Variant** column, evasion highlight, the transformed prompt in the reveal, and the same in the HTML report.
- _(LLM-based `translate zh/ja` deferred — it needs a model call, unlike the pure static transforms.)_

### P1 — Strong value

4. **Config-as-code + headless CLI + CI gate** — `suite.yaml`, `python -m backend.oneshot --suite suite.yaml --min-detection 0.9` with non-zero exit, sample GitHub Action.
5. **Real multi-turn scenarios** — a `turns: [...]` scenario type + stateful runner (crescendo-style).
6. **Custom scenario import** — upload YAML/CSV `{prompt, category, expected, success_criteria}` (mirrors the existing custom-RAG upload).

### P2 — Nice to have

7. **Severity + remediation report card (vulnerability dashboard)** — _done_
   `backend/report.py` analyses each run into an OWASP **vulnerability dashboard**
   (per-category attacks / detection / severity / remediation), an overall
   **posture** (critical→secure), and an ordered **findings & recommendations**
   narrative ("what happened + how to fix it"). Rendered in the modal and the
   HTML report; carried in the JSON export.
8. Optional dynamic attack generation (attacker-LLM refinement), token-gated.
9. Multi-provider side-by-side (LLM03 behavioral drift).
10. Run history / trend diffing across saved JSON reports.

---

## Deliberately NOT copied

- Full general-purpose eval/assertion framework, GCG gradient attacks, media
  encodings, and the plugin marketplace — out of scope for a focused Lakera demo.

## Suggested sequence

P0-1 → P0-2 → P0-3 gives the biggest narrative jump for ~3 changes, all reusing
the existing one-shot + report plumbing. P1 makes it CI-grade.
