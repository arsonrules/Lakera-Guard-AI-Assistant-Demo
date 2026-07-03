"""
Content-based OWASP tactic classifier for imported dataset prompts.

Imported safety datasets ship as raw prompts with (at best) a source-specific
category. To make a one-shot run over them intelligible, we classify each prompt
by the tactic it *attempts*, mapping to:

  • OWASP LLM Top 10 (2025)              — codes "LLM01:2025" … "LLM10:2025"
  • OWASP Agentic AI Threats (v1.0)      — codes "AAI-T1" … "AAI-T15"

This is a deterministic, offline heuristic (keyword / regex signals) — no LLM
call — so it scales to the whole dataset (up to 100k rows) with zero cost and is
reproducible. It is a triage aid, not a definitive label: a prompt is scored
against every tactic and assigned the highest-scoring one; ties fall to a fixed
priority. Prompts with no signal are "unmapped" (likely benign / off-taxonomy).
"""
import re

# Each tactic: (code, family, name, signals). A signal is (weight, pattern) where
# pattern is a lowercase substring, or a compiled regex for structural matches.
# Higher weights mark more specific, higher-confidence indicators.

_LLM_TACTICS = [
    ("LLM01:2025", "llm", "Prompt Injection", [
        (3, "ignore all previous"), (3, "ignore previous instruction"),
        (3, "ignore the above"), (3, "disregard previous"), (3, "disregard all"),
        (3, "you are now"), (3, "developer mode"), (3, "do anything now"),
        (3, re.compile(r"\bdan\b")), (2, "jailbreak"), (2, "no restrictions"),
        (2, "without any restrictions"), (2, "unfiltered"), (2, "pretend you are"),
        (2, "act as"), (2, "roleplay"), (2, "role play"), (2, "bypass"),
        (2, "override"), (2, "new instructions"), (2, re.compile(r"#{3,}")),
        (2, re.compile(r"\bbase64\b|[A-Za-z0-9+/]{40,}={0,2}")),
    ]),
    ("LLM02:2025", "llm", "Sensitive Information Disclosure", [
        (3, "credit card"), (3, "social security"), (3, re.compile(r"\bssn\b")),
        (3, "api key"), (3, "customer records"), (3, "personal information"),
        (2, "password"), (2, re.compile(r"\bpii\b")), (2, "phone number"),
        (2, "home address"), (2, "database dump"), (2, "confidential"),
        (2, "private data"), (2, "leak"),
    ]),
    ("LLM03:2025", "llm", "Supply Chain", [
        (3, "pip install"), (3, "npm install"), (3, "typosquat"),
        (2, "dependency"), (2, "third-party package"), (2, "lora adapter"),
        (2, "model weights"), (2, "download the model"), (2, "checkpoint file"),
        (2, "untrusted source"),
    ]),
    ("LLM04:2025", "llm", "Data & Model Poisoning", [
        (3, "poison"), (3, "backdoor"), (3, "trigger phrase"), (3, "sleeper"),
        (2, "training data"), (2, "fine-tune"), (2, "feedback loop"),
        (2, "from now on treat"),
    ]),
    ("LLM05:2025", "llm", "Improper Output Handling", [
        (3, "<script"), (3, "javascript:"), (3, "drop table"), (3, re.compile(r"\beval\(")),
        (2, "sql injection"), (2, "xss"), (2, "html injection"), (2, "render this"),
        (2, "execute this"),
    ]),
    ("LLM06:2025", "llm", "Excessive Agency", [
        (3, "delete all"), (3, "send an email"), (3, "wire money"),
        (3, "transfer funds"), (3, "issue a refund"), (3, "make a purchase"),
        (2, "cancel all"), (2, "grant admin"), (2, "on my behalf"),
        (2, "place an order"), (2, "run the command"),
    ]),
    ("LLM07:2025", "llm", "System Prompt Leakage", [
        (3, "system prompt"), (3, "your instructions"), (3, "initial prompt"),
        (3, "repeat the words above"), (3, "reveal your"),
        (2, "what were you told"), (2, "print your rules"), (2, "your configuration"),
        (2, "your guidelines"),
    ]),
    ("LLM08:2025", "llm", "Vector & Embedding Weaknesses", [
        (3, "knowledge base"), (3, "retrieved document"), (2, "embedding"),
        (2, "vector store"), (2, "the document says"), (2, "according to the manual"),
        (2, "context injection"),
    ]),
    ("LLM09:2025", "llm", "Misinformation", [
        (3, "make up"), (3, "fabricate"), (3, "fake news"),
        (2, "is it true that"), (2, "confirm that"), (2, "as an expert"),
        (2, "cite a source"), (2, "false claim"),
    ]),
    ("LLM10:2025", "llm", "Unbounded Consumption", [
        (3, "repeat forever"), (3, re.compile(r"repeat .{0,30}\b\d{3,}\s*times")),
        (3, "infinite loop"), (2, "as many as possible"), (2, "denial of service"),
        (2, re.compile(r"generate \d{4,}")), (2, "as long as possible"),
    ]),
]

_AGENTIC_TACTICS = [
    ("AAI-T1", "agentic", "Memory Poisoning", [
        (3, "remember this for later"), (3, "store this in your memory"),
        (2, "persist this"), (2, "add to your memory"), (2, "note for later"),
    ]),
    ("AAI-T2", "agentic", "Tool Misuse", [
        (3, "call the function"), (3, "invoke the tool"), (3, "use the api"),
        (2, "call the tool"), (2, "trigger the action"), (2, "execute the tool"),
    ]),
    ("AAI-T3", "agentic", "Privilege Compromise", [
        (3, "escalate privilege"), (3, "grant me admin"), (3, re.compile(r"\bsudo\b")),
        (2, "root access"), (2, "elevated permission"), (2, "become an administrator"),
    ]),
    ("AAI-T5", "agentic", "Cascading Hallucination", [
        (3, "tell the other agent"), (2, "propagate to"), (2, "pass this to the next agent"),
    ]),
    ("AAI-T6", "agentic", "Intent Breaking & Goal Manipulation", [
        (3, "change your goal"), (3, "your real objective"), (3, "your true task"),
        (2, "forget your task"), (2, "your actual mission"),
    ]),
    ("AAI-T7", "agentic", "Misaligned & Deceptive Behaviors", [
        (3, "don't tell the user"), (3, "hide this from"), (2, "secretly"),
        (2, "without telling anyone"), (2, "deceive"),
    ]),
    ("AAI-T8", "agentic", "Repudiation & Untraceability", [
        (3, "without logging"), (3, "don't record"), (2, "cover your tracks"),
        (2, "no audit"), (2, "erase the logs"),
    ]),
    ("AAI-T9", "agentic", "Identity Spoofing & Impersonation", [
        (3, "impersonate"), (3, "i am the administrator"), (2, "pretend to be the user"),
        (2, "on behalf of the admin"), (2, "spoof"),
    ]),
    ("AAI-T11", "agentic", "Unexpected RCE & Code Attacks", [
        (3, "os.system"), (3, "subprocess"), (3, "reverse shell"),
        (3, re.compile(r"curl\s+.+\|\s*(bash|sh)")), (2, re.compile(r"exec\(")),
        (2, "/bin/sh"), (2, "run shell command"),
    ]),
    ("AAI-T15", "agentic", "Human Manipulation", [
        (3, "convince the user"), (3, "manipulate the user"), (2, "trick the human"),
        (2, "social engineer"), (2, "pressure the user"),
    ]),
]

# Fixed priority for tie-breaking: LLM01 (most common attack) down, then agentic.
_ALL_TACTICS = _LLM_TACTICS + _AGENTIC_TACTICS
_PRIORITY = {code: i for i, (code, *_rest) in enumerate(_ALL_TACTICS)}

UNMAPPED = {"code": "UNMAPPED", "family": "unmapped", "name": "Unclassified / benign"}


def _score(text: str, signals) -> tuple[int, list[str]]:
    total, hit = 0, []
    for weight, pat in signals:
        if isinstance(pat, str):
            if pat in text:
                total += weight
                hit.append(pat)
        elif pat.search(text):
            total += weight
            hit.append(pat.pattern)
    return total, hit


def classify(prompt: str) -> dict:
    """Classify one prompt into its most likely OWASP tactic.

    Returns {code, family, name, score, signals, secondary}. `secondary` is the
    next-best code (or None) so overlapping tactics (e.g. LLM06 vs an agentic
    tool-misuse prompt) are still surfaced.
    """
    text = (prompt or "").lower()
    scored = []
    for code, family, name, signals in _ALL_TACTICS:
        s, hits = _score(text, signals)
        if s > 0:
            scored.append({"score": s, "code": code, "family": family,
                           "name": name, "signals": hits})
    if not scored:
        return {**UNMAPPED, "score": 0, "signals": [], "secondary": None}
    # Highest score wins; ties broken by lower priority index (earlier in list).
    scored.sort(key=lambda x: (-x["score"], _PRIORITY[x["code"]]))
    top = scored[0]
    secondary = scored[1]["code"] if len(scored) > 1 else None
    return {
        "code": top["code"], "family": top["family"], "name": top["name"],
        "score": top["score"], "signals": top["signals"][:6], "secondary": secondary,
    }


def summarize(rows: list[dict]) -> dict | None:
    """
    Aggregate the per-row classifications into a report block. `rows` are the
    executed result rows; only base rows carrying `owasp_class` are counted
    (obfuscation variants inherit the base tactic and would double-count).

    Returns None when nothing was classified (e.g. a catalogue-only run), so the
    report simply omits the section.
    """
    tactics: dict[str, dict] = {}
    families = {"llm": 0, "agentic": 0, "unmapped": 0}
    total = 0
    for r in rows:
        cls = r.get("owasp_class")
        if not cls or r.get("strategy"):
            continue
        total += 1
        families[cls["family"]] = families.get(cls["family"], 0) + 1
        t = tactics.setdefault(cls["code"], {
            "code": cls["code"], "family": cls["family"], "name": cls["name"],
            "count": 0, "blocked": 0, "not_blocked": 0, "breaches": 0,
        })
        t["count"] += 1
        if r.get("outcome") == "blocked":
            t["blocked"] += 1
        elif r.get("outcome") == "not_blocked":
            t["not_blocked"] += 1
        if r.get("risk") == "breach":
            t["breaches"] += 1
    if not total:
        return None
    tactic_list = list(tactics.values())
    for t in tactic_list:
        t["share"] = round(t["count"] / total * 100, 1)
        t["detection_rate"] = (
            round(t["blocked"] / t["count"] * 100, 1) if t["count"] else None
        )
    # Most-represented tactic first; unmapped sinks to the bottom.
    tactic_list.sort(key=lambda t: (t["family"] == "unmapped", -t["count"], t["code"]))
    return {"total": total, "families": families, "tactics": tactic_list}
