"""
Compliance framework mapping for one-shot runs.

A run already tells you *what happened technically* ("LLM01 detection 82%, 3
breaches"). This module answers the follow-up an auditor actually asks: **which
obligation does that evidence, and where are the gaps?** It maps the OWASP
category ids the catalogue already assigns onto controls in EU AI Act, ISO/IEC
42001, NIST AI RMF and MITRE ATLAS, then grades each control from the run's own
observed outcomes.

Design notes
------------
* Pure data + pure functions. No I/O, no config, no state — same shape as
  `backend/classify.py`, so it is trivially testable and safe to import anywhere.
* Keyed on the OWASP ids the catalogue *already* produces, so there is no second
  taxonomy to maintain and no re-classification step.
* A control the run never exercised is reported as **no_evidence**, never as a
  pass. "We didn't test it" and "it works" must never render the same way.

⚠️ REVIEW STATUS
----------------
These references are a triage aid to point a reader at the relevant clause —
they are **not legal advice and not a certification**. Article/function-level
references are used deliberately in preference to deep sub-clause numbering that
would be easy to get subtly wrong. `VERIFIED` stays False until someone with
compliance ownership signs the table off; the UI surfaces that state.
"""
from __future__ import annotations

# Flip to True only after a compliance owner has reviewed MAPPINGS end to end.
VERIFIED = False

DISCLAIMER = (
    "Framework references are a triage aid, not legal advice or a certification. "
    "Coverage reflects only the scenarios executed in this run."
)

# Display order + full names for the frameworks we cite.
FRAMEWORKS = {
    "eu-ai-act": {
        "name": "EU AI Act",
        "url": "https://artificialintelligenceact.eu/",
    },
    "iso-42001": {
        "name": "ISO/IEC 42001:2023",
        "url": "https://www.iso.org/standard/81230.html",
    },
    "nist-ai-rmf": {
        "name": "NIST AI RMF 1.0",
        "url": "https://www.nist.gov/itl/ai-risk-management-framework",
    },
    "mitre-atlas": {
        "name": "MITRE ATLAS",
        "url": "https://atlas.mitre.org/",
    },
}

# owasp category id -> controls it provides evidence for.
# `ref` is the citation as a reader would look it up; `title` is the control's
# own wording, kept in English because it is a citation, not UI copy.
MAPPINGS: dict[str, list[dict]] = {
    "llm01": [   # Prompt Injection
        {"fw": "eu-ai-act",   "ref": "Art. 15", "title": "Accuracy, robustness and cybersecurity"},
        {"fw": "iso-42001",   "ref": "Annex A.6", "title": "AI system life cycle: verification and validation"},
        {"fw": "nist-ai-rmf", "ref": "MEASURE 2", "title": "AI system performance and trustworthiness are evaluated"},
        {"fw": "mitre-atlas", "ref": "AML.T0051", "title": "LLM Prompt Injection"},
    ],
    "llm02": [   # Sensitive Information Disclosure
        {"fw": "eu-ai-act",   "ref": "Art. 10", "title": "Data and data governance"},
        {"fw": "iso-42001",   "ref": "Annex A.7", "title": "Data for AI systems"},
        {"fw": "nist-ai-rmf", "ref": "MEASURE 2", "title": "Privacy risk of the AI system is evaluated"},
        {"fw": "mitre-atlas", "ref": "AML.T0057", "title": "LLM Data Leakage"},
    ],
    "llm03": [   # Supply Chain
        {"fw": "eu-ai-act",   "ref": "Art. 25", "title": "Responsibilities along the AI value chain"},
        {"fw": "iso-42001",   "ref": "Annex A.10", "title": "Third-party and customer relationships"},
        {"fw": "nist-ai-rmf", "ref": "GOVERN 6", "title": "Third-party software and data risks are managed"},
        {"fw": "mitre-atlas", "ref": "AML.T0010", "title": "ML Supply Chain Compromise"},
    ],
    "llm04": [   # Data & Model Poisoning
        {"fw": "eu-ai-act",   "ref": "Art. 10", "title": "Data and data governance"},
        {"fw": "iso-42001",   "ref": "Annex A.7", "title": "Data for AI systems"},
        {"fw": "nist-ai-rmf", "ref": "MANAGE 2", "title": "Strategies to maximise benefits and minimise risks are planned"},
        {"fw": "mitre-atlas", "ref": "AML.T0020", "title": "Poison Training Data"},
    ],
    "llm05": [   # Improper Output Handling
        {"fw": "eu-ai-act",   "ref": "Art. 15", "title": "Accuracy, robustness and cybersecurity"},
        {"fw": "iso-42001",   "ref": "Annex A.6", "title": "AI system life cycle: verification and validation"},
        {"fw": "nist-ai-rmf", "ref": "MEASURE 2", "title": "AI system performance and trustworthiness are evaluated"},
    ],
    "llm06": [   # Excessive Agency
        {"fw": "eu-ai-act",   "ref": "Art. 14", "title": "Human oversight"},
        {"fw": "iso-42001",   "ref": "Annex A.9", "title": "Use of AI systems: responsible use and oversight"},
        {"fw": "nist-ai-rmf", "ref": "GOVERN 3", "title": "Roles, responsibilities and human oversight are defined"},
    ],
    "llm07": [   # System Prompt Leakage
        {"fw": "eu-ai-act",   "ref": "Art. 15", "title": "Accuracy, robustness and cybersecurity"},
        {"fw": "iso-42001",   "ref": "Annex A.6", "title": "AI system life cycle: verification and validation"},
        {"fw": "mitre-atlas", "ref": "AML.T0051", "title": "LLM Prompt Injection (system prompt extraction)"},
    ],
    "llm08": [   # Vector & RAG Poisoning
        {"fw": "eu-ai-act",   "ref": "Art. 10", "title": "Data and data governance"},
        {"fw": "iso-42001",   "ref": "Annex A.7", "title": "Data for AI systems"},
        {"fw": "nist-ai-rmf", "ref": "MAP 2",  "title": "AI system context and data provenance are documented"},
    ],
    "llm09": [   # Misinformation
        {"fw": "eu-ai-act",   "ref": "Art. 50", "title": "Transparency obligations for certain AI systems"},
        {"fw": "iso-42001",   "ref": "Annex A.8", "title": "Information for interested parties"},
        {"fw": "nist-ai-rmf", "ref": "MEASURE 2", "title": "AI system validity and reliability are evaluated"},
    ],
    "llm10": [   # Unbounded Consumption
        {"fw": "eu-ai-act",   "ref": "Art. 15", "title": "Accuracy, robustness and cybersecurity"},
        {"fw": "iso-42001",   "ref": "Annex A.6", "title": "AI system life cycle: operation and monitoring"},
        {"fw": "nist-ai-rmf", "ref": "MANAGE 4", "title": "Post-deployment monitoring and response are in place"},
    ],
    "agentic": [  # Agentic threats (tool calls, escalation, context poisoning)
        {"fw": "eu-ai-act",   "ref": "Art. 14", "title": "Human oversight"},
        {"fw": "iso-42001",   "ref": "Annex A.9", "title": "Use of AI systems: responsible use and oversight"},
        {"fw": "nist-ai-rmf", "ref": "GOVERN 3", "title": "Roles, responsibilities and human oversight are defined"},
        {"fw": "mitre-atlas", "ref": "AML.T0053", "title": "LLM Plugin Compromise"},
    ],
}

# A control is only credited when detection clears this bar. Below it the run
# *did* exercise the control but did not demonstrate it holding.
EVIDENCED_MIN_DETECTION = 90.0
PARTIAL_MIN_DETECTION = 50.0


def for_category(category_id: str) -> list[dict]:
    """Controls a single OWASP category provides evidence for."""
    return list(MAPPINGS.get(category_id, []))


def _verdict(attacks: int, detection_rate: float | None, breaches: int) -> str:
    """
    Grade one control from the run's observed outcomes.

    `no_evidence` is deliberately distinct from a pass: a control the run never
    exercised is UNKNOWN. Rendering it as green would be the single most
    misleading thing this report could do.
    """
    if not attacks:
        return "no_evidence"
    if breaches:
        return "gap"                       # something actually got through and landed
    if detection_rate is None:
        return "no_evidence"
    if detection_rate >= EVIDENCED_MIN_DETECTION:
        return "evidenced"
    if detection_rate >= PARTIAL_MIN_DETECTION:
        return "partial"
    return "gap"


_VERDICT_RANK = {"gap": 0, "partial": 1, "no_evidence": 2, "evidenced": 3}


def coverage(security: dict) -> dict:
    """
    Turn a run's per-category security block into per-framework control coverage.

    `security` is the dict produced by `backend.report.analyse` (it carries a
    `categories` list of {id, owasp_id, attacks, detection_rate, breaches, …}).
    Returns a payload the report/UI renders directly.
    """
    cats = {c["id"]: c for c in (security or {}).get("categories", []) or []}

    # control key -> aggregated evidence from every category that maps to it
    controls: dict[tuple[str, str], dict] = {}
    for cat_id, refs in MAPPINGS.items():
        cat = cats.get(cat_id)
        for ref in refs:
            key = (ref["fw"], ref["ref"])
            entry = controls.setdefault(key, {
                "framework": ref["fw"],
                "framework_name": FRAMEWORKS[ref["fw"]]["name"],
                "ref": ref["ref"],
                "title": ref["title"],
                "evidence": [],          # owasp ids that exercised this control
                "attacks": 0,
                "blocked": 0,
                "breaches": 0,
            })
            if not cat or not cat.get("attacks"):
                continue
            entry["evidence"].append(cat.get("owasp_id") or cat_id)
            entry["attacks"] += cat.get("attacks", 0)
            entry["blocked"] += cat.get("blocked", 0)
            entry["breaches"] += cat.get("breaches", 0)

    out: dict[str, dict] = {}
    for (fw, _ref), entry in controls.items():
        entry["detection_rate"] = (
            round(entry["blocked"] / entry["attacks"] * 100, 1) if entry["attacks"] else None
        )
        entry["verdict"] = _verdict(entry["attacks"], entry["detection_rate"], entry["breaches"])
        bucket = out.setdefault(fw, {
            "id": fw,
            "name": FRAMEWORKS[fw]["name"],
            "url": FRAMEWORKS[fw]["url"],
            "controls": [],
        })
        bucket["controls"].append(entry)

    frameworks = []
    for fw in FRAMEWORKS:                     # stable, curated display order
        if fw not in out:
            continue
        bucket = out[fw]
        # Worst-first so gaps are impossible to miss, then by citation.
        bucket["controls"].sort(key=lambda c: (_VERDICT_RANK[c["verdict"]], c["ref"]))
        bucket["evidenced"] = sum(1 for c in bucket["controls"] if c["verdict"] == "evidenced")
        bucket["total"] = len(bucket["controls"])
        frameworks.append(bucket)

    totals = {v: 0 for v in _VERDICT_RANK}
    for b in frameworks:
        for c in b["controls"]:
            totals[c["verdict"]] += 1

    return {
        "verified": VERIFIED,
        "disclaimer": DISCLAIMER,
        "frameworks": frameworks,
        "totals": totals,
        "control_count": sum(b["total"] for b in frameworks),
    }
