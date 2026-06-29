"""Offline tests for the headless CLI (backend.oneshot): suite parsing, config
merge, gate evaluation, dry-run, and exit codes. No network."""
import json

import pytest

import backend.main as core
from backend import oneshot
from backend.oneshot import (ConfigError, build_effective_config, build_parser,
                             build_request, evaluate_gate, load_suite,
                             resolve_judge_config, resolve_llm_config)


@pytest.fixture(autouse=True)
def _restore_globals(monkeypatch):
    # main() assigns core._llm_config/_lakera_key; pin them so monkeypatch restores after.
    monkeypatch.setattr(core, "_llm_config", core._llm_config)
    monkeypatch.setattr(core, "_lakera_key", core._lakera_key)


def _args(argv):
    return build_parser().parse_args(argv)


# ── suite loading + config merge ──────────────────────────────────────────────

def test_load_suite_yaml_and_json(tmp_path):
    y = tmp_path / "s.yaml"
    y.write_text("scope:\n  category: llm01\noptions:\n  judge: false\n")
    assert load_suite(str(y))["scope"]["category"] == "llm01"
    j = tmp_path / "s.json"
    j.write_text(json.dumps({"gate": {"max_breaches": 2}}))
    assert load_suite(str(j))["gate"]["max_breaches"] == 2


def test_missing_suite_raises():
    with pytest.raises(ConfigError):
        load_suite("/no/such/suite.yaml")


def test_flags_override_suite(tmp_path):
    y = tmp_path / "s.yaml"
    y.write_text("scope:\n  category: llm01\noptions:\n  strategies: [rot13]\n")
    cfg = build_effective_config(_args(
        ["--suite", str(y), "--all-categories", "--strategies", "base64,homoglyph",
         "--max-breaches", "0"]))
    assert cfg["scope"]["category"] is None          # --all-categories wins
    assert cfg["options"]["strategies"] == ["base64", "homoglyph"]
    assert cfg["gate"]["max_breaches"] == 0


def test_suite_used_when_no_flag(tmp_path):
    y = tmp_path / "s.yaml"
    y.write_text("scope:\n  category: llm02\n")
    cfg = build_effective_config(_args(["--suite", str(y)]))
    assert cfg["scope"]["category"] == "llm02"


# ── provider resolution ───────────────────────────────────────────────────────

def test_resolve_requires_key(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        resolve_llm_config({"provider": "openrouter", "model": "x"})
    # dry-run skips the key/model requirement
    cfg = resolve_llm_config({"provider": "openrouter"}, dry_run=True)
    assert cfg["provider"] == "openrouter"


def test_judge_config_defaults_to_target(monkeypatch):
    monkeypatch.delenv("JUDGE_API_KEY", raising=False)
    # Nothing configured → None → judge falls back to the target model.
    assert resolve_judge_config({"provider": None, "base_url": None, "model": None}) is None


def test_judge_config_from_flags(tmp_path):
    cfg = build_effective_config(_args(["--judge-provider", "ollama", "--judge-model", "llama3.1"]))
    jc = resolve_judge_config(cfg["judge_llm"])
    assert jc["provider"] == "ollama" and jc["model"] == "llama3.1"


def test_judge_config_requires_key_when_cloud(monkeypatch):
    monkeypatch.delenv("JUDGE_API_KEY", raising=False)
    with pytest.raises(ConfigError):
        resolve_judge_config({"provider": "openrouter", "model": "x"})


def test_build_request_validation_error():
    cfg = build_effective_config(_args(["--max-scenarios", "99999"]))
    with pytest.raises(ConfigError):       # pydantic le=1000 → mapped to ConfigError
        build_request(cfg)


# ── gate evaluation ───────────────────────────────────────────────────────────

def _summary(**kw):
    base = {"base_detection_rate": 100.0, "breaches": 0, "evasions": 0,
            "effective_evasions": 0, "false_positive": 0}
    base.update(kw)
    return base


def test_gate_passes_when_clean():
    gate = {"min_detection": 0.9, "max_breaches": 0, "max_effective_evasions": 0}
    ok, fails = evaluate_gate(_summary(), gate)
    assert ok and fails == []


def test_gate_fails_on_low_detection():
    ok, fails = evaluate_gate(_summary(base_detection_rate=50.0), {"min_detection": 0.9})
    assert not ok and "detection" in fails[0]


def test_gate_fails_on_breach():
    ok, fails = evaluate_gate(_summary(breaches=2), {"max_breaches": 0})
    assert not ok and "breaches" in fails[0]


def test_gate_unset_thresholds_not_enforced():
    ok, _ = evaluate_gate(_summary(breaches=5, base_detection_rate=0.0), {})
    assert ok


# ── main(): dry-run + gate exit codes (run mocked) ────────────────────────────

def test_main_dry_run_returns_zero(monkeypatch, capsys):
    monkeypatch.delenv("LAKERA_GUARD_API_KEY", raising=False)
    code = oneshot.main(["--all-categories", "--dry-run"])
    assert code == 0
    assert "Run plan" in capsys.readouterr().out


def _mock_run(summary):
    async def _run(req, *, llm_config, lakera_key, judge_config=None):
        return {"summary": summary, "results": []}
    return _run


def _full_summary(**kw):
    s = {"total": 5, "blocked": 5, "not_blocked": 0, "passed": 0, "false_positive": 0,
         "errors": 0, "judged": True, "breaches": 0, "resisted": 0, "prevented": 5,
         "base_detection_rate": 100.0, "detection_rate": 100.0, "strategies_used": [],
         "security": {"posture": {"level": "secure", "headline": "ok"}, "categories": []}}
    s.update(kw)
    return s


def test_main_gate_pass(monkeypatch):
    monkeypatch.setenv("LAKERA_GUARD_API_KEY", "k")
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    monkeypatch.setattr(core, "run_oneshot", _mock_run(_full_summary()))
    assert oneshot.main(["--all-categories", "--min-detection", "0.9", "--max-breaches", "0"]) == 0


def test_main_gate_fail_exit_1(monkeypatch):
    monkeypatch.setenv("LAKERA_GUARD_API_KEY", "k")
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    summary = _full_summary(blocked=3, not_blocked=2, base_detection_rate=60.0,
                            breaches=1, prevented=3,
                            security={"posture": {"level": "critical", "headline": "bad"},
                                      "categories": []})
    monkeypatch.setattr(core, "run_oneshot", _mock_run(summary))
    assert oneshot.main(["--all-categories", "--max-breaches", "0"]) == 1


def test_main_save_history_and_regression_exit_1(monkeypatch, tmp_path):
    import json
    monkeypatch.setenv("LAKERA_GUARD_API_KEY", "k")
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    baseline = tmp_path / "base.json"
    baseline.write_text(json.dumps({"summary": _full_summary(base_detection_rate=100.0, breaches=0)}))
    # This run regressed: detection dropped and a breach appeared.
    summary = _full_summary(blocked=3, not_blocked=2, base_detection_rate=60.0, breaches=1)
    monkeypatch.setattr(core, "run_oneshot", _mock_run(summary))
    runs_dir = tmp_path / "runs"
    code = oneshot.main(["--all-categories", "--baseline", str(baseline),
                         "--fail-on-regression", "--save-history", "--history-dir", str(runs_dir)])
    assert code == 1                                  # regression fails the gate
    assert list(runs_dir.glob("*.json"))             # run was saved to history


def test_main_execution_error_exit_3(monkeypatch):
    monkeypatch.setenv("LAKERA_GUARD_API_KEY", "k")
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    summary = _full_summary(total=3, blocked=0, not_blocked=0, errors=3,
                            base_detection_rate=None, detection_rate=None)
    monkeypatch.setattr(core, "run_oneshot", _mock_run(summary))
    assert oneshot.main(["--all-categories"]) == 3
