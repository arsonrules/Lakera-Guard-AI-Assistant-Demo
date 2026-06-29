"""Offline tests for run-history persistence + regression diff."""
import pytest

from backend import history
from backend.oneshot import load_baseline, render_diff


def _summary(**kw):
    base = {"base_detection_rate": 90.0, "detection_rate": 90.0, "breaches": 0,
            "effective_evasions": 0, "evasions": 0, "not_blocked": 1,
            "false_positive": 0, "errors": 0, "total": 50,
            "security": {"posture": {"level": "low"}}}
    base.update(kw)
    return base


def test_save_list_load_roundtrip(tmp_path):
    rec = history.save({"summary": _summary(), "results": []}, tmp_path, label="run A")
    runs = history.list_runs(tmp_path)
    assert len(runs) == 1 and runs[0]["id"] == rec["id"]
    assert runs[0]["label"] == "run A"
    assert runs[0]["metrics"]["base_detection_rate"] == 90.0
    full = history.load(tmp_path, rec["id"])
    assert full["summary"]["total"] == 50


def test_load_rejects_path_traversal(tmp_path):
    assert history.load(tmp_path, "../etc/passwd") is None
    assert history.delete(tmp_path, "../../x") is False


def test_diff_detects_detection_drop_and_new_breach():
    base = _summary(base_detection_rate=95.0, breaches=0)
    head = _summary(base_detection_rate=80.0, breaches=2)
    d = history.diff_summaries(base, head)
    assert d["regressed"] is True
    by = {r["metric"]: r for r in d["metrics"]}
    assert by["base_detection_rate"]["delta"] == -15.0 and by["base_detection_rate"]["regressed"]
    assert by["breaches"]["delta"] == 2 and by["breaches"]["regressed"]


def test_diff_improvement_is_not_regression():
    base = _summary(base_detection_rate=80.0, breaches=2)
    head = _summary(base_detection_rate=95.0, breaches=0)
    d = history.diff_summaries(base, head)
    assert d["regressed"] is False


def test_load_baseline_accepts_record_or_summary(tmp_path):
    rec = history.save({"summary": _summary()}, tmp_path)
    path = tmp_path / f"{rec['id']}.json"
    assert load_baseline(str(path))["total"] == 50          # full record
    import json
    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps(_summary()))
    assert load_baseline(str(bare))["total"] == 50          # bare summary


def test_load_baseline_missing_raises():
    from backend.oneshot import ConfigError
    with pytest.raises(ConfigError):
        load_baseline("/no/such/run.json")


def test_render_diff_smoke():
    d = history.diff_summaries(_summary(breaches=0), _summary(breaches=3))
    out = render_diff(d)
    assert "REGRESSION" in out and "breaches" in out
