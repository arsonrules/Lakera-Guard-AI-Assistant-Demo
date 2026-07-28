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


# ── Sidecar metadata (listing must not parse the heavy results payload) ───────

def test_save_writes_meta_sidecar(tmp_path):
    rec = history.save({"summary": _summary(), "results": [{"id": "r1"}]}, tmp_path)
    assert (tmp_path / f"{rec['id']}.meta.json").exists()


def test_list_runs_ignores_sidecars_as_runs(tmp_path):
    history.save({"summary": _summary()}, tmp_path)
    runs = history.list_runs(tmp_path)
    assert len(runs) == 1                       # the .meta.json is not its own row
    assert not runs[0]["id"].endswith(".meta")


def test_list_runs_backfills_legacy_records(tmp_path):
    """Runs saved before sidecars existed are parsed once, then back-filled."""
    import json
    rid = "20200101-000000"
    (tmp_path / f"{rid}.json").write_text(json.dumps(
        {"id": rid, "saved_at": "2020-01-01T00:00:00+00:00",
         "label": "legacy", "summary": _summary()}))
    runs = history.list_runs(tmp_path)
    assert [r["label"] for r in runs] == ["legacy"]
    assert (tmp_path / f"{rid}.meta.json").exists()          # migrated


def test_list_runs_does_not_read_the_payload(tmp_path, monkeypatch):
    """Regression: the whole point of the sidecar. Listing must never open the
    (potentially 100 MB) run file once its sidecar exists."""
    rec = history.save({"summary": _summary(), "results": [{"i": i} for i in range(500)]}, tmp_path)
    run_file = tmp_path / f"{rec['id']}.json"

    real_read = type(run_file).read_text
    opened: list[str] = []

    def spy(self, *a, **k):
        opened.append(self.name)
        return real_read(self, *a, **k)

    monkeypatch.setattr(type(run_file), "read_text", spy)
    history.list_runs(tmp_path)
    assert run_file.name not in opened                        # only the sidecar was read


def test_delete_removes_sidecar(tmp_path):
    rec = history.save({"summary": _summary()}, tmp_path)
    assert history.delete(tmp_path, rec["id"]) is True
    assert not (tmp_path / f"{rec['id']}.json").exists()
    assert not (tmp_path / f"{rec['id']}.meta.json").exists()
    assert history.list_runs(tmp_path) == []
