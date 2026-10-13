"""End-to-end evaluation on the miniature recording set with the committed rules."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import RULES
from dac.coverage import build_layer
from dac.evaluate import evaluate, expected_match, metrics
from dac.report import write_figures, write_matrix, write_metrics, write_report
from dac.rules import load_rules


@pytest.fixture
def result(dataset: Path, reviews: Path):
    return evaluate(dataset, RULES, reviews=reviews, jobs=1)


def test_expected_match_counts_sub_techniques_under_their_parent():
    assert expected_match({"T1003.001"}, {"T1003", "T1003.001"})
    assert expected_match({"T1003.002"}, {"T1003", "T1003.001"})  # shared parent T1003
    assert not expected_match({"T1547.001"}, {"T1003", "T1003.001"})
    assert not expected_match({"T1547.001"}, set())


def test_duplicate_recording_is_scored_once(result):
    assert result.duplicates == ["windows/defense_evasion/host/lsass.zip"]
    assert len(result.outcomes) == 5


def test_outcomes_and_miss_reasons(result):
    by_name = {o.recording.name: o for o in result.outcomes}
    assert by_name["run_key"].detected and by_name["lsass"].detected
    assert by_name["no_telemetry"].miss_reason == "required telemetry absent"
    assert by_name["no_match"].miss_reason == "telemetry present, no rule matched"
    assert not by_name["unlabelled"].in_scope


def test_filters_suppress_benign_events(result):
    firings = {(f.rule, Path(f.recording).stem): f for f in result.firings}
    assert firings[("run_key_modification", "run_key")].alerts == 1  # Defender write filtered
    assert firings[("lsass_memory_access", "lsass")].alerts == 1  # wininit boot handle filtered


def test_off_target_signature_carries_the_review_verdict(result):
    [group] = result.off_target
    assert group.rule == "run_key_modification"
    assert group.status == "attack"
    assert list(group.recordings) == ["windows/discovery/host/unlabelled.zip"]


def test_metrics(result):
    m = metrics(result)
    assert m["detection"] == {
        "in_scope": 4,
        "detected": 2,
        "detection_rate": 0.5,
        "in_scope_with_any_alert": 2,
        "missed_telemetry_absent": 1,
        "missed_no_rule_match": 1,
    }
    assert m["alerts"]["total"] == 3
    assert m["alerts"]["expected"] == 2
    assert m["alerts"]["off_target_attack"] == 1
    assert m["alerts"]["false_positive"] == 0
    assert m["recordings"]["unlabelled"] == 1
    rows = {r["technique"]: r for r in m["per_technique"]}
    assert rows["T1003.001"] == {
        "technique": "T1003.001",
        "name": "OS Credential Dumping: LSASS Memory",
        "recordings": 2,
        "detected": 1,
        "detection_rate": 0.5,
    }
    run_key = m["per_rule"]["run_key_modification"]
    assert (run_key["labelled_recordings_fired"], run_key["labelled_recordings"]) == (1, 2)
    dump = m["per_rule"]["registry_hive_dump"]  # T1003.002/.004: no such recording here
    assert dump["labelled_recordings"] == 0


def test_unreviewed_signatures_are_reported(dataset: Path):
    m = metrics(evaluate(dataset, RULES, reviews=None, jobs=1))
    assert m["alerts"]["unreviewed"] == 1
    assert m["off_target_signatures"]["unreviewed"] == 1


def test_parallel_and_serial_runs_agree(dataset: Path, reviews: Path, result):
    parallel = evaluate(dataset, RULES, reviews=reviews, jobs=2)
    assert metrics(parallel) == metrics(result)


def test_report_artifacts_are_written(result, tmp_path: Path):
    m = metrics(result)
    write_metrics(m, tmp_path / "metrics.json", None)
    write_matrix(result, tmp_path / "detection_matrix.csv")
    report = write_report(result, m, tmp_path / "REPORT.md", first=m)
    figures = write_figures(result, m, tmp_path, first=m)
    assert "Missed recordings" in report.read_text()
    assert all(p.exists() and p.stat().st_size > 10_000 for p in figures)
    header = (tmp_path / "detection_matrix.csv").read_text().splitlines()[0]
    assert header.startswith("rule,")


def test_coverage_layer_scores(result):
    layer = build_layer(load_rules(RULES), metrics(result))
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert scores["T1547.001"] == 3  # rule validated on a recording
    assert scores["T1003.002"] == 2  # rule exists, no labelled recording here
    assert layer["domain"] == "enterprise-attack"
    unscored = build_layer(load_rules(RULES))
    assert {t["score"] for t in unscored["techniques"]} == {2}
