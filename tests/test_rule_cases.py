"""Per-rule unit tests (tests/rule_cases/*.yml) and the integrity of the review files."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from conftest import REPO, RULES
from dac import attack
from dac.review import load_verdicts
from dac.ruletest import CASES_DIR, run_cases

CASES = REPO / CASES_DIR
SUITE = run_cases(RULES, CASES)


@pytest.mark.parametrize("result", SUITE.results, ids=lambda r: f"{r.rule}: {r.name}")
def test_rule_case(result):
    assert result.passed, f"expected match={result.expected}, got {result.actual}"


def test_every_rule_has_positive_and_negative_cases():
    assert SUITE.problems == []


def test_suite_reports_structural_problems(tmp_path: Path):
    (tmp_path / "only_positive.yml").write_text(
        yaml.safe_dump(
            {
                "rule": "mavinject_dll_injection",
                "defaults": {"Channel": "Microsoft-Windows-Sysmon/Operational", "EventID": 1},
                "cases": [
                    {
                        "name": "p",
                        "match": True,
                        "event": {"Image": "C:\\x\\mavinject.exe", "CommandLine": "INJECTRUNNING"},
                    }
                ],
            }
        )
    )
    suite = run_cases(RULES, tmp_path)
    assert not suite.ok
    assert any("one matching and one non-matching" in p for p in suite.problems)
    assert any("has no test cases" in p for p in suite.problems)


def test_reviews_are_well_formed_and_reference_known_rules_and_techniques():
    verdicts = load_verdicts(REPO / "reviews/off_target.yaml")
    slugs = {p.stem for p in RULES.rglob("*.yml")}
    assert verdicts
    for v in verdicts.values():
        assert v.rule in slugs
        assert not v.technique or attack.is_known(v.technique)


def test_tuning_log_lists_only_existing_rules_and_allowed_kinds():
    entries = yaml.safe_load((REPO / "reviews/tuning_log.yaml").read_text())
    slugs = {p.stem for p in RULES.rglob("*.yml")}
    assert entries
    for e in entries:
        assert e["rule"] in slugs
        assert e["kind"] in {"bug-fix", "benign-filter"}
        assert e["change"] and e["evidence"]


def test_load_verdicts_rejects_bad_entries(tmp_path: Path):
    bad = tmp_path / "r.yaml"
    bad.write_text(
        yaml.safe_dump([{"rule": "x", "signature": "s", "verdict": "maybe", "rationale": "r"}])
    )
    with pytest.raises(ValueError, match="verdict"):
        load_verdicts(bad)
    bad.write_text(yaml.safe_dump([{"rule": "x", "signature": "s", "verdict": "benign"}]))
    with pytest.raises(ValueError, match="missing"):
        load_verdicts(bad)
    assert load_verdicts(tmp_path / "absent.yaml") == {}
