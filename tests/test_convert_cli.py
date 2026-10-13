"""Query conversion and the command-line interface."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from conftest import REPO, RULES
from dac.cli import app
from dac.convert import TARGETS, convert_rule

runner = CliRunner()


def test_conversion_to_every_target():
    rule = RULES / "credential_access/lsass_dump_via_comsvcs.yml"
    for target in TARGETS.values():
        conversion = convert_rule(rule, target)
        assert conversion.ok, conversion.error
        assert "comsvcs" in conversion.query.lower()
    assert convert_rule(rule, TARGETS["kql"]).query.startswith("DeviceProcessEvents")


def test_unconvertible_rule_is_reported_not_raised():
    rule = RULES / "credential_access/lsass_memory_access.yml"  # no KQL table for Sysmon EID 10
    conversion = convert_rule(rule, TARGETS["kql"])
    assert not conversion.ok
    assert "microsoft_xdr" in conversion.error


def test_conversion_does_not_mutate_between_targets():
    """pySigma pipelines rename fields in place; each target must start from the YAML."""
    rule = RULES / "defense_evasion/mshta_suspicious_execution.yml"
    assert convert_rule(rule, TARGETS["lucene"]).ok
    kql = convert_rule(rule, TARGETS["kql"])
    assert kql.ok and "process.executable" not in kql.query


def test_cli_lint_and_test():
    assert runner.invoke(app, ["lint", "--rules", str(RULES)]).exit_code == 0
    result = runner.invoke(
        app, ["test", "--rules", str(RULES), "--cases", str(REPO / "tests/rule_cases")]
    )
    assert result.exit_code == 0, result.output


def test_cli_convert(tmp_path: Path):
    result = runner.invoke(
        app, ["convert", "--rules", str(RULES), "-o", str(tmp_path), "--target", "splunk"]
    )
    assert result.exit_code == 0, result.output
    index = json.loads((tmp_path / "index.json").read_text())
    assert index["summary"]["splunk"]["converted"] == index["summary"]["splunk"]["total"]
    assert any(tmp_path.joinpath("splunk").glob("*.spl"))
    bad = runner.invoke(
        app, ["convert", "--rules", str(RULES), "-o", str(tmp_path), "--target", "x"]
    )
    assert bad.exit_code == 2


def test_cli_evaluate_and_coverage(dataset: Path, reviews: Path, tmp_path: Path):
    out = tmp_path / "reports"
    result = runner.invoke(
        app,
        [
            "evaluate",
            "--data",
            str(dataset),
            "--rules",
            str(RULES),
            "--reviews",
            str(reviews),
            "--out",
            str(out),
            "--jobs",
            "1",
            "--no-figures",
        ],
    )
    assert result.exit_code == 0, result.output
    metrics = json.loads((out / "metrics.json").read_text())
    assert metrics["detection"]["detected"] == 2
    assert metrics["conversion"]["splunk"]["converted"] == metrics["rules"]
    layer_path = tmp_path / "layer.json"
    result = runner.invoke(
        app,
        [
            "coverage",
            "--rules",
            str(RULES),
            "--metrics",
            str(out / "metrics.json"),
            "-o",
            str(layer_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(layer_path.read_text())["techniques"]


def test_cli_evaluate_without_data(tmp_path: Path):
    result = runner.invoke(app, ["evaluate", "--data", str(tmp_path)])
    assert result.exit_code == 2


def test_cli_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0 and "dac" in result.output
