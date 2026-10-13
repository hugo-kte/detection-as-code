"""Rule linting: the committed rules are clean, and every project check catches its defect."""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import RULES
from dac.lint import duplicate_key_issues, lint
from dac.rules import load_rules

GOOD = """\
title: Example rule
id: 00000000-0000-4000-8000-000000000001
status: experimental
description: Detects an example behaviour for the linter tests.
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: Hugo
date: 2026-10-13
tags:
    - attack.t1059.001
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\example.exe'
    condition: selection
falsepositives:
    - None known
level: low
"""


def write_rule(
    tmp_path: Path, text: str, folder: str = "execution", name: str = "example_rule"
) -> Path:
    path = tmp_path / "rules" / folder / f"{name}.yml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return tmp_path / "rules"


def messages(rules_dir: Path) -> list[str]:
    return [i.message for i in lint(load_rules(rules_dir), run_pysigma=False)]


def test_committed_rules_are_clean():
    loaded = load_rules(RULES)
    assert len(loaded) >= 25
    assert lint(loaded) == []


def test_good_rule_passes(tmp_path):
    assert messages(write_rule(tmp_path, GOOD)) == []


@pytest.mark.parametrize(
    ("old", "new", "expected"),
    [
        ("author: Hugo", "author: Someone", "author must be 'Hugo'"),
        ("level: low", "level: severe", None),  # pySigma refuses to parse an invalid level
        ("    - attack.execution\n", "", "no ATT&CK tactic tag"),
        ("attack.t1059.001", "attack.t9999", "unknown ATT&CK technique T9999"),
        ("attack.execution", "attack.discovery", "is not a tactic of"),
        (
            "https://attack.mitre.org/techniques/T1059/001/",
            "https://example.invalid/x",
            "reference must be on attack.mitre.org",
        ),
        ("category: process_creation", "category: no_such_category", "log source not supported"),
        ("falsepositives:\n    - None known\n", "", "missing falsepositives"),
    ],
)
def test_project_checks(tmp_path, old, new, expected):
    text = GOOD.replace(old, new)
    if expected is None:
        with pytest.raises(Exception):  # noqa: B017 - any pySigma parse error
            load_rules(write_rule(tmp_path, text))
        return
    assert any(expected in m for m in messages(write_rule(tmp_path, text)))


def test_folder_must_match_a_tactic_tag(tmp_path):
    assert any(
        "no matching tactic tag" in m for m in messages(write_rule(tmp_path, GOOD, "discovery"))
    )


def test_duplicate_ids_titles_and_file_names(tmp_path):
    write_rule(tmp_path, GOOD, "execution", "example_rule")
    rules_dir = write_rule(tmp_path, GOOD, "execution", "example_copy")
    found = messages(rules_dir)
    assert any("duplicate rule id" in m for m in found)
    assert any("duplicate title" in m for m in found)


def test_duplicate_yaml_keys_are_rejected(tmp_path):
    """Two `CommandLine|contains` keys in one selection silently drop the first one in PyYAML."""
    text = GOOD.replace(
        "        Image|endswith: '\\example.exe'\n",
        "        CommandLine|contains: 'a'\n        CommandLine|contains: 'b'\n",
    )
    path = write_rule(tmp_path, text) / "execution" / "example_rule.yml"
    issues = duplicate_key_issues([path])
    assert len(issues) == 1 and "duplicate key" in issues[0].message
