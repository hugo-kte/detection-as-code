"""Unit tests for rules: minimal synthetic events that must or must not match.

Each rule has ``tests/rule_cases/<rule>.yml``::

    rule: lsass_memory_access          # rule file stem
    defaults:                          # merged into every event (optional)
      Channel: Microsoft-Windows-Sysmon/Operational
      EventID: 10
    cases:
      - name: dump-capable access to LSASS
        match: true
        event: {TargetImage: 'C:\\Windows\\System32\\lsass.exe', GrantedAccess: '0x1410'}

Every rule needs at least one positive and one negative case; negative cases pin down filters and
past bugs (for example ``IPC$`` must not match the admin-share rule).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .engine import CompiledRule, prepare
from .rules import RULES_DIR, load_rules

CASES_DIR = Path("tests/rule_cases")


@dataclass
class CaseResult:
    rule: str
    name: str
    expected: bool
    actual: bool

    @property
    def passed(self) -> bool:
        return self.expected == self.actual


@dataclass
class SuiteResult:
    results: list[CaseResult]
    problems: list[str]  # structural problems: missing case files, rules without negatives, ...

    @property
    def ok(self) -> bool:
        return not self.problems and all(r.passed for r in self.results)


def load_cases(path: Path) -> dict[str, Any]:
    spec = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if "rule" not in spec or not spec.get("cases"):
        raise ValueError(f"{path}: needs 'rule' and a non-empty 'cases' list")
    return spec


def run_cases(rules_dir: Path = RULES_DIR, cases_dir: Path = CASES_DIR) -> SuiteResult:
    compiled = {lr.path.stem: CompiledRule(lr.rule) for lr in load_rules(rules_dir)}
    results: list[CaseResult] = []
    problems: list[str] = []
    seen: set[str] = set()
    for path in sorted(cases_dir.glob("*.yml")):
        spec = load_cases(path)
        slug = spec["rule"]
        if slug not in compiled:
            problems.append(f"{path.name}: unknown rule '{slug}'")
            continue
        seen.add(slug)
        defaults = spec.get("defaults") or {}
        polarity = set()
        for case in spec["cases"]:
            event = prepare([{**defaults, **(case.get("event") or {})}])[0]
            expected = bool(case["match"])
            polarity.add(expected)
            actual = compiled[slug].event_matches(event)
            results.append(CaseResult(slug, str(case.get("name", "?")), expected, actual))
        if polarity != {True, False}:
            problems.append(f"{path.name}: needs at least one matching and one non-matching case")
    for slug in sorted(set(compiled) - seen):
        problems.append(f"rule '{slug}' has no test cases in {cases_dir}")
    return SuiteResult(results, problems)
