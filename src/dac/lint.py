"""Validate the rule set: pySigma's own validators plus project-specific checks.

The pySigma validators catch structural problems (duplicate ids, dangling conditions, wildcards that
should be modifiers, ...). The project checks enforce the conventions this repository relies on:
full metadata, ATT&CK tags that exist in :mod:`dac.attack`, references that point only at
attack.mitre.org, a log source the engine can actually run, and a disciplined file layout.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml
from sigma.plugins import InstalledSigmaPlugins
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator

from . import attack
from .logsource import UnsupportedLogSourceError, resolve
from .rules import LoadedRule, rule_tactic_tags, rule_techniques

# These pySigma validators download the ATT&CK/D3FEND STIX bundles at runtime; the project validates
# tags offline against dac.attack instead, so they are skipped to keep linting network-free.
_NETWORK_VALIDATORS = {"attacktag", "d3_fendtag"}

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
TACTIC_DIRS = {
    "credential_access": "credential-access",
    "defense_evasion": "defense-evasion",
    "persistence": "persistence",
    "privilege_escalation": "privilege-escalation",
    "lateral_movement": "lateral-movement",
    "discovery": "discovery",
    "execution": "execution",
    "collection": "collection",
}


@dataclass
class Issue:
    rule: str
    message: str
    source: str = "project"

    def __str__(self) -> str:
        return f"[{self.source}] {self.rule}: {self.message}"


class _StrictLoader(yaml.SafeLoader):
    """A YAML loader that rejects duplicate mapping keys instead of silently keeping the last one.

    Sigma selections are YAML mappings, so writing ``CommandLine|contains`` twice in one selection
    is legal YAML but drops the first condition without any error from PyYAML or pySigma. The first
    evaluation of this rule set caught four rules broken that way; this loader turns it into a
    lint error.
    """


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False) -> Any:
    seen: set[Any] = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        seen.add(key)
    return loader.construct_mapping(node, deep)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def duplicate_key_issues(paths: list[Path]) -> list[Issue]:
    issues = []
    for path in paths:
        try:
            yaml.load(path.read_text(encoding="utf-8"), Loader=_StrictLoader)
        except yaml.constructor.ConstructorError as exc:
            line = exc.problem_mark.line + 1 if exc.problem_mark else "?"
            issues.append(Issue(path.name, f"{exc.problem} (line {line}): a selection was dropped"))
    return issues


def pysigma_issues(rules: list[SigmaRule]) -> list[Issue]:
    plugins = InstalledSigmaPlugins.autodiscover()
    validator_classes = {
        name: cls for name, cls in plugins.validators.items() if name not in _NETWORK_VALIDATORS
    }
    validator = SigmaValidator(set(validator_classes.values()))
    issues = []
    for issue in validator.validate_rules(rules):
        titles = ", ".join(r.title for r in issue.rules) or "-"
        issues.append(Issue(rule=titles, message=str(issue), source="pysigma"))
    return issues


def _check_metadata(lr: LoadedRule) -> list[Issue]:
    rule, issues = lr.rule, []
    name = rule.title or lr.path.name

    def require(cond: bool, msg: str) -> None:
        if not cond:
            issues.append(Issue(name, msg))

    require(bool(rule.title), "missing title")
    require(rule.id is not None, "missing id (UUID)")
    require(
        rule.status is not None and rule.status.name.lower() in VALID_STATUSES, "invalid status"
    )
    require(
        bool(rule.description and len(rule.description) >= 16), "missing or too-short description"
    )
    require(rule.author == "Hugo", f"author must be 'Hugo', got {rule.author!r}")
    require(rule.date is not None, "missing date")
    require(bool(rule.falsepositives), "missing falsepositives")
    require(
        rule.level is not None and rule.level.name.lower() in VALID_LEVELS, "missing/invalid level"
    )
    require(bool(rule.references), "missing references")
    for ref in rule.references:
        host = urlparse(ref).netloc.lower()
        require(host == "attack.mitre.org", f"reference must be on attack.mitre.org: {ref}")
    return issues


def _check_attack(lr: LoadedRule) -> list[Issue]:
    rule, issues = lr.rule, []
    name = rule.title or lr.path.name
    techniques = rule_techniques(rule)
    tactic_tags = rule_tactic_tags(rule)
    if not techniques:
        issues.append(Issue(name, "no ATT&CK technique tag (attack.tXXXX)"))
    for tech in techniques:
        if not attack.is_known(tech):
            issues.append(Issue(name, f"unknown ATT&CK technique {tech}"))
    if not tactic_tags:
        issues.append(Issue(name, "no ATT&CK tactic tag (e.g. attack.credential-access)"))
    valid_tactics = {t for tech in techniques for t in attack.tactics_for(tech)}
    for tactic in tactic_tags:
        if valid_tactics and tactic not in valid_tactics:
            issues.append(
                Issue(name, f"tactic tag '{tactic}' is not a tactic of {sorted(techniques)}")
            )
    return issues


def _check_layout(lr: LoadedRule) -> list[Issue]:
    rule, issues = lr.rule, []
    name = rule.title or lr.path.name
    stem = lr.path.stem
    if not stem.replace("_", "").isalnum() or stem != stem.lower():
        issues.append(Issue(name, f"filename '{lr.path.name}' must be lower_snake_case.yml"))
    tactic_dir = lr.path.parent.name
    if tactic_dir not in TACTIC_DIRS:
        issues.append(Issue(name, f"rule is in unknown tactic folder '{tactic_dir}'"))
    elif TACTIC_DIRS[tactic_dir] not in rule_tactic_tags(rule):
        issues.append(Issue(name, f"folder '{tactic_dir}' has no matching tactic tag on the rule"))
    return issues


def _check_logsource(lr: LoadedRule) -> list[Issue]:
    try:
        resolve(lr.rule.logsource)
    except UnsupportedLogSourceError as exc:
        return [
            Issue(lr.rule.title or lr.path.name, f"log source not supported by the engine: {exc}")
        ]
    return []


def project_issues(loaded: list[LoadedRule]) -> list[Issue]:
    issues: list[Issue] = []
    ids: dict[str, list[str]] = defaultdict(list)
    titles: dict[str, list[str]] = defaultdict(list)
    slugs: dict[str, list[str]] = defaultdict(list)
    for lr in loaded:
        issues += _check_metadata(lr)
        issues += _check_attack(lr)
        issues += _check_layout(lr)
        issues += _check_logsource(lr)
        if lr.rule.id is not None:
            ids[str(lr.rule.id)].append(lr.path.name)
        titles[lr.rule.title].append(lr.path.name)
        slugs[lr.path.stem].append(str(lr.path))
    for rid, files in ids.items():
        if len(files) > 1:
            issues.append(Issue(", ".join(files), f"duplicate rule id {rid}"))
    for title, files in titles.items():
        if len(files) > 1:
            issues.append(Issue(", ".join(files), f"duplicate title '{title}'"))
    for slug, files in slugs.items():
        if len(files) > 1:  # the file stem identifies a rule in reviews and reports
            issues.append(Issue(", ".join(files), f"duplicate rule file name '{slug}'"))
    return issues


def lint(loaded: list[LoadedRule], run_pysigma: bool = True) -> list[Issue]:
    """Return every issue found in the rule set (empty list == clean)."""
    issues = duplicate_key_issues(sorted({lr.path for lr in loaded}))
    issues += project_issues(loaded)
    if run_pysigma:
        issues += pysigma_issues([lr.rule for lr in loaded])
    return issues
