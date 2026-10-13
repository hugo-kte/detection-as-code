"""Load the Sigma rules that live under ``rules/`` and expose their ATT&CK metadata."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule

RULES_DIR = Path("rules")


@dataclass
class LoadedRule:
    """A parsed rule together with the file it came from."""

    path: Path
    rule: SigmaRule

    @property
    def techniques(self) -> set[str]:
        return rule_techniques(self.rule)

    @property
    def tactic_tags(self) -> set[str]:
        return rule_tactic_tags(self.rule)


def rule_paths(rules_dir: Path = RULES_DIR) -> list[Path]:
    return sorted(rules_dir.rglob("*.yml"))


def load_rules(rules_dir: Path = RULES_DIR) -> list[LoadedRule]:
    """Parse every rule file. Raises :class:`SigmaError` on the first file that fails to parse."""
    loaded: list[LoadedRule] = []
    for path in rule_paths(rules_dir):
        try:
            collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        except SigmaError as exc:  # pragma: no cover - re-raised with the offending file
            raise SigmaError(f"{path}: {exc}") from exc
        for rule in collection.rules:
            if isinstance(rule, SigmaRule):
                loaded.append(LoadedRule(path=path, rule=rule))
    return loaded


def rule_techniques(rule: SigmaRule) -> set[str]:
    """ATT&CK technique ids from a rule's ``attack.tXXXX`` tags, upper-cased (``T1003.001``)."""
    out: set[str] = set()
    for tag in rule.tags:
        if tag.namespace == "attack" and tag.name[:1] in {"t", "T"} and tag.name[1:2].isdigit():
            out.add(tag.name.upper())
    return out


def rule_tactic_tags(rule: SigmaRule) -> set[str]:
    """ATT&CK tactic short-names from a rule's tags (e.g. ``credential-access``)."""
    out: set[str] = set()
    for tag in rule.tags:
        if tag.namespace == "attack" and not (
            tag.name[:1] in {"t", "T"} and tag.name[1:2].isdigit()
        ):
            out.add(tag.name)
    return out
