"""Analyst verdicts for off-target alert signatures (``reviews/off_target.yaml``).

Every signature a rule produces on a recording that is *not* labelled with the rule's technique gets
one verdict:

* ``benign``: normal system or administrative activity, i.e. a false positive of the rule;
* ``attack``: real attack activity that the recording contains but its label does not name (multi-
  step scenarios: the Empire stager is a PowerShell download cradle whatever technique the scenario
  is labelled with), or the recording's own behaviour when its upstream label is missing or wrong.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

REVIEWS = Path("reviews/off_target.yaml")
VERDICTS = {"benign", "attack"}


@dataclass(frozen=True)
class Verdict:
    rule: str
    signature: str
    verdict: str
    rationale: str
    technique: str = ""


def load_verdicts(path: Path = REVIEWS) -> dict[tuple[str, str], Verdict]:
    """Load the review file; raises ValueError on malformed or duplicate entries."""
    if not path.exists():
        return {}
    entries = yaml.safe_load(path.read_text(encoding="utf-8")) or []
    out: dict[tuple[str, str], Verdict] = {}
    for i, entry in enumerate(entries):
        try:
            verdict = Verdict(
                rule=str(entry["rule"]),
                signature=str(entry["signature"]),
                verdict=str(entry["verdict"]),
                rationale=str(entry["rationale"]),
                technique=str(entry.get("technique") or ""),
            )
        except KeyError as exc:
            raise ValueError(f"{path}: entry {i} is missing {exc}") from exc
        if verdict.verdict not in VERDICTS:
            raise ValueError(f"{path}: entry {i} has verdict {verdict.verdict!r}, not {VERDICTS}")
        if not verdict.rationale.strip():
            raise ValueError(f"{path}: entry {i} has an empty rationale")
        key = (verdict.rule, verdict.signature)
        if key in out:
            raise ValueError(f"{path}: duplicate verdict for {key}")
        out[key] = verdict
    return out
