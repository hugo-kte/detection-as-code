"""ATT&CK Navigator layer: which techniques have a rule, and which rules are validated on data.

Scores (legend in the layer):

* 3 - validated: a rule covers the technique and detected at least one recording labelled with it;
* 2 - rule only: a rule exists but no labelled recording was detected (or none exists);
* 1 - gap: the technique is exercised by a recording but no rule covers it.

Without evaluation metrics (e.g. in CI before ``dac evaluate``), every rule technique scores 2.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from . import attack
from .rules import LoadedRule

COLORS = {3: "#1baf7a", 2: "#eda100", 1: "#e1e0d9"}
LABELS = {
    3: "Rule validated on recorded telemetry",
    2: "Rule written, not validated",
    1: "Recorded, no rule",
}


def build_layer(loaded: list[LoadedRule], metrics: dict[str, Any] | None = None) -> dict[str, Any]:
    exact: dict[str, set[str]] = defaultdict(set)
    for lr in loaded:
        for tech in lr.techniques:
            exact[tech].add(lr.path.stem)

    def covering(tech: str) -> list[str]:
        """Rules on the technique itself, on its parent, or (for a parent) on any sub-technique."""
        found = exact.get(tech, set()) | exact.get(attack.parent(tech), set())
        if "." not in tech:
            found |= {r for t, rules in exact.items() if attack.parent(t) == tech for r in rules}
        return sorted(found)

    per_tech = {row["technique"]: row for row in (metrics or {}).get("per_technique", [])}
    gaps = {row["technique"]: row for row in (metrics or {}).get("uncovered_techniques", [])}
    techniques: set[str] = set(exact) | set(per_tech) | set(gaps)
    entries = []
    for tech in sorted(techniques):
        rules = covering(tech)
        row = per_tech.get(tech)
        if rules and row and row["detected"] > 0:
            score = 3
        elif rules:
            score = 2
        else:
            score = 1
        comment = f"Rules: {', '.join(rules)}" if rules else "No rule yet"
        if row:
            comment += f". Recordings detected: {row['detected']}/{row['recordings']}"
        elif tech in gaps:
            comment += f". Exercised by {gaps[tech]['recordings']} recording(s)"
        entries.append(
            {
                "techniqueID": tech,
                "score": score,
                "color": COLORS[score],
                "comment": comment,
                "enabled": True,
                "showSubtechniques": True,
                "metadata": [{"name": "rules", "value": ", ".join(rules) or "-"}],
            }
        )

    return {
        "name": "detection-as-code coverage",
        "versions": {"attack": attack.ATTACK_VERSION, "layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack",
        "description": (
            "Sigma rules of hugo-kte/detection-as-code, scored by validation against recorded "
            "ATT&CK telemetry (OTRF Security-Datasets)."
        ),
        "metadata": [{"name": "ATT&CK version", "value": f"Enterprise v{attack.ATTACK_VERSION}"}],
        "filters": {"platforms": ["Windows"]},
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": True},
        "hideDisabled": False,
        "techniques": entries,
        "gradient": {"colors": [COLORS[1], COLORS[2], COLORS[3]], "minValue": 1, "maxValue": 3},
        "legendItems": [{"label": LABELS[s], "color": COLORS[s]} for s in (3, 2, 1)],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
    }


def write_layer(layer: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(layer, indent=2) + "\n", encoding="utf-8")
    return path
