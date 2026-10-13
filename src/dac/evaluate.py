"""Run the rule set on the recordings and score it like a detection-engineering regression test.

* A recording is **in scope** when at least one rule shares an ATT&CK technique (or its parent) with
  the recording's label; it is then **expected** to be detected by those rules.
* Every alert a rule raises on a recording that is not labelled with the rule's technique is
  **off-target**. Off-target alerts are grouped into signatures (:mod:`dac.signatures`) and each
  signature carries an analyst verdict from ``reviews/off_target.yaml`` (:mod:`dac.review`):
  ``benign`` (a false positive) or ``attack`` (real activity the recording's label does not name).

Recordings are scanned in parallel worker processes; each worker compiles the rules once.
"""

from __future__ import annotations

import os
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import attack
from .datasets import Recording, catalogue, content_signature, load_events
from .engine import CompiledRule, EventIndex, prepare
from .review import Verdict, load_verdicts
from .rules import RULES_DIR, LoadedRule, load_rules
from .signatures import signature

Telemetry = set[tuple[str, int | None]]


@dataclass
class Firing:
    """One rule raising at least one alert on one recording."""

    rule: str  # rule slug (file stem)
    recording: str  # recording key
    signatures: Counter[str]
    expected: bool

    @property
    def alerts(self) -> int:
        return sum(self.signatures.values())


@dataclass
class RecordingOutcome:
    recording: Recording
    events: int
    in_scope: bool
    detected: bool
    expected_rules: list[str]
    firing_rules: list[str]
    miss_reason: str = ""


@dataclass
class SignatureGroup:
    """All off-target alerts of one rule that share a signature, across recordings."""

    rule: str
    signature: str
    recordings: dict[str, int] = field(default_factory=dict)
    verdict: Verdict | None = None

    @property
    def alerts(self) -> int:
        return sum(self.recordings.values())

    @property
    def status(self) -> str:
        return self.verdict.verdict if self.verdict else "unreviewed"


@dataclass
class EvaluationResult:
    rules: list[LoadedRule]
    recordings: list[Recording]
    duplicates: list[str]
    firings: list[Firing]
    outcomes: list[RecordingOutcome]
    off_target: list[SignatureGroup]
    stale_verdicts: list[Verdict]

    def rule_slugs(self) -> list[str]:
        return [lr.path.stem for lr in self.rules]

    def matrix(self) -> dict[str, dict[str, int]]:
        """rule slug -> recording key -> number of alerts."""
        out: dict[str, dict[str, int]] = {slug: {} for slug in self.rule_slugs()}
        for f in self.firings:
            out[f.rule][f.recording] = f.alerts
        return out


def expected_match(rule_techniques: set[str], recording_techniques: set[str]) -> bool:
    return bool(attack.with_parents(rule_techniques) & attack.with_parents(recording_techniques))


@lru_cache(maxsize=4)
def _compiled(rules_dir: str) -> dict[str, CompiledRule]:
    return {lr.path.stem: CompiledRule(lr.rule) for lr in load_rules(Path(rules_dir))}


def _scan(job: tuple[str, str, str]) -> tuple[str, dict[str, Counter[str]], Telemetry, int]:
    """Worker: run every rule on one recording; return per-rule signature counts and telemetry."""
    rules_dir, key, path = job
    compiled = _compiled(rules_dir)
    index = EventIndex(prepare(load_events(Path(path))))
    hits: dict[str, Counter[str]] = {}
    for slug, rule in compiled.items():
        matched = rule.matching_events(index)
        if matched:
            hits[slug] = Counter(signature(rule.rule.logsource, e) for e in matched)
    present: Telemetry = set(index.by_channel_eid) | {(c, None) for c in index.by_channel}
    n_events = sum(len(v) for v in index.by_channel.values())
    return key, hits, present, n_events


def evaluate(
    data_root: Path,
    rules_dir: Path = RULES_DIR,
    reviews: Path | None = None,
    jobs: int | None = None,
) -> EvaluationResult:
    loaded = load_rules(rules_dir)
    rule_techs = {lr.path.stem: lr.techniques for lr in loaded}
    compiled = _compiled(str(rules_dir))

    recordings = catalogue(data_root)
    first_by_sig: dict[str, str] = {}
    duplicates: list[str] = []
    for rec in sorted(recordings, key=lambda r: r.key):
        sig = content_signature(rec.path)
        if sig in first_by_sig:
            duplicates.append(rec.key)
        else:
            first_by_sig[sig] = rec.key
    scored = [r for r in recordings if r.key not in set(duplicates)]

    # Largest recordings first keeps the worker pool busy until the end.
    jobs_list = [
        (str(rules_dir), r.key, str(r.path))
        for r in sorted(scored, key=lambda r: r.path.stat().st_size, reverse=True)
    ]
    n_jobs = jobs or min(6, os.cpu_count() or 1)
    if n_jobs <= 1:
        scans = [_scan(j) for j in jobs_list]
    else:
        with ProcessPoolExecutor(max_workers=n_jobs) as pool:
            scans = list(pool.map(_scan, jobs_list))
    by_key = {key: (hits, present, n) for key, hits, present, n in scans}

    verdicts = load_verdicts(reviews) if reviews else {}
    firings: list[Firing] = []
    outcomes: list[RecordingOutcome] = []
    groups: dict[tuple[str, str], SignatureGroup] = {}
    for rec in sorted(scored, key=lambda r: r.key):
        hits, present, n_events = by_key[rec.key]
        expected = [s for s in rule_techs if expected_match(rule_techs[s], rec.techniques)]
        for slug, sigs in sorted(hits.items()):
            is_expected = slug in expected
            firings.append(Firing(slug, rec.key, sigs, is_expected))
            if not is_expected:
                for sig, count in sigs.items():
                    group = groups.setdefault((slug, sig), SignatureGroup(slug, sig))
                    group.recordings[rec.key] = count
        detected = any(slug in hits for slug in expected)
        outcome = RecordingOutcome(
            recording=rec,
            events=n_events,
            in_scope=bool(expected),
            detected=detected,
            expected_rules=expected,
            firing_rules=sorted(hits),
        )
        if expected and not detected:
            outcome.miss_reason = explain_miss(present, [compiled[s] for s in expected])
        outcomes.append(outcome)

    for key, group in groups.items():
        group.verdict = verdicts.get(key)
    stale = [v for k, v in verdicts.items() if k not in groups]
    return EvaluationResult(
        rules=loaded,
        recordings=recordings,
        duplicates=duplicates,
        firings=firings,
        outcomes=outcomes,
        off_target=sorted(groups.values(), key=lambda g: (g.rule, -g.alerts, g.signature)),
        stale_verdicts=stale,
    )


def explain_miss(present: Telemetry, expected: list[CompiledRule]) -> str:
    """Why an in-scope recording was missed: the telemetry is absent, or no rule matched it.

    Telemetry counts as present when the recording holds at least one event of a type (channel and
    event id) that one of the expected rules reads.
    """
    for rule in expected:
        for channel, event_ids in rule.telemetry:
            if event_ids is None and (channel, None) in present:
                return "telemetry present, no rule matched"
            if event_ids is not None and any((channel, e) in present for e in event_ids):
                return "telemetry present, no rule matched"
    return "required telemetry absent"


# ----------------------------------------------------------------------------- metrics


def _rate(num: int, den: int) -> float:
    return round(num / den, 4) if den else 0.0


def metrics(result: EvaluationResult) -> dict[str, Any]:
    in_scope = [o for o in result.outcomes if o.in_scope]
    detected = [o for o in in_scope if o.detected]

    per_tactic: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "in_scope": 0,
            "detected": 0,
            "missed_no_rule_match": 0,
            "missed_telemetry_absent": 0,
        }
    )
    for o in in_scope:
        bucket = per_tactic[o.recording.tactic]
        bucket["in_scope"] += 1
        bucket["detected"] += int(o.detected)
        if o.miss_reason == "required telemetry absent":
            bucket["missed_telemetry_absent"] += 1
        elif not o.detected:
            bucket["missed_no_rule_match"] += 1

    status_by_sig = {(g.rule, g.signature): g.status for g in result.off_target}
    alerts = Counter()
    per_rule: dict[str, dict[str, Any]] = {}
    for lr in result.rules:
        slug = lr.path.stem
        per_rule[slug] = {
            "title": lr.rule.title,
            "level": lr.rule.level.name.lower() if lr.rule.level else "",
            "techniques": sorted(lr.techniques),
            "alerts": 0,
            "recordings_fired": 0,
            # recordings labelled with one of the rule's own techniques (sub-technique or the
            # bare parent the rule is tagged with), and how many of them the rule fired on
            "labelled_recordings": 0,
            "labelled_recordings_fired": 0,
            "off_target_attack_alerts": 0,
            "false_positive_alerts": 0,
            "false_positive_recordings": 0,
            "unreviewed_alerts": 0,
        }
    own = {lr.path.stem: lr.techniques for lr in result.rules}
    for o in in_scope:
        for slug in o.expected_rules:
            if own[slug] & o.recording.techniques:
                per_rule[slug]["labelled_recordings"] += 1
                if slug in o.firing_rules:
                    per_rule[slug]["labelled_recordings_fired"] += 1
    fp_recordings: dict[str, set[str]] = defaultdict(set)
    for f in result.firings:
        row = per_rule[f.rule]
        row["alerts"] += f.alerts
        row["recordings_fired"] += 1
        if f.expected:
            alerts["expected"] += f.alerts
            continue
        for sig, count in f.signatures.items():
            status = status_by_sig[(f.rule, sig)]
            if status == "benign":
                alerts["false_positive"] += count
                row["false_positive_alerts"] += count
                fp_recordings[f.rule].add(f.recording)
            elif status == "attack":
                alerts["off_target_attack"] += count
                row["off_target_attack_alerts"] += count
            else:
                alerts["unreviewed"] += count
                row["unreviewed_alerts"] += count
    for slug, recs in fp_recordings.items():
        per_rule[slug]["false_positive_recordings"] = len(recs)

    total_alerts = sum(alerts.values())
    techniques = technique_stats(result)
    covered = attack.with_parents({t for lr in result.rules for t in lr.techniques})
    uncovered: Counter[str] = Counter()
    for o in result.outcomes:
        for tech in _leaf_techniques(o.recording.techniques):
            if tech not in covered and attack.parent(tech) not in covered:
                uncovered[tech] += 1
    return {
        "rules": len(result.rules),
        "recordings": {
            "total": len(result.recordings),
            "scored": len(result.outcomes),
            "duplicates_excluded": result.duplicates,
            "labelled": sum(o.recording.labelled for o in result.outcomes),
            "unlabelled": sum(not o.recording.labelled for o in result.outcomes),
            "events": sum(o.events for o in result.outcomes),
        },
        "detection": {
            "in_scope": len(in_scope),
            "detected": len(detected),
            "detection_rate": _rate(len(detected), len(in_scope)),
            "in_scope_with_any_alert": sum(bool(o.firing_rules) for o in in_scope),
            "missed_telemetry_absent": sum(
                o.miss_reason == "required telemetry absent" for o in in_scope
            ),
            "missed_no_rule_match": sum(
                o.miss_reason == "telemetry present, no rule matched" for o in in_scope
            ),
        },
        "alerts": {
            "total": total_alerts,
            "expected": alerts["expected"],
            "off_target_attack": alerts["off_target_attack"],
            "false_positive": alerts["false_positive"],
            "unreviewed": alerts["unreviewed"],
            "false_positive_share": _rate(alerts["false_positive"], total_alerts),
        },
        "off_target_signatures": {
            "total": len(result.off_target),
            "benign": sum(g.status == "benign" for g in result.off_target),
            "attack": sum(g.status == "attack" for g in result.off_target),
            "unreviewed": sum(g.status == "unreviewed" for g in result.off_target),
            "stale_verdicts": len(result.stale_verdicts),
        },
        "rules_without_validated_detection": sorted(
            slug for slug, row in per_rule.items() if row["labelled_recordings_fired"] == 0
        ),
        "per_tactic": {
            t: {**v, "detection_rate": _rate(v["detected"], v["in_scope"])}
            for t, v in sorted(per_tactic.items())
        },
        "per_technique": techniques,
        "uncovered_techniques": [
            {"technique": t, "name": attack.name_for(t), "recordings": n}
            for t, n in sorted(uncovered.items())
        ],
        "per_rule": per_rule,
    }


def _leaf_techniques(techniques: set[str]) -> set[str]:
    """Sub-techniques, plus bare techniques that carry no sub-technique in the same label."""
    leaves = {t for t in techniques if "." in t}
    return leaves | {
        t for t in techniques if "." not in t and not any(x.startswith(t + ".") for x in techniques)
    }


def technique_stats(result: EvaluationResult) -> list[dict[str, Any]]:
    """Detection per labelled technique, over in-scope recordings carrying that label.

    A recording labelled with a sub-technique counts under the sub-technique only; a bare
    technique label (e.g. ``T1218``) counts under the technique. It counts as detected for a
    technique only if a rule covering *that* technique (or its parent) fired on it.
    """
    rules_for: dict[str, set[str]] = defaultdict(set)
    for lr in result.rules:
        for tech in attack.with_parents(lr.techniques):
            rules_for[tech].add(lr.path.stem)
    rows: dict[str, dict[str, Any]] = {}
    for o in result.outcomes:
        if not o.in_scope:
            continue
        for tech in sorted(_leaf_techniques(o.recording.techniques)):
            covering = rules_for.get(tech, set()) | rules_for.get(attack.parent(tech), set())
            if not covering:
                continue
            row = rows.setdefault(
                tech,
                {"technique": tech, "name": attack.name_for(tech), "recordings": 0, "detected": 0},
            )
            row["recordings"] += 1
            row["detected"] += int(any(slug in o.firing_rules for slug in covering))
    for row in rows.values():
        row["detection_rate"] = _rate(row["detected"], row["recordings"])
    return [rows[t] for t in sorted(rows)]
