"""Convert every rule to SIEM queries with the pySigma backends.

Targets: Splunk SPL (``splunk_windows`` pipeline), Elastic Lucene and ES|QL (``ecs_windows``), and
Microsoft KQL. For KQL the Microsoft Defender XDR advanced-hunting tables are tried first, then the
Azure Monitor / Sentinel ``SecurityEvent`` tables. A rule that no pipeline of a target can map is
recorded as unsupported with the backend's reason instead of aborting the run.

pySigma processing pipelines rewrite field names *in place*, so each conversion parses the rule
from its YAML again rather than reusing a converted object.
"""

from __future__ import annotations

import json
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sigma.backends.elasticsearch import ESQLBackend, LuceneBackend
from sigma.backends.kusto import KustoBackend
from sigma.backends.splunk import SplunkBackend
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.pipelines.azuremonitor import azure_monitor_pipeline
from sigma.pipelines.elasticsearch.windows import ecs_windows
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
from sigma.pipelines.splunk import splunk_windows_pipeline

from .rules import RULES_DIR, rule_paths

Backend = Callable[[], Any]


@dataclass(frozen=True)
class Target:
    name: str
    label: str
    extension: str
    # (pipeline label, backend factory) tried in order until one converts the rule
    chain: tuple[tuple[str, Backend], ...]


TARGETS: dict[str, Target] = {
    "splunk": Target(
        "splunk",
        "Splunk SPL",
        "spl",
        (("splunk_windows", lambda: SplunkBackend(processing_pipeline=splunk_windows_pipeline())),),
    ),
    "lucene": Target(
        "lucene",
        "Elastic Lucene (ECS)",
        "lucene",
        (("ecs_windows", lambda: LuceneBackend(processing_pipeline=ecs_windows())),),
    ),
    "esql": Target(
        "esql",
        "Elastic ES|QL (ECS)",
        "esql",
        (("ecs_windows", lambda: ESQLBackend(processing_pipeline=ecs_windows())),),
    ),
    "kql": Target(
        "kql",
        "Microsoft KQL (Defender XDR / Sentinel)",
        "kql",
        (
            ("microsoft_xdr", lambda: KustoBackend(processing_pipeline=microsoft_xdr_pipeline())),
            ("azure_monitor", lambda: KustoBackend(processing_pipeline=azure_monitor_pipeline())),
        ),
    ),
}


@dataclass
class Conversion:
    rule: str
    target: str
    query: str = ""
    pipeline: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.query)


@dataclass
class ConversionReport:
    conversions: list[Conversion] = field(default_factory=list)

    def summary(self) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for name, target in TARGETS.items():
            rows = [c for c in self.conversions if c.target == name]
            out[name] = {
                "label": target.label,
                "converted": sum(c.ok for c in rows),
                "total": len(rows),
                "unsupported": {c.rule: c.error for c in rows if not c.ok},
            }
        return out


def convert_rule(path: Path, target: Target) -> Conversion:
    text = path.read_text(encoding="utf-8")
    errors = []
    for pipeline_name, backend in target.chain:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                queries = backend().convert(SigmaCollection.from_yaml(text))
        except (SigmaError, NotImplementedError, KeyError, ValueError) as exc:
            errors.append(f"{pipeline_name}: {str(exc).splitlines()[0]}")
            continue
        query = "\n".join(str(q) for q in queries)
        if query.strip():
            return Conversion(path.stem, target.name, query=query, pipeline=pipeline_name)
        errors.append(f"{pipeline_name}: empty query")
    return Conversion(path.stem, target.name, error="; ".join(errors))


def convert_all(rules_dir: Path = RULES_DIR, targets: list[str] | None = None) -> ConversionReport:
    report = ConversionReport()
    for path in rule_paths(rules_dir):
        for name in targets or list(TARGETS):
            report.conversions.append(convert_rule(path, TARGETS[name]))
    return report


def write_queries(report: ConversionReport, out_dir: Path) -> None:
    """One file per rule and target, plus an index with the pipeline used or the failure reason."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for c in report.conversions:
        if c.ok:
            target = TARGETS[c.target]
            dest = out_dir / c.target / f"{c.rule}.{target.extension}"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(c.query + "\n", encoding="utf-8")
    index = {
        "summary": report.summary(),
        "rules": {
            c.rule + "/" + c.target: {"pipeline": c.pipeline} if c.ok else {"error": c.error}
            for c in report.conversions
        },
    }
    (out_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
