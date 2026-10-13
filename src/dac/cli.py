"""Command-line interface: ``dac lint | test | evaluate | convert | coverage | download``."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from . import __version__

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Detection-as-code: lint, unit-test, regression-test and convert Sigma rules.",
)
console = Console()

RulesOpt = Annotated[Path, typer.Option("--rules", help="Directory of Sigma rules.")]
DataOpt = Annotated[Path, typer.Option("--data", help="Root of the downloaded Security-Datasets.")]


def _version(value: bool) -> None:
    if value:
        console.print(f"dac {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show the version.")
    ] = False,
) -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")


@app.command()
def lint(rules: RulesOpt = Path("rules")) -> None:
    """Validate the rules: pySigma validators plus project checks (metadata, ATT&CK tags...)."""
    from .lint import lint as run_lint
    from .rules import load_rules

    loaded = load_rules(rules)
    issues = run_lint(loaded)
    if not issues:
        console.print(f"[green]{len(loaded)} rules, no issues[/green]")
        return
    table = Table("source", "rule", "issue")
    for issue in issues:
        table.add_row(issue.source, issue.rule, issue.message)
    console.print(table)
    console.print(f"[red]{len(issues)} issue(s) in {len(loaded)} rules[/red]")
    raise typer.Exit(1)


@app.command()
def test(
    rules: RulesOpt = Path("rules"),
    cases: Annotated[Path, typer.Option(help="Directory of rule test cases.")] = Path(
        "tests/rule_cases"
    ),
) -> None:
    """Run the per-rule unit tests (synthetic events that must / must not match)."""
    from .ruletest import run_cases

    suite = run_cases(rules, cases)
    failed = [r for r in suite.results if not r.passed]
    for r in failed:
        console.print(f"[red]FAIL[/red] {r.rule}: {r.name} (expected match={r.expected})")
    for problem in suite.problems:
        console.print(f"[red]PROBLEM[/red] {problem}")
    rules_n = len({r.rule for r in suite.results})
    if suite.ok:
        console.print(f"[green]{len(suite.results)} cases passed for {rules_n} rules[/green]")
        return
    console.print(f"[red]{len(failed)} failed case(s), {len(suite.problems)} problem(s)[/red]")
    raise typer.Exit(1)


@app.command()
def evaluate(
    data: DataOpt = Path("data/security-datasets"),
    rules: RulesOpt = Path("rules"),
    reviews: Annotated[Path, typer.Option(help="Analyst verdicts file.")] = Path(
        "reviews/off_target.yaml"
    ),
    out: Annotated[Path, typer.Option(help="Output directory for the report.")] = Path("reports"),
    first_pass: Annotated[
        Path | None,
        typer.Option(help="metrics.json of the first pass, for the before/after comparison."),
    ] = Path("reports/first_pass/metrics.json"),
    jobs: Annotated[int, typer.Option(help="Worker processes (default: up to 6).")] = 0,
    figures: Annotated[bool, typer.Option(help="Also render the figures.")] = True,
) -> None:
    """Run the rules on the recordings and write metrics, report and figures to OUT."""
    from .convert import convert_all
    from .evaluate import evaluate as run_evaluate
    from .evaluate import metrics as compute_metrics
    from .report import write_figures, write_matrix, write_metrics, write_report

    if not (data / "windows").is_dir():
        console.print(f"[red]No recordings under {data}; run `dac download` first.[/red]")
        raise typer.Exit(2)
    result = run_evaluate(data, rules, reviews=reviews, jobs=jobs or None)
    metrics = compute_metrics(result)
    first = None
    if (
        first_pass
        and first_pass.exists()
        and first_pass.resolve() != (out / "metrics.json").resolve()
    ):
        first = json.loads(first_pass.read_text())
    conversion = convert_all(rules)
    write_metrics(metrics, out / "metrics.json", conversion)
    write_matrix(result, out / "detection_matrix.csv")
    write_report(result, metrics, out / "REPORT.md", first=first, conversion=conversion)
    if figures:
        write_figures(result, metrics, out, first)

    det, alerts = metrics["detection"], metrics["alerts"]
    console.print(
        f"Detected [bold]{det['detected']}/{det['in_scope']}[/bold] in-scope recordings "
        f"({det['detection_rate']:.1%}); {alerts['total']} alerts: {alerts['expected']} expected, "
        f"{alerts['off_target_attack']} off-target attack, {alerts['false_positive']} false "
        f"positive, {alerts['unreviewed']} unreviewed."
    )
    console.print(f"Report written to {out}/REPORT.md")
    if alerts["unreviewed"]:
        console.print(f"[yellow]Review the unreviewed signatures in {out}/REPORT.md[/yellow]")


@app.command()
def convert(
    rules: RulesOpt = Path("rules"),
    out: Annotated[Path, typer.Option("-o", "--out", help="Output directory.")] = Path(
        "reports/queries"
    ),
    target: Annotated[
        list[str] | None, typer.Option(help="splunk, lucene, esql, kql (default: all).")
    ] = None,
) -> None:
    """Convert every rule to Splunk SPL, Elastic Lucene / ES|QL and Microsoft KQL."""
    from .convert import TARGETS, convert_all, write_queries

    unknown = set(target or []) - set(TARGETS)
    if unknown:
        console.print(f"[red]Unknown target(s): {', '.join(sorted(unknown))}[/red]")
        raise typer.Exit(2)
    report = convert_all(rules, target)
    write_queries(report, out)
    table = Table("target", "converted", "not convertible")
    for s in report.summary().values():
        if s["total"]:
            table.add_row(
                s["label"],
                f"{s['converted']}/{s['total']}",
                ", ".join(sorted(s["unsupported"])) or "-",
            )
    console.print(table)
    console.print(f"Queries written to {out}/")


@app.command()
def coverage(
    rules: RulesOpt = Path("rules"),
    metrics_path: Annotated[
        Path, typer.Option("--metrics", help="metrics.json from `dac evaluate` (optional).")
    ] = Path("reports/metrics.json"),
    out: Annotated[Path, typer.Option("-o", "--out", help="Layer file to write.")] = Path(
        "reports/attack_navigator_layer.json"
    ),
) -> None:
    """Write an ATT&CK Navigator layer scoring each technique by rule validation status."""
    from .coverage import build_layer, write_layer
    from .rules import load_rules

    metrics = json.loads(metrics_path.read_text()) if metrics_path.exists() else None
    layer = build_layer(load_rules(rules), metrics)
    write_layer(layer, out)
    scores = [t["score"] for t in layer["techniques"]]
    console.print(
        f"{len(scores)} techniques: {scores.count(3)} validated, {scores.count(2)} rule only, "
        f"{scores.count(1)} gaps -> {out}"
    )


@app.command()
def download(
    out: Annotated[Path, typer.Option("-o", "--out", help="Destination directory.")] = Path(
        "data/security-datasets"
    ),
) -> None:
    """Download the pinned OTRF Security-Datasets files (MIT) and verify every git SHA-1."""
    from .datasets import download as run_download

    n = run_download(out)
    console.print(f"{n} files verified under {out}")
