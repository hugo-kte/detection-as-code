"""Report figures (matplotlib, Agg), same visual spec as the rest of the portfolio."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.ticker import PercentFormatter

SURFACE, INK, INK2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4"]
BLUE, ORANGE, GREEN, AMBER, PINK = SERIES

TACTIC_LABELS = {
    "collection": "Collection",
    "credential_access": "Credential Access",
    "defense_evasion": "Defense Evasion",
    "discovery": "Discovery",
    "execution": "Execution",
    "lateral_movement": "Lateral Movement",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
}

plt.rcParams.update(
    {
        "font.family": ["Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"],
        "font.size": 10,
        "axes.labelcolor": INK2,
        "text.color": INK,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "xtick.labelcolor": INK2,
        "ytick.labelcolor": INK2,
        "legend.frameon": False,
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
    }
)


def _style(ax: plt.Axes) -> None:
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(length=0)
    ax.grid(color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def _label(ax: plt.Axes, text: str, offset: float, **style: Any) -> None:
    """Left-aligned text ``offset`` points above the axes."""
    ax.annotate(
        text,
        xy=(0, 1),
        xycoords="axes fraction",
        xytext=(0, offset),
        textcoords="offset points",
        va="bottom",
        **style,
    )


def _titles(ax: plt.Axes, title: str, subtitle: str, offset: float = 8) -> None:
    _label(ax, subtitle, offset, fontsize=9.5, color=INK2)
    _label(ax, title, offset + 18, fontsize=13, fontweight="bold", color=INK)


def _save(fig: plt.Figure, path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=200, bbox_inches="tight", pad_inches=0.25)
    plt.close(fig)
    return path


def detection_by_tactic(metrics: dict[str, Any], path: Path) -> Path:
    """In-scope recordings per tactic: detected, missed with telemetry present, telemetry absent."""
    rows = sorted(metrics["per_tactic"].items(), key=lambda kv: kv[1]["in_scope"])
    names = [TACTIC_LABELS.get(t, t) for t, _ in rows]
    detected = np.array([v["detected"] for _, v in rows])
    no_match = np.array([v["missed_no_rule_match"] for _, v in rows])
    absent = np.array([v["missed_telemetry_absent"] for _, v in rows])
    totals = detected + no_match + absent

    fig, ax = plt.subplots(figsize=(7.6, 0.42 * len(rows) + 1.6), dpi=100)
    _style(ax)
    ax.grid(axis="y", visible=False)
    y = np.arange(len(rows))
    ax.barh(y, detected, color=GREEN, lw=0, height=0.62, label="Detected")
    ax.barh(
        y,
        no_match,
        left=detected,
        color=ORANGE,
        lw=0,
        height=0.62,
        label="Missed: telemetry present, no rule matched",
    )
    ax.barh(
        y,
        absent,
        left=detected + no_match,
        color=GRID,
        lw=0,
        height=0.62,
        label="Missed: required telemetry absent",
    )
    for yi, (d, t) in enumerate(zip(detected, totals, strict=True)):
        ax.text(t + 0.4, yi, f"{d}/{t}  ({d / t:.0%})", va="center", fontsize=9, color=INK2)
    ax.set_yticks(y, names)
    ax.set_ylim(-0.6, len(rows) - 0.4)
    ax.set_xlim(0, totals.max() * 1.28)
    ax.set_xlabel("In-scope recordings")
    ax.legend(
        loc="upper center", bbox_to_anchor=(0.45, -0.16), ncol=2, fontsize=8.5, labelcolor=INK2
    )
    det = metrics["detection"]
    _titles(
        ax,
        f"{det['detected']} of {det['in_scope']} attack recordings detected "
        f"({det['detection_rate']:.0%})",
        f"{metrics['rules']} Sigma rules on OTRF Security-Datasets, by the recording's "
        "ATT&CK tactic",
    )
    return _save(fig, path)


def alerts_before_after(first: dict[str, Any], final: dict[str, Any], path: Path) -> Path:
    """Alert volume by analyst verdict, first pass vs. after fixes and benign filters."""
    passes = [("After fixes + filters", final), ("First pass (as written)", first)]
    fig, ax = plt.subplots(figsize=(7.6, 2.9), dpi=100)
    _style(ax)
    ax.grid(axis="y", visible=False)
    segments = [
        ("expected", "On the labelled technique", GREEN),
        ("off_target_attack", "Off-target, real attack activity", BLUE),
        ("false_positive", "False positive (benign)", ORANGE),
    ]
    y = np.arange(len(passes))
    left = np.zeros(len(passes))
    for key, label, color in segments:
        vals = np.array([m["alerts"][key] for _, m in passes], dtype=float)
        ax.barh(y, vals, left=left, color=color, lw=0, height=0.55, label=label)
        for yi, (lo, v) in enumerate(zip(left, vals, strict=True)):
            if v >= 25:
                ax.text(
                    lo + v / 2,
                    yi,
                    f"{int(v)}",
                    ha="center",
                    va="center",
                    fontsize=9,
                    color=SURFACE,
                    fontweight="bold",
                )
        left += vals
    for yi, (_, m) in enumerate(passes):
        det = m["detection"]
        ax.text(
            left[yi] + 6,
            yi,
            f"{m['alerts']['total']} alerts · detects {det['detected']}/{det['in_scope']}",
            va="center",
            fontsize=9,
            color=INK2,
        )
    ax.set_yticks(y, [name for name, _ in passes])
    ax.set_xlim(0, left.max() * 1.42)
    ax.set_xlabel(f"Alerts on the {final['recordings']['scored']} scored recordings")
    ax.legend(
        loc="upper center", bbox_to_anchor=(0.45, -0.32), ncol=3, fontsize=8.5, labelcolor=INK2
    )
    _titles(
        ax,
        "Fixing two rule bugs and filtering benign noise",
        "Every off-target alert signature reviewed (reviews/off_target.yaml); "
        "filters are in-sample",
    )
    return _save(fig, path)


def rule_matrix(
    rule_tactics: dict[str, str],
    firings: list[tuple[str, str, bool]],
    recording_tactics: dict[str, str],
    path: Path,
) -> Path:
    """Rules x recording tactic: in how many recordings each rule fired (expected cells marked)."""
    tactics = sorted(
        {recording_tactics[r] for _, r, _ in firings} | set(recording_tactics.values())
    )
    rules = sorted(rule_tactics, key=lambda s: (rule_tactics[s], s))
    counts = np.zeros((len(rules), len(tactics)))
    expected = defaultdict(int)
    for slug, rec, is_expected in firings:
        i, j = rules.index(slug), tactics.index(recording_tactics[rec])
        counts[i, j] += 1
        if is_expected:
            expected[(i, j)] += 1

    fig, ax = plt.subplots(figsize=(7.6, 0.24 * len(rules) + 1.9), dpi=100)
    for spine in ax.spines.values():
        spine.set_visible(False)
    ax.tick_params(length=0)
    cmap = LinearSegmentedColormap.from_list("dac", [SURFACE, "#cfe0f6", BLUE])
    ax.imshow(counts, aspect="auto", cmap=cmap, vmin=0, vmax=max(4, counts.max()))
    for (i, j), v in np.ndenumerate(counts):
        if v:
            mark = "*" if expected.get((i, j)) else ""
            ax.text(
                j,
                i,
                f"{int(v)}{mark}",
                ha="center",
                va="center",
                fontsize=7.5,
                color=SURFACE if v >= 0.6 * max(4, counts.max()) else INK,
            )
    ax.set_xticks(
        range(len(tactics)),
        [TACTIC_LABELS.get(t, t).replace(" ", "\n") for t in tactics],
        fontsize=8,
    )
    ax.xaxis.tick_top()
    ax.set_yticks(range(len(rules)), rules, fontsize=7.5)
    ax.set_xticks(np.arange(-0.5, len(tactics)), minor=True)
    ax.set_yticks(np.arange(-0.5, len(rules)), minor=True)
    ax.grid(which="minor", color=GRID, linewidth=0.6)
    ax.tick_params(which="minor", length=0)
    _titles(
        ax,
        "Where each rule fires",
        "Recordings with at least one alert, by recording tactic; * includes a labelled detection",
        offset=44,
    )
    return _save(fig, path)


def _short_name(name: str, limit: int = 40) -> str:
    """Sub-technique part of an ATT&CK name, shortened on a word boundary."""
    text = name.split(": ")[-1]
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "..."


def per_technique(metrics: dict[str, Any], path: Path) -> Path:
    """Detection rate per labelled ATT&CK technique (in-scope recordings only)."""
    rows = sorted(metrics["per_technique"], key=lambda r: (r["detection_rate"], r["recordings"]))
    fig, ax = plt.subplots(figsize=(7.6, 0.25 * len(rows) + 1.4), dpi=100)
    _style(ax)
    ax.grid(axis="y", visible=False)
    y = np.arange(len(rows))
    rates = [r["detection_rate"] for r in rows]
    colors = [GREEN if r == 1 else AMBER if r > 0 else ORANGE for r in rates]
    ax.barh(y, rates, color=colors, lw=0, height=0.62)
    for yi, r in enumerate(rows):
        ax.text(
            r["detection_rate"] + 0.01,
            yi,
            f"{r['detected']}/{r['recordings']}",
            va="center",
            fontsize=7.5,
            color=INK2,
        )
    ax.set_yticks(y, [f"{r['technique']} {_short_name(r['name'])}" for r in rows], fontsize=7.5)
    ax.set_ylim(-0.7, len(rows) - 0.3)
    ax.set_xlim(0, 1.12)
    ax.xaxis.set_major_formatter(PercentFormatter(1.0))
    _titles(
        ax,
        "Detection by ATT&CK technique",
        "Share of in-scope recordings labelled with the technique that a covering rule detected",
    )
    return _save(fig, path)
