"""Shared fixtures: a miniature recording set in the Security-Datasets layout (no download)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
RULES = REPO / "rules"
SYSMON = "Microsoft-Windows-Sysmon/Operational"
SYS32 = "C:\\Windows\\System32\\"


def sysmon(eid: int, **fields: Any) -> dict[str, Any]:
    return {"Channel": SYSMON, "EventID": eid, **fields}


RUN_KEY_SET = sysmon(
    13,
    Image="C:\\Temp\\example.exe",
    TargetObject="HKU\\S-1-5-21-1-2-3-1001\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Example",
    Details="C:\\Temp\\example.exe",
)
DEFENDER_TRAY = sysmon(
    13,
    Image="C:\\Program Files\\Windows Defender\\MsMpEng.exe",
    TargetObject="HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsDefender",
)
LSASS_READ = sysmon(
    10, SourceImage="C:\\Temp\\example.exe", TargetImage=SYS32 + "lsass.exe", GrantedAccess="0x1410"
)
WININIT_BOOT = sysmon(
    10, SourceImage=SYS32 + "wininit.exe", TargetImage=SYS32 + "lsass.exe", GrantedAccess="0x1fffff"
)
NOISE = [
    sysmon(1, Image=SYS32 + "svchost.exe", ParentImage=SYS32 + "services.exe", CommandLine="x"),
    {"Channel": "security", "EventID": 4624, "TargetUserName": "example-user"},
]


def write_zip(path: Path, events: list[dict[str, Any]], appledouble: bool = False) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr(path.stem + ".json", "\n".join(json.dumps(e) for e in events) + "\n")
        if appledouble:  # binary resource-fork stub, not JSON
            zf.writestr(f"__MACOSX/._{path.stem}.json", b"\x00\x05\x16\x07\x00\x02\x00\x00Mac OS X")
    return path


def write_meta(root: Path, ident: str, technique: str, sub: str | None, links: list[str]) -> None:
    meta = {
        "title": f"Example {ident}",
        "id": ident,
        "attack_mappings": [{"technique": technique, "sub-technique": sub, "tactics": ["TA0000"]}],
        "files": [
            {"type": "Host", "link": f"https://example.invalid/datasets/atomic/{link}"}
            for link in links
        ],
    }
    path = root / "_metadata" / f"{ident}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(meta), encoding="utf-8")


@pytest.fixture
def dataset(tmp_path: Path) -> Path:
    """Six recordings exercising every evaluation outcome.

    * persistence/run_key        T1547.001, detected (plus a filtered Defender write)
    * credential_access/lsass    T1003.001, detected (plus a filtered boot-time handle);
      AppleDouble junk in the zip; a byte-identical copy lives under defense_evasion
    * credential_access/no_telemetry  T1003.001, missed: only System events, no telemetry
    * persistence/no_match       T1547.001, missed: registry telemetry but no Run key
    * discovery/unlabelled       no metadata; contains a Run-key write (off-target alert)
    """
    root = tmp_path / "security-datasets"
    win = root / "windows"
    write_zip(win / "persistence/host/run_key.zip", [RUN_KEY_SET, DEFENDER_TRAY, *NOISE])
    lsass_events = [LSASS_READ, WININIT_BOOT, *NOISE]
    write_zip(win / "credential_access/host/lsass.zip", lsass_events, appledouble=True)
    write_zip(win / "defense_evasion/host/lsass.zip", lsass_events)
    write_zip(  # only System events: none of the expected rules has telemetry here
        win / "credential_access/host/no_telemetry.zip",
        [{"Channel": "System", "EventID": 7036, "param1": "Example"}],
    )
    write_zip(
        win / "persistence/host/no_match.zip",
        [
            sysmon(13, Image="C:\\Temp\\x.exe", TargetObject="HKLM\\SOFTWARE\\Example\\Value"),
            *NOISE,
        ],
    )
    write_zip(win / "discovery/host/unlabelled.zip", [RUN_KEY_SET, *NOISE])
    write_meta(root, "SDWIN-1", "T1547", "001", ["windows/persistence/host/run_key.zip"])
    write_meta(root, "SDWIN-2", "T1003", "001", ["windows/credential_access/host/lsass.zip"])
    write_meta(root, "SDWIN-3", "T1003", "001", ["windows/credential_access/host/no_telemetry.zip"])
    write_meta(root, "SDWIN-4", "T1547", "001", ["windows/persistence/host/no_match.zip"])
    return root


@pytest.fixture
def reviews(tmp_path: Path) -> Path:
    path = tmp_path / "off_target.yaml"
    path.write_text(
        yaml.safe_dump(
            [
                {
                    "rule": "run_key_modification",
                    "signature": "TargetObject=HKU\\<SID>\\Software\\Microsoft\\Windows"
                    "\\CurrentVersion\\Run\\Example",
                    "verdict": "attack",
                    "technique": "T1547.001",
                    "rationale": "Run key written by an unknown program, unlabelled recording.",
                }
            ]
        ),
        encoding="utf-8",
    )
    return path
