"""OTRF Security-Datasets: pinned manifest, verified download, catalogue and loader.

Each recording is a zip of JSON lines (Sysmon, Security, System, PowerShell... events) captured
while one ATT&CK technique was exercised in a lab, with a metadata file naming the technique.
The recordings are only consumed as test data here.
"""

from __future__ import annotations

import concurrent.futures as cf
import hashlib
import io
import json
import logging
import re
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

REPO = "OTRF/Security-Datasets"
COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"  # master, 2023-09-20
MANIFEST = Path("configs/security_datasets.json")
HOST_ZIP = re.compile(r"^datasets/atomic/windows/[^/]+/host/[^/]+\.zip$")
METADATA = re.compile(r"^datasets/atomic/_metadata/SDWIN-[^/]+\.yaml$")


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def build_manifest(commit: str = COMMIT, path: Path = MANIFEST) -> dict[str, Any]:
    """Dev helper: list the Windows host recordings and metadata at a pinned commit."""
    url = f"https://api.github.com/repos/{REPO}/git/trees/{commit}?recursive=1"
    tree = json.load(urllib.request.urlopen(url, timeout=60))["tree"]
    files = [
        {"path": t["path"], "size": t["size"], "sha": t["sha"]}
        for t in tree
        if t["type"] == "blob" and (HOST_ZIP.match(t["path"]) or METADATA.match(t["path"]))
    ]
    manifest = {"repo": REPO, "commit": commit, "license": "MIT", "files": files}
    path.write_text(json.dumps(manifest, indent=1) + "\n")
    return manifest


def download(out_dir: Path, manifest_path: Path = MANIFEST, workers: int = 8) -> int:
    """Fetch every manifest file at the pinned commit; each one is checked against its git SHA."""
    manifest = json.loads(manifest_path.read_text())
    base = f"https://raw.githubusercontent.com/{manifest['repo']}/{manifest['commit']}/"

    def fetch(entry: dict[str, Any]) -> str:
        dest = out_dir / entry["path"].removeprefix("datasets/atomic/")
        if dest.exists() and git_blob_sha(dest.read_bytes()) == entry["sha"]:
            return "cached"
        data = urllib.request.urlopen(base + entry["path"], timeout=120).read()
        if git_blob_sha(data) != entry["sha"]:
            raise ValueError(f"checksum mismatch for {entry['path']}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        return "downloaded"

    with cf.ThreadPoolExecutor(workers) as ex:
        results = list(ex.map(fetch, manifest["files"]))
    log.info(
        "%d files: %d downloaded, %d cached",
        len(results),
        results.count("downloaded"),
        results.count("cached"),
    )
    return len(results)


@dataclass
class Recording:
    """One zip of recorded events and the ATT&CK techniques it was labelled with.

    ``key`` is the path relative to the dataset root (e.g.
    ``windows/credential_access/host/empire_mimikatz_logonpasswords.zip``); it is unique even when
    two tactic folders contain a file with the same name. ``techniques`` holds both the
    sub-technique and its parent (e.g. ``{"T1003", "T1003.001"}``). An empty set means the
    recording carries no ATT&CK label in the upstream metadata.
    """

    key: str
    path: Path
    tactic: str
    dataset_id: str = ""
    title: str = ""
    techniques: set[str] = field(default_factory=set)

    @property
    def name(self) -> str:
        return self.path.stem

    @property
    def labelled(self) -> bool:
        return bool(self.techniques)


def _techniques(meta: dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for m in meta.get("attack_mappings") or []:
        tech, sub = m.get("technique"), m.get("sub-technique")
        if not tech or str(tech) == "T0000":  # placeholder used for un-mapped behaviour upstream
            continue
        out.add(str(tech))
        if sub not in (None, "", "null"):
            out.add(f"{tech}.{int(sub):03d}" if str(sub).isdigit() else f"{tech}.{sub}")
    return out


def catalogue(root: Path) -> list[Recording]:
    """Every host recording, labelled from the metadata file that references it.

    Recordings are keyed by their path relative to ``root`` so that the two copies of
    ``empire_wmic_add_user_backdoor.zip`` (shipped under both ``defense_evasion`` and
    ``lateral_movement``) are both kept. Metadata is matched to recordings by file *stem*, so both
    copies inherit the T1047 label even though the upstream metadata only links one of them. Six
    recordings have no metadata at all and are returned with an empty technique set.
    """
    recordings = {
        str(p.relative_to(root)): Recording(
            key=str(p.relative_to(root)), path=p, tactic=p.parent.parent.name
        )
        for p in sorted(root.glob("windows/*/host/*.zip"))
    }
    by_stem: dict[str, list[Recording]] = {}
    for rec in recordings.values():
        by_stem.setdefault(rec.path.stem, []).append(rec)

    for meta_path in sorted((root / "_metadata").glob("SDWIN-*.yaml")):
        meta = yaml.safe_load(meta_path.read_text(encoding="utf-8"))
        for f in meta.get("files") or []:
            if str(f.get("type", "")).lower() != "host":
                continue
            stem = Path(str(f["link"])).name.split(".")[0]
            for rec in by_stem.get(stem, []):
                rec.dataset_id, rec.title = meta["id"], meta.get("title", "")
                rec.techniques |= _techniques(meta)
    return list(recordings.values())


def content_signature(path: Path) -> str:
    """Stable signature of a recording's payload (member names + CRCs), ignoring AppleDouble junk.

    Two recordings with the same signature hold byte-identical events; the catalogue ships one such
    pair, and the evaluation de-duplicates on this so the same events are not counted twice.
    """
    with zipfile.ZipFile(path) as zf:
        parts = sorted(
            f"{i.filename}:{i.CRC}:{i.file_size}"
            for i in zf.infolist()
            if not _is_appledouble(i.filename)
        )
    return hashlib.sha1("|".join(parts).encode()).hexdigest()


def _is_appledouble(name: str) -> bool:
    """macOS archives created on this project leak ``__MACOSX/._*`` AppleDouble members."""
    return name.startswith("__MACOSX/") or Path(name).name.startswith("._")


def load_events(path: Path) -> list[dict[str, Any]]:
    """All events of a recording (one JSON object per line inside the zip).

    ``__MACOSX`` AppleDouble members are skipped: they are binary resource-fork stubs that are not
    JSON and would otherwise crash the parser on the 14 archives that carry them.
    """
    events: list[dict[str, Any]] = []
    with zipfile.ZipFile(path) as zf:
        for name in zf.namelist():
            if name.endswith("/") or _is_appledouble(name):
                continue
            with zf.open(name) as fh:
                for line in io.TextIOWrapper(fh, encoding="utf-8", errors="replace"):
                    line = line.strip()
                    if line:
                        events.append(json.loads(line))
    return events
