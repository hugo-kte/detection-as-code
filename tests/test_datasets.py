"""Catalogue and loader of the Security-Datasets recordings (miniature fixture, no download)."""

from __future__ import annotations

import json
from pathlib import Path

from conftest import write_zip
from dac.datasets import _techniques, catalogue, content_signature, git_blob_sha, load_events


def test_catalogue_keys_by_relative_path(dataset: Path):
    recordings = {r.key: r for r in catalogue(dataset)}
    assert len(recordings) == 6
    # the same file name under two tactics stays two recordings, both labelled through its stem
    copies = [r for r in recordings.values() if r.name == "lsass"]
    assert {r.tactic for r in copies} == {"credential_access", "defense_evasion"}
    assert all(r.techniques == {"T1003", "T1003.001"} for r in copies)


def test_unlabelled_recordings_are_kept(dataset: Path):
    unlabelled = [r for r in catalogue(dataset) if not r.labelled]
    assert [r.name for r in unlabelled] == ["unlabelled"]
    assert unlabelled[0].dataset_id == ""


def test_load_events_skips_appledouble_members(dataset: Path):
    events = load_events(dataset / "windows/credential_access/host/lsass.zip")
    assert len(events) == 4
    assert all(isinstance(e, dict) and "Channel" in e for e in events)


def test_content_signature_ignores_appledouble_and_finds_duplicates(dataset: Path, tmp_path: Path):
    a = dataset / "windows/credential_access/host/lsass.zip"
    b = dataset / "windows/defense_evasion/host/lsass.zip"
    assert content_signature(a) == content_signature(b)
    other = write_zip(tmp_path / "other.zip", [{"Channel": "System", "EventID": 1}])
    assert content_signature(other) != content_signature(a)


def test_techniques_from_metadata():
    meta = {
        "attack_mappings": [
            {"technique": "T1003", "sub-technique": "001"},
            {"technique": "T1021", "sub-technique": None},
            {"technique": "T0000", "sub-technique": None},  # upstream placeholder, not a technique
        ]
    }
    assert _techniques(meta) == {"T1003", "T1003.001", "T1021"}


def test_git_blob_sha_matches_git():
    # `printf 'hello\n' | git hash-object --stdin`
    assert git_blob_sha(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


def test_manifest_is_pinned():
    manifest = json.loads(
        Path(__file__).resolve().parents[1].joinpath("configs/security_datasets.json").read_text()
    )
    assert manifest["repo"] == "OTRF/Security-Datasets"
    assert len(manifest["commit"]) == 40
    zips = [f for f in manifest["files"] if f["path"].endswith(".zip")]
    assert len(zips) == 114 and all(len(f["sha"]) == 40 for f in manifest["files"])
