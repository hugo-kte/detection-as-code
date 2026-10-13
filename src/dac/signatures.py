"""Group alerts into *signatures* an analyst can review once instead of alert by alert.

A signature is the rule plus a few normalised, low-cardinality fields of the matching event: image
names rather than full command lines, registry keys with SIDs and GUIDs masked, account *type*
rather than account name, the script path rather than the script text. Two alerts with the same
signature are the same kind of activity, so one verdict in ``reviews/off_target.yaml`` covers both.
Command lines and script content are deliberately never part of a signature.
"""

from __future__ import annotations

import re
from typing import Any

from sigma.rule import SigmaLogSource

from .engine import field_value

# category -> fields that characterise an alert from that telemetry. ``Verb`` is derived from the
# command line: only its first argument token (e.g. ``save``, ``/c``, ``-enc``), never the payload.
CATEGORY_FIELDS: dict[str, list[str]] = {
    "process_creation": ["ParentImage", "Image", "Verb"],
    "process_access": ["SourceImage", "GrantedAccess"],
    "create_remote_thread": ["SourceImage", "TargetImage"],
    "image_load": ["Image", "ImageLoaded"],
    "file_event": ["Image", "TargetFilename"],
    "registry_add": ["TargetObject"],
    "registry_delete": ["TargetObject"],
    "registry_set": ["TargetObject"],
    "registry_event": ["TargetObject"],
    "wmi_event": ["EventID", "Operation"],
    "pipe_created": ["Image", "PipeName"],
    "ps_script": ["Path"],
    "ps_module": ["Path"],
}
# (service, event id) -> fields
SERVICE_FIELDS: dict[tuple[str, int], list[str]] = {
    ("security", 4662): ["SubjectUserName", "ObjectServer"],
    ("security", 4698): ["EventID", "TaskName", "SubjectUserName"],
    ("security", 4702): ["EventID", "TaskName", "SubjectUserName"],
    ("security", 5145): ["ShareName", "SubjectUserName"],
    ("system", 7045): ["ImagePath", "AccountName"],
}

_IMAGE_FIELDS = {"Image", "ParentImage", "SourceImage", "TargetImage", "ImageLoaded"}
_SID = re.compile(r"S-1-5-21(-\d+)+", re.IGNORECASE)
_GUID = re.compile(
    r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", re.IGNORECASE
)
_HEX_SUFFIX = re.compile(r"[0-9a-f]{6,}", re.IGNORECASE)


def _basename(value: str) -> str:
    return value.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1].lower()


def _registry_key(value: str) -> str:
    value = re.sub(r"^\\REGISTRY\\MACHINE", "HKLM", value, flags=re.IGNORECASE)
    value = re.sub(r"^\\REGISTRY\\USER", "HKU", value, flags=re.IGNORECASE)
    value = _SID.sub("<SID>", value)
    return _GUID.sub("<GUID>", value)


def _account(value: str) -> str:
    """Account *type* only: computer accounts end with '$'; well-known service names kept."""
    text = value.strip()
    if text.endswith("$"):
        return "computer-account"
    if text.upper() in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "LOCALSYSTEM", "-", ""}:
        return text.upper() or "-"
    return "user-account"


def normalise(field: str, value: Any) -> str:
    if value is None:
        return "-"
    text = str(value)
    if field in _IMAGE_FIELDS:
        return _basename(text)
    if field == "TargetObject":
        return _registry_key(text)
    if field in {"SubjectUserName", "AccountName"}:
        return _account(text)
    if field == "ImagePath":  # first token of the service command, e.g. %COMSPEC% or a binary
        first = text.strip().strip('"').split(" ", 1)[0]
        return _basename(first)
    if field in {"Path", "TargetFilename"}:
        return _HEX_SUFFIX.sub("<hex>", _basename(text)) if text.strip() else "-"
    if field == "TaskName":
        return _GUID.sub("<GUID>", text)
    return text[:80]


def command_verb(command_line: Any) -> str:
    """First argument of a command line, lower-cased: a verb or flag, not the payload.

    ``"C:\\Windows\\System32\\reg.exe" save HKLM\\SAM x`` -> ``save``; a bare interactive shell
    -> ``-``. Paths and long tokens collapse to placeholders to keep signatures low-cardinality.
    """
    text = str(command_line or "").strip()
    if text.startswith('"'):
        end = text.find('"', 1)
        rest = text[end + 1 :] if end > 0 else ""
    else:
        rest = text.split(None, 1)[1] if len(text.split(None, 1)) > 1 else ""
    tokens = rest.split()
    if not tokens:
        return "-"
    token = tokens[0].strip("\"'").lower()
    if "\\" in token or "/" in token[1:] or ":" in token[1:]:
        return "<path>"
    return token if len(token) <= 24 else "<long>"


def fields_for(logsource: SigmaLogSource, event_id: int | None) -> list[str]:
    if logsource.category and logsource.category in CATEGORY_FIELDS:
        return CATEGORY_FIELDS[logsource.category]
    if logsource.service and event_id is not None:
        return SERVICE_FIELDS.get((logsource.service, event_id), ["EventID"])
    return ["EventID"]


def signature(logsource: SigmaLogSource, event: dict[str, Any]) -> str:
    """Stable, readable signature of one alert, e.g. ``ParentImage=w3wp.exe | Image=cmd.exe``."""
    parts = []
    for f in fields_for(logsource, event.get("__eventid__")):
        value = (
            command_verb(field_value(event, "CommandLine"))
            if f == "Verb"
            else normalise(f, field_value(event, f))
        )
        parts.append(f"{f}={value}")
    return " | ".join(parts)
