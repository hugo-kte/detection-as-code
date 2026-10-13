"""Alert signatures are stable, low-cardinality and never carry command lines."""

from __future__ import annotations

from sigma.rule import SigmaLogSource

from dac.engine import prepare
from dac.signatures import command_verb, normalise, signature

PROCESS = SigmaLogSource(category="process_creation", product="windows")


def test_command_verb_keeps_only_the_first_argument():
    assert command_verb('"C:\\Windows\\System32\\reg.exe" save HKLM\\X out') == "save"
    assert command_verb("tool.exe -Flag value") == "-flag"
    assert command_verb('"C:\\Windows\\system32\\cmd.exe"') == "-"
    assert command_verb("tool.exe C:\\Temp\\file.txt") == "<path>"
    assert command_verb("tool.exe " + "a" * 40) == "<long>"
    assert command_verb(None) == "-"


def test_registry_keys_mask_sids_guids_and_raw_hive_names():
    key = (
        "\\REGISTRY\\USER\\S-1-5-21-1-2-3-1001\\Software\\{01234567-89ab-cdef-0123-456789abcdef}\\V"
    )
    assert normalise("TargetObject", key) == "HKU\\<SID>\\Software\\<GUID>\\V"


def test_accounts_reduce_to_their_type():
    assert normalise("SubjectUserName", "DC01$") == "computer-account"
    assert normalise("SubjectUserName", "alice") == "user-account"
    assert normalise("SubjectUserName", "SYSTEM") == "SYSTEM"


def test_process_signature_uses_image_names_not_command_lines():
    event = prepare(
        [
            {
                "Channel": "Microsoft-Windows-Sysmon/Operational",
                "EventID": 1,
                "ParentImage": "C:\\Windows\\explorer.exe",
                "Image": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c secret-looking-payload",
            }
        ]
    )[0]
    sig = signature(PROCESS, event)
    assert sig == "ParentImage=explorer.exe | Image=cmd.exe | Verb=/c"
    assert "payload" not in sig


def test_service_signature_by_event_id():
    logsource = SigmaLogSource(product="windows", service="security")
    event = prepare(
        [
            {
                "Channel": "Security",
                "EventID": 5145,
                "ShareName": "\\\\*\\C$",
                "SubjectUserName": "bob",
            }
        ]
    )[0]
    assert signature(logsource, event) == "ShareName=\\\\*\\C$ | SubjectUserName=user-account"
