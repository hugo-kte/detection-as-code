"""The matcher supports every Sigma feature the rules use, with Sigma's semantics."""

from __future__ import annotations

from typing import Any

import pytest
import yaml
from sigma.collection import SigmaCollection

from dac.engine import CompiledRule, EventIndex, prepare
from dac.logsource import UnsupportedLogSourceError, resolve

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def compile_rule(
    detection: dict[str, Any], logsource: dict[str, str] | None = None
) -> CompiledRule:
    rule = {
        "title": "probe",
        "logsource": logsource or {"category": "process_creation", "product": "windows"},
        "detection": detection,
    }
    return CompiledRule(SigmaCollection.from_yaml(yaml.safe_dump(rule)).rules[0])


def proc(**fields: Any) -> dict[str, Any]:
    return prepare([{"Channel": SYSMON, "EventID": 1, **fields}])[0]


def test_plain_value_is_case_insensitive_exact_match():
    rule = compile_rule({"sel": {"Image": "C:\\Windows\\Example.exe"}, "condition": "sel"})
    assert rule.event_matches(proc(Image="c:\\windows\\EXAMPLE.EXE"))
    assert not rule.event_matches(proc(Image="C:\\Windows\\Example.exe.bak"))


@pytest.mark.parametrize(
    ("modifier", "value", "hit", "miss"),
    [
        ("contains", "mid", "start-mid-end", "start-end"),
        ("startswith", "start", "start-end", "x-start"),
        ("endswith", "end", "start-end", "end-x"),
    ],
)
def test_string_modifiers(modifier, value, hit, miss):
    rule = compile_rule({"sel": {f"CommandLine|{modifier}": value}, "condition": "sel"})
    assert rule.event_matches(proc(CommandLine=hit))
    assert not rule.event_matches(proc(CommandLine=miss))


def test_wildcards_star_and_question_mark():
    rule = compile_rule({"sel": {"CommandLine": "a*b?d"}, "condition": "sel"})
    assert rule.event_matches(proc(CommandLine="a-anything-bcd"))
    assert not rule.event_matches(proc(CommandLine="a-anything-bd"))


def test_escaped_wildcard_is_literal():
    rule = compile_rule({"sel": {"CommandLine": "x\\*y"}, "condition": "sel"})
    assert rule.event_matches(proc(CommandLine="x*y"))
    assert not rule.event_matches(proc(CommandLine="x-y"))


def test_value_list_is_or_and_all_modifier_is_and():
    any_of = compile_rule({"sel": {"CommandLine|contains": ["aa", "bb"]}, "condition": "sel"})
    all_of = compile_rule({"sel": {"CommandLine|contains|all": ["aa", "bb"]}, "condition": "sel"})
    assert any_of.event_matches(proc(CommandLine="xx aa"))
    assert not all_of.event_matches(proc(CommandLine="xx aa"))
    assert all_of.event_matches(proc(CommandLine="bb xx aa"))


def test_fields_in_one_selection_are_and():
    rule = compile_rule({"sel": {"Image|endswith": "\\a.exe", "User": "u"}, "condition": "sel"})
    assert rule.event_matches(proc(Image="C:\\a.exe", User="U"))
    assert not rule.event_matches(proc(Image="C:\\a.exe", User="other"))


def test_cased_modifier_is_case_sensitive():
    rule = compile_rule({"sel": {"CommandLine|cased|contains": "Token"}, "condition": "sel"})
    assert rule.event_matches(proc(CommandLine="x Token y"))
    assert not rule.event_matches(proc(CommandLine="x token y"))


def test_regex_is_unanchored_search_and_case_sensitive_by_default():
    rule = compile_rule({"sel": {"CommandLine|re": "ab+c"}, "condition": "sel"})
    assert rule.event_matches(proc(CommandLine="xx abbbc yy"))
    assert not rule.event_matches(proc(CommandLine="xx ABC yy"))


def test_regex_ignorecase_flag():
    rule = compile_rule({"sel": {"CommandLine|re|i": "^abc$"}, "condition": "sel"})
    assert rule.event_matches(proc(CommandLine="ABC"))
    assert not rule.event_matches(proc(CommandLine="ABCD"))


def test_windash_expands_dash_and_slash():
    rule = compile_rule({"sel": {"CommandLine|windash|contains": " -flag"}, "condition": "sel"})
    assert rule.event_matches(proc(CommandLine="tool /flag"))
    assert rule.event_matches(proc(CommandLine="tool -flag"))
    assert rule.event_matches(proc(CommandLine="tool \u2013flag"))  # en dash
    assert not rule.event_matches(proc(CommandLine="tool flag"))


def test_base64offset_expansion():
    rule = compile_rule({"sel": {"CommandLine|base64offset|contains": "hello"}, "condition": "sel"})
    assert rule.event_matches(proc(CommandLine="x aGVsbG8 y"))  # base64("hello") at offset 0
    assert not rule.event_matches(proc(CommandLine="x hello y"))


def test_cidr_modifier():
    rule = compile_rule(
        {"sel": {"DestinationIp|cidr": "10.0.0.0/8"}, "condition": "sel"},
        {"category": "network_connection", "product": "windows"},
    )
    event = prepare([{"Channel": SYSMON, "EventID": 3, "DestinationIp": "10.20.30.40"}])[0]
    other = prepare([{"Channel": SYSMON, "EventID": 3, "DestinationIp": "192.0.2.1"}])[0]
    assert rule.event_matches(event)
    assert not rule.event_matches(other)


def test_numeric_value_matches_int_and_numeric_string():
    rule = compile_rule({"sel": {"EventID": 4698}, "condition": "sel"}, {"service": "security"})
    as_int = prepare([{"Channel": "Security", "EventID": 4698}])[0]
    as_text = prepare([{"Channel": "Security", "EventID": "4698"}])[0]
    assert rule.event_matches(as_int) and rule.event_matches(as_text)


@pytest.mark.parametrize(("modifier", "hit", "miss"), [("gt", 5, 3), ("lte", 3, 5)])
def test_numeric_comparisons(modifier, hit, miss):
    rule = compile_rule({"sel": {f"Count|{modifier}": 4}, "condition": "sel"})
    assert rule.event_matches(proc(Count=hit))
    assert not rule.event_matches(proc(Count=miss))


def test_exists_and_null():
    exists = compile_rule({"sel": {"ParentImage|exists": True}, "condition": "sel"})
    null = compile_rule({"sel": {"ParentImage": None}, "condition": "sel"})
    assert exists.event_matches(proc(ParentImage="x")) and not exists.event_matches(proc())
    assert null.event_matches(proc()) and not null.event_matches(proc(ParentImage="x"))


def test_fieldref_compares_two_fields():
    rule = compile_rule({"sel": {"SourceImage|fieldref": "TargetImage"}, "condition": "sel"})
    assert rule.event_matches(proc(SourceImage="a.exe", TargetImage="A.EXE"))
    assert not rule.event_matches(proc(SourceImage="a.exe", TargetImage="b.exe"))


def test_selectors_not_and_parentheses():
    detection = {
        "selection_a": {"CommandLine|contains": "aa"},
        "selection_b": {"CommandLine|contains": "bb"},
        "filter_x": {"User": "excluded"},
        "condition": "1 of selection_* and not filter_x",
    }
    rule = compile_rule(detection)
    assert rule.event_matches(proc(CommandLine="bb", User="u"))
    assert not rule.event_matches(proc(CommandLine="bb", User="excluded"))
    assert not rule.event_matches(proc(CommandLine="cc", User="u"))
    both = compile_rule({**detection, "condition": "all of selection_*"})
    assert both.event_matches(proc(CommandLine="aa bb")) and not both.event_matches(
        proc(CommandLine="aa")
    )


def test_keyword_search_scans_every_field():
    rule = compile_rule({"kw": ["needle"], "condition": "kw"})
    assert rule.event_matches(proc(Description="hay needle hay"))
    assert not rule.event_matches(proc(Description="hay"))


def test_list_valued_field_matches_any_element():
    rule = compile_rule({"sel": {"Tags": "b"}, "condition": "sel"})
    assert rule.event_matches(proc(Tags=["a", "b"]))
    assert not rule.event_matches(proc(Tags=["a", "c"]))


def test_missing_field_never_matches_a_value():
    rule = compile_rule({"sel": {"CommandLine|contains": "x"}, "condition": "sel"})
    assert not rule.event_matches(proc())


def test_security_4688_resolves_sysmon_field_names():
    rule = compile_rule({"sel": {"Image|endswith": "\\a.exe"}, "condition": "sel"})
    event = prepare([{"Channel": "security", "EventID": 4688, "NewProcessName": "C:\\a.exe"}])[0]
    assert rule.event_matches(event)


def test_log_source_selects_channel_and_event_id():
    rule = compile_rule({"sel": {"Image|endswith": "\\a.exe"}, "condition": "sel"})
    wrong_id = prepare([{"Channel": SYSMON, "EventID": 13, "Image": "C:\\a.exe"}])[0]
    assert not rule.event_matches(wrong_id)


def test_channel_comparison_ignores_case():
    rule = compile_rule({"sel": {"EventID": 1102}, "condition": "sel"}, {"service": "security"})
    assert rule.event_matches(prepare([{"Channel": "security", "EventID": 1102}])[0])
    assert rule.event_matches(prepare([{"Channel": "Security", "EventID": 1102}])[0])


def test_candidate_events_and_counts_use_the_index():
    rule = compile_rule({"sel": {"CommandLine|contains": "x"}, "condition": "sel"})
    events = prepare(
        [
            {"Channel": SYSMON, "EventID": 1, "CommandLine": "x"},
            {"Channel": SYSMON, "EventID": 1, "CommandLine": "y"},
            {"Channel": SYSMON, "EventID": 13, "CommandLine": "x"},
        ]
    )
    assert rule.count_matches(EventIndex(events)) == 1


def test_unknown_log_source_is_rejected():
    with pytest.raises(UnsupportedLogSourceError):
        compile_rule({"sel": {"a": "b"}, "condition": "sel"}, {"category": "no_such_category"})
    with pytest.raises(UnsupportedLogSourceError):
        resolve(
            SigmaCollection.from_yaml(
                "title: t\nlogsource: {product: windows}\ndetection: {s: {a: b}, condition: s}\n"
            )
            .rules[0]
            .logsource
        )
