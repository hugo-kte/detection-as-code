"""A small, sound matcher that runs parsed Sigma rules over recorded Windows events.

pySigma parses each rule into a condition tree whose leaves are field/value expressions with all
value modifiers already applied (``contains`` wraps the value in wildcards, ``windash`` expands it,
``re`` turns it into a regular expression, and so on). This module compiles that tree once into a
Python predicate and evaluates it against the flat JSON events of a recording.

Supported Sigma features: plain and wildcard strings (case-insensitive by default, ``cased`` for
case-sensitive), ``contains`` / ``startswith`` / ``endswith``, ``all`` and value lists, ``not``,
``1 of`` / ``all of`` selectors, ``re`` (with ``i`` / ``m`` / ``s`` flags), ``cidr``, numeric
comparisons (``lt`` / ``lte`` / ``gt`` / ``gte``), ``windash``, ``base64`` family expansions,
``exists``, ``fieldref``, null values and keyword (field-less) searches.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
    ConditionValueExpression,
)
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCIDRExpression,
    SigmaCompareExpression,
    SigmaExists,
    SigmaExpansion,
    SigmaFieldReference,
    SigmaNull,
    SigmaNumber,
    SigmaRegularExpression,
    SigmaString,
)

from .logsource import FIELD_ALIASES

# Internal (lower-cased channel, event id) added to every event; never matched as a user field.
_META_FIELDS = frozenset({"__channel__", "__eventid__"})

EventPredicate = Callable[[dict[str, Any]], bool]
ScalarPredicate = Callable[[Any], bool]


def channel_of(event: dict[str, Any]) -> str:
    return str(event.get("Channel", "")).lower()


def eventid_of(event: dict[str, Any]) -> int | None:
    eid = event.get("EventID")
    if isinstance(eid, bool):
        return None
    if isinstance(eid, int):
        return eid
    try:
        return int(str(eid))
    except (TypeError, ValueError):
        return None


def field_value(event: dict[str, Any], field: str) -> Any:
    """Resolve a field, falling back to the Security/System alias of a Sysmon field name."""
    if field in event:
        return event[field]
    alias_map = FIELD_ALIASES.get((event["__channel__"], event["__eventid__"]))
    if alias_map and field in alias_map:
        return event.get(alias_map[field])
    return None


def _as_str(value: Any) -> str:
    return value if isinstance(value, str) else str(value)


def _num_eq(value: Any, number: float) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return value == number
    text = _as_str(value).strip()
    try:
        parsed = int(text, 0) if text.lower().startswith(("0x", "-0x")) else float(text)
    except ValueError:
        return text == str(number)
    return parsed == number


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    text = _as_str(value).strip().lower()
    if text in {"true", "1", "yes"}:
        return True
    if text in {"false", "0", "no"}:
        return False
    return None


def _string_regex(value: SigmaString) -> re.Pattern[str]:
    pattern = str(value.to_regex().regexp)
    flags = re.DOTALL if isinstance(value, SigmaCasedString) else re.IGNORECASE | re.DOTALL
    return re.compile(pattern, flags)


def _regex(value: SigmaRegularExpression) -> re.Pattern[str]:
    flags = 0
    for flag in value.flags:
        flags |= SigmaRegularExpression.sigma_to_python_flags[flag]
    return re.compile(str(value.regexp), flags)


def _compile_value(value: Any) -> ScalarPredicate:
    """Compile a leaf Sigma value into a predicate over one already-resolved scalar."""
    if isinstance(value, SigmaString):  # also covers SigmaCasedString
        rx = _string_regex(value)
        return lambda v: bool(rx.fullmatch(_as_str(v)))
    if isinstance(value, SigmaNumber):
        number = value.number
        return lambda v: _num_eq(v, number)
    if isinstance(value, SigmaBool):
        wanted = value.boolean
        return lambda v: _as_bool(v) is wanted
    if isinstance(value, SigmaRegularExpression):
        rx = _regex(value)
        return lambda v: bool(rx.search(_as_str(v)))
    if isinstance(value, SigmaCIDRExpression):
        network = value.network
        return lambda v: _in_cidr(v, network)
    if isinstance(value, SigmaCompareExpression):
        return _compile_compare(value)
    if isinstance(value, SigmaExpansion):
        subs = [_compile_value(v) for v in value.values]
        return lambda v: any(sub(v) for sub in subs)
    raise NotImplementedError(f"unsupported Sigma value type: {type(value).__name__}")


def _in_cidr(value: Any, network: Any) -> bool:
    try:
        return ipaddress.ip_address(_as_str(value)) in network
    except ValueError:
        return False


def _compile_compare(value: SigmaCompareExpression) -> ScalarPredicate:
    number = value.number.number
    op = value.op
    ops = SigmaCompareExpression.CompareOperators
    table: dict[Any, Callable[[float], bool]] = {
        ops.LT: lambda x: x < number,
        ops.LTE: lambda x: x <= number,
        ops.GT: lambda x: x > number,
        ops.GTE: lambda x: x >= number,
        ops.NEQ: lambda x: x != number,
    }
    test = table[op]

    def predicate(v: Any) -> bool:
        try:
            return test(float(_as_str(v)))
        except ValueError:
            return False

    return predicate


def _field_test(resolved: Any, scalar_pred: ScalarPredicate) -> bool:
    if resolved is None:
        return False
    if isinstance(resolved, list):
        return any(scalar_pred(item) for item in resolved)
    return scalar_pred(resolved)


def _all_scalar_values(event: dict[str, Any]) -> Iterator[Any]:
    for key, value in event.items():
        if key in _META_FIELDS:
            continue
        if isinstance(value, list):
            yield from value
        else:
            yield value


def compile_condition(cond: Any) -> EventPredicate:
    """Compile a postprocessed pySigma condition tree into an event predicate."""
    if isinstance(cond, ConditionAND):
        subs = [compile_condition(a) for a in cond.args]
        return lambda e: all(sub(e) for sub in subs)
    if isinstance(cond, ConditionOR):
        subs = [compile_condition(a) for a in cond.args]
        return lambda e: any(sub(e) for sub in subs)
    if isinstance(cond, ConditionNOT):
        sub = compile_condition(cond.args[0])
        return lambda e: not sub(e)
    if isinstance(cond, ConditionFieldEqualsValueExpression):
        return _compile_field(cond.field, cond.value)
    if isinstance(cond, ConditionValueExpression):
        return _compile_keyword(cond.value)
    raise NotImplementedError(f"unsupported condition node: {type(cond).__name__}")


def _compile_field(field: str, value: Any) -> EventPredicate:
    if isinstance(value, SigmaNull):
        return lambda e: field_value(e, field) is None
    if isinstance(value, SigmaExists):
        wanted = value.exists
        return lambda e: (field_value(e, field) is not None) is wanted
    if isinstance(value, SigmaFieldReference):
        ref = value.field
        if value.starts_with:
            return lambda e: _ref_affix(e, field, ref, prefix=True)
        if value.ends_with:
            return lambda e: _ref_affix(e, field, ref, prefix=False)
        return lambda e: _ref_equal(e, field, ref)
    scalar_pred = _compile_value(value)
    return lambda e: _field_test(field_value(e, field), scalar_pred)


def _ref_equal(event: dict[str, Any], field: str, ref: str) -> bool:
    a, b = field_value(event, field), field_value(event, ref)
    return a is not None and b is not None and _as_str(a).lower() == _as_str(b).lower()


def _ref_affix(event: dict[str, Any], field: str, ref: str, *, prefix: bool) -> bool:
    a, b = field_value(event, field), field_value(event, ref)
    if a is None or b is None:
        return False
    a, b = _as_str(a).lower(), _as_str(b).lower()
    return a.startswith(b) if prefix else a.endswith(b)


def _compile_keyword(value: Any) -> EventPredicate:
    """Field-less keyword: search the pattern across every scalar value of the event."""
    if isinstance(value, SigmaString):
        rx = _string_regex(value)
        search = rx.search
        return lambda e: any(search(_as_str(v)) for v in _all_scalar_values(e))
    scalar_pred = _compile_value(value)
    return lambda e: any(scalar_pred(v) for v in _all_scalar_values(e))


class CompiledRule:
    """A rule compiled to an event predicate plus the events it should be evaluated against."""

    def __init__(self, rule: SigmaRule):
        self.rule = rule
        condition = rule.detection.parsed_condition[0].parse()
        if condition is None:
            raise ValueError(f"rule '{rule.title}' has an empty condition")
        self._predicate = compile_condition(condition)
        # Resolve the log source lazily to keep import-time failures out of compilation.
        from .logsource import resolve

        self.selectors = resolve(rule.logsource)
        self._channels = {channel for channel, _ in self.selectors}

    def event_matches(self, event: dict[str, Any]) -> bool:
        """Does a single (already prepared) event satisfy the rule's log source and condition?"""
        return self._in_logsource(event) and self._predicate(event)

    def _in_logsource(self, event: dict[str, Any]) -> bool:
        channel, eid = event["__channel__"], event["__eventid__"]
        for sel_channel, sel_ids in self.selectors:
            if channel == sel_channel and (sel_ids is None or eid in sel_ids):
                return True
        return False

    def candidate_events(self, index: EventIndex) -> Iterator[dict[str, Any]]:
        """The events worth testing: only those matching the rule's channel/event-id selectors."""
        for channel, event_ids in self.selectors:
            if event_ids is None:
                yield from index.by_channel.get(channel, [])
            else:
                for eid in event_ids:
                    yield from index.by_channel_eid.get((channel, eid), [])

    def matching_events(self, index: EventIndex) -> list[dict[str, Any]]:
        """Every event of a recording the rule fires on."""
        predicate = self._predicate
        return [event for event in self.candidate_events(index) if predicate(event)]

    def count_matches(self, index: EventIndex) -> int:
        """How many events of a recording the rule fires on."""
        return len(self.matching_events(index))


def prepare(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Annotate events in place with their lower-cased channel and integer event id."""
    prepared = []
    for event in events:
        event["__channel__"] = channel_of(event)
        event["__eventid__"] = eventid_of(event)
        prepared.append(event)
    return prepared


class EventIndex:
    """A recording's events bucketed by channel and by ``(channel, event id)`` for fast lookup."""

    def __init__(self, events: Iterable[dict[str, Any]]):
        self.by_channel: dict[str, list[dict[str, Any]]] = {}
        self.by_channel_eid: dict[tuple[str, int | None], list[dict[str, Any]]] = {}
        for event in events:
            channel, eid = event["__channel__"], event["__eventid__"]
            self.by_channel.setdefault(channel, []).append(event)
            self.by_channel_eid.setdefault((channel, eid), []).append(event)
