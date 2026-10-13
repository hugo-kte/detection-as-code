"""Map a Sigma log source to the Windows events it selects in this telemetry.

The recordings use the OSSEM/Mordor common schema: one flat JSON object per event with a ``Channel``
(e.g. ``Microsoft-Windows-Sysmon/Operational``) and an integer ``EventID``. The generic Sigma
``category`` log sources (``process_creation``, ``registry_set``, ...) are resolved to the concrete
``(channel, event id)`` pairs that carry that telemetry, and ``service`` log sources to a whole
channel where the rule itself selects the ``EventID`` field.
"""

from __future__ import annotations

from sigma.rule import SigmaLogSource

SYSMON = "microsoft-windows-sysmon/operational"
SECURITY = "security"
SYSTEM = "system"
PS_OPERATIONAL = "microsoft-windows-powershell/operational"

# category -> list of (channel, {event ids} or None for any id in that channel)
CATEGORY_EVENTS: dict[str, list[tuple[str, frozenset[int] | None]]] = {
    "process_creation": [(SYSMON, frozenset({1})), (SECURITY, frozenset({4688}))],
    "process_access": [(SYSMON, frozenset({10}))],
    "image_load": [(SYSMON, frozenset({7}))],
    "file_event": [(SYSMON, frozenset({11}))],
    "file_delete": [(SYSMON, frozenset({23, 26}))],
    "pipe_created": [(SYSMON, frozenset({17, 18}))],
    "registry_add": [(SYSMON, frozenset({12}))],
    "registry_delete": [(SYSMON, frozenset({12}))],
    "registry_set": [(SYSMON, frozenset({13}))],
    "registry_event": [(SYSMON, frozenset({12, 13, 14}))],
    "create_remote_thread": [(SYSMON, frozenset({8}))],
    "network_connection": [(SYSMON, frozenset({3}))],
    "dns_query": [(SYSMON, frozenset({22}))],
    "wmi_event": [(SYSMON, frozenset({19, 20, 21}))],
    "ps_script": [(PS_OPERATIONAL, frozenset({4104}))],
    "ps_module": [(PS_OPERATIONAL, frozenset({4103}))],
}

# service -> channels; the rule's detection selects the EventID field explicitly
SERVICE_CHANNELS: dict[str, frozenset[str]] = {
    "security": frozenset({SECURITY}),
    "system": frozenset({SYSTEM}),
    "sysmon": frozenset({SYSMON}),
    "powershell": frozenset({PS_OPERATIONAL}),
    "powershell-classic": frozenset({"windows powershell"}),
    "taskscheduler": frozenset({"microsoft-windows-taskscheduler/operational"}),
    "wmi": frozenset({"microsoft-windows-wmi-activity/operational"}),
    "dns-server": frozenset({"dns server"}),
}

# Fields that carry a different name on Security/System than on Sysmon. Only applied as a fallback:
# a rule written with the Sysmon taxonomy still matches a 4688 process-creation event.
FIELD_ALIASES: dict[tuple[str, int], dict[str, str]] = {
    (SECURITY, 4688): {
        "Image": "NewProcessName",
        "ParentImage": "ParentProcessName",
        "User": "SubjectUserName",
    },
}


class UnsupportedLogSourceError(ValueError):
    """Raised when a rule's log source is not mapped to this telemetry."""


def resolve(ls: SigmaLogSource) -> list[tuple[str, frozenset[int] | None]]:
    """Return the ``(channel, event ids)`` selectors a log source maps to.

    :raises UnsupportedLogSourceError: if neither the category nor the service is known.
    """
    if ls.category:
        if ls.category not in CATEGORY_EVENTS:
            raise UnsupportedLogSourceError(f"unknown category '{ls.category}'")
        return CATEGORY_EVENTS[ls.category]
    if ls.service:
        if ls.service not in SERVICE_CHANNELS:
            raise UnsupportedLogSourceError(f"unknown service '{ls.service}'")
        return [(channel, None) for channel in SERVICE_CHANNELS[ls.service]]
    raise UnsupportedLogSourceError("log source has neither category nor service")


def channels(ls: SigmaLogSource) -> set[str]:
    """The set of channels (lower-case) a log source can match."""
    return {channel for channel, _ in resolve(ls)}
