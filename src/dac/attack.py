"""A small, committed slice of the MITRE ATT&CK Enterprise matrix.

pySigma 1.x can validate ``attack.*`` tags, but only by downloading the ATT&CK STIX bundle at
runtime. CI runs offline and the project pins its data, so the techniques and tactics this
repository actually uses are vendored here instead. The table covers every technique exercised by
the recordings plus every technique a rule is tagged with; :func:`dac.cli` has a helper to check it
stays in sync with the rules.

Source: MITRE ATT&CK Enterprise (https://attack.mitre.org/). ATT&CK is released by The MITRE
Corporation under the terms at https://attack.mitre.org/resources/legal-and-branding/terms-of-use/.
"""

from __future__ import annotations

# ATT&CK tactic id -> Sigma tag short-name (as used in `attack.<short-name>` rule tags).
TACTICS: dict[str, str] = {
    "TA0001": "initial-access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege-escalation",
    "TA0005": "defense-evasion",
    "TA0006": "credential-access",
    "TA0007": "discovery",
    "TA0008": "lateral-movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command-and-control",
    "TA0040": "impact",
}

TACTIC_NAMES: dict[str, str] = {
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
}

# technique id -> (name, [tactic short-names]).
TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    "T1003": ("OS Credential Dumping", ["credential-access"]),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", ["credential-access"]),
    "T1003.002": ("OS Credential Dumping: Security Account Manager", ["credential-access"]),
    "T1003.003": ("OS Credential Dumping: NTDS", ["credential-access"]),
    "T1003.004": ("OS Credential Dumping: LSA Secrets", ["credential-access"]),
    "T1003.006": ("OS Credential Dumping: DCSync", ["credential-access"]),
    "T1012": ("Query Registry", ["discovery"]),
    "T1021": ("Remote Services", ["lateral-movement"]),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", ["lateral-movement"]),
    "T1021.003": ("Remote Services: Distributed Component Object Model", ["lateral-movement"]),
    "T1021.006": ("Remote Services: Windows Remote Management", ["lateral-movement"]),
    "T1037": ("Boot or Logon Initialization Scripts", ["persistence", "privilege-escalation"]),
    "T1037.001": ("Logon Script (Windows)", ["persistence", "privilege-escalation"]),
    "T1047": ("Windows Management Instrumentation", ["execution"]),
    "T1049": ("System Network Connections Discovery", ["discovery"]),
    "T1053": ("Scheduled Task/Job", ["execution", "persistence", "privilege-escalation"]),
    "T1053.005": (
        "Scheduled Task/Job: Scheduled Task",
        ["execution", "persistence", "privilege-escalation"],
    ),
    "T1055": ("Process Injection", ["defense-evasion", "privilege-escalation"]),
    "T1055.001": (
        "Process Injection: Dynamic-link Library Injection",
        ["defense-evasion", "privilege-escalation"],
    ),
    "T1055.002": (
        "Process Injection: Portable Executable Injection",
        ["defense-evasion", "privilege-escalation"],
    ),
    "T1055.003": (
        "Process Injection: Thread Execution Hijacking",
        ["defense-evasion", "privilege-escalation"],
    ),
    "T1056": ("Input Capture", ["collection", "credential-access"]),
    "T1056.002": ("Input Capture: GUI Input Capture", ["collection", "credential-access"]),
    "T1057": ("Process Discovery", ["discovery"]),
    "T1059": ("Command and Scripting Interpreter", ["execution"]),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", ["execution"]),
    "T1059.005": ("Command and Scripting Interpreter: Visual Basic", ["execution"]),
    "T1069": ("Permission Groups Discovery", ["discovery"]),
    "T1069.001": ("Permission Groups Discovery: Local Groups", ["discovery"]),
    "T1069.002": ("Permission Groups Discovery: Domain Groups", ["discovery"]),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", ["defense-evasion"]),
    "T1087": ("Account Discovery", ["discovery"]),
    "T1087.001": ("Account Discovery: Local Account", ["discovery"]),
    "T1087.002": ("Account Discovery: Domain Account", ["discovery"]),
    "T1110": ("Brute Force", ["credential-access"]),
    "T1110.003": ("Brute Force: Password Spraying", ["credential-access"]),
    "T1112": ("Modify Registry", ["defense-evasion"]),
    "T1123": ("Audio Capture", ["collection"]),
    "T1135": ("Network Share Discovery", ["discovery"]),
    "T1136.001": ("Create Account: Local Account", ["persistence"]),
    "T1197": ("BITS Jobs", ["defense-evasion", "persistence"]),
    "T1210": ("Exploitation of Remote Services", ["lateral-movement"]),
    "T1218": ("System Binary Proxy Execution", ["defense-evasion"]),
    "T1218.001": ("System Binary Proxy Execution: Compiled HTML File", ["defense-evasion"]),
    "T1218.002": ("System Binary Proxy Execution: Control Panel", ["defense-evasion"]),
    "T1218.003": ("System Binary Proxy Execution: CMSTP", ["defense-evasion"]),
    "T1218.004": ("System Binary Proxy Execution: InstallUtil", ["defense-evasion"]),
    "T1218.005": ("System Binary Proxy Execution: Mshta", ["defense-evasion"]),
    "T1218.010": ("System Binary Proxy Execution: Regsvr32", ["defense-evasion"]),
    "T1220": ("XSL Script Processing", ["defense-evasion"]),
    "T1222": ("File and Directory Permissions Modification", ["defense-evasion"]),
    "T1222.001": ("Windows File and Directory Permissions Modification", ["defense-evasion"]),
    "T1505": ("Server Software Component", ["persistence"]),
    "T1505.003": ("Server Software Component: Web Shell", ["persistence"]),
    "T1518": ("Software Discovery", ["discovery"]),
    "T1543": ("Create or Modify System Process", ["persistence", "privilege-escalation"]),
    "T1543.003": (
        "Create or Modify System Process: Windows Service",
        ["persistence", "privilege-escalation"],
    ),
    "T1546": ("Event Triggered Execution", ["persistence", "privilege-escalation"]),
    "T1546.003": (
        "Event Triggered Execution: WMI Event Subscription",
        ["persistence", "privilege-escalation"],
    ),
    "T1547": ("Boot or Logon Autostart Execution", ["persistence", "privilege-escalation"]),
    "T1547.001": ("Registry Run Keys / Startup Folder", ["persistence", "privilege-escalation"]),
    "T1548": ("Abuse Elevation Control Mechanism", ["privilege-escalation", "defense-evasion"]),
    "T1548.002": (
        "Abuse Elevation Control Mechanism: Bypass User Account Control",
        ["privilege-escalation", "defense-evasion"],
    ),
    "T1550": ("Use Alternate Authentication Material", ["defense-evasion", "lateral-movement"]),
    "T1550.002": (
        "Use Alternate Authentication Material: Pass the Hash",
        ["defense-evasion", "lateral-movement"],
    ),
    "T1558": ("Steal or Forge Kerberos Tickets", ["credential-access"]),
    "T1558.003": ("Steal or Forge Kerberos Tickets: Kerberoasting", ["credential-access"]),
    "T1562": ("Impair Defenses", ["defense-evasion"]),
    "T1562.002": ("Impair Defenses: Disable Windows Event Logging", ["defense-evasion"]),
    "T1562.004": ("Impair Defenses: Disable or Modify System Firewall", ["defense-evasion"]),
    "T1574": ("Hijack Execution Flow", ["persistence", "privilege-escalation", "defense-evasion"]),
    "T1574.001": (
        "Hijack Execution Flow: DLL Search Order Hijacking",
        ["persistence", "privilege-escalation", "defense-evasion"],
    ),
}


def parent(technique: str) -> str:
    """Return the parent technique id of a sub-technique (``T1003.001`` -> ``T1003``)."""
    return technique.split(".", 1)[0]


def with_parents(techniques: set[str]) -> set[str]:
    """Expand a set of technique ids to also contain their parent techniques."""
    return techniques | {parent(t) for t in techniques}


def is_known(technique: str) -> bool:
    return technique in TECHNIQUES


def tactics_for(technique: str) -> list[str]:
    return TECHNIQUES[technique][1] if technique in TECHNIQUES else []


def name_for(technique: str) -> str:
    return TECHNIQUES[technique][0] if technique in TECHNIQUES else technique
