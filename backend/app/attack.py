"""event_type -> MITRE ATT&CK tactic/technique (docs/prep/03-attack-mapping.md)."""
from __future__ import annotations

# event_type: (tactic, technique id, technique name)
ATTACK_TABLE: dict[str, tuple[str, str, str]] = {
    "email_attachment_macro": ("Initial Access", "T1566.001", "Phishing: Spearphishing Attachment"),
    "email_link_suspicious": ("Initial Access", "T1566.002", "Phishing: Spearphishing Link"),
    "office_spawn_shell": ("Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "encoded_powershell": ("Execution", "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    "outbound_new_domain": ("Command and Control", "T1071.001", "Application Layer Protocol: Web Protocols"),
    "scheduled_task_created": ("Persistence", "T1053.005", "Scheduled Task/Job: Scheduled Task"),
    "registry_run_key": ("Persistence", "T1547.001", "Boot or Logon Autostart: Registry Run Keys"),
    "auth_spray": ("Credential Access", "T1110.003", "Brute Force: Password Spraying"),
    "lateral_logon_new_source": ("Lateral Movement", "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    "domain_discovery": ("Discovery", "T1087.002", "Account Discovery: Domain Account"),
    "shadow_copy_delete": ("Impact", "T1490", "Inhibit System Recovery"),
    "mass_file_rename": ("Impact", "T1486", "Data Encrypted for Impact"),
}

# Known-benign event types: never scored, never grouped with technique alerts.
NOISE_TYPES = frozenset({"auth_failed", "vuln_scan", "av_cleaned", "system_update"})

# ATT&CK Enterprise kill-chain order, used to sort tactics and draw the chain.
TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]

IMPACT_TECHNIQUES = frozenset({"T1490", "T1486"})


def lookup(event_type: str) -> tuple[str | None, str | None]:
    """(tactic, technique) for an event_type, or (None, None) for noise/unknown."""
    tactic, technique, _ = ATTACK_TABLE.get(event_type, (None, None, None))
    return tactic, technique


def is_noise(event_type: str) -> bool:
    return event_type in NOISE_TYPES


def has_technique(event_type: str) -> bool:
    return event_type in ATTACK_TABLE


def sort_tactics(tactics) -> list[str]:
    return sorted(set(tactics), key=TACTIC_ORDER.index)
