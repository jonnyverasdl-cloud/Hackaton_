"""Raw vendor alert -> normalized alert (docs/prep/02-esquema.md) with an event_type.

event_type rules follow docs/prep/03-attack-mapping.md. Anything unrecognized is
"unknown": it scores nothing but can still be grouped by entity.
"""
from __future__ import annotations

import ipaddress
import re

KNOWN_SCANNER_HOSTS = frozenset({"SCAN-01"})
KNOWN_SCANNER_ACCOUNTS = frozenset({"svc_nessus"})

OFFICE_APPS = frozenset({"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"})
SHELLS = frozenset({"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"})
MACRO_EXTENSIONS = (".docm", ".xlsm", ".pptm", ".js", ".vbs", ".hta")
UPDATE_PROCESSES = frozenset({"tiworker.exe", "wuauclt.exe", "trustedinstaller.exe", "shutdown.exe",
                              "usoclient.exe", "musnotification.exe"})
SEVERITIES = ("info", "low", "medium", "high", "critical")

NEW_DOMAIN_DAYS = 30
SPRAY_MIN_FAILURES = 20
SPRAY_MIN_ACCOUNTS = 5
SPRAY_MAX_SECONDS = 300

_ENCODED_PS = re.compile(r"(\s-e(nc(odedcommand)?)?\s)|frombase64string", re.IGNORECASE)
_DISCOVERY = re.compile(r"\bnet1?(\.exe)?\s+(group|user)\b.*\/domain|\bnltest\b", re.IGNORECASE)
_SHADOW_DELETE = re.compile(
    r"vssadmin(\.exe)?\s+delete\s+shadows|wbadmin(\.exe)?\s+delete|bcdedit.*recoveryenabled\s+no",
    re.IGNORECASE,
)
_RUN_KEY = re.compile(r"\\currentversion\\run(once)?\b", re.IGNORECASE)


INTERNAL_NETWORKS = tuple(ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


def is_internal_ip(ip: str | None) -> bool:
    """RFC 1918 only. ipaddress.is_private would also count 203.0.113.0/24 (our 'external' range)."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in INTERNAL_NETWORKS)


def _below(value, limit) -> bool:
    """value < limit, where a missing value never qualifies (0 does)."""
    return value is not None and value < limit


def _lower(value) -> str:
    return (value or "").lower()


def _edr(raw: dict) -> dict:
    process, parent = _lower(raw.get("process")), _lower(raw.get("parent_process"))
    cmd = raw.get("command_line") or ""
    if _SHADOW_DELETE.search(cmd):
        event_type = "shadow_copy_delete"
    elif _DISCOVERY.search(cmd):
        event_type = "domain_discovery"
    elif (raw.get("renamed_files") or 0) > 100:
        event_type = "mass_file_rename"
    elif parent in OFFICE_APPS and process in SHELLS:
        event_type = "office_spawn_shell"
    elif process in {"powershell.exe", "pwsh.exe"} and _ENCODED_PS.search(f" {cmd} "):
        event_type = "encoded_powershell"
    elif process == "schtasks.exe" or raw.get("task_name"):
        event_type = "scheduled_task_created"
    elif _RUN_KEY.search(cmd) or _RUN_KEY.search(raw.get("registry_key") or ""):
        event_type = "registry_run_key"
    elif raw.get("action_taken") == "cleaned":
        event_type = "av_cleaned"
    elif raw.get("signed") and _lower(raw.get("signer")).startswith("microsoft") and process in UPDATE_PROCESSES:
        event_type = "system_update"
    else:
        event_type = "unknown"
    return {
        "host": raw.get("device"), "user": raw.get("account"), "src_ip": raw.get("device_ip"),
        "process": raw.get("process"), "parent_process": raw.get("parent_process"),
        "event_type": event_type,
    }


def _proxy(raw: dict) -> dict:
    age = raw.get("domain_age_days")
    new_and_uncategorized = (
        age is not None and age < NEW_DOMAIN_DAYS
        and _lower(raw.get("category")) == "uncategorized"
        and is_internal_ip(raw.get("client_ip"))
    )
    return {
        "host": raw.get("client_host"), "user": raw.get("user"), "src_ip": raw.get("client_ip"),
        "dst_ip": raw.get("dest_ip"), "domain": raw.get("dest_host"),
        "event_type": "outbound_new_domain" if new_and_uncategorized else "unknown",
    }


def _auth(raw: dict) -> dict:
    # Auth host rule: success belongs to the target host, failure to the source host.
    if raw.get("outcome") == "success":
        lateral = raw.get("first_seen_source") and raw.get("logon_type") in (3, 10)
        return {
            "host": raw.get("target_host"), "user": raw.get("account"), "src_ip": raw.get("src_ip"),
            "event_type": "lateral_logon_new_source" if lateral else "unknown",
        }
    spray = (
        (raw.get("failure_count") or 0) >= SPRAY_MIN_FAILURES
        and (raw.get("distinct_accounts") or 0) >= SPRAY_MIN_ACCOUNTS
        and _below(raw.get("window_seconds"), SPRAY_MAX_SECONDS + 1)
    )
    # A spray has many target accounts: they stay in raw, never as the alert's user.
    return {
        "host": raw.get("src_host"), "user": None if spray else raw.get("account"),
        "src_ip": raw.get("src_ip"),
        "event_type": "auth_spray" if spray else "auth_failed",
    }


def _email(raw: dict) -> dict:
    recipient, sender = raw.get("recipient") or "", raw.get("sender") or ""
    attachment = _lower(raw.get("attachment"))
    if attachment.endswith(MACRO_EXTENSIONS):
        event_type = "email_attachment_macro"
    elif raw.get("url") and _below(raw.get("url_domain_age_days"), NEW_DOMAIN_DAYS):
        event_type = "email_link_suspicious"
    else:
        event_type = "unknown"
    return {
        "host": raw.get("recipient_host"),
        "user": recipient.split("@")[0] or None,
        "domain": sender.split("@")[1] if "@" in sender else None,
        "event_type": event_type,
    }


def _ids(raw: dict) -> dict:
    # The IDS alert belongs to the scanning host, never to the scanned target.
    scanner = raw.get("src_host") in KNOWN_SCANNER_HOSTS or raw.get("account") in KNOWN_SCANNER_ACCOUNTS
    return {
        "host": raw.get("src_host"), "user": raw.get("account"),
        "src_ip": raw.get("src_ip"), "dst_ip": raw.get("dst_ip"),
        "event_type": "vuln_scan" if scanner else "unknown",
    }


_BY_SOURCE = {"edr": _edr, "proxy": _proxy, "auth": _auth, "email_gateway": _email, "ids": _ids}


def normalize(raw: dict, alert_id: str | None = None) -> dict:
    """Map one raw alert to the normalized schema. `alert_id` overrides raw["id"]."""
    source = raw.get("source")
    if source not in _BY_SOURCE:
        raise ValueError(f"unknown alert source: {source!r}")
    severity = _lower(raw.get("severity"))
    alert = {
        "alert_id": alert_id or raw.get("id"),
        "timestamp": raw["timestamp"],
        "source": source,
        "vendor_rule": raw.get("rule") or "",
        "host": None, "user": None, "src_ip": None, "dst_ip": None, "domain": None,
        "process": None, "parent_process": None,
        "event_type": "unknown",
        "severity_raw": severity if severity in SEVERITIES else "info",
        # Hidden keys (e.g. test ground truth "_truth") never reach the normalized alert.
        "raw": {k: v for k, v in raw.items() if not k.startswith("_")},
    }
    alert.update(_BY_SOURCE[source](raw))
    if not alert["alert_id"]:
        raise ValueError("alert has no id")
    return alert
