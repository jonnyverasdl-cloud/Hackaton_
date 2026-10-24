"""Deterministic correlation: normalized alerts -> incidents (docs/prep/03-attack-mapping.md).

Union-find over alerts. Each rule links pairs of alerts and records why; the
connected components are the incidents. Rules:

  same_host_window  same host, dt <= window, both alerts carry a technique
                    (noise such as isolated auth_failed, and "unknown", never join by host)
  user_pivot        successful logon on host B whose source is host A -> joins B to
                    technique alerts on A within the window before the logon
  shared_infra      same external domain or IP contacted from >= 2 hosts
  same_user_window  same user on different hosts, dt <= 15 min, >= 1 technique alert
  noise_isolation   noise alerts group only with the same noise type on the same host

A component becomes an incident if it has a technique alert or >= 2 alerts.
"""
from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import attack, scoring
from .normalizer import KNOWN_SCANNER_HOSTS, is_internal_ip

SAME_USER_WINDOW_MIN = 15


def default_window_min() -> int:
    return int(os.getenv("CORRELATION_WINDOW_MIN", "30"))


@dataclass
class Group:
    alert_ids: list[str]
    reasons: list[dict] = field(default_factory=list)


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _ts(alert: dict) -> datetime:
    return datetime.fromisoformat(alert["timestamp"])


def _host_by_ip(alerts: list[dict]) -> dict[str, str]:
    """Internal IP -> host, learned from alerts whose src_ip is the host's own address."""
    out = {}
    for a in alerts:
        own_ip = not (a["source"] == "auth" and a["raw"].get("outcome") == "success")
        if own_ip and a["host"] and is_internal_ip(a["src_ip"]):
            out.setdefault(a["src_ip"], a["host"])
    return out


def _external_indicators(alert: dict) -> set[str]:
    out = set()
    if alert["domain"]:
        out.add(f"domain:{alert['domain']}")
    if alert["dst_ip"] and not is_internal_ip(alert["dst_ip"]):
        out.add(f"ip:{alert['dst_ip']}")
    return out


def correlate(alerts: list[dict], window_min: int | None = None) -> list[Group]:
    """Group normalized alerts. Output order and content do not depend on input order."""
    window = timedelta(minutes=window_min if window_min is not None else default_window_min())
    user_window = timedelta(minutes=SAME_USER_WINDOW_MIN)
    alerts = sorted(alerts, key=lambda a: (_ts(a), a["alert_id"]))
    uf = _UnionFind()
    links: list[tuple[tuple, str, str]] = []  # (rule, key...), alert id, alert id

    def link(rule_key: tuple, a: dict, b: dict) -> None:
        uf.union(a["alert_id"], b["alert_id"])
        links.append((rule_key, a["alert_id"], b["alert_id"]))

    for a in alerts:
        uf.find(a["alert_id"])

    for i, a in enumerate(alerts):
        a_noise = attack.is_noise(a["event_type"])
        for b in alerts[i + 1:]:
            dt = _ts(b) - _ts(a)
            b_noise = attack.is_noise(b["event_type"])
            same_host = a["host"] and a["host"] == b["host"]
            if a_noise or b_noise:
                if (a_noise and b_noise and same_host and dt <= window
                        and a["event_type"] == b["event_type"]):
                    link(("noise_isolation", a["event_type"], a["host"]), a, b)
                continue
            # Host alone only joins technique alerts; "unknown" joins by user or infra.
            both_techniques = attack.has_technique(a["event_type"]) and attack.has_technique(b["event_type"])
            if same_host and dt <= window and both_techniques:
                link(("same_host_window", a["host"]), a, b)
            if a["host"] != b["host"]:
                for ind in sorted(_external_indicators(a) & _external_indicators(b)):
                    link(("shared_infra", ind), a, b)
                if (a["user"] and a["user"] == b["user"] and dt <= user_window
                        and (attack.has_technique(a["event_type"]) or attack.has_technique(b["event_type"]))):
                    link(("same_user_window", a["user"]), a, b)

    host_by_ip = _host_by_ip(alerts)
    for a in alerts:
        if a["event_type"] != "lateral_logon_new_source":
            continue
        origin = host_by_ip.get(a["src_ip"]) or a["raw"].get("src_host")
        if not origin or origin == a["host"]:
            continue
        for b in alerts:
            if (b is not a and b["host"] == origin and timedelta(0) <= _ts(a) - _ts(b) <= window
                    and attack.has_technique(b["event_type"])):
                link(("user_pivot", a["user"], a["host"], origin), b, a)

    by_id = {a["alert_id"]: a for a in alerts}
    members: dict[str, list[str]] = defaultdict(list)
    for a in alerts:
        members[uf.find(a["alert_id"])].append(a["alert_id"])
    # One reason per (component, rule key): a host with two separate incidents gets two reasons.
    linked: dict[tuple, set[str]] = defaultdict(set)
    for rule_key, x, y in links:
        linked[(uf.find(x), rule_key)].update((x, y))
    reasons_by_root: dict[str, list[dict]] = defaultdict(list)
    for (root, rule_key), ids in sorted(linked.items(),
                                        key=lambda kv: (min(_ts(by_id[x]) for x in kv[1]), str(kv[0][1]))):
        reasons_by_root[root].append(_reason(rule_key, [by_id[x] for x in ids], window))

    groups = []
    for root, ids in members.items():
        if len(ids) >= 2 or any(attack.has_technique(by_id[x]["event_type"]) for x in ids):
            groups.append(Group(alert_ids=ids, reasons=reasons_by_root[root]))
    groups.sort(key=lambda g: (_ts(by_id[g.alert_ids[0]]), g.alert_ids[0]))
    return groups


def _span(alerts: list[dict]) -> str:
    times = sorted(_ts(a) for a in alerts)
    return f"{times[0]:%H:%M}-{times[-1]:%H:%M}"


def _reason(rule_key: tuple, alerts: list[dict], window: timedelta) -> dict:
    rule = rule_key[0]
    minutes = int(window.total_seconds() // 60)
    if rule == "same_host_window":
        detail = f"{len(alerts)} alerts share host {rule_key[1]} within {minutes} min ({_span(alerts)})"
    elif rule == "user_pivot":
        _, user, host, origin = rule_key
        detail = f"{user} logon on {host} originated from {origin}"
    elif rule == "shared_infra":
        hosts = sorted({a["host"] for a in alerts if a["host"]})
        detail = f"{' and '.join(hosts)} both contacted {rule_key[1].split(':', 1)[1]}"
    elif rule == "same_user_window":
        hosts = sorted({a["host"] for a in alerts if a["host"]})
        detail = f"same user {rule_key[1]} across hosts {', '.join(hosts)} within {SAME_USER_WINDOW_MIN} min"
    else:  # noise_isolation
        _, event_type, host = rule_key
        known = " (known scanner)" if host in KNOWN_SCANNER_HOSTS else ""
        detail = (f"{len(alerts)} {event_type} alerts from {host}{known} grouped apart "
                  f"from technique alerts ({_span(alerts)})")
    return {"rule": rule, "detail": detail}


# --- incident assembly -------------------------------------------------------

def summarize(alert: dict) -> str:
    """One-line, fact-only timeline text built from the alert's own fields."""
    r, t = alert["raw"], alert["event_type"]
    host, user = alert["host"] or "unknown host", alert["user"] or "unknown user"
    if t == "email_attachment_macro":
        return f"Macro-enabled attachment {r.get('attachment')} from {r.get('sender')} delivered to {user}"
    if t in ("office_spawn_shell", "encoded_powershell"):
        encoded = " with an encoded command" if "-enc" in (r.get("command_line") or "") else ""
        return f"{alert['parent_process']} spawned {alert['process']}{encoded} on {host}"
    if t == "outbound_new_domain":
        return (f"{host} connected to {alert['domain']} ({alert['dst_ip']}), "
                f"domain registered {r.get('domain_age_days')} days ago")
    if t == "scheduled_task_created":
        return f"Scheduled task {r.get('task_name')} created on {host} pointing to {r.get('file_path')}"
    if t == "auth_spray":
        return (f"{r.get('failure_count')} failed logons from {host} against "
                f"{r.get('distinct_accounts')} accounts in {r.get('window_seconds')} s")
    if t == "lateral_logon_new_source":
        return f"{user} logged on to {host} from {r.get('src_host') or alert['src_ip']} for the first time"
    if t in ("domain_discovery", "shadow_copy_delete"):
        return f"{user} ran `{r.get('command_line')}` on {host}"
    return f"{alert['vendor_rule']} on {host}" + (f" ({alert['user']})" if alert["user"] else "")


NOISE_TITLES = {
    "vuln_scan": "Scheduled vulnerability scan from {host}",
    "auth_failed": "Isolated failed logons on {host}",
    "av_cleaned": "Remediated antivirus detection on {host}",
    "system_update": "Windows Update activity on {host}",
}


def _title(alerts: list[dict], tactics: list[str], hosts: list[str]) -> str:
    types = {a["event_type"] for a in alerts}
    if not tactics:
        noise = sorted(types & attack.NOISE_TYPES)
        if len(noise) == 1:
            return NOISE_TITLES[noise[0]].format(host=hosts[0] if hosts else "unknown host")
        return f"Uncorrelated low-risk activity on {', '.join(hosts) or 'unknown host'}"
    if "Impact" in tactics and len(tactics) >= 3:
        kind = "Pre-ransomware intrusion"
    elif len(tactics) >= 3:
        kind = "Multi-stage intrusion"
    else:
        kind = f"{tactics[0]} activity"
    via = " via phishing" if any(t.startswith("email_") for t in types) else ""
    return f"{kind}{via} on {' and '.join(hosts[:2])}" + (f" (+{len(hosts) - 2} more)" if len(hosts) > 2 else "")


def _unique(values) -> list:
    return list(dict.fromkeys(v for v in values if v))


def build_incident(group: Group, by_id: dict[str, dict], incident_id: str) -> dict:
    alerts = sorted((by_id[x] for x in group.alert_ids), key=lambda a: (_ts(a), a["alert_id"]))
    timeline = []
    for a in alerts:
        tactic, technique = attack.lookup(a["event_type"])
        timeline.append({"timestamp": a["timestamp"], "alert_id": a["alert_id"], "technique": technique,
                         "tactic": tactic, "summary": summarize(a)})
    tactics = attack.sort_tactics(e["tactic"] for e in timeline if e["tactic"])
    hosts = _unique(a["host"] for a in alerts)
    risk, verdict, signals = scoring.score(alerts, group.reasons)
    return {
        "incident_id": incident_id,
        "status": "open",
        "verdict": verdict,
        "risk_score": risk,
        "title": _title(alerts, tactics, hosts),
        "window": {"start": alerts[0]["timestamp"], "end": alerts[-1]["timestamp"]},
        "entities": {
            "hosts": hosts,
            "users": _unique(a["user"] for a in alerts),
            "domains": _unique(a["domain"] for a in alerts),
            "ips": _unique(ip for a in alerts for ip in (a["src_ip"], a["dst_ip"])
                           if ip and not is_internal_ip(ip)),
        },
        "alerts": [a["alert_id"] for a in alerts],
        "timeline": timeline,
        "tactics_covered": tactics,
        "correlation_reasons": group.reasons,
        "signals": signals,
        "ai": None,
        "autonomy": scoring.autonomy_for(verdict),
        "actions": [],
        "approved_by": None,
        "approved_at": None,
    }


def build_incidents(alerts: list[dict], window_min: int | None = None) -> list[dict]:
    """Correlate and assemble incidents, numbered INC-0001.. by first alert time."""
    by_id = {a["alert_id"]: a for a in alerts}
    return [build_incident(g, by_id, f"INC-{i:04d}")
            for i, g in enumerate(correlate(alerts, window_min), start=1)]
