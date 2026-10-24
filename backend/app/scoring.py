"""Incident signals -> risk_score and verdict (docs/prep/03-attack-mapping.md, weights of 2026-10-24).

Kill chain 5/tactic (max 30), impact 15, lateral 15, privileged 10, C2 5,
credential access 10, initial access 5. The demo attack scores 90.
Thresholds: malicious >= 70, suspicious 30-69, benign < 30.
"""
from __future__ import annotations

from . import attack

POINTS_PER_TACTIC = 5
MAX_KILL_CHAIN = 30
IMPACT_POINTS = 15
LATERAL_POINTS = 15
PRIVILEGED_POINTS = 10
C2_POINTS = 5
CREDENTIAL_POINTS = 10
INITIAL_ACCESS_POINTS = 5

MALICIOUS_AT = 70
SUSPICIOUS_AT = 30

ADMIN_USERS = frozenset({"administrator", "admin.ops"})
LATERAL_RULES = frozenset({"user_pivot", "shared_infra"})

AUTONOMY_BY_VERDICT = {
    "benign": "auto_closed",
    "suspicious": "auto_contained",
    "malicious": "awaiting_approval",
}


def is_privileged(user: str | None) -> bool:
    return bool(user) and (user.startswith("svc_") or user in ADMIN_USERS)


def verdict_for(score: int) -> str:
    if score >= MALICIOUS_AT:
        return "malicious"
    if score >= SUSPICIOUS_AT:
        return "suspicious"
    return "benign"


def score(alerts: list[dict], reasons: list[dict]) -> tuple[int, str, list[dict]]:
    """Return (risk_score, verdict, signals). Noise alerts never add points."""
    signal_alerts = [a for a in alerts if not attack.is_noise(a["event_type"])]
    event_types = {a["event_type"] for a in signal_alerts}
    techniques = {attack.lookup(t)[1] for t in event_types} - {None}
    tactics = attack.sort_tactics(attack.lookup(t)[0] for t in event_types if attack.has_technique(t))
    signals = []

    def add(name: str, detail: str, points: int) -> None:
        signals.append({"name": name, "detail": detail, "points": points})

    if tactics:
        add("Kill chain depth", f"{len(tactics)} tactics covered",
            min(len(tactics) * POINTS_PER_TACTIC, MAX_KILL_CHAIN))
    impact = sorted(techniques & attack.IMPACT_TECHNIQUES)
    if impact:
        add("Impact stage reached", ", ".join(impact), IMPACT_POINTS)
    lateral = [r for r in reasons if r["rule"] in LATERAL_RULES]
    hosts = {a["host"] for a in alerts if a["host"]}
    if lateral and len(hosts) >= 2:
        add("Lateral movement", lateral[0]["detail"], LATERAL_POINTS)
    privileged = sorted({a["user"] for a in signal_alerts if is_privileged(a["user"])})
    if privileged:
        add("Privileged / service account", ", ".join(privileged), PRIVILEGED_POINTS)
    if "outbound_new_domain" in event_types:
        domains = sorted({a["domain"] for a in signal_alerts
                          if a["event_type"] == "outbound_new_domain" and a["domain"]})
        add("C2 to new infrastructure", ", ".join(domains) or "newly registered domain", C2_POINTS)
    if "auth_spray" in event_types:
        add("Credential access", "password spraying (T1110.003)", CREDENTIAL_POINTS)
    initial = sorted(t for t in techniques if t.startswith("T1566"))
    if initial:
        add("Initial access confirmed", ", ".join(initial), INITIAL_ACCESS_POINTS)

    total = min(100, sum(s["points"] for s in signals))
    return total, verdict_for(total), signals


def autonomy_for(verdict: str) -> str:
    return AUTONOMY_BY_VERDICT[verdict]
