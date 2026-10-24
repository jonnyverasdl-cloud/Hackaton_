import json
import random
from datetime import datetime
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

from backend.app import attack, scoring
from backend.app.correlator import build_incidents, correlate
from backend.app.normalizer import normalize
from tools.gen_scenario import build_scenario

SCHEMA = json.loads(
    (Path(__file__).parent.parent / "contracts" / "incident.schema.json").read_text(encoding="utf-8")
)
EXPECTED_EVENT_TYPES = {
    "A1": "email_attachment_macro", "A2": "office_spawn_shell", "A3": "outbound_new_domain",
    "A4": "scheduled_task_created", "A5": "auth_spray", "A6": "lateral_logon_new_source",
    "A7": "domain_discovery", "A8": "shadow_copy_delete",
}


def validator(name):
    return Draft202012Validator({**SCHEMA, "$ref": f"#/$defs/{name}"}, format_checker=FormatChecker())


@pytest.fixture(scope="module")
def raw():
    return build_scenario()


@pytest.fixture(scope="module")
def truth(raw):
    return {r["id"]: r["_truth"] for r in raw}


@pytest.fixture(scope="module")
def alerts(raw):
    return [normalize(r) for r in raw]


@pytest.fixture(scope="module")
def by_step(raw, alerts):
    return {r["_truth"]["step"]: a for r, a in zip(raw, alerts) if r["_truth"]["attack"]}


@pytest.fixture(scope="module")
def incidents(alerts):
    return build_incidents(alerts)


@pytest.fixture(scope="module")
def attack_ids(truth):
    return {i for i, t in truth.items() if t["attack"]}


@pytest.fixture(scope="module")
def attack_incident(incidents, attack_ids):
    matches = [inc for inc in incidents if attack_ids & set(inc["alerts"])]
    assert len(matches) == 1, "attack alerts are split across incidents"
    return matches[0]


def ids_where(truth, **match):
    return {i for i, t in truth.items() if all(t.get(k) == v for k, v in match.items())}


# --- normalizer --------------------------------------------------------------

def test_normalized_alerts_match_schema_and_hide_truth(alerts):
    v = validator("alert")
    for a in alerts:
        v.validate(a)
        assert "_truth" not in a["raw"]


def test_attack_event_types(by_step):
    assert {step: a["event_type"] for step, a in by_step.items()} == EXPECTED_EVENT_TYPES


def test_noise_never_gets_a_technique(raw, alerts):
    for r, a in zip(raw, alerts):
        if not r["_truth"]["attack"]:
            assert not attack.has_technique(a["event_type"]), (r["id"], a["event_type"])


def test_audit7_email_recipient_maps_to_bare_user_and_host(by_step):
    a1 = by_step["A1"]
    assert a1["user"] == "maria.lopez"
    assert a1["host"] == "WS-FIN-07"
    assert a1["event_type"] == "email_attachment_macro"


def test_audit6_old_uncategorized_domain_is_not_c2(raw, alerts):
    news = [a for r, a in zip(raw, alerts) if r["_truth"].get("noise") == "proxy_uncategorized"]
    assert len(news) == 8 and all(a["event_type"] == "unknown" for a in news)


@pytest.mark.parametrize("age,category,expected", [
    (2, "uncategorized", "outbound_new_domain"),
    (2, "news", "unknown"),            # new but categorized
    (3000, "uncategorized", "unknown"),  # uncategorized but old
])
def test_audit6_c2_needs_new_and_uncategorized(age, category, expected):
    raw = {"id": "ALT-000900", "source": "proxy", "timestamp": "2026-10-24T14:00:00-06:00",
           "rule": "Web access", "client_host": "WS-X", "client_ip": "10.20.9.9",
           "dest_host": "x.example", "dest_ip": "203.0.113.9", "category": category,
           "domain_age_days": age}
    assert normalize(raw)["event_type"] == expected


def test_audit3_ids_host_is_scanner_not_target(raw, alerts):
    scans = [(r, a) for r, a in zip(raw, alerts) if r["_truth"].get("noise") == "vuln_scan"]
    assert len(scans) == 12
    for r, a in scans:
        assert a["host"] == "SCAN-01" and a["host"] != r["dst_host"]
        assert a["event_type"] == "vuln_scan"


def test_audit4_spray_targets_are_not_entities(by_step):
    a5 = by_step["A5"]
    assert a5["user"] is None and a5["host"] == "WS-FIN-07"
    assert len(a5["raw"]["target_accounts"]) == 12


def test_auth_host_rule(by_step):
    assert by_step["A5"]["host"] == "WS-FIN-07"     # failure/spray -> source host
    assert by_step["A6"]["host"] == "SRV-FILES-01"  # success -> target host
    assert by_step["A6"]["src_ip"] == "10.20.4.17"


# --- correlation on the scenario -------------------------------------------

def test_one_incident_with_all_8_attack_alerts_and_no_noise(attack_incident, attack_ids):
    assert set(attack_incident["alerts"]) == attack_ids
    assert len(attack_incident["alerts"]) == 8


def test_attack_incident_verdict_and_score(attack_incident):
    assert attack_incident["verdict"] == "malicious"
    assert 85 <= attack_incident["risk_score"] <= 95


def test_attack_incident_signal_breakdown(attack_incident):
    points = {s["name"]: s["points"] for s in attack_incident["signals"]}
    assert points == {
        "Kill chain depth": 30, "Impact stage reached": 15, "Lateral movement": 15,
        "Privileged / service account": 10, "C2 to new infrastructure": 5,
        "Credential access": 10, "Initial access confirmed": 5,
    }
    assert attack_incident["risk_score"] == sum(points.values()) == 90


def test_attack_incident_content(attack_incident):
    assert attack_incident["tactics_covered"] == [
        "Initial Access", "Execution", "Persistence", "Credential Access", "Discovery",
        "Lateral Movement", "Command and Control", "Impact"]
    ents = attack_incident["entities"]
    assert ents["hosts"] == ["WS-FIN-07", "SRV-FILES-01"]
    assert "cdn-update-sync.example" in ents["domains"]
    assert ents["ips"] == ["203.0.113.77"]
    rules = {r["rule"] for r in attack_incident["correlation_reasons"]}
    assert rules == {"same_host_window", "user_pivot"}
    assert any(r["detail"] == "svc_backup logon on SRV-FILES-01 originated from WS-FIN-07"
               for r in attack_incident["correlation_reasons"])
    times = [e["timestamp"] for e in attack_incident["timeline"]]
    assert times == sorted(times)
    assert attack_incident["title"].startswith("Pre-ransomware intrusion via phishing")


def test_audit4_no_noise_user_in_attack_incident(attack_incident):
    assert attack_incident["entities"]["users"] == ["maria.lopez", "svc_backup"]


def test_vuln_scan_is_its_own_benign_incident(incidents, truth):
    scan_ids = ids_where(truth, noise="vuln_scan")
    scan = [inc for inc in incidents if scan_ids & set(inc["alerts"])]
    assert len(scan) == 1
    inc = scan[0]
    assert set(inc["alerts"]) == scan_ids
    assert inc["verdict"] == "benign" and inc["risk_score"] <= 10
    assert inc["entities"]["hosts"] == ["SCAN-01"]  # audit #3: targets never become entities
    assert [r["rule"] for r in inc["correlation_reasons"]] == ["noise_isolation"]


def test_audit1_maria_trap_excluded_from_attack(attack_incident, truth, by_step, alerts):
    trap = ids_where(truth, trap="maria_early_failed_logon")
    assert len(trap) == 2
    # Precondition: the trap really is inside A1's same-host 30-min window.
    by_id = {a["alert_id"]: a for a in alerts}
    a1_time = datetime.fromisoformat(by_step["A1"]["timestamp"])
    for i in trap:
        assert by_id[i]["host"] == by_step["A1"]["host"]
        assert (a1_time - datetime.fromisoformat(by_id[i]["timestamp"])).total_seconds() <= 30 * 60
    assert not trap & set(attack_incident["alerts"])
    assert not any(i in r["detail"] for r in attack_incident["correlation_reasons"] for i in trap)


def test_no_incident_mixes_noise_with_techniques(incidents, alerts):
    by_id = {a["alert_id"]: a for a in alerts}
    for inc in incidents:
        types = {by_id[i]["event_type"] for i in inc["alerts"]}
        if any(attack.has_technique(t) for t in types):
            assert not types & attack.NOISE_TYPES, inc["incident_id"]


def test_noise_only_incidents_are_benign(incidents, attack_incident):
    others = [inc for inc in incidents if inc is not attack_incident]
    assert others and all(inc["verdict"] == "benign" for inc in others)


def test_incidents_match_schema(incidents):
    v = validator("incident")
    for inc in incidents:
        v.validate(inc)


def test_input_order_does_not_matter(alerts, incidents):
    shuffled = list(alerts)
    random.Random(7).shuffle(shuffled)
    assert build_incidents(shuffled) == incidents


# --- rules on hand-built alerts ---------------------------------------------

def mk(alert_id, minute, event_type="unknown", **fields):
    alert = {"alert_id": f"ALT-{alert_id:06d}", "timestamp": f"2026-10-24T14:{minute:02d}:00-06:00",
             "source": "edr", "vendor_rule": "test", "host": None, "user": None, "src_ip": None,
             "dst_ip": None, "domain": None, "process": None, "parent_process": None,
             "event_type": event_type, "severity_raw": "low", "raw": {}}
    alert.update(fields)
    return alert


def rules_of(groups):
    return [{r["rule"] for r in g.reasons} for g in groups]


def test_audit1_auth_failed_never_joins_by_host():
    groups = correlate([mk(1, 0, "auth_failed", host="WS-A", user="u1"),
                        mk(2, 5, "office_spawn_shell", host="WS-A", user="u1")])
    assert [g.alert_ids for g in groups] == [["ALT-000002"]]


def test_same_host_window_respects_window():
    near = correlate([mk(1, 0, "office_spawn_shell", host="WS-A"), mk(2, 29, "scheduled_task_created", host="WS-A")])
    assert len(near) == 1 and rules_of(near) == [{"same_host_window"}]
    far = correlate([mk(1, 0, "office_spawn_shell", host="WS-A"), mk(2, 31, "scheduled_task_created", host="WS-A")])
    assert len(far) == 2


def test_shared_infra_joins_hosts():
    groups = correlate([mk(1, 0, "outbound_new_domain", host="WS-A", domain="bad.example", dst_ip="203.0.113.5"),
                        mk(2, 50, "unknown", host="WS-B", domain="bad.example")])
    assert len(groups) == 1 and rules_of(groups) == [{"shared_infra"}]
    assert groups[0].reasons[0]["detail"] == "WS-A and WS-B both contacted bad.example"


def test_same_user_window_needs_a_technique():
    with_tech = correlate([mk(1, 0, "office_spawn_shell", host="WS-A", user="u1"),
                           mk(2, 10, "unknown", host="WS-B", user="u1")])
    assert len(with_tech) == 1 and rules_of(with_tech) == [{"same_user_window"}]
    only_unknown = correlate([mk(1, 0, host="WS-A", user="u1"), mk(2, 10, host="WS-B", user="u1")])
    assert only_unknown == []  # two unrelated unknown singletons are not incidents
    too_late = correlate([mk(1, 0, "office_spawn_shell", host="WS-A", user="u1"),
                          mk(2, 16, "unknown", host="WS-B", user="u1")])
    assert len(too_late) == 1 and too_late[0].alert_ids == ["ALT-000001"]


def test_user_pivot_from_raw_source_host():
    groups = correlate([
        mk(1, 0, "office_spawn_shell", host="WS-A"),
        mk(2, 5, "lateral_logon_new_source", host="SRV-B", user="svc_x", source="auth",
           raw={"outcome": "success", "src_host": "WS-A"}),
    ])
    assert len(groups) == 1
    assert groups[0].reasons[0] == {"rule": "user_pivot", "detail": "svc_x logon on SRV-B originated from WS-A"}


def test_verdict_thresholds():
    assert scoring.verdict_for(70) == "malicious"
    assert scoring.verdict_for(69) == "suspicious"
    assert scoring.verdict_for(30) == "suspicious"
    assert scoring.verdict_for(29) == "benign"


def test_kill_chain_is_capped():
    alerts = [mk(i, i, t) for i, t in enumerate(EXPECTED_EVENT_TYPES.values(), start=1)]
    _, _, signals = scoring.score(alerts, [])
    assert next(s for s in signals if s["name"] == "Kill chain depth")["points"] == 30


def test_privileged_service_account_in_noise_scores_nothing():
    risk, verdict, signals = scoring.score([mk(1, 0, "vuln_scan", host="SCAN-01", user="svc_nessus")], [])
    assert (risk, verdict, signals) == (0, "benign", [])
