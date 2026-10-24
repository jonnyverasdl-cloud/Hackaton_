import json
from collections import Counter
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator, FormatChecker

from backend.app import actions
from backend.app.main import create_app
from backend.app.store import Store
from tools import gen_scenario as gs

SCHEMA = json.loads(
    (Path(__file__).parent.parent / "contracts" / "incident.schema.json").read_text(encoding="utf-8")
)
INCIDENT_SCHEMA = Draft202012Validator({**SCHEMA, "$ref": "#/$defs/incident"}, format_checker=FormatChecker())
RAW = gs.build_scenario()
ATTACK_IDS = {r["id"] for r in RAW if r["_truth"]["attack"]}
SCAN_IDS = {r["id"] for r in RAW if r["_truth"].get("noise") == "vuln_scan"}
TRAP_IDS = {r["id"] for r in RAW if r["_truth"].get("trap")}


def new_client():
    return TestClient(create_app(Store(window_min=30)))


def replay(client, alerts=RAW):
    return gs.replay(alerts, "http://testserver", speed=0, client=client, sleep=lambda s: None)


@pytest.fixture(scope="module")
def client():
    c = new_client()
    replay(c)
    return c


def full(client, incident_id):
    r = client.get(f"/incidents/{incident_id}")
    assert r.status_code == 200
    return r.json()


def incident_with(client, alert_ids):
    hits = [s for s in client.get("/incidents").json()
            if alert_ids & set(full(client, s["incident_id"])["alerts"])]
    assert len(hits) == 1
    return full(client, hits[0]["incident_id"])


def action(incident, action_id):
    return next(a for a in incident["actions"] if a["id"] == action_id)


# --- end-to-end replay ------------------------------------------------------

def test_replay_end_to_end_contract(client):
    summaries = client.get("/incidents").json()
    assert summaries
    for s in summaries:
        INCIDENT_SCHEMA.validate(full(client, s["incident_id"]))


def test_attack_incident_via_api(client):
    inc = incident_with(client, ATTACK_IDS)
    assert set(inc["alerts"]) == ATTACK_IDS
    assert inc["verdict"] == "malicious" and 85 <= inc["risk_score"] <= 95
    assert inc["autonomy"] == "awaiting_approval" and inc["status"] == "open"


def test_attack_block_domain_executed_by_system(client):
    a = action(incident_with(client, ATTACK_IDS), "block_domain")
    assert a["reversible"] is True and a["status"] == "executed" and a["executed_by"] == "system"
    assert a["executed_at"] and a["reason"]
    assert a["targets"] == ["cdn-update-sync.example", "203.0.113.77"]


def test_attack_irreversible_actions_pending(client):
    inc = incident_with(client, ATTACK_IDS)
    for action_id in ("isolate_host", "disable_account", "kill_process"):
        a = action(inc, action_id)
        assert a["reversible"] is False and a["status"] == "pending" and a["executed_by"] is None
        assert a["reason"] == "irreversible: requires analyst approval"
    assert action(inc, "isolate_host")["targets"] == ["WS-FIN-07", "SRV-FILES-01"]
    assert action(inc, "disable_account")["targets"] == ["svc_backup"]


def test_reversible_actions_cover_all_hosts(client):
    # Watchlist ran when only WS-FIN-07 was known; SRV-FILES-01 was added when it joined.
    inc = incident_with(client, ATTACK_IDS)
    assert action(inc, "watchlist_host")["targets"] == ["WS-FIN-07", "SRV-FILES-01"]
    assert action(inc, "watchlist_host")["label"] == "Add WS-FIN-07 and SRV-FILES-01 to watchlist (72 h)"


def test_scanner_incident_auto_closes(client):
    inc = incident_with(client, SCAN_IDS)
    assert set(inc["alerts"]) == SCAN_IDS
    assert inc["verdict"] == "benign" and inc["status"] == "closed" and inc["autonomy"] == "auto_closed"
    close = action(inc, "close_benign")
    assert close["status"] == "executed" and close["executed_by"] == "system"
    assert "known noise pattern" in close["reason"]


def test_maria_trap_is_its_own_closed_incident(client):
    inc = incident_with(client, TRAP_IDS)
    assert set(inc["alerts"]) == TRAP_IDS
    assert inc["status"] == "closed" and inc["verdict"] == "benign"


def test_every_system_action_is_audited_with_reason(client):
    entries = client.get("/audit").json()["entries"]
    system = [e for e in entries if e["executed_by"] == "system" and e["action"] in actions.CATALOG]
    assert system and all(e["reason"] for e in system)
    for s in client.get("/incidents").json():
        for a in full(client, s["incident_id"])["actions"]:
            if a["executed_by"] == "system":
                assert any(e["incident_id"] == s["incident_id"] and e["action"] == a["id"] for e in system)


def test_audit_counts_suppressed_noise(client):
    noise = client.get("/audit").json()["suppressed_noise"]
    assert noise["count"] == 22
    assert noise["by_type"] == {"unknown": 8, "auth_failed": 8, "system_update": 6}
    alerts = client.get("/alerts").json()
    assert sum(a["suppressed"] for a in alerts) == 22
    assert all(a["incident_id"] is None for a in alerts if a["suppressed"])
    assert all("_truth" not in a["raw"] for a in alerts)


def test_health_counts(client):
    h = client.get("/health").json()
    assert h["status"] == "ok" and h["synthetic"] is True
    assert h["counts"] == {"alerts": 50, "incidents": 5, "suppressed_noise": 22, "pending_approvals": 3}


# --- stable ids and idempotence (audit #1) ----------------------------------

def test_incident_ids_stable_when_replayed_alert_by_alert():
    c = new_client()
    seen: dict[str, str] = {}
    for raw in RAW:
        assert c.post("/alerts", json=gs.public_view(raw)).status_code == 201
        for a in c.get("/alerts").json():
            if a["incident_id"]:
                assert seen.setdefault(a["alert_id"], a["incident_id"]) == a["incident_id"], a["alert_id"]
    attack_ids = {seen[x] for x in ATTACK_IDS}
    assert len(attack_ids) == 1


def test_attack_never_auto_closed_while_forming():
    c = new_client()
    for raw in RAW:
        c.post("/alerts", json=gs.public_view(raw))
        for s in c.get("/incidents").json():
            inc = full(c, s["incident_id"])
            if ATTACK_IDS & set(inc["alerts"]):
                assert inc["status"] != "closed", (raw["id"], inc["risk_score"])


def _executions(entries):
    return [(e["incident_id"], e["action"], e["label"]) for e in entries if e["action"] in actions.CATALOG]


def test_no_action_executed_twice():
    c = new_client()
    replay(c)
    first = c.get("/audit").json()["entries"]
    assert len(set(_executions(first))) == len(_executions(first))
    replay(c)  # same ids again: all ignored
    assert c.get("/audit").json()["entries"] == first
    assert c.get("/health").json()["counts"]["alerts"] == 50


def test_store_merge_keeps_lowest_id():
    s = Store(window_min=30)
    base = {"source": "edr", "rule": "t", "device": None, "process": "cmd.exe", "parent_process": "WINWORD.EXE"}
    s.ingest({**base, "id": "ALT-000001", "timestamp": "2026-10-24T14:00:00-06:00", "device": "WS-A", "account": "u1"})
    s.ingest({**base, "id": "ALT-000002", "timestamp": "2026-10-24T14:01:00-06:00", "device": "WS-B", "account": "u2"})
    assert set(s.incidents) == {"INC-0001", "INC-0002"}
    # u1 on WS-B links both incidents through same_user_window.
    s.ingest({**base, "id": "ALT-000003", "timestamp": "2026-10-24T14:02:00-06:00", "device": "WS-B", "account": "u1"})
    assert set(s.incidents) == {"INC-0001"}
    assert any(e["action"] == "merge" and "INC-0002" in e["label"] for e in s.audit)


# --- ingest edge cases (audit #8) -------------------------------------------

def test_duplicate_alert_ids_ignored():
    c = new_client()
    body = gs.public_view(RAW[0])
    r1, r2 = c.post("/alerts", json=body), c.post("/alerts", json=body)
    assert r1.json()["duplicate"] is False and r2.json()["duplicate"] is True
    assert len(c.get("/alerts").json()) == 1


def test_alert_without_id_gets_one():
    c = new_client()
    body = {k: v for k, v in gs.public_view(RAW[0]).items() if k != "id"}
    assert c.post("/alerts", json=body).json()["alert_id"] == "ALT-000001"


@pytest.mark.parametrize("body", [{}, {"source": "edr"}, {"source": "fax", "timestamp": "2026-10-24T14:00:00-06:00"}])
def test_bad_alerts_rejected(body):
    assert new_client().post("/alerts", json=body).status_code == 422


# --- approval -----------------------------------------------------------------

def test_approve_executes_pending_irreversible():
    c = new_client()
    replay(c)
    inc_id = incident_with(c, ATTACK_IDS)["incident_id"]
    before = {a["id"]: a for a in full(c, inc_id)["actions"]}
    r = c.post(f"/incidents/{inc_id}/approve", json={"approved_by": "analyst.demo"})
    assert r.status_code == 200
    inc = r.json()
    INCIDENT_SCHEMA.validate(inc)
    assert inc["status"] == "approved" and inc["approved_by"] == "analyst.demo" and inc["approved_at"]
    for a in inc["actions"]:
        assert a["status"] == "executed"
        if not a["reversible"]:
            assert a["executed_by"] == "analyst.demo" and a["reason"] == "approved by analyst.demo"
        else:  # reversible ones untouched by approval
            assert a == before[a["id"]]
    approved = [e for e in c.get("/audit").json()["entries"] if e["executed_by"] == "analyst.demo"]
    assert Counter(e["action"] for e in approved) == {"isolate_host": 1, "disable_account": 1, "kill_process": 1}
    assert c.get("/health").json()["counts"]["pending_approvals"] == 0
    # nothing left to approve; re-correlation keeps the approval
    assert c.post(f"/incidents/{inc_id}/approve", json={"approved_by": "analyst.demo"}).status_code == 409
    replay(c)
    assert full(c, inc_id)["status"] == "approved"


def test_approve_errors():
    c = new_client()
    replay(c)
    inc_id = incident_with(c, ATTACK_IDS)["incident_id"]
    assert c.post("/incidents/INC-9999/approve", json={"approved_by": "x"}).status_code == 404
    assert c.post(f"/incidents/{inc_id}/approve", json={}).status_code == 422
    assert c.post(f"/incidents/{inc_id}/approve", json={"approved_by": "   "}).status_code == 422
    scan_id = incident_with(c, SCAN_IDS)["incident_id"]
    assert c.post(f"/incidents/{scan_id}/approve", json={"approved_by": "x"}).status_code == 409


def test_unknown_incident_404():
    assert new_client().get("/incidents/INC-0042").status_code == 404


def test_reset_clears_state():
    c = new_client()
    replay(c, RAW[:5])
    assert c.post("/reset").status_code == 200
    assert c.get("/health").json()["counts"] == {"alerts": 0, "incidents": 0, "suppressed_noise": 0,
                                                 "pending_approvals": 0}


# --- catalog safety -------------------------------------------------------------

def test_only_catalog_actions_and_irreversible_never_auto():
    for action_id, spec in actions.CATALOG.items():
        assert isinstance(spec["reversible"], bool)
    assert {a for a, s in actions.CATALOG.items() if not s["reversible"]} == {
        "isolate_host", "disable_account", "kill_process"}


def test_non_catalog_action_never_executes():
    s = Store(window_min=30)
    incident = {"incident_id": "INC-0001", "verdict": "malicious", "risk_score": 90}
    s._reconcile(incident, [("wipe_disk", ["WS-FIN-07"])])
    assert s.records["INC-0001"] == {} and s.audit == []
