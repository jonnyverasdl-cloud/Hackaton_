import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, FormatChecker

SCHEMA = json.loads(
    (Path(__file__).parent.parent / "contracts" / "incident.schema.json").read_text(encoding="utf-8")
)


def validator(name):
    return Draft202012Validator({**SCHEMA, "$ref": f"#/$defs/{name}"}, format_checker=FormatChecker())


T = "2026-10-24T14:{}:00-06:00"

ALERT = {
    "alert_id": "ALT-000123", "timestamp": T.format("06"), "source": "edr",
    "vendor_rule": "Suspicious child process of Office app", "host": "WS-FIN-07",
    "user": "maria.lopez", "src_ip": "10.20.4.17", "dst_ip": None, "domain": None,
    "process": "powershell.exe", "parent_process": "WINWORD.EXE",
    "event_type": "office_spawn_shell", "severity_raw": "high", "raw": {},
}

INCIDENT = {
    "incident_id": "INC-0001", "status": "open", "verdict": "malicious", "risk_score": 87,
    "title": "Pre-ransomware intrusion via phishing on WS-FIN-07",
    "window": {"start": T.format("02"), "end": T.format("22")},
    "entities": {"hosts": ["WS-FIN-07", "SRV-FILES-01"], "users": ["maria.lopez", "svc_backup"],
                 "domains": ["cdn-update-sync.example"], "ips": ["203.0.113.77"]},
    "alerts": ["ALT-000101"],
    "timeline": [{"timestamp": T.format("02"), "alert_id": "ALT-000101", "technique": "T1566.001",
                  "tactic": "Initial Access", "summary": "Macro attachment delivered to maria.lopez"}],
    "tactics_covered": ["Initial Access"],
    "correlation_reasons": [{"rule": "same_host_window", "detail": "share host WS-FIN-07 within 30 min"}],
    "signals": [{"name": "Kill chain depth", "detail": "8 tactics covered", "points": 30}],
    "ai": {"narrative": "At 14:02 ...", "hypothesis": "Pre-encryption ransomware stage",
           "recommended_actions": ["Isolate WS-FIN-07"], "confidence": 0.9, "generated_by": "stub"},
    "autonomy": "awaiting_approval",
    "actions": [
        {"id": "block_domain", "label": "Block cdn-update-sync.example at proxy/DNS", "reversible": True,
         "status": "executed", "executed_by": "system", "executed_at": T.format("22"),
         "reason": "malicious incident, reversible action"},
        {"id": "isolate_host", "label": "Isolate WS-FIN-07 and SRV-FILES-01 (EDR)", "reversible": False,
         "status": "pending", "executed_by": None, "executed_at": None,
         "reason": "irreversible: requires analyst"},
    ],
    "approved_by": None, "approved_at": None,
}


def test_schema_is_valid():
    Draft202012Validator.check_schema(SCHEMA)


def test_example_alert_valid():
    validator("alert").validate(ALERT)


def test_example_incident_valid():
    validator("incident").validate(INCIDENT)


@pytest.mark.parametrize("patch", [
    {"incident_id": "INC-1"}, {"verdict": "bad"}, {"risk_score": 101},
    {"autonomy": "yolo"}, {"status": "pending"},
])
def test_bad_incident_rejected(patch):
    assert list(validator("incident").iter_errors({**INCIDENT, **patch}))


def test_unknown_event_type_rejected():
    assert list(validator("alert").iter_errors({**ALERT, "event_type": "made_up"}))


@pytest.mark.parametrize("bad", ["not-a-date", "2026-10-24 14:06", "2026-13-24T14:06:00-06:00"])
def test_bad_timestamp_rejected(bad):
    assert list(validator("alert").iter_errors({**ALERT, "timestamp": bad}))
