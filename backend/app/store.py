"""In-memory state: alerts, incidents with stable ids, action records and the audit log.

Every ingest re-correlates all alerts. Incident ids are stable: a group keeps the id
of the incident its alerts already belonged to (the lowest one if two merge), and
only a group with no known alerts gets a new id. Actions are tracked per target, so
re-correlation only ever executes work for targets it has not handled yet.

Ingest is all-or-nothing: if correlation fails, the alert and every state change
are rolled back, so one bad alert can never break later ones.

Times: `scenario_time` is the time of the alert that triggered an action (the
story the panel tells); `wall_time` / `executed_at` / audit `at` are the real clock.
"""
from __future__ import annotations

import copy
import re
import threading
from collections import Counter
from datetime import datetime

from . import actions
from .correlator import build_incident, correlate
from .normalizer import normalize

CLIENT_ID = re.compile(r"^ALT-\d{6}$")
AUTO_ID_START = 900001  # server-assigned ids live apart from client ids (ALT-9xxxxx)


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


class ApprovalError(Exception):
    pass


class Store:
    def __init__(self, window_min: int = 30, clock=now_iso):
        self.window_min = window_min
        self.clock = clock
        self.lock = threading.RLock()
        self.reset()

    def reset(self) -> None:
        with self.lock:
            self.alerts: list[dict] = []
            self.by_id: dict[str, dict] = {}
            self.incidents: dict[str, dict] = {}
            self.alert_incident: dict[str, str] = {}
            self.records: dict[str, dict[str, dict]] = {}  # incident id -> action id -> record
            self.audit: list[dict] = []
            self._next_alert = AUTO_ID_START
            self._next_incident = 1
            self._trigger: dict | None = None

    # --- ingest ----------------------------------------------------------------

    def _new_alert_id(self) -> str:
        while f"ALT-{self._next_alert:06d}" in self.by_id:
            self._next_alert += 1
        return f"ALT-{self._next_alert:06d}"

    _STATE = ("alerts", "by_id", "incidents", "alert_incident", "records", "audit",
              "_next_alert", "_next_incident")

    def ingest(self, raw: dict) -> tuple[dict, bool]:
        """Normalize, store and re-correlate. Returns (alert, duplicate); duplicates are ignored.

        Raises ValueError for a bad alert; the store is then exactly as before.
        """
        with self.lock:
            rid = raw.get("id")
            if rid is not None and not (isinstance(rid, str) and CLIENT_ID.match(rid)):
                raise ValueError("id must be a string like ALT-000123")
            if rid in self.by_id:
                return self.by_id[rid], True
            alert = normalize(raw, alert_id=rid or self._new_alert_id())
            snapshot = copy.deepcopy({k: getattr(self, k) for k in self._STATE})
            self.alerts.append(alert)
            self.by_id[alert["alert_id"]] = alert
            self._trigger = alert
            try:
                self._recorrelate()
            except Exception as exc:
                for k, v in snapshot.items():
                    setattr(self, k, v)
                raise ValueError(f"alert rejected, correlation failed: {exc}") from exc
            finally:
                self._trigger = None
            return alert, False

    def _recorrelate(self) -> None:
        incidents: dict[str, dict] = {}
        for group in correlate(self.alerts, self.window_min):
            known = sorted({self.alert_incident[a] for a in group.alert_ids if a in self.alert_incident})
            if known:
                incident_id = known[0]
                for absorbed in known[1:]:
                    self._merge(absorbed, incident_id)
            else:
                incident_id = f"INC-{self._next_incident:04d}"
                self._next_incident += 1
            for a in group.alert_ids:
                self.alert_incident[a] = incident_id
            incidents[incident_id] = self._assemble(group, incident_id)
        self.incidents = incidents

    def _merge(self, absorbed: str, into: str) -> None:
        target = self.records.setdefault(into, {})
        for action_id, rec in self.records.pop(absorbed, {}).items():
            mine = target.get(action_id)
            if mine is None:
                target[action_id] = copy.deepcopy(rec)  # keeps who/when/why
                continue
            mine["done"] += [t for t in rec["done"] if t not in mine["done"]]
            mine["pending"] += [t for t in rec["pending"] if t not in mine["pending"] + mine["done"]]
            for key in ("executed_by", "executed_at", "scenario_time", "reason", "pending_reason"):
                mine[key] = mine[key] or rec[key]
        self._log(into, "merge", f"Merged {absorbed} into {into}", "system",
                  "correlation linked the two incidents")

    def _assemble(self, group, incident_id: str) -> dict:
        previous = self.incidents.get(incident_id)
        incident = build_incident(group, self.by_id, incident_id)
        alerts = [self.by_id[a] for a in group.alert_ids]
        in_group = self._trigger and self._trigger["alert_id"] in group.alert_ids
        trigger_time = self._trigger["timestamp"] if in_group else incident["window"]["end"]
        planned = actions.plan(incident, alerts)
        self._reconcile(incident, planned, trigger_time)
        autonomy = actions.autonomy_for(incident, planned)
        if previous:
            incident["approved_by"] = previous["approved_by"]
            incident["approved_at"] = previous["approved_at"]
            incident["ai"] = previous["ai"]
        recs = self.records.get(incident_id, {})
        pending = any(r["pending"] for r in recs.values())
        if autonomy == "auto_closed":
            incident["status"] = "closed"
        elif incident["approved_by"] and not pending:
            incident["status"], autonomy = "approved", "approved"
        else:
            incident["status"] = "open"
        if previous and previous["status"] == "closed" and incident["status"] != "closed":
            why = f"new evidence: score {incident['risk_score']}, {incident['verdict']}, now {autonomy}"
            if "close_benign" in recs:
                recs["close_benign"].update(reverted=True, reason=f"reverted, {why}")
            self._log(incident_id, "reopen", f"Reopened {incident_id}", "system", why,
                      scenario_time=trigger_time)
        incident["autonomy"] = autonomy
        incident["actions"] = self._render_actions(incident_id)
        return incident

    # --- actions ---------------------------------------------------------------

    @staticmethod
    def _new_record(action_id: str) -> dict:
        return {"id": action_id, "reversible": actions.CATALOG[action_id]["reversible"],
                "done": [], "pending": [], "executed_by": None, "executed_at": None,
                "scenario_time": None, "reason": "", "pending_reason": "", "reverted": False}

    def _reconcile(self, incident: dict, planned: list[tuple[str, list[str]]], scenario_time: str) -> None:
        recs = self.records.setdefault(incident["incident_id"], {})
        for action_id, targets in planned:
            if not actions.is_catalog_action(action_id):
                continue  # only catalog actions can ever execute
            rec = recs.setdefault(action_id, self._new_record(action_id))
            new = [t for t in targets if t not in rec["done"] and t not in rec["pending"]]
            if not new:
                continue
            if rec["reversible"]:
                if action_id == "close_benign":
                    reason = f"benign incident (score {incident['risk_score']}): known noise pattern only"
                else:
                    reason = f"{incident['verdict']} incident (score {incident['risk_score']}), reversible action"
                if rec["done"]:
                    reason = f"extended to new target {' and '.join(new)}; {reason}"
                rec["done"] += new
                rec.update(executed_by="system", executed_at=self.clock(), scenario_time=scenario_time,
                           reason=reason, reverted=False)
                self._log(incident["incident_id"], action_id, actions.label_for(action_id, new), "system",
                          reason, targets=new, scenario_time=scenario_time, at=rec["executed_at"])
            else:
                rec["pending"] += new
                rec["pending_reason"] = "irreversible: requires analyst approval"

    def _render_actions(self, incident_id: str) -> list[dict]:
        out = []
        for rec in self.records.get(incident_id, {}).values():
            targets = rec["done"] + rec["pending"]
            pending = bool(rec["pending"])
            out.append({
                "id": rec["id"], "label": actions.label_for(rec["id"], targets),
                "reversible": rec["reversible"],
                "status": "pending" if pending else "reverted" if rec["reverted"] else "executed",
                "executed_by": None if pending else rec["executed_by"],
                "executed_at": None if pending else rec["executed_at"],
                "scenario_time": None if pending else rec["scenario_time"],
                "wall_time": None if pending else rec["executed_at"],
                "reason": rec["pending_reason"] if pending else rec["reason"],
                "targets": targets,
            })
        return out

    def approve(self, incident_id: str, approved_by: str) -> dict:
        with self.lock:
            if incident_id not in self.incidents:
                raise KeyError(incident_id)
            recs = self.records.get(incident_id, {})
            pending = [r for r in recs.values() if r["pending"]]
            if not pending:
                raise ApprovalError(f"{incident_id} has no actions awaiting approval")
            at = self.clock()
            for rec in pending:
                reason = f"approved by {approved_by}"
                self._log(incident_id, rec["id"], actions.label_for(rec["id"], rec["pending"]), approved_by,
                          reason, targets=rec["pending"], at=at)
                rec["done"] += rec["pending"]
                rec["pending"] = []
                rec.update(executed_by=approved_by, executed_at=at, scenario_time=None, reason=reason)
            incident = self.incidents[incident_id]
            incident.update(approved_by=approved_by, approved_at=at, status="approved", autonomy="approved",
                            actions=self._render_actions(incident_id))
            return incident

    def _log(self, incident_id: str, action: str, label: str, by: str, reason: str, *,
             targets: list[str] | None = None, scenario_time: str | None = None, at: str | None = None) -> None:
        self.audit.append({"at": at or self.clock(), "scenario_time": scenario_time, "incident_id": incident_id,
                           "action": action, "label": label, "targets": list(targets or []),
                           "executed_by": by, "reason": reason})

    # --- views -----------------------------------------------------------------

    def suppressed(self) -> list[dict]:
        """Alerts in no incident: no ATT&CK technique and no correlation pattern."""
        return [a for a in self.alerts if a["alert_id"] not in self.alert_incident]

    def alert_view(self) -> list[dict]:
        with self.lock:
            return [{**a, "incident_id": self.alert_incident.get(a["alert_id"]),
                     "suppressed": a["alert_id"] not in self.alert_incident}
                    for a in sorted(self.alerts, key=lambda a: (a["timestamp"], a["alert_id"]))]

    def summaries(self) -> list[dict]:
        with self.lock:
            return [{
                "incident_id": i["incident_id"], "title": i["title"], "verdict": i["verdict"],
                "risk_score": i["risk_score"], "status": i["status"], "autonomy": i["autonomy"],
                "window": i["window"], "alert_count": len(i["alerts"]), "hosts": i["entities"]["hosts"],
                "tactics_covered": i["tactics_covered"],
                "pending_actions": sum(a["status"] == "pending" for a in i["actions"]),
            } for i in sorted(self.incidents.values(), key=lambda i: i["incident_id"])]

    def audit_view(self) -> dict:
        with self.lock:
            suppressed = self.suppressed()
            return {"entries": list(self.audit),
                    "suppressed_noise": {"count": len(suppressed),
                                         "by_type": dict(Counter(a["event_type"] for a in suppressed))}}

    def counts(self) -> dict:
        with self.lock:
            return {"alerts": len(self.alerts), "incidents": len(self.incidents),
                    "suppressed_noise": len(self.suppressed()),
                    "pending_approvals": sum(a["status"] == "pending"
                                             for i in self.incidents.values() for a in i["actions"])}
