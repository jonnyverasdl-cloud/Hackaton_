"""Action catalog (simulated) and which actions an incident calls for (03-attack-mapping.md).

Autonomy by blast radius: `reversible: True` actions are executed by the system on
its own and logged with a reason; irreversible ones stay `pending` until an analyst
approves. Only catalog ids can ever execute. Each action is tracked per target
(host, user, domain...), so re-correlation never executes the same thing twice.
"""
from __future__ import annotations

from . import scoring

CATALOG: dict[str, dict] = {
    "close_benign": {"reversible": True, "label": "Close incident as benign (known noise pattern)"},
    "watchlist_host": {"reversible": True, "label": "Add {targets} to watchlist (72 h)"},
    "tag_user": {"reversible": True, "label": "Flag {targets} for review"},
    "block_domain": {"reversible": True, "label": "Block {targets} at proxy/DNS"},
    "collect_triage": {"reversible": True, "label": "Collect triage package (processes, connections) from {targets}"},
    "isolate_host": {"reversible": False, "label": "Isolate {targets} (EDR)"},
    "disable_account": {"reversible": False, "label": "Disable {targets} and force password reset"},
    "kill_process": {"reversible": False, "label": "Kill process and remove persistence: {targets}"},
}

PERSISTENCE_TYPES = frozenset({"scheduled_task_created", "registry_run_key"})


def is_catalog_action(action_id: str) -> bool:
    return action_id in CATALOG


def label_for(action_id: str, targets: list[str]) -> str:
    return CATALOG[action_id]["label"].format(targets=" and ".join(targets) if len(targets) <= 2
                                              else ", ".join(targets[:-1]) + " and " + targets[-1])


def _unique(values) -> list[str]:
    return list(dict.fromkeys(v for v in values if v))


def plan(incident: dict, alerts: list[dict]) -> list[tuple[str, list[str]]]:
    """(action_id, targets) the incident calls for right now, in display order."""
    verdict = incident["verdict"]
    ents = incident["entities"]
    if verdict == "benign":
        # Only pure known-noise groups auto-close. A benign incident with an ATT&CK
        # technique is still forming: the system waits for more evidence (monitoring).
        has_technique = any(e["technique"] for e in incident["timeline"])
        return [] if has_technique else [("close_benign", [incident["incident_id"]])]

    out = [("watchlist_host", ents["hosts"]), ("tag_user", ents["users"])]
    if verdict == "malicious":
        c2 = [a for a in alerts if a["event_type"] == "outbound_new_domain"]
        out.append(("block_domain", _unique([a["domain"] for a in c2] + [a["dst_ip"] for a in c2])))
    out.append(("collect_triage", ents["hosts"]))
    if verdict == "malicious":
        out.append(("isolate_host", ents["hosts"]))
        lateral_users = [a["user"] for a in alerts if a["event_type"] == "lateral_logon_new_source"]
        accounts = _unique([u for u in ents["users"] if scoring.is_privileged(u)] + lateral_users)
        out.append(("disable_account", accounts))
        persistence = [f"{a['host']} {a['raw'].get('task_name') or a['process']}"
                       + (f" ({a['raw']['file_path']})" if a["raw"].get("file_path") else "")
                       for a in alerts if a["event_type"] in PERSISTENCE_TYPES]
        out.append(("kill_process", _unique(persistence)))
    return [(aid, targets) for aid, targets in out if targets]


def autonomy_for(incident: dict, planned: list[tuple[str, list[str]]]) -> str:
    if incident["verdict"] == "benign":
        return "auto_closed" if planned else "monitoring"
    return scoring.autonomy_for(incident["verdict"])
