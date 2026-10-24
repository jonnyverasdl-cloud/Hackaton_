"""Rebuild panel/fixtures (offline ?mock=1 data) from the real backend Store.

    .venv\\Scripts\\python.exe tools\\build_fixtures.py

Replays the synthetic scenario through the real Store (rules only, no model call)
with a simulated wall clock, and snapshots the state after every alert that changed
it. The malicious incident's `ai` block is the real recorded model output from
panel/fixtures/ai_recorded.json (see tools/record_ai.py), copied verbatim.
Run after any backend change; tests/test_fixtures.py fails when fixtures drift.
"""
from __future__ import annotations

import copy
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend.app.store import Store  # noqa: E402
from tools.gen_scenario import build_scenario, public_view  # noqa: E402

OUT = ROOT / "panel" / "fixtures"
WALL0 = datetime.fromisoformat("2026-10-24T10:26:00-06:00")


def build() -> dict[str, object]:
    """Return {file name: content} for every fixture file."""
    tick = {"s": 0}
    store = Store(window_min=30, clock=lambda: (WALL0 + timedelta(seconds=tick["s"])).isoformat())
    steps, prev = [], None
    for k, raw in enumerate(build_scenario(), start=1):
        tick["s"] = round(k * 0.96)  # ~48 s of simulated wall clock, like a --speed 40 replay
        store.ingest(public_view(raw))
        incs = [{a: b for a, b in i.items() if a not in ("timeline", "ai")}
                for i in sorted(store.incidents.values(), key=lambda i: i["incident_id"])]
        sig = json.dumps(incs, sort_keys=True)
        if sig != prev:
            steps.append({"k": k, "audit_len": len(store.audit), "incidents": copy.deepcopy(incs)})
            prev = sig

    alerts = [{a: b for a, b in al.items() if a != "raw"} for al in store.alert_view()]
    final = copy.deepcopy(sorted(store.incidents.values(), key=lambda i: i["incident_id"]))
    mal = next(i for i in final if i["verdict"] == "malicious")
    rec = json.loads((OUT / "ai_recorded.json").read_text(encoding="utf-8"))
    assert rec["incident_id"] == mal["incident_id"], "recorded AI is for a different incident: re-run record_ai.py"
    mal["ai"] = rec["ai"]  # real recorded model output, verbatim
    tr = rec["ai"]["trace"]
    health = {"status": "ok", "synthetic": True, "ai_model": tr["model"], "mode": "rules+ai (recorded)",
              "ai": {"mode": "recorded",
                     "reason": f"mock mode: narrative is a recorded {tr['model']} output from {tr['called_at']}, "
                               "not a live call",
                     "calls": 0, "last_latency_ms": tr["latency_ms"], "last_error": None},
              "counts": store.counts()}
    note = ("Snapshots of the real backend Store after each ingested alert (k = alerts seen; audit_len = audit "
            "entries so far). Wall clock is simulated. Timeline and ai come from incidents.json; the malicious "
            "incident's ai is the real recorded model output (ai_recorded.json), verbatim.")
    return {"alerts.json": alerts, "incidents.json": final, "audit.json": store.audit_view(),
            "health.json": health, "replay.json": {"note": note, "steps": steps}}


def dumps(name: str, obj: object) -> str:
    return json.dumps(obj, indent=None if name == "replay.json" else 1, ensure_ascii=False)


def main() -> int:
    files = build()
    for name, obj in files.items():
        (OUT / name).write_text(dumps(name, obj), encoding="utf-8")
    print(f"Wrote {len(files)} fixtures to {OUT.relative_to(ROOT)}: {files['health.json']['counts']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
