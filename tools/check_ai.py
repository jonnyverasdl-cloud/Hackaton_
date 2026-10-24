"""Warm-up / smoke test for the AI layer. Run before the demo.

    .venv\\Scripts\\python.exe tools\\check_ai.py

Builds the synthetic attack incident, calls the configured model once and prints
mode, model, latency, flags and the narrative. Never prints credentials or .env
values. Exit code 0 when the model answered, 1 when it fell back to the stub.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

from backend.app.ai import Narrator, load_config  # noqa: E402
from backend.app.store import Store  # noqa: E402
from tools.gen_scenario import build_scenario, public_view  # noqa: E402


def main() -> int:
    load_dotenv()
    cfg = load_config()
    print(f"AI mode: {cfg.mode}  model: {cfg.model}  location: {cfg.location if cfg.mode == 'vertex' else '-'}")
    if cfg.mode != "vertex":
        print(f"Stub only: {cfg.reason}")
        return 1
    store = Store(window_min=30)  # rules only; the call below is the single model call
    for raw in build_scenario():
        store.ingest(public_view(raw))
    incident = max(store.incidents.values(), key=lambda i: i["risk_score"])
    block = Narrator(cfg).narrate(incident)
    trace = block["trace"]
    print(f"Incident: {incident['incident_id']} {incident['title']} ({incident['verdict']} {incident['risk_score']})")
    print(f"generated_by: {block['generated_by']}  latency: {trace['latency_ms']} ms  "
          f"prompt sha256: {trace['prompt_sha256'][:16]}")
    if trace["error"]:
        print(f"Fallback reason: {trace['error']}")
    print(f"Flags ({len(block['flags'])}): {block['flags']}")
    print(f"\nHypothesis: {block['hypothesis']}  (confidence {block['confidence']})")
    print(f"Narrative: {block['narrative']}")
    print("Recommended actions:")
    for a in block["recommended_actions"]:
        print(f"  - {a}")
    return 0 if block["generated_by"] != "stub" else 1


if __name__ == "__main__":
    sys.exit(main())
