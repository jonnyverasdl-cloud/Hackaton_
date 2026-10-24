"""Record ONE real model narrative for the offline panel (?mock=1).

    .venv\\Scripts\\python.exe tools\\record_ai.py

Builds the synthetic attack incident, calls the configured model once and writes
the full `ai` block (output, trace, flags) verbatim to panel/fixtures/ai_recorded.json.
The panel labels it "Recorded model output". Refuses to write a stub.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

from backend.app.ai import Narrator, load_config  # noqa: E402
from backend.app.store import Store  # noqa: E402
from tools.gen_scenario import build_scenario, public_view  # noqa: E402

OUT = ROOT / "panel" / "fixtures" / "ai_recorded.json"


def main() -> int:
    load_dotenv(ROOT / ".env")
    cfg = load_config()
    if cfg.mode != "vertex":
        print(f"Not recording: AI is in stub mode ({cfg.reason})")
        return 1
    store = Store(window_min=30)
    for raw in build_scenario():
        store.ingest(public_view(raw))
    incident = max(store.incidents.values(), key=lambda i: i["risk_score"])
    block = Narrator(cfg).narrate(incident)
    if block["generated_by"] == "stub":
        print(f"Not recording: the model call fell back to the stub ({block['trace']['error']})")
        return 1
    OUT.write_text(json.dumps({"incident_id": incident["incident_id"], "ai": block}, indent=1), encoding="utf-8")
    print(f"Recorded {block['generated_by']} ({block['trace']['latency_ms']} ms, "
          f"{len(block['flags'])} flags) to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
