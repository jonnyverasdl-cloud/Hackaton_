"""The offline panel fixtures must match what the backend produces today."""
import json
from pathlib import Path

from tools import build_fixtures

FIXTURES = Path(__file__).parent.parent / "panel" / "fixtures"


def test_fixtures_are_up_to_date():
    for name, obj in build_fixtures.build().items():
        on_disk = (FIXTURES / name).read_text(encoding="utf-8")
        assert on_disk == build_fixtures.dumps(name, obj), f"{name} drifted: run tools/build_fixtures.py"


def test_recorded_ai_is_a_real_model_call():
    rec = json.loads((FIXTURES / "ai_recorded.json").read_text(encoding="utf-8"))
    ai = rec["ai"]
    assert ai["generated_by"] != "stub" and ai["trace"]["error"] is None
    assert json.loads(ai["trace"]["raw_response"])["narrative"] == ai["narrative"]


def test_fixtures_hold_no_ground_truth_or_secrets():
    text = "".join(p.read_text(encoding="utf-8") for p in FIXTURES.glob("*.json"))
    for needle in ("_truth", "private_key", "gserviceaccount", "AIza", "BEGIN "):
        assert needle not in text
