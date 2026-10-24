"""Measure the pipeline on the synthetic scenario: alerts in -> incident formed. 3 runs.

    .venv\\Scripts\\python.exe tools\\benchmark.py                 # in-process, rules only
    .venv\\Scripts\\python.exe tools\\benchmark.py --ai            # + live model narration (real calls)
    .venv\\Scripts\\python.exe tools\\benchmark.py --url http://127.0.0.1:8000   # against a running backend

Every number printed here is measured on this machine, now, and written with the
machine details to docs/benchmark-results.md. Alerts are posted back to back (no
replay sleeps), so timings are processing cost, not scenario time. Scenario time to
detection is reported separately and comes from the alerts' own timestamps.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tools.gen_scenario import build_scenario, public_view  # noqa: E402

RESULTS = ROOT / "docs" / "benchmark-results.md"
RESULTS_AI = ROOT / "docs" / "benchmark-results-ai.md"
AI_WAIT_S = 90


def _client(url: str | None, ai: bool):
    if url:
        import httpx
        return httpx.Client(base_url=url, timeout=40)
    if not ai:
        os.environ["AI_DISABLED"] = "1"
    from fastapi.testclient import TestClient

    from backend.app.ai import Narrator
    from backend.app.main import create_app
    from backend.app.store import Store
    narrator = Narrator() if ai else None
    return TestClient(create_app(Store(window_min=30, narrator=narrator, ai_async=ai)))


def _pct(values: list[float], q: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, round(q * (len(s) - 1)))]


def run_once(client, alerts: list[dict], ai: bool) -> dict:
    client.post("/reset").raise_for_status()
    attack_ids = {a["id"] for a in alerts if a["_truth"]["attack"]}
    first_attack = next(a for a in alerts if a["id"] in attack_ids)
    post_ms: list[float] = []
    malicious_after = None  # (alerts posted, wall ms since first attack alert, scenario seconds)
    t0 = time.perf_counter()
    t_first_attack = None
    for n, raw in enumerate(alerts, start=1):
        start = time.perf_counter()
        r = client.post("/alerts", json=public_view(raw))
        post_ms.append((time.perf_counter() - start) * 1000)
        r.raise_for_status()
        if raw["id"] == first_attack["id"]:
            t_first_attack = time.perf_counter()
        if malicious_after is None and r.json().get("incident_id") and raw["id"] in attack_ids:
            inc = client.get(f"/incidents/{r.json()['incident_id']}").json()
            if inc["verdict"] == "malicious":
                scen = (datetime.fromisoformat(raw["timestamp"])
                        - datetime.fromisoformat(first_attack["timestamp"])).total_seconds()
                malicious_after = (n, (time.perf_counter() - t_first_attack) * 1000, scen, raw["id"])
    total_ms = (time.perf_counter() - t0) * 1000

    summaries = client.get("/incidents").json()
    incidents = [client.get(f"/incidents/{s['incident_id']}").json() for s in summaries]
    attack = [i for i in incidents if attack_ids & set(i["alerts"])]
    counts = client.get("/health").json()["counts"]
    out = {
        "alerts": len(alerts), "total_ms": total_ms,
        "post_ms_p50": statistics.median(post_ms), "post_ms_p95": _pct(post_ms, 0.95), "post_ms_max": max(post_ms),
        "incidents": counts["incidents"], "suppressed": counts["suppressed_noise"],
        "pending_approvals": counts["pending_approvals"],
        "needs_human": sum(1 for i in incidents if any(a["status"] == "pending" for a in i["actions"])),
        "attack_correct": (len(attack) == 1 and set(attack[0]["alerts"]) == attack_ids
                           and attack[0]["verdict"] == "malicious"),
        "attack_score": attack[0]["risk_score"] if attack else None,
        "malicious_after_alerts": malicious_after[0] if malicious_after else None,
        "malicious_wall_ms_from_first_attack": malicious_after[1] if malicious_after else None,
        "malicious_scenario_s_from_first_attack": malicious_after[2] if malicious_after else None,
        "malicious_at_alert": malicious_after[3] if malicious_after else None,
    }
    if ai and attack:
        t_last = time.perf_counter()
        deadline = t_last + AI_WAIT_S
        block = None
        while time.perf_counter() < deadline:
            block = client.get(f"/incidents/{attack[0]['incident_id']}").json()["ai"]
            if block and block["alerts_covered"] == len(attack_ids) and block["generated_by"] != "stub":
                break
            if block and block["alerts_covered"] == len(attack_ids) and block["trace"]["error"]:
                break  # fell back to the stub for the final state: report it, don't wait
            time.sleep(0.25)
        out.update({
            "ai_generated_by": block["generated_by"] if block else None,
            "ai_ms_after_last_alert": (time.perf_counter() - t_last) * 1000,
            "ai_call_latency_ms": block["trace"]["latency_ms"] if block else None,
            "ai_flags": len(block["flags"]) if block else None,
            "ai_error": block["trace"]["error"] if block else "no narrative within wait",
        })
    return out


def _fmt(v) -> str:
    if isinstance(v, float):
        return f"{v:.1f}"
    return "—" if v is None else str(v)


def render(runs: list[dict], mode: str) -> str:
    keys = list(runs[0])
    lines = [
        "# Benchmark results",
        "",
        f"Measured by `tools/benchmark.py` on {datetime.now().astimezone():%Y-%m-%d %H:%M %z}. "
        "Synthetic scenario (50 alerts, 8 attack). Alerts posted back to back: timings are processing cost "
        "on this machine, not scenario time.",
        "",
        f"- Mode: {mode}",
        f"- Machine: {platform.platform()}, {platform.processor() or platform.machine()}, "
        f"Python {platform.python_version()}",
        "",
        "| Metric | " + " | ".join(f"Run {i}" for i in range(1, len(runs) + 1)) + " |",
        "|---|" + "---|" * len(runs),
    ]
    for k in keys:
        lines.append(f"| `{k}` | " + " | ".join(_fmt(r[k]) for r in runs) + " |")
    lines += ["", "Field notes:",
              "- `post_ms_*`: wall time of one `POST /alerts` (normalize + full re-correlation + actions).",
              "- `malicious_*`: when the attack incident first became malicious; `scenario_s` is from the alerts' "
              "own timestamps (first attack alert to the alert that tipped the verdict).",
              "- `needs_human`: incidents with at least one irreversible action awaiting approval.",
              "- `ai_*` (only with `--ai`): real model call; `ai_ms_after_last_alert` includes queueing behind "
              "earlier narrations of the same incident."]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--runs", type=int, default=3)
    p.add_argument("--ai", action="store_true", help="narrate with the live model (real calls)")
    p.add_argument("--url", help="benchmark a running backend instead of an in-process app")
    p.add_argument("--no-write", action="store_true", help="print only, don't write docs/benchmark-results*.md")
    args = p.parse_args(argv)
    if args.ai:
        from dotenv import load_dotenv
        load_dotenv(ROOT / ".env")
    alerts = build_scenario()
    client = _client(args.url, args.ai)
    runs = []
    for i in range(1, args.runs + 1):
        r = run_once(client, alerts, args.ai)
        runs.append(r)
        print(f"run {i}: {json.dumps({k: round(v, 1) if isinstance(v, float) else v for k, v in r.items()})}")
    mode = (f"HTTP against {args.url}" if args.url else "in-process (FastAPI TestClient)") + \
           (", live model narration" if args.ai else ", rules only (AI disabled)")
    report = render(runs, mode)
    if not args.no_write:
        out = RESULTS_AI if args.ai else RESULTS
        out.write_text(report, encoding="utf-8")
        print(f"Wrote {out.relative_to(ROOT)}")
    return 0 if all(r["attack_correct"] for r in runs) else 1


if __name__ == "__main__":
    sys.exit(main())
