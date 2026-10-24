# Benchmark results

Measured by `tools/benchmark.py` on 2026-10-24 12:02 -0600. Synthetic scenario (50 alerts, 8 attack). Alerts posted back to back: timings are processing cost on this machine, not scenario time.

- Mode: in-process (FastAPI TestClient), rules only (AI disabled)
- Machine: Windows-11-10.0.26200-SP0, Intel64 Family 6 Model 142 Stepping 12, GenuineIntel, Python 3.12.10

| Metric | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| `alerts` | 50 | 50 | 50 |
| `total_ms` | 1628.4 | 1603.6 | 1977.9 |
| `post_ms_p50` | 23.7 | 24.6 | 37.0 |
| `post_ms_p95` | 60.6 | 59.4 | 66.9 |
| `post_ms_max` | 76.4 | 94.9 | 75.6 |
| `incidents` | 5 | 5 | 5 |
| `suppressed` | 22 | 22 | 22 |
| `pending_approvals` | 3 | 3 | 3 |
| `needs_human` | 1 | 1 | 1 |
| `attack_correct` | True | True | True |
| `attack_score` | 90 | 90 | 90 |
| `malicious_after_alerts` | 38 | 38 | 38 |
| `ingest_ms_first_attack_to_verdict` | 849.2 | 837.6 | 951.6 |
| `malicious_scenario_s_from_first_attack` | 954.0 | 954.0 | 954.0 |
| `malicious_at_alert` | ALT-000038 | ALT-000038 | ALT-000038 |

Field notes:
- `post_ms_*`: wall time of one `POST /alerts` (normalize + full re-correlation + actions).
- `malicious_*`: when the attack incident first became malicious; `scenario_s` is from the alerts' own timestamps (first attack alert to the alert that tipped the verdict).
- `ingest_ms_first_attack_to_verdict`: processing time to post the alerts from the first attack alert up to the one that tipped the verdict, back to back. It is not a detection latency; detection in scenario time is `malicious_scenario_s_from_first_attack`.
- `needs_human`: incidents with at least one irreversible action awaiting approval.
- `ai_*` (only with `--ai`): real model call; `ai_ms_after_last_alert` runs from the last POST and includes queueing behind earlier narrations of the same incident.
