# Benchmark results

Measured by `tools/benchmark.py` on 2026-10-24 11:44 -0600. Synthetic scenario (50 alerts, 8 attack). Alerts posted back to back: timings are processing cost on this machine, not scenario time.

- Mode: in-process (FastAPI TestClient), live model narration
- Machine: Windows-11-10.0.26200-SP0, Intel64 Family 6 Model 142 Stepping 12, GenuineIntel, Python 3.12.10

| Metric | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| `alerts` | 50 | 50 | 50 |
| `total_ms` | 1888.2 | 1253.0 | 2240.0 |
| `post_ms_p50` | 22.3 | 22.9 | 44.5 |
| `post_ms_p95` | 44.9 | 33.8 | 63.2 |
| `post_ms_max` | 565.0 | 38.8 | 64.9 |
| `incidents` | 5 | 5 | 5 |
| `suppressed` | 22 | 22 | 22 |
| `pending_approvals` | 3 | 3 | 3 |
| `needs_human` | 1 | 1 | 1 |
| `attack_correct` | True | True | True |
| `attack_score` | 90 | 90 | 90 |
| `malicious_after_alerts` | 38 | 38 | 38 |
| `malicious_wall_ms_from_first_attack` | 1306.0 | 606.9 | 1114.2 |
| `malicious_scenario_s_from_first_attack` | 954.0 | 954.0 | 954.0 |
| `malicious_at_alert` | ALT-000038 | ALT-000038 | ALT-000038 |
| `ai_generated_by` | gemini-2.5-flash | gemini-2.5-flash | gemini-2.5-flash |
| `ai_ms_after_last_alert` | 12784.1 | 7579.9 | 7771.2 |
| `ai_call_latency_ms` | 5322 | 4749 | 5456 |
| `ai_flags` | 0 | 0 | 0 |
| `ai_error` | — | — | — |

Field notes:
- `post_ms_*`: wall time of one `POST /alerts` (normalize + full re-correlation + actions).
- `malicious_*`: when the attack incident first became malicious; `scenario_s` is from the alerts' own timestamps (first attack alert to the alert that tipped the verdict).
- `needs_human`: incidents with at least one irreversible action awaiting approval.
- `ai_*` (only with `--ai`): real model call; `ai_ms_after_last_alert` includes queueing behind earlier narrations of the same incident.
