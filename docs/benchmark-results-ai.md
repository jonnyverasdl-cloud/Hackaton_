# Benchmark results

Measured by `tools/benchmark.py` on 2026-10-24 12:03 -0600. Synthetic scenario (50 alerts, 8 attack). Alerts posted back to back: timings are processing cost on this machine, not scenario time.

- Mode: in-process (FastAPI TestClient), live model narration
- Machine: Windows-11-10.0.26200-SP0, Intel64 Family 6 Model 142 Stepping 12, GenuineIntel, Python 3.12.10

| Metric | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| `alerts` | 50 | 50 | 50 |
| `total_ms` | 3160.7 | 1366.9 | 1303.0 |
| `post_ms_p50` | 30.9 | 22.4 | 23.1 |
| `post_ms_p95` | 377.0 | 56.8 | 44.0 |
| `post_ms_max` | 505.8 | 68.2 | 55.5 |
| `incidents` | 5 | 5 | 5 |
| `suppressed` | 22 | 22 | 22 |
| `pending_approvals` | 3 | 3 | 3 |
| `needs_human` | 1 | 1 | 1 |
| `attack_correct` | True | True | True |
| `attack_score` | 90 | 90 | 90 |
| `malicious_after_alerts` | 38 | 38 | 38 |
| `ingest_ms_first_attack_to_verdict` | 2359.1 | 782.3 | 609.8 |
| `malicious_scenario_s_from_first_attack` | 954.0 | 954.0 | 954.0 |
| `malicious_at_alert` | ALT-000038 | ALT-000038 | ALT-000038 |
| `ai_generated_by` | gemini-2.5-flash | gemini-2.5-flash | gemini-2.5-flash |
| `ai_ms_after_last_alert` | 15464.4 | 10831.7 | 13309.8 |
| `ai_call_latency_ms` | 5688 | 7555 | 6659 |
| `ai_flags` | 0 | 0 | 0 |
| `ai_error` | — | — | — |

Field notes:
- `post_ms_*`: wall time of one `POST /alerts` (normalize + full re-correlation + actions).
- `malicious_*`: when the attack incident first became malicious; `scenario_s` is from the alerts' own timestamps (first attack alert to the alert that tipped the verdict).
- `ingest_ms_first_attack_to_verdict`: processing time to post the alerts from the first attack alert up to the one that tipped the verdict, back to back. It is not a detection latency; detection in scenario time is `malicious_scenario_s_from_first_attack`.
- `needs_human`: incidents with at least one irreversible action awaiting approval.
- `ai_*` (only with `--ai`): real model call; `ai_ms_after_last_alert` runs from the last POST and includes queueing behind earlier narrations of the same incident.
