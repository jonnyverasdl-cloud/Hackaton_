# Integration guide

How Storyline would plug into a real SOC stack. Everything below describes the code as it is
in this repo; anything that is **not** built yet is marked as such. The prototype runs on
synthetic data only.

## 1. Data flow

```
 sources ──POST /alerts──▶ normalizer ──▶ correlator ──▶ scoring ──▶ actions (autonomy by blast radius)
 (EDR, proxy,              (raw → common   (union-find,    (signals,     reversible: executed by "system"
  auth, email, IDS)         schema +        rules with      70/30         irreversible: pending → /approve
                            event_type)     reasons)        verdict)              │
                                                                                  ▼
 analyst panel ◀── GET /incidents, /incidents/{id}, /audit, /health ◀── AI narrator (background, optional)
```

Each `POST /alerts` re-correlates every alert in memory. Incident ids are stable across
re-correlation; actions are tracked per target, so nothing executes twice.

## 2. Sending alerts

`POST /alerts` takes one raw alert as JSON and returns `201`:

```json
{"alert_id": "ALT-000016", "duplicate": false, "incident_id": "INC-0003"}
```

Common fields:

| Field | Required | Notes |
|---|---|---|
| `source` | yes | `edr`, `proxy`, `auth`, `email_gateway` or `ids` |
| `timestamp` | yes | ISO 8601 **with a UTC offset** (`2026-10-24T14:02:11-06:00`); otherwise `422` |
| `id` | no | `ALT-` + 6 digits, below `ALT-900000`. A repeated id is ignored (`duplicate: true`), so forwarders can retry safely. Without an id, the server assigns one from `ALT-9xxxxx`. |
| `rule` | no | vendor rule name, shown in the queue |
| `severity` | no | `info`, `low`, `medium`, `high`, `critical` |

A bad alert gets `422` and leaves the state exactly as it was (ingest is all-or-nothing).

### Source-specific fields

| Source | Fields used (all optional) | Host / user taken from |
|---|---|---|
| `edr` | `device`, `device_ip`, `account`, `process`, `parent_process`, `command_line`, `signed`, `signer`, `action_taken`, `task_name`, `file_path`, `registry_key`, `renamed_files` | `device` / `account` |
| `proxy` | `client_host`, `client_ip`, `user`, `dest_host`, `dest_ip`, `category`, `domain_age_days` | `client_host` / `user` |
| `auth` | `outcome` (`success`/`failure`), `logon_type`, `src_host`, `src_ip`, `target_host`, `account`, `failure_count`, `distinct_accounts`, `window_seconds`, `first_seen_source` | success → `target_host`; failure/spray → `src_host` |
| `email_gateway` | `recipient`, `recipient_host`, `sender`, `attachment`, `url`, `url_domain_age_days` | `recipient_host` / local part of `recipient` |
| `ids` | `src_host`, `src_ip`, `dst_ip`, `account` | `src_host` (the scanner, never the scanned target) |

Unknown extra fields are kept in `raw` and never break ingest. `docs/prep/03-attack-mapping.md`
has the `event_type` rules (which field values make an alert an ATT&CK technique).

### Example: forwarding from PowerShell

```powershell
$alert = @{ id = "ALT-000123"; source = "edr"; timestamp = (Get-Date).ToString("o")
            rule = "Suspicious child process"; severity = "high"; device = "WS-FIN-07"
            account = "maria.lopez"; process = "powershell.exe"; parent_process = "WINWORD.EXE"
            command_line = "powershell.exe -enc ..." }
Invoke-RestMethod -Uri http://127.0.0.1:8000/alerts -Method Post -ContentType "application/json" `
  -Body ($alert | ConvertTo-Json)
```

A SIEM or log shipper (syslog-to-HTTP, webhook action, Logic App, Lambda) only needs to map its
event to the fields above and POST it. Retries are safe because ids are deduplicated.

## 3. Adding a new vendor or source

1. Add a mapping function in `backend/app/normalizer.py` (`_edr`, `_proxy`, … are the pattern)
   and register it in `_BY_SOURCE`. It returns `host`, `user`, `src_ip`, `dst_ip`, `domain`,
   `process`, `parent_process` and `event_type`.
2. If the source shows a new technique, add its `event_type` to `backend/app/attack.py`
   (`ATTACK_TABLE`) and to the enum in `contracts/incident.schema.json`.
3. Add a test with a raw sample to `tests/test_core.py`. The scenario tests must still pass:
   one malicious incident with exactly the 8 attack alerts.

## 4. Reading incidents

| Route | Use |
|---|---|
| `GET /incidents` | summaries: id, title, verdict, score, status, autonomy, hosts, tactics, pending actions |
| `GET /incidents/{id}` | full incident per `contracts/incident.schema.json`: timeline, reasons, signals, actions, `ai` |
| `GET /alerts` | the raw queue, each alert with `incident_id` and `suppressed` |
| `GET /audit` | everything the system did alone (with `reason`), approvals, AI calls, merges, reopens, plus `suppressed_noise` counts |
| `GET /health` | mode, AI status, counts |

A ticketing or case-management integration can poll `GET /incidents` and open a case when an
incident reaches `awaiting_approval`. There are no webhooks yet (**not built**).

## 5. Executing real actions

All actions are **simulated** today: they are recorded with who, when, why and targets, but
nothing outside the process is called. The single place to connect real tools is
`Store._reconcile` (reversible actions run by `system`) and `Store.approve` (irreversible
actions run by the analyst) in `backend/app/store.py`.

| Action id | Reversible | Typical real integration |
|---|---|---|
| `block_domain` | yes | DNS sinkhole / proxy block list API |
| `watchlist_host`, `tag_user` | yes | SIEM watchlist or identity-risk tag |
| `collect_triage` | yes | EDR live-response package |
| `close_benign` | yes | case status in the ticketing tool |
| `isolate_host` | **no** | EDR network containment |
| `disable_account` | **no** | directory: disable account + force password reset |
| `kill_process` | **no** | EDR kill process + remove persistence |

Rules to keep when wiring them:

- Only catalog ids (`backend/app/actions.py`) may execute. The AI's `recommended_actions` are
  text shown to the analyst and are never executed.
- Irreversible actions must stay behind `POST /incidents/{id}/approve`.
- Keep the per-target bookkeeping: a target that is already done is never re-sent.

## 6. AI (optional)

Configured from environment variables (`.env`, never committed). See `.env.example`:

| Variable | Meaning |
|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS` | path to a service-account JSON **outside the repo** |
| `GOOGLE_CLOUD_PROJECT` | optional; otherwise read from the service-account file |
| `GOOGLE_CLOUD_LOCATION` | default `us-central1` |
| `AI_MODEL` | default `gemini-2.5-flash` |
| `AI_DISABLED=1` | force rules-only |

The model only reads a finished incident and writes text. Each call is traced (model, prompt
sha256, latency, raw response). Anything it names that is not in the incident is listed in
`ai.flags`. On a missing credential, a timeout (30 s), an error or bad JSON, the panel shows a
rules-only summary. Error details stay in the server log; only the exception type is exposed.
Check the setup with `tools/check_ai.py`.

## 7. What a production deployment still needs (not built)

- **Authentication and authorization** on every route. Today anyone who can reach the port can
  post alerts or approve actions; `approved_by` is self-declared.
- **Persistent storage.** State is in memory and lost on restart; `/reset` wipes it.
- **Scale.** Every ingest re-correlates all alerts, which is fine for hundreds of alerts and
  not for a production feed. An incremental union-find and a time-windowed store would be next.
- **TLS** and a reverse proxy; the backend listens on plain HTTP.
- **Real asset and identity context** (admin lists, known scanners) instead of the constants in
  `normalizer.py` and `scoring.py`.
