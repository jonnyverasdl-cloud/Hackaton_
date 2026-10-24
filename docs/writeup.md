# Storyline — write-up

Alert Correlation & Incident Timeline · SOC hackathon (Alaris Security), 2026-10-24 · solo entry by
Jonathan Veras. All data in this project is synthetic.

## 1. What it is

**The problem is fragments.** An analyst does not get "an attack". They get a macro attachment from
the email gateway, a strange PowerShell from the EDR, a connection to a new domain from the proxy,
40 failed logons from the identity system — interleaved with vulnerability scans, Windows updates
and people mistyping their password. Seeing the story means correlating by hand, under time
pressure, across tools.

**The solution is an incident with a timeline.** Storyline ingests raw alerts from five source
types, groups them into incidents with deterministic rules that write down why, maps every alert
to MITRE ATT&CK, scores the incident, starts the safe part of the response by itself, and asks a
language model to tell the story in plain English, with every claim checked against the evidence.

**The criterion is Audit-First with autonomy by blast radius.** Rules decide what goes together
and how bad it is; every decision leaves a reason a human can read. The system acts alone only
where the action can be undone, logs why, and waits for an analyst on anything irreversible. The
AI writes, it never decides.

## 2. Demo in 60 seconds

`.\run_demo.ps1` starts the backend, waits for `/health`, resets state, makes one warm-up call to
the model, opens the panel and prints **READY FOR DEMO**. On Enter it replays the scenario — 35
minutes of alerts in about 52 seconds.

1. **The noise arrives.** The left column fills with 50 alerts from EDR, proxy, auth, email and IDS.
   The top bar counts: alerts in, noise suppressed, incidents, auto-closed, awaiting an analyst.
2. **Incidents form.** Four benign incidents appear and are **closed by system**, each with its
   reason: a scheduled vulnerability scan, a printer with an expired password, adware already
   cleaned, and two failed logons by maria.lopez before the attack.
3. **The attack escalates.** The phishing incident starts in **monitoring** (score 10, nothing
   done), becomes **auto-contained** at 30 (host on watchlist, user flagged, triage requested),
   and reaches **awaiting approval** at 75 when the service account logs on to the file server —
   the system blocks the C2 domain and IP by itself. The kill-chain strip lights up tactic by
   tactic until 8 of 14 are covered and the score reaches 90.
4. **The narrative appears.** Gemini's account of the intrusion shows up with its trace (model,
   latency, prompt hash) and "✓ 0 entities outside the incident".
5. **A human decides.** The analyst signs with a name and approves host isolation, disabling
   `svc_backup` and removing the persistence task. The audit log shows what the system did alone,
   what the analyst approved, and every AI call.

If the network fails during the presentation, `/panel/?mock=1` replays the same run offline from
fixtures built by the real backend, with a real recorded model output labelled as recorded.

## 3. How it works

```
 POST /alerts ─▶ normalizer ─▶ correlator ─▶ scoring ─▶ actions ─▶ AI narrator ─▶ panel
                 raw → schema   union-find     kill chain  reversible   background,    polls /incidents
                 + event_type   + reasons      → verdict   → system     traced,        every 2 s
                                                           irreversible checked
                                                           → /approve
```

**Normalizer.** Each source has its own field names (`device` on EDR, `client_host` on the proxy,
`src_host`/`target_host` on auth…). The normalizer maps them to one schema
(`contracts/incident.schema.json`) and assigns an `event_type` from a closed vocabulary, which is
the key to ATT&CK. Small decisions matter here: a successful logon belongs to the *target* host, a
failed one to the *source*; an IDS alert belongs to the *scanner*, never to the scanned host; the
12 accounts hit by a password spray stay in the raw record and never become entities. Each of
those decisions prevents a false link that would drag noise into the attack.

**What goes together: rules with reasons.** A union-find over alerts; five rules link pairs and
each link writes a sentence:

- `same_host_window`: same host within 30 minutes, both alerts carrying a technique.
- `user_pivot`: a first-time logon on host B from host A links B's activity to A's.
- `shared_infra`: two hosts contacting the same external domain or IP.
- `same_user_window`: the same user on two hosts within 15 minutes.
- `noise_isolation`: known noise groups only with its own kind.

The scenario has a deliberate trap: maria.lopez mistypes her password twice at 13:55, on the same
host, seven minutes before the phishing email. A naive same-host rule pulls those logons into the
attack. Here, noise never joins by host alone, so they form their own benign incident.

**How bad: the kill chain.** Each tactic reached is worth 5 points (max 30). Added signals: impact
stage (15), lateral movement across hosts (15), privileged or service account (10), credential
access (10), C2 to new infrastructure (5) and confirmed initial access (5). Thresholds: malicious
≥ 70, suspicious 30–69. The attack scores 90; every noise incident scores 0. The panel shows each
signal with its points, so the score can be checked by hand.

**Stable and idempotent.** Every new alert re-correlates everything, but an incident keeps its id
(when two merge, the lower id survives). Actions are tracked per target, so a re-correlation never
runs anything twice — it only extends an action to new targets, and says so.

## 4. Autonomy by blast radius

The question for every action is not "is the AI confident?" but "can it be undone?".

| Verdict | The system, alone | Waits for a human |
|---|---|---|
| benign, known noise only | closes the incident, with a reason | — |
| benign, with a technique or unexplained activity | nothing: **monitoring**, re-scored on every alert | — |
| suspicious | watchlist, review flag, triage package | — |
| malicious | the above, plus blocking the C2 domain and IP | isolate hosts, disable accounts, kill processes |

| Action | Reversible |
|---|---|
| `close_benign`, `watchlist_host`, `tag_user`, `collect_triage`, `block_domain` | yes: executed by `system`, with a reason, in `/audit` |
| `isolate_host`, `disable_account`, `kill_process` | **no**: pending until `POST /incidents/{id}/approve` |

The `monitoring` state was added during the build. A literal "benign → auto-close" rule would have
closed the phishing incident in the first seconds of the attack (one alert, score 10) and reopened
it a minute later. An incident that already shows an ATT&CK technique is never closed by the
machine; only pure known noise is.

## 5. The AI: scope and observability

The design goal was an AI that is useful and *checkable*.

- **Bounded input.** The model sees one finished incident: timeline, techniques, entities,
  correlation reasons, signals and the state of the actions. No raw vendor payloads, no other
  incidents, no tools.
- **Structured output.** A strict JSON schema (`narrative`, `hypothesis`, `recommended_actions`,
  `confidence`) with `response_mime_type: application/json`. The system prompt forbids inventing
  hosts, users, IPs, domains, files, times or dates, changing the verdict, or claiming actions
  that did not run, and the prompt carries today's date.
- **No agency.** There is no function calling, and no code path reads the AI's output to act.
  Recommended actions are displayed as "suggestions only; only catalog actions execute". A test
  feeds the model hostile recommendations ("wipe_disk WS-FIN-07") and checks the executed
  actions are identical to a run without AI.
- **A trace per call.** Model, SHA-256 of the exact prompt, latency, raw response, error and time
  are stored on the incident, shown under the narrative, and logged in `/audit`.
- **Entity verification.** After every call, each host, user, IP, domain, time and date in the
  text is checked against the incident. Anything the incident does not contain becomes a flag in
  `ai.flags` and an amber "Not in incident — verify" list in the panel. CVE ids, hash names, file
  names and code namespaces are recognised as non-entities, so the check stays quiet on normal
  analyst prose. In every measured run with the live model, the narrative produced 0 flags.
- **Graceful degradation.** No credentials, a 30-second timeout, a network or auth error, or a
  response that is not valid JSON → a deterministic rules-only summary built from the timeline,
  clearly labelled "Rules-only summary (AI unavailable)". The demo works without the model.
- **No secrets on screen.** Vertex error messages can contain the project id or the service
  account's email. Only the exception type reaches the trace, the panel, `/health` and `/audit`;
  the full text stays in the server log.
- **Never in the hot path.** Narration runs in a background worker. Alerts are ingested, correlated
  and acted on without waiting for the model; the panel shows "AI updating narrative (covers 5 of
  7 alerts)" while it catches up.

## 6. Data

Everything is synthetic and generated deterministically by `tools/gen_scenario.py`: a fictional
bank (NovaBanco), `.example` domains, external IPs from the documentation range `203.0.113.0/24`
(RFC 5737), internal IPs from `10.20.0.0/16`. The panel always shows "SYNTHETIC SCENARIO".

The scenario is a pre-ransomware intrusion mapped to MITRE ATT&CK Enterprise:
phishing attachment (T1566.001) → encoded PowerShell from Word (T1059.001) → C2 over HTTPS to a
2-day-old domain (T1071.001) → scheduled-task persistence (T1053.005) → password spraying
(T1110.003) → service-account logon to the file server (T1021.002) → Domain Admins enumeration
(T1087.002) → shadow copy deletion (T1490). Eight alerts over 20 minutes, hidden among 42 noise
alerts in the same 35-minute window.

Reference: MITRE ATT&CK®, https://attack.mitre.org/. ATT&CK is a registered trademark of The
MITRE Corporation.

## 7. Measured results

All numbers come from `tools/benchmark.py`, 3 runs, on the demo laptop (Windows 11, Intel64,
Python 3.12.10), recorded in `docs/benchmark-results.md` and `docs/benchmark-results-ai.md`.
Nothing here is estimated.

| | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| 50 alerts in → incidents | 5 | 5 | 5 |
| suppressed as noise | 22 | 22 | 22 |
| incidents needing a human | 1 | 1 | 1 |
| attack incident correct (exactly the 8 attack alerts, malicious) | yes | yes | yes |
| risk score | 90 | 90 | 90 |
| verdict became malicious at alert | #38 | #38 | #38 |
| `POST /alerts` median / p95 (ms) | 23.7 / 60.6 | 24.6 / 59.4 | 37.0 / 66.9 |
| model call latency, gemini-2.5-flash (ms) | 5688 | 7555 | 6659 |
| narrative ready after the last alert (ms) | 15464 | 10832 | 13310 |
| entities outside the incident in the AI text | 0 | 0 | 0 |

In scenario time, the incident becomes malicious 15.9 minutes after the first attack alert — at
the lateral logon (A6), before the discovery and shadow-copy deletion steps. The attack is fully
deterministic, so the outcome rows are identical across runs; latency varies with the machine and
the network. The AI rows are from the separate `--ai` run.

## 8. Stack and setup

Python 3.12, FastAPI, Uvicorn, Pydantic, httpx, `google-genai` with Gemini 2.5 Flash on Vertex
AI, plain HTML/CSS/JS (no build step, no external assets), pytest. State is in memory.

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env     # Vertex AI settings; leave empty for rules-only
.\run_demo.ps1
```

Vertex AI is the only external host the system contacts. The service-account file lives outside
the repository and `.env` is git-ignored. `docs/integration.md` describes how real sources and
response tools would plug in, and what a production deployment still needs (authentication,
persistence, incremental correlation, TLS).

## 9. AI used to build it

The project was built during the event with Claude Code. `docs/ai-usage.md` logs every task with
time, what was done and why, and has a column for my own review of each step. Two project agents
live in `.claude/agents/`:

- **auditor**: an independent, read-only reviewer that runs after every commit, reads the code
  rather than trusting commit messages, runs the tests and reports ranked findings. Its findings
  shaped the result. One malformed alert could freeze ingest for the rest of the demo. An offline
  fixture presented hand-written text as model output. Raw Vertex errors could have put the
  project name on the projector. A later fix had silently stopped flagging some invented
  domains. Each was fixed with a test.
- **ui-designer**: owns the panel only, works against the API contract, and reports what fields it
  needs instead of touching the backend.

Design notes written before the event, with no code, are in `docs/prep/`.

## 10. Tests

143 tests run in about 40 seconds with no network access; the model is replaced by a fake client.
They cover:

- the scenario's ground truth and the synthetic-only rule;
- every correlation rule and the maria.lopez trap;
- scoring and the exact signal breakdown of the attack;
- every API route, autonomy and approval;
- incident ids staying stable while the scenario is replayed one alert at a time;
- that no action ever runs twice;
- rollback of a bad alert;
- the AI trace, fallbacks, entity flags, and absence of secrets in errors;
- that the offline fixtures still match the backend.

A passing test is only evidence if it would fail on broken code. For each important rule I broke
the code on purpose and checked that the right test turned red:

- isolated failed logons treated as attack evidence;
- the scanned host used instead of the scanner;
- `unknown` alerts allowed to join by host;
- auto-closing anything without a technique;
- the ingest rollback removed;
- raw Vertex errors exposed;
- the reset guard on AI calls dropped.

Twice the test stayed green: the duplicate-AI-call and reset-during-call tests had the wrong
timing. Both were rewritten until they failed on the bug and passed on the fix.

## Limits, stated plainly

- **Simulated actions.** They are recorded, not sent to real EDR, proxy or directory tools.
- **No authentication.** `approved_by` is self-declared.
- **In-memory state.** It is lost on restart.
- **Re-correlation cost.** Every alert re-correlates all alerts. That is fine for a shift's worth of
  alerts in a demo, not for a production feed.
- **One scenario.** The rules were designed for it, and tested with hand-built cases beyond it.
- **Heuristic entity check.** It catches invented hosts, users, IPs, domains, times and dates, not
  every possible misstatement (for example a correct host with a wrong action attributed to it).
