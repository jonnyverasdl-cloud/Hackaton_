# Brief for Claude Code — Alert Correlation & Incident Timeline

Paste this at 9:00. Everything is built today, from scratch, in this repo.

## Context
SOC hackathon (Alaris), 6 hours, solo participant. Task: **correlate raw security alerts into
incidents with a timeline**. Approach is "Audit-First": deterministic rules group and score;
the AI only writes the narrative and suggests actions. **Autonomy by blast radius**: the system
executes reversible actions on its own (logged with a reason), and waits for a human only on
irreversible ones. Benign incidents auto-close. Everything
user-facing is in **English** from the first file (IDs `INC-0001`, `ALT-000001`, labels, docs).

Design docs are in `docs/prep/` (read `01-escenario.md`, `02-esquema.md`,
`03-attack-mapping.md` first). They are specs, not code. Do not copy code from the
practice repo `Test_Hackaton`.

## Hard rules
1. Use the repo `.venv` only. Never touch the global Python.
2. No credentials in the repo. `.env` ignored, `.env.example` empty values.
3. Synthetic data only, `.example` domains, documentation IP ranges. Label it as synthetic in the UI.
4. No fabricated numbers. Timings are measured by `tools/benchmark.py`.
5. Log every task you do in `docs/ai-usage.md` (time, what, why). I fill the "human review" column.
6. Run tests after every task. Small commits with clear messages. I do the pushes.

## Layout
```
contracts/incident.schema.json   alert + incident schemas (from 02-esquema.md)
backend/app/normalizer.py        raw alert -> normalized alert, assigns event_type
backend/app/correlator.py        union-find over entities; rules with reasons
backend/app/scoring.py           signals -> risk_score, verdict (70/30 thresholds)
backend/app/attack.py            event_type -> tactic/technique table
backend/app/ai.py                Gemini via Vertex (google-genai); stub fallback
backend/app/main.py              FastAPI routes from 02-esquema.md, CORS, state in memory
panel/index.html                 plain HTML+JS, no build step
tools/gen_scenario.py            builds scenario.json; --replay posts alerts with compressed time
tools/benchmark.py               alerts in -> incident formed, 3 runs
tests/                           pytest
docs/                            writeup.md, ai-usage.md
run_demo.ps1                     starts backend, waits for /health, runs replay, opens panel
```

## Tasks, in order (stop after each and report)
1. **Setup + scenario.** venv, requirements (fastapi, uvicorn, pydantic, httpx, python-dotenv,
   google-genai, jsonschema, pytest), `.gitignore`, `.env.example`, schema, `gen_scenario.py`
   producing exactly the 8 attack alerts + noise from `01-escenario.md`. Test: 50 ± 5 alerts, 8 tagged `attack=true` in a hidden field used only by tests.
2. **Core.** normalizer, attack table, correlator, scoring. Tests: scenario → exactly one
   incident containing all 8 attack alerts and none of the noise; verdict malicious, score
   85–95; vuln scan forms its own incident, benign; the two early failed logons of
   `maria.lopez` are NOT in the attack incident.
3. **API + autonomy.** Routes per contract. Action catalog in `backend/app/actions.py` with a
   `reversible` flag (see `03-attack-mapping.md`). On incident creation/update: benign →
   `auto_closed`; reversible actions → executed by `system` with a reason, written to an audit
   log (`GET /audit`); irreversible → `pending` until `POST /incidents/{id}/approve`.
   Re-correlation must not re-execute an action twice. `--replay` works end to end. Tests with
   httpx ASGI client, schema validation, and: scanner incident auto-closes; attack incident has
   `block_domain` executed by system and `isolate_host` pending.
4. **Panel.** Alert queue (left), incidents (center), detail (right): horizontal ATT&CK chain
   that lights up per tactic covered, vertical timeline, correlation reasons, signals with
   points, AI block marked "AI-generated", actions panel with badges **auto-executed** (by system, with reason) and **awaiting approval**;
   approve button only for irreversible ones; a small `/audit` view listing what the system did alone.
   A visible "Synthetic scenario" label. Dark SOC style.
   Polls `/incidents` every 2 s during replay.
5. **AI.** `ai.py`: `genai.Client(vertexai=True, project, location)` from env; model from
   `AI_MODEL` default `gemini-2.5-flash`; 30 s timeout; strict JSON output; prompt forbids
   inventing entities not in the timeline; include today's date. Stub when no credentials.
   `tools/check_ai.py` warm-up.
6. **Finish.** `run_demo.ps1` with READY FOR DEMO; `benchmark.py`; `docs/writeup.md`
   (problem, solution, architecture, tech, synthetic data, measured results, responsible AI);
   fill `ai-usage.md`; README with Windows commands.
7. **Bonus only if told:** `GET /shift-report`.
