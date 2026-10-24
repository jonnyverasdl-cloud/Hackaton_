# AI usage log (event rule 3)

Tools: Claude Code (scaffolding, tests, review), Gemini 2.5 Flash via Vertex AI (inside the product: narrative + playbook only).

| Time | Tool | Task | Why | Human review (what I checked) |
|------|------|------|-----|-------------------------------|
| 09:48–09:55 | Claude Code | Task 1 — setup + scenario: `.venv` (Python 3.12), pinned `requirements.txt`, `contracts/incident.schema.json` (alert + incident from 02-esquema.md), `tools/gen_scenario.py` (8 attack alerts + 42 noise, `--dump`/`--replay`), `scenario.json`, 20 pytest tests | Fixed data contract and a deterministic, synthetic scenario first, so core logic in task 2 can be tested against known ground truth | |
| 10:03 | Claude Code | Task 1 follow-up (audit #2, #5, #9): A5 spray no longer targets DC-01 (shared with printer noise); auth host rule documented; `rfc3339-validator` added so schema actually checks timestamps; `.gitignore` covers default-named key files | Auditor found these could merge noise into the attack, let bad timestamps pass schema tests, or leak a credentials file | |

## AI inside the product
- Gemini reads a **finished** incident (timeline, techniques, entities) and returns narrative, hypothesis, recommended actions, confidence.
- It never correlates, never scores, never executes. Only catalog actions run; only reversible ones run without a human.
- Narrative is labeled "AI-generated — verify against timeline" in the panel.
