# AI usage log (event rule 3)

Tools: Claude Code (scaffolding, tests, review), Gemini 2.5 Flash via Vertex AI (inside the product: narrative + playbook only).

| Time | Tool | Task | Why | Human review (what I checked) |
|------|------|------|-----|-------------------------------|
| 09:48–09:55 | Claude Code | Task 1 — setup + scenario: `.venv` (Python 3.12), pinned `requirements.txt`, `contracts/incident.schema.json` (alert + incident from 02-esquema.md), `tools/gen_scenario.py` (8 attack alerts + 42 noise, `--dump`/`--replay`), `scenario.json`, 20 pytest tests | Fixed data contract and a deterministic, synthetic scenario first, so core logic in task 2 can be tested against known ground truth | |
| 10:03 | Claude Code | Task 1 follow-up (audit #2, #5, #9): A5 spray no longer targets DC-01 (shared with printer noise); auth host rule documented; `rfc3339-validator` added so schema actually checks timestamps; `.gitignore` covers default-named key files | Auditor found these could merge noise into the attack, let bad timestamps pass schema tests, or leak a credentials file | |
| 10:04 | Claude Code | Spec edits from audit: 02-esquema.md alert example uses `office_spawn_shell` and privileged signal = 10 pts; 03-attack-mapping.md scoring weights set to the agreed 30/15/15/10/5/10/5 (attack ≈ 90) and `outbound_new_domain` requires new AND uncategorized; auditor.md points at `_truth` and root `scenario.json` | Keep the design specs consistent with the agreed weights and with what the code actually does | |

## AI inside the product
- Gemini reads a **finished** incident (timeline, techniques, entities) and returns narrative, hypothesis, recommended actions, confidence.
- It never correlates, never scores, never executes. Only catalog actions run; only reversible ones run without a human.
- Narrative is labeled "AI-generated — verify against timeline" in the panel.
