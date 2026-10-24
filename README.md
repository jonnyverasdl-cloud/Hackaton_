# Storyline — Alert Correlation & Incident Timeline

SOC hackathon (Alaris Security), 2026-10-24. Solo entry by Jonathan Veras. Built during the event.

Raw alerts from across the stack → one incident with a MITRE ATT&CK timeline, an AI-written
narrative and playbook, and safe actions already executed. **Audit-First**: deterministic rules
correlate and score; the AI only narrates and proposes; **autonomy by blast radius**: reversible
actions run on their own and are logged, irreversible ones wait for the analyst.

Design notes written before the event (no code) are in `docs/prep/`. Everything else in this
repo was written today. AI tooling used is logged in `docs/ai-usage.md`.
