# AI usage log (event rule 3)

Tools: Claude Code (scaffolding, tests, review), Gemini 2.5 Flash via Vertex AI (inside the product: narrative + playbook only).

| Time | Tool | Task | Why | Human review (what I checked) |
|------|------|------|-----|-------------------------------|
|      |      |      |     |                               |

## AI inside the product
- Gemini reads a **finished** incident (timeline, techniques, entities) and returns narrative, hypothesis, recommended actions, confidence.
- It never correlates, never scores, never executes. Only catalog actions run; only reversible ones run without a human.
- Narrative is labeled "AI-generated — verify against timeline" in the panel.
