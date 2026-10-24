# Pitch — 2 minutos (objetivo 1:55)

Panel abierto con `run_demo.ps1`. El replay se dispara con un Enter en la terminal.
Habla mientras pasan cosas; el silencio parece fallo.

---

**[0:00–0:20] Opening**

> I worked as a level-2 support analyst. My job was to escalate alerts to the SOC, one at a
> time. The SOC received fragments: a failed login here, a strange process there. Nobody saw
> the story until it was too late. *[pausa]* That's the problem I wanted to fix.

**[0:20–0:30] Promise**

> This takes raw alerts from across the stack and turns them into one incident, with a
> timeline, a playbook, and the safe actions already done. Python, FastAPI, Gemini. Built today.

**[0:30–0:55] How it works**

> Correlation is deterministic: alerts are linked by what they share, the same host, a user
> moving between machines, the same attacker infrastructure, inside a time window. Every link
> has a written reason. Each alert maps to a MITRE ATT&CK technique and the incident is scored
> by how deep the kill chain goes. The AI reads the finished timeline and writes the story and
> the playbook. And here's the part CISOs asked for: the system acts on its own where the action
> is reversible, and asks a human where it isn't. Autonomy by blast radius, not by hype.

**[0:55–1:45] Demo**

> *[Enter]* Fifty alerts from four sources, arriving now. Scanners, failed logins, updates: noise.
> *[aparece el incidente del escáner]* The vulnerability scan gets grouped, scored benign, and
> closed by the system, with the reason written. No human needed.
> *[aparece el ataque]* And this one. Eight alerts, two hosts, two users. *[abres el detalle]*
> The kill chain lights up: phishing attachment, PowerShell, command and control, persistence,
> password spraying, lateral movement with a service account, shadow copies deleted. Ransomware
> about to fire. *[señalas acciones]* The system already blocked the domain and put both hosts on
> the watchlist, logged as system actions. *[señalas narrativa]* The AI wrote the narrative and the
> playbook. What's left is irreversible: isolate the hosts, disable the account. *[clic]* That's
> mine, recorded with my name and the time.

**[1:45–1:55] Close**

> Fifty alerts, one incident, safe actions done, in under a minute. The machine handles what can
> be undone. The analyst decides what can't. Thank you.

---

## Si algo falla en vivo
- **IA no responde:** "The rules already built the timeline and ran the safe actions; the AI layer is optional by design."
- **Replay no arranca:** `run_demo.ps1 -static` carga el escenario ya procesado; narra sobre el incidente formado.
- **Panel congelado:** `Ctrl+F5`. Habla del problema mientras carga.

## Preguntas probables
| Pregunta | Respuesta corta |
|---|---|
| "A SIEM / SOAR already does this." | "A SIEM groups by rules someone wrote; a SOAR runs playbooks someone wrote. Neither explains, and neither decides by blast radius. This is the layer they asked for on the slide: AI with the playbook, not bolted onto SOAR." |
| "Why not let the AI correlate or decide?" | "You can't audit a hunch. Rules leave a reason; the AI narrates. And the AI never executes: only catalog actions run, and only reversible ones run alone." |
| "What if the auto-action is wrong?" | "It's reversible by definition: unblock the domain, remove the watchlist. Everything the system did alone is in the audit log with its reason. The irreversible ones never ran without a person." |
| "Is the data real?" | "Synthetic scenario modelled on a typical pre-ransomware intrusion, mapped to ATT&CK. `.example` domains. The pipeline and the AI run live." |
| "How did you use AI to build it?" | "Claude Code for scaffolding and tests, logged in `docs/ai-usage.md` with what I reviewed. I wrote the correlator, scoring and the autonomy rules; ask me about any file." |
| "What's next?" | "Real ingestion from Defender or syslog, and the shift-handoff report so the next analyst inherits the story, not the fragments." |

## Ensayo
Tres veces con cronómetro. Si pasas de 2:00, recorta en "How it works", nunca apertura ni cierre.
