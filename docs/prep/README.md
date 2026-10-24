# Kit de preparación — Hackathon Alaris SOC (evento real)

Proyecto: **Alert Correlation & Incident Timeline** ("Storyline" como nombre de trabajo).
Una tarea del SOC: convertir alertas sueltas en incidentes con historia.

Este kit es DISEÑO, no código (regla 2: el código se escribe durante el evento).
Léelo la noche anterior; a las 9:00 arrancas construyendo, no pensando.

| Archivo | Qué es | Cuándo usarlo |
|---|---|---|
| `01-escenario.md` | El ataque sintético de la demo, paso a paso, más el ruido | Al diseñar `gen_scenario.py` (9:00) |
| `02-esquema.md` | Esquema común de alerta y contrato de incidente | Primeros 20 minutos |
| `03-attack-mapping.md` | Tabla alerta → técnica MITRE ATT&CK y pesos del scoring | Al escribir el correlador y el scoring |
| `04-plan-6h.md` | Cronograma por bloques con puntos de corte | Todo el día |
| `05-cc-brief.md` | Brief para Claude Code, listo para pegar | 9:00 |
| `06-pitch.md` | Guion de 2 minutos con tiempos y preguntas probables | Ensayar antes; 15:15 |
| `07-lecciones.md` | Lo que aprendimos en la práctica | Leer la noche anterior |
| `scenario.json` | El escenario en JSON (datos sintéticos) | Ver nota abajo |

## Sobre `scenario.json`
Son datos sintéticos (regla 5 los permite), no código. Pero la regla 2 es estricta con
"pre-existing projects". **Pregunta a los organizadores en el briefing** si se permiten datos
de prueba preparados. Si dicen que no, el archivo `01-escenario.md` tiene la tabla: se
reescribe en 10 minutos durante el evento.

## Antes del evento
- [ ] Preguntar a los organizadores: ¿datos sintéticos preparados? ¿participación solo confirmada?
- [ ] Laptop con Python 3.12, Node (si harás el panel con Vite), Playwright NO hace falta esta vez
- [ ] `.env` de prueba con las credenciales de Vertex AI (proyecto, location, service account) probado con una llamada
- [ ] Gemini: `google-genai` instalado y probado la noche anterior
- [ ] Ensayar el pitch 3 veces con cronómetro
- [ ] Cargador, agua, el escenario impreso o en el teléfono

## Ajuste del 24-oct (briefing de Alaris)
Las slides pidieron más autonomía: "AI SOC with our playbooks, not bolted onto SOAR",
"one operating surface for humans, workflows and agents". Respuesta integrada en el kit:
**autonomía por radio de impacto**. Benign se cierra solo; acciones reversibles se ejecutan
solas con razón en `/audit`; irreversibles esperan al analista. Ver `02-esquema.md` (sección
final), `03-attack-mapping.md` (catálogo de acciones), `04-plan-6h.md` (bloque 11:00) y `06-pitch.md`.
Frase clave: "Autonomy by blast radius, not by hype."
