# Plan de 6 horas (solo)

Principio: a cada hora hay algo que funciona de punta a punta, aunque sea feo.
A las 14:00 se congela el alcance. Lo que no está integrado, se recorta.

| Hora | Bloque | Entregable al final del bloque | Si vas tarde |
|---|---|---|---|
| 9:00–9:30 | Setup | Repo en GitHub (privado), `.venv`, `.env` con Vertex, `.gitignore`, esquema en `contracts/`, `gen_scenario.py` que escribe `scenario.json` con las 8 alertas del ataque + ruido | Menos ruido (20 en vez de 42) |
| 9:30–11:00 | Núcleo | `normalizer.py`, `correlator.py` (union-find), `scoring.py`. Test: el escenario produce 1 incidente malicious de 8 alertas y el escaneo queda aparte | Quitar `shared_infra` y `same_user_window`; con `same_host_window` + `user_pivot` basta para la demo |
| 11:00–12:00 | API + autonomía | FastAPI con las rutas del contrato; catálogo de acciones con `reversible`; benign auto-close, reversibles auto-ejecutadas con razón en `/audit`, irreversibles esperan `/approve`; `gen_scenario.py --replay` alimentando `POST /alerts` | Replay sin velocidad variable; `/audit` como lista simple |
| 12:00–12:30 | Almuerzo | Comer. Pensar el pitch, no codear | |
| 12:30–14:00 | Panel | Cola de alertas + lista de incidentes + detalle con **cadena ATT&CK horizontal** que se enciende, timeline vertical, razones, panel de acciones con badges **auto-executed** / **awaiting approval**, botón aprobar solo para las irreversibles, y una vista `/audit`. HTML+JS plano (sin build) para no perder tiempo | Quitar la cola cruda; mostrar solo incidentes |
| 14:00–14:45 | IA | `ai.py` con Gemini (Vertex) → narrativa, hipótesis, acciones. Stub si falla. Marcar "AI-generated" | Stub determinista: narrativa armada con plantillas desde el timeline |
| 14:45–15:15 | Cierre | `run_demo.ps1`, benchmark (alertas → incidente en X s), write-up, `ai-usage.md`, README, push | Write-up mínimo: problema, solución, arquitectura, tecnologías, datos sintéticos, IA |
| 15:15–15:30 | Ensayo | Pitch 2 veces con cronómetro y la demo corriendo | |
| 15:30–15:45 | Entrega | Submit | |

## Puntos de corte
- **11:00:** si el correlador no agrupa el escenario, no sigas al API; arregla eso primero. Sin correlador no hay proyecto.
- **14:00:** si el panel no muestra el timeline, la IA espera. Un timeline sin narrativa se entiende; una narrativa sin timeline no.
- **12:00:** si la autonomía por reversibilidad no está, déjala como flag en el JSON y píntala en el panel; la lógica de auto-ejecución puede ser 20 líneas a las 14:30.
- **15:00:** si la IA no responde, stub y punto. Dilo en el pitch: "rules did this; the AI layer is optional by design".

## Bonus (solo si a las 14:30 todo lo anterior está)
- `GET /shift-report`: resumen de incidentes abiertos para el handoff de turno.
- Exportar el incidente como PDF/Markdown.

## Log de IA (regla 3)
Mantén `docs/ai-usage.md` abierto y anota cada vez que CC termina algo: hora, qué pidió, qué revisaste tú. Dos minutos cada vez; al final cuesta veinte.
