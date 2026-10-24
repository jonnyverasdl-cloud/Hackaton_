# Esquema común y contrato de incidente

## Alerta normalizada (lo que produce el normalizador para cualquier fuente)

```json
{
  "alert_id": "ALT-000123",
  "timestamp": "2026-10-30T14:06:12-06:00",
  "source": "edr | proxy | auth | email_gateway | ids",
  "vendor_rule": "Suspicious child process of Office app",
  "host": "WS-FIN-07",
  "user": "maria.lopez",
  "src_ip": "10.20.4.17",
  "dst_ip": "203.0.113.77",
  "domain": "cdn-update-sync.example",
  "process": "powershell.exe",
  "parent_process": "WINWORD.EXE",
  "event_type": "office_spawn_shell",
  "severity_raw": "medium",
  "raw": {}
}
```
Campos nulos permitidos. `event_type` es un vocabulario cerrado (ver `03-attack-mapping.md`);
es la llave para mapear a ATT&CK.

## Incidente (contrato backend ↔ panel)

```json
{
  "incident_id": "INC-0001",
  "status": "open | approved | closed",
  "verdict": "malicious | suspicious | benign",
  "risk_score": 87,
  "title": "Pre-ransomware intrusion via phishing on WS-FIN-07",
  "window": {"start": "...14:02", "end": "...14:22"},
  "entities": {"hosts": ["WS-FIN-07","SRV-FILES-01"], "users": ["maria.lopez","svc_backup"],
               "domains": ["cdn-update-sync.example"], "ips": ["203.0.113.77"]},
  "alerts": ["ALT-000101", "..."],
  "timeline": [
    {"timestamp": "...", "alert_id": "ALT-000101", "technique": "T1566.001",
     "tactic": "Initial Access", "summary": "Macro attachment delivered to maria.lopez"}
  ],
  "tactics_covered": ["Initial Access","Execution","Command and Control","Persistence",
                      "Credential Access","Lateral Movement","Discovery","Impact"],
  "correlation_reasons": [
    {"rule": "same_host_window", "detail": "A1–A5 share host WS-FIN-07 within 30 min"},
    {"rule": "user_pivot", "detail": "svc_backup logon on SRV-FILES-01 originated from WS-FIN-07"}
  ],
  "signals": [
    {"name": "Kill chain depth", "detail": "8 tactics covered", "points": 30},
    {"name": "Privileged account involved", "detail": "svc_backup", "points": 10}
  ],
  "ai": {
    "narrative": "At 14:02 ...",
    "hypothesis": "Pre-encryption stage of a ransomware intrusion",
    "recommended_actions": ["Isolate WS-FIN-07", "..."],
    "confidence": 0.9,
    "generated_by": "gemini-2.5-flash | stub"
  },
  "autonomy": "auto_closed | auto_contained | awaiting_approval",
  "actions": [
    {"id": "block_domain", "label": "Block cdn-update-sync.example at proxy/DNS", "reversible": true,
     "status": "executed", "executed_by": "system", "executed_at": "...", "reason": "malicious incident, reversible action"},
    {"id": "watchlist_host", "label": "Add WS-FIN-07 and SRV-FILES-01 to watchlist", "reversible": true,
     "status": "executed", "executed_by": "system", "executed_at": "...", "reason": "..."},
    {"id": "isolate_host", "label": "Isolate WS-FIN-07 and SRV-FILES-01 (EDR)", "reversible": false,
     "status": "pending", "executed_by": null, "executed_at": null, "reason": "irreversible: requires analyst"},
    {"id": "disable_account", "label": "Disable svc_backup and force reset", "reversible": false,
     "status": "pending", "executed_by": null, "executed_at": null, "reason": "irreversible: requires analyst"}
  ],
  "approved_by": null, "approved_at": null
}
```

Umbrales: malicious ≥ 70, suspicious 30–69, benign < 30. Mismos que la práctica.

## Rutas de la API
| Método | Ruta | Para qué |
|---|---|---|
| POST | `/alerts` | Ingesta de una alerta cruda (cualquier fuente); normaliza y re-correlaciona |
| GET | `/alerts` | Cola cruda (para mostrar el caos) |
| GET | `/incidents` | Lista con resumen |
| GET | `/incidents/{id}` | Incidente completo |
| POST | `/incidents/{id}/approve` | `{"approved_by": "..."}` → ejecuta las acciones **irreversibles** pendientes (simulado) |
| GET | `/audit` | Log de todo lo que el sistema hizo solo y por qué (auto-close, auto-contain) |
| GET | `/shift-report` | (bonus) resumen de incidentes abiertos para handoff |
| GET | `/health` | modo, modelo de IA, conteos |

## Autonomía por radio de impacto ("autonomy by blast radius")

| Veredicto | Qué hace el sistema solo | Qué espera al humano |
|---|---|---|
| benign | Cierra el incidente con razón escrita (`auto_closed`) | nada |
| suspicious | Ejecuta acciones reversibles: watchlist, captura extra, etiqueta (`auto_contained`) | nada, pero queda visible |
| malicious | Ejecuta acciones reversibles (bloquear dominio/IP en lista, watchlist) y prepara el playbook (`awaiting_approval`) | las irreversibles: aislar host, deshabilitar cuenta |

Todo lo que el sistema hace solo queda en `/audit` con `executed_by: system` y su `reason`.
Esa es la respuesta a "Audit-First con autonomía": actúa donde se puede deshacer; pregunta donde no.

**Implementado el 24-oct (tarea 3):**
- `autonomy: "monitoring"`: incidente benign que no es solo ruido conocido (p. ej. el ataque a
  mitad de replay, score 10–25, o actividad `unknown` agrupada). No se cierra solo ni ejecuta nada;
  espera más evidencia. Solo los benign de ruido puro pasan a `auto_closed`.
- `autonomy: "approved"` cuando el analista aprobó y no queda nada pendiente. Si un incidente
  cerrado se reabre, `close_benign` queda con `status: "reverted"` y razón.
- Cada acción lleva `scenario_time` (hora de la alerta que la disparó, la que muestra el panel) y
  `wall_time` = `executed_at` (reloj real). `/audit` guarda ambos (`scenario_time`, `at`) y `targets`.
- Ingesta todo-o-nada: timestamp sin zona horaria o ID que no sea `ALT-` + 6 dígitos → 422 sin
  tocar el estado. Los IDs asignados por el servidor usan `ALT-9xxxxx`.
- Cada acción lleva `targets` (hosts, usuarios, dominios...). Se ejecuta una vez por objetivo: si
  un host nuevo entra al incidente, solo se ejecuta para ese host (queda en `/audit`).
- Los IDs de incidente son estables al re-correlacionar; si dos se fusionan, queda el menor.
- `GET /alerts` añade `incident_id` y `suppressed`; `GET /audit` devuelve `entries` y
  `suppressed_noise` (`count`, `by_type`); `GET /health` devuelve `counts`
  (`alerts`, `incidents`, `suppressed_noise`, `pending_approvals`). `POST /reset` limpia el estado.
- `POST /alerts` ignora IDs repetidos (`duplicate: true`), así `--replay` se puede repetir.

**IA (tarea 5):** `ai` añade `trace` (`model`, `prompt_sha256`, `latency_ms`, `raw_response`,
`error`, `called_at`), `flags` (cada host/usuario/IP/dominio/hora/fecha que la IA menciona y no está
en el incidente: `{type, value, field}`) y `alerts_covered`. Timeout 30 s; sin credenciales, error,
timeout o JSON inválido → stub determinista (`generated_by: "stub"`). Cada llamada real al modelo
queda en `/audit` (`action: "ai_narrative"`, `executed_by: "ai:<modelo>"` o `"ai:stub"` si cayó al
stub). Los incidentes de ruido puro reciben el stub sin llamar al modelo. `/health` añade `ai`
(`mode`, `reason`, `calls`, `last_latency_ms`, `last_error`). La IA nunca cambia acciones.
`trace.error` y `/health.ai.last_error` llevan solo el **tipo** de excepción (p. ej.
`PermissionError`), el aviso de timeout o la razón del stub, nunca texto de Vertex; el texto completo de Vertex (puede nombrar proyecto o cuenta de servicio) va solo
al log del servidor. IDs `ALT-900000`+ reservados al servidor (422 si los manda un cliente). El panel
usa fuentes del sistema: el único host externo es Vertex AI. Fixtures del modo offline:
`tools/build_fixtures.py` (+ `tools/record_ai.py`, una llamada real grabada).
