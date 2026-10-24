# Mapeo alerta → MITRE ATT&CK y pesos del scoring

## Vocabulario de `event_type` y su técnica

| event_type | Táctica | Técnica | Pista para el normalizador |
|---|---|---|---|
| `email_attachment_macro` | Initial Access | T1566.001 | gateway: adjunto .docm/.xlsm/.js |
| `email_link_suspicious` | Initial Access | T1566.002 | gateway: URL a dominio nuevo |
| `office_spawn_shell` | Execution | T1059.001 | edr: parent WINWORD/EXCEL, child powershell/cmd/wscript |
| `encoded_powershell` | Execution | T1059.001 | edr: `-enc`, `-e `, `FromBase64String` |
| `outbound_new_domain` | Command and Control | T1071.001 | proxy: dominio < 30 días y sin categoría + host interno (la categoría sola no basta) |
| `scheduled_task_created` | Persistence | T1053.005 | edr: schtasks / TaskScheduler event |
| `registry_run_key` | Persistence | T1547.001 | edr: Run/RunOnce |
| `auth_spray` | Credential Access | T1110.003 | auth: ≥ 20 fallos, ≥ 5 cuentas, 1 origen, ≤ 5 min |
| `auth_failed` | (ruido salvo agregación) | — | auth: 1–3 fallos sueltos |
| `lateral_logon_new_source` | Lateral Movement | T1021.002 | auth: logon exitoso tipo 3/10 desde host nunca visto para ese usuario |
| `domain_discovery` | Discovery | T1087.002 | edr: `net group`, `net user /domain`, `nltest` |
| `shadow_copy_delete` | Impact | T1490 | edr: vssadmin delete shadows, wbadmin delete, bcdedit recoveryenabled no |
| `mass_file_rename` | Impact | T1486 | edr: > 100 renames con extensión nueva |
| `vuln_scan` | (ruido) | — | ids: origen = escáner conocido |
| `av_cleaned` | (ruido) | — | edr: detección ya remediada |
| `system_update` | (ruido) | — | edr: proceso firmado Microsoft |

El normalizador asigna `event_type` por reglas simples (regex sobre `vendor_rule`, proceso,
parent). Si no reconoce, `event_type = "unknown"` y la alerta no suma puntos pero sí puede
agruparse por entidad.

## Reglas de correlación (deterministas, cada una deja razón)

| Regla | Condición | Razón que escribe |
|---|---|---|
| `same_host_window` | Mismo `host`, Δt ≤ 30 min | "share host X within window" |
| `user_pivot` | Logon exitoso de usuario U en host B con `src_ip` = host A que ya está en un incidente | "U logon on B originated from A" |
| `shared_infra` | Mismo `domain` o `dst_ip` externo en ≥ 2 hosts | "both contacted D" |
| `same_user_window` | Mismo `user` en hosts distintos, Δt ≤ 15 min, y al menos una alerta no-ruido | "same user across hosts" |
| `noise_isolation` | `event_type` de ruido y origen = escáner/servicio conocido | se agrupa aparte, nunca con incidentes con técnicas |

Implementación sugerida: union-find sobre claves de entidad `host:X`, `user:U`, `domain:D`,
`ip:I`. Cada alerta se une a sus entidades; cada regla decide qué entidades se unen entre sí.
El componente conexo es el incidente. ~80 líneas.

**Notas de implementación (24-oct, tras auditoría):**
- `same_host_window` solo une alertas que **ambas** tienen técnica. El ruido (incluido `auth_failed`
  suelto) y `unknown` nunca se unen solo por host; `unknown` puede unirse por usuario
  (`same_user_window`) o infraestructura compartida (`shared_infra`).
- `noise_isolation` agrupa ruido del **mismo tipo en el mismo host** dentro de la ventana (no solo
  escáneres conocidos): así el escaneo, la impresora, los 2 fallos tempranos de `maria.lopez` y el
  adware quedan como incidentes benignos aparte.
- `user_pivot` solo une la alerta de logon con alertas con técnica del host origen dentro de la
  ventana anterior al logon.
- "Interno" = solo RFC 1918 (10/8, 172.16/12, 192.168/16). `203.0.113.0/24` cuenta como externo
  (Python `is_private` lo trata como privado, por eso no se usa).

## Scoring del incidente

| Señal | Puntos | Condición |
|---|---|---|
| Kill chain depth | 5 por táctica distinta, máx. 30 | tácticas cubiertas |
| Impact stage reached | 15 | alguna técnica T1490 / T1486 |
| Lateral movement | 15 | ≥ 2 hosts unidos por `user_pivot` o `shared_infra` |
| Privileged / service account | 10 | usuario empieza por `svc_` o está en lista de admins |
| C2 to new infrastructure | 5 | `outbound_new_domain` |
| Credential access | 10 | `auth_spray` |
| Initial access confirmed | 5 | técnica T1566.* |
| Volume (ruido no suma) | 0 | — |

Escenario esperado: 8 tácticas → 30 (tope) + 15 + 15 + 10 + 5 + 10 + 5 = **90**.
Pesos ajustados el 24-oct (antes 35/20/10 daban 105 → tope 100). El test exige 85–95.
El escaneo de vulnerabilidades: 0 tácticas, ruido → **0–10, benign**.

## Qué hace la IA (y qué no)

Entrada: el incidente ya agrupado, con timeline ordenado y técnicas asignadas. Nada más.
Salida JSON: `narrative` (cronológica, 5–8 frases, solo hechos del timeline), `hypothesis`
(una frase), `recommended_actions` (3–5, priorizadas, concretas: host, cuenta, dominio),
`confidence`.
Prohibido en el prompt: inventar hosts/usuarios/fechas no presentes; cambiar severidad.
Marcar en el panel: "AI-generated narrative — verify against timeline".

## Catálogo de acciones (simuladas) y su reversibilidad

| id | Acción | reversible | Se dispara cuando |
|---|---|---|---|
| `close_benign` | Cerrar incidente como benigno | sí | verdict benign **y** todas las alertas son ruido conocido (benign con técnica o `unknown` → `monitoring`) |
| `watchlist_host` | Añadir host(s) a watchlist 72 h | sí | suspicious o malicious |
| `tag_user` | Marcar usuario(s) para revisión | sí | suspicious o malicious |
| `block_domain` | Bloquear dominio/IP externo en proxy/DNS | sí | malicious con C2 |
| `collect_triage` | Pedir paquete de triage del host (procesos, conexiones) | sí | suspicious o malicious |
| `isolate_host` | Aislar host en EDR | **no** | malicious |
| `disable_account` | Deshabilitar cuenta y forzar reset | **no** | malicious con cuenta privilegiada o lateral |
| `kill_process` | Terminar proceso y borrar persistencia | **no** | malicious con persistencia |

Regla: `reversible: true` → el sistema lo ejecuta solo y lo registra. `reversible: false` →
queda `pending` hasta `/approve`. La IA puede *proponer* acciones extra, pero solo las del catálogo
se ejecutan; una acción propuesta fuera del catálogo se muestra como sugerencia, nunca se ejecuta.
