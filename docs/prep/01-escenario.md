# Escenario de la demo — "Pre-ransomware intrusion at NovaBanco"

Marca ficticia: **NovaBanco** (`novabanco.example`). Todo dominio externo usa `.example`; IPs del
rango de documentación `203.0.113.0/24` (externo) y `10.20.0.0/16` (interno). Nada real.

Objetivo de la demo: entran ~50 alertas de 4 fuentes en 30 segundos. El sistema devuelve
**1 incidente de 8 alertas** (el ataque) y deja ~42 alertas de ruido fuera o en incidentes
menores. El incidente cubre 7 etapas de ATT&CK y sale **malicious**.

## El ataque (8 alertas, 20 minutos, 2 hosts, 2 usuarios)

| # | Hora | Fuente | Host | Usuario | Alerta | Técnica |
|---|---|---|---|---|---|---|
| A1 | 14:02 | email_gateway | WS-FIN-07 | maria.lopez | Email with macro-enabled attachment `Invoice_8841.docm` delivered from `billing@nb-suppliers.example` | T1566.001 Phishing: attachment |
| A2 | 14:06 | edr | WS-FIN-07 | maria.lopez | `WINWORD.EXE` spawned `powershell.exe -enc <base64>` | T1059.001 PowerShell |
| A3 | 14:07 | proxy | WS-FIN-07 | maria.lopez | Outbound HTTPS to `cdn-update-sync.example` (203.0.113.77), domain registered 2 days ago | T1071.001 Web protocols (C2) |
| A4 | 14:09 | edr | WS-FIN-07 | maria.lopez | Scheduled task `OneDriveSyncHelper` created pointing to `%APPDATA%\sync.exe` | T1053.005 Scheduled task |
| A5 | 14:15 | auth | WS-FIN-07 | (multiple) | 40 failed logons from WS-FIN-07 against 12 accounts in 90 s | T1110.003 Password spraying |
| A6 | 14:18 | auth | SRV-FILES-01 | svc_backup | Successful logon of `svc_backup` from WS-FIN-07 — first time from this host | T1021.002 SMB / lateral movement |
| A7 | 14:20 | edr | SRV-FILES-01 | svc_backup | `net group "Domain Admins" /domain` executed | T1087.002 Domain account discovery |
| A8 | 14:22 | edr | SRV-FILES-01 | svc_backup | `vssadmin delete shadows /all /quiet` executed | T1490 Inhibit system recovery |

**Entidades que unen las alertas:** host `WS-FIN-07` (A1–A5), usuario `svc_backup` + host origen
`WS-FIN-07` (A6 une los dos hosts), host `SRV-FILES-01` (A6–A8).
**Hipótesis que debe escribir la IA:** acceso inicial por phishing, C2, persistencia, spraying,
movimiento lateral con cuenta de servicio, borrado de shadow copies = preparación de ransomware.
**Acciones recomendadas esperadas:** aislar WS-FIN-07 y SRV-FILES-01; deshabilitar `svc_backup`
y forzar reset; bloquear `cdn-update-sync.example` y 203.0.113.77; buscar `sync.exe` en otros hosts.

## El ruido (~42 alertas en la misma ventana 13:50–14:30)

| Tipo | Cantidad | Fuente | Por qué NO debe unirse al ataque |
|---|---|---|---|
| Escaneo de vulnerabilidades programado desde `SCAN-01` a 20 hosts | 12 | ids | Host origen distinto, usuario de servicio `svc_nessus`, patrón conocido |
| Login fallido suelto (1–2 intentos) de usuarios normales | 10 | auth | Sin host del ataque, por debajo del umbral de spraying |
| Windows Update / reinicio programado | 6 | edr | Proceso firmado, hosts distintos |
| Antivirus detecta y limpia adware en `WS-MKT-03` | 2 | edr | Host distinto, ya remediado |
| Navegación a dominios de noticias con categoría "uncategorized" | 8 | proxy | Hosts distintos, dominios antiguos |
| Impresora con error de autenticación repetido | 4 | auth | Cuenta de impresora, host `PRN-02` |

**Trampa deliberada:** 2 de los logins fallidos sueltos son de `maria.lopez` desde su propio host
a las 13:55 (olvidó la contraseña). Están antes del ataque y no deben contar como spraying:
demuestra que la ventana de tiempo y el umbral importan.

**Incidente menor esperado:** el escaneo de `SCAN-01` puede agruparse como su propio incidente
(12 alertas, mismo host origen) y salir **benign/suspicious** porque la IP es un escáner conocido.
Eso es bueno para la demo: muestra que agrupa, no solo que detecta.

## Reproducción en vivo
`gen_scenario.py --replay --speed 40` emite las alertas por `POST /alerts` con el tiempo
comprimido (40 min reales → 60 s). El panel muestra la cola creciendo y el incidente formándose.
Modo `--dump` escribe `scenario.json` para tests y para la demo sin red.
