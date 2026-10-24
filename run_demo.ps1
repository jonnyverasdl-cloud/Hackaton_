<#
.SYNOPSIS
  Storyline demo launcher: backend + AI warm-up + panel + replay.

.DESCRIPTION
  1. Starts the backend (uvicorn) from the repo .venv in the background.
  2. Waits for GET /health, then POST /reset (clean state).
  3. AI warm-up: one real model call (tools/check_ai.py). If it fails, the demo
     still runs rules-only and says so.
  4. Opens the panel and prints READY FOR DEMO.
  5. Waits for Enter, then replays the synthetic scenario (40 min -> ~60 s).
  The backend keeps running after the script ends; stop it with -Stop.

.EXAMPLE
  .\run_demo.ps1                 # full demo
  .\run_demo.ps1 -NoAI           # rules only, no model calls
  .\run_demo.ps1 -Yes -Speed 80  # no Enter prompt, faster replay
  .\run_demo.ps1 -Stop           # stop the backend started by this script
#>
param(
  [int]$Port = 8000,
  [double]$Speed = 40,
  [switch]$NoAI,
  [switch]$NoBrowser,
  [switch]$NoReplay,
  [switch]$Yes,
  [switch]$Stop
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot
$Python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$Logs = Join-Path $PSScriptRoot "logs"
$PidFile = Join-Path $Logs "backend.pid"
$Base = "http://127.0.0.1:$Port"

function Say([string]$msg, [string]$color = "Gray") { Write-Host $msg -ForegroundColor $color }

function Stop-Backend {
  # The PID is a cmd.exe wrapper; /T also ends the venv launcher and the real python under it.
  if (Test-Path $PidFile) {
    $id = [int](Get-Content $PidFile)
    if (Get-Process -Id $id -ErrorAction SilentlyContinue) {
      & taskkill.exe /PID $id /T /F | Out-Null
      Say "Backend (PID $id and children) stopped." "Yellow"
    } else { Say "Backend PID $id was no longer running." "Yellow" }
    Remove-Item $PidFile -Force -Confirm:$false
  } else { Say "No backend started by this script is running." "Yellow" }
}

if ($Stop) { Stop-Backend; exit 0 }

if (-not (Test-Path $Python)) {
  Say "Missing .venv. Create it first:" "Red"
  Say "  py -3.12 -m venv .venv; .venv\Scripts\python.exe -m pip install -r requirements.txt"
  exit 1
}
New-Item -ItemType Directory -Force -Path $Logs | Out-Null

# --- 1. backend ---------------------------------------------------------------
$busy = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($busy) {
  $owner = (Get-Process -Id $busy[0].OwningProcess -ErrorAction SilentlyContinue).ProcessName
  Say "Port $Port is already in use by $owner (PID $($busy[0].OwningProcess))." "Red"
  Say "Run .\run_demo.ps1 -Stop if it is a previous demo, or pick another port with -Port 8010."
  exit 1
}
# Started through WMI so it is fully detached: it inherits no console or pipe from this
# script (a piped caller would otherwise wait forever) and keeps running after we exit.
$aiFlag = if ($NoAI) { "set AI_DISABLED=1&& " } else { "set AI_DISABLED=&& " }
$cmdLine = "cmd.exe /c `"$aiFlag`"$Python`" -m uvicorn backend.app.main:app --host 127.0.0.1 --port $Port " +
           "> `"$Logs\backend.out.log`" 2> `"$Logs\backend.err.log`"`""
$created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
  -Arguments @{ CommandLine = $cmdLine; CurrentDirectory = $PSScriptRoot }
if ($created.ReturnValue -ne 0) { Say "Could not start the backend (WMI code $($created.ReturnValue))." "Red"; exit 1 }
$backendPid = $created.ProcessId
Set-Content -Path $PidFile -Value $backendPid
Say "Backend starting on $Base (PID $backendPid), logs in logs\" "Cyan"

# --- 2. health + reset ------------------------------------------------------------
$health = $null
for ($i = 0; $i -lt 60; $i++) {
  try { $health = Invoke-RestMethod -Uri "$Base/health" -TimeoutSec 2; break } catch { Start-Sleep -Milliseconds 500 }
  if (-not (Get-Process -Id $backendPid -ErrorAction SilentlyContinue)) { break }
}
if (-not $health) {
  Say "Backend did not become healthy. Last lines of logs\backend.err.log:" "Red"
  if (Test-Path (Join-Path $Logs "backend.err.log")) { Get-Content (Join-Path $Logs "backend.err.log") -Tail 15 }
  Stop-Backend
  exit 1
}
Invoke-RestMethod -Uri "$Base/reset" -Method Post -TimeoutSec 5 | Out-Null
Say "Backend healthy: mode $($health.mode), model $($health.ai_model)." "Green"

# --- 3. AI warm-up -------------------------------------------------------------------
$aiLine = "AI: rules only (started with -NoAI)"
if (-not $NoAI) {
  if ($health.mode -ne "rules+ai") {
    $aiLine = "AI: rules only ($($health.ai.reason))"
  } else {
    Say "AI warm-up: one real model call on the synthetic incident..." "Cyan"
    $warm = & $Python (Join-Path $PSScriptRoot "tools\check_ai.py") 2>&1
    $warmLine = ($warm | Select-String -Pattern "generated_by:" | Select-Object -First 1)
    if ($LASTEXITCODE -eq 0) { $aiLine = "AI: live, $(($warmLine -replace '\s+prompt sha256.*$', '').ToString().Trim())" }
    else {
      $why = ($warm | Select-String -Pattern "Fallback reason:" | Select-Object -First 1)
      $aiLine = "AI: warm-up failed, panel will show rules-only summaries ($why)"
    }
  }
}

# --- 4. panel ----------------------------------------------------------------------------
$panel = "$Base/panel/"
if (-not $NoBrowser) { Start-Process $panel }
Say ""
Say "==============================================" "Green"
Say "  READY FOR DEMO" "Green"
Say "  Panel:   $panel" "Green"
Say "  Offline: $panel`?mock=1" "Green"
Say "  $aiLine" "Green"
Say "  Synthetic scenario, 50 alerts, replay x$Speed" "Green"
Say "==============================================" "Green"
Say ""

# --- 5. replay ------------------------------------------------------------------------------
if (-not $NoReplay) {
  if (-not $Yes) { Read-Host "Press Enter to start the replay" | Out-Null }
  & $Python (Join-Path $PSScriptRoot "tools\gen_scenario.py") --replay --speed $Speed --url $Base
  if ($LASTEXITCODE -ne 0) { Say "Replay failed (see output above)." "Red"; exit 1 }
  $final = Invoke-RestMethod -Uri "$Base/health" -TimeoutSec 5
  Say ("Replay done: {0} alerts -> {1} incidents, {2} suppressed as noise, {3} actions awaiting approval." -f `
    $final.counts.alerts, $final.counts.incidents, $final.counts.suppressed_noise, $final.counts.pending_approvals) "Green"
}
Say "Backend keeps running. Re-run the replay: click Reset in the panel, then"
Say "  .venv\Scripts\python.exe tools\gen_scenario.py --replay --speed $Speed --url $Base"
Say "Stop it: .\run_demo.ps1 -Stop"
