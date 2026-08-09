param(
  [int]$Port = 8080,
  [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $projectRoot

if (-not $SkipInstall) {
  & (Join-Path $projectRoot "scripts\bootstrap.ps1")
}

$pythonExe = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $pythonExe)) {
  throw "Python environment is missing. Run without -SkipInstall first."
}

Write-Host "MaskGate Playground: http://127.0.0.1:$Port/playground" -ForegroundColor Green
Write-Host "Press Ctrl+C to stop." -ForegroundColor DarkGray
& $pythonExe -m uvicorn app.main:app --host 127.0.0.1 --port $Port
