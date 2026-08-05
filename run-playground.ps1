$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonExe = Join-Path $projectRoot ".venv\Scripts\python.exe"
$bundledPython = "C:\Users\user\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$pnpmExe = "pnpm"
$bundledPnpm = "C:\Users\user\.cache\codex-runtimes\codex-primary-runtime\dependencies\bin\fallback\pnpm.cmd"

if (-not (Test-Path $pythonExe)) {
  if (Test-Path $bundledPython) {
    $pythonExe = $bundledPython
  } else {
    $pythonExe = "python"
  }
}
if (Test-Path $bundledPnpm) {
  $pnpmExe = $bundledPnpm
} else {
  $pnpmExe = "pnpm"
}

Set-Location $projectRoot

if (-not (Test-Path ".\playground-react\dist\index.html")) {
  Push-Location ".\playground-react"
  & $pnpmExe install
  & $pnpmExe build
  Pop-Location
}

Write-Host "MaskGate Playground: http://localhost:8080/playground" -ForegroundColor Green
Write-Host "Keep this terminal open. Press Ctrl+C to stop the local proxy." -ForegroundColor DarkGray
& $pythonExe -m uvicorn app.main:app --host 127.0.0.1 --port 8080
