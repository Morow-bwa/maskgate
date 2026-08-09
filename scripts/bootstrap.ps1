param(
  [switch]$SkipFrontend
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"

Set-Location -LiteralPath $projectRoot

if (-not (Test-Path -LiteralPath $venvPython)) {
  $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
  if ($pyLauncher) {
    & $pyLauncher.Source -3.12 -m venv .venv
  } else {
    $python = Get-Command python -ErrorAction Stop
    & $python.Source -m venv .venv
  }
}

& $venvPython -m pip install --upgrade "pip>=26.2.1"
& $venvPython -m pip install -e ".[dev,media]"

if (-not $SkipFrontend) {
  Push-Location -LiteralPath (Join-Path $projectRoot "playground-react")
  try {
    $pnpm = Get-Command pnpm -ErrorAction SilentlyContinue
    if ($pnpm) {
      & $pnpm.Source install --frozen-lockfile
      & $pnpm.Source build
    } else {
      $corepack = Get-Command corepack -ErrorAction Stop
      & $corepack.Source pnpm install --frozen-lockfile
      & $corepack.Source pnpm build
    }
  } finally {
    Pop-Location
  }
}

Write-Host "MaskGate dependencies and Playground are ready." -ForegroundColor Green
