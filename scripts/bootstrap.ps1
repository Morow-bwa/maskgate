param(
  [switch]$SkipFrontend
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"

Set-Location -LiteralPath $projectRoot

function Assert-NativeSuccess([string]$Step) {
  if ($LASTEXITCODE -ne 0) {
    throw "$Step failed (exit $LASTEXITCODE). Dependencies are not ready."
  }
}

if (-not (Test-Path -LiteralPath $venvPython)) {
  $pyLauncher = Get-Command py -ErrorAction SilentlyContinue
  if ($pyLauncher) {
    & $pyLauncher.Source -3.12 -m venv .venv
    Assert-NativeSuccess 'Create virtual environment'
  } else {
    $python = Get-Command python -ErrorAction Stop
    & $python.Source -m venv .venv
    Assert-NativeSuccess 'Create virtual environment'
  }
}

& $venvPython -c "import sys; print(sys.version)"
Assert-NativeSuccess 'Check venv Python; its original interpreter may have been removed'
& $venvPython -m pip install --upgrade "pip>=26.2.1"
Assert-NativeSuccess 'Upgrade pip'
& $venvPython -m pip install -e ".[dev,media]"
Assert-NativeSuccess 'Install Python dependencies'

if (-not $SkipFrontend) {
  Push-Location -LiteralPath (Join-Path $projectRoot "playground-react")
  try {
    $pnpm = Get-Command pnpm -ErrorAction SilentlyContinue
    if ($pnpm) {
      & $pnpm.Source install --frozen-lockfile
      Assert-NativeSuccess 'Install frontend dependencies'
      & $pnpm.Source build
      Assert-NativeSuccess 'Build frontend'
    } else {
      $corepack = Get-Command corepack -ErrorAction Stop
      & $corepack.Source pnpm install --frozen-lockfile
      Assert-NativeSuccess 'Install frontend dependencies'
      & $corepack.Source pnpm build
      Assert-NativeSuccess 'Build frontend'
    }
  } finally {
    Pop-Location
  }
}

Write-Host "MaskGate dependencies and Playground are ready." -ForegroundColor Green
