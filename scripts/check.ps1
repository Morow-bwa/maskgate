param(
    [ValidateSet('context', 'doctor', 'check')]
    [string]$Command = 'check',
    [string]$Python,
    [switch]$Quick,
    [switch]$Frontend
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$projectRoot = Split-Path -Parent $PSScriptRoot
$venvPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
$originalPythonPath = $env:PYTHONPATH

try {
    if (-not $Python) {
        if (Test-Path -LiteralPath $venvPython) {
            & $venvPython -c 'import sys; print(sys.version)' 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { $Python = $venvPython }
        }
        if (-not $Python) {
            # Codex on Windows can retain a venv whose original Python was removed.
            # Reuse its packages without deleting/rebuilding the user's environment.
            $bundledPython = Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
            if ((Test-Path -LiteralPath $bundledPython) -and
                (Test-Path -LiteralPath (Join-Path $projectRoot '.venv\Lib\site-packages'))) {
                $Python = $bundledPython
                $env:PYTHONPATH = Join-Path $projectRoot '.venv\Lib\site-packages'
                Write-Host 'Using bundled Python with existing .venv packages.'
            } else {
                throw 'No working project Python. Run bootstrap.ps1 or pass -Python with a prepared interpreter.'
            }
        }
    }
    $harnessArgs = @((Join-Path $PSScriptRoot 'harness.py'), $Command)
    if ($Quick) { $harnessArgs += '--quick' }
    if ($Frontend) { $harnessArgs += '--frontend' }
    & $Python @harnessArgs
    $checkExitCode = $LASTEXITCODE
} finally {
    $env:PYTHONPATH = $originalPythonPath
}
exit $checkExitCode
