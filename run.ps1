# =============================================================================
# CryptAudio-Web — Local Application Launcher (Windows PowerShell)
# =============================================================================

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "              CryptAudio-Web Local Launcher               " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$PythonExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"

# 1. Verify virtual environment exists
if (-not (Test-Path $PythonExe)) {
    Write-Host "[ERROR] Virtual environment not found at .venv" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please create the virtual environment and install dependencies:" -ForegroundColor Yellow
    Write-Host "  python -m venv .venv" -ForegroundColor White
    Write-Host "  .\.venv\Scripts\python.exe -m pip install -r requirements.txt" -ForegroundColor White
    Write-Host ""
    Exit 1
}

# 2. Verify dependencies are importable
Write-Host "[*] Checking required dependencies..." -ForegroundColor Gray
$VerifyCommand = "$PythonExe -c ""import fastapi, uvicorn, cryptography, numpy, wave; print('OK')"""
try {
    $Result = Invoke-Expression $VerifyCommand
    if ($Result -ne "OK") {
        throw "Dependency check failed."
    }
    Write-Host "[✔] Dependencies verified successfully." -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Required packages are missing in .venv." -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install dependencies:" -ForegroundColor Yellow
    Write-Host "  .\.venv\Scripts\python.exe -m pip install -r requirements.txt" -ForegroundColor White
    Write-Host ""
    Exit 1
}

# 3. Start local Uvicorn server on loopback interface
Write-Host ""
Write-Host "[*] Starting CryptAudio-Web on http://127.0.0.1:8000" -ForegroundColor Cyan
Write-Host "    Press Ctrl+C to stop the server." -ForegroundColor Gray
Write-Host ""

& $PythonExe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
