# Windows Demo Script — Avvia il Central (BLE client)
<#
.SYNOPSIS
    Avvia il central PQ-BLE su Windows. Il peripheral deve girare su nRF54L15 o VM Linux.
.DESCRIPTION
    Su Windows, solo il ruolo CENTRAL funziona (bleak supporta GATT client via WinRT).
    Il PERIPHERAL (GATT server) NON funziona su Windows — va eseguito su nRF54L15 o VM Linux.
    Per il setup completo vedi docs/WINDOWS_GUIDE.md
#>

$RootDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " PQ-BLE-HANDSHAKE — Central (Windows)" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "ATTENZIONE: questo avvia solo il CENTRAL." -ForegroundColor Yellow
Write-Host "Il PERIPHERAL deve essere in esecuzione su:" -ForegroundColor Yellow
Write-Host "  - nRF54L15 DK (firmware embedded)" -ForegroundColor White
Write-Host "  - VM Linux (VirtualBox con Ubuntu)" -ForegroundColor White
Write-Host "  - Secondo PC Linux / Raspberry Pi" -ForegroundColor White
Write-Host ""

$continue = Read-Host "Il peripheral è attivo? Premi INVIO per continuare (Ctrl+C per uscire)"

# Activate venv if it exists
if (Test-Path "$RootDir\venv\Scripts\Activate.ps1") {
    & "$RootDir\venv\Scripts\Activate.ps1"
}

# Ensure liboqs DLL is findable
if (Test-Path "$RootDir\liboqs\install\bin") {
    $env:PATH = "$RootDir\liboqs\install\bin;$env:PATH"
}

# Run central
Set-Location $RootDir
python -m src.central.main
