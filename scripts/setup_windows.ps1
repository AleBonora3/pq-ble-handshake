# Setup Windows per PQ-BLE-HANDSHAKE
<#
.SYNOPSIS
    Installa tutte le dipendenze per PQ-BLE-HANDSHAKE su Windows.
    Richiede: Git, Python 3.10+, Visual Studio Build Tools 2022.

.DESCRIPTION
    1. Verifica Python, Git, CMake, VS Build Tools
    2. Installa dipendenze Python (bleak, cryptography, pytest...)
    3. Compila liboqs da sorgente con MSVC
    4. Installa liboqs-python (binding Python)
    5. Verifica che ML-KEM-768 funzioni

.EXAMPLE
    .\scripts\setup_windows.ps1
#>

param(
    [switch]$SkipBuildTools = $false,
    [switch]$SkipLibOqs = $false
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " PQ-BLE-HANDSHAKE — Windows Setup" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan

# ── Step 0: Check prerequisites ─────────────────────────────

Write-Host "`n[0/6] Verifica prerequisiti..." -ForegroundColor Yellow

# Python
try {
    $pyVer = python --version 2>&1
    Write-Host "  Python:   $pyVer" -ForegroundColor Green
} catch {
    Write-Host "  Python NON trovato. Installa da https://python.org" -ForegroundColor Red
    Write-Host "  Spunta 'Add Python to PATH' durante l'installazione." -ForegroundColor Red
    exit 1
}

# Git
try {
    $gitVer = git --version 2>&1
    Write-Host "  Git:      $gitVer" -ForegroundColor Green
} catch {
    Write-Host "  Git non trovato. Installa: winget install Git.Git" -ForegroundColor Red
    exit 1
}

# CMake
try {
    $cmakeVer = cmake --version 2>&1 | Select-Object -First 1
    Write-Host "  CMake:    $cmakeVer" -ForegroundColor Green
} catch {
    Write-Host "  CMake non trovato. Installa: winget install Kitware.CMake" -ForegroundColor Yellow
    Write-Host "  Oppure da: https://cmake.org/download/" -ForegroundColor Yellow
    if (-not $SkipBuildTools) {
        Write-Host "  Riavvia questo script dopo l'installazione." -ForegroundColor Yellow
        exit 1
    }
}

# Visual Studio Build Tools (cl.exe)
if (-not $SkipBuildTools) {
    $clPath = Get-Command cl.exe -ErrorAction SilentlyContinue
    if (-not $clPath) {
        # Try common VS 2022 paths
        $vsPaths = @(
            "${env:ProgramFiles}\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe",
            "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe",
            "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe"
        )
        $found = $false
        foreach ($p in $vsPaths) {
            $match = Get-ChildItem $p -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($match) {
                Write-Host "  MSVC:     $($match.FullName)" -ForegroundColor Green
                $found = $true
                break
            }
        }
        if (-not $found) {
            Write-Host "  Visual Studio Build Tools NON trovati." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Scarica da: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022" -ForegroundColor White
            Write-Host "  Durante l'installazione, seleziona:" -ForegroundColor White
            Write-Host "    ☑ Desktop development with C++" -ForegroundColor White
            Write-Host ""
            Write-Host "  Dopo l'installazione, riavvia questo script." -ForegroundColor Yellow
            Write-Host "  Oppure esegui con -SkipBuildTools se hai già MSVC in un path custom." -ForegroundColor Yellow
            exit 1
        }
    } else {
        Write-Host "  MSVC:     $clPath" -ForegroundColor Green
    }
} else {
    Write-Host "  MSVC:     skip (--SkipBuildTools)" -ForegroundColor DarkGray
}

# ── Step 1: Python virtual environment ──────────────────────

Write-Host "`n[1/6] Ambiente virtuale Python..." -ForegroundColor Yellow

if (-not (Test-Path "$RootDir\venv")) {
    python -m venv "$RootDir\venv"
    Write-Host "  Creato venv\" -ForegroundColor Green
} else {
    Write-Host "  venv già esistente" -ForegroundColor Green
}

# Activate
& "$RootDir\venv\Scripts\Activate.ps1"
Write-Host "  Ambiente attivato" -ForegroundColor Green

# ── Step 2: Python dependencies ─────────────────────────────

Write-Host "`n[2/6] Dipendenze Python..." -ForegroundColor Yellow
pip install --upgrade pip -q
pip install -r "$RootDir\requirements.txt" -q
Write-Host "  bleak, cryptography, matplotlib, pytest installati" -ForegroundColor Green

# ── Step 3: Clone liboqs ────────────────────────────────────

if (-not $SkipLibOqs) {
    Write-Host "`n[3/6] Download liboqs..." -ForegroundColor Yellow

    if (-not (Test-Path "$RootDir\liboqs")) {
        git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs.git "$RootDir\liboqs"
        Write-Host "  liboqs clonato" -ForegroundColor Green
    } else {
        Write-Host "  liboqs già presente" -ForegroundColor Green
    }

    # ── Step 4: Build liboqs ───────────────────────────────────

    Write-Host "`n[4/6] Compilazione liboqs (MSVC)..." -ForegroundColor Yellow
    Write-Host "  Questa operazione richiede 5-10 minuti..." -ForegroundColor DarkGray

    $liboqsBuildDir = "$RootDir\liboqs\build"
    New-Item -ItemType Directory -Force -Path $liboqsBuildDir | Out-Null

    Push-Location $liboqsBuildDir
    try {
        cmake .. -G "Visual Studio 17 2022" -A x64 `
            -DCMAKE_INSTALL_PREFIX="$RootDir\liboqs\install" `
            -DBUILD_SHARED_LIBS=ON `
            -DOQS_USE_OPENSSL=OFF
        if ($LASTEXITCODE -ne 0) { throw "CMake configure failed" }

        cmake --build . --config Release --parallel
        if ($LASTEXITCODE -ne 0) { throw "CMake build failed" }

        cmake --install . --config Release
        if ($LASTEXITCODE -ne 0) { throw "CMake install failed" }

        Write-Host "  liboqs compilata" -ForegroundColor Green
    } finally {
        Pop-Location
    }

    # ── Step 5: liboqs-python ─────────────────────────────────

    Write-Host "`n[5/6] Installazione liboqs-python..." -ForegroundColor Yellow

    # Set environment variables for liboqs-python to find our build
    $env:LIBOQS_INSTALL = "$RootDir\liboqs\install"
    $env:PATH = "$RootDir\liboqs\install\bin;$env:PATH"

    if (-not (Test-Path "$RootDir\liboqs-python")) {
        git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git "$RootDir\liboqs-python"
    }

    Push-Location "$RootDir\liboqs-python"
    try {
        # Tell liboqs-python where to find the DLL
        pip install -e . -q
        Write-Host "  liboqs-python installato" -ForegroundColor Green
    } finally {
        Pop-Location
    }
} else {
    Write-Host "`n[3/6] liboqs: skip (--SkipLibOqs)" -ForegroundColor DarkGray
    Write-Host "[4/6] liboqs build: skip" -ForegroundColor DarkGray
    Write-Host "[5/6] liboqs-python: skip" -ForegroundColor DarkGray
}

# ── Step 6: Verify installation ────────────────────────────

Write-Host "`n[6/6] Verifica installazione..." -ForegroundColor Yellow

$env:PATH = "$RootDir\liboqs\install\bin;$env:PATH"

python -c @"
import oqs
kem = oqs.KeyEncapsulation('ML-KEM-768')
pk = kem.generate_keypair()
ct, ss1 = kem.encap_secret(pk)
ss2 = kem.decap_secret(ct)
assert ss1 == ss2, 'ML-KEM FAILED'
print('ML-KEM-768 funzionante')
"@

if ($LASTEXITCODE -eq 0) {
    Write-Host "  ML-KEM-768 funzionante!" -ForegroundColor Green
} else {
    Write-Host "  ERRORE: ML-KEM-768 non funziona. Verifica che liboqs.dll sia nel PATH." -ForegroundColor Red
    Write-Host "  Prova: copy liboqs\install\bin\oqs.dll C:\Windows\System32\" -ForegroundColor Yellow
    exit 1
}

# ── Test BLE scan ──────────────────────────────────────────

Write-Host "`n  Test scan BLE (5 secondi)..." -ForegroundColor Yellow
python -c @"
import asyncio
from bleak import BleakScanner

async def scan():
    devices = await BleakScanner.discover(timeout=5.0)
    if devices:
        print(f'  Trovati {len(devices)} dispositivi BLE')
        for d in devices:
            name = d.name or '(senza nome)'
            print(f'    {name} — {d.address} (RSSI: {d.rssi})')
    else:
        print('  Nessun dispositivo trovato (normale). Lo scan funziona!')

asyncio.run(scan())
"@

if ($LASTEXITCODE -eq 0) {
    Write-Host "  BLE scan funzionante!" -ForegroundColor Green
} else {
    Write-Host "  BLE scan fallito. Verifica che il dongle USB sia inserito." -ForegroundColor Yellow
    Write-Host "  Su Windows non servono driver — bleak usa WinRT nativamente." -ForegroundColor Yellow
}

# ── Done ───────────────────────────────────────────────────

Write-Host ""
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Setup Windows completato!" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "Prossimi passi:" -ForegroundColor White
Write-Host "  1. Test:   python -m pytest tests/ -v" -ForegroundColor White
Write-Host "  2. Demo:   .\scripts\run_demo_windows.ps1" -ForegroundColor White
Write-Host "  3. Guida:  vedi docs\WINDOWS_GUIDE.md" -ForegroundColor White
Write-Host ""

# Persist environment for next sessions
@"
REM PQ-BLE-HANDSHAKE environment setup
REM Run this before working on the project: venv\Scripts\activate.bat
"@ | Out-File -FilePath "$RootDir\activate_env.bat" -Encoding ASCII

Write-Host "File 'activate_env.bat' creato. Eseguilo per attivare l'ambiente." -ForegroundColor DarkGray
