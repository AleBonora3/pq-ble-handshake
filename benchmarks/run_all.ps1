param(
    [int]$HandshakeIterations = 1000,
    [int]$HandshakeWarmup = 20,
    [int]$ThroughputTrials = 5,
    [int]$FragmentationIterations = 10000
)

$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

$BenchmarkDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $BenchmarkDir
$ResultsDir = Join-Path $BenchmarkDir "results"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

New-Item -ItemType Directory -Force -Path $ResultsDir | Out-Null
Push-Location $ProjectRoot

try {
    $env:PYTHONPATH = $ProjectRoot

    function Save-Utf8 {
        param([string]$Path, [string]$Content)
        [System.IO.File]::WriteAllText($Path, $Content, $Utf8NoBom)
    }

    function Run-Benchmark {
        param(
            [string]$Name,
            [string]$Script,
            [string[]]$Arguments
        )

        Write-Host ""
        Write-Host "============================================================"
        Write-Host $Name
        Write-Host "============================================================"

        $pythonArgs = @("-X", "utf8", $Script) + $Arguments
        $lines = & python @pythonArgs 2>&1 | ForEach-Object {
            $line = $_.ToString()
            Write-Host $line
            $line
        }

        if ($LASTEXITCODE -ne 0) {
            throw "$Name failed with exit code $LASTEXITCODE"
        }

        $content = ($lines -join [Environment]::NewLine) +
            [Environment]::NewLine
        Save-Utf8 `
            -Path (Join-Path $ResultsDir "$Name.txt") `
            -Content $content
        return $content
    }

    $gitCommit = (& git rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -ne 0) {
        $gitCommit = "unavailable"
    }

    $pythonVersion = (& python --version 2>&1 | Out-String).Trim()
    $pipFreeze = (& python -m pip freeze 2>&1 | Out-String).Trim()
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $os = Get-CimInstance Win32_OperatingSystem
    $ramGb = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)

    $environment = @"
PQ-BLE-HANDSHAKE benchmark environment
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss K")
Git commit: $gitCommit
Python: $pythonVersion
OS: $($os.Caption) $($os.Version)
CPU: $($cpu.Name)
Logical processors: $($cpu.NumberOfLogicalProcessors)
RAM: $ramGb GB

Installed Python packages:
$pipFreeze
"@

    Save-Utf8 `
        -Path (Join-Path $ResultsDir "environment.txt") `
        -Content $environment

    $handshake = Run-Benchmark `
        -Name "handshake" `
        -Script "benchmarks\benchmark_handshake.py" `
        -Arguments @(
            "--iterations", "$HandshakeIterations",
            "--warmup", "$HandshakeWarmup"
        )

    $throughput = Run-Benchmark `
        -Name "throughput" `
        -Script "benchmarks\benchmark_throughput.py" `
        -Arguments @("--trials", "$ThroughputTrials")

    $fragmentation = Run-Benchmark `
        -Name "fragmentation" `
        -Script "benchmarks\benchmark_fragmentation.py" `
        -Arguments @("--iterations", "$FragmentationIterations")

    $latest = @"
$environment

============================================================
HANDSHAKE
============================================================
$handshake
============================================================
THROUGHPUT
============================================================
$throughput
============================================================
FRAGMENTATION
============================================================
$fragmentation
"@

    Save-Utf8 `
        -Path (Join-Path $ResultsDir "latest.txt") `
        -Content $latest

    Write-Host ""
    Write-Host "============================================================"
    Write-Host "All benchmarks completed."
    Write-Host "Results: $ResultsDir"
    Write-Host "============================================================"
    Get-ChildItem $ResultsDir |
        Select-Object Name, Length, LastWriteTime
}
finally {
    Pop-Location
}
