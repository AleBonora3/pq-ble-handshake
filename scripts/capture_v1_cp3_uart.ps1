param(
    [string]$Port = 'COM8',
    [ValidateRange(1, 3600)][int]$Seconds = 180,
    [string]$Log = (Join-Path $PSScriptRoot '..\firmware\build_cp3_logs\dk-uart.log')
)
$ErrorActionPreference = 'Stop'
$serial = [System.IO.Ports.SerialPort]::new($Port, 115200, 'None', 8, 'One')
$serial.ReadTimeout = 200
$logStream = [System.IO.File]::Open($Log, [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
$capture = [System.IO.StreamWriter]::new($logStream, [System.Text.UTF8Encoding]::new($false))
$capture.AutoFlush = $true
try {
    $serial.Open()
    Write-Output "Capturing $Port at 115200 baud to $Log"
    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt $Seconds) {
        $data = $serial.ReadExisting()
        if ($data.Length -gt 0) {
            $capture.Write($data)
            [Console]::Write($data)
        }
        Start-Sleep -Milliseconds 100
    }
} finally {
    if ($serial.IsOpen) { $serial.Close() }
    $serial.Dispose()
    $capture.Dispose()
}
