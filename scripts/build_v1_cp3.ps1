param(
    [ValidateSet('v1', 'v07')][string]$Profile = 'v1',
    [string]$NcsRoot = 'C:\ncs\v3.0.0',
    [string]$Toolchain = 'C:\ncs\toolchains\0b393f9e1b',
    [switch]$Incremental,
    [switch]$Flash,
    [string]$SerialNumber = '1057790967',
    [string]$BuildDirectory = '',
    [string]$LogDirectory = ''
)
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$vendorEnvironment = Get-Content -LiteralPath (Join-Path $Toolchain 'environment.json') | ConvertFrom-Json
foreach ($entry in $vendorEnvironment.env_vars) {
    $value = if ($entry.type -eq 'relative_paths') {
        ($entry.values | ForEach-Object { Join-Path $Toolchain $_ }) -join ';'
    } else { $entry.value }
    if ($entry.existing_value_treatment -eq 'prepend_to') {
        $value += ';' + [Environment]::GetEnvironmentVariable($entry.key, 'Process')
    }
    [Environment]::SetEnvironmentVariable($entry.key, $value, 'Process')
}
$env:ZEPHYR_BASE = Join-Path $NcsRoot 'zephyr'
$env:CCACHE_DISABLE = '1'
$buildName = if ($Profile -eq 'v1') { 'build_v1_cp3' } else { 'build_v07_cp3_check' }
$buildDir = Join-Path $repoRoot "firmware\$buildName"
$logDir = Join-Path $repoRoot 'firmware\build_cp3_logs'
if ($BuildDirectory) { $buildDir = [IO.Path]::GetFullPath($BuildDirectory) }
if ($LogDirectory) { $logDir = [IO.Path]::GetFullPath($LogDirectory) }
# west --pristine may recursively replace the build directory. Keep custom
# experiment targets within firmware/build* and outside any existing evidence.
$firmwareRoot = [IO.Path]::GetFullPath((Join-Path $repoRoot 'firmware')) + '\'
if (-not $buildDir.StartsWith($firmwareRoot, [StringComparison]::OrdinalIgnoreCase) -or
    -not ([IO.Path]::GetFileName($buildDir).StartsWith('build'))) {
    throw 'Build directory must be a firmware/build* directory in this checkout'
}
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$configArgs = @('-DCONF_FILE=prj.conf', '-DDEBUG_THREAD_INFO=Off', '-Dfirmware_DEBUG_THREAD_INFO=Off')
if ($Profile -eq 'v1') { $configArgs += '-DEXTRA_CONF_FILE=v1_smp_l4_mlkem.conf' }
else { $configArgs += '-DEXTRA_CONF_FILE=' }
# Windows PowerShell treats native stderr (including CMake status) as ErrorRecord.
# Judge the native exit code, rather than stopping on informational stderr.
$ErrorActionPreference = 'Continue'
$pristine = if ($Incremental) { 'never' } else { 'always' }
& (Join-Path $Toolchain 'opt\bin\Scripts\west.exe') build --build-dir $buildDir `
    (Join-Path $repoRoot 'firmware') --pristine=$pristine --board nrf54l15dk/nrf54l15/cpuapp -- @configArgs `
    2>&1 | ForEach-Object { $_.ToString() } | Tee-Object -FilePath (Join-Path $logDir "$Profile-build.log")
$buildExit = $LASTEXITCODE
if ($buildExit -ne 0) { exit $buildExit }
if ($Flash) {
    & (Join-Path $Toolchain 'opt\bin\Scripts\west.exe') flash --build-dir $buildDir `
        --runner nrfutil --dev-id $SerialNumber `
        2>&1 | ForEach-Object { $_.ToString() } | Tee-Object -FilePath (Join-Path $logDir "$Profile-flash.log")
    exit $LASTEXITCODE
}
exit 0
