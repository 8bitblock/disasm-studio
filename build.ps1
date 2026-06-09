<#
.SYNOPSIS
    Build DisasmStudio.sln with MSBuild (VS 2022/x64), no Developer Prompt needed.

.DESCRIPTION
    Locates MSBuild via vswhere, then builds the solution. Returns MSBuild's exit
    code so it composes in CI/scripts. On success, prints the output exe path.

.PARAMETER Configuration
    Release (default) or Debug.

.PARAMETER Platform
    x64 (default). The project is x64-only (vcpkg x64-windows-static triplet).

.PARAMETER Rebuild
    Clean then build (MSBuild /t:Rebuild) instead of an incremental build.

.PARAMETER Clean
    Clean only (MSBuild /t:Clean); no build.

.PARAMETER Verbosity
    MSBuild verbosity: quiet | minimal (default) | normal | detailed | diagnostic.

.EXAMPLE
    .\build.ps1
.EXAMPLE
    .\build.ps1 -Configuration Debug
.EXAMPLE
    .\build.ps1 -Rebuild -Verbosity normal
#>
[CmdletBinding()]
param(
    [ValidateSet('Release', 'Debug')] [string] $Configuration = 'Release',
    [ValidateSet('x64')]              [string] $Platform = 'x64',
    [switch] $Rebuild,
    [switch] $Clean,
    [ValidateSet('quiet', 'minimal', 'normal', 'detailed', 'diagnostic')]
    [string] $Verbosity = 'minimal'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$solution = Join-Path $root 'DisasmStudio.sln'
if (-not (Test-Path $solution)) { Write-Error "Solution not found: $solution"; exit 1 }

# --- Locate MSBuild via vswhere (ships with VS 2017+ installer) ----------------
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) {
    Write-Error "vswhere.exe not found. Install Visual Studio 2022 with the C++ workload."
    exit 1
}
$msbuild = & $vswhere -latest -requires Microsoft.Component.MSBuild `
                      -find 'MSBuild\**\Bin\MSBuild.exe' | Select-Object -First 1
if (-not $msbuild) {
    Write-Error "MSBuild not found. Install the 'Desktop development with C++' workload in VS 2022."
    exit 1
}

# --- Pick the target -----------------------------------------------------------
$target = if ($Clean) { 'Clean' } elseif ($Rebuild) { 'Rebuild' } else { 'Build' }

Write-Host "MSBuild : $msbuild"
Write-Host "Solution: $solution"
Write-Host "Config  : $Configuration|$Platform  (target: $target)`n"

& $msbuild $solution `
    "/t:$target" `
    "/p:Configuration=$Configuration" `
    "/p:Platform=$Platform" `
    /m `
    /nologo `
    "/v:$Verbosity"
$code = $LASTEXITCODE

if ($code -eq 0) {
    if ($target -ne 'Clean') {
        $exe = Join-Path $root "build\$Platform\$Configuration\DisasmStudio.exe"
        Write-Host "`nBuild succeeded -> $exe"
    } else {
        Write-Host "`nClean succeeded."
    }
} else {
    Write-Host "`nBuild FAILED (MSBuild exit code $code)." -ForegroundColor Red
}
exit $code
