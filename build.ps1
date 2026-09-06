<#
.SYNOPSIS
    Build DisasmStudio.sln with MSBuild (VS 2022/x64), no Developer Prompt needed.

.DESCRIPTION
    Locates MSBuild via vswhere, then builds the solution. Returns MSBuild's exit
    code so it composes in CI/scripts. The solution builds the private GameMaker
    helper first, embeds it into the executable, and verifies resource freshness
    before reporting success. Distribute DisasmStudio.exe; the build-output DLL
    is an embedding input, not a runtime sidecar dependency.

.PARAMETER Configuration
    Release (default) or Debug.

.PARAMETER Platform
    x64 (default). The project is x64-only (vcpkg x64-windows-static triplet).

.PARAMETER VisualStudioPath
    Optional Visual Studio installation root. When omitted, an existing
    VCPKG_VISUAL_STUDIO_PATH is respected; otherwise vswhere selects the latest
    complete VS2022 C++ instance. No edition or installation path is hardcoded.

.PARAMETER VcpkgRoot
    Optional vcpkg checkout used by MSBuild. CI passes its pinned repo-local
    checkout; local builds may continue to use their integrated vcpkg root.

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
    [string] $VisualStudioPath,
    [string] $VcpkgRoot,
    [switch] $Rebuild,
    [switch] $Clean,
    [ValidateSet('quiet', 'minimal', 'normal', 'detailed', 'diagnostic')]
    [string] $Verbosity = 'minimal'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$solution = Join-Path $root 'DisasmStudio.sln'
if (-not (Test-Path $solution)) { Write-Error "Solution not found: $solution"; exit 1 }

# --- Resolve one VS instance for both MSBuild and vcpkg ------------------------
$selectedVisualStudio = $VisualStudioPath
if (-not $selectedVisualStudio) {
    $selectedVisualStudio = $env:VCPKG_VISUAL_STUDIO_PATH
}
if (-not $selectedVisualStudio) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) {
        Write-Error "vswhere.exe not found. Install Visual Studio 2022 with the C++ workload or pass -VisualStudioPath."
        exit 1
    }
    $selectedVisualStudio = & $vswhere `
        -latest `
        -version '[17.0,18.0)' `
        -products * `
        -requires Microsoft.Component.MSBuild Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
        -property installationPath | Select-Object -First 1
}
if (-not $selectedVisualStudio) {
    Write-Error "A complete VS2022 C++ installation was not found. Install the Desktop development with C++ workload."
    exit 1
}
$selectedVisualStudio = [IO.Path]::GetFullPath($selectedVisualStudio).TrimEnd([char[]]'\/')
$msbuild = Join-Path $selectedVisualStudio 'MSBuild\Current\Bin\MSBuild.exe'
if (-not (Test-Path -LiteralPath $msbuild)) {
    Write-Error "MSBuild was not found in the selected Visual Studio instance: $selectedVisualStudio"
    exit 1
}

$toolsetVersion = $env:DS_VCPKG_PLATFORM_TOOLSET_VERSION
if (-not $toolsetVersion) {
    $toolsetMarker = Join-Path $selectedVisualStudio 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.v143.default.txt'
    if (-not (Test-Path -LiteralPath $toolsetMarker)) {
        Write-Error "The selected Visual Studio instance does not provide the v143 default-toolset marker: $toolsetMarker"
        exit 1
    }
    $toolsetVersion = (Get-Content -LiteralPath $toolsetMarker -TotalCount 1).Trim()
}
if ($toolsetVersion -notmatch '^14\.[0-9]+(\.[0-9]+)?$') {
    Write-Error "Invalid v143 toolset version: '$toolsetVersion'"
    exit 1
}
$compiler = Join-Path $selectedVisualStudio "VC\Tools\MSVC\$toolsetVersion\bin\Hostx64\x64\cl.exe"
if (-not (Test-Path -LiteralPath $compiler)) {
    Write-Error "The selected Visual Studio instance does not contain v143 ${toolsetVersion}: $selectedVisualStudio"
    exit 1
}

$resolvedVcpkgRoot = $null
if ($VcpkgRoot) {
    $candidateVcpkgRoot = if ([IO.Path]::IsPathRooted($VcpkgRoot)) {
        $VcpkgRoot
    } else {
        Join-Path $root $VcpkgRoot
    }
    $resolvedVcpkgRoot = [IO.Path]::GetFullPath($candidateVcpkgRoot).TrimEnd([char[]]'\/')
    if (-not (Test-Path -LiteralPath (Join-Path $resolvedVcpkgRoot 'vcpkg.exe'))) {
        Write-Error "vcpkg.exe was not found under VcpkgRoot: $resolvedVcpkgRoot"
        exit 1
    }
}

# --- Pick the target -----------------------------------------------------------
$target = if ($Clean) { 'Clean' } elseif ($Rebuild) { 'Rebuild' } else { 'Build' }

Write-Host "MSBuild : $msbuild"
Write-Host "VS root : $selectedVisualStudio"
Write-Host "v143    : $toolsetVersion"
if ($resolvedVcpkgRoot) { Write-Host "vcpkg   : $resolvedVcpkgRoot" }
Write-Host "Solution: $solution"
Write-Host "Config  : $Configuration|$Platform  (target: $target)`n"

$arguments = @(
    $solution,
    "/t:$target",
    "/p:Configuration=$Configuration",
    "/p:Platform=$Platform",
    "/p:VCToolsVersion=$toolsetVersion",
    '/m',
    '/nologo',
    "/v:$Verbosity"
)
if ($resolvedVcpkgRoot) {
    $arguments += "/p:VcpkgRoot=$resolvedVcpkgRoot\"
}

$oldVcpkgVsPath = [Environment]::GetEnvironmentVariable('VCPKG_VISUAL_STUDIO_PATH', 'Process')
$oldVcpkgToolset = [Environment]::GetEnvironmentVariable('DS_VCPKG_PLATFORM_TOOLSET_VERSION', 'Process')
try {
    [Environment]::SetEnvironmentVariable('VCPKG_VISUAL_STUDIO_PATH', $selectedVisualStudio, 'Process')
    [Environment]::SetEnvironmentVariable('DS_VCPKG_PLATFORM_TOOLSET_VERSION', $toolsetVersion, 'Process')
    & $msbuild @arguments
    $code = $LASTEXITCODE
} finally {
    [Environment]::SetEnvironmentVariable('VCPKG_VISUAL_STUDIO_PATH', $oldVcpkgVsPath, 'Process')
    [Environment]::SetEnvironmentVariable('DS_VCPKG_PLATFORM_TOOLSET_VERSION', $oldVcpkgToolset, 'Process')
}

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
