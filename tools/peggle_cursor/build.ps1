param(
    [switch]$ProbeOnly,
    [ValidatePattern('^[A-Za-z0-9_-]+$')][string]$BuildFolder = 'peggle_cursor'
)
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vs = & $vswhere -latest -version '[17.0,18.0)' -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw 'Visual Studio 2022 C++ tools required.' }
$version = (Get-Content -LiteralPath (Join-Path $vs 'VC/Auxiliary/Build/Microsoft.VCToolsVersion.v143.default.txt') -TotalCount 1).Trim()
$vcvars = Join-Path $vs 'VC/Auxiliary/Build/vcvars64.bat'
$environmentLines = & $env:ComSpec /d /c ('call "' + $vcvars + '" -vcvars_ver=' + $version + ' >nul && set')
if ($LASTEXITCODE) { throw 'VS environment initialization failed.' }
foreach ($line in $environmentLines) {
    if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
}
$outDir = Join-Path $taskRoot ('build/' + $BuildFolder)
[IO.Directory]::CreateDirectory($outDir) | Out-Null
$deps = Join-Path $taskRoot 'vcpkg_installed/x64-windows-static/x64-windows-static'
Push-Location $outDir
try {
    & cl.exe /nologo /std:c++20 /EHsc /MT /O2 /W4 /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /I (Join-Path $taskRoot 'src') /I (Join-Path $deps 'include') (Join-Path $PSScriptRoot 'probe.cpp') (Join-Path $taskRoot 'src/Core/ProcessMemorySession.cpp') (Join-Path $taskRoot 'src/Disasm/ZydisDisassembler.cpp') "/Fe:$outDir/probe.exe" /link (Join-Path $deps 'lib/Zydis.lib') (Join-Path $deps 'lib/Zycore.lib')
    if ($LASTEXITCODE) { throw 'Probe compilation failed.' }
    if ($ProbeOnly) { return }
    & cl.exe /nologo /std:c++20 /EHsc /MT /O2 /W4 /DNOMINMAX /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS /I (Join-Path $taskRoot 'src') (Join-Path $PSScriptRoot 'controller.cpp') (Join-Path $taskRoot 'src/Core/ProcessMemorySession.cpp') "/Fe:$outDir/PeggleCursor.exe" /link /SUBSYSTEM:WINDOWS user32.lib gdi32.lib shell32.lib
    if ($LASTEXITCODE) { throw 'Cursor controller compilation failed.' }
} finally { Pop-Location }
