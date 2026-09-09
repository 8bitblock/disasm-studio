param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$taskRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vs = & $vswhere -latest -version '[17.0,18.0)' -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw 'Visual Studio 2022 C++ tools are required.' }
$version = (Get-Content -LiteralPath (Join-Path $vs 'VC/Auxiliary/Build/Microsoft.VCToolsVersion.v143.default.txt') -TotalCount 1).Trim()
$vcvars = Join-Path $vs 'VC/Auxiliary/Build/vcvars64.bat'
$environmentLines = & $env:ComSpec /d /c ('call "' + $vcvars + '" -vcvars_ver=' + $version + ' >nul && set')
if ($LASTEXITCODE) { throw 'VS environment initialization failed.' }
foreach ($line in $environmentLines) {
    if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
}
$outDir = Join-Path $taskRoot 'build/peggle_zen'
[IO.Directory]::CreateDirectory($outDir) | Out-Null
Push-Location $outDir
try {
    & cl.exe /nologo /std:c++20 /EHsc /MT /O2 /W4 /DNOMINMAX /DUNICODE /D_UNICODE /I (Join-Path $taskRoot 'src') (Join-Path $PSScriptRoot 'main.cpp') (Join-Path $taskRoot 'src/Core/ProcessMemorySession.cpp') "/Fe:$outDir/PeggleZen.exe"
    if ($LASTEXITCODE) { throw 'Console build failed.' }
    if (!$SkipTests) {
        & cl.exe /nologo /std:c++20 /EHsc /MT /O2 /W4 /DNOMINMAX (Join-Path $PSScriptRoot 'zen_core_test.cpp') "/Fe:$outDir/zen_core_test.exe"
        if ($LASTEXITCODE) { throw 'Test build failed.' }
        & (Join-Path $outDir 'zen_core_test.exe')
        if ($LASTEXITCODE) { throw 'Console core tests failed.' }
    }
} finally { Pop-Location }
