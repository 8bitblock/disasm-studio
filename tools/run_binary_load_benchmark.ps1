param(
    [string]$Binary = "$env:WINDIR\System32\notepad.exe",
    [ValidateRange(1,100)][int]$Runs = 3,
    [switch]$WarmCache,
    [ValidateRange(1,3600)][int]$TimeoutSeconds = 300,
    [string]$SourceRoot,
    [string]$OutputRoot,
    [switch]$BuildOnly,
    [switch]$ReuseBuild
)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
if (!$SourceRoot) { $SourceRoot = Join-Path $taskRoot 'src' }
$SourceRoot = (Resolve-Path -LiteralPath $SourceRoot).Path
if (!$OutputRoot) {
    $OutputRoot = Join-Path ([IO.Path]::GetTempPath()) ('ds_load_benchmark_' + [guid]::NewGuid().ToString('N'))
}
[IO.Directory]::CreateDirectory($OutputRoot) | Out-Null
$OutputRoot = (Resolve-Path -LiteralPath $OutputRoot).Path
$dependencyRoot = Join-Path $taskRoot 'vcpkg_installed\x64-windows-static\x64-windows-static'
$executable = Join-Path $OutputRoot 'binary_load_benchmark.exe'
$compileLog = Join-Path $OutputRoot 'build.log'
Write-Host "Headless binary-load benchmark artifacts: $OutputRoot"
if (!$ReuseBuild) {
    $vsPath = $env:VCPKG_VISUAL_STUDIO_PATH
    if (!$vsPath) {
        $vsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        $vsPath = & $vsWhere -latest -version '[17.0,18.0)' -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    }
    if (!$vsPath) { throw 'Visual Studio 2022 C++ tools were not found.' }
    $vcVars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'
    $environmentLines = & $env:ComSpec /d /c ('call "' + $vcVars + '" >nul && set')
    if ($LASTEXITCODE) { throw 'Visual Studio environment setup failed.' }
    foreach ($line in $environmentLines) {
        if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
    }
    # Reuse the maintained Core dependency closure and add the real decoders.
    $manifest = Get-Content -LiteralPath (Join-Path $taskRoot 'tests\run_core_tests.bat')
    $declaration = @($manifest | Where-Object { $_.StartsWith('rem TEST|analysis_service_test|') })
    if ($declaration.Count -ne 1) { throw 'Expected one analysis_service_test dependency declaration.' }
    $relativeSources = ($declaration[0] -split '\|', 3)[2] -split '\s+'
    $sources = @($relativeSources | ForEach-Object {
        if (!$_.StartsWith('src\') -or !$_.EndsWith('.cpp')) { throw "Unexpected source dependency: $_" }
        Join-Path $SourceRoot $_.Substring(4)
    })
    $sources += @('Disasm\DisassemblerFactory.cpp', 'Disasm\ZydisDisassembler.cpp', 'Disasm\CapstoneDisassembler.cpp') |
        ForEach-Object { Join-Path $SourceRoot $_ }
    $arguments = @('/nologo', '/std:c++20', '/EHsc', '/O2', '/MP4', '/MT', '/DNDEBUG', '/DNOMINMAX',
        '/DUNICODE', '/D_UNICODE', '/DWIN32_LEAN_AND_MEAN', '/D_CRT_SECURE_NO_WARNINGS',
        ('/I"' + $SourceRoot + '"'), ('/I"' + (Join-Path $dependencyRoot 'include') + '"'),
        ('"' + (Join-Path $PSScriptRoot 'binary_load_benchmark.cpp') + '"'))
    $arguments += $sources | ForEach-Object { '"' + $_ + '"' }
    $arguments += @('/Fo"' + $OutputRoot + '\\"', '/Fe"' + $executable + '"')
    $arguments += @('Zydis.lib', 'Zycore.lib', 'capstone.lib') | ForEach-Object {
        '"' + (Join-Path $dependencyRoot ('lib\' + $_)) + '"'
    }
    $arguments += @('/link', '/INCREMENTAL:NO', '/OPT:REF', '/OPT:ICF', 'dbghelp.lib', 'advapi32.lib')
    $response = Join-Path $OutputRoot 'build.rsp'
    [IO.File]::WriteAllLines($response, $arguments, [Text.Encoding]::ASCII)
    & cl.exe "@$response" *> $compileLog
    if ($LASTEXITCODE) { Get-Content -LiteralPath $compileLog; throw 'Benchmark compilation failed.' }
    [IO.File]::WriteAllLines((Join-Path $OutputRoot 'sources.txt'), $sources, [Text.Encoding]::UTF8)
    $sources | Get-FileHash -Algorithm SHA256 | Select-Object Path,Hash |
        Export-Csv -NoTypeInformation -LiteralPath (Join-Path $OutputRoot 'source_hashes.csv')
}
if ($BuildOnly) { Write-Host "Built $executable"; return }
if (!(Test-Path -LiteralPath $executable)) { throw "Benchmark executable is missing: $executable" }
$Binary = (Resolve-Path -LiteralPath $Binary).Path
$log = Join-Path $OutputRoot (([IO.Path]::GetFileName($Binary)) + $(if ($WarmCache) { '.warm.tsv' } else { '.cold.tsv' }))
& $executable $Binary $Runs ([int]$WarmCache.IsPresent) $TimeoutSeconds | Tee-Object -FilePath $log
if ($LASTEXITCODE) { throw "Binary load benchmark failed: $LASTEXITCODE" }
