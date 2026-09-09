param([ValidateSet('Release')][string]$Configuration = 'Release', [switch]$CompileOnly,
      [switch]$ReleaseWorkbenchOnly, [switch]$FeatureTabsOnly, [switch]$LiveScrollOnly, [string]$ObjectRoot,
      [string]$DependencyRoot, [string]$OutputRoot)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$objectRoot = if ($ObjectRoot) { [IO.Path]::GetFullPath($ObjectRoot) }
              else { Join-Path $taskRoot "build\int\x64\$Configuration" }
$dependencyRoot = if ($DependencyRoot) { [IO.Path]::GetFullPath($DependencyRoot) }
                  else { Join-Path $taskRoot 'vcpkg_installed\x64-windows-static\x64-windows-static' }
if (!(Test-Path -LiteralPath (Join-Path $objectRoot 'BinaryViewTab.obj'))) {
    throw 'Build DisasmStudio.sln Release|x64 first; this integration harness links the production app objects.'
}
$vsPath = $env:VCPKG_VISUAL_STUDIO_PATH
if (!$vsPath) {
    $vsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vsPath = & $vsWhere -latest -version '[17.0,18.0)' -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
}
if (!$vsPath) { throw 'Visual Studio 2022 C++ tools were not found.' }
$vcVars = Join-Path $vsPath 'VC\Auxiliary\Build\vcvars64.bat'
# Production objects use v143 even when a newer VS installation hosts the
# build. Match its compiler/linker for LTCG instead of taking vcvars' newest ABI.
$toolsetVersion = $env:DS_VCPKG_PLATFORM_TOOLSET_VERSION
if (!$toolsetVersion) {
    $toolsetVersion = (Get-Content -LiteralPath (Join-Path $vsPath 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.v143.default.txt') -TotalCount 1).Trim()
}
if ($toolsetVersion -notmatch '^14\.[0-9]+(\.[0-9]+)?$') { throw 'Invalid v143 toolset version.' }
$environmentLines = & $env:ComSpec /d /c ('call "' + $vcVars + '" -vcvars_ver=' + $toolsetVersion + ' >nul && set')
if ($LASTEXITCODE) { throw 'Visual Studio environment setup failed.' }
foreach ($line in $environmentLines) {
    if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
}
$outputRoot = if ($OutputRoot) { Join-Path ([IO.Path]::GetFullPath($OutputRoot)) 'app-objects' }
              else { Join-Path ([IO.Path]::GetTempPath()) ('ds_static_listing_' + [Guid]::NewGuid().ToString('N')) }
[IO.Directory]::CreateDirectory($outputRoot) | Out-Null
$source = Join-Path $PSScriptRoot $(if ($FeatureTabsOnly) { 'feature_tabs_ui_test.cpp' } elseif ($ReleaseWorkbenchOnly) { 'release_workbench_test.cpp' } else { 'static_listing_actions_test.cpp' })
$testObject = Join-Path $outputRoot 'static_listing_actions_test.obj'
$executable = Join-Path $outputRoot 'static_listing_actions_test.exe'
$compileLog = Join-Path $outputRoot 'compile.log'
$linkLog = Join-Path $outputRoot 'link.log'
$runLog = Join-Path $outputRoot 'run.log'
Write-Host "Headless listing integration artifacts: $outputRoot"
if ($ReleaseWorkbenchOnly) {
    Write-Host 'Focused release-workbench composition, register editor, and inspector validity checks.'
}
if (!$CompileOnly) {
    # Link only an isolated snapshot. The long LTCG link must not keep the live
    # build objects locked while the developer rebuilds the application.
    $linkObjectRoot = Join-Path $outputRoot 'production-objects'
    [IO.Directory]::CreateDirectory($linkObjectRoot) | Out-Null
    $productionObjects = @(Get-ChildItem -LiteralPath $objectRoot -Filter '*.obj' | Where-Object Name -ne 'main.obj')
    foreach ($object in $productionObjects) {
        Copy-Item -LiteralPath $object.FullName -Destination (Join-Path $linkObjectRoot $object.Name)
    }
    foreach ($object in $productionObjects) {
        $current = Get-Item -LiteralPath $object.FullName
        if ($current.Length -ne $object.Length -or $current.LastWriteTimeUtc -ne $object.LastWriteTimeUtc) {
            throw 'Production objects changed during snapshot. Finish the application build before running integration tests.'
        }
    }
    if (@(Get-ChildItem -LiteralPath $objectRoot -Filter '*.obj' | Where-Object Name -ne 'main.obj').Count -ne $productionObjects.Count) {
        throw 'Production object inventory changed during snapshot. Finish the application build before running integration tests.'
    }
    Write-Host "Snapshotted $($productionObjects.Count) production objects."
}
& cl.exe /nologo /std:c++20 /EHsc /MT /Gy /W4 /DNOMINMAX /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS /I (Join-Path $taskRoot 'src') /I (Join-Path $dependencyRoot 'include') /c $source "/Fo$testObject" *> $compileLog
if ($LASTEXITCODE) { Get-Content -LiteralPath $compileLog; throw 'Integration harness compilation failed.' }
if ($CompileOnly) { Write-Host 'Integration harness compilation passed.'; return }
$linkArguments = @('/NOLOGO', '/LTCG', '/INCREMENTAL:NO', '/OPT:REF', '/OPT:ICF', '/MACHINE:X64', '/SUBSYSTEM:CONSOLE', ('/OUT:"' + $executable + '"'), ('"' + $testObject + '"'))
if ($LiveScrollOnly) {
    # Retain the linker's checked code-generation cache for quick scroll
    # regression retries. The executable still supports the complete suite.
    $linkArguments[1] = '/LTCG:INCREMENTAL'
    $linkArguments += ('/LTCGOUT:"' + (Join-Path $outputRoot 'live_scroll.iobj') + '"')
}
    # MSVC encodes private/public access in decorated method names even though the
    # calling convention and object layout are identical. Alias only this fixture's
    # exposed tab references back to the unchanged private app symbols.
$symbols = & dumpbin.exe /nologo /symbols $testObject
foreach ($line in $symbols) {
    if ($line -match 'UNDEF.*External\s+\|\s+(\?\S+)') {
        $symbol = $matches[1]
        foreach ($fixtureClass in @('BinaryViewTab', 'CortexTab', 'SigScannerTab', 'BinaryTechTab', 'BinaryDiffTab', 'ProjectsTab', 'MemoryToolsTab', 'PrismTab', 'CommunicationsTab', 'ConnectionsTab')) {
            if ($symbol.Contains('@' + $fixtureClass + '@ds@@QE')) {
                $original = $symbol.Replace('@' + $fixtureClass + '@ds@@QE', '@' + $fixtureClass + '@ds@@AE')
                $linkArguments += ('/ALTERNATENAME:' + $symbol + '=' + $original)
            }
            if ($fixtureClass -eq 'SigScannerTab' -and
                $symbol.Contains('@SigScannerTab@ds@@SA')) {
                $original = $symbol.Replace('@SigScannerTab@ds@@SA', '@SigScannerTab@ds@@CA')
                $linkArguments += ('/ALTERNATENAME:' + $symbol + '=' + $original)
            }
        }
    }
}
$linkArguments += Get-ChildItem -LiteralPath $linkObjectRoot -Filter '*.obj' | ForEach-Object { '"' + $_.FullName + '"' }
$linkArguments += Get-ChildItem -LiteralPath (Join-Path $dependencyRoot 'lib') -Filter '*.lib' | ForEach-Object { '"' + $_.FullName + '"' }
$linkArguments += @('d3d11.lib','dxgi.lib','d3dcompiler.lib','dwmapi.lib','psapi.lib','iphlpapi.lib','ws2_32.lib','advapi32.lib','shell32.lib','kernel32.lib','user32.lib','gdi32.lib','winspool.lib','comdlg32.lib','ole32.lib','oleaut32.lib','uuid.lib','odbc32.lib','odbccp32.lib')
$responsePath = Join-Path $outputRoot 'link.rsp'
[IO.File]::WriteAllLines($responsePath, $linkArguments, [Text.Encoding]::ASCII)
& link.exe "@$responsePath" *> $linkLog
if ($LASTEXITCODE) { Get-Content -LiteralPath $linkLog; throw 'Production-object integration linking failed.' }
$priorAppData = $env:APPDATA
$priorFixtureRoot = $env:DS_STATIC_LISTING_TEST_ROOT
$priorLiveScrollOnly = $env:DS_LIVE_SCROLL_ONLY
try {
    $env:APPDATA = Join-Path $outputRoot 'appdata'
    $env:DS_STATIC_LISTING_TEST_ROOT = $outputRoot
    if ($LiveScrollOnly) { $env:DS_LIVE_SCROLL_ONLY = '1' }
    [IO.Directory]::CreateDirectory($env:APPDATA) | Out-Null
    Push-Location $taskRoot
    try { & $executable 2>&1 | Tee-Object -FilePath $runLog; $testExit = $LASTEXITCODE } finally { Pop-Location }
    if ($testExit) { throw "Static listing action integration test failed: $testExit" }
} finally {
    $env:APPDATA = $priorAppData
    $env:DS_STATIC_LISTING_TEST_ROOT = $priorFixtureRoot
    $env:DS_LIVE_SCROLL_ONLY = $priorLiveScrollOnly
}
