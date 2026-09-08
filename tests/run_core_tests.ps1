<#
.SYNOPSIS
    Compile and execute declared tests with the application's exact v143 toolset.
.DESCRIPTION
    The default Core suite reports environment-dependent and app-object tests as
    excluded. All executes every declaration, requiring live debugger support.
    Build Release|x64 before Integration or All. A positional test name preserves
    the batch runner's focused-test interface. Logs and summary.json are retained
    beneath build/test-results; a nonzero exit means a build, test or setup failed.
.EXAMPLE
    tests\run_core_tests.bat -Suite All
.EXAMPLE
    tests\run_core_tests.bat patch_set_test
.EXAMPLE
    .\tests\run_core_tests.ps1 -Suite Integration -ListOnly
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)][string]$TestName,
    [ValidateSet('Core', 'Live', 'Integration', 'All')][string]$Suite = 'Core',
    [switch]$ListOnly,
    [switch]$RequireLiveDebugTests,
    [string]$OutputRoot,
    [string]$DependencyRoot
)

$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$dependencyPrefix = 'vcpkg_installed\x64-windows-static\x64-windows-static'
$resolvedDependencyRoot = if ($DependencyRoot) { [IO.Path]::GetFullPath($DependencyRoot) }
                          else { Join-Path $taskRoot $dependencyPrefix }
$records = @(& (Join-Path $PSScriptRoot 'validate_test_manifest.ps1') -PassThru)
if ($TestName -and $PSBoundParameters.ContainsKey('Suite')) {
    throw 'Choose one test name or a suite, not both.'
}
$kindBySuite = @{ Core = 'TEST'; Live = 'LIVE_TEST'; Integration = 'INTEGRATION_TEST' }
$selected = @($records | Where-Object {
    if ($TestName) { $_.Name -eq $TestName }
    elseif ($Suite -eq 'All') { $true }
    else { $_.Kind -eq $kindBySuite[$Suite] }
})
if (!$selected.Count) { throw "No declared test matches '$TestName'." }
$excluded = @($records | Where-Object { $_ -notin $selected })
foreach ($record in $selected) { Write-Host "SELECT [$($record.Kind)]: $($record.Name)" }
Write-Host "Selected $($selected.Count) of $($records.Count) declared tests; $($excluded.Count) excluded by selection."
if ($ListOnly) { exit 0 }

$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N')
$resultsParent = if ($OutputRoot) { [IO.Path]::GetFullPath($OutputRoot) }
                 else { Join-Path $taskRoot 'build\test-results' }
$resultsRoot = Join-Path $resultsParent $runId
[IO.Directory]::CreateDirectory($resultsRoot) | Out-Null
$results = [Collections.Generic.List[object]]::new()
$setupFailure = $null
$selectedVisualStudio = $null
$toolsetVersion = $null
$savedEnvironment = @{}
foreach ($entry in [Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
    $savedEnvironment[$entry.Key] = $entry.Value
}
Write-Host "Test results: $resultsRoot"

function Invoke-CheckedNative {
    param([string]$Program, [string[]]$Arguments, [string]$LogPath, [switch]$EchoOutput)
    # Multiple VS installations can expose several cl/link executables. Use the
    # first PATH match from the exact vcvars environment selected above.
    $resolvedProgram = (Get-Command -Name $Program -CommandType Application -ErrorAction Stop |
        Select-Object -First 1).Source
    # Native stderr is diagnostic output, not a PowerShell terminating exception.
    # The process exit status remains the sole success criterion on PS5 and PS7.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $resolvedProgram @Arguments *> $LogPath
        $nativeExit = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    if ($EchoOutput -or $nativeExit) { Get-Content -LiteralPath $LogPath | ForEach-Object { Write-Host $_ } }
    if ($nativeExit) { throw "$Program failed with exit code $nativeExit; see $LogPath" }
}

Push-Location $taskRoot
try {
    $selectedVisualStudio = $env:VCPKG_VISUAL_STUDIO_PATH
    if (!$selectedVisualStudio) {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        if (!(Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw 'Install Visual Studio 2022 with the C++ workload, or set VCPKG_VISUAL_STUDIO_PATH.' }
        $selectedVisualStudio = & $vswhere -latest -version '[17.0,18.0)' -products '*' `
            -requires Microsoft.Component.MSBuild Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property installationPath | Select-Object -First 1
        if ($LASTEXITCODE -or !$selectedVisualStudio) { throw 'A complete Visual Studio 2022 C++ installation was not found.' }
    }
    $selectedVisualStudio = [IO.Path]::GetFullPath($selectedVisualStudio)
    $toolsetVersion = $env:DS_VCPKG_PLATFORM_TOOLSET_VERSION
    if (!$toolsetVersion) {
        $marker = Join-Path $selectedVisualStudio 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.v143.default.txt'
        $toolsetVersion = (Get-Content -LiteralPath $marker -TotalCount 1).Trim()
    }
    if ($toolsetVersion -notmatch '^14\.[0-9]+(\.[0-9]+)?$') { throw "Invalid v143 toolset version '$toolsetVersion'." }
    $vcvars = Join-Path $selectedVisualStudio 'VC\Auxiliary\Build\vcvars64.bat'
    if (!(Test-Path -LiteralPath $vcvars -PathType Leaf)) { throw "Missing Visual Studio environment script: $vcvars" }
    $environmentLines = & $env:ComSpec /d /c ('call "' + $vcvars + '" -vcvars_ver=' + $toolsetVersion + ' >nul && set')
    if ($LASTEXITCODE) { throw 'Visual Studio environment setup failed.' }
    foreach ($line in $environmentLines) {
        if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process') }
    }
    $env:VCPKG_VISUAL_STUDIO_PATH = $selectedVisualStudio
    $env:DS_VCPKG_PLATFORM_TOOLSET_VERSION = $toolsetVersion
    if ($RequireLiveDebugTests -or $Suite -in @('All', 'Live')) { $env:DS_REQUIRE_LIVE_DEBUG_TESTS = '1' }
    if ($RequireLiveDebugTests -or $Suite -eq 'All') { $env:DS_PATCH_RESTORATION_LIVE_TEST = '1' }
    Write-Host "Toolset: v143 $toolsetVersion ($selectedVisualStudio)"
    if (@($selected | Where-Object Kind -eq 'INTEGRATION_TEST').Count) {
        foreach ($required in @('build\x64\Release\DisasmStudio.exe', 'build\int\x64\Release\BinaryViewTab.obj')) {
            if (!(Test-Path -LiteralPath (Join-Path $taskRoot $required) -PathType Leaf)) {
                throw "Build Release|x64 before app-object integration tests. Missing: $required"
            }
        }
    }

    foreach ($record in $selected) {
        $testRoot = Join-Path $resultsRoot $record.Name
        [IO.Directory]::CreateDirectory($testRoot) | Out-Null
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $result = [ordered]@{ name = $record.Name; kind = $record.Kind; status = 'failed'; phase = 'build'; seconds = 0; error = $null }
        Write-Host "`n---- $($record.Name) [$($record.Kind)] ----"
        try {
            if ($record.Kind -eq 'INTEGRATION_TEST') {
                $result.phase = 'integration'
                $shell = if ($PSVersionTable.PSEdition -eq 'Core') { Join-Path $PSHOME 'pwsh.exe' } else { Join-Path $PSHOME 'powershell.exe' }
                Invoke-CheckedNative $shell @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $taskRoot $record.Dependencies), '-OutputRoot', $testRoot, '-DependencyRoot', $resolvedDependencyRoot) (Join-Path $testRoot 'integration.log') -EchoOutput
            } else {
                $dependencies = @($record.Dependencies -split '\s+' | Where-Object { $_ })
                $dependencies = @($dependencies | ForEach-Object {
                    if ($_.StartsWith($dependencyPrefix + '\', [StringComparison]::OrdinalIgnoreCase)) {
                        Join-Path $resolvedDependencyRoot $_.Substring($dependencyPrefix.Length + 1)
                    } else { $_ }
                })
                if ($record.Name -eq 'gamemaker_helper_gate_test') {
                    foreach ($assembly in @(
                        @{ source = 'src\GameMakerHelper\GameMakerGates.asm'; name = 'gamemaker_gates' },
                        @{ source = 'tests\gamemaker_helper_gate_test.asm'; name = 'gamemaker_gate_fixture' }
                    )) {
                        $objectPath = Join-Path $testRoot ($assembly.name + '.obj')
                        Invoke-CheckedNative 'ml64.exe' @('/nologo', '/c', "/Fo$objectPath", $assembly.source) (Join-Path $testRoot ($assembly.name + '.build.log'))
                        $dependencies += $objectPath
                    }
                }
                $exe = Join-Path $testRoot ($record.Name + '.exe')
                $compilerArgs = @('/nologo', '/std:c++20', '/EHsc', '/I', 'src', ('tests\' + $record.Name + '.cpp')) + $dependencies + @("/Fo$testRoot\", "/Fe$exe")
                Invoke-CheckedNative 'cl.exe' $compilerArgs (Join-Path $testRoot 'build.log')
                $result.phase = 'run'
                Invoke-CheckedNative $exe @() (Join-Path $testRoot 'run.log') -EchoOutput
            }
            $result.status = 'passed'
            $result.phase = 'complete'
            Write-Host "PASS: $($record.Name)"
        } catch {
            $result.error = $_.Exception.Message
            Write-Host "FAIL: $($record.Name): $($result.error)" -ForegroundColor Red
        } finally {
            $result.seconds = [Math]::Round($timer.Elapsed.TotalSeconds, 3)
            $results.Add([pscustomobject]$result)
        }
    }
} catch {
    $setupFailure = $_.Exception.Message
    Write-Host "TEST SETUP FAILED: $setupFailure" -ForegroundColor Red
} finally {
    Pop-Location
    foreach ($key in @([Environment]::GetEnvironmentVariables('Process').Keys)) {
        if (!$savedEnvironment.ContainsKey($key)) { [Environment]::SetEnvironmentVariable($key, $null, 'Process') }
    }
    foreach ($entry in $savedEnvironment.GetEnumerator()) { [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process') }
    $summary = [ordered]@{
        suite = if ($TestName) { $TestName } else { $Suite }
        declared = $records.Count
        selected = $selected.Count
        excluded = @($excluded | ForEach-Object { $_.Name })
        visualStudio = $selectedVisualStudio
        toolset = $toolsetVersion
        dependencyRoot = $resolvedDependencyRoot
        setupFailure = $setupFailure
        results = $results.ToArray()
    }
    [IO.File]::WriteAllText((Join-Path $resultsRoot 'summary.json'), ($summary | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
}
$failed = @($results | Where-Object status -eq 'failed').Count
$passed = @($results | Where-Object status -eq 'passed').Count
Write-Host "`n===== $passed PASSED, $failed FAILED, $($selected.Count - $results.Count) NOT RUN; $($excluded.Count) EXCLUDED BY SELECTION ====="
Write-Host "Logs and summary: $resultsRoot"
if ($setupFailure -or $failed -or $results.Count -ne $selected.Count) { exit 1 }
exit 0
