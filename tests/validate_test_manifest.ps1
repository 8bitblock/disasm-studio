param(
    [Parameter(Mandatory = $false)]
    [string]$ManifestPath
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($ManifestPath)) {
    $ManifestPath = Join-Path $PSScriptRoot 'run_core_tests.bat'
}

$manifest = (Resolve-Path -LiteralPath $ManifestPath).Path
$testsRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$records = [System.Collections.Generic.List[object]]::new()
$lineNumber = 0

foreach ($line in [IO.File]::ReadLines($manifest)) {
    $lineNumber++
    if ($line -notmatch '^rem (TEST|LIVE_TEST|INTEGRATION_TEST)\|([^|]+)\|(.*)$') {
        if ($line -match '^rem (?:TEST|LIVE_TEST|INTEGRATION_TEST)\|') {
            throw "Malformed test manifest record at ${manifest}:$lineNumber"
        }
        continue
    }

    $kind = $Matches[1]
    $name = $Matches[2]
    $dependencies = $Matches[3]
    if ($name -notmatch '^[A-Za-z0-9_]+$') {
        throw "Unsafe test name '$name' at ${manifest}:$lineNumber"
    }

    $source = Join-Path $testsRoot ($name + '.cpp')
    if (!(Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Manifest record '$name' has no source file: $source"
    }
    if ($kind -eq 'INTEGRATION_TEST') {
        if ($dependencies -notmatch '^tests\\run_[A-Za-z0-9_]+\.ps1$' -or
            !(Test-Path -LiteralPath (Join-Path (Split-Path -Parent $testsRoot) $dependencies) -PathType Leaf)) {
            throw "Integration record '$name' requires an existing tests\\run_*.ps1 runner."
        }
    }

    foreach ($match in [regex]::Matches($dependencies, '(?:^|\s)((?:src|tests)\\[^\s]+\.cpp)(?=\s|$)', 'IgnoreCase')) {
        $dependencySource = Join-Path (Split-Path -Parent $testsRoot) $match.Groups[1].Value
        if (!(Test-Path -LiteralPath $dependencySource -PathType Leaf)) {
            throw "Manifest record '$name' references a missing source: $($match.Groups[1].Value)"
        }
    }

    $records.Add([pscustomobject]@{
        Kind = $kind
        Name = $name
        Line = $lineNumber
    })
}

if ($records.Count -eq 0) {
    throw "No test records were found in $manifest"
}

$duplicates = @($records | Group-Object { $_.Name.ToLowerInvariant() } | Where-Object Count -ne 1)
if ($duplicates.Count -ne 0) {
    $details = $duplicates | ForEach-Object {
        $entries = $_.Group | ForEach-Object { "$($_.Name) (line $($_.Line))" }
        $entries -join ', '
    }
    throw "Duplicate test manifest record(s): $($details -join '; ')"
}

$declared = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($record in $records) {
    $null = $declared.Add($record.Name)
}

$sources = @(Get-ChildItem -LiteralPath $testsRoot -Filter '*.cpp' -File)
$undeclared = @($sources | Where-Object { !$declared.Contains($_.BaseName) } | Sort-Object Name)
if ($undeclared.Count -ne 0) {
    throw "Undeclared C++ test source(s): $((@($undeclared.Name) -join ', ')). Add each source to the manifest in tests/run_core_tests.bat."
}

$liveCount = @($records | Where-Object Kind -eq 'LIVE_TEST').Count
$integrationCount = @($records | Where-Object Kind -eq 'INTEGRATION_TEST').Count
$eligibleCount = $records.Count - $liveCount - $integrationCount
Write-Host "Test manifest OK: $($records.Count) declared ($eligibleCount eligible, $liveCount live/environment-dependent, $integrationCount app-object integration)."
