param([ValidateSet('Release')][string]$Configuration = 'Release', [switch]$CompileOnly, [string]$ObjectRoot)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'run_static_listing_actions_test.ps1') `
    -Configuration $Configuration -CompileOnly:$CompileOnly -FeatureTabsOnly -ObjectRoot $ObjectRoot
