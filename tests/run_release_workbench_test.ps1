param([ValidateSet('Release')][string]$Configuration = 'Release', [switch]$CompileOnly)
$ErrorActionPreference = 'Stop'

# The manifest dispatches script paths, so keep the focused app-object mode in a
# small explicit entrypoint instead of encoding arguments into a path field.
& (Join-Path $PSScriptRoot 'run_static_listing_actions_test.ps1') `
    -Configuration $Configuration -CompileOnly:$CompileOnly -ReleaseWorkbenchOnly
