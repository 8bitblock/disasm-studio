# Launch the built app, wait briefly, and report whether it stayed alive.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$exe = Join-Path $root 'build\x64\Release\DisasmStudio.exe'
if (-not (Test-Path $exe)) { Write-Host "MISSING: $exe"; exit 1 }
$p = Start-Process -FilePath $exe -PassThru
Start-Sleep -Seconds 5
if ($p.HasExited) { Write-Host "EXITED early, code=$($p.ExitCode)"; exit 1 }
Write-Host "ALIVE after 5s (pid $($p.Id)) - startup OK"
Stop-Process -Id $p.Id -Force
exit 0
