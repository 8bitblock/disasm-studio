# Compile + run the function-namer unit test with MSVC (cl) in a VS dev shell.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath
Import-Module (Join-Path $vs "Common7\Tools\Microsoft.VisualStudio.DevShell.dll")
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments "-arch=x64 -host_arch=x64" | Out-Null
Set-Location $root
$out = Join-Path $env:TEMP 'dstest'
New-Item -ItemType Directory -Force $out | Out-Null
cl /nologo /std:c++20 /EHsc /I src tests\function_namer_test.cpp src\Core\FunctionNamer.cpp src\Core\BinaryFile.cpp /Fo"$out\\" /Fe"$out\fnt.exe"
if ($LASTEXITCODE -ne 0) { Write-Host "COMPILE FAILED"; exit 1 }
& "$out\fnt.exe"
exit $LASTEXITCODE
