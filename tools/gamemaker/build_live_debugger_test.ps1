param([string]$Configuration='Release',[ValidateSet('live_debugger_test','live_lifecycle_test','live_call_step_test')][string]$Test='live_debugger_test')
$ErrorActionPreference='Stop'
$projectRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$testOutput=Join-Path $projectRoot 'build\gamemaker-live-test'
$null=New-Item -ItemType Directory -Path $testOutput -Force
$vswhere=Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$studio=& $vswhere -latest -version '[17.0,18.0)' -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$helper=Join-Path $projectRoot "build\x64\$Configuration\GameMakerHelper.dll"
if(!(Test-Path -LiteralPath $helper)){throw 'Build the embedded helper before this acceptance harness.'}
$resource=Join-Path $testOutput 'GameMakerLiveTest.rc'
$rcPath=$helper.Replace('\','/')
[IO.File]::WriteAllText($resource,"30101 RCDATA `"$rcPath`"`r`n",[Text.Encoding]::ASCII)
$deps=(Get-Content (Join-Path $projectRoot 'tests\run_core_tests.bat') | Where-Object { $_ -like 'rem LIVE_TEST|x64_debug_test|*' }).Split('|')[2]
$deps+=' src/Core/Project.cpp src/Core/AtomicFile.cpp src/Core/Json.cpp src/Core/ConnectionSchema.cpp'
if($Test -eq 'live_call_step_test'){$deps+=' src/Disasm/GmlDisassembler.cpp'}
$source=Join-Path $PSScriptRoot ($Test+'.cpp')
$command=@"
@echo off
call "$studio\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 exit /b 1
cd /d "$projectRoot"
rc /nologo /fo "$testOutput\GameMakerLiveTest.res" "$resource"
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /EHsc /O2 /W3 /DWIN32_LEAN_AND_MEAN /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS /Isrc "$source" $deps "$testOutput\GameMakerLiveTest.res" /Fo"$testOutput\\" /Fe"$testOutput\$Test.exe" /link /INCREMENTAL:NO
exit /b %errorlevel%
"@
$batch=Join-Path $testOutput 'build.cmd'
[IO.File]::WriteAllText($batch,$command,[Text.Encoding]::ASCII)
& $env:ComSpec /c $batch
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $projectRoot 'tests\verify_gamemaker_helper_resource.ps1') -Executable (Join-Path $testOutput ($Test+'.exe')) -HelperDll $helper
exit $LASTEXITCODE
