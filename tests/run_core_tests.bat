@echo off
rem Build + run the Core test harnesses touched by the bug-fix/feature pass:
rem   memcompare, cond_eval, cond_compiled, patch_pristine (new),
rem   decompiler_linemap (new), and the regression set
rem   (decompiler_switch / decompiler_fixes / dataflow_decomp / analysis_service).
rem Run from the project root in any shell; locates VS via vswhere.
setlocal enabledelayedexpansion

for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set VSPATH=%%i
if "%VSPATH%"=="" ( echo vswhere failed & exit /b 1 )
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1

set OUT=%TEMP%\dsm_tests
if not exist "%OUT%" mkdir "%OUT%"
set FAILED=0

call :one fuzzy_test             ""
call :one memcompare_test        ""
call :one connection_schema_test "src\Core\ConnectionSchema.cpp src\Core\Json.cpp"
call :one gamecontext_test       "src\Core\GameContext.cpp"
call :one binaryfile_overlay_test "src\Core\BinaryFile.cpp src\Core\JvmClass.cpp"
call :one inflate_test           "src\Core\Inflate.cpp"
call :one zipextract_test        "src\Core\JavaScan.cpp src\Core\Inflate.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\SigMatch.cpp"
call :one runtimescan_test       "src\Core\RuntimeScan.cpp src\Core\SigMatch.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp"
call :one javascan_test          "src\Core\JavaScan.cpp src\Core\Inflate.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\SigMatch.cpp"
call :one techscan_multi_test    "src\Core\TechScan.cpp src\Core\JavaScan.cpp src\Core\RuntimeScan.cpp src\Core\Inflate.cpp src\Core\SigMatch.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp"
call :one jvmaware_test          ""
call :one excname_test           ""
call :one functionanalyzer_test  "src\Core\FunctionAnalyzer.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp"
call :one jvmclass_test          "src\Core\JvmClass.cpp"
call :one jvmdisasm_test         "src\Core\JvmClass.cpp src\Disasm\JvmDisassembler.cpp src\Core\CFG.cpp"
call :one jvmload_test           "src\Core\JvmClass.cpp src\Core\BinaryFile.cpp src\Core\FunctionAnalyzer.cpp src\Disasm\JvmDisassembler.cpp"
call :one jvmannotate_test       "src\Core\JvmAnnotate.cpp src\Core\JvmClass.cpp src\Disasm\JvmDisassembler.cpp"
call :one jdwp_test              "src\Core\Jdwp.cpp"
call :one project_roundtrip_test "src\Core\Project.cpp src\Core\Json.cpp src\Core\ConnectionSchema.cpp"
call :one xref_report_test       "src\Core\XrefIndex.cpp src\Core\Report.cpp"
call :one cond_eval_test         "src\Core\Cond.cpp"
call :one cond_compiled_test     "src\Core\Cond.cpp"
call :one patch_pristine_test    ""
call :one decompiler_linemap_test "src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp"
call :one decompiler_python_test  "src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp"
call :one decompiler_switch_test  "src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp"
call :one decompiler_fixes_test   "src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp"
call :one dataflow_decomp_test    "src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp"
call :one decompiler_tempname_test "src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp"
call :one decompiler_folder_test  "src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp"
call :one funcannotate_test       "src\Core\FuncAnnotate.cpp src\Core\CFG.cpp"

echo.
if %FAILED%==0 ( echo ===== ALL TEST BINARIES PASSED ===== ) else ( echo ===== %FAILED% TEST BINARIES FAILED ===== )
exit /b %FAILED%

:one
set NAME=%~1
set DEPS=%~2
echo.
echo ---- %NAME% ----
cl /nologo /std:c++20 /EHsc /I src tests\%NAME%.cpp %DEPS% /Fo"%OUT%"\ /Fe"%OUT%\%NAME%.exe" >"%OUT%\%NAME%.build.log" 2>&1
if errorlevel 1 (
    echo BUILD FAILED:
    type "%OUT%\%NAME%.build.log"
    set /a FAILED+=1
    goto :eof
)
"%OUT%\%NAME%.exe"
if errorlevel 1 set /a FAILED+=1
goto :eof
