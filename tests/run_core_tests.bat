@echo off
rem Build + run the dependency-light Core test harnesses with MSVC.
rem Run from any directory; Visual Studio is located with vswhere. Pass one test
rem name as the optional first argument to run only that declaration.
rem
rem Test declarations live at the bottom as "rem TEST|name|dependencies" records.
rem Keeping them as data avoids CALL/GOTO subroutines: cmd.exe can mis-seek labels in
rem LF-only batch files, silently skip calls, or re-enter the main body.
setlocal EnableExtensions EnableDelayedExpansion
set "FILTER=%~1"

pushd "%~dp0.." >nul
if errorlevel 1 (
    echo Failed to enter the project root.
    exit /b 1
)

set "VSPATH="
for /f "usebackq delims=" %%i in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (
    echo vswhere failed
    popd
    exit /b 1
)

call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
    echo Visual Studio environment setup failed.
    popd
    exit /b 1
)

rem An isolated directory prevents concurrent or previously interrupted runs
rem from sharing compiler outputs. cmd.exe instances can start with identical
rem RANDOM sequences, so retry mkdir atomically instead of trusting one token.
set "OUT="
for /l %%R in (1,1,32) do if not defined OUT (
    set "CANDIDATE=%TEMP%\dsm_tests_!RANDOM!_!RANDOM!_!RANDOM!"
    mkdir "!CANDIDATE!" >nul 2>&1 && set "OUT=!CANDIDATE!"
)
if not defined OUT (
    echo Failed to create an isolated test output directory under %TEMP%.
    popd
    exit /b 1
)

set /a DECLARED=0
set /a SELECTED=0
set /a FAILED=0

for /f "usebackq tokens=2,* delims=|" %%A in (`findstr /b /l /c:"rem TEST|" "%~f0"`) do (
    set /a DECLARED+=1
    set "NAME=%%A"
    set "DEPS=%%B"
    set "RUN_THIS=1"
    if defined FILTER if /i not "!NAME!"=="!FILTER!" set "RUN_THIS=0"

    if "!RUN_THIS!"=="1" (
        set /a SELECTED+=1
        echo.
        echo ---- !NAME! ----
        cl /nologo /std:c++20 /EHsc /I src tests\!NAME!.cpp !DEPS! /Fo"!OUT!\\" /Fe"!OUT!\!NAME!.exe" >"!OUT!\!NAME!.build.log" 2>&1
        set "BUILD_RC=!ERRORLEVEL!"

        if not "!BUILD_RC!"=="0" (
            echo BUILD FAILED ^(exit !BUILD_RC!^):
            type "!OUT!\!NAME!.build.log"
            set /a FAILED+=1
        ) else (
            "!OUT!\!NAME!.exe"
            set "TEST_RC=!ERRORLEVEL!"
            if not "!TEST_RC!"=="0" (
                echo TEST FAILED: !NAME! ^(exit !TEST_RC!^)
                set /a FAILED+=1
            )
        )
    )
)

echo.
if !DECLARED! EQU 0 (
    echo ===== NO TEST BINARIES DECLARED =====
    set /a FAILED+=1
) else if !SELECTED! EQU 0 (
    echo ===== NO TEST MATCHED "!FILTER!" =====
    set /a FAILED+=1
) else if !FAILED! EQU 0 (
    echo ===== ALL !SELECTED! SELECTED TEST BINARIES PASSED ^(!DECLARED! DECLARED^) =====
) else (
    echo ===== !FAILED! OF !SELECTED! SELECTED TEST BINARIES FAILED ^(!DECLARED! DECLARED^) =====
)

set "RESULT=!FAILED!"
popd
exit /b !RESULT!

rem TEST|fuzzy_test|
rem TEST|memcompare_test|
rem TEST|connection_schema_test|src\Core\ConnectionSchema.cpp src\Core\Json.cpp
rem TEST|gamecontext_test|src\Core\GameContext.cpp
rem TEST|binaryfile_pe_va_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
rem TEST|binaryfile_overlay_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
rem TEST|binaryfile_exports_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
rem TEST|binaryfile_memimage_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
rem TEST|inflate_test|src\Core\Inflate.cpp
rem TEST|zipextract_test|src\Core\JavaScan.cpp src\Core\Inflate.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\SigMatch.cpp
rem TEST|runtimescan_test|src\Core\RuntimeScan.cpp src\Core\SigMatch.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
rem TEST|javascan_test|src\Core\JavaScan.cpp src\Core\Inflate.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\SigMatch.cpp
rem TEST|techscan_multi_test|src\Core\TechScan.cpp src\Core\JavaScan.cpp src\Core\RuntimeScan.cpp src\Core\Inflate.cpp src\Core\SigMatch.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
rem TEST|jvmaware_test|
rem TEST|excname_test|
rem TEST|functionanalyzer_test|src\Core\FunctionAnalyzer.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
rem TEST|function_namer_test|src\Core\FunctionNamer.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
rem TEST|function_namer_pipeline_test|src\Core\FunctionNamer.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
rem TEST|analysis_service_test|src\Core\AnalysisService.cpp src\Core\AnalysisJobs.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Core\SynthesisJob.cpp src\Core\Synthesis.cpp src\Core\PathExploreJob.cpp src\Core\PathExplore.cpp src\Core\ExprAst.cpp src\Core\SymEngine.cpp src\Core\Simplify.cpp src\Disasm\JvmDisassembler.cpp
rem TEST|livescan_service_test|src\Core\LiveScanService.cpp src\Core\AnalysisJobs.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|jvmclass_test|src\Core\JvmClass.cpp
rem TEST|jvmdisasm_test|src\Core\JvmClass.cpp src\Disasm\JvmDisassembler.cpp src\Core\CFG.cpp
rem TEST|jvmload_test|src\Core\JvmClass.cpp src\Core\BinaryFile.cpp src\Core\FunctionAnalyzer.cpp src\Disasm\JvmDisassembler.cpp
rem TEST|jvmannotate_test|src\Core\JvmAnnotate.cpp src\Core\JvmClass.cpp src\Disasm\JvmDisassembler.cpp
rem TEST|jdwp_test|src\Core\Jdwp.cpp
rem TEST|project_roundtrip_test|src\Core\Project.cpp src\Core\Json.cpp src\Core\ConnectionSchema.cpp
rem TEST|xref_report_test|src\Core\XrefIndex.cpp src\Core\Report.cpp
rem TEST|cond_eval_test|src\Core\Cond.cpp
rem TEST|cond_compiled_test|src\Core\Cond.cpp
rem TEST|patch_pristine_test|
rem TEST|decompiler_linemap_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|decompiler_python_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|decompiler_switch_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|decompiler_fixes_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|dataflow_decomp_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|decompiler_tempname_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|decompiler_folder_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|funcannotate_test|src\Core\FuncAnnotate.cpp src\Core\CFG.cpp
rem TEST|cortex_test|src\Core\Cortex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
rem TEST|prism_test|src\Core\Prism.cpp
