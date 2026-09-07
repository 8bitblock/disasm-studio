@echo off
rem Build + run the Core test harnesses with MSVC. Most are dependency-light;
rem xref_arch_test links the static decoder libraries installed by the app build.
rem Run from any directory; Visual Studio is located with vswhere. Pass one test
rem name as the optional first argument to run only that declaration.
rem
rem Test declarations live at the bottom as "rem TEST|name|dependencies" records.
rem Environment-dependent process/debugger checks use LIVE_TEST records. They are
rem reported as explicit skips in the default local suite and run when selected
rem by name, for example: run_core_tests.bat wow64_debug_test. CI sets
rem DS_REQUIRE_LIVE_DEBUG_TESTS=1 so an unavailable target/privilege is a failure.
rem Keeping them as data avoids CALL/GOTO subroutines: cmd.exe can mis-seek labels in
rem LF-only batch files, silently skip calls, or re-enter the main body.
setlocal EnableExtensions EnableDelayedExpansion
set "FILTER=%~1"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0validate_test_manifest.ps1" -ManifestPath "%~f0"
if errorlevel 1 exit /b 1

pushd "%~dp0.." >nul
if errorlevel 1 (
    echo Failed to enter the project root.
    exit /b 1
)

rem Use the same VS2022 major selected by the app build. An explicit path is
rem useful for side-by-side installations; otherwise constrain vswhere so a
rem newer Visual Studio cannot silently change the test ABI/toolset.
set "VSPATH=%VCPKG_VISUAL_STUDIO_PATH%"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
set "VS2022_RANGE=[17.0,18.0)"
set "VSWHERE_MISSING="
if not defined VSPATH if not exist "!VSWHERE!" set "VSWHERE_MISSING=1"
if defined VSWHERE_MISSING (
    echo vswhere.exe was not found. Install Visual Studio 2022 with the C++ workload or set VCPKG_VISUAL_STUDIO_PATH.
    popd
    exit /b 1
)
if not defined VSPATH for /f "usebackq delims=" %%i in (`""!VSWHERE!" -latest -version "!VS2022_RANGE!" -products * -requires Microsoft.Component.MSBuild Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath"`) do set "VSPATH=%%i"
if not defined VSPATH (
    echo A complete Visual Studio 2022 C++ installation was not found.
    popd
    exit /b 1
)
if not exist "!VSPATH!\VC\Auxiliary\Build\vcvars64.bat" (
    echo The selected Visual Studio path is missing vcvars64.bat: "!VSPATH!"
    popd
    exit /b 1
)

call "!VSPATH!\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
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
set /a SKIPPED=0
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
        rem The pure gate ABI fixture links freshly assembled production gates.
        rem It neither injects nor requires an application build.
        if /i "!NAME!"=="gamemaker_helper_gate_test" (
            ml64 /nologo /c /Fo"!OUT!\gamemaker_gates.obj" src\GameMakerHelper\GameMakerGates.asm
            if errorlevel 1 set /a FAILED+=1
            ml64 /nologo /c /Fo"!OUT!\gamemaker_gate_fixture.obj" tests\gamemaker_helper_gate_test.asm
            if errorlevel 1 set /a FAILED+=1
            set "DEPS=!DEPS! "!OUT!\gamemaker_gates.obj" "!OUT!\gamemaker_gate_fixture.obj""
        )
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

for /f "usebackq tokens=2,* delims=|" %%A in (`findstr /b /l /c:"rem LIVE_TEST|" "%~f0"`) do (
    set /a DECLARED+=1
    set "NAME=%%A"
    set "DEPS=%%B"
    set "RUN_THIS=0"
    if defined FILTER if /i "!NAME!"=="!FILTER!" set "RUN_THIS=1"

    if "!RUN_THIS!"=="1" (
        set /a SELECTED+=1
        echo.
        echo ---- !NAME! [LIVE] ----
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
    ) else if not defined FILTER (
        set /a SKIPPED+=1
        echo SKIP [LIVE]: !NAME! ^(requires a launchable target and debugger privileges^)
    )
)

for /f "usebackq tokens=2,* delims=|" %%A in (`findstr /b /l /c:"rem INTEGRATION_TEST|" "%~f0"`) do (
    set /a DECLARED+=1
    set "NAME=%%A"
    set "RUN_THIS=0"
    if defined FILTER if /i "!NAME!"=="!FILTER!" set "RUN_THIS=1"
    if "!RUN_THIS!"=="1" (
        set /a SELECTED+=1
        echo.
        echo ---- !NAME! [INTEGRATION] ----
        powershell -NoProfile -ExecutionPolicy Bypass -File "%%B"
        if errorlevel 1 set /a FAILED+=1
    ) else if not defined FILTER (
        set /a SKIPPED+=1
        echo SKIP [INTEGRATION]: !NAME! ^(requires a current Release app build^)
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
    echo ===== ALL !SELECTED! SELECTED TEST BINARIES PASSED ^(!DECLARED! DECLARED, !SKIPPED! EXPLICITLY SKIPPED^) =====
) else (
    echo ===== !FAILED! OF !SELECTED! SELECTED TEST BINARIES FAILED ^(!DECLARED! DECLARED, !SKIPPED! EXPLICITLY SKIPPED^) =====
)

set "RESULT=!FAILED!"
popd
rem A passing run has no useful artifacts, but a failure keeps its exact build
rem logs for diagnosis. Guard recursive cleanup with the leaf name generated by
rem the bounded mkdir loop above; never delete an empty or unexpected path.
if "!RESULT!"=="0" (
    set "OUT_NAME="
    if defined OUT for %%I in ("!OUT!") do set "OUT_NAME=%%~nxI"
    if defined OUT_NAME if /i "!OUT_NAME:~0,10!"=="dsm_tests_" (
        rem A just-exited live debugger fixture can retain its image mapping for a
        rem fraction of a second. Retry only this run's already-validated exact
        rem directory; never enumerate or remove sibling dsm_tests directories.
        for /l %%R in (1,1,5) do if exist "!OUT!\" (
            rmdir /s /q "!OUT!" >nul 2>&1
            if exist "!OUT!\" ping 127.0.0.1 -n 2 >nul
        )
        if exist "!OUT!\" (
            echo ERROR: Could not remove current temporary test directory "!OUT!" after bounded retries.
            set /a RESULT+=1
        )
    ) else (
        echo WARNING: Refusing to remove unexpected temporary test path "!OUT!".
    )
) else (
    echo Failed-test artifacts retained at "!OUT!".
)
exit /b !RESULT!

rem TEST|fuzzy_test|
rem TEST|function_filter_test|
rem TEST|investigation_index_test|src\Core\InvestigationIndex.cpp
rem TEST|investigation_service_test|src\Core\InvestigationService.cpp src\Core\InvestigationIndex.cpp
rem TEST|address_span_test|src\Core\CFG.cpp
rem TEST|address_inspector_test|src\Core\AddressInspector.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|diffregions_test|
rem TEST|semantic_diff_test|src\Core\SemanticDiff.cpp
rem TEST|semantic_diff_binary_test|src\Core\SemanticDiff.cpp src\Core\SemanticDiffBinary.cpp src\Core\CFG.cpp src\Core\JumpTableResolver.cpp src\Core\FunctionAnalyzer.cpp src\Core\Demangle.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|semantic_transfer_test|src\Core\SemanticTransfer.cpp
rem TEST|symbol_service_test|src\Core\SymbolService.cpp src\Core\SymbolResolver.cpp src\Core\Demangle.cpp
rem TEST|preferences_test|src\Core\Preferences.cpp src\Core\AtomicFile.cpp
rem TEST|instr_dataref_test|
rem TEST|step_logic_test|
rem TEST|memcompare_test|
rem TEST|memory_scan_test|src\Core\MemoryScan.cpp
rem TEST|memory_pointer_test|src\Core\MemoryPointer.cpp
rem TEST|memory_table_test|src\Core\MemoryTable.cpp src\Core\MemoryScan.cpp src\Core\Json.cpp
rem TEST|process_memory_session_test|src\Core\ProcessMemorySession.cpp
rem TEST|register_edit_test|
rem TEST|api_database_test|
rem TEST|connection_schema_test|src\Core\ConnectionSchema.cpp src\Core\Json.cpp
rem TEST|demangle_test|src\Core\Demangle.cpp
rem TEST|network_endpoint_test|src\Core\NetworkEndpoint.cpp
rem TEST|network_api_catalog_test|src\Core\NetworkApiCatalog.cpp
rem TEST|validation_api_catalog_test|src\Core\ValidationApiCatalog.cpp
rem TEST|verification_api_catalog_test|src\Core\VerificationApiCatalog.cpp
rem TEST|machine_identity_api_catalog_test|src\Core\MachineIdentityApiCatalog.cpp
rem TEST|authorization_trail_test|src\Core\AuthorizationTrail.cpp src\Core\AuthorizationAnalysis.cpp src\Core\PersistentStateCatalog.cpp
rem TEST|authorization_patch_advisor_test|src\Core\AuthorizationPatchAdvisor.cpp
rem TEST|authorization_experiment_test|src\Core\AuthorizationExperiment.cpp
rem TEST|patch_set_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|persistent_state_catalog_test|src\Core\PersistentStateCatalog.cpp src\Core\AuthorizationAnalysis.cpp
rem TEST|authorization_analysis_test|src\Core\AuthorizationAnalysis.cpp src\Core\PersistentStateCatalog.cpp
rem TEST|authorization_field_alias_test|src\Core\AuthorizationFieldAlias.cpp
rem TEST|authorization_watch_test|src\Core\AuthorizationWatch.cpp
rem TEST|crackme_triage_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Core\AnalysisCache.cpp src\Core\AnalysisService.cpp src\Core\AnalysisJobs.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\Demangle.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Core\FuncAnnotate.cpp src\Core\CrackmeTriage.cpp src\Core\NetworkApiCatalog.cpp src\Core\PersistentStateCatalog.cpp src\Core\ValidationApiCatalog.cpp src\Core\VerificationApiCatalog.cpp src\Core\MachineIdentityApiCatalog.cpp src\Core\AuthorizationAnalysis.cpp src\Core\AuthorizationTrail.cpp src\Core\AuthorizationPatchAdvisor.cpp src\Core\AuthorizationFieldAlias.cpp src\Core\SynthesisJob.cpp src\Core\Synthesis.cpp src\Core\PathExploreJob.cpp src\Core\PathExplore.cpp src\Core\ExprAst.cpp src\Core\SymEngine.cpp src\Core\Simplify.cpp src\Disasm\JvmDisassembler.cpp src\Disasm\ZydisDisassembler.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zydis.lib vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zycore.lib src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp
rem TEST|gamecontext_test|src\Core\GameContext.cpp src\Core\NetworkApiCatalog.cpp
rem TEST|module_registry_test|src\Core\ModuleRegistry.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|binaryfile_pe_va_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|binaryfile_overlay_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|binaryfile_exports_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|binaryfile_macho_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|binaryfile_macho_metadata_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|elf_symbols_test|src\Core\FunctionAnalyzer.cpp src\Core\JumpTableResolver.cpp src\Core\CFG.cpp src\Core\Demangle.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|binaryfile_elf_metadata_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|binaryfile_resources_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|binary_overview_test|src\Core\BinaryOverview.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|binaryfile_pe_metadata_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|resourcedecode_test|src\Core\ResourceDecode.cpp
rem TEST|binaryfile_memimage_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|binaryfile_real_mode_test|src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|inflate_test|src\Core\Inflate.cpp
rem TEST|_inflate_fuzz|/O2 src\Core\Inflate.cpp
rem TEST|zipextract_test|src\Core\JavaScan.cpp src\Core\Inflate.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\SigMatch.cpp src\Core\GameMakerArchive.cpp
rem TEST|runtimescan_test|src\Core\RuntimeScan.cpp src\Core\SigMatch.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|javascan_test|src\Core\JavaScan.cpp src\Core\Inflate.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\SigMatch.cpp src\Core\GameMakerArchive.cpp
rem TEST|techscan_multi_test|src\Core\TechScan.cpp src\Core\NetworkApiCatalog.cpp src\Core\JavaScan.cpp src\Core\RuntimeScan.cpp src\Core\Inflate.cpp src\Core\SigMatch.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|sigmatch_test|src\Core\SigMatch.cpp
rem TEST|algoscan_test|src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|jvmaware_test|
rem TEST|excname_test|
rem TEST|functionanalyzer_test|src\Core\FunctionAnalyzer.cpp src\Core\JumpTableResolver.cpp src\Core\CFG.cpp src\Core\Demangle.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|jump_table_resolver_test|src\Core\JumpTableResolver.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|codedata_classifier_test|src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|function_namer_test|src\Core\FunctionNamer.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|function_namer_pipeline_test|src\Core\FunctionNamer.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|analysis_cache_test|src\Core\AnalysisCache.cpp
rem TEST|document_result_identity_test|
rem TEST|attach_image_policy_test|
rem TEST|document_context_test|src\Core\DocumentContext.cpp src\Core\AnalysisCache.cpp src\Core\AnalysisService.cpp src\Core\CodeExport.cpp src\Core\AnalysisJobs.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\Demangle.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Core\FuncAnnotate.cpp src\Core\CrackmeTriage.cpp src\Core\NetworkApiCatalog.cpp src\Core\PersistentStateCatalog.cpp src\Core\ValidationApiCatalog.cpp src\Core\VerificationApiCatalog.cpp src\Core\MachineIdentityApiCatalog.cpp src\Core\AuthorizationAnalysis.cpp src\Core\AuthorizationTrail.cpp src\Core\AuthorizationPatchAdvisor.cpp src\Core\AuthorizationFieldAlias.cpp src\Core\SynthesisJob.cpp src\Core\Synthesis.cpp src\Core\PathExploreJob.cpp src\Core\PathExplore.cpp src\Core\ExprAst.cpp src\Core\SymEngine.cpp src\Core\Simplify.cpp src\Disasm\JvmDisassembler.cpp src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp
rem TEST|analysis_service_test|src\Core\AnalysisCache.cpp src\Core\AnalysisService.cpp src\Core\AnalysisJobs.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\Demangle.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Core\FuncAnnotate.cpp src\Core\CrackmeTriage.cpp src\Core\NetworkApiCatalog.cpp src\Core\PersistentStateCatalog.cpp src\Core\ValidationApiCatalog.cpp src\Core\VerificationApiCatalog.cpp src\Core\MachineIdentityApiCatalog.cpp src\Core\AuthorizationAnalysis.cpp src\Core\AuthorizationTrail.cpp src\Core\AuthorizationPatchAdvisor.cpp src\Core\AuthorizationFieldAlias.cpp src\Core\SynthesisJob.cpp src\Core\Synthesis.cpp src\Core\PathExploreJob.cpp src\Core\PathExplore.cpp src\Core\ExprAst.cpp src\Core\SymEngine.cpp src\Core\Simplify.cpp src\Disasm\JvmDisassembler.cpp src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp
rem TEST|persistent_file_triage_test|src\Core\AnalysisCache.cpp src\Core\AnalysisService.cpp src\Core\AnalysisJobs.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\Demangle.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Core\FuncAnnotate.cpp src\Core\CrackmeTriage.cpp src\Core\NetworkApiCatalog.cpp src\Core\PersistentStateCatalog.cpp src\Core\ValidationApiCatalog.cpp src\Core\VerificationApiCatalog.cpp src\Core\MachineIdentityApiCatalog.cpp src\Core\AuthorizationAnalysis.cpp src\Core\AuthorizationTrail.cpp src\Core\AuthorizationPatchAdvisor.cpp src\Core\AuthorizationFieldAlias.cpp src\Core\SynthesisJob.cpp src\Core\Synthesis.cpp src\Core\PathExploreJob.cpp src\Core\PathExplore.cpp src\Core\ExprAst.cpp src\Core\SymEngine.cpp src\Core\Simplify.cpp src\Disasm\JvmDisassembler.cpp src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp
rem TEST|synthesisjob_test|src\Core\SynthesisJob.cpp src\Core\Synthesis.cpp src\Core\SymEngine.cpp src\Core\ExprAst.cpp src\Core\Simplify.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|listing_layout_test|src\Core\AnalysisJobs.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\Demangle.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Disasm\JvmDisassembler.cpp src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp
rem TEST|listing_virtual_index_test|
rem TEST|graph_viewport_test|
rem TEST|patch_refresh_test|
rem TEST|firmware_sniffer_test|src\Core\FirmwareSniffer.cpp
rem TEST|code_export_test|src\Core\CodeExport.cpp src\Core\AnalysisJobs.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\Demangle.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Disasm\JvmDisassembler.cpp src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp
rem TEST|trace_coverage_test|src\Core\TraceCoverage.cpp
rem TEST|dll_debug_plan_test|src\Core\DllDebugPlan.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|unpack_engine_test|src\Core\UnpackEngine.cpp
rem TEST|pe_unpack_test|src\Core\PeUnpack.cpp
rem TEST|static_unpack_test|src\Core\StaticUnpack.cpp src\Core\PeUnpack.cpp
rem TEST|passive_dump_test|src\Core\PassiveDump.cpp src\Core\PeUnpack.cpp
rem TEST|anti_debug_test|src\Core\AntiDebug.cpp
rem TEST|livescan_service_test|src\Core\LiveScanService.cpp src\Core\AnalysisJobs.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\Demangle.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Core\GameMakerArchive.cpp
rem TEST|expr_simplify_test|src\Core\ExprAst.cpp src\Core\Simplify.cpp
rem TEST|solver_test|src\Core\SymEngine.cpp src\Core\ExprAst.cpp src\Core\Simplify.cpp
rem TEST|synthesis_test|src\Core\Synthesis.cpp src\Core\ExprAst.cpp src\Core\Simplify.cpp
rem TEST|pathexplore_test|src\Core\PathExplore.cpp src\Core\ExprAst.cpp
rem TEST|patchplacer_test|src\Core\PatchPlacer.cpp
rem TEST|jvmclass_test|src\Core\JvmClass.cpp
rem TEST|jvmdisasm_test|src\Core\JvmClass.cpp src\Disasm\JvmDisassembler.cpp src\Core\CFG.cpp src\Disasm\GmlDisassembler.cpp src\Core\GameMakerArchive.cpp
rem TEST|jvmload_test|src\Core\JvmClass.cpp src\Core\BinaryFile.cpp src\Core\FunctionAnalyzer.cpp src\Core\JumpTableResolver.cpp src\Core\CFG.cpp src\Core\Demangle.cpp src\Disasm\JvmDisassembler.cpp src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp
rem TEST|jvmannotate_test|src\Core\JvmAnnotate.cpp src\Core\JvmClass.cpp src\Disasm\JvmDisassembler.cpp src\Disasm\GmlDisassembler.cpp src\Core\GameMakerArchive.cpp
rem TEST|jdwp_test|src\Core\Jdwp.cpp
rem TEST|jdwp_client_mock_test|/DDS_JDWP_TEST_HOOKS src\Core\Jdwp.cpp src\Core\JdwpClient.cpp ws2_32.lib
rem TEST|project_roundtrip_test|src\Core\Project.cpp src\Core\AtomicFile.cpp src\Core\Json.cpp src\Core\ConnectionSchema.cpp
rem TEST|type_system_test|
rem TEST|project_synth_test|src\Core\Project.cpp src\Core\AtomicFile.cpp src\Core\Json.cpp src\Core\ConnectionSchema.cpp
rem TEST|raw_project_reopen_test|src\Core\Project.cpp src\Core\AtomicFile.cpp src\Core\Json.cpp src\Core\ConnectionSchema.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|xref_report_test|src\Core\XrefIndex.cpp src\Core\Report.cpp
rem TEST|xref_arch_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Core\XrefIndex.cpp src\Disasm\ZydisDisassembler.cpp src\Disasm\CapstoneDisassembler.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zydis.lib vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zycore.lib vcpkg_installed\x64-windows-static\x64-windows-static\lib\capstone.lib
rem TEST|cond_eval_test|src\Core\Cond.cpp
rem TEST|cond_compiled_test|src\Core\Cond.cpp
rem TEST|patch_pristine_test|
rem TEST|live_patch_original_test|
rem TEST|patched_image_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|decompiler_linemap_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|decompiler_python_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|decompiler_switch_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|decompiler_fixes_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|dataflow_decomp_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|decompiler_tempname_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|decompiler_folder_test|src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp
rem TEST|funcannotate_test|src\Core\FuncAnnotate.cpp src\Core\NetworkApiCatalog.cpp src\Core\ValidationApiCatalog.cpp src\Core\CFG.cpp
rem TEST|cortex_test|src\Core\Cortex.cpp src\Core\NetworkApiCatalog.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\AuthorizationAnalysis.cpp src\Core\PersistentStateCatalog.cpp src\Core\GameMakerArchive.cpp
rem TEST|prism_test|src\Core\Prism.cpp

rem LIVE_TEST|x64_debug_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Core\Debugger.cpp src\Core\Cond.cpp src\Core\AntiDebug.cpp src\Core\TraceCoverage.cpp src\Core\AuthorizationWatch.cpp src\Core\DllDebugPlan.cpp src\Core\NetworkEndpoint.cpp src\Core\NetworkApiCatalog.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Disasm\ZydisDisassembler.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zydis.lib vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zycore.lib ws2_32.lib winhttp.lib wininet.lib src\Core\GameMakerArchive.cpp src\Core\DebuggerGameMaker.cpp src\Core\GameMakerDebug.cpp src\Core\GameMakerRunner.cpp src\Core\GameMakerHelperImage.cpp src\Core\GameMakerInspection.cpp
rem TEST|debugger_lifecycle_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Core\Debugger.cpp src\Core\Cond.cpp src\Core\AntiDebug.cpp src\Core\TraceCoverage.cpp src\Core\AuthorizationWatch.cpp src\Core\DllDebugPlan.cpp src\Core\NetworkEndpoint.cpp src\Core\NetworkApiCatalog.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Disasm\ZydisDisassembler.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zydis.lib vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zycore.lib ws2_32.lib winhttp.lib wininet.lib src\Core\GameMakerArchive.cpp src\Core\DebuggerGameMaker.cpp src\Core\GameMakerDebug.cpp src\Core\GameMakerRunner.cpp src\Core\GameMakerHelperImage.cpp src\Core\GameMakerInspection.cpp
rem LIVE_TEST|wow64_debug_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Core\Debugger.cpp src\Core\Cond.cpp src\Core\AntiDebug.cpp src\Core\TraceCoverage.cpp src\Core\AuthorizationWatch.cpp src\Core\DllDebugPlan.cpp src\Core\NetworkEndpoint.cpp src\Core\NetworkApiCatalog.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Disasm\ZydisDisassembler.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zydis.lib vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zycore.lib ws2_32.lib winhttp.lib wininet.lib src\Core\GameMakerArchive.cpp src\Core\DebuggerGameMaker.cpp src\Core\GameMakerDebug.cpp src\Core\GameMakerRunner.cpp src\Core\GameMakerHelperImage.cpp src\Core\GameMakerInspection.cpp
rem LIVE_TEST|authorization_watch_live_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Core\Debugger.cpp src\Core\Cond.cpp src\Core\AntiDebug.cpp src\Core\TraceCoverage.cpp src\Core\AuthorizationWatch.cpp src\Core\DllDebugPlan.cpp src\Core\NetworkEndpoint.cpp src\Core\NetworkApiCatalog.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Disasm\ZydisDisassembler.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zydis.lib vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zycore.lib ws2_32.lib winhttp.lib wininet.lib src\Core\GameMakerArchive.cpp src\Core\DebuggerGameMaker.cpp src\Core\GameMakerDebug.cpp src\Core\GameMakerRunner.cpp src\Core\GameMakerHelperImage.cpp src\Core\GameMakerInspection.cpp

rem TEST|ui_widgets_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Ui\Widgets.cpp src\Ui\Theme.cpp src\Ui\Fonts.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\imgui.lib
rem INTEGRATION_TEST|static_listing_actions_test|tests\run_static_listing_actions_test.ps1
rem INTEGRATION_TEST|release_workbench_test|tests\run_release_workbench_test.ps1

rem TEST|gamemaker_archive_test|src\Core\GameMakerArchive.cpp
rem TEST|gml_disasm_test|src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp src\Core\CFG.cpp
rem TEST|gamemaker_debug_test|src\Core\GameMakerDebug.cpp
rem TEST|gamemaker_helper_image_test|src\Core\GameMakerHelperImage.cpp
rem TEST|gamemaker_runner_test|src\Core\GameMakerRunner.cpp
rem TEST|gamemaker_helper_gate_test|
rem TEST|gamemaker_inspection_test|src\Core\GameMakerInspection.cpp src\Core\GameMakerRunner.cpp
rem TEST|gamemaker_helper_state_test|src\Core\GameMakerDebug.cpp src\Core\GameMakerRunner.cpp
rem TEST|gamemaker_hook_mutation_test|
rem TEST|gamemaker_project_test|src\Core\Project.cpp src\Core\AtomicFile.cpp src\Core\Json.cpp src\Core\ConnectionSchema.cpp
rem TEST|gamemaker_load_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp src\Core\FunctionAnalyzer.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\CFG.cpp src\Core\Demangle.cpp
