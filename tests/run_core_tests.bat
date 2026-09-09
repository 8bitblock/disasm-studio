@echo off
rem Compatibility entrypoint and validated test manifest. Execution is owned by
rem run_core_tests.ps1: default Core; -Suite All includes every declaration;
rem -Suite Integration or Live selects that category; a test name selects one.
rem Build Release|x64 before All/Integration. Live/All require debugger support.
rem Logs and summary.json are retained under build/test-results.
setlocal EnableExtensions DisableDelayedExpansion
set "DS_TEST_SHELL=powershell.exe"
where pwsh.exe >nul 2>&1
if not errorlevel 1 set "DS_TEST_SHELL=pwsh.exe"
"%DS_TEST_SHELL%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_core_tests.ps1" %*
exit /b %ERRORLEVEL%
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
rem TEST|instruction_byte_pattern_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zydis.lib vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zycore.lib
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
rem TEST|crackme_triage_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Core\AnalysisCache.cpp src\Core\AnalysisService.cpp src\Core\ValueOrigin.cpp src\Core\StringActionTrace.cpp src\Core\AnalysisJobs.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\Demangle.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Core\FuncAnnotate.cpp src\Core\CrackmeTriage.cpp src\Core\NetworkApiCatalog.cpp src\Core\PersistentStateCatalog.cpp src\Core\ValidationApiCatalog.cpp src\Core\VerificationApiCatalog.cpp src\Core\MachineIdentityApiCatalog.cpp src\Core\AuthorizationAnalysis.cpp src\Core\AuthorizationTrail.cpp src\Core\AuthorizationPatchAdvisor.cpp src\Core\AuthorizationFieldAlias.cpp src\Core\SynthesisJob.cpp src\Core\Synthesis.cpp src\Core\PathExploreJob.cpp src\Core\PathExplore.cpp src\Core\ExprAst.cpp src\Core\SymEngine.cpp src\Core\Simplify.cpp src\Disasm\JvmDisassembler.cpp src\Disasm\ZydisDisassembler.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zydis.lib vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zycore.lib src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp
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
rem TEST|backtrace_test|
rem TEST|function_namer_pipeline_test|src\Core\FunctionNamer.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|string_action_trace_test|src\Core\StringActionTrace.cpp src\Core\CFG.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|analysis_cache_test|src\Core\AnalysisCache.cpp
rem TEST|document_result_identity_test|
rem TEST|attach_image_policy_test|
rem TEST|document_context_test|src\Core\DocumentContext.cpp src\Core\AnalysisCache.cpp src\Core\AnalysisService.cpp src\Core\ValueOrigin.cpp src\Core\StringActionTrace.cpp src\Core\CodeExport.cpp src\Core\AnalysisJobs.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\Demangle.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Core\FuncAnnotate.cpp src\Core\CrackmeTriage.cpp src\Core\NetworkApiCatalog.cpp src\Core\PersistentStateCatalog.cpp src\Core\ValidationApiCatalog.cpp src\Core\VerificationApiCatalog.cpp src\Core\MachineIdentityApiCatalog.cpp src\Core\AuthorizationAnalysis.cpp src\Core\AuthorizationTrail.cpp src\Core\AuthorizationPatchAdvisor.cpp src\Core\AuthorizationFieldAlias.cpp src\Core\SynthesisJob.cpp src\Core\Synthesis.cpp src\Core\PathExploreJob.cpp src\Core\PathExplore.cpp src\Core\ExprAst.cpp src\Core\SymEngine.cpp src\Core\Simplify.cpp src\Disasm\JvmDisassembler.cpp src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp
rem TEST|analysis_service_test|src\Core\AnalysisCache.cpp src\Core\AnalysisService.cpp src\Core\ValueOrigin.cpp src\Core\StringActionTrace.cpp src\Core\AnalysisJobs.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\Demangle.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Core\FuncAnnotate.cpp src\Core\CrackmeTriage.cpp src\Core\NetworkApiCatalog.cpp src\Core\PersistentStateCatalog.cpp src\Core\ValidationApiCatalog.cpp src\Core\VerificationApiCatalog.cpp src\Core\MachineIdentityApiCatalog.cpp src\Core\AuthorizationAnalysis.cpp src\Core\AuthorizationTrail.cpp src\Core\AuthorizationPatchAdvisor.cpp src\Core\AuthorizationFieldAlias.cpp src\Core\SynthesisJob.cpp src\Core\Synthesis.cpp src\Core\PathExploreJob.cpp src\Core\PathExplore.cpp src\Core\ExprAst.cpp src\Core\SymEngine.cpp src\Core\Simplify.cpp src\Disasm\JvmDisassembler.cpp src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp
rem TEST|persistent_file_triage_test|src\Core\AnalysisCache.cpp src\Core\AnalysisService.cpp src\Core\ValueOrigin.cpp src\Core\StringActionTrace.cpp src\Core\AnalysisJobs.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\Demangle.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Core\FuncAnnotate.cpp src\Core\CrackmeTriage.cpp src\Core\NetworkApiCatalog.cpp src\Core\PersistentStateCatalog.cpp src\Core\ValidationApiCatalog.cpp src\Core\VerificationApiCatalog.cpp src\Core\MachineIdentityApiCatalog.cpp src\Core\AuthorizationAnalysis.cpp src\Core\AuthorizationTrail.cpp src\Core\AuthorizationPatchAdvisor.cpp src\Core\AuthorizationFieldAlias.cpp src\Core\SynthesisJob.cpp src\Core\Synthesis.cpp src\Core\PathExploreJob.cpp src\Core\PathExplore.cpp src\Core\ExprAst.cpp src\Core\SymEngine.cpp src\Core\Simplify.cpp src\Disasm\JvmDisassembler.cpp src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp
rem TEST|synthesisjob_test|src\Core\SynthesisJob.cpp src\Core\Synthesis.cpp src\Core\SymEngine.cpp src\Core\ExprAst.cpp src\Core\Simplify.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|listing_layout_test|src\Core\AnalysisJobs.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\Demangle.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Disasm\JvmDisassembler.cpp src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp
rem TEST|listing_virtual_index_test|
rem TEST|graph_viewport_test|
rem TEST|patch_refresh_test|
rem TEST|firmware_sniffer_test|src\Core\FirmwareSniffer.cpp
rem TEST|code_export_test|src\Core\CodeExport.cpp src\Core\AnalysisJobs.cpp src\Core\CodeDataClassifier.cpp src\Core\JumpTableResolver.cpp src\Core\Demangle.cpp src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp src\Core\CFG.cpp src\Core\Decompiler.cpp src\Core\DataFlow.cpp src\Disasm\JvmDisassembler.cpp src\Core\GameMakerArchive.cpp src\Disasm\GmlDisassembler.cpp
rem TEST|trace_coverage_test|src\Core\TraceCoverage.cpp
rem TEST|trace_plan_test|
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

rem LIVE_TEST|x64_debug_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Core\Debugger.cpp src\Core\DebuggerBreakpointMemory.cpp src\Core\DebuggerBreakpoints.cpp src\Core\DebuggerExecution.cpp src\Core\DebuggerObservers.cpp src\Core\Cond.cpp src\Core\AntiDebug.cpp src\Core\TraceCoverage.cpp src\Core\AuthorizationWatch.cpp src\Core\DllDebugPlan.cpp src\Core\NetworkEndpoint.cpp src\Core\NetworkApiCatalog.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Disasm\ZydisDisassembler.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zydis.lib vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zycore.lib ws2_32.lib winhttp.lib wininet.lib src\Core\GameMakerArchive.cpp src\Core\DebuggerGameMaker.cpp src\Core\GameMakerDebug.cpp src\Core\GameMakerRunner.cpp src\Core\GameMakerHelperImage.cpp src\Core\GameMakerInspection.cpp
rem TEST|debugger_lifecycle_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Core\Debugger.cpp src\Core\DebuggerBreakpointMemory.cpp src\Core\DebuggerBreakpoints.cpp src\Core\DebuggerExecution.cpp src\Core\DebuggerObservers.cpp src\Core\Cond.cpp src\Core\AntiDebug.cpp src\Core\TraceCoverage.cpp src\Core\AuthorizationWatch.cpp src\Core\DllDebugPlan.cpp src\Core\NetworkEndpoint.cpp src\Core\NetworkApiCatalog.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Disasm\ZydisDisassembler.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zydis.lib vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zycore.lib ws2_32.lib winhttp.lib wininet.lib src\Core\GameMakerArchive.cpp src\Core\DebuggerGameMaker.cpp src\Core\GameMakerDebug.cpp src\Core\GameMakerRunner.cpp src\Core\GameMakerHelperImage.cpp src\Core\GameMakerInspection.cpp
rem LIVE_TEST|wow64_debug_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Core\Debugger.cpp src\Core\DebuggerBreakpointMemory.cpp src\Core\DebuggerBreakpoints.cpp src\Core\DebuggerExecution.cpp src\Core\DebuggerObservers.cpp src\Core\Cond.cpp src\Core\AntiDebug.cpp src\Core\TraceCoverage.cpp src\Core\AuthorizationWatch.cpp src\Core\DllDebugPlan.cpp src\Core\NetworkEndpoint.cpp src\Core\NetworkApiCatalog.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Disasm\ZydisDisassembler.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zydis.lib vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zycore.lib ws2_32.lib winhttp.lib wininet.lib src\Core\GameMakerArchive.cpp src\Core\DebuggerGameMaker.cpp src\Core\GameMakerDebug.cpp src\Core\GameMakerRunner.cpp src\Core\GameMakerHelperImage.cpp src\Core\GameMakerInspection.cpp
rem LIVE_TEST|authorization_watch_live_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Core\Debugger.cpp src\Core\DebuggerBreakpointMemory.cpp src\Core\DebuggerBreakpoints.cpp src\Core\DebuggerExecution.cpp src\Core\DebuggerObservers.cpp src\Core\Cond.cpp src\Core\AntiDebug.cpp src\Core\TraceCoverage.cpp src\Core\AuthorizationWatch.cpp src\Core\DllDebugPlan.cpp src\Core\NetworkEndpoint.cpp src\Core\NetworkApiCatalog.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Disasm\ZydisDisassembler.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zydis.lib vcpkg_installed\x64-windows-static\x64-windows-static\lib\Zycore.lib ws2_32.lib winhttp.lib wininet.lib src\Core\GameMakerArchive.cpp src\Core\DebuggerGameMaker.cpp src\Core\GameMakerDebug.cpp src\Core\GameMakerRunner.cpp src\Core\GameMakerHelperImage.cpp src\Core\GameMakerInspection.cpp

rem TEST|ui_widgets_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Ui\Widgets.cpp src\Ui\Theme.cpp src\Ui\Fonts.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\imgui.lib
rem INTEGRATION_TEST|static_listing_actions_test|tests\run_static_listing_actions_test.ps1
rem INTEGRATION_TEST|release_workbench_test|tests\run_release_workbench_test.ps1
rem INTEGRATION_TEST|feature_tabs_ui_test|tests\run_feature_tabs_ui_test.ps1
rem TEST|signature_library_test|src\Core\SignatureLibrary.cpp src\Core\Json.cpp src\Core\SigMatch.cpp src\Core\AtomicFile.cpp
rem TEST|value_origin_test|src\Core\ValueOrigin.cpp src\Core\CFG.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp

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

rem TEST|patch_recovery_test|src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp src\Core\Project.cpp src\Core\AtomicFile.cpp src\Core\Json.cpp src\Core\ConnectionSchema.cpp
rem TEST|assembler_encoding_test|/MT /I vcpkg_installed\x64-windows-static\x64-windows-static\include src\Disasm\Assembler.cpp src\Core\PatchCompiler.cpp vcpkg_installed\x64-windows-static\x64-windows-static\lib\keystone.lib shell32.lib
rem TEST|artifact_write_test|src\Core\ArtifactWrite.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp src\Core\GameMakerArchive.cpp
rem TEST|debugger_memory_mutation_test|src\Core\DebuggerBreakpointMemory.cpp
