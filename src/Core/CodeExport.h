#pragma once
//
// CodeExport.h
// Whole-program / per-function assembly and C export.  The generator and its
// small background service are deliberately ImGui- and Win32-free: callers pass
// immutable function/name/comment snapshots and the worker builds its own
// decoder through an injected factory.
//
// Lifetime contract: CodeExportRequest::binary is read on the worker.  It must
// outlive the request, and the owner MUST call cancelAndWaitIdle() before a load,
// clear, patch, or destruction which can mutate/reallocate that BinaryFile.
// expectedImageRevision detects a stale request at safe checkpoints; it is not a
// substitute for the lifetime contract.

#include "AnalysisJobs.h"              // DecompileNameMap
#include "../Disasm/IDisassembler.h"   // Engine, Arch, IDisassembler

#include <cstdint>
#include <functional>
#include <iosfwd>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace ds {

class BinaryFile;

enum class CodeExportFormat : uint8_t {
    Asm = 0,
    Assembly = Asm, // readable alias for call sites
    C
};

enum class CodeExportScope : uint8_t {
    WholeProgram = 0,
    Function,
    CurrentFunction = Function
};

enum class CodeExportCStyle : uint8_t {
    Readable = 0,   // the decompiler's display pseudo-C, unchanged
    Compilable      // normalized, self-contained portable C11 translation unit
};

struct CodeExportFunction {
    uint64_t    address = 0;
    uint32_t    size = 0;
    std::string name;
    std::string signature; // optional inferred "<return-type> (args)" snapshot
    std::string callingConvention; // analyst ABI override for Raw images
    std::vector<FunctionChunk> chunks;
    bool ownershipTruncated = false;
    FunctionSeedKind seedKind = FunctionSeedKind::Prologue;
    FunctionBoundaryConfidence boundaryConfidence = FunctionBoundaryConfidence::Heuristic;
    bool noreturnValid = false;
    bool noreturn = false;
};

using CodeExportCommentMap = std::unordered_map<uint64_t, std::string>;

struct CodeExportRequest {
    const BinaryFile* binary = nullptr;
    Engine            engine = Engine::Zydis;
    Arch              arch = Arch::X64;
    ByteOrder         byteOrder = ByteOrder::Little;
    DecoderFeatures   decoderFeatures;
    std::string       outputPath; // UTF-8 destination (service only)
    std::string       sourceName; // optional display name; binary->path() is fallback

    CodeExportFormat format = CodeExportFormat::Asm;
    CodeExportScope  scope = CodeExportScope::WholeProgram;
    CodeExportCStyle cStyle = CodeExportCStyle::Readable;

    // Used only for Function scope.  VA zero is valid: scope, rather than a zero
    // sentinel, says whether this member is active.
    uint64_t functionVA = 0;

    // Immutable UI snapshots.  `functions` is sorted/de-duplicated again by the
    // generator defensively.  `names` should include imports, discovered/guessed
    // functions, then analyst renames (last writer wins).
    std::vector<CodeExportFunction> functions;
    DecompileNameMap                names;
    CodeExportCommentMap            comments;

    // Zero means "capture binary->imageRevision() when the service accepts the
    // request".  A non-zero mismatch fails before the worker reads image bytes.
    uint64_t expectedImageRevision = 0;
};

enum class CodeExportPhase : uint8_t {
    Idle = 0,
    Preparing,
    Assembly,
    Decompiling,
    Finalizing
};

const char* CodeExportPhaseName(CodeExportPhase phase);

struct CodeExportProgress {
    CodeExportPhase phase = CodeExportPhase::Idle;
    uint64_t current = 0;       // bytes for Assembly, functions for Decompiling
    uint64_t total = 0;
    uint64_t functionVA = 0;    // current function during C export (zero may be real)
    uint64_t bytesWritten = 0;
};

struct CodeExportResult {
    bool        success = false;
    bool        cancelled = false;
    std::string path;
    std::string message;
    uint64_t    bytesWritten = 0;
};

using CodeExportCancelFn = std::function<bool()>;
using CodeExportProgressFn = std::function<void(const CodeExportProgress&)>;

// Stream an export through `out`.  This is the pure generator used by the
// background service and by focused tests.  It never opens request.outputPath.
// The returned byte count is the number written to `out`.
CodeExportResult GenerateCodeExport(const CodeExportRequest& request,
                                    IDisassembler& decoder,
                                    std::ostream& out,
                                    const CodeExportCancelFn& cancelled = {},
                                    const CodeExportProgressFn& progress = {});

class CodeExportService {
public:
    using DecoderFactory = std::function<std::unique_ptr<IDisassembler>(const DecoderConfig&)>;
    using LegacyDecoderFactory = std::function<std::unique_ptr<IDisassembler>(Engine, Arch)>;

    explicit CodeExportService(DecoderFactory factory);
    explicit CodeExportService(LegacyDecoderFactory factory);
    ~CodeExportService();

    CodeExportService(const CodeExportService&) = delete;
    CodeExportService& operator=(const CodeExportService&) = delete;

    // Accept one export at a time.  Returns false while another request is queued
    // or running, or when the request is structurally invalid.  A completed,
    // unpicked result does not prevent a new request.
    bool request(CodeExportRequest request);

    bool pending() const;
    CodeExportProgress progress() const;
    bool tryTakeResult(CodeExportResult& out);

    // Non-blocking cancel: queued work is dropped and active generation stops at
    // its next checkpoint.  Active cancellation still yields a cancelled result.
    void cancel();

    // Supersede queued/running work, remove unpicked results, and wait until the
    // worker is no longer reading the BinaryFile.  Required before image mutation.
    void cancelAndWaitIdle();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace ds
