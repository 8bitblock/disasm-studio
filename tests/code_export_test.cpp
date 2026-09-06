#include "Core/CodeExport.h"
#include "Core/BinaryFile.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(x, msg) do { if (!(x)) { std::fprintf(stderr, "FAIL: %s\n", msg); ++g_fail; } } while (0)

class ExportStubDisasm : public IDisassembler {
public:
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "export-test-stub"; }

    std::vector<Instruction> disassemble(const uint8_t* p, size_t n, uint64_t va,
                                         size_t max = 0) override {
        std::vector<Instruction> out;
        for (size_t off = 0; off < n && (!max || out.size() < max);) {
            Instruction in;
            if (!decodeOne(p + off, n - off, va + off, in)) { ++off; continue; }
            out.push_back(in); off += in.length;
        }
        return out;
    }

    bool decodeOne(const uint8_t* p, size_t n, uint64_t va, Instruction& out) override {
        if (!p || !n || p[0] == 0xFF) return false;
        out = {};
        out.address = va; out.length = 1;
        char b[4]; std::snprintf(b, sizeof(b), "%02X", p[0]); out.bytes = b;
        switch (p[0]) {
            case 0x01: out.mnemonic = "mov"; out.operands = "rax, 0x2a"; break;
            case 0x02:
                out.mnemonic = "call"; out.isBranch = out.isCall = true;
                out.branchTarget = 0x2000; out.branchTargetValid = true; break;
            case 0x03: out.mnemonic = "ret"; out.isBranch = out.isRet = true; break;
            case 0x04: out.mnemonic = "cpuid"; break; // becomes DS_UNMODELED in compilable C
            case 0x05: out.mnemonic = "lea"; out.operands = "rax, [rax + 4]"; break;
            default:   out.mnemonic = "nop"; break;
        }
        return true;
    }
};

class GateExportDisasm final : public ExportStubDisasm {
public:
    GateExportDisasm(std::shared_ptr<std::atomic<bool>> entered,
                     std::shared_ptr<std::atomic<bool>> release)
        : entered_(std::move(entered)), release_(std::move(release)) {}

    bool decodeOne(const uint8_t* p, size_t n, uint64_t va, Instruction& out) override {
        bool expected = false;
        if (gated_.compare_exchange_strong(expected, true)) {
            entered_->store(true, std::memory_order_release);
            while (!release_->load(std::memory_order_acquire)) std::this_thread::yield();
        }
        return ExportStubDisasm::decodeOne(p, n, va, out);
    }

private:
    std::shared_ptr<std::atomic<bool>> entered_, release_;
    std::atomic<bool> gated_{false};
};

class FixedWidthExportDisasm final : public IDisassembler {
public:
    Engine engine() const override { return Engine::Capstone; }
    const char* engineName() const override { return "fixed-width-export-test"; }
    uint32_t invalidDecodeWidth() const override { return 4; }
    bool decodeOne(const uint8_t* p, size_t n, uint64_t va, Instruction& out) override {
        if (!p || n < 4 || p[0] == 0xFF) return false;
        out = {}; out.address = va; out.length = 4; out.mnemonic = "nop";
        char b[16];
        std::snprintf(b, sizeof(b), "%02X %02X %02X %02X", p[0], p[1], p[2], p[3]);
        out.bytes = b;
        return true;
    }
    std::vector<Instruction> disassemble(const uint8_t* p, size_t n, uint64_t va,
                                         size_t max = 0) override {
        std::vector<Instruction> out;
        for (size_t off = 0; off < n && (!max || out.size() < max);) {
            Instruction in;
            if (!decodeOne(p + off, n - off, va + off, in)) {
                off += std::min<size_t>(n - off, invalidDecodeWidth());
                continue;
            }
            out.push_back(in); off += in.length;
        }
        return out;
    }
};

static std::string slurp(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream s; s << f.rdbuf(); return s.str();
}

static bool awaitExport(CodeExportService& service, CodeExportResult& result) {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (std::chrono::steady_clock::now() < deadline) {
        if (service.tryTakeResult(result)) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    return false;
}

int main() {
    namespace fs = std::filesystem;
    const std::string imagePath = "ds_code_export_fixture.bin";
    const std::string outPath = "ds_code_export_generated.c";
    const std::string cancelPath = "ds_code_export_cancelled.c";
    const std::string objPath = "ds_code_export_generated.obj";
    const std::string logPath = "ds_code_export_compile.log";
    const std::vector<uint8_t> bytes = {
        0x01, 0x02, 0x04, 0x03, // first function: value, external call, raw op, return
        0x05, 0x01, 0x03, 0xFF  // second function plus an ASM decode failure
    };
    { std::ofstream f(imagePath, std::ios::binary | std::ios::trunc);
      f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }

    BinaryFile bin;
    CHECK(bin.loadRaw(imagePath, 0x1000), "load raw export fixture");

    CodeExportRequest req;
    req.binary = &bin; req.engine = Engine::Zydis; req.arch = Arch::X64;
    req.sourceName = "fixture */ still-comment.c";
    req.expectedImageRevision = bin.imageRevision();
    req.functions = {
        { 0x1000, 4, "9bad.name", "__int64 (a1)" },
        { 0x1004, 4, "9bad-name", "__int64 ()" }
    };
    req.names[0x1000] = "9bad.name";
    req.names[0x1004] = "9bad-name"; // sanitizes to same base; VA suffix must de-dup
    req.names[0x2000] = "KERNEL32.Create-FileW";
    req.comments[0x1000] = "analyst entry comment";

    // Full ASM sweep: labels/comments survive, and an undecodable byte becomes db
    // rather than truncating the remainder of the executable section.
    {
        ExportStubDisasm dis;
        CodeExportRequest a = req;
        a.format = CodeExportFormat::Assembly;
        std::ostringstream text;
        CodeExportResult r = GenerateCodeExport(a, dis, text);
        const std::string s = text.str();
        CHECK(r.success, "whole-program ASM generator succeeds");
        CHECK(s.find("9bad_name:") != std::string::npos, "ASM has sanitized function label");
        CHECK(s.find("analyst entry comment") != std::string::npos, "ASM has analyst comment");
        CHECK(s.find("db 0xFF ; decode failure") != std::string::npos,
              "ASM emits db and continues on decode failure");
        CHECK(s.find("0000000000001007") != std::string::npos, "ASM sweeps the complete executable range");
    }

    // Fixed-width ARM-family exports recover by a whole word after malformed
    // data. The directive contains the complete failed word and the next aligned
    // instruction remains decodable.
    {
        const std::string fixedPath = "ds_code_export_fixed.bin";
        const uint8_t fixedBytes[] = { 0xFF,0xFF,0xFF,0xFF, 0x00,0x00,0x00,0x00 };
        { std::ofstream f(fixedPath, std::ios::binary | std::ios::trunc);
          f.write((const char*)fixedBytes, sizeof(fixedBytes)); }
        BinaryFile fixedBin;
        CHECK(fixedBin.loadRaw(fixedPath, 0x80000000ull), "load fixed-width export fixture");
        CodeExportRequest a;
        a.binary = &fixedBin; a.engine = Engine::Capstone; a.arch = Arch::ARM;
        a.format = CodeExportFormat::Assembly;
        a.expectedImageRevision = fixedBin.imageRevision();
        std::ostringstream text;
        FixedWidthExportDisasm dis;
        const CodeExportResult r = GenerateCodeExport(a, dis, text);
        const std::string s = text.str();
        CHECK(r.success, "fixed-width ASM generator succeeds after malformed word");
        CHECK(s.find("db 0xFF, 0xFF, 0xFF, 0xFF") != std::string::npos,
              "fixed-width ASM emits one complete-word decode-failure directive");
        CHECK(s.find("0000000080000004") != std::string::npos &&
              s.find("nop") != std::string::npos,
              "fixed-width ASM resumes at the next aligned instruction");
        fs::remove(fixedPath);
    }

    // Real-mode firmware remains fully exportable as ASM and as conservative
    // readable pseudocode.  The self-contained C transform stays restricted to
    // the architectures whose data-flow and ABI model it can represent safely.
    {
        ExportStubDisasm dis;
        CodeExportRequest a = req;
        a.arch = Arch::X86_16;
        a.format = CodeExportFormat::Assembly;
        std::ostringstream asmText;
        CHECK(GenerateCodeExport(a, dis, asmText).success,
              "x86-16 supports whole-image assembly export");
        a.format = CodeExportFormat::C;
        a.cStyle = CodeExportCStyle::Readable;
        std::ostringstream cText;
        CodeExportResult c = GenerateCodeExport(a, dis, cText);
        CHECK(c.success && cText.str().find("__asm") != std::string::npos,
              "x86-16 readable pseudocode preserves raw instructions");
        a.cStyle = CodeExportCStyle::Compilable;
        std::ostringstream compilable;
        c = GenerateCodeExport(a, dis, compilable);
        CHECK(!c.success && c.message.find("x86/x64") != std::string::npos,
              "x86-16 rejects the self-contained C export path clearly");
    }

    // Function scope is exact, including a nonzero selected VA (the Core path also
    // treats VA zero as valid because scope is explicit rather than sentinel-based).
    {
        ExportStubDisasm dis;
        CodeExportRequest a = req;
        a.format = CodeExportFormat::Assembly; a.scope = CodeExportScope::Function;
        a.functionVA = 0x1004;
        std::ostringstream text;
        CodeExportResult r = GenerateCodeExport(a, dis, text);
        CHECK(r.success, "per-function ASM generator succeeds");
        CHECK(text.str().find("0000000000001004") != std::string::npos &&
              text.str().find("0000000000001000") == std::string::npos,
              "per-function ASM includes only the exact selected function");
    }

    // Readable mode concatenates every selected function without applying the
    // compilable transform: analyst display names and raw pseudo-C remain intact.
    {
        ExportStubDisasm dis;
        CodeExportRequest c = req;
        c.format = CodeExportFormat::C; c.cStyle = CodeExportCStyle::Readable;
        std::ostringstream text;
        CodeExportResult r = GenerateCodeExport(c, dis, text);
        const std::string s = text.str();
        CHECK(r.success, "readable C generator succeeds");
        CHECK(s.find("9bad.name") != std::string::npos &&
              s.find("9bad-name") != std::string::npos,
              "readable whole-program C exports every function without sanitizing display names");
        CHECK(s.find("__asm") != std::string::npos && s.find("DS_UNMODELED") == std::string::npos,
              "readable mode preserves the decompiler's original pseudo-C body");
        CHECK(s.find("analyst entry comment") != std::string::npos,
              "readable C carries the function-level analyst comment");
    }

    // Discovery provenance, confidence, noncontiguous chunks, and ownership
    // truncation remain visible in every export representation.
    {
        ExportStubDisasm dis;
        CodeExportRequest metadata = req;
        metadata.scope = CodeExportScope::Function;
        metadata.functionVA = 0x1000;
        metadata.functions.resize(1);
        metadata.functions[0].chunks = {{0x1000, 2}, {0x1004, 2}};
        metadata.functions[0].ownershipTruncated = true;
        metadata.functions[0].seedKind = FunctionSeedKind::Analyst;
        metadata.functions[0].boundaryConfidence =
            FunctionBoundaryConfidence::Reconciled;
        auto checkMetadata = [&](CodeExportFormat format, CodeExportCStyle style,
                                 const char* label) {
            metadata.format = format;
            metadata.cStyle = style;
            std::ostringstream text;
            CodeExportResult result = GenerateCodeExport(metadata, dis, text);
            const std::string output = text.str();
            CHECK(result.success, label);
            CHECK(output.find("seed=analyst") != std::string::npos, label);
            CHECK(output.find("boundary=reconciled") != std::string::npos, label);
            CHECK(output.find("ownership=truncated") != std::string::npos, label);
            CHECK(output.find("chunks=2 [0x1000+0x2, 0x1004+0x2]") !=
                  std::string::npos, label);
        };
        checkMetadata(CodeExportFormat::Assembly, CodeExportCStyle::Readable,
                      "ASM retains function discovery metadata");
        checkMetadata(CodeExportFormat::C, CodeExportCStyle::Readable,
                      "readable C retains function discovery metadata");
        checkMetadata(CodeExportFormat::C, CodeExportCStyle::Compilable,
                      "compilable C retains function discovery metadata");
    }

    // Compilable mode produces a self-contained C11 unit, sanitizes/collision-
    // de-dups symbols, stubs external calls, neutralizes comment terminators, and
    // translates unmodeled assembly / LEA forms to portable helpers.
    {
        ExportStubDisasm dis;
        CodeExportRequest c = req;
        c.format = CodeExportFormat::C; c.cStyle = CodeExportCStyle::Compilable;
        std::ostringstream text;
        CodeExportResult r = GenerateCodeExport(c, dis, text);
        const std::string s = text.str();
        CHECK(r.success, "compilable C generator succeeds");
        CHECK(s.find("#include <stdint.h>") != std::string::npos &&
              s.find("typedef uintptr_t ds_word_t") != std::string::npos,
              "compilable C has a self-contained portable preamble");
        CHECK(s.find("static ds_word_t sym_9bad_name(") != std::string::npos,
              "invalid leading-digit/dotted symbol is sanitized");
        CHECK(s.find("sym_9bad_name_1004") != std::string::npos,
              "sanitized symbol collisions receive a deterministic VA suffix");
        CHECK(s.find("KERNEL32_Create_FileW") != std::string::npos,
              "external punctuation is sanitized and a call stub is emitted");
        CHECK(s.find("DS_UNMODELED") != std::string::npos && s.find("DS_ADDR") != std::string::npos,
              "unsupported instructions and address expressions use portable helpers");
        CHECK(s.find("fixture */ still") == std::string::npos,
              "analyst-controlled comment terminators are neutralized");
    }

    // Service path: private decoder, background temp output, result pickup, and
    // successful final commit. The generated translation unit is then compiled by
    // the platform C compiler, making "compilable" an executable contract.
    {
        CodeExportService svc([](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<ExportStubDisasm>();
        });
        CodeExportRequest c = req;
        c.format = CodeExportFormat::C; c.cStyle = CodeExportCStyle::Compilable;
        c.outputPath = outPath;
        CHECK(svc.request(std::move(c)), "background service accepts an idle request");
        CodeExportResult result;
        bool have = false;
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline && !have) {
            have = svc.tryTakeResult(result);
            if (!have) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(have && result.success, "background service returns a successful result");
        CHECK(!svc.pending() && svc.progress().phase == CodeExportPhase::Idle,
              "service returns to Idle after final commit");
        CHECK(fs::exists(outPath) && slurp(outPath).find("self-contained compilable C") != std::string::npos,
              "service commits the complete generated file");
        bool tempLeft = false;
        for (const auto& e : fs::directory_iterator("."))
            if (e.path().filename().string().find("ds_code_export_generated.c.disasmstudio-") == 0)
                tempLeft = true;
        CHECK(!tempLeft, "service leaves no temporary or backup file after commit");
        svc.cancelAndWaitIdle();
    }

    // A decoder factory is extension-shaped code even though the application
    // ships no plugin API.  An exception at that boundary must become a normal
    // failed result, and the owned worker must remain usable for a later export.
    {
        auto calls = std::make_shared<std::atomic<unsigned>>(0);
        CodeExportService svc([calls](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            if (calls->fetch_add(1, std::memory_order_acq_rel) == 0)
                throw std::runtime_error("injected decoder-factory failure");
            return std::make_unique<ExportStubDisasm>();
        });
        CodeExportRequest first = req;
        first.format = CodeExportFormat::C;
        first.cStyle = CodeExportCStyle::Compilable;
        first.outputPath = outPath;
        CHECK(svc.request(std::move(first)), "worker accepts injected failing export");
        CodeExportResult failed;
        bool haveFailure = false;
        const auto failureDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < failureDeadline && !haveFailure) {
            haveFailure = svc.tryTakeResult(failed);
            if (!haveFailure) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(haveFailure && !failed.success &&
              failed.message.find("injected decoder-factory failure") != std::string::npos,
              "worker publishes decoder-factory exceptions as failed results");

        CodeExportRequest second = req;
        second.format = CodeExportFormat::C;
        second.cStyle = CodeExportCStyle::Compilable;
        second.outputPath = outPath;
        CHECK(svc.request(std::move(second)), "worker remains usable after a failed factory call");
        CodeExportResult recovered;
        bool haveRecovery = false;
        const auto recoveryDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < recoveryDeadline && !haveRecovery) {
            haveRecovery = svc.tryTakeResult(recovered);
            if (!haveRecovery) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(haveRecovery && recovered.success,
              "worker completes a later export after the injected exception");
        svc.cancelAndWaitIdle();
    }

    // In-flight cancellation is cooperative and leaves an existing destination
    // byte-for-byte intact. A gated private decoder makes the cancellation window
    // deterministic, then release lets the worker observe its cancellation token.
    {
        { std::ofstream keep(cancelPath, std::ios::binary | std::ios::trunc); keep << "KEEP\n"; }
        auto entered = std::make_shared<std::atomic<bool>>(false);
        auto release = std::make_shared<std::atomic<bool>>(false);
        CodeExportService svc([entered, release](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<GateExportDisasm>(entered, release);
        });
        CodeExportRequest c = req;
        c.format = CodeExportFormat::C; c.cStyle = CodeExportCStyle::Compilable;
        c.outputPath = cancelPath;
        CHECK(svc.request(std::move(c)), "cancellation service accepts request");
        const auto enterDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (!entered->load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < enterDeadline)
            std::this_thread::yield();
        CHECK(entered->load(std::memory_order_acquire), "export is demonstrably in flight before cancellation");
        svc.cancel();
        release->store(true, std::memory_order_release);

        CodeExportResult result;
        bool have = false;
        const auto resultDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < resultDeadline && !have) {
            have = svc.tryTakeResult(result);
            if (!have) std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(have && result.cancelled && !result.success,
              "in-flight cancellation returns an explicit cancelled result");
        CHECK(slurp(cancelPath) == "KEEP\n", "cancelled export leaves existing destination unchanged");
        bool tempLeft = false;
        for (const auto& e : fs::directory_iterator("."))
            if (e.path().filename().string().find("ds_code_export_cancelled.c.disasmstudio-") == 0)
                tempLeft = true;
        CHECK(!tempLeft, "cancelled export removes its temporary output");
        svc.cancelAndWaitIdle();
    }

    // A destination directory is never an export file, even when empty. The
    // previous commit path moved it aside and silently replaced it with text.
    {
        const std::string directoryPath = "ds_code_export_directory_" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        CHECK(fs::create_directory(directoryPath), "create directory destination fixture");
        CodeExportService svc([](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<ExportStubDisasm>();
        });
        CodeExportRequest request = req;
        request.outputPath = directoryPath;
        CHECK(svc.request(std::move(request)), "worker accepts directory-path validation request");
        CodeExportResult result;
        CHECK(awaitExport(svc, result) && !result.success,
              "export refuses to replace an existing directory");
        CHECK(fs::is_directory(directoryPath), "rejected directory remains in place");
        svc.cancelAndWaitIdle();
        fs::remove(directoryPath);
    }

    // Document services may export the same path concurrently. Keep the first
    // writer paused with its stream open while the second finishes: each must
    // own its scratch, and the final destination must contain one whole export.
    {
        const std::string sharedPath = "ds_code_export_shared_" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".asm";
        const std::string oldTemp = sharedPath + ".disasmstudio-tmp-1";
        const std::string oldBackup = sharedPath + ".disasmstudio-backup-1";
        { std::ofstream file(sharedPath); file << "ORIGINAL"; }
        { std::ofstream file(oldTemp); file << "UNRELATED TEMP"; }
        { std::ofstream file(oldBackup); file << "UNRELATED BACKUP"; }
        auto entered = std::make_shared<std::atomic<bool>>(false);
        auto release = std::make_shared<std::atomic<bool>>(false);
        CodeExportService first([entered, release](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<GateExportDisasm>(entered, release);
        });
        CodeExportService second([](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<ExportStubDisasm>();
        });
        CodeExportRequest a = req;
        a.outputPath = sharedPath;
        a.sourceName = "first concurrent export";
        CodeExportRequest b = a;
        b.sourceName = "second concurrent export";
        CHECK(first.request(std::move(a)), "first document starts its export");
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (!entered->load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline)
            std::this_thread::yield();
        CHECK(entered->load(std::memory_order_acquire), "first document holds an open export stream");
        CHECK(second.request(std::move(b)), "second document starts the same destination export");
        CodeExportResult secondResult;
        const bool secondDone = awaitExport(second, secondResult);
        CHECK(secondDone && secondResult.success,
              "second document completes while the first export is paused");
        CHECK(slurp(sharedPath).find("second concurrent export") != std::string::npos,
              "second document installs its complete output");
        release->store(true, std::memory_order_release);
        CodeExportResult firstResult;
        CHECK(awaitExport(first, firstResult) && firstResult.success,
              "first document retains its scratch and completes afterward");
        CHECK(slurp(sharedPath).find("first concurrent export") != std::string::npos &&
              slurp(sharedPath).find("second concurrent export") == std::string::npos,
              "last completed export replaces the destination without mixed output");
        CHECK(slurp(oldTemp) == "UNRELATED TEMP" && slurp(oldBackup) == "UNRELATED BACKUP",
              "export never removes or truncates a pre-existing scratch-shaped file");
        first.cancelAndWaitIdle();
        second.cancelAndWaitIdle();
        fs::remove(sharedPath);
        fs::remove(oldTemp);
        fs::remove(oldBackup);
    }

#ifdef _WIN32
    const std::string compile = "cl /nologo /TC /c \"" + outPath + "\" /Fo\"" + objPath +
                                "\" >\"" + logPath + "\" 2>&1";
#else
    const std::string compile = "cc -std=c11 -c \"" + outPath + "\" -o \"" + objPath +
                                "\" >\"" + logPath + "\" 2>&1";
#endif
    const int compileRc = std::system(compile.c_str());
    if (compileRc != 0) std::fprintf(stderr, "Generated-C compiler output:\n%s\n", slurp(logPath).c_str());
    CHECK(compileRc == 0, "self-contained compilable export compiles as C");

    std::remove(imagePath.c_str());
    std::remove(outPath.c_str());
    std::remove(cancelPath.c_str());
    std::remove(objPath.c_str());
    std::remove(logPath.c_str());
    if (!g_fail) std::printf("code_export_test: all checks passed\n");
    else std::printf("code_export_test: %d FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
