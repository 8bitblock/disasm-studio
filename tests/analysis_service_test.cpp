//
// analysis_service_test.cpp
// Unit-tests the background analysis foundation (AnalysisJobs + AnalysisService)
// with a stub disassembler — the threading/epoch/coalescing mechanics and the
// ported string scanner, none of which need Windows/Zydis/ImGui.
//
// Compile + run (MSVC dev shell), from the repo root:
//   cl /nologo /std:c++20 /EHsc /I src tests\analysis_service_test.cpp ^
//      src\Core\AnalysisService.cpp src\Core\AnalysisJobs.cpp src\Core\XrefIndex.cpp ^
//      src\Core\BinaryFile.cpp src\Core\FunctionAnalyzer.cpp src\Core\FunctionNamer.cpp ^
//      src\Core\AlgoScan.cpp src\Core\SigMatch.cpp
//
#include "Core/AnalysisService.h"
#include "Core/AnalysisJobs.h"
#include "Core/BinaryFile.h"
#include "Disasm/IDisassembler.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <memory>
#include <thread>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

// Minimal decoder: every byte is a 1-byte "nop"; no branches/calls/rets.
struct StubDisasm : IDisassembler {
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "stub"; }
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va, Instruction& out) override {
        if (!data || size == 0) return false;
        out = Instruction{};
        out.address = va; out.length = 1; out.mnemonic = "nop"; out.bytes = "90";
        return true;
    }
    std::vector<Instruction> disassemble(const uint8_t* data, size_t size,
                                         uint64_t va, size_t maxInstructions) override {
        std::vector<Instruction> v;
        size_t off = 0;
        while (off < size && (maxInstructions == 0 || v.size() < maxInstructions)) {
            Instruction in;
            if (!decodeOne(data + off, size - off, va + off, in)) break;
            v.push_back(in); off += in.length;
        }
        return v;
    }
};

static std::string writeTempBlob() {
    std::string path = "ds_anajobs_tmp.bin";
    std::ofstream f(path, std::ios::binary);
    char z = 0; char ff = (char)0xFF;             // 0xFF: non-printable, non-zero separator
    const char* ascii = "Hello, world!";          // ASCII run at offset 0
    f.write(ascii, (std::streamsize)std::strlen(ascii));
    f.write(&ff, 1);
    f.write("no", 2); f.write(&ff, 1);            // < 4 chars: ignored (FF stops a wide chain)
    for (const char* s = "Wide"; *s; ++s) { f.write(s, 1); f.write(&z, 1); }  // UTF-16LE "Wide"
    f.write(&ff, 1);                              // terminate the wide run (non-zero)
    return path;
}

int main() {
    const uint64_t base = 0x140000000ull;
    std::string path = writeTempBlob();
    BinaryFile bin;
    CHECK(bin.loadRaw(path, base), "loadRaw");

    // ---- ScanStringsImage ----
    auto strs = ScanStringsImage(bin);
    bool foundHello = false, foundWide = false;
    for (auto& s : strs) {
        if (s.text == "Hello, world!" && !s.wide && s.address == base + 0) foundHello = true;
        if (s.text == "Wide" && s.wide) foundWide = true;
    }
    CHECK(foundHello, "ascii 'Hello, world!' at base+0");
    CHECK(foundWide,  "utf-16 'Wide'");
    for (size_t i = 1; i < strs.size(); ++i) CHECK(strs[i - 1].address <= strs[i].address, "strings sorted by address");

    // ---- AnalysisService mechanics (worker pool, incremental per-pass delivery) ----
    AnalysisService svc([](Engine, Arch) -> std::unique_ptr<IDisassembler> {
        return std::make_unique<StubDisasm>();
    });

    // The pool emits ONE result per pass, so drain everything for `wantEpoch` and
    // merge the per-pass valid flags. Stops early once `done(merged)` holds.
    auto collect = [&](int ms, uint64_t wantEpoch,
                       const std::function<bool(const AnalysisResult&)>& done) -> AnalysisResult {
        AnalysisResult merged; merged.epoch = wantEpoch;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            AnalysisResult tmp;
            while (svc.tryTakeBulk(tmp)) {
                if (tmp.epoch != wantEpoch) continue;
                if (tmp.stringsValid) { merged.strings = tmp.strings; merged.stringsValid = true; }
                if (tmp.funcsValid)   { merged.functions = tmp.functions; merged.summary = tmp.summary; merged.funcsValid = true; }
                if (tmp.listingValid) { merged.listRows = tmp.listRows; merged.listInsnCount = tmp.listInsnCount; merged.listingValid = true; }
                if (tmp.xref)         { merged.xref = tmp.xref; }
                if (tmp.algosValid)   { merged.algos = tmp.algos; merged.algosValid = true; }
                if (tmp.moduleBase)   merged.moduleBase = tmp.moduleBase;
            }
            if (done(merged)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return merged;
    };

    // Bulk K_Strings round-trips with the matching epoch.
    {
        uint64_t e = svc.epoch();
        svc.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Strings, false, e);
        AnalysisResult got = collect(3000, e, [](const AnalysisResult& r) { return r.stringsValid; });
        CHECK(got.stringsValid, "bulk K_Strings produced a stringsValid result");
        CHECK(e == svc.epoch(), "epoch unchanged");
        bool h = false; for (auto& s : got.strings) if (s.text == "Hello, world!") h = true;
        CHECK(h, "worker scanned the ascii string");
    }

    // Epoch gating: a bumped epoch means no result is ever accepted as current.
    {
        uint64_t e = svc.epoch();
        svc.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Strings, false, e);
        svc.bumpEpoch();
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        while (std::chrono::steady_clock::now() < deadline) {
            AnalysisResult got;
            if (svc.tryTakeBulk(got)) CHECK(got.epoch != svc.epoch(), "superseded result not current-epoch");
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    // Incremental delivery: all four passes arrive (as separate results) and merge.
    {
        uint64_t e = svc.epoch();
        svc.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Funcs | K_Strings | K_Listing | K_Xref, true, e);
        AnalysisResult got = collect(3000, e, [](const AnalysisResult& r) {
            return r.stringsValid && r.funcsValid && r.listingValid; });
        CHECK(got.stringsValid, "incremental: strings delivered");
        CHECK(got.funcsValid,   "incremental: funcs delivered");
        CHECK(got.listingValid, "incremental: listing delivered");
        CHECK(got.listRows.empty(), "no listing rows for a section-less raw blob");
    }

    // K_Intent: the algorithm recognizer runs as a background pass (after K_Funcs/K_Xref)
    // and delivers an algosValid result; a planted AES S-box is recognized.
    {
        std::string cpath = "ds_anajobs_crypto_tmp.bin";
        {
            std::ofstream f(cpath, std::ios::binary);
            std::vector<uint8_t> pad(32, (char)0x11);
            static const uint8_t sbox[16] = {
                0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76 };
            f.write((const char*)pad.data(), (std::streamsize)pad.size());
            f.write((const char*)sbox, 16);
            f.write((const char*)pad.data(), (std::streamsize)pad.size());
        }
        BinaryFile cbin;
        CHECK(cbin.loadRaw(cpath, base), "loadRaw crypto blob");
        uint64_t e = svc.epoch();
        svc.requestBulk(&cbin, Engine::Zydis, Arch::X64, K_Funcs | K_Xref | K_Intent, false, e);
        AnalysisResult got = collect(3000, e, [](const AnalysisResult& r) { return r.algosValid; });
        CHECK(got.algosValid, "K_Intent delivered an algosValid result");
        bool foundAes = false;
        for (auto& m : got.algos) if (m.name == "AES Rijndael S-box") foundAes = true;
        CHECK(foundAes, "AlgoScan found the planted AES S-box via the worker");
        svc.cancelAndWaitIdle();   // ensure no worker reads cbin after this scope
        std::remove(cpath.c_str());
    }

    // Module tagging: a job with a non-zero moduleBase rides through to the result.
    {
        uint64_t e = svc.epoch();
        const uint64_t modBase = 0x7FF000000000ull;
        svc.beginModuleBatch(1);
        svc.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Strings, false, e, modBase);
        AnalysisResult got = collect(3000, e, [](const AnalysisResult& r) { return r.stringsValid; });
        CHECK(got.moduleBase == modBase, "result carries its moduleBase");
        // The batch of 1 completes and auto-resets the module counters.
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
        bool reset = false;
        while (std::chrono::steady_clock::now() < deadline) {
            if (svc.progress().modulesTotal == 0) { reset = true; break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(reset, "module batch resets after the last module completes");
    }

    // ---- DecompileRegion (the K_Decompile job body) ----
    // The stub decodes every byte as a nop, so [base, base+8) builds a trivial CFG that
    // Decompile turns into a small but non-empty function body.
    {
        StubDisasm stub;
        std::string t = DecompileRegion(bin, stub, /*x86=*/true, base, base + 8);
        CHECK(!t.empty(), "DecompileRegion produced non-empty pseudo-C");
        // hi <= lo and unmapped regions yield an empty string (no crash).
        CHECK(DecompileRegion(bin, stub, true, base, base).empty(), "DecompileRegion empty for hi<=lo");
        CHECK(DecompileRegion(bin, stub, true, 0xDEAD0000ull, 0xDEAD0010ull).empty(),
              "DecompileRegion empty for an unmapped region");
    }

    // ---- K_Decompile bulk pass ----
    // A single-region job delivers a decompValid result tagged with the function VA and
    // the region it targeted (mirrors the K_Synthesis/K_PathExplore region-job contract).
    {
        uint64_t e = svc.epoch();
        svc.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Decompile, false, e,
                        /*moduleBase=*/0, /*regionLo=*/base, /*regionHi=*/base + 8);
        AnalysisResult got; got.epoch = e;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(3000);
        bool have = false;
        while (std::chrono::steady_clock::now() < deadline && !have) {
            AnalysisResult tmp;
            while (svc.tryTakeBulk(tmp)) {
                if (tmp.epoch != e) continue;
                if (tmp.decompValid) { got = tmp; have = true; }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(have, "K_Decompile delivered a decompValid result");
        CHECK(got.decompVA == base, "K_Decompile result tagged with the region start VA");
        CHECK(got.regionLo == base && got.regionHi == base + 8, "K_Decompile result carries its region");
        CHECK(!got.decompText.empty(), "K_Decompile result has pseudo-C text");
        svc.cancelAndWaitIdle();
    }

    // cancelAndWaitIdle leaves the pool idle (no pending work, progress back to Idle).
    {
        svc.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Strings, false, svc.epoch());
        svc.cancelAndWaitIdle();
        CHECK(!svc.bulkPending(), "no pending work after cancelAndWaitIdle");
        CHECK(svc.progress().phase == AnalysisPhase::Idle, "progress phase Idle after cancel");
    }

    std::remove(path.c_str());
    if (g_fail == 0) std::printf("analysis_service_test: all checks passed\n");
    else             std::printf("analysis_service_test: %d FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
