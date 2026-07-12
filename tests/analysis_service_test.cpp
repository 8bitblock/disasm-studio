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
#include "Core/XrefIndex.h"
#include "Disasm/IDisassembler.h"

#include <chrono>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <memory>
#include <limits>
#include <thread>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

// Minimal decoder: every byte is a 1-byte "nop"; no branches/calls/rets.
struct StubDisasm : IDisassembler {
    uint64_t highestVA = 0;
    size_t decodeCalls = 0;
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "stub"; }
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va, Instruction& out) override {
        if (!data || size == 0) return false;
        highestVA = decodeCalls ? std::max(highestVA, va) : va;
        ++decodeCalls;
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

struct GateDisasm : StubDisasm {
    std::shared_ptr<std::atomic<bool>> release;
    std::shared_ptr<std::atomic<int>> entered;
    GateDisasm(std::shared_ptr<std::atomic<bool>> r,
               std::shared_ptr<std::atomic<int>> e)
        : release(std::move(r)), entered(std::move(e)) {}
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va, Instruction& out) override {
        if (!release->load(std::memory_order_acquire)) {
            entered->fetch_add(1, std::memory_order_acq_rel);
            while (!release->load(std::memory_order_acquire))
                std::this_thread::yield();
        }
        return StubDisasm::decodeOne(data, size, va, out);
    }
};

// Tiny byte-scripted decoder used to prove that the synthetic raw section feeds
// recursive function discovery, whole-image listing, call graph, and xrefs.
// E8 <offset> calls rawBase+offset; C3 returns; every other byte is a nop.
struct RawFlowDisasm : StubDisasm {
    explicit RawFlowDisasm(uint64_t rawBase) : rawBase(rawBase) {}
    uint64_t rawBase;
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va, Instruction& out) override {
        if (!data || !size) return false;
        out = Instruction{};
        out.address = va;
        if (data[0] == 0xE8 && size >= 2) {
            out.length = 2; out.mnemonic = "call"; out.isCall = true; out.isBranch = true;
            out.branchTarget = rawBase + data[1];
            out.branchTargetValid = true;
        } else if (data[0] == 0xC3) {
            out.length = 1; out.mnemonic = "ret"; out.isRet = true; out.isBranch = true;
        } else {
            out.length = 1; out.mnemonic = "nop";
        }
        return true;
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
    CHECK(bin.format() == BinFormat::Raw && bin.entryPoint() == 0,
          "raw format retains an honest no-header-entry model");
    CHECK(bin.machine() == MachineArch::Unknown,
          "raw loader leaves architecture selection to the caller");
    CHECK(bin.sections().size() == 1, "raw load creates exactly one synthetic section");
    if (bin.sections().size() == 1) {
        const Section& raw = bin.sections()[0];
        CHECK(raw.name == ".raw" && raw.executable, "synthetic raw section is executable and named");
        CHECK(raw.virtualAddress == 0 && raw.rawOffset == 0,
              "synthetic raw section begins at mapping/file offset zero");
        CHECK(raw.virtualSize == bin.bytes().size() && raw.rawSize == bin.bytes().size(),
              "synthetic raw section covers the complete blob");
    }
    CHECK(bin.firstCodeSection() == &bin.sections()[0], "raw section is the default code section");

    // Raw VA/file translation stays an exact inverse, rejects sub-base aliases,
    // and remains patchable through the same BinaryFile API as structured images.
    {
        uint64_t va = 0, off = 0;
        const uint64_t last = static_cast<uint64_t>(bin.bytes().size() - 1);
        CHECK(bin.offsetToVA(last, va) && va == base + last, "raw last offset maps to base+offset");
        CHECK(bin.vaToOffset(base + last, off) && off == last, "raw VA maps back to last offset");
        size_t avail = 0;
        CHECK(bin.ptrFromVA(base - 1, avail) == nullptr && avail == 0,
              "raw VA below the selected base is unmapped");
        CHECK(!bin.vaToOffset(base - 1, off), "raw patch mapping rejects a sub-base VA");
        const uint8_t original = bin.bytes()[3], replacement = original ^ 0x5A;
        CHECK(bin.writeImage(base + 3, &replacement, 1) == 1 && bin.bytes()[3] == replacement,
              "raw image patch writes through VA mapping");
        CHECK(bin.writeImage(base + 3, &original, 1) == 1 && bin.bytes()[3] == original,
              "raw image patch can be restored");
    }

    // Ordinary auto-detection and a failed structured parse must produce the
    // same clean section model; no stale machine/entry state may leak through.
    BinaryFile autoRaw;
    CHECK(autoRaw.load(path), "ordinary load auto-detects an unknown blob as raw");
    CHECK(autoRaw.format() == BinFormat::Raw && autoRaw.imageBase() == 0,
          "auto-detected raw maps at zero");
    CHECK(autoRaw.sections().size() == 1 && autoRaw.sections()[0].executable,
          "auto-detected raw receives the synthetic executable section");
    {
        const std::string malformedPath = "ds_anajobs_malformed_elf.bin";
        std::vector<uint8_t> malformed(0x40, 0);
        std::memcpy(malformed.data(), "\x7F" "ELF", 4);
        malformed[4] = 2; malformed[5] = 1; // ELF64 little-endian
        malformed[18] = 0xB7;               // would select ARM64 before parse fallback
        { std::ofstream f(malformedPath, std::ios::binary);
          f.write((const char*)malformed.data(), (std::streamsize)malformed.size()); }
        BinaryFile fallback;
        CHECK(fallback.load(malformedPath), "malformed structured image degrades to raw");
        CHECK(fallback.format() == BinFormat::Raw && fallback.machine() == MachineArch::Unknown,
              "structured fallback clears partial parser format/machine state");
        CHECK(fallback.entryPoint() == 0 && fallback.sections().size() == 1 &&
              fallback.sections()[0].name == ".raw" && fallback.sections()[0].executable,
              "structured fallback owns one clean complete raw section");
        std::remove(malformedPath.c_str());
    }

    // A flat mapping is invalid if its final byte cannot be represented as a VA.
    {
        const uint64_t last = static_cast<uint64_t>(bin.bytes().size() - 1);
        BinaryFile boundary;
        CHECK(boundary.loadRaw(path, std::numeric_limits<uint64_t>::max() - last),
              "raw mapping ending exactly at UINT64_MAX is valid");
        uint64_t va = 0;
        CHECK(boundary.offsetToVA(last, va) && va == std::numeric_limits<uint64_t>::max(),
              "boundary raw mapping translates its final byte exactly");
        BinaryFile overflow;
        CHECK(!overflow.loadRaw(path, std::numeric_limits<uint64_t>::max() - last + 1),
              "raw mapping whose final VA wraps is rejected");
        CHECK(!overflow.loaded() && overflow.sections().empty(),
              "rejected overflowing raw mapping leaves no partial image");
        CHECK(!overflow.loadFromMemory(std::vector<uint8_t>(0x40, 0x90),
                                       std::numeric_limits<uint64_t>::max(), "overflow"),
              "non-PE memory fallback rejects an overflowing flat mapping");
    }

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

    // Raw base is a real function root (not entryRVA evidence), and the naming
    // layer describes it honestly. Explicit validity keeps VA 0 usable too.
    {
        StubDisasm dis;
        AnalyzeOut named = AnalyzeFunctionsNamed(bin, dis, strs, true, Arch::X64);
        CHECK(!named.functions.empty() && named.functions[0].address == base,
              "explicit raw base is the first discovered function");
        CHECK(named.functions[0].guessed && named.functions[0].name == "start" &&
              named.functions[0].reason.find("raw image base") != std::string::npos,
              "raw root naming is explicit and never claims a header entry point");

        std::vector<StrResult> zeroStrings = ScanStringsImage(autoRaw);
        AnalyzeOut zeroNamed = AnalyzeFunctionsNamed(autoRaw, dis, zeroStrings, true, Arch::X64);
        CHECK(!zeroNamed.functions.empty() && zeroNamed.functions[0].address == 0,
              "raw mapping at VA 0 retains an explicit function root");
        CHECK(zeroNamed.functions[0].guessed && zeroNamed.functions[0].name == "start",
              "FunctionNamer accepts an explicitly-valid raw root at VA 0");
        std::vector<ListRowR> zeroRows = BuildListingRows(autoRaw, dis, {0}, zeroStrings);
        CHECK(zeroRows.size() >= 2 && zeroRows[0].divider && zeroRows[0].addr == 0 &&
              !zeroRows[1].divider && zeroRows[1].addr == 0,
              "full-program listing emits divider and instruction rows at VA 0");
    }

    // Architecture-neutral base/call seeds still run for non-x86 raw blobs,
    // while x86 byte-pattern prologues are gated by the selected decoder arch.
    {
        const std::string archPath = "ds_anajobs_raw_arch_tmp.bin";
        std::vector<uint8_t> bytes(32, 0x90);
        bytes[8] = 0x55; bytes[9] = 0x48; bytes[10] = 0x89; bytes[11] = 0xE5;
        bytes[16] = 0x55; bytes[17] = 0x8B; bytes[18] = 0xEC;
        { std::ofstream f(archPath, std::ios::binary);
          f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }
        BinaryFile archBin;
        CHECK(archBin.loadRaw(archPath, base), "load raw architecture-gating fixture");
        StubDisasm dis;
        AnalyzeOut arm = AnalyzeFunctionsNamed(archBin, dis, {}, false, Arch::ARM64);
        CHECK(arm.functions.size() == 1 && arm.functions[0].address == base,
              "non-x86 raw analysis keeps the base seed but skips x86 prologues");
        AnalyzeOut x64 = AnalyzeFunctionsNamed(archBin, dis, {}, false, Arch::X64);
        bool sawX64Prologue = false;
        for (const auto& f : x64.functions) if (f.address == base + 8) sawX64Prologue = true;
        CHECK(sawX64Prologue, "x64 raw analysis applies x64 prologue discovery");
        AnalyzeOut x86 = AnalyzeFunctionsNamed(archBin, dis, {}, false, Arch::X86);
        bool sawX86Prologue = false;
        for (const auto& f : x86.functions) if (f.address == base + 16) sawX86Prologue = true;
        CHECK(sawX86Prologue, "x86 raw analysis applies x86 prologue discovery");
        std::remove(archPath.c_str());
    }

    // A real direct call inside a raw image flows through all pure whole-program
    // products: functions, divider rows, call graph, and target->source xrefs.
    {
        const std::string flowPath = "ds_anajobs_raw_flow_tmp.bin";
        std::vector<uint8_t> bytes(16, 0x90);
        bytes[0] = 0xE8; bytes[1] = 8; bytes[2] = 0xC3;
        bytes[8] = 0xE8; bytes[9] = 0; bytes[10] = 0xC3; // second function calls VA 0
        { std::ofstream f(flowPath, std::ios::binary);
          f.write((const char*)bytes.data(), (std::streamsize)bytes.size()); }
        BinaryFile flowBin;
        CHECK(flowBin.loadRaw(flowPath, 0), "load raw control-flow fixture at VA 0");
        RawFlowDisasm dis(0);
        AnalyzeOut analyzed = AnalyzeFunctionsNamed(flowBin, dis, {}, false, Arch::ARM64);
        CHECK(analyzed.functions.size() == 2 && analyzed.functions[0].address == 0 &&
              analyzed.functions[1].address == 8,
              "raw recursive discovery follows a direct call from the base root");
        std::vector<uint64_t> starts;
        for (const auto& f : analyzed.functions) starts.push_back(f.address);
        std::vector<ListRowR> rows = BuildListingRows(flowBin, dis, starts, {});
        bool divider0 = false, divider8 = false;
        for (const auto& row : rows) if (row.divider) {
            divider0 |= row.addr == 0; divider8 |= row.addr == 8;
        }
        CHECK(divider0 && divider8 && !rows.empty(), "raw full listing covers both discovered functions");
        std::vector<CallEdgeR> calls = BuildCallEdges(flowBin, dis, analyzed.functions);
        bool callOut = false, callBackToZero = false;
        for (const auto& edge : calls) {
            callOut |= edge.from == 0 && edge.to == 8;
            callBackToZero |= edge.from == 8 && edge.to == 0;
        }
        CHECK(callOut && callBackToZero,
              "raw call graph preserves outbound and inbound-to-VA0 call edges");
        XrefIndex xrefs;
        size_t avail = 0;
        const uint8_t* p = flowBin.ptrFromVA(0, avail);
        BuildXrefInto(xrefs, p, avail, 0, dis);
        FinalizeXrefIndex(xrefs);
        const std::vector<uint64_t>* sources = xrefs.sources(8);
        CHECK(sources && sources->size() == 1 && (*sources)[0] == 0,
              "raw xref index maps the call target back to its source VA");
        const std::vector<uint64_t>* zeroSources = xrefs.sources(0);
        CHECK(zeroSources && zeroSources->size() == 1 && (*zeroSources)[0] == 8,
              "raw xref index preserves a known direct call target of VA 0");
        std::remove(flowPath.c_str());
    }

    // Regression: the old scanner silently stopped at 20,000 and scanned narrow
    // strings first, so a narrow-heavy file could omit every UTF-16 result. The new
    // high safety cap must preserve a >20k mixed corpus in address order.
    {
        constexpr size_t kMany = 25050;
        std::vector<uint8_t> bytes;
        bytes.reserve(kMany * 18);
        for (size_t i = 0; i < kMany; ++i) {
            char word[24]; std::snprintf(word, sizeof(word), "%c%05zu", (i & 1) ? 'W' : 'A', i);
            if (i & 1) {
                for (const char* p = word; *p; ++p) { bytes.push_back((uint8_t)*p); bytes.push_back(0); }
            } else {
                bytes.insert(bytes.end(), word, word + std::strlen(word));
            }
            bytes.push_back(0xFF); bytes.push_back(0xFF);
        }
        std::vector<StrResult> many;
        bool truncated = false;
        ScanStringsBuffer(bytes.data(), bytes.size(), base, many,
                          kDefaultStringScanCap, &truncated);
        CHECK(many.size() == kMany, ">20k mixed strings survive the default scan cap");
        CHECK(!truncated, ">20k mixed scan is not falsely reported as truncated");
        size_t narrow = 0, wide = 0;
        for (const auto& s : many) { if (s.wide) ++wide; else ++narrow; }
        CHECK(narrow > 12000 && wide > 12000, "mixed scan retains both narrow and UTF-16 strings");
        for (size_t i = 1; i < many.size(); ++i)
            CHECK(many[i - 1].address < many[i].address, "large mixed result remains address-sorted");

        std::vector<StrResult> capped;
        truncated = false;
        ScanStringsBuffer(bytes.data(), bytes.size(), base, capped, 2000, &truncated);
        CHECK(capped.size() == 2000 && truncated, "explicit low cap is exact and surfaced");
        bool cappedHasWide = false;
        for (const auto& s : capped) if (s.wide) { cappedHasWide = true; break; }
        CHECK(cappedHasWide, "narrow results cannot starve UTF-16 results at the cap");
    }

    // The UI promises UTF-8 rather than merely accepting 7-bit ASCII.
    {
        const uint8_t utf8[] = { 'c','a','f',0xC3,0xA9,0 }; // caf\xC3\xA9: four code points
        std::vector<StrResult> u;
        ScanStringsBuffer(utf8, sizeof(utf8), base, u);
        CHECK(u.size() == 1 && u[0].text == std::string((const char*)utf8, 5),
              "valid printable UTF-8 string is extracted intact");

        std::vector<uint8_t> huge(5000, (uint8_t)'X'); huge.push_back(0);
        u.clear(); ScanStringsBuffer(huge.data(), huge.size(), base, u);
        CHECK(u.size() == 1 && u[0].text.size() == 512 && u[0].textTruncated,
              "pathological individual run is stored as an explicit bounded prefix");
    }

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
                if (tmp.stringsValid) {
                    merged.strings = tmp.strings;
                    merged.stringsValid = true;
                    merged.stringsTruncated = tmp.stringsTruncated;
                }
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
            return r.stringsValid && r.funcsValid && r.listingValid && r.xref != nullptr; });
        CHECK(got.stringsValid, "incremental: strings delivered");
        CHECK(got.funcsValid,   "incremental: funcs delivered");
        CHECK(got.listingValid, "incremental: listing delivered");
        CHECK(got.xref != nullptr, "incremental: xrefs delivered for the raw section");
        CHECK(!got.functions.empty() && got.functions[0].address == base,
              "incremental: raw base function delivered");
        CHECK(!got.listRows.empty() && got.listInsnCount == (int)bin.bytes().size(),
              "incremental: full raw blob listing delivered");
        CHECK(got.listRows[0].divider && got.listRows[0].addr == base,
              "incremental: raw listing begins with the base function divider");
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
        DecompileNameMap names{ { base, "analyst_main" } };
        DecompResult t = DecompileRegion(bin, stub, /*x86=*/true, base, base + 8,
                                         &names, "int (a1)");
        CHECK(!t.text.empty(), "DecompileRegion produced non-empty pseudo-C");
        CHECK(t.text.find("int analyst_main(a1)") != std::string::npos,
              "DecompileRegion applies analyst function name and inferred signature");
        CHECK(stub.decodeCalls > 0 && stub.highestVA < base + 8,
              "DecompileRegion never decodes beyond its exclusive regionHi");
        // The per-line VA map parallels the text: one entry per '\n'-line.
        size_t nl = 0; for (char c : t.text) if (c == '\n') ++nl;
        CHECK(t.lineVA.size() == nl, "DecompileRegion lineVA parallels the text lines");
        // hi <= lo and unmapped regions yield an empty result (no crash).
        CHECK(DecompileRegion(bin, stub, true, base, base).text.empty(), "DecompileRegion empty for hi<=lo");
        CHECK(DecompileRegion(bin, stub, true, 0xDEAD0000ull, 0xDEAD0010ull).text.empty(),
              "DecompileRegion empty for an unmapped region");

        BinaryFile high;
        const uint64_t highBase = std::numeric_limits<uint64_t>::max() - 32;
        CHECK(high.loadRaw(path, highBase), "loadRaw near the address-space limit");
        StubDisasm highStub;
        DecompResult highResult = DecompileRegion(
            high, highStub, true, highBase, std::numeric_limits<uint64_t>::max());
        CHECK(!highResult.text.empty() && highStub.highestVA < std::numeric_limits<uint64_t>::max(),
              "DecompileRegion handles a high address without interval overflow");
    }

    // ---- K_Decompile bulk pass ----
    // A single-region job delivers a decompValid result tagged with the function VA and
    // the region it targeted (mirrors the K_Synthesis/K_PathExplore region-job contract).
    {
        uint64_t e = svc.epoch();
        auto names = std::make_shared<DecompileNameMap>();
        (*names)[base] = "worker_named_main";
        svc.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Decompile, false, e,
                        /*moduleBase=*/0, /*regionLo=*/base, /*regionHi=*/base + 8,
                        names, "long (a1)", /*decompContext=*/77);
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
        CHECK(got.decompText.find("long worker_named_main(a1)") != std::string::npos,
              "K_Decompile transports the immutable name/signature snapshot");
        CHECK(got.decompContext == 77, "K_Decompile echoes the caller name-context generation");
        svc.cancelAndWaitIdle();
    }

    // Pending targeted passes for one module must not coalesce when their kinds
    // differ: they share region storage, so the old merge moved the first pass to
    // the second pass's address. Occupy every possible pool worker with gated jobs
    // to make both target requests deterministically pending together.
    {
        auto release = std::make_shared<std::atomic<bool>>(false);
        auto entered = std::make_shared<std::atomic<int>>(0);
        AnalysisService targeted([release, entered](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<GateDisasm>(release, entered);
        });
        const uint64_t e = targeted.epoch();
        for (uint64_t i = 0; i < 8; ++i)
            targeted.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Decompile,
                                 false, e, 0x100 + i, base, base + 2);

        auto enteredDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
        while (!entered->load(std::memory_order_acquire)
               && std::chrono::steady_clock::now() < enteredDeadline)
            std::this_thread::yield();
        CHECK(entered->load(std::memory_order_acquire) > 0,
              "targeted-coalescing test occupied an analysis worker");

        constexpr uint64_t targetModule = 0xBEEF;
        targeted.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Decompile,
                             false, e, targetModule, base, base + 4);
        targeted.requestBulk(&bin, Engine::Zydis, Arch::X64, K_Synthesis,
                             false, e, targetModule, base + 8, base + 12);
        release->store(true, std::memory_order_release);

        bool sawDecompile = false, sawSynthesis = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline
               && !(sawDecompile && sawSynthesis)) {
            AnalysisResult got;
            while (targeted.tryTakeBulk(got)) {
                if (got.moduleBase != targetModule) continue;
                if (got.decompValid) {
                    sawDecompile = got.decompVA == base
                                && got.regionLo == base && got.regionHi == base + 4;
                }
                if (got.synthValid) {
                    sawSynthesis = got.regionLo == base + 8 && got.regionHi == base + 12;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(sawDecompile, "different targeted kind preserves decompile region");
        CHECK(sawSynthesis, "different targeted kind preserves synthesis region");
        targeted.cancelAndWaitIdle();
    }

    // VA 0 is a legitimate function address for raw/ELF/Mach-O images. Keep this
    // backend regression beside the BinaryView validity-flag fix: zero must not be
    // treated as the decompiler's "not initialized" sentinel.
    {
        BinaryFile zeroBin;
        CHECK(zeroBin.loadRaw(path, 0), "loadRaw at VA 0");
        uint64_t e = svc.epoch();
        svc.requestBulk(&zeroBin, Engine::Zydis, Arch::X64, K_Decompile, false, e,
                        /*moduleBase=*/0, /*regionLo=*/0, /*regionHi=*/8);
        AnalysisResult got;
        bool have = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(3000);
        while (std::chrono::steady_clock::now() < deadline && !have) {
            AnalysisResult tmp;
            while (svc.tryTakeBulk(tmp)) {
                if (tmp.epoch == e && tmp.decompValid) { got = std::move(tmp); have = true; }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        CHECK(have && got.decompVA == 0 && !got.decompText.empty(),
              "K_Decompile supports a real function at VA 0");
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
