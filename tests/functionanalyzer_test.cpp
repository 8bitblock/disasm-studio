//
// functionanalyzer_test.cpp
// Off-target tests for src/Core/FunctionAnalyzer.cpp driven by a FAKE
// IDisassembler over a tiny synthetic fixed-length ISA, so the analyzer's
// *decisions* are pinned without Zydis/Capstone:
//   - .pdata (RUNTIME_FUNCTION) seeding on x64 PE: begins become function
//     starts, extents beat the gap size guess, chained entries are folded,
//   - tail-call detection: an unconditional jmp to a known function start or
//     through an import thunk ends the function (no bogus targets after it),
//   - noreturn: a call to an exit-family import (or a wrapper that tail-jumps
//     to one) ends the fall-through scan.
// Also pins BinaryFile::pdataRanges() directly (chained-entry skip, bounds).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\functionanalyzer_test.cpp src\Core\FunctionAnalyzer.cpp src\Core\BinaryFile.cpp
//   .\functionanalyzer_test.exe
//
#include "Core/FunctionAnalyzer.h"
#include "Core/BinaryFile.h"
#include "Disasm/IDisassembler.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static constexpr uint64_t kBase = 0x140000000ull;

// ---- fake ISA: 8-byte fixed-length records --------------------------------
//   [0]=opcode  [1..4]=u32 RVA operand  [5..7]=0
//   0=nop  1=call rva  2=ret  3=jmp rva  4=call [abs]  5=jmp [abs]
struct FakeDis : IDisassembler {
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "Fake"; }
    bool decodeOne(const uint8_t* d, size_t n, uint64_t va, Instruction& out) override {
        if (!d || n < 8) return false;
        out = Instruction{};
        out.address = va;
        out.length  = 8;
        uint32_t rva = 0; std::memcpy(&rva, d + 1, 4);
        char ops[40];
        switch (d[0]) {
            case 1: out.mnemonic = "call"; out.isCall = true; out.isBranch = true;
                    out.branchTarget = rva ? kBase + rva : 0; break;
            case 2: out.mnemonic = "ret";  out.isRet = true;  out.isBranch = true; break;
            case 3: out.mnemonic = "jmp";  out.isBranch = true;
                    out.branchTarget = rva ? kBase + rva : 0; break;
            case 4: out.mnemonic = "call"; out.isCall = true; out.isBranch = true;
                    std::snprintf(ops, sizeof(ops), "[0x%llX]", (unsigned long long)(kBase + rva));
                    out.operands = ops; break;
            case 5: out.mnemonic = "jmp";  out.isBranch = true;
                    std::snprintf(ops, sizeof(ops), "[0x%llX]", (unsigned long long)(kBase + rva));
                    out.operands = ops; break;
            default: out.mnemonic = "nop"; break;
        }
        return true;
    }
    std::vector<Instruction> disassemble(const uint8_t* d, size_t n, uint64_t va,
                                         size_t maxInstructions) override {
        std::vector<Instruction> out;
        size_t off = 0;
        while (off + 8 <= n && (!maxInstructions || out.size() < maxInstructions)) {
            Instruction in;
            if (!decodeOne(d + off, n - off, va + off, in)) break;
            out.push_back(std::move(in));
            off += 8;
        }
        return out;
    }
};

// ---- synthetic PE32+ with one .text section, imports, and .pdata ------------
// .text RVA 0x1000, raw [0x400, 0xC00) -> RVA<->file delta is 0xC00.
static void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) { std::memcpy(b.data() + off, &v, 2); }
static void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) { std::memcpy(b.data() + off, &v, 4); }
static void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) { std::memcpy(b.data() + off, &v, 8); }
static size_t fo(uint32_t rva) { return rva - 0xC00; }   // file offset of an RVA

// Emit one fake instruction at RVA `rva`.
static void ins(std::vector<uint8_t>& b, uint32_t rva, uint8_t op, uint32_t operandRVA = 0) {
    size_t off = fo(rva);
    b[off] = op;
    put32(b, off + 1, operandRVA);
}

static std::vector<uint8_t> buildImage() {
    std::vector<uint8_t> b(0xC00, 0);
    b[0] = 'M'; b[1] = 'Z';
    const uint32_t e_lfanew = 0x80;
    put32(b, 0x3C, e_lfanew);
    put32(b, e_lfanew, 0x00004550);
    const size_t coff = e_lfanew + 4;
    put16(b, coff + 0,  0x8664);                 // x64
    put16(b, coff + 2,  1);                      // 1 section
    put16(b, coff + 16, 0xF0);                   // SizeOfOptionalHeader (PE32+)
    put16(b, coff + 18, 0x22);
    const size_t opt = coff + 20;
    put16(b, opt + 0,  0x20B);                   // PE32+
    put32(b, opt + 16, 0x1000);                  // entry RVA
    put64(b, opt + 24, kBase);                   // ImageBase
    put32(b, opt + 32, 0x1000);                  // SectionAlignment
    put32(b, opt + 36, 0x200);                   // FileAlignment
    put32(b, opt + 56, 0x2000);                  // SizeOfImage
    put32(b, opt + 60, 0x400);                   // SizeOfHeaders
    const size_t dataDir = opt + 112;
    put32(b, dataDir - 4, 16);                   // NumberOfRvaAndSizes
    put32(b, dataDir + 1 * 8,     0x1600);       // [1] import dir RVA
    put32(b, dataDir + 1 * 8 + 4, 40);
    put32(b, dataDir + 3 * 8,     0x1700);       // [3] exception dir (.pdata)
    put32(b, dataDir + 3 * 8 + 4, 5 * 12);
    const size_t sec = opt + 0xF0;
    std::memcpy(b.data() + sec, ".text\0\0\0", 8);
    put32(b, sec + 8,  0x800);                   // VirtualSize
    put32(b, sec + 12, 0x1000);                  // VirtualAddress
    put32(b, sec + 16, 0x800);                   // SizeOfRawData
    put32(b, sec + 20, 0x400);                   // PointerToRawData
    put32(b, sec + 36, 0x60000020u);             // CODE|EXECUTE|READ

    // ---- imports: kernel32.dll!ExitProcess, IAT at RVA 0x1660 ----
    const size_t id = fo(0x1600);                // IMAGE_IMPORT_DESCRIPTOR
    put32(b, id + 0,  0x1640);                   // OriginalFirstThunk
    put32(b, id + 12, 0x16A0);                   // Name -> "kernel32.dll"
    put32(b, id + 16, 0x1660);                   // FirstThunk (IAT)
    put64(b, fo(0x1640), 0x1680);                // OFT[0] -> hint/name
    put64(b, fo(0x1660), 0x1680);                // IAT[0]
    std::memcpy(b.data() + fo(0x1680) + 2, "ExitProcess", 12);
    std::memcpy(b.data() + fo(0x16A0), "kernel32.dll", 13);

    // ---- .pdata at RVA 0x1700 (5 entries) ----
    auto pdata = [&](int i, uint32_t begin, uint32_t end, uint32_t unwind) {
        size_t off = fo(0x1700) + (size_t)i * 12;
        put32(b, off, begin); put32(b, off + 4, end); put32(b, off + 8, unwind);
    };
    pdata(0, 0x1030, 0x1038, 0x17F0);            // B
    pdata(1, 0x1040, 0x1048, 0x17F0);            // W (noreturn wrapper)
    pdata(2, 0x1100, 0x1180, 0x17F0);            // P (size hint 0x80)
    pdata(3, 0x1200, 0x1240, 0x17F1);            // chained (odd UnwindData) -> folded
    pdata(4, 0x1300, 0x1340, 0x17F8);            // chained (UNW_FLAG_CHAININFO) -> folded
    b[fo(0x17F0)] = 0x01;                        // UNWIND_INFO: version 1, flags 0
    b[fo(0x17F8)] = 0x21;                        // version 1, flags 0x4 (CHAININFO)

    // ---- code ----
    ins(b, 0x1000, 1, 0x1020);                   // entry: call A
    ins(b, 0x1008, 1, 0x1040);                   // entry: call W (noreturn wrapper)
    ins(b, 0x1010, 1, 0x1500);                   // DEAD: after a noreturn call -> never seen
    ins(b, 0x1020, 3, 0x1030);                   // A: jmp B (tail-call to a known start)
    ins(b, 0x1028, 1, 0x1510);                   // DEAD: after the tail-call -> never seen
    ins(b, 0x1030, 2);                           // B: ret
    ins(b, 0x1040, 5, 0x1660);                   // W: jmp [IAT ExitProcess]
    ins(b, 0x1100, 2);                           // P: ret
    return b;
}

static bool has(const std::vector<DiscoveredFunction>& fns, uint64_t a) {
    for (const auto& f : fns) if (f.address == a) return true;
    return false;
}
static const DiscoveredFunction* get(const std::vector<DiscoveredFunction>& fns, uint64_t a) {
    for (const auto& f : fns) if (f.address == a) return &f;
    return nullptr;
}

int main() {
    auto img = buildImage();
    const std::string tmp = "fa_test.bin";
    { std::ofstream f(tmp, std::ios::binary); f.write((const char*)img.data(), (std::streamsize)img.size()); }
    BinaryFile bf;
    CHECK(bf.load(tmp));
    std::remove(tmp.c_str());
    CHECK(bf.format() == BinFormat::PE32Plus);
    CHECK(bf.machine() == MachineArch::X64);

    // ---- pdataRanges(): chained entries folded, ranges exact -----------------
    {
        auto pr = bf.pdataRanges();
        CHECK(pr.size() == 3);
        bool b = false, w = false, p = false;
        for (auto& [lo, hi] : pr) {
            if (lo == kBase + 0x1030 && hi == kBase + 0x1038) b = true;
            if (lo == kBase + 0x1040 && hi == kBase + 0x1048) w = true;
            if (lo == kBase + 0x1100 && hi == kBase + 0x1180) p = true;
            CHECK(lo != kBase + 0x1200 && lo != kBase + 0x1300);   // chained: folded away
        }
        CHECK(b && w && p);
    }

    // ---- analyzer over the fake ISA ------------------------------------------
    FakeDis dis;
    FunctionAnalyzer fa;
    auto fns = fa.analyze(bf, dis);

    CHECK(has(fns, kBase + 0x1000));   // entry
    CHECK(has(fns, kBase + 0x1020));   // A (call target)
    CHECK(has(fns, kBase + 0x1030));   // B (pdata + tail-call target)
    CHECK(has(fns, kBase + 0x1040));   // W (pdata seed)
    CHECK(has(fns, kBase + 0x1100));   // P (pdata seed)

    // noreturn: the call after `call W` is dead -> 0x1500 must NOT be a function.
    CHECK(!has(fns, kBase + 0x1500));
    // tail-call: the call after `jmp B` is dead -> 0x1510 must NOT be a function.
    CHECK(!has(fns, kBase + 0x1510));
    // chained pdata chunks are not functions.
    CHECK(!has(fns, kBase + 0x1200));
    CHECK(!has(fns, kBase + 0x1300));

    // .pdata extent beats the gap guess: P's next start is far away, but the
    // linker says it is exactly 0x80 bytes.
    if (const DiscoveredFunction* p = get(fns, kBase + 0x1100)) CHECK(p->size == 0x80);
    if (const DiscoveredFunction* b = get(fns, kBase + 0x1030)) CHECK(b->size == 0x8);

    if (g_fail == 0) std::printf("ALL FUNCTIONANALYZER TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
