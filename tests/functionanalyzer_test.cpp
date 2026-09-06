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
//   6=jcc rva  7=jmp rva with one architectural delay slot  8=pop eax
//   9=unresolved indirect jmp rax (shared resolver callback supplies cases)
struct FakeDis : IDisassembler {
    uint64_t base = kBase;
    explicit FakeDis(uint64_t imageBase = kBase) : base(imageBase) {}
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
                    out.branchTarget = rva ? base + rva : 0; break;
            case 2: out.mnemonic = "ret";  out.isRet = true;  out.isBranch = true; break;
            case 3: out.mnemonic = "jmp";  out.isBranch = true;
                    out.branchTarget = rva ? base + rva : 0; break;
            case 4: out.mnemonic = "call"; out.isCall = true; out.isBranch = true;
                    std::snprintf(ops, sizeof(ops), "[0x%llX]", (unsigned long long)(base + rva));
                    out.operands = ops; break;
            case 5: out.mnemonic = "jmp";  out.isBranch = true;
                    std::snprintf(ops, sizeof(ops), "[0x%llX]", (unsigned long long)(base + rva));
                    out.operands = ops; break;
            case 6: out.mnemonic = "jcc"; out.isBranch = out.branchTargetValid = true;
                    out.branchTarget = base + rva;
                    out.flow.kind = FlowKind::ConditionalBranch;
                    out.flow.directTargetValid = true; out.flow.directTarget = base + rva; break;
            case 7: out.mnemonic = "jmp"; out.isBranch = out.branchTargetValid = true;
                    out.branchTarget = base + rva;
                    out.flow.kind = FlowKind::UnconditionalBranch;
                    out.flow.directTargetValid = true; out.flow.directTarget = base + rva;
                    out.flow.delaySlots = 1; break;
            case 8: {
                    out.mnemonic = "pop"; out.operands = "eax";
                    TypedOperand reg;
                    reg.kind = OperandKind::Register;
                    reg.access = OperandAccess::Write;
                    reg.widthBits = 32;
                    reg.registerName = "eax";
                    out.typedOperands.push_back(std::move(reg));
                    break;
                }
            case 9:
                    out.mnemonic = "jmp"; out.operands = "rax"; out.isBranch = true;
                    out.flow.kind = FlowKind::IndirectBranch;
                    break;
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

// Minimal ARM-family decoder for prologue/literal/interworking decisions. Raw
// words are real common encodings; one synthetic marker (DEAD/AAAAAAAA) emits a
// direct odd Thumb-state call so target policy is pinned without Capstone.
struct ArmFakeDis : IDisassembler {
    Arch arch;
    uint64_t base;
    bool bigEndian;
    explicit ArmFakeDis(Arch a, uint64_t b = 0, bool be = false)
        : arch(a), base(b), bigEndian(be) {}
    Engine engine() const override { return Engine::Capstone; }
    const char* engineName() const override { return "ArmFake"; }
    bool decodeOne(const uint8_t* d, size_t n, uint64_t va, Instruction& out) override {
        out = Instruction{}; out.address = va;
        if (arch == Arch::THUMB) {
            if (!d || n < 2) return false;
            const uint16_t h = bigEndian
                ? static_cast<uint16_t>((static_cast<uint16_t>(d[0]) << 8) | d[1])
                : static_cast<uint16_t>(d[0] | (static_cast<uint16_t>(d[1]) << 8));
            out.length = 2;
            if ((h & 0xff00u) == 0xb500u) { out.mnemonic = "push"; out.operands = "{r4, lr}"; }
            else if ((h & 0xff00u) == 0xbd00u || h == 0x4770u) {
                out.mnemonic = h == 0x4770u ? "bx" : "pop";
                out.operands = h == 0x4770u ? "lr" : "{r4, pc}";
                out.isBranch = out.isRet = true;
            } else if (h == 0xdeadu) {
                out.mnemonic = "bl"; out.operands = "0x41";
                out.isBranch = out.isCall = out.branchTargetValid = true;
                out.branchTarget = base + 0x41;
            } else if (h == 0xbeefu) {
                out.mnemonic = "blx"; out.operands = "0x60";
                out.isBranch = out.isCall = out.branchTargetValid = true;
                out.branchTarget = base + 0x60;
            } else { out.mnemonic = "nop"; }
            return true;
        }
        if (!d || n < 4) return false;
        const uint32_t w = bigEndian
            ? (static_cast<uint32_t>(d[0]) << 24) |
              (static_cast<uint32_t>(d[1]) << 16) |
              (static_cast<uint32_t>(d[2]) << 8) | d[3]
            : static_cast<uint32_t>(d[0]) |
              (static_cast<uint32_t>(d[1]) << 8) |
              (static_cast<uint32_t>(d[2]) << 16) |
              (static_cast<uint32_t>(d[3]) << 24);
        out.length = 4;
        if (arch == Arch::ARM64) {
            if (w == 0xd503233fu) out.mnemonic = "paciasp";
            else if (w == 0x11111111u) {
                out.mnemonic = "ldr"; out.operands = "x0, [x1, #0x40]";
            }
            else if ((w & 0xffc07fffu) == 0xa9807bfdu) {
                out.mnemonic = "stp"; out.operands = "x29, x30, [sp, #-0x10]!";
            } else if ((w & 0xfffffc1fu) == 0xd65f0000u) {
                out.mnemonic = "ret"; out.isBranch = out.isRet = true;
            } else if (w == 0x910003fdu) { out.mnemonic = "mov"; out.operands = "x29, sp"; }
            else out.mnemonic = "nop";
            return true;
        }
        if ((w & 0x0fff4000u) == 0x092d4000u) {
            out.mnemonic = "push"; out.operands = "{r4, r11, lr}";
        } else if (w == 0xe59f0000u) {
            out.mnemonic = "ldr"; out.operands = "r0, [pc, #-0x28]";
        } else if (w == 0xaaaaaaaau) {
            out.mnemonic = "blx"; out.operands = "0x81";
            out.isBranch = out.isCall = out.branchTargetValid = true;
            out.branchTarget = base + 0x81;
        } else if (w == 0xbbbbbbbbu) {
            out.mnemonic = "blx"; out.operands = "0x80";
            out.isBranch = out.isCall = out.branchTargetValid = true;
            out.branchTarget = base + 0x80;
        } else if ((w & 0x0fffffffu) == 0x012fff1eu) {
            out.mnemonic = "bx"; out.operands = "lr"; out.isBranch = out.isRet = true;
        } else out.mnemonic = "nop";
        return true;
    }
    std::vector<Instruction> disassemble(const uint8_t* d, size_t n, uint64_t va,
                                         size_t maxInstructions) override {
        std::vector<Instruction> out;
        size_t off = 0;
        while (off < n && (!maxInstructions || out.size() < maxInstructions)) {
            Instruction in;
            if (!decodeOne(d + off, n - off, va + off, in) || !in.length) break;
            out.push_back(in); off += in.length;
        }
        return out;
    }
};

// ---- synthetic PE32+ with one .text section, imports, and .pdata ------------
// .text RVA 0x1000, raw [0x400, 0xC00) -> RVA<->file delta is 0xC00.
static void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) { std::memcpy(b.data() + off, &v, 2); }
static void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) { std::memcpy(b.data() + off, &v, 4); }
static void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) { std::memcpy(b.data() + off, &v, 8); }
static void put16be(std::vector<uint8_t>& b, size_t off, uint16_t v) {
    b[off] = static_cast<uint8_t>(v >> 8); b[off + 1] = static_cast<uint8_t>(v);
}
static void put32be(std::vector<uint8_t>& b, size_t off, uint32_t v) {
    b[off] = static_cast<uint8_t>(v >> 24); b[off + 1] = static_cast<uint8_t>(v >> 16);
    b[off + 2] = static_cast<uint8_t>(v >> 8); b[off + 3] = static_cast<uint8_t>(v);
}
static size_t fo(uint32_t rva) { return rva - 0xC00; }   // file offset of an RVA

// Emit one fake instruction at RVA `rva`.
static void ins(std::vector<uint8_t>& b, uint32_t rva, uint8_t op, uint32_t operandRVA = 0) {
    size_t off = fo(rva);
    b[off] = op;
    put32(b, off + 1, operandRVA);
}

static void rawIns(std::vector<uint8_t>& b, size_t off, uint8_t op, uint32_t operand = 0) {
    CHECK(off + 8 <= b.size());
    if (off + 8 > b.size()) return;
    b[off] = op;
    put32(b, off + 1, operand);
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
    put32(b, id + 12, 0x1580);                   // Name -> "kernel32.dll"
    put32(b, id + 16, 0x1660);                   // FirstThunk (IAT)
    put64(b, fo(0x1640), 0x1540);                // OFT[0] -> hint/name
    put64(b, fo(0x1660), 0x1540);                // IAT[0]
    std::memcpy(b.data() + fo(0x1540) + 2, "ExitProcess", 12);
    std::memcpy(b.data() + fo(0x1580), "kernel32.dll", 13);

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
static bool owns(const DiscoveredFunction* function, uint64_t address) {
    if (!function) return false;
    for (const FunctionChunk& chunk : function->chunks)
        if (chunk.size && address >= chunk.address && address - chunk.address < chunk.size)
            return true;
    return false;
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
    if (const DiscoveredFunction* p = get(fns, kBase + 0x1100)) {
        CHECK(p->size == 0x80);
        CHECK(p->chunks.size() == 1 && p->chunks[0].size == 0x80); // authoritative extent owns range
    }
    if (const DiscoveredFunction* b = get(fns, kBase + 0x1030)) CHECK(b->size == 0x8);

    // Calls create a separate function and retain caller fallthrough; a direct
    // branch to an existing root is a tail boundary and never owns the callee.
    const DiscoveredFunction* entry = get(fns, kBase + 0x1000);
    const DiscoveredFunction* tail = get(fns, kBase + 0x1020);
    CHECK(entry && entry->size == 0x10 && owns(entry, kBase + 0x1008));
    CHECK(!owns(entry, kBase + 0x1020));
    CHECK(tail && tail->size == 8 && owns(tail, kBase + 0x1020));
    CHECK(!owns(tail, kBase + 0x1030));
    const DiscoveredFunction* wrapper = get(fns, kBase + 0x1040);
    CHECK(wrapper && wrapper->noreturn);
    CHECK(entry && entry->boundaryConfidence == FunctionBoundaryConfidence::Authoritative);
    CHECK(entry && entry->seedKind == FunctionSeedKind::Entry);
    CHECK(tail && tail->boundaryConfidence == FunctionBoundaryConfidence::Reconciled);
    CHECK(tail && tail->seedKind == FunctionSeedKind::ReachedCall);
    CHECK(wrapper && wrapper->seedKind == FunctionSeedKind::Unwind);

    // Analyst noreturn decisions participate in discovery and final ownership,
    // not merely post-hoc labels. Explicit false restores the caller tail that
    // API/wrapper proof would cut; explicit true trims a call to an otherwise
    // returning function.
    {
        FunctionNoreturnDecisionResolver returningWrapper = [](uint64_t target)
            -> std::optional<bool> {
            if (target == kBase + 0x1040) return false;
            return std::nullopt;
        };
        FunctionAnalyzer restoredAnalyzer;
        std::vector<DiscoveredFunction> restored = restoredAnalyzer.analyze(
            bf, dis, Arch::X64, 50000, 4000, {}, {}, {}, {}, returningWrapper);
        const DiscoveredFunction* restoredEntry = get(restored, kBase + 0x1000);
        const DiscoveredFunction* restoredWrapper = get(restored, kBase + 0x1040);
        CHECK(restoredEntry && owns(restoredEntry, kBase + 0x1010));
        CHECK(has(restored, kBase + 0x1500));
        CHECK(restoredWrapper && !restoredWrapper->noreturn);

        FunctionNoreturnDecisionResolver forcedNoreturn = [](uint64_t target)
            -> std::optional<bool> {
            if (target == kBase + 0x1020) return true;
            return std::nullopt;
        };
        FunctionAnalyzer trimmedAnalyzer;
        std::vector<DiscoveredFunction> trimmed = trimmedAnalyzer.analyze(
            bf, dis, Arch::X64, 50000, 4000, {}, {}, {}, {}, forcedNoreturn);
        const DiscoveredFunction* trimmedEntry = get(trimmed, kBase + 0x1000);
        CHECK(trimmedEntry && trimmedEntry->noreturn);
        CHECK(trimmedEntry && !owns(trimmedEntry, kBase + 0x1008));
    }

    // The noreturn allow-list is exact. Proven exit-family calls end the
    // caller, while similarly dramatic APIs that can return must not hide the
    // subsequent call target.
    {
        struct ImportCase { const char* name; bool noreturn; };
        static constexpr ImportCase cases[] = {
            {"ExitProcess", true}, {"RtlExitUserProcess", true},
            {"exit", true}, {"_Exit", true}, {"_exit", true},
            {"_o_exit", true}, {"quick_exit", true}, {"abort", true},
            {"__fastfail", true}, {"_invalid_parameter_noinfo_noreturn", true},
            {"_cexit", false}, {"TerminateProcess", false}, {"RaiseException", false},
        };
        size_t caseIndex = 0;
        for (const ImportCase& testCase : cases) {
            auto namedImage = buildImage();
            std::memset(namedImage.data() + fo(0x1540), 0, 0x40);
            std::memcpy(namedImage.data() + fo(0x1540) + 2,
                        testCase.name, std::strlen(testCase.name) + 1);
            const std::string path = "fa_noreturn_" + std::to_string(caseIndex++) + ".bin";
            { std::ofstream f(path, std::ios::binary); f.write((const char*)namedImage.data(), (std::streamsize)namedImage.size()); }
            BinaryFile namedBinary; CHECK(namedBinary.load(path)); std::remove(path.c_str());
            FakeDis namedDis;
            FunctionAnalyzer namedAnalyzer;
            const auto namedFunctions = namedAnalyzer.analyze(namedBinary, namedDis);
            const DiscoveredFunction* namedWrapper = get(namedFunctions, kBase + 0x1040);
            CHECK(namedWrapper && namedWrapper->noreturn == testCase.noreturn);
            CHECK(has(namedFunctions, kBase + 0x1500) == !testCase.noreturn);
        }
    }

    // ---- reachable chunks, delay slots, and overlapping entries ------------
    {
        // call $+instruction_size; pop-reg is a PC-materialization idiom, not a
        // real call to a new adjacent function.
        std::vector<uint8_t> raw(0x20, 0);
        rawIns(raw, 0x00, 1, 0x08);
        rawIns(raw, 0x08, 8); // pop eax
        rawIns(raw, 0x10, 2);
        const std::string path = "fa_call_next_raw.bin";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb; CHECK(rb.loadRaw(path, 0)); std::remove(path.c_str());
        CHECK(rb.setRawEntryPointVA(0));
        FakeDis rawDis(0);
        const auto refusedRaw = fa.analyze(rb, rawDis);
        CHECK(refusedRaw.empty());
        CHECK(fa.lastSummary().find("explicit architecture") != std::string::npos);
        auto callNextFns = fa.analyze(rb, rawDis, Arch::X86);
        CHECK(has(callNextFns, 0));
        CHECK(!has(callNextFns, 8));
        CHECK(owns(get(callNextFns, 0), 8));
    }
    {
        // `call next_instruction` without a following register pop is an
        // ordinary adjacent call and must retain a real callee boundary.
        std::vector<uint8_t> raw(0x20, 0);
        rawIns(raw, 0x00, 1, 0x08);
        rawIns(raw, 0x08, 0); // nop, not pop reg
        rawIns(raw, 0x10, 2);
        const std::string path = "fa_adjacent_call_raw.bin";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb; CHECK(rb.loadRaw(path, 0)); std::remove(path.c_str());
        CHECK(rb.setRawEntryPointVA(0));
        FakeDis rawDis(0);
        auto adjacentFns = fa.analyze(rb, rawDis, Arch::X86);
        CHECK(has(adjacentFns, 0) && has(adjacentFns, 8));
        CHECK(!owns(get(adjacentFns, 0), 8));
        CHECK(get(adjacentFns, 8) &&
              get(adjacentFns, 8)->boundaryConfidence == FunctionBoundaryConfidence::Reconciled);
    }
    {
        // A byte-pattern prologue inside an authoritative reachable body stays
        // provisional. It may be displayed as a heuristic candidate, but it
        // cannot truncate ownership of the exact entry stream.
        std::vector<uint8_t> raw(0x20, 0);
        rawIns(raw, 0x00, 0);
        raw[0x08] = 0x55; raw[0x09] = 0x8B; raw[0x0A] = 0xEC;
        rawIns(raw, 0x10, 2);
        const std::string path = "fa_embedded_prologue_raw.bin";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb; CHECK(rb.loadRaw(path, 0)); std::remove(path.c_str());
        CHECK(rb.setRawEntryPointVA(0));
        FakeDis rawDis(0);
        auto embeddedFns = fa.analyze(rb, rawDis, Arch::X86);
        const DiscoveredFunction* exact = get(embeddedFns, 0);
        const DiscoveredFunction* guess = get(embeddedFns, 8);
        CHECK(exact && owns(exact, 8) && owns(exact, 0x10));
        CHECK(guess && guess->boundaryConfidence == FunctionBoundaryConfidence::Heuristic);
    }
    {
        // Analyst definitions are authoritative roots, distinct from classifier
        // feedback. A callee reached by their exact instruction stream is
        // reconciled rather than left at heuristic confidence.
        std::vector<uint8_t> raw(0x40, 0);
        rawIns(raw, 0x00, 2);
        rawIns(raw, 0x10, 1, 0x20);
        rawIns(raw, 0x18, 2);
        rawIns(raw, 0x20, 2);
        const std::string path = "fa_analyst_seed_raw.bin";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb; CHECK(rb.loadRaw(path, 0)); std::remove(path.c_str());
        CHECK(rb.setRawEntryPointVA(0));
        FakeDis rawDis(0);
        auto functions = fa.analyze(rb, rawDis, Arch::X86, 50000, 4000,
                                    {}, {}, {0x10});
        const DiscoveredFunction* analyst = get(functions, 0x10);
        const DiscoveredFunction* callee = get(functions, 0x20);
        CHECK(analyst && analyst->seedKind == FunctionSeedKind::Analyst &&
              analyst->boundaryConfidence == FunctionBoundaryConfidence::Authoritative);
        CHECK(callee && callee->seedKind == FunctionSeedKind::ReachedCall &&
              callee->boundaryConfidence == FunctionBoundaryConfidence::Reconciled);
    }
    {
        // The unconditional branch skips an unowned hole. Gap-to-next sizing
        // would claim all 40 bytes; reachable ownership retains two chunks and
        // the compatibility size describes only the entry chunk.
        std::vector<uint8_t> raw(0x40, 0);
        rawIns(raw, 0x00, 3, 0x20);
        rawIns(raw, 0x20, 2);
        const std::string path = "fa_chunks_raw.bin";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb; CHECK(rb.loadRaw(path, 0)); std::remove(path.c_str());
        CHECK(rb.setRawEntryPointVA(0));
        FakeDis rawDis(0);
        auto chunkFns = fa.analyze(rb, rawDis, Arch::X86_16);
        const DiscoveredFunction* root = get(chunkFns, 0);
        CHECK(root && root->size == 8 && root->chunks.size() == 2);
        CHECK(owns(root, 0) && owns(root, 0x20));
        CHECK(!owns(root, 8) && !owns(root, 0x18));
        CHECK(fa.lastSummary().find("1 non-contiguous") != std::string::npos);
    }
    {
        // Function ownership consumes only case targets supplied by the shared
        // evidence-backed resolver. An unresolved computed jump owns no guessed
        // bytes; the resolved case becomes a real noncontiguous chunk.
        std::vector<uint8_t> raw(0x40, 0);
        rawIns(raw, 0x00, 9);
        rawIns(raw, 0x20, 2);
        const std::string path = "fa_jump_table_raw.bin";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb; CHECK(rb.loadRaw(path, 0)); std::remove(path.c_str());
        CHECK(rb.setRawEntryPointVA(0));
        FakeDis rawDis(0);
        auto unresolved = fa.analyze(rb, rawDis, Arch::X86);
        CHECK(get(unresolved, 0) && !owns(get(unresolved, 0), 0x20));
        auto resolved = fa.analyze(
            rb, rawDis, Arch::X86, 50000, 4000, {}, {}, {},
            [](const Instruction& instruction) {
                return instruction.flow.kind == FlowKind::IndirectBranch
                     ? std::vector<uint64_t>{0x20} : std::vector<uint64_t>{};
            });
        const DiscoveredFunction* root = get(resolved, 0);
        CHECK(root && root->chunks.size() == 2 && owns(root, 0x20));
    }
    {
        // A MIPS-style transfer owns its architectural delay slot even when the
        // destination is a trusted function root. Bytes after the slot are dead
        // and must not manufacture the call target at 30h.
        std::vector<uint8_t> raw(0x48, 0);
        rawIns(raw, 0x00, 7, 0x20); // delayed tail branch
        rawIns(raw, 0x08, 0);       // architectural delay slot
        rawIns(raw, 0x10, 1, 0x30); // dead fallthrough call
        rawIns(raw, 0x20, 2);
        rawIns(raw, 0x30, 2);
        const std::string path = "fa_delay_raw.bin";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb; CHECK(rb.loadRaw(path, 0)); std::remove(path.c_str());
        CHECK(rb.setRawEntryPointVA(0));
        CHECK(rb.setAnalysisLandmarks({ { 0x20, "tail_target", "trusted delayed target" } }));
        FakeDis rawDis(0);
        auto delayedFns = fa.analyze(rb, rawDis, Arch::MIPS);
        const DiscoveredFunction* root = get(delayedFns, 0);
        CHECK(root && root->chunks.size() == 1 && root->chunks[0].size == 16);
        CHECK(owns(root, 0x08) && !owns(root, 0x10) && !owns(root, 0x20));
        CHECK(has(delayedFns, 0x20));
        CHECK(!has(delayedFns, 0x30));
    }
    {
        // Two authoritative starts can intentionally begin inside different
        // decodings of the same bytes. Both survive and expose overlapping
        // chunks; ownership is not represented by one global byte sentinel.
        std::vector<uint8_t> raw(0x20, 0);
        rawIns(raw, 0x00, 2); // root 0 returns after bytes [0,8)
        raw[12] = 2;          // root 4: nop [4,12), ret [12,20)
        const std::string path = "fa_overlap_raw.bin";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb; CHECK(rb.loadRaw(path, 0)); std::remove(path.c_str());
        CHECK(rb.setRawEntryPointVA(0));
        CHECK(rb.setAnalysisLandmarks({ { 4, "overlap_entry", "trusted alternate stream" } }));
        FakeDis rawDis(0);
        auto overlapFns = fa.analyze(rb, rawDis, Arch::X86_16);
        const DiscoveredFunction* zero = get(overlapFns, 0);
        const DiscoveredFunction* four = get(overlapFns, 4);
        CHECK(zero && four);
        CHECK(owns(zero, 4) && owns(four, 4));
        CHECK(zero->size == 8 && four->size == 16);
        CHECK(four->name == "overlap_entry");
    }

    // ---- raw firmware entry + named-landmark integration --------------------
    // Real-mode far pointers retain their segmented spelling in Instruction,
    // while BinaryFile resolves direct conventional mappings and the final
    // 1-MiB alias of a top-mapped firmware image without using VA 0 as a
    // failure sentinel.
    {
        std::vector<uint8_t> raw(0x10000, 0);
        const std::string rawTmp = "fa_real_mode_alias.bin";
        { std::ofstream f(rawTmp, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile topMapped;
        CHECK(topMapped.loadRaw(rawTmp, 0xFFFF0000ull));
        uint64_t alias = 0;
        CHECK(topMapped.resolveRealModeAlias(0xF000, 0xFFF0, alias));
        CHECK(alias == 0xFFFFFFF0ull);
        CHECK(!topMapped.resolveRealModeAlias(0x1000, 0, alias));

        BinaryFile conventional;
        CHECK(conventional.loadRaw(rawTmp, 0xC0000));
        std::remove(rawTmp.c_str());
        CHECK(conventional.resolveRealModeAlias(0xC000, 0x0100, alias));
        CHECK(alias == 0xC0100);
    }

    // An explicit raw entry replaces the historical base seed, and a recovered
    // firmware landmark becomes an authoritative named function root.
    {
        std::vector<uint8_t> raw(64, 0);
        raw[16] = 2; // fake ret at selected entry
        raw[32] = 2; // fake ret at detector landmark
        const std::string rawTmp = "fa_raw_test.bin";
        { std::ofstream f(rawTmp, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb;
        CHECK(rb.loadRaw(rawTmp, kBase));
        std::remove(rawTmp.c_str());
        CHECK(!rb.hasEntryPoint());
        CHECK(rb.setRawEntryPointVA(kBase + 16));
        CHECK(rb.hasEntryPoint() && rb.entryPoint() == 16 && rb.entryPointVA() == kBase + 16);
        CHECK(rb.setAnalysisLandmarks({ { kBase + 32, "firmware_boot_target", "resolved reset jump" } }));
        CHECK(!rb.setAnalysisLandmarks({ { kBase + 0x1000, "outside", "invalid" } }));
        CHECK(rb.analysisLandmarks().size() == 1); // invalid replacement was atomic

        auto rawFns = fa.analyze(rb, dis, Arch::X86_16);
        CHECK(!has(rawFns, kBase));               // explicit entry wins over base fallback
        CHECK(has(rawFns, kBase + 16));
        const DiscoveredFunction* boot = get(rawFns, kBase + 32);
        CHECK(boot && boot->name == "firmware_boot_target" && boot->isExport);
        CHECK(boot && boot->seedKind == FunctionSeedKind::Landmark);
    }

    // VA/RVA zero is a valid explicitly selected raw entry.
    {
        std::vector<uint8_t> raw(16, 0); raw[0] = 2;
        const std::string rawTmp = "fa_raw_zero_test.bin";
        { std::ofstream f(rawTmp, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb;
        CHECK(rb.loadRaw(rawTmp, 0));
        std::remove(rawTmp.c_str());
        CHECK(rb.setRawEntryPointVA(0));
        CHECK(rb.hasEntryPoint() && rb.entryPointVA() == 0);
        auto rawFns = fa.analyze(rb, dis, Arch::X86_16);
        CHECK(has(rawFns, 0));
        const DiscoveredFunction* zero = get(rawFns, 0);
        CHECK(zero && zero->size == 8 && zero->chunks.size() == 1 && owns(zero, 0));
    }

    // ---- ARM-family prologues, literal pools, and interworking ------------
    {
        // The word at VA 0 looks exactly like an A32 prologue but is referenced
        // by the trusted entry's PC-relative LDR, so it is a literal, not code.
        // A real prologue at +40h is discovered. The odd BLX target is skipped
        // (and reported) because a fixed A32 decoder cannot switch to Thumb.
        std::vector<uint8_t> raw(0x100, 0);
        put32(raw, 0x00, 0xe92d4800u);
        put32(raw, 0x20, 0xe59f0000u); // fake decoder: ldr r0,[pc,#-0x28] -> VA 0
        put32(raw, 0x24, 0xaaaaaaaau); // fake decoder: BLX odd target 0x81
        put32(raw, 0x28, 0xbbbbbbbbu); // BLX even target also changes state
        put32(raw, 0x2c, 0xe12fff1eu);
        put32(raw, 0x40, 0xe92d4800u);
        put32(raw, 0x44, 0xe12fff1eu);
        const std::string path = "fa_arm_raw.bin";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb; CHECK(rb.loadRaw(path, 0)); std::remove(path.c_str());
        CHECK(rb.setRawEntryPointVA(0x20));
        ArmFakeDis arm(Arch::ARM);
        auto fnsA32 = fa.analyze(rb, arm, Arch::ARM);
        CHECK(has(fnsA32, 0x20));
        CHECK(has(fnsA32, 0x40));
        CHECK(!has(fnsA32, 0x00)); // literal-pool prologue lookalike excluded, including VA 0
        CHECK(!has(fnsA32, 0x80)); // neither odd nor aligned BLX targets are decoded as A32
        CHECK(fa.lastSummary().find("skipped 2 ARM/Thumb interworking target") != std::string::npos);
    }
    {
        // Big-endian structured images must compare prologue words in target
        // byte order. The entry at 1020h returns immediately; the independent
        // frame-save at 1040h is therefore found only by the prologue scan.
        std::vector<uint8_t> elf(0x180, 0);
        std::memcpy(elf.data(), "\x7f" "ELF", 4);
        elf[4] = 1; elf[5] = 2; elf[6] = 1;       // ELF32, big-endian, v1
        put16be(elf, 16, 2);                       // ET_EXEC
        put16be(elf, 18, 0x28);                    // EM_ARM
        put32be(elf, 20, 1);
        put32be(elf, 24, 0x1020);                  // entry
        put32be(elf, 28, 52);                      // program-header table
        put16be(elf, 40, 52); put16be(elf, 42, 32); put16be(elf, 44, 1);
        put32be(elf, 52, 1);                       // PT_LOAD
        put32be(elf, 56, 0x100);                   // file offset
        put32be(elf, 60, 0x1000);                  // virtual address
        put32be(elf, 68, 0x80); put32be(elf, 72, 0x80);
        put32be(elf, 76, 5); put32be(elf, 80, 4);  // RX, alignment 4
        put32be(elf, 0x120, 0xe12fff1eu);          // bx lr at entry
        put32be(elf, 0x140, 0xe92d4800u);          // stmdb sp!,{r11,lr}
        put32be(elf, 0x144, 0xe12fff1eu);
        const std::string path = "fa_arm_be.elf";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)elf.data(), (std::streamsize)elf.size()); }
        BinaryFile be; CHECK(be.load(path)); std::remove(path.c_str());
        CHECK(be.format() == BinFormat::ELF && be.bigEndian() && be.machine() == MachineArch::ARM);
        ArmFakeDis armBe(Arch::ARM, 0x1000, true);
        auto functions = fa.analyze(be, armBe, Arch::ARM);
        CHECK(has(functions, 0x1020));
        CHECK(has(functions, 0x1040));
    }
    {
        // In explicit Thumb mode the same low bit is decoder state, so a direct
        // call to 41h becomes the mapped even function at 40h. A separate 16-bit
        // PUSH {...,lr} prologue is independently discovered at 50h.
        std::vector<uint8_t> raw(0x100, 0);
        put16(raw, 0x20, 0xdeadu);
        put16(raw, 0x22, 0xbeefu); // BLX even target 60h: do not follow in fixed Thumb mode
        put16(raw, 0x24, 0x4770u);
        put16(raw, 0x40, 0xbf00u); put16(raw, 0x42, 0x4770u);
        put16(raw, 0x50, 0xb510u); put16(raw, 0x52, 0xbd10u);
        put16(raw, 0x60, 0xbf00u); put16(raw, 0x62, 0x4770u);
        const std::string path = "fa_thumb_raw.bin";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb; CHECK(rb.loadRaw(path, 0)); std::remove(path.c_str());
        CHECK(rb.setRawEntryPointVA(0x20));
        ArmFakeDis thumb(Arch::THUMB);
        auto fnsThumb = fa.analyze(rb, thumb, Arch::THUMB);
        CHECK(has(fnsThumb, 0x20));
        CHECK(has(fnsThumb, 0x40)); // canonicalized from branch target 0x41
        CHECK(has(fnsThumb, 0x50)); // 16-bit prologue scan
        CHECK(!has(fnsThumb, 0x60)); // BLX switches out of Thumb even with an aligned numeric target
        const DiscoveredFunction* entry = get(fnsThumb, 0x20);
        const DiscoveredFunction* callTarget = get(fnsThumb, 0x40);
        const DiscoveredFunction* prologue = get(fnsThumb, 0x50);
        CHECK(entry && entry->boundaryConfidence == FunctionBoundaryConfidence::Authoritative);
        CHECK(callTarget && callTarget->boundaryConfidence == FunctionBoundaryConfidence::Reconciled);
        CHECK(prologue && prologue->boundaryConfidence == FunctionBoundaryConfidence::Heuristic);
    }
    {
        // Adversarial Thumb data can make every halfword resemble PUSH {lr}.
        // Candidate construction is capped before the recursive maxFunctions
        // limit, and cancellation is observed inside the scan rather than only
        // after a multi-megabyte pass finishes.
        std::vector<uint8_t> raw(2u * 1024u * 1024u, 0);
        for (size_t i = 0; i + 1 < raw.size(); i += 2) put16(raw, i, 0xb500u);
        const std::string path = "fa_thumb_adversarial.bin";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb; CHECK(rb.loadRaw(path, 0)); std::remove(path.c_str());
        CHECK(rb.setRawEntryPointVA(0));
        ArmFakeDis thumb(Arch::THUMB);
        auto bounded = fa.analyze(rb, thumb, Arch::THUMB, 128, 8);
        CHECK(bounded.size() <= 128);
        CHECK(fa.lastSummary().find("prologue scan truncated after 128 candidate") != std::string::npos);

        size_t cancellationChecks = 0;
        auto cancelled = [&] { return ++cancellationChecks >= 2; };
        auto stopped = fa.analyze(rb, thumb, Arch::THUMB, 50000, 8, cancelled);
        CHECK(stopped.size() <= 1); // authoritative VA-0 entry may still be retained
        CHECK(fa.lastSummary().find("function analysis cancelled") != std::string::npos);
    }
    {
        // PACIASP immediately before the canonical AArch64 frame save belongs
        // to the function root; do not create a second start at the STP.
        std::vector<uint8_t> raw(0x100, 0);
        put32(raw, 0x20, 0xd65f03c0u);
        put32(raw, 0x40, 0xd503233fu);
        put32(raw, 0x44, 0xa9bf7bfdu);
        put32(raw, 0x48, 0x910003fdu);
        put32(raw, 0x4c, 0xd65f03c0u);
        const std::string path = "fa_a64_raw.bin";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb; CHECK(rb.loadRaw(path, 0)); std::remove(path.c_str());
        CHECK(rb.setRawEntryPointVA(0x20));
        ArmFakeDis a64(Arch::ARM64);
        auto fnsA64 = fa.analyze(rb, a64, Arch::ARM64);
        CHECK(has(fnsA64, 0x40));
        CHECK(!has(fnsA64, 0x44));
    }
    {
        // A normal base-register load is not an AArch64 PC-literal form. Its
        // displacement must not turn VA 0x40 into a fake literal island and
        // suppress the real frame prologue located there.
        std::vector<uint8_t> raw(0x100, 0);
        put32(raw, 0x20, 0x11111111u); // fake: ldr x0,[x1,#0x40]
        put32(raw, 0x24, 0xd65f03c0u);
        put32(raw, 0x40, 0xa9bf7bfdu);
        put32(raw, 0x44, 0xd65f03c0u);
        const std::string path = "fa_a64_nonliteral_raw.bin";
        { std::ofstream f(path, std::ios::binary); f.write((const char*)raw.data(), (std::streamsize)raw.size()); }
        BinaryFile rb; CHECK(rb.loadRaw(path, 0)); std::remove(path.c_str());
        CHECK(rb.setRawEntryPointVA(0x20));
        ArmFakeDis a64(Arch::ARM64);
        auto fnsA64 = fa.analyze(rb, a64, Arch::ARM64);
        CHECK(has(fnsA64, 0x40));
    }

    if (g_fail == 0) std::printf("ALL FUNCTIONANALYZER TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
