// End-to-end regression coverage for FunctionNamer's evidence collector and
// name allocator.  Uses a scripted disassembler over a raw BinaryFile so no
// Zydis/Capstone or UI dependency is needed.
//
// MSVC dev shell:
//   cl /nologo /std:c++20 /EHsc /I src tests\function_namer_pipeline_test.cpp ^
//      src\Core\FunctionNamer.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp

#include "Core/BinaryFile.h"
#include "Core/FunctionNamer.h"
#include "Disasm/IDisassembler.h"

#include <cstdio>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++g_fail; } } while (0)
#define CHECK_EQ(a,b) do { const std::string _a=(a), _b=(b); if (_a != _b) { \
    std::printf("FAIL %s:%d  got \"%s\" want \"%s\"\n", __FILE__, __LINE__, _a.c_str(), _b.c_str()); ++g_fail; } } while (0)

struct ScriptDisasm final : IDisassembler {
    std::unordered_map<uint64_t, std::vector<Instruction>> bodies;

    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "script"; }

    bool decodeOne(const uint8_t*, size_t, uint64_t va, Instruction& out) override {
        auto it = bodies.find(va);
        if (it == bodies.end() || it->second.empty()) return false;
        out = it->second.front();
        return true;
    }

    std::vector<Instruction> disassemble(const uint8_t*, size_t, uint64_t va,
                                         size_t maxInstructions) override {
        auto it = bodies.find(va);
        if (it == bodies.end()) return {};
        std::vector<Instruction> out = it->second;
        if (maxInstructions && out.size() > maxInstructions) out.resize(maxInstructions);
        return out;
    }
};

static Instruction op(uint64_t va, const char* mnemonic, const std::string& operands = {}) {
    Instruction in;
    in.address = va; in.length = 1; in.mnemonic = mnemonic; in.operands = operands;
    return in;
}

static Instruction callMem(uint64_t va, uint64_t slot) {
    char b[40]; std::snprintf(b, sizeof(b), "[0x%llX]", (unsigned long long)slot);
    Instruction in = op(va, "call", b);
    in.isCall = true; in.isBranch = true;
    return in;
}

static Instruction jumpMem(uint64_t va, uint64_t slot) {
    char b[40]; std::snprintf(b, sizeof(b), "[0x%llX]", (unsigned long long)slot);
    Instruction in = op(va, "jmp", b);
    in.isBranch = true;
    return in;
}

static Instruction jumpTo(uint64_t va, uint64_t target) {
    Instruction in = op(va, "jmp");
    in.isBranch = true; in.branchTarget = target;
    return in;
}

static Instruction ret(uint64_t va) {
    Instruction in = op(va, "ret");
    in.isRet = true; in.isBranch = true;
    return in;
}

int main() {
    const uint64_t base = 0x100000;
    const uint64_t iatCreate = base + 0xE00;
    const uint64_t iatOrdinal = base + 0xE10;
    const uint64_t iatRead = base + 0xE20;
    const uint64_t iatSub = base + 0xE30;
    const uint64_t stringVA = base + 0xF00;

    const std::string path = "ds_function_namer_tmp.bin";
    {
        std::ofstream f(path, std::ios::binary);
        std::vector<char> bytes(0x1000, 0);
        f.write(bytes.data(), (std::streamsize)bytes.size());
    }
    BinaryFile bin;
    CHECK(bin.loadRaw(path, base));

    ScriptDisasm dis;
    auto importNameFor = [&](uint64_t va) -> std::string {
        if (va == iatCreate)  return "KERNEL32.CreateFileW";
        if (va == iatOrdinal) return "KERNEL32.#12";
        if (va == iatRead)    return "KERNEL32.ReadFile";
        if (va == iatSub)     return "odd.sub_100210";
        return {};
    };
    auto stringRefFor = [&](uint64_t va) -> std::string {
        return va == stringVA ? "OpenConfig" : std::string();
    };

    // An authoritative export is protected even when its real name happens to
    // have FunctionAnalyzer's anonymous sub_<hex> shape.
    {
        const uint64_t a = base + 0x10, b = base + 0x20;
        dis.bodies[a] = { ret(a) };
        dis.bodies[b] = { ret(b) };
        std::vector<NamerInput> f = {
            { a, 8, true,  "sub_ABCD" },
            { b, 8, false, "sub_100020" },
        };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        CHECK(!r[0].guessed); CHECK_EQ(r[0].name, "sub_ABCD");
        CHECK(r[1].guessed);  CHECK_EQ(r[1].name, "nullsub");
    }

    // Allocation is case-insensitive, accounts for real names, and reports a
    // suffix in the reason rather than silently changing the evidence name.
    {
        const uint64_t real = base + 0x100, a = base + 0x110, b = base + 0x120;
        dis.bodies[real] = { ret(real) };
        dis.bodies[a] = { callMem(a, iatRead), ret(a + 1) };
        dis.bodies[b] = { callMem(b, iatRead), ret(b + 1) };
        std::vector<NamerInput> f = {
            { real, 8, true,  "Read_File" },
            { a,    8, false, "sub_100110" },
            { b,    8, false, "sub_100120" },
        };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        CHECK_EQ(r[1].name, "read_file_1");
        CHECK_EQ(r[2].name, "read_file_2");
        CHECK(r[1].reason.find("shown as \"read_file_1\"") != std::string::npos);
    }

    // Future unresolved sub_ names are reserved too; the allocator must not
    // create a duplicate before discovering that the future function stays put.
    {
        const uint64_t a = base + 0x200, b = base + 0x210;
        dis.bodies[a] = { callMem(a, iatSub), ret(a + 1) };
        dis.bodies[b] = {};
        std::vector<NamerInput> f = {
            { a, 8, false, "sub_100200" },
            { b, 8, false, "sub_100210" },
        };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        CHECK_EQ(r[0].name, "sub_100210_1");
        CHECK_EQ(r[1].name, "sub_100210"); CHECK(!r[1].guessed);
    }

    // Chained local thunks inherit the final IAT target; ordinal thunks remain
    // anonymous instead of producing invalid j_#12 identifiers.
    {
        const uint64_t outer = base + 0x300, inner = base + 0x310, ordinal = base + 0x320;
        dis.bodies[outer] = { jumpTo(outer, inner) };
        dis.bodies[inner] = { jumpMem(inner, iatCreate) };
        dis.bodies[ordinal] = { jumpMem(ordinal, iatOrdinal) };
        std::vector<NamerInput> f = {
            { outer,   8, false, "sub_100300" },
            { inner,   8, false, "sub_100310" },
            { ordinal, 8, false, "sub_100320" },
        };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        CHECK_EQ(r[0].name, "j_CreateFileW");
        CHECK_EQ(r[1].name, "j_CreateFileW_1");
        CHECK(!r[2].guessed); CHECK_EQ(r[2].name, "sub_100320");
    }

    // x86 immediate string pointers now feed identifier evidence (previously
    // only bracketed/RIP-relative references were considered).
    {
        const uint64_t a = base + 0x400;
        char imm[40]; std::snprintf(imm, sizeof(imm), "eax, 0x%llX", (unsigned long long)stringVA);
        dis.bodies[a] = { op(a, "mov", imm), ret(a + 1) };
        std::vector<NamerInput> f = { { a, 8, false, "sub_100400" } };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        CHECK(r[0].guessed); CHECK_EQ(r[0].name, "OpenConfig");
    }

    // ret_zero requires the accumulator still to be zero at RET.  Arbitrary
    // push/pop and a leading INT3 are not empty nullsub bodies.
    {
        const uint64_t changed = base + 0x500, stack = base + 0x510;
        const uint64_t zero = base + 0x520, trap = base + 0x530, framed = base + 0x540;
        dis.bodies[changed] = { op(changed, "xor", "eax, eax"),
                                op(changed + 1, "mov", "eax, 5"), ret(changed + 2) };
        dis.bodies[stack] = { op(stack, "push", "1"), op(stack + 1, "pop", "eax"), ret(stack + 2) };
        dis.bodies[zero] = { op(zero, "mov", "eax, 0x0"), ret(zero + 1) };
        dis.bodies[trap] = { op(trap, "int3"), ret(trap + 1) };
        dis.bodies[framed] = { op(framed, "push", "rbp"), op(framed + 1, "mov", "rbp, rsp"),
                               op(framed + 2, "pop", "rbp"), ret(framed + 3) };
        std::vector<NamerInput> f = {
            { changed, 8, false, "sub_100500" }, { stack, 8, false, "sub_100510" },
            { zero, 8, false, "sub_100520" }, { trap, 8, false, "sub_100530" },
            { framed, 8, false, "sub_100540" },
        };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        CHECK(!r[0].guessed); CHECK(!r[1].guessed); CHECK(!r[3].guessed);
        CHECK_EQ(r[2].name, "ret_zero");
        CHECK_EQ(r[4].name, "nullsub");
    }

    std::remove(path.c_str());
    if (!g_fail) std::printf("function_namer_pipeline_test: ALL PASS\n");
    else std::printf("function_namer_pipeline_test: %d FAIL\n", g_fail);
    return g_fail ? 1 : 0;
}
