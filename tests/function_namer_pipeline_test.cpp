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

#include <chrono>
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

static Instruction dataRef(uint64_t va, uint64_t target) {
    char b[64]; std::snprintf(b, sizeof(b), "rcx, [0x%llX]", (unsigned long long)target);
    return op(va, "lea", b);
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

static Instruction jumpIf(uint64_t va, const char* mnemonic, uint64_t target) {
    Instruction in = op(va, mnemonic);
    in.isBranch = true; in.branchTarget = target;
    return in;
}

static Instruction ret(uint64_t va) {
    Instruction in = op(va, "ret");
    in.isRet = true; in.isBranch = true;
    return in;
}

// Large batches exercise allocation after reserved-name holes and long thunk
// chains without depending on a particular unordered-map traversal order. The
// optional benchmark reports wall time; correctness never uses timing limits.
static void checkLargeNamingBatches(size_t count, bool reportTime) {
    const uint64_t base = 0x200000, iat = base + count + 16;
    const std::string path = "ds_function_namer_scale_tmp.bin";
    {
        std::ofstream f(path, std::ios::binary);
        const std::vector<char> bytes(count + 32, 0);
        f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }
    BinaryFile bin;
    CHECK(bin.loadRaw(path, base));
    ScriptDisasm dis;
    std::vector<NamerInput> funcs;
    for (size_t i = 0; i < count; ++i) {
        const uint64_t address = base + i;
        char name[40];
        std::snprintf(name, sizeof(name), "sub_%llX", static_cast<unsigned long long>(address));
        funcs.push_back({address, 1, false, name});
        dis.bodies[address] = {ret(address)};
    }
    funcs.push_back({base + count, 1, true, "NULLSUB"});
    funcs.push_back({base + count + 1, 1, true, "NullSub_2"});
    funcs.push_back({base + count + 2, 1, true, "nullsub_4"});
    FunctionNamer namer;
    auto begin = std::chrono::steady_clock::now();
    auto results = namer.name(bin, dis, funcs, 0, false, false, {}, {});
    const double repeatedMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - begin).count();
    size_t suffix = 1;
    for (size_t i = 0; i < count; ++i) {
        while (suffix == 2 || suffix == 4) ++suffix;
        const std::string expected = "nullsub_" + std::to_string(suffix++);
        CHECK(results[i].guessed);
        CHECK_EQ(results[i].name, expected);
        CHECK_EQ(results[i].reason, "empty stub (returns immediately); name \"nullsub\" already existed, shown as \"" + expected + "\"");
    }
    CHECK(namer.guessedCount() == static_cast<int>(count));
    for (size_t i = count; i < funcs.size(); ++i) {
        CHECK(!results[i].guessed);
        CHECK_EQ(results[i].name, funcs[i].name);
    }

    // Named thunks still donate API evidence to the first anonymous thunk.
    // Giving the rest authoritative names isolates chain-resolution cost from
    // duplicate guessed-name allocation and protects those names at the same time.
    funcs.resize(count);
    for (size_t i = 0; i < count; ++i) {
        const uint64_t address = base + i;
        dis.bodies[address] = {i + 1 < count ? jumpTo(address, address + 1) : jumpMem(address, iat)};
        if (i) { funcs[i].isExport = true; funcs[i].name = "export_" + std::to_string(i); }
    }
    const auto importName = [iat](uint64_t address) -> std::string {
        return address == iat ? "KERNEL32.CreateFileW" : "";
    };
    begin = std::chrono::steady_clock::now();
    results = namer.name(bin, dis, funcs, 0, false, false, importName, {});
    const double chainMs = std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now() - begin).count();
    CHECK_EQ(results.front().name, "j_CreateFileW");
    CHECK_EQ(results.front().reason, "tail-jumps to CreateFileW");
    CHECK(namer.guessedCount() == 1);
    for (size_t i = 1; i < count; ++i) {
        CHECK(!results[i].guessed);
        CHECK_EQ(results[i].name, funcs[i].name);
    }
    if (reportTime)
        std::printf("function_namer benchmark: %zu functions, duplicate names %.3f ms, thunk chain %.3f ms\n",
                    count, repeatedMs, chainMs);
    std::remove(path.c_str());
}

int main(int argc, char** argv) {
    const uint64_t base = 0x100000;
    const uint64_t iatCreate = base + 0xE00;
    const uint64_t iatOrdinal = base + 0xE10;
    const uint64_t iatRead = base + 0xE20;
    const uint64_t iatSub = base + 0xE30;
    const uint64_t iatConnectivity = base + 0xE40;
    const uint64_t iatSend = base + 0xE50;
    const uint64_t iatCryptCreateHash = base + 0xE60;
    const uint64_t iatCryptHashData = base + 0xE70;
    const uint64_t iatCryptGetHashParam = base + 0xE80;
    const uint64_t iatMemcmp = base + 0xE90;
    const uint64_t stringVA = base + 0xF00;
    const uint64_t licenseKeyVA = base + 0xF20;

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
        if (va == iatConnectivity) return "WININET.InternetGetConnectedState";
        if (va == iatSend)    return "WS2_32.send";
        if (va == iatCryptCreateHash) return "ADVAPI32.CryptCreateHash";
        if (va == iatCryptHashData) return "ADVAPI32.CryptHashData";
        if (va == iatCryptGetHashParam) return "ADVAPI32.CryptGetHashParam";
        if (va == iatMemcmp) return "MSVCRT.memcmp";
        return {};
    };
    auto stringRefFor = [&](uint64_t va) -> std::string {
        if (va == stringVA) return "OpenConfig";
        if (va == licenseKeyVA) return "license key";
        return {};
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

    // Cycles, self-loops, and chains ending outside the known functions cannot
    // inherit an unrelated resolved import.
    {
        const uint64_t a = base + 0x900, b = base + 0x910, lead = base + 0x920;
        const uint64_t self = base + 0x930, unknown = base + 0x940, good = base + 0x950;
        dis.bodies[a] = {jumpTo(a, b)};
        dis.bodies[b] = {jumpTo(b, a)};
        dis.bodies[lead] = {jumpTo(lead, a)};
        dis.bodies[self] = {jumpTo(self, self)};
        dis.bodies[unknown] = {jumpTo(unknown, base + 0xDDD)};
        dis.bodies[good] = {jumpMem(good, iatCreate)};
        std::vector<NamerInput> f;
        for (uint64_t address : {a, b, lead, self, unknown, good}) {
            char name[40];
            std::snprintf(name, sizeof(name), "sub_%llX", static_cast<unsigned long long>(address));
            f.push_back({address, 1, false, name});
        }
        FunctionNamer n;
        const auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        for (size_t i = 0; i + 1 < r.size(); ++i) {
            CHECK(!r[i].guessed);
            CHECK_EQ(r[i].name, f[i].name);
        }
        CHECK_EQ(r.back().name, "j_CreateFileW");
    }

    // A thin wrapper that returns the predicate's BOOL directly also qualifies.
    {
        const uint64_t direct = base + 0x5F0;
        dis.bodies[direct] = {
            callMem(direct, iatConnectivity),
            ret(direct + 1),
        };
        std::vector<NamerInput> f = {
            { direct, 8, false, "sub_1005F0" },
        };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        CHECK(r[0].guessed); CHECK_EQ(r[0].name, "WifiCheck");
        CHECK(r[0].reason.find("returns InternetGetConnectedState") != std::string::npos);
    }

    // A strong connectivity predicate must have immediate result-flow evidence:
    // here its EAX result directly feeds TEST/JNZ. The same shape is vetoed when
    // the function also performs transport work, which is a network routine rather
    // than a bounded online-state wrapper.
    {
        const uint64_t checked = base + 0x600, transports = base + 0x620;
        dis.bodies[checked] = {
            callMem(checked, iatConnectivity),
            op(checked + 1, "test", "eax, eax"),
            jumpIf(checked + 2, "jnz", checked + 4),
            ret(checked + 3),
            ret(checked + 4),
        };
        dis.bodies[transports] = {
            callMem(transports, iatConnectivity),
            op(transports + 1, "cmp", "eax, 0"),
            jumpIf(transports + 2, "je", transports + 5),
            callMem(transports + 3, iatSend),
            ret(transports + 4),
            ret(transports + 5),
        };
        std::vector<NamerInput> f = {
            { checked,    8, false, "sub_100600" },
            { transports, 8, false, "sub_100620" },
        };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        CHECK(r[0].guessed); CHECK_EQ(r[0].name, "WifiCheck");
        CHECK(r[0].reason.find("InternetGetConnectedState") != std::string::npos);
        CHECK(r[0].reason.find("connectivity result") != std::string::npos);
        CHECK(r[1].name != "WifiCheck");
        CHECK_EQ(r[1].name, "net_send");
    }

    // TEST establishes several flags, but only a zero/equality Jcc is evidence
    // that the connectivity BOOL controls a decision. JO observes OF (which TEST
    // clears), so this shape must remain an ordinary API wrapper rather than a
    // high-confidence online-state predicate.
    {
        const uint64_t overflowBranch = base + 0x650;
        dis.bodies[overflowBranch] = {
            callMem(overflowBranch, iatConnectivity),
            op(overflowBranch + 1, "test", "eax, eax"),
            jumpIf(overflowBranch + 2, "jo", overflowBranch + 5),
            op(overflowBranch + 3, "xor", "eax, eax"),
            ret(overflowBranch + 4),
            ret(overflowBranch + 5),
        };
        std::vector<NamerInput> f = {
            { overflowBranch, 8, false, "sub_100650" },
        };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        CHECK(r[0].guessed);
        CHECK(r[0].name != "WifiCheck");
        CHECK_EQ(r[0].name, "internet_get_connected_state");
    }

    // MSVC commonly normalizes a tested Win32 BOOL with SETNE AL followed by
    // MOVZX EAX, AL before returning. The full-width MOVZX makes this a valid
    // predicate result; SETNE alone updates only AL and must not promote the
    // partially stale EAX value to WifiCheck evidence.
    {
        const uint64_t normalized = base + 0x660;
        const uint64_t partial = base + 0x670;
        dis.bodies[normalized] = {
            callMem(normalized, iatConnectivity),
            op(normalized + 1, "test", "eax, eax"),
            op(normalized + 2, "setne", "al"),
            op(normalized + 3, "movzx", "eax, al"),
            ret(normalized + 4),
        };
        dis.bodies[partial] = {
            callMem(partial, iatConnectivity),
            op(partial + 1, "test", "eax, eax"),
            op(partial + 2, "setne", "al"),
            ret(partial + 3),
        };

        std::vector<NamerInput> positive = {
            { normalized, 8, false, "sub_100660" },
        };
        FunctionNamer positiveNamer;
        auto normalizedResult = positiveNamer.name(
            bin, dis, positive, 0, importNameFor, stringRefFor);
        CHECK(normalizedResult[0].guessed);
        CHECK_EQ(normalizedResult[0].name, "WifiCheck");
        CHECK(normalizedResult[0].reason.find("returns InternetGetConnectedState") !=
              std::string::npos);

        std::vector<NamerInput> negative = {
            { partial, 8, false, "sub_100670" },
        };
        FunctionNamer negativeNamer;
        auto partialResult = negativeNamer.name(
            bin, dis, negative, 0, importNameFor, stringRefFor);
        CHECK(partialResult[0].guessed);
        CHECK(partialResult[0].name != "WifiCheck");
        CHECK_EQ(partialResult[0].name, "internet_get_connected_state");
    }

    // ARM/AArch64 CB(N)Z combines the accumulator zero test and branch in one
    // instruction. W0 is the ABI return register, so a strong connectivity call
    // followed by CBNZ w0 is the same predicate evidence as x86 TEST/JNZ.
    {
        const uint64_t armChecked = base + 0x680;
        Instruction cbnz = jumpIf(armChecked + 1, "cbnz", armChecked + 3);
        cbnz.operands = "w0, loc_online";
        cbnz.flow.kind = FlowKind::ConditionalBranch;
        dis.bodies[armChecked] = {
            callMem(armChecked, iatConnectivity),
            cbnz,
            ret(armChecked + 2),
            ret(armChecked + 3),
        };
        std::vector<NamerInput> f = {
            { armChecked, 8, false, "sub_100680" },
        };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        CHECK(r[0].guessed);
        CHECK_EQ(r[0].name, "WifiCheck");
        CHECK(r[0].reason.find("InternetGetConnectedState") != std::string::npos);
    }

    // Contextual names require two independent kinds of evidence.  This
    // function references a strong subject phrase and performs a complete
    // CryptoAPI create/update/final hash pipeline, so the generic hash_data
    // fallback can be refined honestly to licenseHashing.
    {
        const uint64_t hashing = base + 0x700;
        dis.bodies[hashing] = {
            dataRef(hashing, licenseKeyVA),
            callMem(hashing + 1, iatCryptCreateHash),
            callMem(hashing + 2, iatCryptHashData),
            callMem(hashing + 3, iatCryptGetHashParam),
            ret(hashing + 4),
        };
        std::vector<NamerInput> f = {
            { hashing, 16, false, "sub_100700" },
        };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        CHECK(r[0].guessed);
        CHECK_EQ(r[0].name, "licenseHashing");
        CHECK(r[0].reason.find("license key") != std::string::npos);
        CHECK(r[0].reason.find("CryptHashData") != std::string::npos);
    }

    // The same hash pipeline becomes validation only when a comparison result
    // demonstrably controls an equality decision.  TEST/JNZ is the canonical
    // x86 shape for consuming memcmp's zero/non-zero result.
    {
        const uint64_t validation = base + 0x740;
        dis.bodies[validation] = {
            dataRef(validation, licenseKeyVA),
            callMem(validation + 1, iatCryptCreateHash),
            callMem(validation + 2, iatCryptHashData),
            callMem(validation + 3, iatCryptGetHashParam),
            callMem(validation + 4, iatMemcmp),
            op(validation + 5, "test", "eax, eax"),
            jumpIf(validation + 6, "jnz", validation + 8),
            ret(validation + 7),
            ret(validation + 8),
        };
        std::vector<NamerInput> f = {
            { validation, 24, false, "sub_100740" },
        };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        CHECK(r[0].guessed);
        CHECK_EQ(r[0].name, "licenseValidation");
        CHECK(r[0].reason.find("license key") != std::string::npos);
        CHECK(r[0].reason.find("memcmp") != std::string::npos);
    }

    // Result-use refinement follows each supported native ABI's return register.
    // These scripted bodies share the same imported workflow but consume the
    // comparator on AArch64, MIPS, PowerPC, and RISC-V respectively.
    {
        const uint64_t a64 = base + 0x800, mips = base + 0x820;
        const uint64_t ppc = base + 0x840, riscv = base + 0x860;
        auto prefix = [&](uint64_t at) {
            return std::vector<Instruction>{
                dataRef(at, licenseKeyVA),
                callMem(at + 1, iatCryptCreateHash),
                callMem(at + 2, iatCryptHashData),
                callMem(at + 3, iatCryptGetHashParam),
                callMem(at + 4, iatMemcmp),
            };
        };

        dis.bodies[a64] = prefix(a64);
        dis.bodies[a64].push_back(op(a64 + 5, "cmp", "w0, #0"));
        dis.bodies[a64].push_back(op(a64 + 6, "cset", "w0, eq"));
        dis.bodies[a64].push_back(ret(a64 + 7));

        dis.bodies[mips] = prefix(mips);
        dis.bodies[mips].push_back(op(mips + 5, "bne", "v0, $zero, loc_bad"));
        dis.bodies[mips].back().isBranch = true;
        dis.bodies[mips].push_back(ret(mips + 6));

        dis.bodies[ppc] = prefix(ppc);
        dis.bodies[ppc].push_back(op(ppc + 5, "cmpwi", "r3, 0"));
        dis.bodies[ppc].push_back(jumpIf(ppc + 6, "bne", ppc + 8));
        dis.bodies[ppc].push_back(ret(ppc + 7));
        dis.bodies[ppc].push_back(ret(ppc + 8));

        dis.bodies[riscv] = prefix(riscv);
        dis.bodies[riscv].push_back(op(riscv + 5, "bne", "a0, zero, loc_bad"));
        dis.bodies[riscv].back().isBranch = true;
        dis.bodies[riscv].push_back(ret(riscv + 6));

        std::vector<NamerInput> f = {
            { a64,   24, false, "sub_100800" },
            { mips,  24, false, "sub_100820" },
            { ppc,   24, false, "sub_100840" },
            { riscv, 24, false, "sub_100860" },
        };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        for (const auto& named : r) {
            CHECK(named.guessed);
            CHECK(named.name.rfind("licenseValidation", 0) == 0);
        }
    }

    // Evidence is function-local.  A neighboring routine that merely refers
    // to the licensing phrase must not donate that subject to a generic hash
    // worker in the same naming batch.
    {
        const uint64_t subjectOnly = base + 0x780;
        const uint64_t hashOnly = base + 0x7A0;
        dis.bodies[subjectOnly] = {
            dataRef(subjectOnly, licenseKeyVA),
            ret(subjectOnly + 1),
        };
        dis.bodies[hashOnly] = {
            callMem(hashOnly, iatCryptCreateHash),
            callMem(hashOnly + 1, iatCryptHashData),
            callMem(hashOnly + 2, iatCryptGetHashParam),
            ret(hashOnly + 3),
        };
        std::vector<NamerInput> f = {
            { subjectOnly, 8, false, "sub_100780" },
            { hashOnly,   16, false, "sub_1007A0" },
        };
        FunctionNamer n;
        auto r = n.name(bin, dis, f, 0, importNameFor, stringRefFor);
        CHECK(r[0].name != "licenseHashing");
        CHECK(r[0].name != "licenseValidation");
        CHECK(r[1].guessed);
        CHECK_EQ(r[1].name, "hash_data");
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

    const bool benchmark = argc > 1 && std::string(argv[1]) == "--benchmark";
    checkLargeNamingBatches(benchmark ? 16384 : 1024, benchmark);

    std::remove(path.c_str());
    if (!g_fail) std::printf("function_namer_pipeline_test: ALL PASS\n");
    else std::printf("function_namer_pipeline_test: %d FAIL\n", g_fail);
    return g_fail ? 1 : 0;
}
