// Metadata-only investigation leads: validity, provenance, bounds, and stable
// selection. No decoder or GUI dependencies are required.
// cl /std:c++20 /EHsc /I src tests\binary_overview_test.cpp ^
//    src\Core\BinaryOverview.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp

#include "Core/BinaryOverview.h"
#include "Core/AnalysisJobs.h"
#include "Core/BinaryFile.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <vector>

using namespace ds;

static int failures = 0;
#define CHECK(test) do { if (!(test)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #test); ++failures; } } while (0)

template<class T>
static void put(std::vector<uint8_t>& bytes, size_t offset, T value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

static void putString(std::vector<uint8_t>& bytes, size_t offset, const char* text) {
    std::memcpy(bytes.data() + offset, text, std::strlen(text) + 1);
}

static std::vector<uint8_t> makePE(uint32_t entry = 0x1000,
                                   bool exports = true, bool thumb = false) {
    std::vector<uint8_t> bytes(0xA00, 0);
    putString(bytes, 0, "MZ");
    put<uint32_t>(bytes, 0x3C, 0x80);
    put<uint32_t>(bytes, 0x80, 0x00004550);
    const size_t coff = 0x84, opt = 0x98;
    put<uint16_t>(bytes, coff, thumb ? 0x01C4 : 0x014C);
    put<uint16_t>(bytes, coff + 2, 2);
    put<uint16_t>(bytes, coff + 16, 0xE0);
    put<uint16_t>(bytes, coff + 18, 0x0102);
    put<uint16_t>(bytes, opt, 0x10B);
    put<uint32_t>(bytes, opt + 16, entry);
    put<uint32_t>(bytes, opt + 28, 0x400000);
    put<uint32_t>(bytes, opt + 32, 0x1000);
    put<uint32_t>(bytes, opt + 36, 0x200);
    put<uint32_t>(bytes, opt + 56, 0x3000);
    put<uint32_t>(bytes, opt + 60, 0x200);
    put<uint32_t>(bytes, opt + 92, 16);
    if (exports) {
        put<uint32_t>(bytes, opt + 96, 0x2000);
        put<uint32_t>(bytes, opt + 100, 0x100);
    }
    const size_t text = opt + 0xE0, data = text + 40;
    putString(bytes, text, ".text");
    put<uint32_t>(bytes, text + 8, 0x200);
    put<uint32_t>(bytes, text + 12, 0x1000);
    put<uint32_t>(bytes, text + 16, 0x200);
    put<uint32_t>(bytes, text + 20, 0x200);
    put<uint32_t>(bytes, text + 36, 0x60000020);
    putString(bytes, data, ".rdata");
    put<uint32_t>(bytes, data + 8, 0x600);
    put<uint32_t>(bytes, data + 12, 0x2000);
    put<uint32_t>(bytes, data + 16, 0x600);
    put<uint32_t>(bytes, data + 20, 0x400);
    put<uint32_t>(bytes, data + 36, 0x40000040);
    // Two local code exports, a forwarder, data, and an unmapped target.
    put<uint32_t>(bytes, 0x400 + 16, 5);
    put<uint32_t>(bytes, 0x400 + 20, 5);
    put<uint32_t>(bytes, 0x400 + 24, 4);
    put<uint32_t>(bytes, 0x400 + 28, 0x2040);
    put<uint32_t>(bytes, 0x400 + 32, 0x2054);
    put<uint32_t>(bytes, 0x400 + 36, 0x2064);
    for (size_t i = 0; i < 5; ++i) {
        constexpr uint32_t values[] = {0x1011, 0x1020, 0x2080, 0x2180, 0x5000};
        put<uint32_t>(bytes, 0x440 + i * 4, values[i]);
    }
    for (size_t i = 0; i < 4; ++i) {
        put<uint32_t>(bytes, 0x454 + i * 4, static_cast<uint32_t>(0x2120 + i * 16));
        constexpr uint16_t ordinals[] = {0, 2, 3, 4};
        put<uint16_t>(bytes, 0x464 + i * 2, ordinals[i]);
    }
    putString(bytes, 0x480, "OTHER.Function");
    putString(bytes, 0x520, "Run");
    putString(bytes, 0x530, "Forwarded");
    putString(bytes, 0x540, "Data");
    putString(bytes, 0x550, "Unmapped");
    return bytes;
}

static bool loadPE(BinaryFile& binary, const std::vector<uint8_t>& bytes) {
    static unsigned sequence = 0;
    const auto path = std::filesystem::temp_directory_path() /
        ("ds_binary_overview_" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()) + "_" +
         std::to_string(++sequence) + ".bin");
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
    }
    const auto native = path.u8string();
    const bool loaded = binary.load(std::string(native.begin(), native.end()));
    std::filesystem::remove(path);
    return loaded;
}

static bool hasAddress(const BinaryOverview& overview, uint64_t va) {
    return std::any_of(overview.leads.begin(), overview.leads.end(),
        [&](const BinaryOverviewLead& lead) { return lead.va == va; });
}

static void checkBacked(const BinaryFile& binary, const BinaryOverview& overview) {
    for (const BinaryOverviewLead& lead : overview.leads) {
        size_t available = 0;
        uint64_t offset = 0;
        CHECK(binary.ptrFromVA(lead.va, available) != nullptr && available > 0);
        CHECK(binary.vaToOffset(lead.va, offset) && offset < binary.bytes().size());
    }
}

int main() {
    {
        BinaryFile empty;
        const auto overview = BuildBinaryOverview(empty);
        CHECK(overview.leads.empty() && !overview.entryDeclared && !overview.entryMapped);
    }
    {
        BinaryFile raw;
        CHECK(raw.loadFromMemory(std::vector<uint8_t>(256, 0x90), 0, "overview_raw"));
        auto overview = BuildBinaryOverview(raw);
        CHECK(!overview.entryDeclared && !overview.entryMapped);
        CHECK(overview.leads.size() == 1 && overview.leads[0].va == 0);
        CHECK(overview.leads[0].label == "Browse executable section");
        CHECK(overview.leads[0].evidence.find("not a proven function") != std::string::npos);
        CHECK(raw.setRawEntryPointVA(0));
        CHECK(raw.setAnalysisLandmarks({{0, "duplicate_entry", "reset root"},
                                       {0x40, "interrupt_entry", "named firmware root"}}));
        overview = BuildBinaryOverview(raw);
        CHECK(overview.entryDeclared && overview.entryMapped);
        CHECK(overview.leads.size() == 2 && overview.leads[0].va == 0);
        CHECK(overview.leads[0].label == "Declared entry");
        CHECK(overview.leads[1].label == "interrupt_entry");
        checkBacked(raw, overview);
        CHECK(raw.setRawEntryPointVA(1));
        CHECK(raw.setAnalysisLandmarks({{0x41, "thumb_root", "explicit raw root"}}));
        const auto thumb = BuildBinaryOverview(raw, nullptr, Arch::THUMB);
        CHECK(thumb.leads.front().va == 0 && hasAddress(thumb, 0x40));
        const auto x86 = BuildBinaryOverview(raw, nullptr, Arch::X86);
        CHECK(x86.leads.front().va == 1 && hasAddress(x86, 0x41));
    }
    {
        BinaryFile binary;
        CHECK(loadPE(binary, makePE()));
        const auto overview = BuildBinaryOverview(binary);
        CHECK(overview.entryDeclared && overview.entryMapped);
        CHECK(overview.leads.size() == 3);
        CHECK(overview.leads.front().va == 0x401000);
        CHECK(hasAddress(overview, 0x401011) && hasAddress(overview, 0x401020));
        CHECK(!hasAddress(overview, 0x402080));
        CHECK(!hasAddress(overview, 0x402180));
        CHECK(!hasAddress(overview, 0x405000));
        checkBacked(binary, overview);
    }
    {
        BinaryFile binary;
        CHECK(loadPE(binary, makePE(0x5000, false)));
        const auto overview = BuildBinaryOverview(binary);
        CHECK(overview.entryDeclared && !overview.entryMapped);
        CHECK(overview.leads.size() == 1 && overview.leads[0].va == 0x401000);
        CHECK(overview.leads[0].label == "Browse executable section");
    }
    {
        BinaryFile binary;
        CHECK(loadPE(binary, makePE(0x2180, false)));
        const auto overview = BuildBinaryOverview(binary);
        CHECK(overview.entryDeclared && overview.entryMapped);
        CHECK(overview.leads.size() == 1 && !overview.leads[0].code);
        CHECK(overview.leads[0].evidence.find("not executable") != std::string::npos);
        checkBacked(binary, overview);
    }
    {
        BinaryFile binary;
        CHECK(loadPE(binary, makePE(0x1001, true, true)));
        const auto overview = BuildBinaryOverview(binary);
        CHECK(binary.machine() == MachineArch::THUMB);
        CHECK(overview.leads.front().va == 0x401000);
        CHECK(hasAddress(overview, 0x401010));
        CHECK(!hasAddress(overview, 0x401011));
        checkBacked(binary, overview);
    }
    {
        BinaryFile binary;
        auto bytes = makePE(0x1300, false);
        // Declared executable virtual padding has no bytes and cannot be a lead.
        put<uint32_t>(bytes, 0x178 + 8, 0x400);
        CHECK(loadPE(binary, bytes));
        std::vector<FuncResult> functions(3);
        functions[0].address = 0x402180; functions[0].name = "data_function";
        functions[1].address = 0x401300; functions[1].name = "padding_function";
        functions[2].address = 0x405000; functions[2].name = "unmapped_function";
        const auto overview = BuildBinaryOverview(binary, &functions);
        CHECK(overview.entryDeclared && !overview.entryMapped);
        CHECK(overview.leads.size() == 1 && overview.leads[0].label == "Browse executable section");
    }
    {
        BinaryFile raw;
        CHECK(raw.loadFromMemory(std::vector<uint8_t>(4096, 0x90), 0, "overview_functions"));
        std::vector<FuncResult> functions(4);
        functions[0].address = 0x20; functions[0].name = "guessed_reader";
        functions[0].guessed = true; functions[0].reason = "calls a file-reading API";
        functions[0].ownershipTruncated = true;
        functions[1].address = 0; functions[1].name = "exact_symbol";
        functions[1].seedKind = FunctionSeedKind::Symbol;
        functions[1].boundaryConfidence = FunctionBoundaryConfidence::Authoritative;
        functions[2] = functions[1]; functions[2].name = "alias_at_zero";
        functions[3].address = 0x10; functions[3].name = "reached_call";
        functions[3].seedKind = FunctionSeedKind::ReachedCall;
        functions[3].boundaryConfidence = FunctionBoundaryConfidence::Reconciled;
        const auto overview = BuildBinaryOverview(raw, &functions);
        CHECK(overview.leads.size() == 3);
        CHECK(overview.leads[0].label == "exact_symbol" && !overview.leads[0].inferred);
        CHECK(overview.leads[1].label == "reached_call" && overview.leads[1].inferred);
        CHECK(overview.leads[2].inferred);
        CHECK(overview.leads[2].evidence.find("Name is inferred") != std::string::npos);
        CHECK(overview.leads[2].evidence.find("coverage is partial") != std::string::npos);
        checkBacked(raw, overview);

        functions.resize(kBinaryOverviewSourceLimit + 1);
        for (size_t i = 0; i < functions.size(); ++i) {
            functions[i] = {};
            functions[i].address = i;
            functions[i].name = "candidate_" + std::to_string(i);
        }
        const auto capped = BuildBinaryOverview(raw, &functions);
        const auto again = BuildBinaryOverview(raw, &functions);
        CHECK(capped.leads.size() == kBinaryOverviewLeadLimit && capped.candidatesLimited);
        for (size_t i = 0; i < capped.leads.size(); ++i) {
            CHECK(capped.leads[i].va == i && capped.leads[i].va == again.leads[i].va);
            CHECK(capped.leads[i].label == again.leads[i].label);
        }
        // A high-confidence record outside the admitted source prefix is omitted.
        for (auto& function : functions) function.address = 0;
        functions.back().address = 0x900;
        functions.back().boundaryConfidence = FunctionBoundaryConfidence::Authoritative;
        const auto sourceCapped = BuildBinaryOverview(raw, &functions);
        CHECK(sourceCapped.candidatesLimited && sourceCapped.leads.size() == 1);
        CHECK(!hasAddress(sourceCapped, 0x900));
    }
    {
        BinaryFile high;
        constexpr uint64_t top = (std::numeric_limits<uint64_t>::max)();
        CHECK(high.loadFromMemory(std::vector<uint8_t>(64, 0x90), top - 63, "overview_high"));
        std::vector<FuncResult> functions(2);
        functions[0].address = top; functions[0].name = "last_address";
        functions[1].address = 0; functions[1].name = "wrapped_address";
        const auto overview = BuildBinaryOverview(high, &functions);
        CHECK(overview.leads.size() == 1 && overview.leads[0].va == top);
        checkBacked(high, overview);
    }
    std::printf("binary_overview_test: %s\n", failures ? "FAILED" : "passed");
    return failures ? 1 : 0;
}
