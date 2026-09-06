//
// persistent_file_triage_test.cpp
// Focused production-adapter regression for endpoint-free file-backed
// authorization triage.  The PE loader, function/xref discovery,
// FuncAnnotate argument recovery, persistence catalog, and AnalysisService
// correlation all remain real; only instruction decoding is scripted.
//
// Compile with the same dependency list as analysis_service_test.cpp.
//

#include "Core/AnalysisService.h"
#include "Core/BinaryFile.h"
#include "Core/PersistentStateCatalog.h"
#include "Disasm/IDisassembler.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace ds;

namespace {

int g_fail = 0;

#define CHECK(condition, message)                                             \
    do {                                                                      \
        if (!(condition)) {                                                   \
            std::printf("FAIL: %s\n", message);                             \
            ++g_fail;                                                         \
        }                                                                     \
    } while (0)

constexpr uint64_t kImageBase = UINT64_C(0x1A0000000);
constexpr uint64_t kCreateFileIat = kImageBase + 0x2200;
constexpr uint64_t kReadFileIat = kImageBase + 0x2208;
constexpr uint64_t kWriteFileIat = kImageBase + 0x2210;
constexpr uint64_t kReadConsoleIat = kImageBase + 0x2218;
constexpr uint64_t kStatePath = kImageBase + 0x2400;
constexpr uint64_t kSuccessText = kImageBase + 0x2500;
constexpr uint64_t kSuccessText2 = kImageBase + 0x2520;
constexpr uint64_t kFailureText = kImageBase + 0x2540;
constexpr uint64_t kFailureText2 = kImageBase + 0x2560;
constexpr char kExpectedPath[] =
    "C:\\ProgramData\\Acme\\DisasmStudio\\Licensing\\RememberedValidation\\authorization-state.json";

uint16_t registerWidth(const char* name) {
    const std::string value(name ? name : "");
    if (value == "eax" || value == "ecx" || value == "edx" ||
        value == "ebx" || value == "r8d" || value == "r9d")
        return 32;
    if (value == "ax" || value == "cx" || value == "dx" || value == "bx")
        return 16;
    if (value == "al" || value == "cl" || value == "dl" || value == "bl")
        return 8;
    return 64;
}

struct PersistentFileDisasm final : IDisassembler {
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "persistent-file-fixture"; }

    static void addRegister(Instruction& instruction, const char* name,
                            OperandAccess access) {
        TypedOperand operand;
        operand.kind = OperandKind::Register;
        operand.access = access;
        operand.registerName = name;
        operand.widthBits = registerWidth(name);
        instruction.typedOperands.push_back(std::move(operand));
        if (OperandReads(access)) instruction.registersRead.emplace_back(name);
        if (OperandWrites(access)) instruction.registersWritten.emplace_back(name);
    }

    static void addImmediate(Instruction& instruction, uint64_t value) {
        TypedOperand operand;
        operand.kind = OperandKind::Immediate;
        operand.access = OperandAccess::Read;
        operand.immediate = value;
        operand.widthBits = 64;
        instruction.typedOperands.push_back(std::move(operand));
    }

    static void addAbsoluteMemory(Instruction& instruction, uint64_t address) {
        TypedOperand operand;
        operand.kind = OperandKind::Memory;
        operand.access = OperandAccess::Read;
        operand.displacement = static_cast<int64_t>(address);
        operand.displacementValid = true;
        operand.widthBits = 64;
        instruction.typedOperands.push_back(std::move(operand));
    }

    static void addLocalMemory(Instruction& instruction, const char* base,
                               int64_t displacement, OperandAccess access,
                               uint16_t width = 64) {
        TypedOperand operand;
        operand.kind = OperandKind::Memory;
        operand.access = access;
        operand.baseRegister = base;
        operand.displacement = displacement;
        operand.displacementValid = true;
        operand.widthBits = width;
        instruction.typedOperands.push_back(std::move(operand));
        instruction.registersRead.emplace_back(base);
    }

    static void call(Instruction& instruction, uint64_t target) {
        instruction.mnemonic = "call";
        char text[32]{};
        std::snprintf(text, sizeof(text), "0x%llx",
                      static_cast<unsigned long long>(target));
        instruction.operands = text;
        instruction.isCall = true;
        instruction.isBranch = true;
        instruction.branchTarget = target;
        instruction.branchTargetValid = true;
        instruction.flow.kind = FlowKind::DirectCall;
        instruction.flow.directTarget = target;
        instruction.flow.directTargetValid = true;
    }

    static void branch(Instruction& instruction, const char* mnemonic,
                       uint64_t target) {
        instruction.mnemonic = mnemonic;
        char text[32]{};
        std::snprintf(text, sizeof(text), "0x%llx",
                      static_cast<unsigned long long>(target));
        instruction.operands = text;
        instruction.isBranch = true;
        instruction.branchTarget = target;
        instruction.branchTargetValid = true;
        instruction.flow.kind = FlowKind::ConditionalBranch;
        instruction.flow.directTarget = target;
        instruction.flow.directTargetValid = true;
        instruction.flagsRead = SemanticFlagBit(SemanticFlag::Zero);
    }

    static void ret(Instruction& instruction) {
        instruction.mnemonic = "ret";
        instruction.isRet = true;
        instruction.isBranch = true;
        instruction.flow.kind = FlowKind::Return;
    }

    static void movImmediate(Instruction& instruction, const char* destination,
                             uint64_t value) {
        instruction.mnemonic = "mov";
        char text[80]{};
        std::snprintf(text, sizeof(text), "%s, 0x%llx", destination,
                      static_cast<unsigned long long>(value));
        instruction.operands = text;
        addRegister(instruction, destination, OperandAccess::Write);
        addImmediate(instruction, value);
    }

    static void zeroRegister(Instruction& instruction, const char* name) {
        instruction.mnemonic = "xor";
        instruction.operands = std::string(name) + ", " + name;
        addRegister(instruction, name, OperandAccess::ReadWrite);
        addRegister(instruction, name, OperandAccess::Read);
        instruction.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
    }

    static void movRegister(Instruction& instruction, const char* destination,
                            const char* source) {
        instruction.mnemonic = "mov";
        instruction.operands = std::string(destination) + ", " + source;
        addRegister(instruction, destination, OperandAccess::Write);
        addRegister(instruction, source, OperandAccess::Read);
    }

    static void leaAbsolute(Instruction& instruction, const char* destination,
                            uint64_t address) {
        instruction.mnemonic = "lea";
        char text[96]{};
        std::snprintf(text, sizeof(text), "%s, [0x%llx]", destination,
                      static_cast<unsigned long long>(address));
        instruction.operands = text;
        addRegister(instruction, destination, OperandAccess::Write);
        addAbsoluteMemory(instruction, address);
    }

    static void leaLocal(Instruction& instruction, const char* destination,
                         int64_t displacement) {
        instruction.mnemonic = "lea";
        char text[96]{};
        std::snprintf(text, sizeof(text), "%s, [rbp - 0x%llx]", destination,
                      static_cast<unsigned long long>(-displacement));
        instruction.operands = text;
        addRegister(instruction, destination, OperandAccess::Write);
        addLocalMemory(instruction, "rbp", displacement, OperandAccess::Read);
    }

    static void movStackImmediate(Instruction& instruction, uint64_t offset,
                                  uint64_t value) {
        instruction.mnemonic = "mov";
        char text[96]{};
        std::snprintf(text, sizeof(text), "[rsp + 0x%llx], 0x%llx",
                      static_cast<unsigned long long>(offset),
                      static_cast<unsigned long long>(value));
        instruction.operands = text;
        addLocalMemory(instruction, "rsp", static_cast<int64_t>(offset),
                       OperandAccess::Write);
        addImmediate(instruction, value);
    }

    static void loadByte(Instruction& instruction, int64_t displacement) {
        instruction.mnemonic = "movzx";
        char text[96]{};
        std::snprintf(text, sizeof(text),
                      "eax, byte ptr [rbp - 0x%llx]",
                      static_cast<unsigned long long>(-displacement));
        instruction.operands = text;
        addRegister(instruction, "eax", OperandAccess::Write);
        addLocalMemory(instruction, "rbp", displacement,
                       OperandAccess::Read, 8);
    }

    static void loadWord(Instruction& instruction, int64_t displacement) {
        instruction.mnemonic = "movzx";
        char text[96]{};
        std::snprintf(text, sizeof(text),
                      "eax, word ptr [rbp - 0x%llx]",
                      static_cast<unsigned long long>(-displacement));
        instruction.operands = text;
        addRegister(instruction, "eax", OperandAccess::Write);
        addLocalMemory(instruction, "rbp", displacement,
                       OperandAccess::Read, 16);
    }

    static void compareOne(Instruction& instruction) {
        instruction.mnemonic = "cmp";
        instruction.operands = "eax, 1";
        addRegister(instruction, "eax", OperandAccess::Read);
        addImmediate(instruction, 1);
        instruction.flagsWritten = SemanticFlagBit(SemanticFlag::Zero);
    }

    bool decodeOne(const uint8_t* data, size_t size, uint64_t va,
                   Instruction& instruction) override {
        if (!data || size == 0 || va < kImageBase) return false;
        instruction = {};
        instruction.address = va;
        instruction.length = 1;
        instruction.bytes = "90";
        const uint64_t rva = va - kImageBase;

        switch (rva) {
        // PE entry: both helpers are startup-reachable.
        case 0x1000: call(instruction, kImageBase + 0x1100); break;
        case 0x1001: call(instruction, kImageBase + 0x1200); break;
        case 0x1002: ret(instruction); break;

        // Startup state load.  CreateFileW's returned handle is explicitly
        // copied to rbx, then consumed by ReadFile.  The byte loaded from the
        // fixed ReadFile output buffer reaches an adjacent compare/branch.
        case 0x1100: leaAbsolute(instruction, "rcx", kStatePath); break;
        case 0x1101: movImmediate(instruction, "rdx", 0x80000000u); break;
        case 0x1102: movImmediate(instruction, "r8", 1); break;
        case 0x1103: zeroRegister(instruction, "r9"); break;
        case 0x1104: movStackImmediate(instruction, 0x20, 3); break;
        case 0x1105: movStackImmediate(instruction, 0x28, 0); break;
        case 0x1106: movStackImmediate(instruction, 0x30, 0); break;
        case 0x1107: call(instruction, kCreateFileIat); break;
        case 0x1108: movRegister(instruction, "rbx", "rax"); break;
        case 0x1109: movRegister(instruction, "rcx", "rbx"); break;
        case 0x110A: leaLocal(instruction, "rdx", -0x40); break;
        case 0x110B: movImmediate(instruction, "r8", 16); break;
        case 0x110C: leaLocal(instruction, "r9", -0x48); break;
        case 0x110D: movStackImmediate(instruction, 0x20, 0); break;
        case 0x110E: call(instruction, kReadFileIat); break;
        case 0x110F: loadByte(instruction, -0x40); break;
        case 0x1110: compareOne(instruction); break;
        case 0x1111: branch(instruction, "jne", kImageBase + 0x1120); break;
        case 0x1112: leaAbsolute(instruction, "rax", kSuccessText); break;
        case 0x1113: movImmediate(instruction, "rax", 1); break;
        case 0x1114: ret(instruction); break;
        case 0x1120: leaAbsolute(instruction, "rax", kFailureText); break;
        case 0x1121: zeroRegister(instruction, "rax"); break;
        case 0x1122: ret(instruction); break;

        // Endpoint-free local validation.  ReadConsoleW supplies the exact
        // local input origin.  Its allow arm creates and writes the same path,
        // giving AuthorizationAnalysis a real authorization flow from which it
        // can link the durable write to the next-launch startup read above.
        case 0x1200: zeroRegister(instruction, "rcx"); break;
        case 0x1201: leaLocal(instruction, "rdx", -0x80); break;
        case 0x1202: movImmediate(instruction, "r8", 16); break;
        case 0x1203: leaLocal(instruction, "r9", -0x88); break;
        case 0x1204: movStackImmediate(instruction, 0x20, 0); break;
        case 0x1205: call(instruction, kReadConsoleIat); break;
        case 0x1206: loadWord(instruction, -0x80); break;
        case 0x1207: compareOne(instruction); break;
        case 0x1208: branch(instruction, "jne", kImageBase + 0x1250); break;
        case 0x1209: leaAbsolute(instruction, "rcx", kStatePath); break;
        case 0x120A: movImmediate(instruction, "rdx", 0x40000000u); break;
        case 0x120B: zeroRegister(instruction, "r8"); break;
        case 0x120C: zeroRegister(instruction, "r9"); break;
        case 0x120D: movStackImmediate(instruction, 0x20, 2); break;
        case 0x120E: movStackImmediate(instruction, 0x28, 0); break;
        case 0x120F: movStackImmediate(instruction, 0x30, 0); break;
        case 0x1210: call(instruction, kCreateFileIat); break;
        case 0x1211: movRegister(instruction, "rbx", "rax"); break;
        case 0x1212: movRegister(instruction, "rcx", "rbx"); break;
        case 0x1213: leaLocal(instruction, "rdx", -0x90); break;
        case 0x1214: movImmediate(instruction, "r8", 1); break;
        case 0x1215: leaLocal(instruction, "r9", -0x98); break;
        case 0x1216: movStackImmediate(instruction, 0x20, 0); break;
        case 0x1217: call(instruction, kWriteFileIat); break;
        case 0x1218: leaAbsolute(instruction, "rax", kSuccessText); break;
        case 0x1219: leaAbsolute(instruction, "rax", kSuccessText2); break;
        case 0x121A: movImmediate(instruction, "rax", 1); break;
        case 0x121B: ret(instruction); break;
        case 0x1250: leaAbsolute(instruction, "rax", kFailureText); break;
        case 0x1251: leaAbsolute(instruction, "rax", kFailureText2); break;
        case 0x1252: zeroRegister(instruction, "rax"); break;
        case 0x1253: ret(instruction); break;

        default: instruction.mnemonic = "nop"; break;
        }
        return true;
    }

    std::vector<Instruction> disassemble(const uint8_t* data, size_t size,
                                         uint64_t va,
                                         size_t maxInstructions) override {
        std::vector<Instruction> result;
        size_t offset = 0;
        while (offset < size &&
               (maxInstructions == 0 || result.size() < maxInstructions)) {
            Instruction instruction;
            if (!decodeOne(data + offset, size - offset, va + offset,
                           instruction))
                break;
            result.push_back(instruction);
            offset += instruction.length;
        }
        return result;
    }
};

template <typename T>
void put(std::vector<uint8_t>& bytes, size_t offset, T value) {
    CHECK(offset <= bytes.size() && sizeof(value) <= bytes.size() - offset,
          "fixture write stays in bounds");
    if (offset <= bytes.size() && sizeof(value) <= bytes.size() - offset)
        std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

void putAscii(std::vector<uint8_t>& bytes, size_t offset,
              const char* value) {
    const size_t count = std::strlen(value) + 1;
    CHECK(offset <= bytes.size() && count <= bytes.size() - offset,
          "fixture string stays in bounds");
    if (offset <= bytes.size() && count <= bytes.size() - offset)
        std::memcpy(bytes.data() + offset, value, count);
}

void putUtf16(std::vector<uint8_t>& bytes, size_t offset,
              const char* ascii) {
    const size_t count = std::strlen(ascii);
    CHECK(offset <= bytes.size() && (count + 1) * 2 <= bytes.size() - offset,
          "fixture UTF-16 string stays in bounds");
    if (offset > bytes.size() || (count + 1) * 2 > bytes.size() - offset)
        return;
    for (size_t index = 0; index < count; ++index)
        put<uint16_t>(bytes, offset + index * 2,
                      static_cast<uint8_t>(ascii[index]));
    put<uint16_t>(bytes, offset + count * 2, 0);
}

std::vector<uint8_t> buildPe64() {
    std::vector<uint8_t> bytes(0x1200, 0);
    bytes[0] = 'M';
    bytes[1] = 'Z';
    constexpr uint32_t pe = 0x80;
    put<uint32_t>(bytes, 0x3C, pe);
    put<uint32_t>(bytes, pe, 0x00004550u);
    const size_t coff = pe + 4;
    put<uint16_t>(bytes, coff + 0, 0x8664); // AMD64
    put<uint16_t>(bytes, coff + 2, 2);
    put<uint16_t>(bytes, coff + 16, 0xF0);
    put<uint16_t>(bytes, coff + 18, 0x22);

    const size_t opt = coff + 20;
    put<uint16_t>(bytes, opt + 0, 0x20B);
    put<uint32_t>(bytes, opt + 16, 0x1000);
    put<uint64_t>(bytes, opt + 24, kImageBase);
    put<uint32_t>(bytes, opt + 32, 0x1000);
    put<uint32_t>(bytes, opt + 36, 0x200);
    put<uint32_t>(bytes, opt + 56, 0x3000);
    put<uint32_t>(bytes, opt + 60, 0x400);
    put<uint32_t>(bytes, opt + 108, 16);
    put<uint32_t>(bytes, opt + 120, 0x2100); // import directory
    put<uint32_t>(bytes, opt + 124, 0x28);

    const size_t text = opt + 0xF0;
    std::memcpy(bytes.data() + text, ".text\0\0\0", 8);
    put<uint32_t>(bytes, text + 8, 0x800);
    put<uint32_t>(bytes, text + 12, 0x1000);
    put<uint32_t>(bytes, text + 16, 0x800);
    put<uint32_t>(bytes, text + 20, 0x400);
    put<uint32_t>(bytes, text + 36, 0x60000020u);

    const size_t rdata = text + 40;
    std::memcpy(bytes.data() + rdata, ".rdata\0\0", 8);
    put<uint32_t>(bytes, rdata + 8, 0x600);
    put<uint32_t>(bytes, rdata + 12, 0x2000);
    put<uint32_t>(bytes, rdata + 16, 0x600);
    put<uint32_t>(bytes, rdata + 20, 0xC00);
    put<uint32_t>(bytes, rdata + 36, 0x40000040u);

    // One exact kernel32 import descriptor with four named entries.
    put<uint32_t>(bytes, 0xD00 + 0, 0x2180);
    put<uint32_t>(bytes, 0xD00 + 12, 0x2300);
    put<uint32_t>(bytes, 0xD00 + 16, 0x2200);
    constexpr uint64_t names[] = {0x2320, 0x2340, 0x2360, 0x2380};
    for (size_t index = 0; index < std::size(names); ++index) {
        put<uint64_t>(bytes, 0xD80 + index * 8, names[index]);
        put<uint64_t>(bytes, 0xE00 + index * 8, names[index]);
    }
    putAscii(bytes, 0xF00, "KERNEL32.dll");
    put<uint16_t>(bytes, 0xF20, 0);
    putAscii(bytes, 0xF22, "CreateFileW");
    put<uint16_t>(bytes, 0xF40, 0);
    putAscii(bytes, 0xF42, "ReadFile");
    put<uint16_t>(bytes, 0xF60, 0);
    putAscii(bytes, 0xF62, "WriteFile");
    put<uint16_t>(bytes, 0xF80, 0);
    putAscii(bytes, 0xF82, "ReadConsoleW");

    putUtf16(bytes, 0x1000, kExpectedPath);
    putAscii(bytes, 0x1100, "access granted");
    putAscii(bytes, 0x1120, "welcome licensed user");
    putAscii(bytes, 0x1140, "invalid license");
    putAscii(bytes, 0x1160, "access denied");
    return bytes;
}

bool loadFixture(BinaryFile& binary) {
    const char* path = "ds_persistent_file_triage_fixture.exe";
    {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        const std::vector<uint8_t> bytes = buildPe64();
        output.write(reinterpret_cast<const char*>(bytes.data()),
                     static_cast<std::streamsize>(bytes.size()));
        if (!output.good()) return false;
    }
    const bool loaded = binary.load(path);
    std::remove(path);
    return loaded;
}

bool imported(const BinaryFile& binary, const char* name, uint64_t iat) {
    return std::any_of(binary.imports().begin(), binary.imports().end(),
        [&](const BinaryFile::Import& item) {
            return item.dll == "KERNEL32.dll" && item.name == name &&
                   item.addressKnown && item.iatVA == iat;
        });
}

bool containsIndex(const std::vector<size_t>& values, size_t wanted) {
    return std::find(values.begin(), values.end(), wanted) != values.end();
}

} // namespace

int main() {
    BinaryFile binary;
    CHECK(loadFixture(binary), "load endpoint-free x64 PE fixture");
    CHECK(binary.format() == BinFormat::PE32Plus &&
              binary.machine() == MachineArch::X64,
          "fixture is recognized as PE32+ AMD64");
    CHECK(imported(binary, "CreateFileW", kCreateFileIat),
          "loader retains exact KERNEL32.dll!CreateFileW import");
    CHECK(imported(binary, "ReadFile", kReadFileIat),
          "loader retains exact KERNEL32.dll!ReadFile import");
    CHECK(imported(binary, "WriteFile", kWriteFileIat),
          "loader retains exact KERNEL32.dll!WriteFile import");

    AnalysisService service(
        [](Engine, Arch) -> std::unique_ptr<IDisassembler> {
            return std::make_unique<PersistentFileDisasm>();
        },
        1);
    const uint64_t epoch = service.epoch();
    service.requestBulk(&binary, Engine::Zydis, Arch::X64,
                        K_CrackmeTriage, false, epoch);

    AnalysisResult result;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(8);
    while (std::chrono::steady_clock::now() < deadline &&
           !result.crackmeTriageValid) {
        AnalysisResult next;
        while (service.tryTakeBulk(next)) {
            if (next.epoch == epoch && next.crackmeTriageValid) {
                result = std::move(next);
                break;
            }
        }
        if (!result.crackmeTriageValid)
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    CHECK(result.crackmeTriageValid,
          "AnalysisService publishes persistent-file triage");
    if (result.crackmeTriageValid) {
        const CrackmeTriageReport& triage = result.crackmeTriage;
        const AuthorizationAnalysisReport& authorization =
            triage.authorization;
        CHECK(triage.endpoints.empty() && triage.apis.empty(),
              "file-backed authorization is retained without a network endpoint or API");

        const PersistentStateIdentity expected =
            CanonicalizeFileIdentity(kExpectedPath);
        size_t readIndex = (std::numeric_limits<size_t>::max)();
        size_t writeIndex = (std::numeric_limits<size_t>::max)();
        bool exactCreateRead = false;
        bool exactCreateWrite = false;
        for (size_t index = 0;
             index < authorization.stateOperations.size(); ++index) {
            const PersistentStateOperation& operation =
                authorization.stateOperations[index];
            const bool exactFile =
                PersistentStateIdentityEquivalentExact(operation.identity,
                                                       expected);
            if (operation.apiName == "CreateFile" && exactFile &&
                operation.access == PersistentStateAccess::Read)
                exactCreateRead = true;
            if (operation.apiName == "CreateFile" && exactFile &&
                operation.access == PersistentStateAccess::Write)
                exactCreateWrite = true;
            if (operation.apiName == "ReadFile" && exactFile &&
                operation.access == PersistentStateAccess::Read)
                readIndex = index;
            if (operation.apiName == "WriteFile" && exactFile &&
                operation.access == PersistentStateAccess::Write)
                writeIndex = index;
        }

        const bool readFound =
            readIndex != (std::numeric_limits<size_t>::max)();
        const bool writeFound =
            writeIndex != (std::numeric_limits<size_t>::max)();
        CHECK(exactCreateRead && exactCreateWrite && readFound && writeFound,
              "CreateFile desired access and handle lineage yield exact file read/write operations");
        if (readFound && writeFound) {
            const PersistentStateOperation& read =
                authorization.stateOperations[readIndex];
            const PersistentStateOperation& write =
                authorization.stateOperations[writeIndex];
            CHECK(read.startupReachable && read.startupDepthValid &&
                      read.startupDepth == 1,
                  "entry-reachable ReadFile is marked as a startup read");
            CHECK(!read.outputExpression.empty(),
                  "ReadFile fixed output buffer is retained for value provenance");
            CHECK(PersistentStateIdentityEquivalentExact(read.identity,
                                                          write.identity),
                  "ReadFile and WriteFile resolve to one exact durable path");
            CHECK(InferPersistentContentKind(read.identity) ==
                      PersistentContentKind::Json &&
                      read.identity.canonicalValue.empty() &&
                      write.identity.canonicalValue.empty(),
                  "JSON is an extension-derived format hint only; no field identity is fabricated");
        }

        bool persistedOutputFlow = false;
        bool persistedReload = false;
        bool persistedCompare = false;
        bool persistedBranch = false;
        bool remembered = false;
        bool linkedRead = false;
        bool linkedWrite = false;
        bool writeStage = false;
        bool readStage = false;
        bool gateStage = false;
        for (const AuthorizationFlow& flow : authorization.flows) {
            if (readFound && flow.gateSource ==
                                 AuthorizationGateSource::PersistentOutput &&
                flow.stateReadOperationIndexValid &&
                flow.stateReadOperationIndex == readIndex) {
                persistedOutputFlow = flow.expectedValue == "1" &&
                                      !flow.originExpression.empty();
                for (const ValueProvenanceHop& hop : flow.provenance) {
                    persistedReload |=
                        hop.kind == ValueProvenanceHopKind::Reload &&
                        hop.addressValid && hop.address == kImageBase + 0x110F;
                    persistedCompare |=
                        hop.kind == ValueProvenanceHopKind::Compare &&
                        hop.addressValid && hop.address == kImageBase + 0x1110;
                    persistedBranch |=
                        hop.kind == ValueProvenanceHopKind::Branch &&
                        hop.addressValid && hop.address == kImageBase + 0x1111;
                }
            }
            if (!flow.rememberedAccessLinked) continue;
            remembered = true;
            if (readFound) linkedRead |=
                containsIndex(flow.linkedStartupReadIndices, readIndex);
            if (writeFound) linkedWrite |=
                containsIndex(flow.linkedStateWriteIndices, writeIndex);
            for (const AuthorizationStageRecord& stage : flow.stages) {
                writeStage |= stage.stage == AuthorizationStage::StateWrite;
                readStage |= stage.stage == AuthorizationStage::StartupRead;
                gateStage |= stage.stage == AuthorizationStage::StartupGate;
            }
        }
        CHECK(persistedOutputFlow && persistedReload && persistedCompare &&
                  persistedBranch,
              "startup flow follows persisted file output through load, compare, and branch");
        CHECK(remembered && linkedRead && linkedWrite,
              "local allow path links WriteFile to the exact next-launch ReadFile identity");
        CHECK(writeStage && readStage && gateStage,
              "remembered-access flow exposes write, startup-read, and startup-gate stages");
    }

    service.cancelAndWaitIdle();
    if (g_fail == 0)
        std::printf("persistent_file_triage_test: all checks passed\n");
    else
        std::printf("persistent_file_triage_test: %d FAILED\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
