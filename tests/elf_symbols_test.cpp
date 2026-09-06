// Bounded ELF32/ELF64 symbol-table integration tests. Exercises linked string
// tables, dynsym imports, symtab locals/aliases, exact function-size seeding,
// extended section indices, and hostile table geometry.

#include "Core/BinaryFile.h"
#include "Core/FunctionAnalyzer.h"
#include "Disasm/IDisassembler.h"

#include <algorithm>
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

static void put16(std::vector<uint8_t>& b, size_t off, uint16_t v) { std::memcpy(b.data() + off, &v, 2); }
static void put32(std::vector<uint8_t>& b, size_t off, uint32_t v) { std::memcpy(b.data() + off, &v, 4); }
static void put64(std::vector<uint8_t>& b, size_t off, uint64_t v) { std::memcpy(b.data() + off, &v, 8); }

struct Strings {
    std::vector<uint8_t> bytes{0};
    uint32_t add(const char* value) {
        const uint32_t offset = static_cast<uint32_t>(bytes.size());
        const size_t n = std::strlen(value) + 1;
        bytes.insert(bytes.end(), value, value + n);
        return offset;
    }
};

static void copyAt(std::vector<uint8_t>& out, size_t off, const std::vector<uint8_t>& in) {
    std::memcpy(out.data() + off, in.data(), in.size());
}

static constexpr size_t kElf64ShOff = 0x700;
static constexpr size_t kElf64DynSymSection = 5;

static std::vector<uint8_t> buildElf64() {
    std::vector<uint8_t> b(0xA00, 0);
    std::memcpy(b.data(), "\x7F" "ELF", 4);
    b[4] = 2; b[5] = 1; b[6] = 1;                  // ELF64, little-endian
    put16(b, 16, 3);                                // ET_DYN
    put16(b, 18, 0x3E);                             // EM_X86_64
    put32(b, 20, 1);
    put64(b, 24, 0x400100);
    put64(b, 40, kElf64ShOff);
    put16(b, 52, 64); put16(b, 58, 64); put16(b, 60, 10); put16(b, 62, 9);

    Strings dyn;
    const uint32_t nPuts       = dyn.add("puts");
    const uint32_t nApi        = dyn.add("api_alias");
    const uint32_t nGlobalData = dyn.add("global_data");
    const uint32_t nTls        = dyn.add("tls_value");
    const uint32_t nHidden     = dyn.add("hidden_api");
    constexpr size_t dynOff = 0x200;
    copyAt(b, dynOff, dyn.bytes);

    Strings str;
    const uint32_t sApi       = str.add("api_alias");
    const uint32_t sAlias2    = str.add("api_alias2");
    const uint32_t sHelper    = str.add("helper");
    const uint32_t sLocalData = str.add("local_data");
    const uint32_t sCodeLabel = str.add("code_label");
    const uint32_t sBss       = str.add("bss_global");
    const uint32_t sFile      = str.add("source.c");
    const uint32_t sTextObj   = str.add("text_object");
    const uint32_t sPuts      = str.add("puts");
    constexpr size_t strOff = 0x340;
    copyAt(b, strOff, str.bytes);

    Strings shstr;
    const uint32_t shText   = shstr.add(".text");
    const uint32_t shData   = shstr.add(".data");
    const uint32_t shBss    = shstr.add(".bss");
    const uint32_t shDynStr = shstr.add(".dynstr");
    const uint32_t shDynSym = shstr.add(".dynsym");
    const uint32_t shStr    = shstr.add(".strtab");
    const uint32_t shSym    = shstr.add(".symtab");
    const uint32_t shX      = shstr.add(".symtab_shndx");
    const uint32_t shNames  = shstr.add(".shstrtab");
    constexpr size_t shstrOff = 0x580;
    copyAt(b, shstrOff, shstr.bytes);

    auto sh = [&](size_t index, uint32_t name, uint32_t type, uint64_t flags,
                  uint64_t address, uint64_t offset, uint64_t size,
                  uint32_t link = 0, uint32_t info = 0, uint64_t entrySize = 0) {
        const size_t p = kElf64ShOff + index * 64;
        put32(b, p, name); put32(b, p + 4, type); put64(b, p + 8, flags);
        put64(b, p + 16, address); put64(b, p + 24, offset); put64(b, p + 32, size);
        put32(b, p + 40, link); put32(b, p + 44, info); put64(b, p + 56, entrySize);
    };
    sh(1, shText,   1, 0x6, 0x400100, 0x100, 0x20);
    sh(2, shData,   1, 0x3, 0x401000, 0x140, 0x20);
    sh(3, shBss,    8, 0x3, 0x402000, 0,     0x20);
    sh(4, shDynStr, 3, 0,   0,        dynOff, dyn.bytes.size());
    sh(5, shDynSym, 11,0,   0,        0x280, 7 * 24, 4, 1, 24);
    sh(6, shStr,    3, 0,   0,        strOff, str.bytes.size());
    sh(7, shSym,    2, 0,   0,        0x400, 10 * 24, 6, 4, 24);
    sh(8, shX,      18,0,   0,        0x500, 10 * 4, 7, 0, 4);
    sh(9, shNames,  3, 0,   0,        shstrOff, shstr.bytes.size());

    auto sym = [&](size_t tableOff, size_t index, uint32_t name, uint8_t bind,
                   uint8_t type, uint8_t visibility, uint16_t section,
                   uint64_t value, uint64_t size) {
        const size_t p = tableOff + index * 24;
        put32(b, p, name); b[p + 4] = static_cast<uint8_t>((bind << 4) | type);
        b[p + 5] = visibility; put16(b, p + 6, section);
        put64(b, p + 8, value); put64(b, p + 16, size);
    };
    sym(0x280, 1, nPuts,       1, 2, 0, 0, 0, 0);             // undefined dyn import
    sym(0x280, 2, nApi,        1, 2, 0, 1, 0x400100, 8);
    sym(0x280, 3, nGlobalData, 2, 1, 0, 2, 0x401000, 4);
    sym(0x280, 4, nTls,        1, 6, 0, 2, 0x401008, 8);
    sym(0x280, 5, nHidden,     1, 2, 2, 1, 0x400118, 4);
    sym(0x280, 6, static_cast<uint32_t>(dyn.bytes.size()), 1, 2, 0, 0, 0, 0); // bad name offset

    sym(0x400, 1, sApi,       1, 2, 0, 1,      0x400100, 8); // duplicate of dynsym
    sym(0x400, 2, sAlias2,    1, 2, 0, 1,      0x400100, 8); // true alias
    sym(0x400, 3, sHelper,    0, 2, 0, 0xFFFF, 0x400108, 8); // SHN_XINDEX -> section 1
    sym(0x400, 4, sLocalData, 0, 1, 0, 2,      0x401004, 4);
    sym(0x400, 5, sCodeLabel, 1, 0, 0, 1,      0x400110, 0);
    sym(0x400, 6, sBss,       1, 1, 0, 3,      0x402000, 4);
    sym(0x400, 7, sFile,      0, 4, 0, 0xFFF1, 0, 0);        // STT_FILE ignored
    sym(0x400, 8, sTextObj,   1, 1, 0, 1,      0x40011C, 4); // object in .text: not a function
    sym(0x400, 9, sPuts,      1, 2, 0, 0,      0, 0);        // DYNSYM duplicate: dynamic metadata wins
    put32(b, 0x500 + 3 * 4, 1);                              // helper's extended shndx

    b[0x100] = b[0x108] = b[0x110] = b[0x118] = 0xC3;       // RET at every code symbol
    return b;
}

static std::vector<uint8_t> buildElf32() {
    std::vector<uint8_t> b(0x400, 0);
    std::memcpy(b.data(), "\x7F" "ELF", 4);
    b[4] = 1; b[5] = 1; b[6] = 1;
    put16(b, 16, 2); put16(b, 18, 3); put32(b, 20, 1);
    put32(b, 24, 0x08048100); put32(b, 32, 0x200);
    put16(b, 40, 52); put16(b, 46, 40); put16(b, 48, 5); put16(b, 50, 4);

    Strings dyn;
    const uint32_t mallocName = dyn.add("malloc");
    const uint32_t fnName = dyn.add("elf32_fn");
    copyAt(b, 0xA0, dyn.bytes);
    Strings shstr;
    const uint32_t textName = shstr.add(".text");
    const uint32_t dynstrName = shstr.add(".dynstr");
    const uint32_t dynsymName = shstr.add(".dynsym");
    const uint32_t shstrName = shstr.add(".shstrtab");
    copyAt(b, 0x120, shstr.bytes);

    auto sh = [&](size_t i, uint32_t name, uint32_t type, uint32_t flags, uint32_t addr,
                  uint32_t off, uint32_t size, uint32_t link = 0, uint32_t entsize = 0) {
        const size_t p = 0x200 + i * 40;
        put32(b, p, name); put32(b, p + 4, type); put32(b, p + 8, flags);
        put32(b, p + 12, addr); put32(b, p + 16, off); put32(b, p + 20, size);
        put32(b, p + 24, link); put32(b, p + 36, entsize);
    };
    sh(1, textName,   1, 0x6, 0x08048100, 0x80, 0x10);
    sh(2, dynstrName, 3, 0,   0,          0xA0, static_cast<uint32_t>(dyn.bytes.size()));
    sh(3, dynsymName, 11,0,   0,          0xE0, 3 * 16, 2, 16);
    sh(4, shstrName,  3, 0,   0,          0x120,static_cast<uint32_t>(shstr.bytes.size()));

    auto sym = [&](size_t i, uint32_t name, uint32_t value, uint32_t size,
                   uint8_t bind, uint8_t type, uint16_t section) {
        const size_t p = 0xE0 + i * 16;
        put32(b, p, name); put32(b, p + 4, value); put32(b, p + 8, size);
        b[p + 12] = static_cast<uint8_t>((bind << 4) | type); put16(b, p + 14, section);
    };
    sym(1, mallocName, 0,          0, 1, 2, 0);
    sym(2, fnName,     0x08048100, 4, 1, 2, 1);
    b[0x80] = 0xC3;
    return b;
}

static constexpr size_t kRelShOff = 0x300;
static std::vector<uint8_t> buildRelocatableElf64() {
    std::vector<uint8_t> b(0x600, 0);
    std::memcpy(b.data(), "\x7F" "ELF", 4);
    b[4] = 2; b[5] = 1; b[6] = 1;
    put16(b, 16, 1); put16(b, 18, 0x3E); put32(b, 20, 1); // ET_REL, x86-64
    put64(b, 40, kRelShOff);
    put16(b, 52, 64); put16(b, 58, 64); put16(b, 60, 7); put16(b, 62, 6);

    Strings str;
    const uint32_t alphaName = str.add("alpha");
    const uint32_t betaName  = str.add("beta");
    const uint32_t bssName   = str.add("bss_value");
    const uint32_t externalName = str.add("external_only");
    copyAt(b, 0x140, str.bytes);
    Strings shstr;
    const uint32_t alphaSection = shstr.add(".text.alpha");
    const uint32_t betaSection  = shstr.add(".text.beta");
    const uint32_t bssSection   = shstr.add(".bss.shared");
    const uint32_t strSection   = shstr.add(".strtab");
    const uint32_t symSection   = shstr.add(".symtab");
    const uint32_t namesSection = shstr.add(".shstrtab");
    copyAt(b, 0x220, shstr.bytes);

    auto sh = [&](size_t index, uint32_t name, uint32_t type, uint64_t flags,
                  uint64_t offset, uint64_t size, uint64_t alignment,
                  uint32_t link = 0, uint32_t info = 0, uint64_t entrySize = 0) {
        const size_t p = kRelShOff + index * 64;
        put32(b, p, name); put32(b, p + 4, type); put64(b, p + 8, flags);
        put64(b, p + 16, 0); // realistic ET_REL: every sh_addr is zero
        put64(b, p + 24, offset); put64(b, p + 32, size);
        put32(b, p + 40, link); put32(b, p + 44, info);
        put64(b, p + 48, alignment); put64(b, p + 56, entrySize);
    };
    sh(1, alphaSection, 1, 0x6, 0x100, 8, 16);
    sh(2, betaSection,  1, 0x6, 0x108, 8, 32);
    sh(3, bssSection,   8, 0x3, 0,     16,64);
    sh(4, strSection,   3, 0,   0x140, str.bytes.size(), 1);
    sh(5, symSection,   2, 0,   0x180, 5 * 24, 8, 4, 1, 24);
    sh(6, namesSection, 3, 0,   0x220, shstr.bytes.size(), 1);

    auto sym = [&](size_t index, uint32_t name, uint8_t type, uint16_t section,
                   uint64_t value, uint64_t size) {
        const size_t p = 0x180 + index * 24;
        put32(b, p, name); b[p + 4] = static_cast<uint8_t>((1u << 4) | type);
        put16(b, p + 6, section); put64(b, p + 8, value); put64(b, p + 16, size);
    };
    sym(1, alphaName, 2, 1, 0, 1);
    sym(2, betaName,  2, 2, 0, 1); // same st_value, different owning section
    sym(3, bssName,   1, 3, 0, 4);
    sym(4, externalName, 2, 0, 0, 0); // undefined external exists only in SYMTAB
    b[0x100] = 0xC3; b[0x101] = 0xA1;
    b[0x108] = 0xC3; b[0x109] = 0xB2;
    return b;
}

static bool loadBytes(BinaryFile& bin, const std::vector<uint8_t>& bytes, const char* path) {
    { std::ofstream out(path, std::ios::binary); out.write(reinterpret_cast<const char*>(bytes.data()),
                                                           static_cast<std::streamsize>(bytes.size())); }
    const bool ok = bin.load(path);
    std::remove(path);
    return ok;
}

static const BinaryFile::Export* symbol(const BinaryFile& bin, const char* name) {
    for (const auto& value : bin.exports()) if (value.name == name) return &value;
    return nullptr;
}
static const BinaryFile::Import* imported(const BinaryFile& bin, const char* name) {
    for (const auto& value : bin.imports()) if (value.name == name) return &value;
    return nullptr;
}
static const Section* sectionNamed(const BinaryFile& bin, const char* name) {
    for (const auto& section : bin.sections()) if (section.name == name) return &section;
    return nullptr;
}

struct RetDisassembler final : IDisassembler {
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "ELF-test"; }
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va, Instruction& out) override {
        if (!data || !size) return false;
        out = Instruction{}; out.address = va; out.length = 1;
        out.mnemonic = data[0] == 0xC3 ? "ret" : "nop";
        out.isRet = data[0] == 0xC3; out.isBranch = out.isRet;
        return true;
    }
    std::vector<Instruction> disassemble(const uint8_t* data, size_t size, uint64_t va,
                                         size_t maxInstructions) override {
        std::vector<Instruction> out;
        const size_t count = std::min(size, maxInstructions ? maxInstructions : size);
        for (size_t i = 0; i < count; ++i) {
            Instruction instruction;
            if (!decodeOne(data + i, size - i, va + i, instruction)) break;
            out.push_back(instruction);
            if (instruction.isRet) break;
        }
        return out;
    }
};

static const DiscoveredFunction* functionAt(const std::vector<DiscoveredFunction>& functions, uint64_t va) {
    for (const auto& function : functions) if (function.address == va) return &function;
    return nullptr;
}

int main() {
    // A supported machine still must agree with EI_CLASS. Granting x86 decoder
    // authority to an ELF64 header would be a structured-format contradiction.
    {
        auto bytes = buildElf64();
        put16(bytes, 18, 0x03); // EM_386 in an ELF64 container
        const char* path = "elf_symbols_bad_machine_class.bin";
        { std::ofstream f(path, std::ios::binary); f.write(
            reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size())); }
        BinaryFile rejected;
        CHECK(!rejected.load(path));
        CHECK(rejected.loadError() == BinaryLoadError::MalformedELF);
        CHECK(!rejected.loaded() && rejected.machine() == MachineArch::Unknown);
        std::remove(path);
    }
    {
        BinaryFile bin;
        CHECK(loadBytes(bin, buildElf64(), "elf_symbols_64.bin"));
        CHECK(bin.format() == BinFormat::ELF && bin.is64Bit() && bin.machine() == MachineArch::X64);
        CHECK(bin.exports().size() == 10); // dyn/sym duplicate merged; aliases retained
        CHECK(bin.imports().size() == 1);

        const auto* puts = imported(bin, "puts");
        CHECK(puts && !puts->addressKnown && puts->dynamicSymbol && puts->dll == "(dynamic)");
        CHECK(puts && puts->kind == BinaryFile::SymbolKind::Function);

        const auto* api = symbol(bin, "api_alias");
        const auto* alias = symbol(bin, "api_alias2");
        const auto* helper = symbol(bin, "helper");
        const auto* data = symbol(bin, "global_data");
        const auto* tls = symbol(bin, "tls_value");
        const auto* hidden = symbol(bin, "hidden_api");
        const auto* localData = symbol(bin, "local_data");
        const auto* bss = symbol(bin, "bss_global");
        const auto* textObject = symbol(bin, "text_object");
        CHECK(api && api->dynamicSymbol && api->va == 0x400100 && api->size == 8 && api->isCode);
        CHECK(alias && !alias->dynamicSymbol && alias->va == api->va); // true alias survives
        CHECK(helper && helper->binding == BinaryFile::SymbolBinding::Local && helper->isCode);
        CHECK(data && data->kind == BinaryFile::SymbolKind::Object && !data->isCode && data->mapped);
        CHECK(tls && tls->kind == BinaryFile::SymbolKind::ThreadLocal);
        CHECK(hidden && hidden->visibility == BinaryFile::SymbolVisibility::Hidden);
        CHECK(localData && localData->binding == BinaryFile::SymbolBinding::Local);
        CHECK(bss && bss->kind == BinaryFile::SymbolKind::Object && !bss->mapped);
        CHECK(textObject && textObject->mapped && !textObject->isCode &&
              textObject->kind == BinaryFile::SymbolKind::Object);
        CHECK(!symbol(bin, "source.c"));

        size_t aliases = 0;
        for (const auto& value : bin.exports()) if (value.va == 0x400100) ++aliases;
        CHECK(aliases == 2);

        RetDisassembler dis;
        FunctionAnalyzer analyzer;
        const auto functions = analyzer.analyze(bin, dis, Arch::X64);
        const auto* apiFn = functionAt(functions, 0x400100);
        const auto* helperFn = functionAt(functions, 0x400108);
        const auto* labelFn = functionAt(functions, 0x400110);
        const auto* hiddenFn = functionAt(functions, 0x400118);
        CHECK(apiFn && apiFn->name == "api_alias" && apiFn->size == 8 && apiFn->isExport);
        CHECK(helperFn && helperFn->name == "helper" && helperFn->size == 8 && helperFn->isExport);
        CHECK(labelFn && labelFn->name == "code_label");
        CHECK(hiddenFn && hiddenFn->name == "hidden_api" && hiddenFn->size == 4);
        CHECK(!functionAt(functions, 0x401000)); // data symbols are never function roots
        CHECK(!functionAt(functions, 0x40011C)); // STT_OBJECT in executable storage is still data
    }

    {
        BinaryFile bin;
        CHECK(loadBytes(bin, buildElf32(), "elf_symbols_32.bin"));
        CHECK(bin.format() == BinFormat::ELF && !bin.is64Bit() && bin.machine() == MachineArch::X86);
        const auto* fn = symbol(bin, "elf32_fn");
        CHECK(fn && fn->va == 0x08048100 && fn->rva == 0x08048100 && fn->size == 4 && fn->isCode);
        const auto* mallocImport = imported(bin, "malloc");
        CHECK(mallocImport && !mallocImport->addressKnown);
    }

    // A valid ELF container with an unsupported e_machine must not retain the
    // caller's default x86/x64 decoder authority.
    {
        auto bytes = buildElf32();
        put16(bytes, 18, 0x02); // EM_SPARC: unsupported by this build
        BinaryFile bin;
        CHECK(!loadBytes(bin, bytes, "elf_symbols_unsupported_machine.bin"));
        CHECK(!bin.loaded() && bin.format() == BinFormat::Unknown &&
              bin.machine() == MachineArch::Unknown);
        CHECK(bin.loadError() == BinaryLoadError::UnsupportedMachine &&
              !bin.loadErrorText().empty());
    }

    // ARM ELF uses bit zero of e_entry/STT_FUNC values as the historical
    // Thumb-state marker. The loader selects Thumb and publishes a canonical
    // even entry, while preserving the raw symbol metadata. Fixed Thumb analysis
    // must retain the linker's exact size under the canonical function key.
    {
        auto bytes = buildElf32();
        put16(bytes, 18, 0x28);                       // EM_ARM
        put32(bytes, 24, 0x08048101);                 // Thumb entry marker
        put32(bytes, 0xE0 + 2 * 16 + 4, 0x08048101); // elf32_fn st_value
        BinaryFile bin;
        CHECK(loadBytes(bin, bytes, "elf_symbols_thumb.bin"));
        CHECK(bin.format() == BinFormat::ELF && bin.machine() == MachineArch::THUMB);
        CHECK(bin.hasEntryPoint() && bin.entryPointVA() == 0x08048100);
        const auto* rawFn = symbol(bin, "elf32_fn");
        CHECK(rawFn && rawFn->va == 0x08048101 && rawFn->size == 4 && rawFn->isCode);

        RetDisassembler dis;
        FunctionAnalyzer analyzer;
        const auto functions = analyzer.analyze(bin, dis, Arch::THUMB);
        const auto* thumbFn = functionAt(functions, 0x08048100);
        CHECK(thumbFn && thumbFn->name == "elf32_fn" && thumbFn->size == 4 && thumbFn->isExport);
        CHECK(!functionAt(functions, 0x08048101));
    }

    // Real ET_REL objects give each allocated section address zero and use
    // section-relative st_value. The loader must synthesize disjoint aligned
    // analysis ranges so equal symbol values still map to different bytes/functions.
    {
        BinaryFile bin;
        CHECK(loadBytes(bin, buildRelocatableElf64(), "elf_symbols_rel_real.bin"));
        CHECK(bin.format() == BinFormat::ELF && !bin.hasEntryPoint());
        const Section* alphaSection = sectionNamed(bin, ".text.alpha");
        const Section* betaSection  = sectionNamed(bin, ".text.beta");
        const Section* bssSection   = sectionNamed(bin, ".bss.shared");
        const auto* external = imported(bin, "external_only");
        CHECK(alphaSection && betaSection && bssSection);
        CHECK(external && !external->dynamicSymbol && !external->addressKnown &&
              external->dll == "(undefined)" && external->kind == BinaryFile::SymbolKind::Function);
        if (alphaSection && betaSection && bssSection) {
            CHECK(alphaSection->virtualAddress != betaSection->virtualAddress);
            CHECK((alphaSection->virtualAddress & 15u) == 0);
            CHECK((betaSection->virtualAddress & 31u) == 0);
            CHECK((bssSection->virtualAddress & 63u) == 0 && bssSection->rawSize == 0);
            size_t alphaAvail = 0, betaAvail = 0, bssAvail = 99;
            const uint8_t* alphaBytes = bin.ptrFromVA(alphaSection->virtualAddress, alphaAvail);
            const uint8_t* betaBytes = bin.ptrFromVA(betaSection->virtualAddress, betaAvail);
            CHECK(alphaBytes && alphaAvail >= 2 && alphaBytes[0] == 0xC3 && alphaBytes[1] == 0xA1);
            CHECK(betaBytes && betaAvail >= 2 && betaBytes[0] == 0xC3 && betaBytes[1] == 0xB2);
            CHECK(!bin.ptrFromVA(bssSection->virtualAddress, bssAvail) && bssAvail == 0);

            const auto* alpha = symbol(bin, "alpha");
            const auto* beta  = symbol(bin, "beta");
            const auto* bss   = symbol(bin, "bss_value");
            CHECK(alpha && alpha->va == alphaSection->virtualAddress && alpha->mapped);
            CHECK(beta && beta->va == betaSection->virtualAddress && beta->mapped);
            CHECK(bss && bss->va == bssSection->virtualAddress && !bss->mapped);

            RetDisassembler dis;
            FunctionAnalyzer analyzer;
            const auto functions = analyzer.analyze(bin, dis, Arch::X64);
            const auto* alphaFn = alpha ? functionAt(functions, alpha->va) : nullptr;
            const auto* betaFn = beta ? functionAt(functions, beta->va) : nullptr;
            CHECK(alphaFn && alphaFn->name == "alpha" && alphaFn->size == 1);
            CHECK(betaFn && betaFn->name == "beta" && betaFn->size == 1);
        }
    }

    // An allocated section whose synthetic range would overflow is skipped;
    // later valid sections still receive non-overlapping analysis ranges.
    {
        auto bytes = buildRelocatableElf64();
        put64(bytes, kRelShOff + 1 * 64 + 32, UINT64_MAX);
        BinaryFile bin;
        CHECK(loadBytes(bin, bytes, "elf_symbols_rel_overflow.bin"));
        CHECK(bin.format() == BinFormat::ELF);
        CHECK(!sectionNamed(bin, ".text.alpha") && !symbol(bin, "alpha"));
        CHECK(sectionNamed(bin, ".text.beta") && symbol(bin, "beta"));
    }

    // Invalid sh_link and out-of-file symbol data are ignored without losing the
    // otherwise valid ELF/section model. The independent symtab still parses.
    {
        auto bytes = buildElf64();
        put32(bytes, kElf64ShOff + kElf64DynSymSection * 64 + 40, 999);
        BinaryFile bin;
        CHECK(loadBytes(bin, bytes, "elf_symbols_bad_link.bin"));
        CHECK(bin.format() == BinFormat::ELF);
        CHECK(imported(bin, "puts") && imported(bin, "puts")->dll == "(undefined)" &&
              !imported(bin, "puts")->dynamicSymbol);
        const auto* api = symbol(bin, "api_alias");
        CHECK(api && !api->dynamicSymbol);
    }
    {
        auto bytes = buildElf64();
        put64(bytes, kElf64ShOff + kElf64DynSymSection * 64 + 24, UINT64_MAX - 15);
        BinaryFile bin;
        CHECK(loadBytes(bin, bytes, "elf_symbols_bad_offset.bin"));
        CHECK(bin.format() == BinFormat::ELF);
        CHECK(imported(bin, "puts") && imported(bin, "puts")->dll == "(undefined)");
        CHECK(symbol(bin, "helper"));
    }
    {
        auto bytes = buildElf64();
        put64(bytes, kElf64ShOff + 1 * 64 + 24, UINT64_MAX - 3); // executable section raw offset
        BinaryFile bin;
        CHECK(!loadBytes(bin, bytes, "elf_symbols_wrapping_raw_offset.bin"));
        size_t avail = 123;
        CHECK(!bin.ptrFromVA(0x400108, avail) && avail == 0);
        CHECK(!bin.loaded() && !symbol(bin, "helper"));
    }

    // Too-small entry sizes disable only the malformed table. A truncated
    // section-header array is rejected wholesale rather than partially parsed.
    {
        auto bytes = buildElf64();
        put64(bytes, kElf64ShOff + kElf64DynSymSection * 64 + 56, 8);
        BinaryFile bin;
        CHECK(loadBytes(bin, bytes, "elf_symbols_bad_entsize.bin"));
        CHECK(bin.format() == BinFormat::ELF);
        CHECK(imported(bin, "puts") && imported(bin, "puts")->dll == "(undefined)");
        CHECK(symbol(bin, "helper"));
    }
    {
        auto bytes = buildElf64();
        put64(bytes, 24, 0);
        bytes.resize(kElf64ShOff + 5 * 64 + 7); // declared table has ten headers
        BinaryFile bin;
        CHECK(!loadBytes(bin, bytes, "elf_symbols_truncated_sht.bin"));
        CHECK(!bin.loaded() && bin.exports().empty() && bin.imports().empty());
    }

    // A truncated SHT_SYMTAB_SHNDX companion invalidates only the XINDEX row.
    {
        auto bytes = buildElf64();
        put64(bytes, kElf64ShOff + 8 * 64 + 32, 3 * 4); // helper is symbol index 3
        BinaryFile bin;
        CHECK(loadBytes(bin, bytes, "elf_symbols_bad_xindex.bin"));
        CHECK(bin.format() == BinFormat::ELF && !symbol(bin, "helper"));
        CHECK(symbol(bin, "api_alias2"));
    }

    // ET_REL symbol values are section-relative, unlike ET_EXEC/ET_DYN values.
    {
        auto bytes = buildElf64();
        put16(bytes, 16, 1); // ET_REL
        put64(bytes, 24, 0); // no entry
        auto setValue = [&](size_t table, size_t index, uint64_t value) {
            put64(bytes, table + index * 24 + 8, value);
        };
        setValue(0x280, 2, 0);    setValue(0x280, 3, 0);
        setValue(0x280, 4, 8);    setValue(0x280, 5, 0x18);
        setValue(0x400, 1, 0);    setValue(0x400, 2, 0);
        setValue(0x400, 3, 8);    setValue(0x400, 4, 4);
        setValue(0x400, 5, 0x10); setValue(0x400, 6, 0);
        setValue(0x400, 8, 0x1C);
        BinaryFile bin;
        CHECK(loadBytes(bin, bytes, "elf_symbols_rel.bin"));
        CHECK(bin.format() == BinFormat::ELF);
        const Section* text = sectionNamed(bin, ".text");
        const Section* data = sectionNamed(bin, ".data");
        const Section* bss = sectionNamed(bin, ".bss");
        CHECK(text && data && bss);
        CHECK(text && symbol(bin, "api_alias") && symbol(bin, "api_alias")->va == text->virtualAddress);
        CHECK(text && symbol(bin, "helper") && symbol(bin, "helper")->va == text->virtualAddress + 8);
        CHECK(data && symbol(bin, "global_data") && symbol(bin, "global_data")->va == data->virtualAddress);
        CHECK(bss && symbol(bin, "bss_global") && symbol(bin, "bss_global")->va == bss->virtualAddress);
    }

    // Unsupported/corrupted structured headers must never be silently decoded
    // as Raw; analysts can still choose Open as Raw explicitly.
    {
        auto bytes = buildElf64(); bytes[5] = 2;
        BinaryFile bin;
        CHECK(!loadBytes(bin, bytes, "elf_symbols_big_endian.bin"));
        CHECK(!bin.loaded() && bin.exports().empty() && bin.imports().empty());
    }
    {
        auto bytes = buildElf64(); bytes[4] = 3;
        BinaryFile bin;
        CHECK(!loadBytes(bin, bytes, "elf_symbols_bad_class.bin"));
        CHECK(!bin.loaded() && bin.exports().empty() && bin.imports().empty());
    }

    if (!g_fail) std::puts("ALL ELF SYMBOL TESTS PASSED");
    return g_fail ? 1 : 0;
}
