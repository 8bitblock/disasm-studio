#include "Assembler.h"
#include <keystone/keystone.h>
#include <memory>

namespace ds {

AsmResult Assemble(const DecoderConfig& config, const std::string& text, uint64_t address) {
    AsmResult res;
    if (!PatchAssemblerAvailable(config, &res.error)) return res;
    if (text.empty() || text.find('\0') != std::string::npos) {
        res.error = "assembly must be nonempty text without embedded NUL bytes";
        return res;
    }

    ks_arch karch; ks_mode kmode;
    switch (config.arch) {
        case Arch::X86:   karch = KS_ARCH_X86;   kmode = KS_MODE_32;            break;
        case Arch::X64:   karch = KS_ARCH_X86;   kmode = KS_MODE_64;            break;
        case Arch::ARM:   karch = KS_ARCH_ARM;   kmode = KS_MODE_ARM;           break;
        case Arch::THUMB: karch = KS_ARCH_ARM;   kmode = KS_MODE_THUMB;         break;
        case Arch::ARM64: karch = KS_ARCH_ARM64; kmode = KS_MODE_LITTLE_ENDIAN; break;
        default:
            // Disassembly/analysis support more arches (via Capstone) than the
            // patch assembler does; fail clearly instead of mis-encoding as x64.
            res.error = "patch assembler supports x86 / x64 / ARM / Thumb / ARM64 only";
            return res;
    }
    if (config.byteOrder == ByteOrder::Big)
        kmode = static_cast<ks_mode>(kmode | KS_MODE_BIG_ENDIAN);
    if (config.features.armV8 && (config.arch == Arch::ARM || config.arch == Arch::THUMB))
        kmode = static_cast<ks_mode>(kmode | KS_MODE_V8);

    ks_engine* ks = nullptr;
    const ks_err opened = ks_open(karch, kmode, &ks);
    if (opened != KS_ERR_OK || !ks) {
        res.error = std::string("failed to initialize the requested assembler configuration: ") + ks_strerror(opened);
        return res;
    }
    const std::unique_ptr<ks_engine, decltype(&ks_close)> engine(ks, &ks_close);

    unsigned char* enc = nullptr;
    size_t encSize = 0, stmtCount = 0;
    const int assembled = ks_asm(ks, text.c_str(), address, &enc, &encSize, &stmtCount);
    const std::unique_ptr<unsigned char, decltype(&ks_free)> encoding(enc, &ks_free);
    if (assembled != 0) {
        res.error = ks_strerror(ks_errno(ks));
        return res;
    }
    if (!enc || encSize == 0 || stmtCount == 0) {
        res.error = "assembly produced no instruction bytes";
        return res;
    }
    try { res.bytes.assign(enc, enc + encSize); }
    catch (const std::bad_alloc&) {
        res.error = "not enough memory to retain assembled bytes";
        return res;
    } catch (const std::length_error&) {
        res.error = "assembled bytes exceed the container limit";
        return res;
    }
    res.count = stmtCount;
    res.ok    = true;

    return res;
}

} // namespace ds
