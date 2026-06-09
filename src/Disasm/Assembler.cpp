#include "Assembler.h"
#include <keystone/keystone.h>

namespace ds {

AsmResult Assemble(Arch arch, const std::string& text, uint64_t address) {
    AsmResult res;

    ks_arch karch; ks_mode kmode;
    switch (arch) {
        case Arch::X86:   karch = KS_ARCH_X86;   kmode = KS_MODE_32;            break;
        case Arch::X64:   karch = KS_ARCH_X86;   kmode = KS_MODE_64;            break;
        case Arch::ARM:   karch = KS_ARCH_ARM;   kmode = KS_MODE_ARM;           break;
        case Arch::ARM64: karch = KS_ARCH_ARM64; kmode = KS_MODE_LITTLE_ENDIAN; break;
        default:
            // Disassembly/analysis support more arches (via Capstone) than the
            // patch assembler does; fail clearly instead of mis-encoding as x64.
            res.error = "patch assembler supports x86 / x64 / ARM / ARM64 only";
            return res;
    }

    ks_engine* ks = nullptr;
    if (ks_open(karch, kmode, &ks) != KS_ERR_OK || !ks) {
        res.error = "failed to initialize the assembler engine";
        return res;
    }

    unsigned char* enc = nullptr;
    size_t encSize = 0, stmtCount = 0;
    if (ks_asm(ks, text.c_str(), address, &enc, &encSize, &stmtCount) != KS_ERR_OK) {
        res.error = ks_strerror(ks_errno(ks));
        if (enc) ks_free(enc);
        ks_close(ks);
        return res;
    }

    res.bytes.assign(enc, enc + encSize);
    res.count = stmtCount;
    res.ok    = true;

    ks_free(enc);
    ks_close(ks);
    return res;
}

} // namespace ds
