#pragma once
//
// IDisassembler.h
// Engine-agnostic disassembly interface. Both the Zydis and Capstone backends
// implement this so the UI never depends on a concrete engine.
//
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

// Architecture-neutral control-flow semantics.  The legacy isBranch/isCall/
// isRet fields below remain available while consumers migrate incrementally.
enum class FlowKind : uint8_t {
    None,
    DirectCall,
    IndirectCall,
    ConditionalBranch,
    UnconditionalBranch,
    IndirectBranch,
    Return,
    Switch,
    // JVM jsr/ret transfer control inside a method but do not call or return
    // from a method.  Keeping them distinct prevents function-call analysis
    // from inventing methods at subroutine bytecode labels.
    SubroutineCall,
    SubroutineReturn
};

struct FlowInfo {
    FlowKind kind = FlowKind::None;
    bool     directTargetValid = false;
    uint64_t directTarget = 0;  // may legitimately be VA 0
    uint8_t  delaySlots = 0;    // architectural instructions after the transfer
};

enum class OperandKind : uint8_t {
    Invalid,
    Register,
    Immediate,
    Memory,
    Pointer
};

enum class OperandAccess : uint8_t {
    None      = 0,
    Read      = 1,
    Write     = 2,
    ReadWrite = 3
};

inline bool OperandReads(OperandAccess access) {
    return (static_cast<uint8_t>(access) & static_cast<uint8_t>(OperandAccess::Read)) != 0;
}
inline bool OperandWrites(OperandAccess access) {
    return (static_cast<uint8_t>(access) & static_cast<uint8_t>(OperandAccess::Write)) != 0;
}

// Register names are lower-case decoder-independent spellings ("rax", "x0",
// "sp", ...).  A zero width means that the backend does not expose the width
// for that operand.  Immediate values preserve the decoder's numeric value;
// pcRelative identifies encoded relative immediates.  The resolved control-flow
// destination, when one exists, is always in FlowInfo::directTarget.
struct TypedOperand {
    OperandKind   kind = OperandKind::Invalid;
    OperandAccess access = OperandAccess::None;
    uint16_t      widthBits = 0;

    std::string registerName;

    uint64_t immediate = 0;
    bool     immediateSigned = false;

    std::string segmentRegister;
    std::string baseRegister;
    std::string indexRegister;
    int32_t     scale = 0;
    int64_t     displacement = 0;
    bool        displacementValid = false;
    bool        pcRelative = false;
};

// Common flag identities, deliberately independent of the layout of x86
// RFLAGS or any decoder-specific action mask.  Sign doubles as ARM's N flag.
enum class SemanticFlag : uint64_t {
    Carry       = 1ull << 0,
    Parity      = 1ull << 1,
    AuxCarry    = 1ull << 2,
    Zero        = 1ull << 3,
    Sign        = 1ull << 4,
    Trap        = 1ull << 5,
    Interrupt   = 1ull << 6,
    Direction   = 1ull << 7,
    Overflow    = 1ull << 8,
    NestedTask  = 1ull << 9,
    Resume      = 1ull << 10,
    Alignment   = 1ull << 11,
    Virtual8086 = 1ull << 12,
    VirtualInt  = 1ull << 13,
    VirtualPend = 1ull << 14,
    Id          = 1ull << 15,
    Condition   = 1ull << 16
};

inline constexpr uint64_t SemanticFlagBit(SemanticFlag flag) {
    return static_cast<uint64_t>(flag);
}

// Prefixes are semantic metadata rather than part of the base mnemonic.  This
// keeps mnemonic-based analysis stable while allowing renderers/exporters to
// reproduce the complete instruction text through InstructionText().
enum class InstructionPrefix : uint8_t {
    Lock,
    Rep,
    Repe,
    Repne,
    Bnd,
    XAcquire,
    XRelease,
    NoTrack
};

inline const char* InstructionPrefixName(InstructionPrefix prefix) {
    switch (prefix) {
        case InstructionPrefix::Lock:     return "lock";
        case InstructionPrefix::Rep:      return "rep";
        case InstructionPrefix::Repe:     return "repe";
        case InstructionPrefix::Repne:    return "repne";
        case InstructionPrefix::Bnd:      return "bnd";
        case InstructionPrefix::XAcquire: return "xacquire";
        case InstructionPrefix::XRelease: return "xrelease";
        case InstructionPrefix::NoTrack:  return "notrack";
    }
    return "";
}

struct SwitchCase {
    int64_t  value = 0;
    uint64_t target = 0;
    bool     targetValid = false;
};

struct SwitchInfo {
    uint64_t defaultTarget = 0;
    bool     defaultTargetValid = false;
    std::vector<SwitchCase> cases;
};

// Segment:offset is intentionally preserved even when the current flat image
// has no unambiguous alias for the real-mode linear address.
struct FarTarget {
    uint16_t segment = 0;
    uint32_t offset = 0;
    uint8_t  offsetBits = 0;
    bool     valid = false;
    uint64_t linearAddress = 0;
    bool     linearAddressValid = false;
};

// A single decoded instruction in a form the UI can render directly.
struct Instruction {
    uint64_t    address   = 0;     // virtual address of the instruction
    uint32_t    length    = 0;     // size in bytes
    std::string bytes;             // hex byte string, e.g. "48 89 5C 24 08"
    std::string mnemonic;          // e.g. "mov"
    std::string operands;          // e.g. "rbx, [rsp+0x8]"
    std::vector<InstructionPrefix> prefixes;
    bool        isBranch  = false; // jmp/jcc/call/ret family
    bool        isCall    = false;
    bool        isRet     = false; // ret/retf/iret family (returns from a call frame)
    bool        isRepString = false; // has a REP/REPE/REPNE prefix (rep movs/stos/cmps/scas/...)
    uint64_t    branchTarget = 0;  // resolved target value (may legitimately be VA 0)
    bool        branchTargetValid = false; // distinguishes target VA 0 from unresolved
    // Structured semantics supplied directly by the decoder.  Existing display
    // strings and legacy flow fields above are intentionally retained.
    FlowInfo    flow;
    std::vector<TypedOperand> typedOperands;
    std::vector<std::string>  registersRead;
    std::vector<std::string>  registersWritten;
    uint64_t    flagsRead = 0;    // SemanticFlag bit mask
    uint64_t    flagsWritten = 0; // SemanticFlag bit mask
    // Decoder-supplied inline annotation (rendered as a "; ..." comment). The
    // JVM backend fills it with resolved constant-pool text (method/field refs,
    // string literals); the x86/ARM backends leave it empty.
    std::string comment;
    // Additional statically-known control-flow targets beyond branchTarget:
    // tableswitch/lookupswitch case targets (JVM). branchTarget holds the
    // switch default. Empty for ordinary instructions; CFG links these as
    // switch-case successors.
    std::vector<uint64_t> extraTargets;
    SwitchInfo switchInfo;
    FarTarget  farTarget;
};

// Canonical display spelling shared by decoder consumers.  mnemonic remains
// the prefix-free base operation so semantic users never need to strip text.
inline std::string InstructionText(const Instruction& in) {
    std::string text;
    for (InstructionPrefix prefix : in.prefixes) {
        if (!text.empty()) text.push_back(' ');
        text += InstructionPrefixName(prefix);
    }
    if (!in.mnemonic.empty()) {
        if (!text.empty()) text.push_back(' ');
        text += in.mnemonic;
    }
    if (!in.operands.empty()) {
        if (!text.empty()) text.push_back(' ');
        text += in.operands;
    }
    return text;
}

// Semantic-first compatibility helpers. Older pure tests and small custom
// decoders populated only the legacy booleans / a non-zero branchTarget; the
// fallback keeps those users working while production consumers migrate away
// from mnemonic and formatted-operand parsing. A valid target may be VA 0.
inline bool TryGetDirectTarget(const Instruction& in, uint64_t& target) {
    if (in.flow.directTargetValid) {
        target = in.flow.directTarget;
        return true;
    }
    if (in.branchTargetValid || in.branchTarget != 0) {
        target = in.branchTarget;
        return true;
    }
    target = 0;
    return false;
}

inline bool HasBranchTarget(const Instruction& in) {
    uint64_t ignored = 0;
    return TryGetDirectTarget(in, ignored);
}

inline bool InstructionIsCall(const Instruction& in) {
    if (in.flow.kind != FlowKind::None)
        return in.flow.kind == FlowKind::DirectCall ||
               in.flow.kind == FlowKind::IndirectCall;
    return in.isCall;
}

inline bool InstructionIsReturn(const Instruction& in) {
    if (in.flow.kind != FlowKind::None) return in.flow.kind == FlowKind::Return;
    return in.isRet;
}

inline bool InstructionIsSubroutineCall(const Instruction& in) {
    return in.flow.kind == FlowKind::SubroutineCall;
}

inline bool InstructionIsSubroutineReturn(const Instruction& in) {
    return in.flow.kind == FlowKind::SubroutineReturn;
}

inline bool InstructionEndsBlock(const Instruction& in) {
    switch (in.flow.kind) {
        case FlowKind::ConditionalBranch:
        case FlowKind::UnconditionalBranch:
        case FlowKind::IndirectBranch:
        case FlowKind::Return:
        case FlowKind::Switch:
        case FlowKind::SubroutineCall:
        case FlowKind::SubroutineReturn:
            return true;
        case FlowKind::DirectCall:
        case FlowKind::IndirectCall:
            return false;
        case FlowKind::None:
            return in.isBranch && !in.isCall;
    }
    return false;
}

inline bool InstructionIsUnconditionalBranch(const Instruction& in) {
    return in.flow.kind == FlowKind::UnconditionalBranch ||
           in.flow.kind == FlowKind::IndirectBranch ||
           in.flow.kind == FlowKind::Switch;
}

inline bool InstructionHasMemoryOperand(const Instruction& in) {
    for (const TypedOperand& operand : in.typedOperands)
        if (operand.kind == OperandKind::Memory) return true;
    return false;
}

enum class Arch  { X86_16, X86, X64, ARM, THUMB, ARM64, MIPS, MIPS64, PPC, PPC64, RISCV32, RISCV64, JVM, GML };
enum class Engine { Zydis, Capstone };

enum class ByteOrder : uint8_t { Little, Big };

struct DecoderFeatures {
    // RISC-V compressed instructions are part of the common executable ABI;
    // callers can turn them off for an explicitly base-ISA-only stream.
    bool riscvCompressed = true;
    bool armV8 = false;
    bool armMClass = false;
    bool mipsMicro = false;

    bool operator==(const DecoderFeatures&) const = default;
};

// Stable persisted/cache identity for DecoderFeatures.  Keep these bit
// assignments append-only: Raw project sidecars store the mask so a file can be
// reopened under the exact ISA mode selected by the analyst.
inline constexpr uint32_t kDecoderFeatureRiscvCompressed = 1u << 0;
inline constexpr uint32_t kDecoderFeatureArmV8           = 1u << 1;
inline constexpr uint32_t kDecoderFeatureArmMClass       = 1u << 2;
inline constexpr uint32_t kDecoderFeatureMipsMicro       = 1u << 3;
inline constexpr uint32_t kKnownDecoderFeatureBits =
    kDecoderFeatureRiscvCompressed | kDecoderFeatureArmV8 |
    kDecoderFeatureArmMClass | kDecoderFeatureMipsMicro;

inline constexpr uint32_t DecoderFeatureBits(const DecoderFeatures& features) {
    return (features.riscvCompressed ? kDecoderFeatureRiscvCompressed : 0u) |
           (features.armV8           ? kDecoderFeatureArmV8 : 0u) |
           (features.armMClass       ? kDecoderFeatureArmMClass : 0u) |
           (features.mipsMicro       ? kDecoderFeatureMipsMicro : 0u);
}

inline constexpr bool DecoderFeatureBitsValid(uint32_t bits) {
    return (bits & ~kKnownDecoderFeatureBits) == 0;
}

// Decode only a fully-known mask.  Failure deliberately leaves `features`
// untouched so callers cannot partially apply a malformed persisted setting.
inline constexpr bool DecoderFeaturesFromBits(uint32_t bits,
                                              DecoderFeatures& features) {
    if (!DecoderFeatureBitsValid(bits)) return false;
    DecoderFeatures decoded;
    decoded.riscvCompressed = (bits & kDecoderFeatureRiscvCompressed) != 0;
    decoded.armV8           = (bits & kDecoderFeatureArmV8) != 0;
    decoded.armMClass       = (bits & kDecoderFeatureArmMClass) != 0;
    decoded.mipsMicro       = (bits & kDecoderFeatureMipsMicro) != 0;
    features = decoded;
    return true;
}

struct DecoderConfig {
    Engine          engine = Engine::Zydis;
    Arch            arch = Arch::X64;
    ByteOrder       byteOrder = ByteOrder::Little;
    DecoderFeatures features;

    bool operator==(const DecoderConfig&) const = default;
};

// Engine/architecture-only factories can represent exactly the historical
// little-endian/default-feature configuration.  Compatibility adapters must
// reject every richer request instead of silently constructing a decoder for a
// different byte order or ISA feature set.
inline constexpr bool LegacyDecoderFactoryCanRepresent(
    const DecoderConfig& config) {
    return config.byteOrder == ByteOrder::Little &&
           config.features == DecoderFeatures{};
}

// True for the architectures Zydis can decode (the x86 family); everything else
// must be routed to Capstone. X86_16 means 8086-compatible real mode, not 16-bit
// protected/compatibility mode.
inline bool ArchIsX86(Arch a) {
    return a == Arch::X86_16 || a == Arch::X86 || a == Arch::X64;
}
// True only for the flat 32/64-bit x86 modes. Use this for analysis or runtime
// features whose register/ABI/address assumptions do not cover 16-bit real mode.
inline bool ArchIsX86_32Or64(Arch a) {
    return a == Arch::X86 || a == Arch::X64;
}
// ARM instruction-set modes share analysis conventions but are deliberately
// distinct decoder modes: a raw Thumb image must never be decoded as A32.
inline bool ArchIsArm(Arch a) {
    return a == Arch::ARM || a == Arch::THUMB || a == Arch::ARM64;
}
// Capability gates used by the shell and Binary View. The current decompiler
// and Win32 debugger model x86 registers/ABIs only. Keystone supports A32,
// Thumb/Thumb-2 and AArch64 in addition to flat x86/x64.
// Every decoder can produce conservative raw pseudocode statements. Deep data
// flow and ABI recovery remain exactly gated to x86/x64 by DecompileTarget.
inline bool ArchSupportsDecompiler(Arch arch) { return arch != Arch::GML; }
inline bool ArchSupportsDebugger(Arch a)   { return ArchIsX86_32Or64(a); }
inline bool ArchSupportsAssembler(Arch a) {
    return a == Arch::X86 || a == Arch::X64 || a == Arch::ARM ||
           a == Arch::THUMB || a == Arch::ARM64;
}
inline Engine EffectiveDisasmEngine(Engine requested, Arch arch) {
    // Factory routing ignores the requested x86 backend for every non-x86 ISA
    // (and JVM has its own decoder). Treat those as one effective engine so a
    // cosmetic Zydis/Capstone toggle does not invalidate identical analysis.
    return ArchIsX86(arch) ? requested : Engine::Capstone;
}
inline uint64_t AnalysisIsaSignature(const DecoderConfig& config) {
    // Retain the historical engine/architecture bit positions and extend the
    // identity with byte order plus every explicit decoder feature.  Cache
    // keys must not alias streams decoded under different ISA modes.
    return (static_cast<uint64_t>(config.arch) << 8) |
           static_cast<uint64_t>(EffectiveDisasmEngine(config.engine, config.arch)) |
           (static_cast<uint64_t>(config.byteOrder) << 16) |
           (static_cast<uint64_t>(DecoderFeatureBits(config.features)) << 17);
}
inline uint64_t AnalysisIsaSignature(Arch arch, Engine requested) {
    DecoderConfig config;
    config.arch = arch;
    config.engine = requested;
    return AnalysisIsaSignature(config);
}
// Central instruction alignment/resynchronization contract. Feature-controlled
// variable-width modes must participate: base RISC-V is word aligned, RVC and
// microMIPS are halfword aligned. A byte-wise fallback would permanently shift
// every later decode on these ISAs.
inline uint32_t ArchInstructionAlignment(const DecoderConfig& config) {
    const Arch a = config.arch;
    if (a == Arch::ARM || a == Arch::ARM64 || a == Arch::PPC || a == Arch::PPC64 || a == Arch::GML)
        return 4;
    if (a == Arch::MIPS || a == Arch::MIPS64)
        return config.features.mipsMicro ? 2 : 4;
    if (a == Arch::RISCV32 || a == Arch::RISCV64)
        return config.features.riscvCompressed ? 2 : 4;
    if (a == Arch::THUMB) return 2;
    return 1;
}
inline uint32_t ArchInstructionAlignment(Arch arch) {
    DecoderConfig config;
    config.arch = arch;
    return ArchInstructionAlignment(config);
}
inline uint32_t ArchInvalidDecodeWidth(const DecoderConfig& config) {
    return ArchInstructionAlignment(config);
}
inline uint32_t ArchInvalidDecodeWidth(Arch arch) {
    return ArchInstructionAlignment(arch);
}

// Validate a flat mapping against the ISA's address space as well as uint64_t
// arithmetic. A32/Thumb branch immediates and architectural PCs are 32-bit, so
// allowing their raw image above 4 GiB would manufacture unmapped targets.
inline bool ArchMappingRangeFits(Arch a, uint64_t base, uint64_t size) {
    if (!size || size - 1 > (std::numeric_limits<uint64_t>::max)() - base) return false;
    if (a == Arch::X86 || a == Arch::ARM || a == Arch::THUMB ||
        a == Arch::MIPS || a == Arch::PPC || a == Arch::RISCV32) {
        constexpr uint64_t max32 = (std::numeric_limits<uint32_t>::max)();
        return base <= max32 && size - 1 <= max32 - base;
    }
    return true;
}
// Short display name for an architecture.
inline const char* ArchName(Arch a) {
    switch (a) {
        case Arch::X86_16:  return "x86-16";
        case Arch::X86:     return "x86";
        case Arch::X64:     return "x64";
        case Arch::ARM:     return "ARM";
        case Arch::THUMB:   return "Thumb/Thumb-2";
        case Arch::ARM64:   return "ARM64";
        case Arch::MIPS:    return "MIPS";
        case Arch::MIPS64:  return "MIPS64";
        case Arch::PPC:     return "PPC";
        case Arch::PPC64:   return "PPC64";
        case Arch::RISCV32: return "RISC-V 32";
        case Arch::RISCV64: return "RISC-V 64";
        case Arch::JVM:     return "JVM";
        case Arch::GML:     return "GML";
    }
    return "?";
}

// Inverse of ArchName: parse a saved arch string back to the enum (for per-project
// persistence). Returns false for an unrecognized / empty name.
inline bool ArchFromName(const char* s, Arch& out) {
    if (!s) return false;
    const std::string n(s);
    if      (n == "x86-16")    out = Arch::X86_16;
    else if (n == "x86")       out = Arch::X86;
    else if (n == "x64")       out = Arch::X64;
    else if (n == "ARM")       out = Arch::ARM;
    else if (n == "Thumb/Thumb-2" || n == "Thumb" || n == "Thumb-2") out = Arch::THUMB;
    else if (n == "ARM64")     out = Arch::ARM64;
    else if (n == "MIPS")      out = Arch::MIPS;
    else if (n == "MIPS64")    out = Arch::MIPS64;
    else if (n == "PPC")       out = Arch::PPC;
    else if (n == "PPC64")     out = Arch::PPC64;
    else if (n == "RISC-V 32") out = Arch::RISCV32;
    else if (n == "RISC-V 64") out = Arch::RISCV64;
    else if (n == "JVM")       out = Arch::JVM;
    else if (n == "GML")       out = Arch::GML;
    else return false;
    return true;
}

// Name <-> enum for the disassembly engine (for per-project persistence).
inline const char* EngineNameOf(Engine e) { return e == Engine::Zydis ? "Zydis" : "Capstone"; }
inline bool EngineFromName(const char* s, Engine& out) {
    if (!s) return false;
    const std::string n(s);
    if (n == "Zydis")    { out = Engine::Zydis;    return true; }
    if (n == "Capstone") { out = Engine::Capstone; return true; }
    return false;
}

// Pure interface. Implementations live in ZydisDisassembler / CapstoneDisassembler.
class IDisassembler {
public:
    virtual ~IDisassembler() = default;

    virtual Engine engine() const = 0;
    virtual const char* engineName() const = 0;

    // Construction can fail (unsupported mode/endianness, unavailable engine)
    // without producing a half-working object.  decode APIs return no results
    // while !ready(); errorMessage() is stable for the object's lifetime.
    virtual bool ready() const { return true; }
    virtual std::string_view errorMessage() const { return {}; }

    // Number of bytes a streaming caller should consume when decodeOne fails.
    // Variable-width backends default to one; fixed ARM modes override this so
    // one malformed word/halfword cannot desynchronize the remainder.
    virtual uint32_t invalidDecodeWidth() const { return 1; }

    // Natural alignment for validated code targets. Decoder implementations
    // override this when feature bits change the base architecture's width.
    virtual uint32_t instructionAlignment() const { return invalidDecodeWidth(); }

    // Decode a buffer starting at the given virtual address. Stops after
    // `maxInstructions` or when the buffer is exhausted.
    virtual std::vector<Instruction> disassemble(const uint8_t* data,
                                                 size_t          size,
                                                 uint64_t        virtualAddress,
                                                 size_t          maxInstructions = 0) = 0;

    // Decode exactly one instruction; returns false on a decode error.
    virtual bool decodeOne(const uint8_t* data, size_t size,
                           uint64_t virtualAddress, Instruction& out) = 0;
};

} // namespace ds
// (engine-agnostic disassembly interface)
