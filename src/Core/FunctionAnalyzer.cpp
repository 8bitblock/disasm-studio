#include "FunctionAnalyzer.h"
#include "AddressSpan.h"
#include "BinaryFile.h"
#include "Demangle.h"
#include "JvmClass.h"
#include "GameMakerArchive.h"
#include "ApiDatabase.h"
#include "CFG.h"
#include "../Disasm/IDisassembler.h"
#include "InstructionReference.h"   // TryGetInstrDataRef(): memory operand, including valid VA 0

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace ds {

// Seed local code exports from BinaryFile's complete, bounds-checked EAT model.
// Prefer a real alias as the function label; an ordinal-only export still gets
// an authoritative #ordinal label and must not be replaced by a heuristic guess.
void FunctionAnalyzer::collectExports(const BinaryFile& bin,
                                      std::vector<uint64_t>& seeds,
                                      std::vector<std::pair<uint64_t,std::string>>& named) {
    struct Label { std::string name; int rank = 0; };
    std::map<uint64_t, Label> labels;
    for (const BinaryFile::Export& ex : bin.exports()) {
        if (!ex.isCode || !ex.mapped) continue;
        if (ex.elfSymbol && ex.kind != BinaryFile::SymbolKind::Function &&
            ex.kind != BinaryFile::SymbolKind::IndirectFunction &&
            ex.kind != BinaryFile::SymbolKind::Unknown)
            continue; // an STT_OBJECT placed in executable storage is still data

        auto it = labels.find(ex.va);
        if (!ex.name.empty()) {
            // Prefer externally visible dynamic spellings, then global/weak
            // symtab names, then local names. This makes .dynsym win over a
            // duplicate .symtab row without discarding genuine aliases.
            int rank = 100; // PE named export
            if (ex.elfSymbol) {
                rank = ex.dynamicSymbol ? 70 : 40;
                if (ex.binding == BinaryFile::SymbolBinding::Global ||
                    ex.binding == BinaryFile::SymbolBinding::Weak ||
                    ex.binding == BinaryFile::SymbolBinding::Unique) rank += 20;
                if (ex.visibility == BinaryFile::SymbolVisibility::Hidden ||
                    ex.visibility == BinaryFile::SymbolVisibility::Internal) rank -= 10;
            }
            if (it == labels.end() || rank > it->second.rank)
                labels[ex.va] = {DemangleForLabel(ex.name), rank};
        } else if (it == labels.end()) {
            labels[ex.va] = {"#" + std::to_string(ex.ordinal), 1};
        }
    }
    for (auto& [va, label] : labels) {
        seeds.push_back(va); // aliases share one authoritative function seed
        named.emplace_back(va, std::move(label.name));
    }
}

static std::string lowerCopy(std::string text) {
    for (char& c : text) c = (char)std::tolower((unsigned char)c);
    return text;
}

static uint16_t readTarget16(const uint8_t* bytes, bool bigEndian) {
    if (bigEndian)
        return static_cast<uint16_t>((static_cast<uint16_t>(bytes[0]) << 8) |
                                     static_cast<uint16_t>(bytes[1]));
    return static_cast<uint16_t>(static_cast<uint16_t>(bytes[0]) |
                                 (static_cast<uint16_t>(bytes[1]) << 8));
}

static uint32_t readTarget32(const uint8_t* bytes, bool bigEndian) {
    if (bigEndian)
        return (static_cast<uint32_t>(bytes[0]) << 24) |
               (static_cast<uint32_t>(bytes[1]) << 16) |
               (static_cast<uint32_t>(bytes[2]) << 8) |
                static_cast<uint32_t>(bytes[3]);
    return  static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

static uint64_t canonicalCodeTarget(Arch arch, uint64_t target) {
    // ELF/PE symbols sometimes retain the historical Thumb-state low bit. The
    // decoder mode already carries that state, so mapped code addresses do not.
    // In fixed A32 mode an odd BLX/symbol target requests an interworking mode
    // switch that this decoder cannot safely follow, so leave it odd and let
    // the natural-alignment gate reject it.
    return arch == Arch::THUMB ? (target & ~uint64_t{1}) : target;
}

static uint32_t decoderCodeAlignment(const IDisassembler& dis, Arch arch) {
    const uint32_t reported = dis.instructionAlignment();
    return reported > 1 ? reported : ArchInstructionAlignment(arch);
}

static bool codeTargetAligned(uint32_t alignment, uint64_t target) {
    return alignment <= 1 || target % alignment == 0;
}

static bool executableCodeTarget(const BinaryFile& bin, Arch arch, uint64_t target) {
    for (const Section& s : bin.sections()) {
        if (!s.executable) continue;
        uint64_t begin = 0;
        if (!CheckedAddressAdd(bin.imageBase(), s.virtualAddress, begin)) continue;
        // Function analysis can only decode file-backed bytes. A virtual tail
        // (for example PE zero-fill) is mapped but is not an instruction stream.
        const uint64_t extent = s.rawSize ? s.rawSize : s.virtualSize;
        if (target >= begin && target - begin < extent) return true;
    }
    return false;
}

using LiteralSpan = std::pair<uint64_t,uint64_t>; // [first,second)

static bool parseHashImmediate(const std::string& operands, int64_t& value) {
    const size_t hash = operands.find('#');
    if (hash == std::string::npos) return false;
    const char* p = operands.c_str() + hash + 1;
    char* end = nullptr;
    value = std::strtoll(p, &end, 0);
    return end && end != p;
}

// Recover literal-pool spans referenced by code reached from authoritative
// roots. A prologue-looking word inside one of these spans is data, not a new
// function. This is intentionally conservative: uncertain expressions are not
// guessed, and every walk is bounded/stops at a return or direct tail branch.
static std::vector<LiteralSpan> collectArmLiteralSpans(const BinaryFile& bin,
                                                       IDisassembler& dis,
                                                       Arch arch,
                                                       const std::vector<uint64_t>& roots,
                                                       const std::function<bool()>& cancelled) {
    std::vector<LiteralSpan> spans;
    if (!ArchIsArm(arch)) return spans;
    constexpr size_t kMaxRoots = 2048;
    constexpr size_t kMaxRootCandidates = 8192;
    constexpr size_t kMaxInstructions = 65536;
    constexpr size_t kMaxInstructionsPerRoot = 256;
    constexpr size_t kMaxSpans = 4096;
    std::unordered_set<uint64_t> seenRoots;
    size_t rootsExamined = 0, rootsVisited = 0, instructionsLeft = kMaxInstructions;
    for (uint64_t rawRoot : roots) {
        if (cancelled && cancelled()) break;
        if (++rootsExamined > kMaxRootCandidates) break;
        if (rootsVisited >= kMaxRoots || instructionsLeft == 0 || spans.size() >= kMaxSpans) break;
        const uint64_t root = canonicalCodeTarget(arch, rawRoot);
        if (!codeTargetAligned(decoderCodeAlignment(dis, arch), root) ||
            !seenRoots.insert(root).second) continue;
        ++rootsVisited;
        size_t avail = 0;
        const uint8_t* p = bin.ptrFromVA(root, avail);
        if (!p) continue;
        const size_t perRoot = std::min(kMaxInstructionsPerRoot, instructionsLeft);
        auto insns = dis.disassemble(p, std::min<size_t>(avail, 4096), root, perRoot);
        for (const Instruction& in : insns) {
            if (cancelled && ((kMaxInstructions - instructionsLeft) & 0xFFu) == 0 && cancelled())
                break;
            if (instructionsLeft == 0 || spans.size() >= kMaxSpans) break;
            --instructionsLeft;
            const std::string mn = lowerCopy(in.mnemonic);
            const std::string op = lowerCopy(in.operands);
            const bool a64PcLiteral = arch == Arch::ARM64 &&
                                      op.find('[') == std::string::npos &&
                                      op.find('#') != std::string::npos;
            if ((mn == "ldr" || mn == "ldr.w" || mn == "vldr") &&
                (op.find("[pc") != std::string::npos || a64PcLiteral)) {
                int64_t imm = 0;
                if (parseHashImmediate(op, imm)) {
                    uint64_t address = 0;
                    bool addressValid = false;
                    if (a64PcLiteral) {
                        if (imm >= 0) {
                            address = static_cast<uint64_t>(imm); // Capstone prints absolute literal VA
                            addressValid = true;
                        }
                    } else {
                        uint64_t pc = 0;
                        const uint64_t pipeline = arch == Arch::ARM ? 8u : 4u;
                        const bool pcValid = in.address <=
                            (std::numeric_limits<uint64_t>::max)() - pipeline;
                        if (pcValid) {
                            pc = in.address + pipeline;
                            if (arch == Arch::THUMB) pc &= ~uint64_t{3};
                        }
                        if (pcValid && imm >= 0 && static_cast<uint64_t>(imm) <=
                                (std::numeric_limits<uint64_t>::max)() - pc) {
                            address = pc + static_cast<uint64_t>(imm);
                            addressValid = true;
                        } else if (pcValid && imm < 0 &&
                                   static_cast<uint64_t>(-(imm + 1)) + 1 <= pc) {
                            address = pc - (static_cast<uint64_t>(-(imm + 1)) + 1);
                            addressValid = true;
                        }
                    }
                    size_t mapped = 0;
                    if (addressValid && bin.ptrFromVA(address, mapped)) {
                        size_t width = 4;
                        if (!op.empty() && (op[0] == 'x' || op[0] == 'd')) width = 8;
                        if (!op.empty() && op[0] == 'q') width = 16;
                        const size_t bounded = std::min(width, mapped);
                        uint64_t end = 0;
                        if (CheckedAddressAdd(address, bounded, end))
                            spans.push_back({address, end});
                    }
                }
            }
            if (in.isRet) break;
            if (!in.isCall && in.isBranch &&
                (mn == "b" || mn == "b.w" || mn == "bx" || mn == "br")) break;
        }
    }
    std::sort(spans.begin(), spans.end(), [](const LiteralSpan& a, const LiteralSpan& b) {
        return a.first < b.first;
    });
    std::vector<LiteralSpan> merged;
    merged.reserve(spans.size());
    for (const LiteralSpan& span : spans) {
        if (span.first >= span.second) continue;
        if (!merged.empty() && span.first <= merged.back().second)
            merged.back().second = std::max(merged.back().second, span.second);
        else
            merged.push_back(span);
    }
    return merged;
}

static bool decodedArmPrologue(IDisassembler& dis, const uint8_t* p, size_t avail,
                               uint64_t va, Arch arch) {
    Instruction first;
    if (!dis.decodeOne(p, avail, va, first) || !first.length || first.mnemonic == "db") return false;
    std::string mn = lowerCopy(first.mnemonic), op = lowerCopy(first.operands);
    if (arch == Arch::ARM64) {
        if (mn == "paciasp") {
            if (avail <= first.length) return false;
            Instruction second;
            uint64_t secondVA = 0;
            if (!CheckedAddressAdd(va, first.length, secondVA) ||
                !dis.decodeOne(p + first.length, avail - first.length, secondVA, second))
                return false;
            mn = lowerCopy(second.mnemonic); op = lowerCopy(second.operands);
        }
        return mn == "stp" && op.find("x29") != std::string::npos &&
               op.find("x30") != std::string::npos && op.find("sp") != std::string::npos;
    }
    const bool push = mn == "push" || mn == "push.w" || mn.rfind("stmdb", 0) == 0;
    const bool save = mn == "str" || mn == "str.w";
    return (push && op.find("lr") != std::string::npos) ||
           (save && op.find("lr") != std::string::npos && op.find("sp") != std::string::npos);
}

// Heuristic prologue scan across executable sections. ARM-family candidates
// use strict natural alignment, saved-return-address patterns, decoder
// confirmation, and trusted literal-pool exclusions.
void FunctionAnalyzer::prologueScan(const BinaryFile& bin, IDisassembler& dis, Arch arch,
                                    const std::vector<LiteralSpan>& literals,
                                    std::vector<uint64_t>& seeds, size_t candidateBudget,
                                    const std::function<bool()>& cancelled) {
    const bool x64 = arch == Arch::X64;
    const bool x86 = arch == Arch::X86;
    const bool a32 = arch == Arch::ARM;
    const bool thumb = arch == Arch::THUMB;
    const bool a64 = arch == Arch::ARM64;
    const bool bigEndian = bin.bigEndian();
    if (!x64 && !x86 && !a32 && !thumb && !a64) return;
    constexpr size_t kMaxScanBytes = 64u * 1024u * 1024u;
    if (!candidateBudget) { prologueTruncated_ = true; return; }
    const auto isLiteral = [&](uint64_t va) {
        const auto it = std::upper_bound(literals.begin(), literals.end(), va,
            [](uint64_t value, const LiteralSpan& span) { return value < span.first; });
        return it != literals.begin() && va < std::prev(it)->second;
    };
    for (const auto& s : bin.sections()) {
        if (cancelled && cancelled()) { cancelled_ = true; return; }
        if (!s.executable) continue;
        uint64_t sectionVA = 0;
        if (!CheckedAddressAdd(bin.imageBase(), s.virtualAddress, sectionVA)) continue;
        size_t avail = 0;
        const uint8_t* p = bin.ptrFromVA(sectionVA, avail);
        if (!p) continue;
        size_t n = std::min<size_t>(avail, (size_t)s.rawSize);
        const size_t stride = thumb ? 2 : (a32 || a64 ? 4 : 1);
        for (size_t i = 0; i + (thumb ? 2 : 4) <= n; i += stride) {
            if (prologueBytesScanned_ >= kMaxScanBytes) {
                prologueTruncated_ = true;
                return;
            }
            prologueBytesScanned_ += stride;
            if (cancelled && (prologueBytesScanned_ & 0xFFFu) == 0 && cancelled()) {
                cancelled_ = true;
                return;
            }
            uint64_t va = 0;
            if (!CheckedAddressAdd(sectionVA, static_cast<uint64_t>(i), va)) {
                prologueTruncated_ = true;
                return;
            }
            if ((a32 || a64) && (va & 3u)) continue;
            if (thumb && (va & 1u)) continue;
            bool hit = false;
            if (x64) {
                // push rbp; mov rbp, rsp           => 55 48 8B EC  (or 48 89 E5)
                // sub rsp, imm8 after push regs    => 48 83 EC xx
                // mov [rsp+x], reg  (MS x64 home)  => 48 89 5C 24 xx / 48 89 4C 24 xx
                hit =
                    (p[i] == 0x55 && p[i+1] == 0x48 && (p[i+2] == 0x8B && p[i+3] == 0xEC)) ||
                    (p[i] == 0x55 && p[i+1] == 0x48 && p[i+2] == 0x89 && p[i+3] == 0xE5) ||
                    (p[i] == 0x48 && p[i+1] == 0x83 && p[i+2] == 0xEC) ||
                    (p[i] == 0x48 && p[i+1] == 0x89 && (p[i+2] == 0x5C || p[i+2] == 0x4C || p[i+2] == 0x54) && p[i+3] == 0x24);
            } else if (x86) {
                // 32-bit: push ebp; mov ebp, esp   => 55 8B EC  (Intel) / 55 89 E5 (AT&T-encoded gcc)
                hit =
                    (p[i] == 0x55 && p[i+1] == 0x8B && p[i+2] == 0xEC) ||
                    (p[i] == 0x55 && p[i+1] == 0x89 && p[i+2] == 0xE5);
            } else if (a32 && i + 4 <= n) {
                const uint32_t w = readTarget32(p + i, bigEndian);
                hit = (w & 0x0fff4000u) == 0x092d4000u || // stmdb sp!,{...,lr}
                      (w & 0x0ffff000u) == 0x052de000u;   // str lr,[sp,#-imm]!
            } else if (thumb) {
                const uint16_t h = readTarget16(p + i, bigEndian);
                hit = (h & 0xff00u) == 0xb500u;           // push {...,lr}
                if (!hit && i + 4 <= n) {
                    const uint16_t h2 = readTarget16(p + i + 2, bigEndian);
                    hit = h == 0xe92du && (h2 & 0x4000u); // push.w/stmdb sp!,{...,lr}
                }
            } else if (a64 && i + 4 <= n) {
                const uint32_t w = readTarget32(p + i, bigEndian);
                hit = (w & 0xffc07fffu) == 0xa9807bfdu;   // stp x29,x30,[sp,#-imm]!
                if (hit && i >= 4) {
                    const uint32_t prev = readTarget32(p + i - 4, bigEndian);
                    if (prev == 0xd503233fu) {             // include PACIASP in the function root
                        const uint64_t pacVA = va - 4;
                        if (!isLiteral(pacVA) && decodedArmPrologue(dis, p + i - 4, n - (i - 4), pacVA, arch)) {
                            seeds.push_back(pacVA);
                            if (++prologueCandidates_ >= candidateBudget) {
                                prologueTruncated_ = true;
                                return;
                            }
                        }
                        hit = false;
                    }
                }
            }
            if (hit && !isLiteral(va) &&
                (!ArchIsArm(arch) || decodedArmPrologue(dis, p + i, n - i, va, arch))) {
                seeds.push_back(va);
                if (++prologueCandidates_ >= candidateBudget) {
                    prologueTruncated_ = true;
                    return;
                }
            }
        }
    }
}

// Structured flow is authoritative. These mnemonic checks exist only for the
// small legacy/custom decoders that still populate the compatibility booleans.
static bool isUnconditionalTransfer(const Instruction& in) {
    if (in.flow.kind != FlowKind::None) return InstructionIsUnconditionalBranch(in);
    if (!in.isBranch || in.isCall || in.isRet) return false;
    const std::string mnemonic = lowerCopy(in.mnemonic);
    return mnemonic == "jmp" || mnemonic == "b" || mnemonic == "b.w" ||
           mnemonic == "bx" || mnemonic == "br" || mnemonic == "j" ||
           mnemonic == "jr" || mnemonic == "goto" || mnemonic == "goto_w";
}

static bool isSwitchTransfer(const Instruction& in) {
    return in.flow.kind == FlowKind::Switch || !in.extraTargets.empty();
}

// Validate and normalize a statically known flow destination for the fixed
// decoder mode selected by this analysis job. BLX/interworking destinations are
// deliberately rejected: owning them would require a second decoder mode.
static bool normalizedFlowTarget(const BinaryFile& bin, const Instruction& in,
                                 Arch arch, uint32_t alignment, uint64_t& target,
                                 std::unordered_set<uint64_t>* skippedInterworking) {
    uint64_t raw = 0;
    if (!TryGetDirectTarget(in, raw)) {
        if (arch != Arch::X86_16 || !in.farTarget.valid ||
            !bin.resolveRealModeAlias(in.farTarget.segment, in.farTarget.offset, raw))
            return false;
    }
    const std::string mnemonic = lowerCopy(in.mnemonic);
    const bool explicitModeSwitch = (arch == Arch::ARM || arch == Arch::THUMB) &&
                                    mnemonic == "blx";
    if (explicitModeSwitch || (arch == Arch::ARM && (raw & 1u))) {
        if (skippedInterworking) skippedInterworking->insert(raw);
        return false;
    }
    target = canonicalCodeTarget(arch, raw);
    return codeTargetAligned(alignment, target) && executableCodeTarget(bin, arch, target);
}

// Return the exact number of file-backed bytes remaining in the executable
// section containing address. BinaryFile::ptrFromVA may expose a larger mapped
// tail; block ownership must never cross a section boundary through that tail.
static size_t executableBytesAvailable(const BinaryFile& bin, uint64_t address) {
    size_t mapped = 0;
    if (!bin.ptrFromVA(address, mapped) || !mapped) return 0;
    for (const Section& section : bin.sections()) {
        if (!section.executable) continue;
        uint64_t begin = 0;
        if (!CheckedAddressAdd(bin.imageBase(), section.virtualAddress, begin)) continue;
        const uint64_t extent = section.rawSize ? section.rawSize : section.virtualSize;
        if (address < begin || address - begin >= extent) continue;
        const uint64_t left = extent - (address - begin);
        return static_cast<size_t>(std::min<uint64_t>(mapped, left));
    }
    return 0;
}

static bool decodeReachableInstruction(const BinaryFile& bin, IDisassembler& dis,
                                       uint64_t address, Instruction& out) {
    const size_t available = executableBytesAvailable(bin, address);
    if (!available) return false;
    size_t mapped = 0;
    const uint8_t* bytes = bin.ptrFromVA(address, mapped);
    const size_t limit = std::min<size_t>({available, mapped, 32});
    if (!bytes || !limit || !dis.decodeOne(bytes, limit, address, out) ||
        !out.length || out.length > limit || lowerCopy(out.mnemonic) == "db")
        return false;
    return true;
}

// `call next_instruction; pop reg` is the classic x86 PC-materialization
// idiom.  A call merely landing at its fallthrough address is not sufficient:
// ordinary adjacent calls are real function edges and must remain visible.
static bool isX86CallNextPop(const BinaryFile& bin, IDisassembler& dis, Arch arch,
                             uint64_t target, uint64_t returnAddress) {
    if (!ArchIsX86(arch) || target != returnAddress) return false;
    Instruction next;
    if (!decodeReachableInstruction(bin, dis, returnAddress, next) ||
        lowerCopy(next.mnemonic) != "pop")
        return false;
    for (const TypedOperand& operand : next.typedOperands)
        if (operand.kind == OperandKind::Register) return true;
    return false;
}

struct ReachableBody {
    std::vector<FunctionChunk> chunks;
    size_t decodedInstructions = 0;
    bool truncated = false;
    bool cancelled = false;
};

// Own one function by recursive basic-block traversal. Calls create function
// entries through onDirectCall but are never traversed as intra-function edges.
// Direct branches remain intra-function unless their destination is already a
// function start, in which case an unconditional transfer is a tail boundary.
// Delay slots are decoded and owned before the parent transfer takes effect.
static ReachableBody walkReachableBody(
    const BinaryFile& bin, IDisassembler& dis, Arch arch, uint64_t functionStart,
    const std::set<uint64_t>& functionStarts,
    const std::vector<LiteralSpan>& literalSpans,
    size_t maxInstructions, size_t& globalInstructionBudget,
    const std::function<bool()>& cancelled,
    const std::function<bool(const Instruction&)>& isNoreturnTransfer,
    const std::function<void(uint64_t)>& onDirectCall,
    const JumpTableResolver& resolveTable,
    std::unordered_set<uint64_t>* skippedInterworking) {
    ReachableBody body;
    if (!maxInstructions) maxInstructions = 1;
    const uint32_t targetAlignment = decoderCodeAlignment(dis, arch);

    const auto isLiteral = [&](uint64_t address) {
        const auto it = std::upper_bound(literalSpans.begin(), literalSpans.end(), address,
            [](uint64_t value, const LiteralSpan& span) { return value < span.first; });
        return it != literalSpans.begin() && address < std::prev(it)->second;
    };

    struct OwnedRange { uint64_t begin = 0, end = 0; }; // checked [begin,end)
    std::vector<OwnedRange> owned;
    owned.reserve(std::min<size_t>(maxInstructions, 4096));
    std::vector<uint64_t> blocks{functionStart};
    std::unordered_set<uint64_t> queued{functionStart};
    std::unordered_set<uint64_t> visitedBlocks;
    std::unordered_set<uint64_t> visitedInstructions;
    bool truncatedByLimit = false;

    auto consume = [&](uint64_t address, Instruction& in) -> bool {
        if (body.decodedInstructions >= maxInstructions || !globalInstructionBudget) {
            body.truncated = true;
            truncatedByLimit = true;
            return false;
        }
        if (cancelled && ((body.decodedInstructions & 0xFFu) == 0) && cancelled()) {
            body.cancelled = true;
            return false;
        }
        if (!decodeReachableInstruction(bin, dis, address, in)) return false;
        uint64_t end = 0;
        if (!CheckedAddressAdd(address, in.length, end)) return false;
        owned.push_back({address, end});
        ++body.decodedInstructions;
        --globalInstructionBudget;
        return true;
    };

    auto queueTarget = [&](uint64_t target) {
        if (target != functionStart && functionStarts.count(target)) return;
        if (isLiteral(target) || !executableCodeTarget(bin, arch, target)) return;
        if (queued.insert(target).second) blocks.push_back(target);
    };

    auto publishCall = [&](const Instruction& in, uint64_t returnAddress) {
        if (!InstructionIsCall(in) || !onDirectCall) return;
        uint64_t target = 0;
        if (normalizedFlowTarget(bin, in, arch, targetAlignment, target, skippedInterworking) &&
            !isLiteral(target) &&
            !isX86CallNextPop(bin, dis, arch, target, returnAddress))
            onDirectCall(target);
    };

    bool stopAll = false;
    while (!blocks.empty() && !stopAll) {
        if (cancelled && cancelled()) { body.cancelled = true; break; }
        const uint64_t block = blocks.back();
        blocks.pop_back();
        if (!visitedBlocks.insert(block).second) continue;
        if (block != functionStart && functionStarts.count(block)) continue;

        uint64_t pc = block;
        for (;;) {
            if (pc != functionStart && functionStarts.count(pc)) break;
            if (isLiteral(pc) || !visitedInstructions.insert(pc).second) break;

            Instruction in;
            if (!consume(pc, in)) {
                stopAll = truncatedByLimit || body.cancelled;
                break;
            }
            uint64_t afterTransfer = 0;
            if (!CheckedAddressAdd(pc, in.length, afterTransfer)) break;

            // Architectural delay slots remain part of the transferring block.
            // Their own flow is not followed (nested transfers are generally
            // illegal/undefined), but direct calls are still discovered.
            for (uint8_t slot = 0; slot < in.flow.delaySlots; ++slot) {
                Instruction delayed;
                if (!consume(afterTransfer, delayed)) {
                    // A malformed/unmapped delay slot makes ownership incomplete
                    // even though the parent transfer was valid.
                    if (!truncatedByLimit && !body.cancelled) body.truncated = true;
                    stopAll = true;
                    break;
                }
                visitedInstructions.insert(afterTransfer);
                uint64_t delayedReturn = 0;
                if (!CheckedAddressAdd(delayed.address, delayed.length, delayedReturn)) {
                    stopAll = true;
                    break;
                }
                publishCall(delayed, delayedReturn);
                if (!CheckedAddressAdd(afterTransfer, delayed.length, afterTransfer)) {
                    stopAll = true;
                    break;
                }
            }
            if (stopAll) break;

            // For delay-slot ISAs the architectural return address is after all
            // validated slots.  This also makes the call-next exclusion exact.
            publishCall(in, afterTransfer);

            const bool call = InstructionIsCall(in);
            const bool ret = InstructionIsReturn(in);
            const bool endsBlock = InstructionEndsBlock(in);
            const bool uncond = isUnconditionalTransfer(in);
            const bool switchTransfer = isSwitchTransfer(in);

            if (call) {
                if (isNoreturnTransfer && isNoreturnTransfer(in)) break;
                pc = afterTransfer;
                continue;
            }
            if (ret) break;

            if (endsBlock || switchTransfer) {
                uint64_t target = 0;
                if (normalizedFlowTarget(bin, in, arch, targetAlignment, target, skippedInterworking))
                    queueTarget(target);
                for (uint64_t rawTarget : in.extraTargets) {
                    Instruction synthetic;
                    synthetic.flow.directTargetValid = true;
                    synthetic.flow.directTarget = rawTarget;
                    uint64_t extraTarget = 0;
                    if (normalizedFlowTarget(bin, synthetic, arch, targetAlignment, extraTarget,
                                             skippedInterworking))
                        queueTarget(extraTarget);
                }
                // A shared binary-aware resolver is the only authority for
                // native computed-switch edges. Empty means unresolved; never
                // turn an arbitrary register/memory jump into guessed ownership.
                if (resolveTable && !TryGetDirectTarget(in, target)) {
                    ResolvedJumpTable table = resolveTable(in);
                    if (table.truncated) body.truncated = true;
                    for (uint64_t tableTarget : table.targets)
                        queueTarget(tableTarget);
                }
                if (uncond || switchTransfer) break;
                // Conditional flow owns both the queued target and fallthrough.
                pc = afterTransfer;
                continue;
            }

            pc = afterTransfer;
        }
    }

    std::sort(owned.begin(), owned.end(), [](const OwnedRange& a, const OwnedRange& b) {
        return a.begin < b.begin || (a.begin == b.begin && a.end < b.end);
    });
    std::vector<OwnedRange> merged;
    merged.reserve(owned.size());
    for (const OwnedRange& range : owned) {
        if (range.begin >= range.end) continue;
        if (!merged.empty() && range.begin <= merged.back().end)
            merged.back().end = std::max(merged.back().end, range.end);
        else
            merged.push_back(range);
    }
    body.chunks.reserve(merged.size());
    for (const OwnedRange& range : merged) {
        uint64_t begin = range.begin;
        uint64_t left = range.end - range.begin;
        while (left) {
            const uint32_t piece = static_cast<uint32_t>(std::min<uint64_t>(
                left, (std::numeric_limits<uint32_t>::max)()));
            body.chunks.push_back({begin, piece});
            begin += piece;
            left -= piece;
        }
    }
    return body;
}

std::vector<DiscoveredFunction>
FunctionAnalyzer::analyze(const BinaryFile& bin, IDisassembler& dis,
                          size_t maxFunctions, size_t maxInstrPerFunc) {
    Arch arch{};
    switch (bin.machine()) {
        case MachineArch::X86:     arch = Arch::X86; break;
        case MachineArch::X64:     arch = Arch::X64; break;
        case MachineArch::ARM:     arch = Arch::ARM; break;
        case MachineArch::THUMB:   arch = Arch::THUMB; break;
        case MachineArch::ARM64:   arch = Arch::ARM64; break;
        case MachineArch::MIPS:    arch = Arch::MIPS; break;
        case MachineArch::MIPS64:  arch = Arch::MIPS64; break;
        case MachineArch::PPC:     arch = Arch::PPC; break;
        case MachineArch::PPC64:   arch = Arch::PPC64; break;
        case MachineArch::RISCV:   arch = Arch::RISCV32; break;
        case MachineArch::RISCV64: arch = Arch::RISCV64; break;
        case MachineArch::JVM:     arch = Arch::JVM; break;
        case MachineArch::GML:     arch = Arch::GML; break;
        case MachineArch::Unknown:
            summary_ = "analysis refused: Raw/Unknown image requires an explicit architecture";
            return {};
    }
    return analyze(bin, dis, arch, maxFunctions, maxInstrPerFunc);
}

std::vector<DiscoveredFunction>
FunctionAnalyzer::analyze(const BinaryFile& bin, IDisassembler& dis, Arch arch,
                          size_t maxFunctions, size_t maxInstrPerFunc,
                          const std::function<bool()>& cancelled,
                          const std::vector<uint64_t>& supplementalSeeds,
                          const std::vector<uint64_t>& analystSeeds,
                          const JumpTableResolver& resolveTable,
                          const FunctionNoreturnDecisionResolver& noreturnDecision) {
    summary_.clear();
    prologueTruncated_ = false;
    cancelled_ = false;
    prologueCandidates_ = 0;
    prologueBytesScanned_ = 0;
    std::vector<DiscoveredFunction> out;
    if (!bin.loaded()) { summary_ = "no binary loaded"; return out; }
    const uint32_t targetAlignment = decoderCodeAlignment(dis, arch);

    if (bin.format() == BinFormat::GameMakerArchive && bin.gameMakerArchive()) {
        const GameMakerArchive& archive = *bin.gameMakerArchive();
        if (!archive.bytecodeSupported) {
            summary_ = "GameMaker archive bytecode version is unsupported";
            return out;
        }
        std::set<uint64_t> entries;
        for (const auto& code : archive.code)
            if (archive.isInstructionOffset(code.entryFileOffset()))
                entries.insert(code.entryFileOffset());
        std::set<uint64_t> emitted;
        size_t budget = 4u * 1024u * 1024u;
        size_t truncated = 0;
        for (const auto& code : archive.code) {
            if (cancelled && cancelled()) { cancelled_ = true; break; }
            const uint64_t entry = code.entryFileOffset();
            if (!entries.count(entry) || !emitted.insert(entry).second) continue;
            if (out.size() >= maxFunctions) { ++truncated; break; }
            DiscoveredFunction function;
            function.address = entry;
            function.name = code.name;
            function.isExport = true;
            function.seedKind = FunctionSeedKind::GameMakerCode;
            function.boundaryConfidence = FunctionBoundaryConfidence::Authoritative;
            auto body = walkReachableBody(bin, dis, Arch::GML, entry, entries, {},
                maxInstrPerFunc, budget, cancelled, {}, {}, {}, nullptr);
            function.chunks = std::move(body.chunks);
            // CODE lengths describe shared blobs, not child function extents.
            // Only reachable chunks belong to this function; names at the same
            // entry remain aliases in the archive's code table.
            for (const auto& chunk : function.chunks)
                if (chunk.address == entry) { function.size = chunk.size; break; }
            function.ownershipTruncated = body.truncated || body.cancelled ||
                                          !code.instructionsComplete;
            if (function.ownershipTruncated) ++truncated;
            out.push_back(std::move(function));
            if (body.cancelled) { cancelled_ = true; break; }
        }
        std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
            return a.address < b.address;
        });
        summary_ = std::to_string(out.size()) + " GameMaker code entries; " +
            std::to_string(archive.code.size()) + " named records including aliases";
        if (truncated) summary_ += "; " + std::to_string(truncated) + " bounded/incomplete bodies";
        if (cancelled_) summary_ += "; cancelled";
        return out;
    }

    // Java class: the method table is authoritative — exact starts, exact sizes,
    // real names. The x86 heuristics (descent, prologue scan, .pdata) don't apply.
    if (bin.format() == BinFormat::JavaClass && bin.javaClass()) {
        const JvmClassFile& cf = *bin.javaClass();
        const std::string cls = JvmShortClassName(cf.thisClass);
        std::unordered_map<std::string, int> nameCount;
        for (const auto& m : cf.methods) if (m.codeLength) ++nameCount[m.name];
        for (const auto& m : cf.methods) {
            if (cancelled && cancelled()) { cancelled_ = true; break; }
            if (!m.codeLength || out.size() >= maxFunctions) continue;
            DiscoveredFunction f;
            f.address = m.codeOffset;
            f.size    = m.codeLength;
            f.chunks.push_back({m.codeOffset, m.codeLength});
            // Overloads share a name: disambiguate with the pretty signature.
            f.name = (nameCount[m.name] > 1) ? cls + "." + JvmPrettyMethod(m.name, m.descriptor)
                                             : cls + "." + m.name;
            f.isExport = true;   // a real (compiler-recorded) name, not a sub_ guess
            f.seedKind = FunctionSeedKind::JavaMethod;
            f.boundaryConfidence = FunctionBoundaryConfidence::Authoritative;
            out.push_back(std::move(f));
        }
        std::sort(out.begin(), out.end(),
                  [](const DiscoveredFunction& a, const DiscoveredFunction& b) {
                      return a.address < b.address;
                  });
        char sum[160];
        std::snprintf(sum, sizeof(sum), "%zu methods from the class file (%s)",
                      out.size(), cf.thisClass.c_str());
        summary_ = sum;
        if (cancelled_) summary_ += "; function analysis cancelled";
        return out;
    }

    std::vector<uint64_t> seeds;
    std::vector<std::pair<uint64_t,std::string>> named;
    std::unordered_set<uint64_t> legacyRawSeeds;
    std::unordered_map<uint64_t, FunctionSeedKind> loaderSeedKinds;

    if (bin.hasEntryPoint()) {
        seeds.push_back(bin.entryPointVA());
        loaderSeedKinds.try_emplace(bin.entryPointVA(), FunctionSeedKind::Entry);
    }
    // A legacy raw image without an explicitly selected entry retains the old
    // base-as-root behavior (including VA 0). Firmware-aware raw loads set a
    // real entry above, so discovery starts at the recovered/edited boot target.
    if (bin.format() == BinFormat::Raw && !bin.hasEntryPoint()) {
        const Section* raw = bin.firstCodeSection();
        if (raw && raw->executable) {
            uint64_t start = 0;
            size_t avail = 0;
            if (CheckedAddressAdd(bin.imageBase(), raw->virtualAddress, start) &&
                bin.ptrFromVA(start, avail) && avail) {
                seeds.push_back(start);
                legacyRawSeeds.insert(start);
                loaderSeedKinds.try_emplace(start, FunctionSeedKind::LegacyRawBase);
            }
        }
    }
    const size_t exportSeedBegin = seeds.size();
    collectExports(bin, seeds, named);
    for (size_t i = exportSeedBegin; i < seeds.size(); ++i)
        loaderSeedKinds.try_emplace(seeds[i], FunctionSeedKind::Symbol);

    // Firmware/header-external landmarks are authoritative named roots. They
    // participate in recursive descent exactly like exports while retaining the
    // detector's stable symbol names in every listing/decompiler consumer.
    for (const AnalysisLandmark& lm : bin.analysisLandmarks()) {
        size_t avail = 0;
        if (!lm.name.empty() && bin.ptrFromVA(lm.address, avail) && avail) {
            seeds.push_back(lm.address);
            named.emplace_back(lm.address, lm.name);
            loaderSeedKinds.try_emplace(lm.address, FunctionSeedKind::Landmark);
        }
    }

    // .pdata seeding (x64 PE): every RUNTIME_FUNCTION begin is an authoritative
    // function start, and its [begin, end) extent beats the gap-to-next-start
    // size guess. Chained-unwind chunks were already folded by pdataRanges().
    std::unordered_map<uint64_t, uint64_t> sizeHint;       // start -> linker/symbol-known size
    size_t elfSizeHints = 0;
    for (const BinaryFile::Export& ex : bin.exports()) {
        if (!ex.elfSymbol || !ex.mapped || !ex.isCode || !ex.size) continue;
        if (ex.kind != BinaryFile::SymbolKind::Function &&
            ex.kind != BinaryFile::SymbolKind::IndirectFunction) continue;
        const uint64_t hintVA = canonicalCodeTarget(arch, ex.va);
        if (!codeTargetAligned(targetAlignment, hintVA)) continue;
        size_t avail = 0;
        if (!bin.ptrFromVA(hintVA, avail) || ex.size > avail) continue;
        auto [it, inserted] = sizeHint.try_emplace(hintVA, ex.size);
        if (!inserted) it->second = std::max(it->second, ex.size);
        else ++elfSizeHints;
    }
    size_t pdataCount = 0;
    {
        auto ranges = bin.pdataRanges();
        pdataCount = ranges.size();
        for (const auto& [b, e] : ranges) {
            seeds.push_back(b);
            loaderSeedKinds.try_emplace(b, FunctionSeedKind::Unwind);
            uint64_t len = e - b;
            auto it = sizeHint.find(b);
            if (it == sizeHint.end() || it->second < len) sizeHint[b] = len;
        }
    }
    // Everything accumulated above came from loader-owned metadata, except the
    // explicitly recorded legacy raw-base fallback.  Keep that distinction so a
    // byte-pattern seed can never authorize patch/breakpoint boundaries.
    const size_t loaderSeedCount = seeds.size();
    std::vector<uint64_t> trustedRoots;
    trustedRoots.reserve(loaderSeedCount + analystSeeds.size());
    for (uint64_t seed : seeds)
        if (!legacyRawSeeds.count(seed)) trustedRoots.push_back(seed);

    // Analyst definitions are authoritative roots, not classifier guesses. Put
    // them in their own provenance tier so their exact decoded call stream can
    // reconcile provisional descendants.
    for (uint64_t seed : analystSeeds) {
        seed = canonicalCodeTarget(arch, seed);
        size_t available = 0;
        if (codeTargetAligned(targetAlignment, seed) && executableCodeTarget(bin, arch, seed) &&
            bin.ptrFromVA(seed, available) && available) {
            seeds.push_back(seed);
            trustedRoots.push_back(seed);
        }
    }
    const size_t analystSeedEnd = seeds.size();

    // Strong entries recovered by the global code/data classifier (CET landing
    // pads, vtables and relocation-backed callback pointers). They are inserted
    // before the heuristic prologue scan, so its candidate flood cannot crowd an
    // indirect-only function out of the bounded recursive-descent worklist.
    for (uint64_t seed : supplementalSeeds) {
        seed = canonicalCodeTarget(arch, seed);
        size_t available = 0;
        if (codeTargetAligned(targetAlignment, seed) && executableCodeTarget(bin, arch, seed) &&
            bin.ptrFromVA(seed, available) && available)
            seeds.push_back(seed);
    }
    const size_t classifierSeedEnd = seeds.size();
    const std::vector<LiteralSpan> armLiteralSpans =
        collectArmLiteralSpans(bin, dis, arch, trustedRoots, cancelled);
    if (cancelled && cancelled()) cancelled_ = true;
    constexpr size_t kHardPrologueCandidateCap = 100000;
    const size_t prologueBudget = std::min(maxFunctions, kHardPrologueCandidateCap);
    if (!cancelled_)
        prologueScan(bin, dis, arch, armLiteralSpans, seeds, prologueBudget, cancelled);
    const auto isArmLiteral = [&](uint64_t va) {
        const auto it = std::upper_bound(armLiteralSpans.begin(), armLiteralSpans.end(), va,
            [](uint64_t value, const LiteralSpan& span) { return value < span.first; });
        return it != armLiteralSpans.begin() && va < std::prev(it)->second;
    };

    std::map<uint64_t,std::string> nameMap;
    for (auto& n : named) nameMap[canonicalCodeTarget(arch, n.first)] = n.second;

    // Only well-known exit-family imports are authoritative noreturn evidence.
    // Ordinary IAT transfers are tail boundaries, but are not marked noreturn.
    std::unordered_set<uint64_t> noretIat;
    for (const auto& im : bin.imports()) {
        if (!im.addressKnown) continue;
        if (IsKnownNoreturnApi(im.name)) noretIat.insert(im.iatVA);
    }

    // Admit authoritative seeds first, then heuristic prologues. This preserves
    // entry/export/unwind roots when an adversarial prologue flood reaches the
    // maxFunctions cap. Provisional starts remain candidates, not hard
    // ownership boundaries, until an exact call stream reconciles them.
    std::set<uint64_t> starts;
    std::set<uint64_t> exactBoundaries;
    std::unordered_set<uint64_t> skippedInterworkingTargets;
    std::unordered_map<uint64_t, FunctionBoundaryConfidence> boundaryConfidence;
    std::unordered_map<uint64_t, FunctionSeedKind> seedKinds;
    std::vector<uint64_t> work;
    work.reserve(std::min(seeds.size(), maxFunctions));
    auto confidenceRank = [](FunctionBoundaryConfidence value) {
        return static_cast<unsigned>(value);
    };
    auto admitStart = [&](uint64_t seed, FunctionSeedKind kind,
                          FunctionBoundaryConfidence confidence) {
        if (arch == Arch::ARM && (seed & 1u)) skippedInterworkingTargets.insert(seed);
        seed = canonicalCodeTarget(arch, seed);
        if (!codeTargetAligned(targetAlignment, seed) ||
            !executableCodeTarget(bin, arch, seed)) return;
        auto known = boundaryConfidence.find(seed);
        bool upgraded = false;
        if (known == boundaryConfidence.end() ||
            confidenceRank(confidence) > confidenceRank(known->second)) {
            boundaryConfidence[seed] = confidence;
            seedKinds[seed] = kind;
            upgraded = true;
        }
        // Exact boundaries remain authoritative even when the output cap is
        // full. Heuristic/classifier/legacy-raw starts deliberately do not
        // truncate a loader-owned or reconciled reachable body.
        if (confidence != FunctionBoundaryConfidence::Heuristic)
            exactBoundaries.insert(seed);
        if (starts.count(seed)) {
            // A provisional start may already have been scanned before an
            // authoritative caller reaches it. Requeue the stronger stream so
            // its callees inherit reconciled confidence as well.
            if (upgraded) work.push_back(seed);
            return;
        }
        if (starts.size() >= maxFunctions) return;
        starts.insert(seed);
        work.push_back(seed);
    };
    const size_t loaderLimit = std::min(loaderSeedCount, seeds.size());
    for (size_t i = 0; i < loaderLimit; ++i) {
        const bool legacyRaw = legacyRawSeeds.count(seeds[i]) != 0;
        const auto provenance = loaderSeedKinds.find(seeds[i]);
        admitStart(seeds[i], legacyRaw ? FunctionSeedKind::LegacyRawBase
                                      : (provenance != loaderSeedKinds.end()
                                             ? provenance->second
                                             : FunctionSeedKind::Loader),
                   legacyRaw ? FunctionBoundaryConfidence::Heuristic
                             : FunctionBoundaryConfidence::Authoritative);
    }
    const size_t analystLimit = std::min(analystSeedEnd, seeds.size());
    for (size_t i = loaderLimit; i < analystLimit; ++i)
        admitStart(seeds[i], FunctionSeedKind::Analyst,
                   FunctionBoundaryConfidence::Authoritative);
    const size_t classifierLimit = std::min(classifierSeedEnd, seeds.size());
    for (size_t i = analystLimit; i < classifierLimit; ++i)
        admitStart(seeds[i], FunctionSeedKind::Classifier,
                   FunctionBoundaryConfidence::Heuristic);
    for (size_t i = classifierLimit; i < seeds.size(); ++i)
        admitStart(seeds[i], FunctionSeedKind::Prologue,
                   FunctionBoundaryConfidence::Heuristic);

    // Prove noreturn wrappers by a bounded recursive walk. The proof bottoms out
    // only at the exact exit-family IAT set above. Conditional/indirect flow and
    // cycles fail closed; straight-line setup plus call/jump wrapper chains are
    // propagated to a fixed point through the memoized recursion.
    enum class NoreturnProof : uint8_t { Visiting, ReturnsOrUnknown, Proven };
    std::unordered_map<uint64_t, NoreturnProof> noretProof;
    size_t noretProofBudget = 262144;
    std::function<bool(uint64_t,size_t)> proveNoreturn;
    proveNoreturn = [&](uint64_t start, size_t depth) -> bool {
        if (noreturnDecision) {
            const std::optional<bool> decision = noreturnDecision(start);
            if (decision.has_value()) return *decision;
        }
        if ((!noreturnDecision && noretIat.empty()) || depth > 32 ||
            !noretProofBudget || isArmLiteral(start))
            return false;
        if (auto it = noretProof.find(start); it != noretProof.end())
            return it->second == NoreturnProof::Proven;
        noretProof[start] = NoreturnProof::Visiting;
        auto finish = [&](bool proven) {
            noretProof[start] = proven ? NoreturnProof::Proven
                                       : NoreturnProof::ReturnsOrUnknown;
            return proven;
        };

        uint64_t pc = start;
        for (size_t i = 0; i < 128 && noretProofBudget; ++i) {
            if (cancelled && ((i & 0x1Fu) == 0) && cancelled()) {
                cancelled_ = true;
                noretProof.erase(start);
                return false;
            }
            Instruction in;
            if (!decodeReachableInstruction(bin, dis, pc, in)) return finish(false);
            --noretProofBudget;
            uint64_t afterTransfer = 0;
            if (!CheckedAddressAdd(pc, in.length, afterTransfer)) return finish(false);
            // Delay slots execute before the transfer. Conservatively reject a
            // proof when a slot itself contains control flow; otherwise include
            // every slot in the bounded validation before following the edge.
            for (uint8_t slot = 0; slot < in.flow.delaySlots; ++slot) {
                if (!noretProofBudget) return finish(false);
                Instruction delayed;
                if (!decodeReachableInstruction(bin, dis, afterTransfer, delayed))
                    return finish(false);
                --noretProofBudget;
                if (InstructionIsCall(delayed) || InstructionEndsBlock(delayed) ||
                    InstructionIsReturn(delayed))
                    return finish(false);
                if (!CheckedAddressAdd(afterTransfer, delayed.length, afterTransfer))
                    return finish(false);
            }
            const bool call = InstructionIsCall(in);
            const bool ret = InstructionIsReturn(in);
            const bool uncond = isUnconditionalTransfer(in);
            const bool switchTransfer = isSwitchTransfer(in);
            uint64_t dataRef = 0;
            const bool dataRefValid = TryGetInstrDataRef(in, dataRef);
            if ((call || uncond) && dataRefValid) {
                if (noreturnDecision) {
                    const std::optional<bool> decision = noreturnDecision(dataRef);
                    if (decision.has_value()) return finish(*decision);
                }
                if (noretIat.count(dataRef)) return finish(true);
            }

            uint64_t target = 0;
            const bool direct = normalizedFlowTarget(bin, in, arch, targetAlignment, target,
                                                     &skippedInterworkingTargets);
            if (call) {
                if (direct && proveNoreturn(target, depth + 1)) return finish(true);
            } else if (ret) {
                return finish(false);
            } else if (switchTransfer || (InstructionEndsBlock(in) && !uncond)) {
                return finish(false);
            } else if (uncond) {
                return finish(direct && proveNoreturn(target, depth + 1));
            }

            pc = afterTransfer;
        }
        return finish(false);
    };

    auto isNoreturnTransfer = [&](const Instruction& in) -> bool {
        const bool transfer = InstructionIsCall(in) || isUnconditionalTransfer(in);
        uint64_t dataRef = 0;
        const bool dataRefValid = TryGetInstrDataRef(in, dataRef);
        if (transfer && dataRefValid) {
            if (noreturnDecision) {
                const std::optional<bool> decision = noreturnDecision(dataRef);
                if (decision.has_value()) return *decision;
            }
            if (noretIat.count(dataRef)) return true;
        }
        uint64_t target = 0;
        return transfer && normalizedFlowTarget(bin, in, arch, targetAlignment, target,
                                                &skippedInterworkingTargets) &&
               proveNoreturn(target, 1);
    };
    constexpr size_t kGlobalReachabilityInstructionCap = 4u * 1024u * 1024u;
    const size_t perFunctionLimit = std::max<size_t>(1, maxInstrPerFunc);
    const auto makePassBudget = [&] {
        if (!maxFunctions) return size_t{0};
        if (maxFunctions > kGlobalReachabilityInstructionCap / perFunctionLimit)
            return kGlobalReachabilityInstructionCap;
        return std::min(kGlobalReachabilityInstructionCap,
                        maxFunctions * perFunctionLimit);
    };

    // First pass discovers direct callees from every reachable block. A direct
    // branch is an intra-function edge unless it targets an already admitted
    // function root; calls always create roots and retain caller fallthrough.
    size_t discoveryBudget = makePassBudget();
    bool discoveryTruncated = false;
    std::unordered_map<uint64_t, FunctionBoundaryConfidence> scanned;
    while (!work.empty() && !cancelled_) {
        if (cancelled && cancelled()) { cancelled_ = true; break; }
        const uint64_t fn = work.back();
        work.pop_back();
        const FunctionBoundaryConfidence callerConfidence =
            boundaryConfidence.count(fn) ? boundaryConfidence[fn]
                                         : FunctionBoundaryConfidence::Heuristic;
        if (auto it = scanned.find(fn); it != scanned.end() &&
            confidenceRank(it->second) >= confidenceRank(callerConfidence))
            continue;
        scanned[fn] = callerConfidence;
        ReachableBody body = walkReachableBody(
            bin, dis, arch, fn, exactBoundaries, armLiteralSpans, perFunctionLimit,
            discoveryBudget, cancelled, isNoreturnTransfer,
            [&](uint64_t target) {
                admitStart(target, FunctionSeedKind::ReachedCall,
                           callerConfidence == FunctionBoundaryConfidence::Heuristic
                               ? FunctionBoundaryConfidence::Heuristic
                               : FunctionBoundaryConfidence::Reconciled);
            },
            resolveTable,
            &skippedInterworkingTargets);
        discoveryTruncated = discoveryTruncated || body.truncated;
        if (body.cancelled) { cancelled_ = true; break; }
        if (!discoveryBudget && !work.empty()) { discoveryTruncated = true; break; }
    }

    // Second pass computes final ownership against the complete start set.
    // Loader extents retain their exact legacy size; heuristic functions expose
    // the entry chunk in size and every separated range through chunks.
    std::vector<uint64_t> sorted(starts.begin(), starts.end());
    out.reserve(sorted.size());
    size_t ownershipBudget = makePassBudget();
    size_t nonContiguousFunctions = 0;
    size_t truncatedOwnerships = 0;
    for (uint64_t start : sorted) {
        DiscoveredFunction f;
        f.address = start;
        ReachableBody body;
        if (!cancelled_ && ownershipBudget) {
            body = walkReachableBody(bin, dis, arch, start, exactBoundaries, armLiteralSpans,
                                     perFunctionLimit, ownershipBudget, cancelled,
                                     isNoreturnTransfer, {}, resolveTable,
                                     &skippedInterworkingTargets);
            if (body.cancelled) cancelled_ = true;
        } else if (!cancelled_) {
            body.truncated = true;
        } else {
            body.cancelled = true;
        }
        f.chunks = std::move(body.chunks);
        f.ownershipTruncated = body.truncated || body.cancelled;
        if (auto confidence = boundaryConfidence.find(f.address);
            confidence != boundaryConfidence.end())
            f.boundaryConfidence = confidence->second;
        if (auto kind = seedKinds.find(f.address); kind != seedKinds.end())
            f.seedKind = kind->second;
        if (f.ownershipTruncated) ++truncatedOwnerships;
        if (auto h = sizeHint.find(f.address); h != sizeHint.end())
            f.size = (uint32_t)std::min<uint64_t>(h->second, 0x100000);
        else {
            for (const FunctionChunk& chunk : f.chunks) {
                if (chunk.address == f.address) { f.size = chunk.size; break; }
            }
        }
        // Authoritative loader extents describe ownership even when recursive
        // decoding stops early at a return. Keep the reachable chunks (useful
        // evidence) and add the exact declared range; coalesce below.
        if (auto h = sizeHint.find(f.address); h != sizeHint.end() && h->second) {
            const uint64_t bounded = std::min<uint64_t>(h->second, 0x100000);
            uint64_t declaredEnd = 0;
            if (CheckedAddressAdd(f.address, bounded, declaredEnd)) {
                size_t mapped = executableBytesAvailable(bin, f.address);
                uint64_t exact = std::min<uint64_t>(bounded, mapped);
                // A second authoritative start inside a malformed/overlapping
                // loader extent remains a hard ownership boundary. Overlapping
                // instruction streams without an extent are still retained.
                const auto nextBoundary = exactBoundaries.upper_bound(f.address);
                if (nextBoundary != exactBoundaries.end() && *nextBoundary < declaredEnd)
                    exact = std::min<uint64_t>(exact, *nextBoundary - f.address);
                if (exact) f.chunks.push_back({f.address, static_cast<uint32_t>(exact)});
            }
        }
        if (f.chunks.size() > 1) {
            std::sort(f.chunks.begin(), f.chunks.end(), [](const FunctionChunk& a,
                                                           const FunctionChunk& b) {
                return a.address < b.address;
            });
            std::vector<FunctionChunk> merged;
            for (const FunctionChunk& chunk : f.chunks) {
                if (!chunk.size) continue;
                if (!merged.empty()) {
                    uint64_t previousEnd = 0, chunkEnd = 0;
                    const bool previousOk = CheckedAddressAdd(merged.back().address,
                                                               merged.back().size,
                                                               previousEnd);
                    const bool chunkOk = CheckedAddressAdd(chunk.address, chunk.size, chunkEnd);
                    if (previousOk && chunkOk && chunk.address <= previousEnd) {
                        const uint64_t joinedEnd = std::max(previousEnd, chunkEnd);
                        merged.back().size = static_cast<uint32_t>(joinedEnd - merged.back().address);
                        continue;
                    }
                }
                merged.push_back(chunk);
            }
            f.chunks = std::move(merged);
        }
        if (f.chunks.size() > 1) ++nonContiguousFunctions;
        f.noreturn = !cancelled_ && proveNoreturn(f.address, 0);
        auto it = nameMap.find(f.address);
        if (it != nameMap.end()) { f.name = it->second; f.isExport = true; }
        else {
            char b[32]; std::snprintf(b, sizeof(b), "sub_%llX", (unsigned long long)f.address);
            f.name = b;
        }
        out.push_back(std::move(f));
    }

    char sum[360];
    std::snprintf(sum, sizeof(sum),
                  "%zu functions (%zu high-confidence seeds incl. %zu pdata/%zu ELF sized, %zu total seeds; %zu non-contiguous) via %s",
                  out.size(), loaderSeedCount, pdataCount, elfSizeHints, seeds.size(),
                  nonContiguousFunctions, dis.engineName());
    summary_ = sum;
    if (discoveryTruncated) summary_ += "; reachable-call discovery truncated at its instruction cap";
    if (truncatedOwnerships)
        summary_ += "; " + std::to_string(truncatedOwnerships) +
                    " function ownership traversal(s) truncated";
    if (prologueTruncated_)
        summary_ += "; prologue scan truncated after " +
                    std::to_string(prologueCandidates_) + " candidate(s)/" +
                    std::to_string(prologueBytesScanned_) + " byte(s)";
    if (cancelled_) summary_ += "; function analysis cancelled";
    if (!skippedInterworkingTargets.empty())
        summary_ += "; skipped " + std::to_string(skippedInterworkingTargets.size()) +
                    " ARM/Thumb interworking target(s) in fixed decoder mode";
    return out;
}

} // namespace ds
