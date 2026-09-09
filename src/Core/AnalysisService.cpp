//
// AnalysisService.cpp — see AnalysisService.h.
//
#include "AnalysisService.h"
#include "ApiDatabase.h"
#include "BinaryFile.h"
#include "CodeByteSignatureBuilder.h"
#include "Project.h"
#include "JumpTableResolver.h"
#include "FuncAnnotate.h"
#include "AuthorizationPatchAdvisor.h"
#include "AuthorizationFieldAlias.h"
#include "MachineIdentityApiCatalog.h"
#include "PersistentStateCatalog.h"
#include "ValidationApiCatalog.h"
#include "VerificationApiCatalog.h"
#include "SynthesisJob.h"     // K_Synthesis (F1)
#include "PathExploreJob.h"   // K_PathExplore (F3, static)
#include "../Disasm/JvmDisassembler.h"   // AttachJvmClass (JavaClass symbolication)
#include "../Disasm/GmlDisassembler.h"
#include "InstructionReference.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <limits>
#include <set>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

namespace ds {

namespace {

static bool mappedSpan(const BinaryFile& bin, uint64_t address, uint64_t size) {
    if (!size || address > UINT64_MAX - size) return false;
    size_t available = 0;
    return bin.ptrFromVA(address, available) && size <= static_cast<uint64_t>(available);
}

static NoreturnCallResolver
noreturnResolver(const BinaryFile* bin,
                 std::shared_ptr<const ProjectAnalysisOverrides> overrides,
                 std::shared_ptr<const std::vector<uint64_t>> inferredTargets = {},
                 const std::vector<FuncResult>* inferredFunctions = nullptr) {
    auto targets = std::make_shared<std::vector<uint64_t>>();
    auto forcedReturning = std::make_shared<std::vector<uint64_t>>();
    if (inferredTargets) *targets = *inferredTargets;
    if (inferredFunctions)
        for (const FuncResult& function : *inferredFunctions)
            if (function.noreturnValid && function.noreturn)
                targets->push_back(function.address);
    if (bin) {
        for (const BinaryFile::Import& item : bin->imports())
            if (item.addressKnown && IsKnownNoreturnApi(item.name))
                targets->push_back(item.iatVA);
    }
    if (overrides) {
        targets->reserve(targets->size() + overrides->functions.size());
        forcedReturning->reserve(overrides->functions.size());
        for (const PjFunctionOverride& item : overrides->functions) {
            if (item.action != PjFunctionAction::Define) continue;
            if (item.noreturn == PjOverrideBool::True) targets->push_back(item.address);
            else if (item.noreturn == PjOverrideBool::False)
                forcedReturning->push_back(item.address);
        }
    }
    auto normalize = [](std::vector<uint64_t>& values) {
        std::sort(values.begin(), values.end());
        values.erase(std::unique(values.begin(), values.end()), values.end());
    };
    normalize(*targets);
    normalize(*forcedReturning);
    if (targets->empty()) return {};
    return [targets = std::move(targets), forcedReturning = std::move(forcedReturning)](
               uint64_t target) {
        if (std::binary_search(forcedReturning->begin(), forcedReturning->end(), target))
            return false;
        return std::binary_search(targets->begin(), targets->end(), target);
    };
}

static std::string_view analystCallingConvention(
    const std::shared_ptr<const ProjectAnalysisOverrides>& overrides,
    uint64_t functionAddress) {
    if (!overrides) return {};
    for (const PjFunctionOverride& item : overrides->functions)
        if (item.address == functionAddress &&
            item.action == PjFunctionAction::Define)
            return item.callingConvention;
    return {};
}

static std::vector<uint64_t>
analystFunctionSeeds(const BinaryFile& bin,
                     const std::shared_ptr<const ProjectAnalysisOverrides>& overrides) {
    std::vector<uint64_t> seeds;
    if (!overrides) return seeds;
    seeds.reserve(overrides->functions.size());
    for (const PjFunctionOverride& item : overrides->functions) {
        size_t ignored = 0;
        if (item.action == PjFunctionAction::Define &&
            bin.ptrFromVA(item.address, ignored))
            seeds.push_back(item.address);
    }
    std::sort(seeds.begin(), seeds.end());
    seeds.erase(std::unique(seeds.begin(), seeds.end()), seeds.end());
    return seeds;
}

static FunctionNoreturnDecisionResolver analystNoreturnDecisions(
    const std::shared_ptr<const ProjectAnalysisOverrides>& overrides) {
    if (!overrides) return {};
    auto decisions = std::make_shared<std::vector<std::pair<uint64_t, bool>>>();
    decisions->reserve(overrides->functions.size());
    for (const PjFunctionOverride& item : overrides->functions) {
        if (item.action != PjFunctionAction::Define ||
            item.noreturn == PjOverrideBool::Unspecified)
            continue;
        decisions->push_back({item.address, item.noreturn == PjOverrideBool::True});
    }
    std::stable_sort(decisions->begin(), decisions->end(),
                     [](const auto& a, const auto& b) { return a.first < b.first; });
    decisions->erase(std::unique(decisions->begin(), decisions->end(),
                                 [](const auto& a, const auto& b) {
                                     return a.first == b.first;
                                 }), decisions->end());
    if (decisions->empty()) return {};
    return [decisions = std::move(decisions)](uint64_t target) -> std::optional<bool> {
        auto it = std::lower_bound(decisions->begin(), decisions->end(), target,
                                   [](const auto& item, uint64_t address) {
                                       return item.first < address;
                                   });
        if (it == decisions->end() || it->first != target) return std::nullopt;
        return it->second;
    };
}

static void applyFunctionOverrides(const BinaryFile& bin,
                                   const ProjectAnalysisOverrides& overrides,
                                   std::vector<FuncResult>& functions) {
    if (overrides.functions.empty()) return;
    for (const PjFunctionOverride& decision : overrides.functions) {
        auto it = std::find_if(functions.begin(), functions.end(), [&](const FuncResult& fn) {
            return fn.address == decision.address;
        });
        if (decision.action == PjFunctionAction::Undefine) {
            if (it != functions.end()) functions.erase(it);
            continue;
        }

        // A stale project coordinate must not manufacture an unmapped function.
        size_t ignored = 0;
        if (!bin.ptrFromVA(decision.address, ignored)) continue;
        if (it == functions.end()) {
            char name[32];
            std::snprintf(name, sizeof(name), "sub_%llX",
                          static_cast<unsigned long long>(decision.address));
            functions.push_back({ decision.address, 0, name, false,
                                  "authoritative analyst definition", false });
            it = std::prev(functions.end());
        }
        it->guessed = false;
        it->reason = "authoritative analyst definition";
        it->analystDefined = true;
        it->seedKind = FunctionSeedKind::Analyst;
        it->boundaryConfidence = FunctionBoundaryConfidence::Authoritative;
        it->noreturnValid = decision.noreturn != PjOverrideBool::Unspecified;
        it->noreturn = decision.noreturn == PjOverrideBool::True;
        it->analystMode = decision.mode == PjFunctionMode::ARM ? 1
                          : decision.mode == PjFunctionMode::Thumb ? 2 : 0;
        it->callingConvention = decision.callingConvention;
        it->prototype = decision.prototype;
        if (decision.exactExtentValid && mappedSpan(bin, decision.address, decision.exactSize))
            it->size = static_cast<uint32_t>(decision.exactSize);
        if (decision.exactExtentValid && mappedSpan(bin, decision.address, decision.exactSize))
            it->chunks = {{decision.address, static_cast<uint32_t>(decision.exactSize)}};
    }
    std::sort(functions.begin(), functions.end(), [](const FuncResult& a, const FuncResult& b) {
        return a.address < b.address;
    });
}

// Pass-input digests are produced on a worker from immutable request snapshots.
// They are deliberately framed and deterministic even for unordered maps.
class PassDigest {
public:
    void u8(uint8_t value) { byte(value); }
    void u32(uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) byte(static_cast<uint8_t>(value >> (i * 8)));
    }
    void u64(uint64_t value) {
        for (unsigned i = 0; i < 8; ++i) byte(static_cast<uint8_t>(value >> (i * 8)));
    }
    void text(std::string_view value) {
        u64(static_cast<uint64_t>(value.size()));
        for (unsigned char ch : value) byte(ch);
    }
    uint64_t finish() const { return value_; }

private:
    void byte(uint8_t value) {
        value_ ^= value;
        value_ *= 1099511628211ull;
    }
    uint64_t value_ = 1469598103934665603ull;
};

// contentHash() intentionally identifies pristine file bytes only.  Every
// cached static pass also carries VAs, so reopening identical Raw bytes at a
// different base/entry/landmark set (or changing a loader's section mapping)
// must form a distinct service-cache identity.
static uint64_t binaryMappingInputsDigest(const BinaryFile& binary) {
    PassDigest digest;
    digest.u8(static_cast<uint8_t>(binary.format()));
    digest.u8(binary.isMappedImage() ? 1u : 0u);
    digest.u64(binary.imageBase());
    digest.u8(binary.hasEntryPoint() ? 1u : 0u);
    digest.u64(binary.entryPoint());
    digest.u64(binary.hasEntryPoint() ? binary.entryPointVA() : 0);
    digest.u8(binary.rawEntryExplicit() ? 1u : 0u);
    digest.u64(binary.overlayOffset());
    digest.u64(binary.overlaySize());

    digest.u64(static_cast<uint64_t>(binary.sections().size()));
    for (const Section& section : binary.sections()) {
        digest.text(section.name);
        digest.u64(section.virtualAddress);
        digest.u64(section.virtualSize);
        digest.u64(section.rawOffset);
        digest.u64(section.rawSize);
        digest.u32(section.characteristics);
        digest.u8(section.executable ? 1u : 0u);
    }

    digest.u64(static_cast<uint64_t>(binary.analysisLandmarks().size()));
    for (const AnalysisLandmark& landmark : binary.analysisLandmarks()) {
        digest.u64(landmark.address);
        digest.text(landmark.name);
        digest.text(landmark.evidence);
    }
    return digest.finish();
}

static uint64_t listingInputsDigest(const ListingLayout* layout,
                                    const std::vector<StrResult>& strings,
                                    const CodeDataMap* codeData) {
    PassDigest digest;
    digest.u8(layout ? 1u : 0u);
    if (layout) {
        digest.u8(layout->peHeaderVisible ? 1u : 0u);
        digest.u8(layout->peHeaderFolded ? 1u : 0u);
        digest.u64(static_cast<uint64_t>(layout->sections.size()));
        for (const ListingSectionState& section : layout->sections) {
            digest.u64(section.rva);
            digest.text(section.name);
            digest.u8(section.visible ? 1u : 0u);
            digest.u8(section.folded ? 1u : 0u);
        }
    }
    digest.u64(static_cast<uint64_t>(strings.size()));
    for (const StrResult& string : strings) {
        digest.u64(string.address);
        digest.text(string.text);
        digest.u8(string.wide ? 1u : 0u);
        digest.u8(string.textTruncated ? 1u : 0u);
    }
    digest.u8(codeData ? 1u : 0u);
    if (codeData) {
        // imageRevision is a transient object generation, not semantic input.
        digest.u64(static_cast<uint64_t>(codeData->spans.size()));
        for (const CodeDataSpan& span : codeData->spans) {
            digest.u64(span.address);
            digest.u64(span.size);
            digest.u8(static_cast<uint8_t>(span.kind));
            digest.u8(span.elementWidth);
            digest.u8(static_cast<uint8_t>(span.confidence));
            digest.text(span.evidence);
        }
    }
    digest.u64(kDefaultListingDataByteCap);
    return digest.finish();
}

static uint64_t listingPrefixInputsDigest(uint64_t startVA, uint64_t pageBase,
                                          uint64_t targetPage) {
    PassDigest digest;
    digest.u64(startVA);
    digest.u64(pageBase);
    digest.u64(targetPage);
    digest.u64(kListingPrefixExactByteCap);
    return digest.finish();
}

static uint64_t functionInputsDigest(const std::vector<FuncResult>& functions) {
    PassDigest digest;
    digest.u64(static_cast<uint64_t>(functions.size()));
    for (const FuncResult& function : functions) {
        digest.u64(function.address);
        digest.u32(function.size);
        digest.text(function.name);
        digest.u8(function.guessed ? 1u : 0u);
        digest.u8(function.isExport ? 1u : 0u);
        digest.u8(function.analystDefined ? 1u : 0u);
        digest.u8(static_cast<uint8_t>(function.seedKind));
        digest.u8(static_cast<uint8_t>(function.boundaryConfidence));
        digest.u8(function.ownershipTruncated ? 1u : 0u);
        digest.u64(static_cast<uint64_t>(function.chunks.size()));
        for (const FunctionChunk& chunk : function.chunks) {
            digest.u64(chunk.address);
            digest.u32(chunk.size);
        }
    }
    return digest.finish();
}

static uint64_t xrefInputsDigest(const XrefIndex* xref) {
    PassDigest digest;
    digest.u8(xref ? 1u : 0u);
    if (!xref) return digest.finish();
    digest.u8(xref->complete ? 1u : 0u);
    digest.u8(static_cast<uint8_t>(xref->stopReason));
    digest.u64(xref->bytesSwept);
    digest.u64(xref->decodeAttempts);
    digest.u64(xref->acceptedEdges);
    digest.u8(xref->classificationApplied ? 1u : 0u);
    digest.u8(xref->classificationTruncated ? 1u : 0u);
    digest.u64(xref->classificationScopeDigest);
    digest.u64(xref->classificationDataBytes);
    std::vector<uint64_t> targets;
    targets.reserve(xref->toTarget.size());
    for (const auto& item : xref->toTarget) targets.push_back(item.first);
    std::sort(targets.begin(), targets.end());
    digest.u64(static_cast<uint64_t>(targets.size()));
    for (uint64_t target : targets) {
        digest.u64(target);
        const auto found = xref->toTarget.find(target);
        if (found == xref->toTarget.end()) { digest.u64(0); continue; }
        digest.u64(static_cast<uint64_t>(found->second.size()));
        for (uint64_t source : found->second) {
            digest.u64(source);
            digest.u8(xref->access(source));
        }
    }
    return digest.finish();
}

static uint64_t xrefPolicyDigest() {
    PassDigest digest;
    // Schema marker: v3 suppresses ambiguous bare-immediate zero while
    // preserving explicit VA-zero memory and direct-control-flow references.
    digest.u64(4); // classification-aware scope and authoritative static references
    digest.u64(kDefaultXrefByteBudget);
    digest.u64(kDefaultXrefDecodeBudget);
    digest.u64(static_cast<uint64_t>(kDefaultXrefEdgeBudget));
    digest.u64(static_cast<uint64_t>(kDefaultXrefTargetBudget));
    return digest.finish();
}

static uint64_t noreturnInputsDigest(const std::vector<uint64_t>* targets) {
    PassDigest digest;
    // The resolver treats this snapshot as a set. Equivalent discovery order
    // and duplicate entries must retain the same derived-result identity.
    std::vector<uint64_t> ordered;
    if (targets) ordered = *targets;
    std::sort(ordered.begin(), ordered.end());
    ordered.erase(std::unique(ordered.begin(), ordered.end()), ordered.end());
    digest.u64(static_cast<uint64_t>(ordered.size()));
    for (uint64_t target : ordered) digest.u64(target);
    return digest.finish();
}

static uint64_t decompileInputsDigest(uint64_t lo, uint64_t hi,
                                      const DecompileNameMap* names,
                                      std::string_view signature,
                                      const std::vector<FunctionChunk>* chunks,
                                      bool ownershipTruncated,
                                      const std::vector<uint64_t>* noreturnTargets) {
    PassDigest digest;
    digest.u64(lo);
    digest.u64(hi);
    digest.text(signature);
    digest.u8(ownershipTruncated ? 1 : 0);
    digest.u64(chunks ? static_cast<uint64_t>(chunks->size()) : 0);
    if (chunks) for (const FunctionChunk& chunk : *chunks) {
        digest.u64(chunk.address);
        digest.u64(chunk.size);
    }
    digest.u64(noreturnInputsDigest(noreturnTargets));
    std::vector<std::pair<uint64_t, std::string_view>> ordered;
    if (names) {
        ordered.reserve(names->size());
        for (const auto& name : *names) ordered.emplace_back(name.first, name.second);
        std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
            if (a.first != b.first) return a.first < b.first;
            return a.second < b.second;
        });
    }
    digest.u64(static_cast<uint64_t>(ordered.size()));
    for (const auto& name : ordered) {
        digest.u64(name.first);
        digest.text(name.second);
    }
    return digest.finish();
}

static std::string authorizationLower(std::string value) {
    for (char& c : value)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

static std::string authorizationExpressionKey(std::string value) {
    value = authorizationLower(std::move(value));
    static constexpr std::string_view decorators[] = {
        // Longest first: "word ptr" is a suffix of dword/qword/xmmword.
        "xmmword ptr", "qword ptr", "dword ptr", "word ptr", "byte ptr"
    };
    for (std::string_view decorator : decorators) {
        const size_t at = value.find(decorator);
        if (at != std::string::npos) value.erase(at, decorator.size());
    }
    value.erase(std::remove_if(value.begin(), value.end(), [](char c) {
        return std::isspace(static_cast<unsigned char>(c)) != 0;
    }), value.end());
    // Register width aliases describe the same pointer/value lineage for this
    // bounded x86/x64 adapter. Memory expressions remain textually exact.
    if (value.find('[') == std::string::npos) {
        static constexpr std::pair<std::string_view, std::string_view> aliases[] = {
            {"eax", "rax"}, {"ax", "rax"}, {"al", "rax"}, {"ah", "rax"},
            {"ebx", "rbx"}, {"bx", "rbx"}, {"bl", "rbx"}, {"bh", "rbx"},
            {"ecx", "rcx"}, {"cx", "rcx"}, {"cl", "rcx"}, {"ch", "rcx"},
            {"edx", "rdx"}, {"dx", "rdx"}, {"dl", "rdx"}, {"dh", "rdx"},
            {"esi", "rsi"}, {"si", "rsi"}, {"sil", "rsi"},
            {"edi", "rdi"}, {"di", "rdi"}, {"dil", "rdi"},
            {"ebp", "rbp"}, {"bp", "rbp"}, {"bpl", "rbp"},
            {"esp", "rsp"}, {"sp", "rsp"}, {"spl", "rsp"},
            {"r8d", "r8"}, {"r8w", "r8"}, {"r8b", "r8"},
            {"r9d", "r9"}, {"r9w", "r9"}, {"r9b", "r9"},
            {"r10d", "r10"}, {"r10w", "r10"}, {"r10b", "r10"},
            {"r11d", "r11"}, {"r11w", "r11"}, {"r11b", "r11"},
            {"r12d", "r12"}, {"r12w", "r12"}, {"r12b", "r12"},
            {"r13d", "r13"}, {"r13w", "r13"}, {"r13b", "r13"},
            {"r14d", "r14"}, {"r14w", "r14"}, {"r14b", "r14"},
            {"r15d", "r15"}, {"r15w", "r15"}, {"r15b", "r15"},
        };
        for (const auto& [alias, canonical] : aliases)
            if (value == alias) return std::string(canonical);
    }
    return value;
}

static std::vector<std::string> authorizationSplitOperands(std::string_view text) {
    std::vector<std::string> result;
    size_t start = 0;
    int brackets = 0;
    for (size_t i = 0; i <= text.size(); ++i) {
        const char c = i < text.size() ? text[i] : ',';
        if (c == '[' || c == '(') ++brackets;
        else if ((c == ']' || c == ')') && brackets > 0) --brackets;
        if (c != ',' || brackets != 0) continue;
        result.push_back(authorizationExpressionKey(
            std::string(text.substr(start, i - start))));
        start = i + 1;
    }
    return result;
}

static std::string authorizationRawOperand(std::string_view text, size_t wanted) {
    size_t start = 0;
    size_t ordinal = 0;
    int brackets = 0;
    for (size_t i = 0; i <= text.size(); ++i) {
        const char c = i < text.size() ? text[i] : ',';
        if (c == '[' || c == '(') ++brackets;
        else if ((c == ']' || c == ')') && brackets > 0) --brackets;
        if (c != ',' || brackets != 0) continue;
        if (ordinal++ == wanted) {
            std::string result(text.substr(start, i - start));
            while (!result.empty() && std::isspace(
                       static_cast<unsigned char>(result.front())))
                result.erase(result.begin());
            while (!result.empty() && std::isspace(
                       static_cast<unsigned char>(result.back())))
                result.pop_back();
            return authorizationLower(std::move(result));
        }
        start = i + 1;
    }
    return {};
}

static uint16_t authorizationRegisterWidthBits(std::string value) {
    value = authorizationLower(std::move(value));
    value.erase(std::remove_if(value.begin(), value.end(), [](char c) {
        return std::isspace(static_cast<unsigned char>(c)) != 0 || c == '%';
    }), value.end());
    static constexpr std::string_view r64[] = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    };
    static constexpr std::string_view r32[] = {
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"
    };
    static constexpr std::string_view r16[] = {
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"
    };
    static constexpr std::string_view r8[] = {
        "al", "ah", "bl", "bh", "cl", "ch", "dl", "dh",
        "sil", "dil", "bpl", "spl", "r8b", "r9b", "r10b", "r11b",
        "r12b", "r13b", "r14b", "r15b"
    };
    auto contains = [&](const auto& values) {
        return std::find(std::begin(values), std::end(values), value) !=
               std::end(values);
    };
    if (contains(r64)) return 64;
    if (contains(r32)) return 32;
    if (contains(r16)) return 16;
    if (contains(r8)) return 8;
    return 0;
}

static uint16_t authorizationOperandWidthBits(const Instruction& instruction,
                                              size_t operandIndex) {
    if (operandIndex < instruction.typedOperands.size() &&
        instruction.typedOperands[operandIndex].widthBits)
        return instruction.typedOperands[operandIndex].widthBits;
    const std::string raw = authorizationRawOperand(instruction.operands,
                                                    operandIndex);
    if (raw.empty()) return 0;
    if (raw.find("xmmword ptr") != std::string::npos) return 128;
    if (raw.find("qword ptr") != std::string::npos) return 64;
    if (raw.find("dword ptr") != std::string::npos) return 32;
    if (raw.find("word ptr") != std::string::npos) return 16;
    if (raw.find("byte ptr") != std::string::npos) return 8;
    if (raw.find('[') == std::string::npos)
        return authorizationRegisterWidthBits(raw);
    return 0;
}

static std::string authorizationOutputStorageExpression(
    const ApiArgumentObservation* argument) {
    if (!argument || !argument->sourceIsAddress) return {};
    std::string expression = authorizationExpressionKey(
        argument->sourceExpression.empty()
            ? argument->renderedValue
            : argument->sourceExpression);
    if (expression.find('[') != std::string::npos) return expression;
    if (authorizationRegisterWidthBits(expression) != 0)
        return '[' + expression + ']';
    if (argument->referencedAddressValid)
        return "va:" + std::to_string(argument->referencedAddress);
    if (argument->immediateValid && argument->immediate != 0)
        return "va:" + std::to_string(argument->immediate);
    return {};
}

static bool authorizationTokenContains(std::string_view expression,
                                       std::string_view token) {
    if (token.empty() || expression.size() < token.size()) return false;
    size_t at = expression.find(token);
    while (at != std::string_view::npos) {
        const auto identifier = [](char c) {
            const unsigned char value = static_cast<unsigned char>(c);
            return std::isalnum(value) || c == '_';
        };
        const bool left = at == 0 || !identifier(expression[at - 1]);
        const size_t end = at + token.size();
        const bool right = end == expression.size() || !identifier(expression[end]);
        if (left && right) return true;
        at = expression.find(token, at + 1);
    }
    return false;
}

static bool authorizationExpressionTainted(
    std::string_view expression,
    const std::set<std::string>& tainted) {
    if (expression.empty()) return false;
    if (tainted.count(std::string(expression))) return true;
    for (const std::string& origin : tainted) {
        if (origin.empty() || origin.find('[') != std::string::npos) continue;
        if (authorizationTokenContains(expression, origin)) return true;
    }
    return false;
}

static bool authorizationExpressionUsesTaintedAddress(
    std::string_view expression,
    const std::set<std::string>& tainted) {
    if (expression.find('[') == std::string_view::npos) return false;
    for (const std::string& origin : tainted) {
        if (origin.empty() || origin.find('[') != std::string::npos) continue;
        if (authorizationTokenContains(expression, origin)) return true;
    }
    return false;
}

static bool authorizationConditionalBranch(const Instruction& instruction) {
    if (instruction.flow.kind == FlowKind::ConditionalBranch) return true;
    if (!instruction.isBranch || instruction.isCall || instruction.isRet) return false;
    const std::string mnemonic = authorizationLower(instruction.mnemonic);
    return mnemonic.size() > 1 && mnemonic.front() == 'j' && mnemonic != "jmp";
}

static void authorizationApplyLineageInstruction(
    const Instruction& instruction,
    std::set<std::string>& tainted) {
    const std::string mnemonic = authorizationLower(instruction.mnemonic);
    const std::vector<std::string> operands =
        authorizationSplitOperands(instruction.operands);
    if ((mnemonic == "mov" || mnemonic == "movzx" || mnemonic == "movsx" ||
         mnemonic == "movsxd" || mnemonic == "lea") && operands.size() >= 2) {
        const bool sourceTainted = authorizationExpressionTainted(operands[1], tainted);
        if (sourceTainted) tainted.insert(operands[0]);
        else tainted.erase(operands[0]);
    } else if (mnemonic == "xchg" && operands.size() == 2) {
        const bool left = authorizationExpressionTainted(operands[0], tainted);
        const bool right = authorizationExpressionTainted(operands[1], tainted);
        if (right) tainted.insert(operands[0]); else tainted.erase(operands[0]);
        if (left) tainted.insert(operands[1]); else tainted.erase(operands[1]);
    } else if ((mnemonic == "xor" || mnemonic == "sub") && operands.size() == 2 &&
               operands[0] == operands[1]) {
        tainted.erase(operands[0]);
    } else if (mnemonic == "pop" && !operands.empty()) {
        tainted.erase(operands[0]);
    }

    if (instruction.isCall) {
        static constexpr std::string_view volatileRegisters[] = {
            "rax", "rcx", "rdx", "r8", "r9", "r10", "r11"
        };
        for (std::string_view reg : volatileRegisters)
            tainted.erase(std::string(reg));
    }
}

// Reply-buffer lineage distinguishes values loaded from the cataloged output
// storage from addresses that merely point at that storage.  The generic
// scalar helper above intentionally treats LEA like a copy; that is useful for
// address lineage, but would let `lea rax, [reply]; test rax, rax` masquerade as
// a reply-content decision.
static bool authorizationReplyContentExpression(
    std::string_view expression,
    const std::set<std::string>& content,
    const std::set<std::string>& pointers) {
    if (expression.empty()) return false;
    const std::string key = authorizationExpressionKey(std::string(expression));
    if (content.count(key)) return true;
    return key.find('[') != std::string::npos &&
           authorizationExpressionUsesTaintedAddress(key, pointers);
}

static void authorizationApplyReplyLineageInstruction(
    const Instruction& instruction,
    std::set<std::string>& content,
    std::set<std::string>& pointers) {
    const std::string mnemonic = authorizationLower(instruction.mnemonic);
    const std::vector<std::string> operands =
        authorizationSplitOperands(instruction.operands);
    const auto clear = [&](const std::string& destination) {
        content.erase(destination);
        pointers.erase(destination);
    };

    if ((mnemonic == "mov" || mnemonic == "movzx" ||
         mnemonic == "movsx" || mnemonic == "movsxd") &&
        operands.size() >= 2) {
        const bool sourceContent = authorizationReplyContentExpression(
            operands[1], content, pointers);
        // Width-changing loads preserve reply-content provenance, but not a
        // pointer value whose width/meaning was changed.
        const bool sourcePointer = mnemonic == "mov" &&
                                   pointers.count(operands[1]) != 0;
        clear(operands[0]);
        if (sourceContent) content.insert(operands[0]);
        else if (sourcePointer) pointers.insert(operands[0]);
    } else if (mnemonic == "lea" && operands.size() >= 2) {
        // LEA constructs an address.  It may propagate a pointer within the
        // recovered reply window, but never turns that address into content.
        const bool pointsAtReply = content.count(operands[1]) != 0 ||
            authorizationExpressionUsesTaintedAddress(operands[1], pointers);
        clear(operands[0]);
        if (pointsAtReply) pointers.insert(operands[0]);
    } else if (mnemonic == "xchg" && operands.size() == 2) {
        const bool leftContent = authorizationReplyContentExpression(
            operands[0], content, pointers);
        const bool rightContent = authorizationReplyContentExpression(
            operands[1], content, pointers);
        const bool leftPointer = pointers.count(operands[0]) != 0;
        const bool rightPointer = pointers.count(operands[1]) != 0;
        clear(operands[0]);
        clear(operands[1]);
        if (rightContent) content.insert(operands[0]);
        else if (rightPointer) pointers.insert(operands[0]);
        if (leftContent) content.insert(operands[1]);
        else if (leftPointer) pointers.insert(operands[1]);
    } else if ((mnemonic == "xor" || mnemonic == "sub") &&
               operands.size() == 2 && operands[0] == operands[1]) {
        clear(operands[0]);
    } else if (mnemonic == "pop" && !operands.empty()) {
        clear(operands[0]);
    }

    if (instruction.isCall) {
        static constexpr std::string_view volatileRegisters[] = {
            "rax", "rcx", "rdx", "r8", "r9", "r10", "r11"
        };
        for (std::string_view reg : volatileRegisters) {
            content.erase(std::string(reg));
            pointers.erase(std::string(reg));
        }
    }
}

static std::vector<std::string> authorizationReturnDestinations(
    const ApiCallObservation& observation) {
    std::vector<std::string> result;
    if (observation.returnUseKind != ApiReturnUseKind::Stored &&
        observation.returnUseKind != ApiReturnUseKind::Propagated)
        return result;
    const std::string instruction = authorizationLower(
        observation.returnUseInstruction);
    const size_t space = instruction.find(' ');
    if (space == std::string::npos) return result;
    const std::string mnemonic = instruction.substr(0, space);
    const std::vector<std::string> operands =
        authorizationSplitOperands(instruction.substr(space + 1));
    if (operands.empty()) return result;
    if (mnemonic == "push") {
        // FuncAnnotate's x86 argument recovery retains the pushed source
        // expression, so keeping the ABI return alias is useful and bounded.
        result.push_back(authorizationExpressionKey(operands[0]));
    } else {
        result.push_back(authorizationExpressionKey(operands[0]));
    }
    result.erase(std::remove_if(result.begin(), result.end(),
        [](const std::string& item) { return item.empty(); }), result.end());
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

static bool authorizationExpressionsShareLineage(
    const ControlFlowGraph& graph,
    uint64_t fromAddress,
    std::string fromExpression,
    uint64_t toAddress,
    std::string toExpression,
    size_t maxStates = 64) {
    fromExpression = authorizationExpressionKey(std::move(fromExpression));
    toExpression = authorizationExpressionKey(std::move(toExpression));
    if (fromExpression.empty() || toExpression.empty() || fromAddress > toAddress)
        return false;
    if (fromExpression == toExpression) return true;
    size_t firstBlock = graph.blocks.size();
    for (size_t i = 0; i < graph.blocks.size(); ++i) {
        const BasicBlock& block = graph.blocks[i];
        if (fromAddress >= block.start && fromAddress < block.end) {
            firstBlock = i;
            break;
        }
    }
    if (firstBlock >= graph.blocks.size()) return false;
    struct State { size_t block = 0; std::set<std::string> tainted; };
    std::deque<State> queue;
    queue.push_back({firstBlock, {fromExpression}});
    std::unordered_set<std::string> visited;
    size_t states = 0;
    while (!queue.empty() && states++ < maxStates) {
        State state = std::move(queue.front());
        queue.pop_front();
        if (state.block >= graph.blocks.size()) continue;
        std::string key = std::to_string(state.block);
        for (const std::string& value : state.tainted) key += '|' + value;
        if (!visited.insert(std::move(key)).second) continue;
        const BasicBlock& block = graph.blocks[state.block];
        for (const Instruction& instruction : block.insns) {
            if (state.block == firstBlock && instruction.address <= fromAddress) continue;
            if (instruction.address == toAddress)
                return authorizationExpressionTainted(toExpression, state.tainted);
            if (instruction.address > toAddress) break;
            authorizationApplyLineageInstruction(instruction, state.tainted);
        }
        for (size_t successor : block.succ)
            if (successor < graph.blocks.size())
                queue.push_back({successor, state.tainted});
    }
    return false;
}

static PersistentStateAccess authorizationCustomPersistenceHint(
    std::string name) {
    name = authorizationLower(std::move(name));
    if (const size_t bang = name.rfind('!'); bang != std::string::npos)
        name.erase(0, bang + 1);
    while (!name.empty() && (name.front() == '_' || name.front() == '@'))
        name.erase(name.begin());
    static constexpr std::string_view reads[] = {
        "load_license", "read_license", "load_config", "read_config",
        "load_state", "read_state", "load_token", "read_token",
        "load_credentials", "read_credentials", "read_registry", "read_file"
    };
    static constexpr std::string_view writes[] = {
        "save_license", "write_license", "save_config", "write_config",
        "save_state", "write_state", "save_token", "store_token",
        "save_credentials", "store_credentials", "write_registry", "write_file"
    };
    for (std::string_view value : reads)
        if (name == value) return PersistentStateAccess::Read;
    for (std::string_view value : writes)
        if (name == value) return PersistentStateAccess::Write;
    return PersistentStateAccess::Unknown;
}

static std::vector<std::string> authorizationArgumentExpressions(
    const ApiArgumentObservation& argument) {
    std::vector<std::string> result;
    if (!argument.sourceExpression.empty())
        result.push_back(authorizationExpressionKey(argument.sourceExpression));
    if (!argument.renderedValue.empty())
        result.push_back(authorizationExpressionKey(argument.renderedValue));
    if (argument.referencedAddressValid)
        result.push_back("va:" + std::to_string(argument.referencedAddress));
    result.erase(std::remove_if(result.begin(), result.end(),
        [](const std::string& value) { return value.empty(); }), result.end());
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

static std::vector<std::string> authorizationIncomingParameterExpressions(
    size_t argumentIndex, bool x64) {
    std::vector<std::string> result;
    if (x64) {
        static constexpr std::string_view registers[] = {"rcx", "rdx", "r8", "r9"};
        if (argumentIndex < std::size(registers))
            result.push_back(std::string(registers[argumentIndex]));
        else {
            const uint64_t offset = UINT64_C(0x28) +
                                    (argumentIndex - std::size(registers)) * 8;
            char stack[48]{};
            std::snprintf(stack, sizeof(stack), "[rsp+0x%llx]",
                          static_cast<unsigned long long>(offset));
            result.emplace_back(stack);
            // Conventional frame-pointer prologues add the saved RBP slot.
            std::snprintf(stack, sizeof(stack), "[rbp+0x%llx]",
                          static_cast<unsigned long long>(offset + 8));
            result.emplace_back(stack);
        }
    } else {
        const uint64_t stackOffset = UINT64_C(4) + argumentIndex * 4;
        const uint64_t frameOffset = UINT64_C(8) + argumentIndex * 4;
        char stack[48]{};
        std::snprintf(stack, sizeof(stack), "[esp+0x%llx]",
                      static_cast<unsigned long long>(stackOffset));
        result.emplace_back(stack);
        std::snprintf(stack, sizeof(stack), "[ebp+0x%llx]",
                      static_cast<unsigned long long>(frameOffset));
        result.emplace_back(stack);
    }
    result.push_back("arg" + std::to_string(argumentIndex + 1));
    for (std::string& value : result)
        value = authorizationExpressionKey(std::move(value));
    std::sort(result.begin(), result.end());
    result.erase(std::unique(result.begin(), result.end()), result.end());
    return result;
}

static const Instruction* authorizationNearbyConditionalBranch(
    const BasicBlock& block, size_t comparisonIndex) {
    const size_t stop = (std::min)(block.insns.size(), comparisonIndex + 5);
    for (size_t i = comparisonIndex + 1; i < stop; ++i) {
        const Instruction& instruction = block.insns[i];
        if (authorizationConditionalBranch(instruction)) return &instruction;
        const std::string mnemonic = authorizationLower(instruction.mnemonic);
        if (instruction.flagsWritten || instruction.isCall ||
            mnemonic == "cmp" || mnemonic == "test" ||
            mnemonic == "add" || mnemonic == "adc" ||
            mnemonic == "sub" || mnemonic == "sbb" ||
            mnemonic == "and" || mnemonic == "or" ||
            mnemonic == "xor" || mnemonic == "inc" ||
            mnemonic == "dec" || mnemonic == "imul" ||
            mnemonic == "mul" || mnemonic == "idiv" ||
            mnemonic == "div" || mnemonic == "shl" ||
            mnemonic == "sal" || mnemonic == "shr" ||
            mnemonic == "sar" || mnemonic == "rol" ||
            mnemonic == "ror" || mnemonic == "neg") break;
        if (instruction.isBranch) break;
    }
    return nullptr;
}

static bool authorizationReturnsInteger(const Instruction& instruction,
                                        uint64_t expected) {
    const std::string mnemonic = authorizationLower(instruction.mnemonic);
    if (mnemonic == "xor" && expected == 0) {
        std::vector<std::string> registers;
        for (const TypedOperand& operand : instruction.typedOperands) {
            if (operand.kind != OperandKind::Register) continue;
            registers.push_back(authorizationExpressionKey(
                operand.registerName));
        }
        if (registers.size() >= 2 && registers[0] == "rax" &&
            registers[0] == registers[1]) return true;
    }
    if (mnemonic == "mov") {
        bool writesReturn = false;
        bool hasImmediate = false;
        uint64_t immediate = 0;
        for (const TypedOperand& operand : instruction.typedOperands) {
            if (operand.kind == OperandKind::Register &&
                OperandWrites(operand.access) &&
                authorizationExpressionKey(operand.registerName) == "rax")
                writesReturn = true;
            if (operand.kind == OperandKind::Immediate) {
                hasImmediate = true;
                immediate = operand.immediate;
            }
        }
        if (writesReturn && hasImmediate) return immediate == expected;
    }

    // Compatibility for simple fixture/legacy decoders without typed operands.
    const std::vector<std::string> operands =
        authorizationSplitOperands(instruction.operands);
    if (mnemonic == "xor" && expected == 0 && operands.size() == 2)
        return operands[0] == "rax" && operands[1] == "rax";
    if (mnemonic != "mov" || operands.size() != 2 || operands[0] != "rax")
        return false;
    if (expected == 0) return operands[1] == "0" || operands[1] == "0x0";
    if (expected == 1) return operands[1] == "1" || operands[1] == "0x1";
    return false;
}

static AuthorizationLocation authorizationLocation(const BinaryFile& binary,
                                                    uint64_t address,
                                                    bool addressValid,
                                                    uint64_t functionAddress,
                                                    bool functionAddressValid,
                                                    const std::string& functionName) {
    AuthorizationLocation location;
    location.address = address;
    location.addressValid = addressValid;
    location.functionAddress = functionAddress;
    location.functionAddressValid = functionAddressValid;
    location.functionName = functionName;
    location.fileOffsetValid = addressValid &&
        binary.vaToOffset(address, location.fileOffset);
    return location;
}

static const BasicBlock* authorizationBlockForAddress(const ControlFlowGraph& graph,
                                                       uint64_t address) {
    for (const BasicBlock& block : graph.blocks)
        if (address >= block.start && address < block.end) return &block;
    return nullptr;
}

static uint64_t authorizationFallthrough(const ControlFlowGraph& graph,
                                         uint64_t decisionAddress,
                                         uint64_t branchTarget,
                                         bool& valid) {
    valid = false;
    for (const BasicBlock& block : graph.blocks) {
        bool owns = false;
        for (const Instruction& instruction : block.insns)
            if (instruction.address == decisionAddress) { owns = true; break; }
        if (!owns) continue;
        for (size_t successor : block.succ) {
            if (successor >= graph.blocks.size()) continue;
            const uint64_t candidate = graph.blocks[successor].start;
            if (candidate == branchTarget) continue;
            valid = true;
            return candidate;
        }
        for (const Instruction& instruction : block.insns) {
            if (instruction.address != decisionAddress || !instruction.length) continue;
            valid = instruction.address <= UINT64_MAX - instruction.length;
            return valid ? instruction.address + instruction.length : 0;
        }
    }
    return 0;
}

static std::string authorizationInstructionText(const Instruction& instruction) {
    return instruction.operands.empty()
         ? instruction.mnemonic
         : instruction.mnemonic + " " + instruction.operands;
}

struct AuthorizationIntegerLiteral {
    uint64_t bits = 0;
};

static bool authorizationParseInteger(std::string value,
                                      AuthorizationIntegerLiteral& result) {
    value = authorizationExpressionKey(std::move(value));
    if (value.empty()) return false;
    bool negative = false;
    size_t start = 0;
    if (value.front() == '+' || value.front() == '-') {
        negative = value.front() == '-';
        start = 1;
    }
    if (start == value.size()) return false;
    errno = 0;
    char* end = nullptr;
    const unsigned long long magnitude = std::strtoull(
        value.c_str() + static_cast<std::ptrdiff_t>(start), &end, 0);
    if (errno == ERANGE || !end ||
        end == value.c_str() + static_cast<std::ptrdiff_t>(start) ||
        *end != '\0')
        return false;
    result.bits = negative
        ? UINT64_C(0) - static_cast<uint64_t>(magnitude)
        : static_cast<uint64_t>(magnitude);
    return true;
}

static bool authorizationEqualityHelper(const BinaryFile& binary,
                                        const ApiCallObservation& call) {
    // Prefer the loader's exact IAT identity. A bare/local symbol named
    // `strcmp` has no contract: only a catalogued DLL+symbol pair may consume
    // pointer provenance as equality-comparison contents.
    if (call.targetVAValid) {
        for (const auto& imported : binary.imports()) {
            if (!imported.addressKnown || imported.iatVA != call.targetVA) continue;
            return LookupValidationEqualityComparator(imported.dll,
                                                       imported.name).has_value();
        }
    }
    // Directly qualified resolver names are also accepted by the exact
    // catalog. Lookup rejects bare names and conflicting module qualifiers.
    return LookupValidationEqualityComparator({}, call.resolvedName).has_value();
}

static AuthorizationEntitlementKind authorizationEntitlementKind(
    std::initializer_list<std::string_view> values) {
    std::vector<std::string> tokens;
    for (std::string_view value : values) {
        std::string token;
        auto flush = [&] {
            if (!token.empty()) tokens.push_back(std::move(token));
            token.clear();
        };
        for (size_t i = 0; i < value.size(); ++i) {
            const char c = value[i];
            const unsigned char byte = static_cast<unsigned char>(c);
            if (!std::isalnum(byte)) {
                flush();
                continue;
            }
            if (!token.empty()) {
                const unsigned char previous =
                    static_cast<unsigned char>(value[i - 1]);
                const bool lowerToUpper = std::islower(previous) &&
                                          std::isupper(byte);
                const bool alphaToDigit = std::isalpha(previous) &&
                                          std::isdigit(byte);
                const bool digitToAlpha = std::isdigit(previous) &&
                                          std::isalpha(byte);
                const bool acronymToWord = std::isupper(previous) &&
                    std::isupper(byte) && i + 1 < value.size() &&
                    std::islower(static_cast<unsigned char>(value[i + 1]));
                if (lowerToUpper || alphaToDigit || digitToAlpha ||
                    acronymToWord)
                    flush();
            }
            token.push_back(static_cast<char>(std::tolower(byte)));
        }
        flush();
    }
    auto has = [&](std::string_view wanted) {
        return std::find(tokens.begin(), tokens.end(), wanted) != tokens.end();
    };
    // Canonical persistent identities are intentionally case-folded, so retain
    // a small exact allowlist for common camel-case predicates after folding.
    // These are whole tokens only; names such as process/profile/provenance do
    // not match.
    if (has("pro") || has("ispro"))
        return AuthorizationEntitlementKind::Pro;
    if (has("validated") || has("isvalidated"))
        return AuthorizationEntitlementKind::Validated;
    if (has("licensed") || has("islicensed"))
        return AuthorizationEntitlementKind::Licensed;
    if (has("activated") || has("isactivated"))
        return AuthorizationEntitlementKind::Activated;
    if (has("premium") || has("ispremium"))
        return AuthorizationEntitlementKind::Premium;
    if (has("1") || has("true"))
        return AuthorizationEntitlementKind::BooleanTrue;
    return AuthorizationEntitlementKind::Unknown;
}

static const Instruction* authorizationInstructionAt(
    const ControlFlowGraph& graph, uint64_t address) {
    for (const BasicBlock& block : graph.blocks)
        for (const Instruction& instruction : block.insns)
            if (instruction.address == address) return &instruction;
    return nullptr;
}

struct AuthorizationBooleanBranchDestinations {
    uint64_t trueDestination = 0;
    bool trueDestinationValid = false;
    uint64_t falseDestination = 0;
    bool falseDestinationValid = false;
    uint8_t comparedWidthBits = 0;
    bool complete = false;
    std::string evidence;
};

// Resolve only the canonical x86 call-result shapes the UI can explain and a
// live experiment can reproduce: test result,result / cmp result,0|1 followed
// by JE/JZ/JNE/JNZ. Other conditions remain navigable uses, but are not assigned
// a true edge.
static AuthorizationBooleanBranchDestinations
authorizationBooleanDestinations(
    const ControlFlowGraph& graph,
    const ApiCallObservation& call,
    AuthorizationTrailBooleanContract contract) {
    AuthorizationBooleanBranchDestinations result;
    if (!call.returnUseVAValid || !call.decisionVAValid ||
        !call.decisionTargetValid ||
        contract == AuthorizationTrailBooleanContract::Unknown)
        return result;
    const Instruction* comparison = authorizationInstructionAt(
        graph, call.returnUseVA);
    const Instruction* branch = authorizationInstructionAt(
        graph, call.decisionVA);
    if (!comparison || !branch ||
        !authorizationConditionalBranch(*branch))
        return result;

    const std::string compareMnemonic =
        authorizationLower(comparison->mnemonic);
    const std::string branchMnemonic = authorizationLower(branch->mnemonic);
    const std::vector<std::string> operands =
        authorizationSplitOperands(comparison->operands);
    if (operands.size() != 2 ||
        (compareMnemonic != "test" && compareMnemonic != "cmp"))
        return result;

    int resultOperand = -1;
    for (size_t i = 0; i < operands.size(); ++i)
        if (operands[i] == "rax") resultOperand = static_cast<int>(i);
    if (resultOperand < 0) return result;
    const size_t resultIndex = static_cast<size_t>(resultOperand);
    const size_t otherIndex = resultIndex == 0 ? 1 : 0;
    result.comparedWidthBits = static_cast<uint8_t>((std::min<uint16_t>)(
        authorizationOperandWidthBits(*comparison, resultIndex), 255));
    if (result.comparedWidthBits != 8 && result.comparedWidthBits != 32 &&
        result.comparedWidthBits != 64)
        return result;

    bool takenMeansTrue = false;
    if (compareMnemonic == "test") {
        if (operands[0] != "rax" || operands[1] != "rax") return result;
        if (contract == AuthorizationTrailBooleanContract::OneIsTrue)
            return result;
        const bool takenWhenNonzero =
            branchMnemonic == "jne" || branchMnemonic == "jnz";
        if (!takenWhenNonzero && branchMnemonic != "je" &&
            branchMnemonic != "jz")
            return result;
        const bool nonzeroMeansTrue =
            contract != AuthorizationTrailBooleanContract::ZeroIsTrue;
        takenMeansTrue = takenWhenNonzero == nonzeroMeansTrue;
    } else {
        AuthorizationIntegerLiteral literal;
        if (!authorizationParseInteger(operands[otherIndex], literal) ||
            (literal.bits != 0 && literal.bits != 1))
            return result;
        const bool equalTaken = branchMnemonic == "je" || branchMnemonic == "jz";
        const bool notEqualTaken =
            branchMnemonic == "jne" || branchMnemonic == "jnz";
        if (!equalTaken && !notEqualTaken) return result;
        if (contract == AuthorizationTrailBooleanContract::OneIsTrue) {
            if (literal.bits != 1) return result;
            takenMeansTrue = equalTaken;
        } else {
            // Zero/nonzero API contracts partition the full ABI result only
            // when compared with zero.  `cmp eax, 1; jne ...` is not an exact
            // zero-success test: every other nonzero error code also takes the
            // not-equal edge.  A literal-one comparison is exact only for a
            // canonical 0/1 value (or the OneIsTrue case above).
            if (literal.bits == 1 &&
                contract !=
                    AuthorizationTrailBooleanContract::CanonicalZeroOrOne)
                return result;
            const bool equalValueIsTrue = literal.bits == 0
                ? contract == AuthorizationTrailBooleanContract::ZeroIsTrue
                : contract != AuthorizationTrailBooleanContract::ZeroIsTrue;
            takenMeansTrue = equalTaken ? equalValueIsTrue
                                       : !equalValueIsTrue;
        }
    }

    bool fallthroughValid = false;
    const uint64_t fallthrough = authorizationFallthrough(
        graph, call.decisionVA, call.decisionTarget, fallthroughValid);
    if (!fallthroughValid) return result;
    result.trueDestination = takenMeansTrue
        ? call.decisionTarget : fallthrough;
    result.trueDestinationValid = true;
    result.falseDestination = takenMeansTrue
        ? fallthrough : call.decisionTarget;
    result.falseDestinationValid = true;
    result.complete = graph.complete;
    result.evidence = "exact " + authorizationInstructionText(*comparison) +
        " / " + authorizationInstructionText(*branch) +
        " pair maps the callee boolean to true and false successors";
    return result;
}

static bool authorizationPredicateSideEffectLight(
    const ControlFlowGraph& graph, const FuncAnnotations& annotations) {
    if (!graph.complete || !annotations.returnObservation.complete ||
        graph.decodedInstructions > 96)
        return false;
    for (const ObjectFieldAccessObservation& field : annotations.fieldAccesses)
        if (field.access == ObjectFieldAccessKind::Write ||
            field.access == ObjectFieldAccessKind::ReadWrite)
            return false;
    for (const BasicBlock& block : graph.blocks) {
        for (const Instruction& instruction : block.insns) {
            if (InstructionIsCall(instruction) || instruction.isRepString)
                return false;
            const std::string mnemonic =
                authorizationLower(instruction.mnemonic);
            // These instructions have process-, kernel-, device-, transaction-,
            // or exception-visible behavior even when no explicit memory-write
            // operand is exposed by the decoder.  A direct-return patch would
            // skip that behavior, so this narrow advisor must fail closed.
            static constexpr std::string_view kObservableInstructions[] = {
                "syscall", "sysenter", "sysexit", "sysret", "sysretq",
                "int", "int1", "int3", "into", "icebp", "ud0", "ud1",
                "ud2", "hlt", "cli", "sti", "clac", "stac", "clts",
                "in", "ins", "insb", "insw", "insd", "out", "outs",
                "outsb", "outsw", "outsd", "invd", "wbinvd", "wbnoinvd",
                "invlpg", "invpcid", "lgdt", "lidt", "lldt", "ltr",
                "lmsw", "wrmsr", "xsetbv", "wrpkru", "wrfsbase",
                "wrgsbase", "xabort", "xbegin", "xend", "xtest",
                "monitor", "monitorx", "mwait", "mwaitx", "umonitor",
                "umwait", "tpause", "vmcall", "vmmcall", "vmlaunch",
                "vmresume", "vmxon", "vmxoff", "vmclear", "vmptrld",
                "invept", "invvpid", "vmrun", "vmload", "vmsave",
                "stgi", "clgi", "skinit", "rsm", "swapgs", "setssbsy",
                "clrssbsy", "rstorssp", "saveprevssp", "incsspq",
                "incsspd", "movdir64b", "enqcmd", "enqcmds", "pcommit",
                "stos", "stosb", "stosw", "stosd", "stosq", "movs",
                "movsb", "movsw", "movsd", "movsq"
            };
            if (std::find(std::begin(kObservableInstructions),
                          std::end(kObservableInstructions), mnemonic) !=
                std::end(kObservableInstructions))
                return false;
            for (InstructionPrefix prefix : instruction.prefixes)
                if (prefix == InstructionPrefix::Lock ||
                    prefix == InstructionPrefix::XAcquire ||
                    prefix == InstructionPrefix::XRelease)
                    return false;
            // An indirect/tail transfer can invoke behavior which the local CFG
            // and call annotations do not model as a call.  Switch and call
            // transfers are likewise outside this deliberately tiny proof.
            // A normal return is required by the candidate contract and is safe.
            if (instruction.flow.kind == FlowKind::IndirectBranch ||
                instruction.flow.kind == FlowKind::Switch ||
                instruction.flow.kind == FlowKind::SubroutineCall)
                return false;
            bool typedMemoryWrite = false;
            for (const TypedOperand& operand : instruction.typedOperands)
                typedMemoryWrite |= operand.kind == OperandKind::Memory &&
                                    OperandWrites(operand.access);
            if (typedMemoryWrite) return false;
            if (instruction.typedOperands.empty()) {
                const std::vector<std::string> operands =
                    authorizationSplitOperands(instruction.operands);
                if (!operands.empty() && operands.front().find('[') !=
                        std::string::npos &&
                    mnemonic != "cmp" && mnemonic != "test" &&
                    mnemonic != "lea")
                    return false;
            }
        }
    }
    return true;
}

static bool authorizationIsHexToken32(std::string_view value) {
    if (value.size() != 32) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

struct StaticNetworkBranchOutcome {
    NetworkReturnDisposition taken = NetworkReturnDisposition::Indeterminate;
    NetworkReturnDisposition fallthrough =
        NetworkReturnDisposition::Indeterminate;
};

static NetworkReturnDisposition authorizationFailureDisposition(
    const NetworkApiReturnContract& contract) {
    return contract.asyncPendingPossible
         ? NetworkReturnDisposition::Indeterminate
         : NetworkReturnDisposition::Failure;
}

static StaticNetworkBranchOutcome authorizationClassifyNetworkBranch(
    const NetworkApiReturnContract& contract,
    std::string comparisonMnemonic,
    std::string expectedExpression,
    std::string branchMnemonic,
    uint8_t pointerWidthBits,
    bool selfTest,
    int matchedOperand,
    uint16_t comparedWidthBits) {
    StaticNetworkBranchOutcome result;
    comparisonMnemonic = authorizationLower(std::move(comparisonMnemonic));
    branchMnemonic = authorizationLower(std::move(branchMnemonic));
    const NetworkReturnDisposition failure =
        authorizationFailureDisposition(contract);
    auto assign = [&](NetworkReturnDisposition conditionTrue,
                      NetworkReturnDisposition conditionFalse) {
        result.taken = conditionTrue;
        result.fallthrough = conditionFalse;
    };

    const bool zeroBranch = branchMnemonic == "je" || branchMnemonic == "jz";
    const bool nonzeroBranch = branchMnemonic == "jne" || branchMnemonic == "jnz";
    const bool negativeBranch = branchMnemonic == "js" || branchMnemonic == "jl" ||
                                branchMnemonic == "jnge";
    const bool nonnegativeBranch = branchMnemonic == "jns" ||
                                   branchMnemonic == "jge" ||
                                   branchMnemonic == "jnl";

    const bool pointerValue =
        contract.returnKind == NetworkReturnKind::SocketHandle ||
        contract.returnKind == NetworkReturnKind::InternetHandle ||
        contract.returnKind == NetworkReturnKind::Pointer;
    const uint16_t contractWidthBits = pointerValue
        ? pointerWidthBits : 32u;
    if (comparedWidthBits != 32 && comparedWidthBits != 64)
        return result;
    // Win32 scalar returns occupy the low 32 bits and are zero-extended by the
    // x64 ABI.  A 32- or 64-bit zero/equality check can therefore observe the
    // complete value, but a byte/word test cannot. Pointer contracts require
    // the exact native width because truncation can turn a non-NULL value into
    // zero or hide INVALID_SOCKET's upper bits.
    const bool observesCompleteValue = comparedWidthBits != 0 &&
        (pointerValue ? comparedWidthBits == contractWidthBits
                      : comparedWidthBits >= contractWidthBits);
    if (!observesCompleteValue) return result;

    // `test value,mask` is a bit test, not a zero/sign test of the complete
    // status value.  Only the canonical `test value,value` form is eligible
    // for documented return-contract classification.
    if (comparisonMnemonic == "test" && !selfTest) return result;

    if (negativeBranch || nonnegativeBranch) {
        AuthorizationIntegerLiteral boundary;
        const bool signBoundary =
            (comparisonMnemonic == "test" && selfTest) ||
            (comparisonMnemonic == "cmp" && matchedOperand == 0 &&
             authorizationParseInteger(expectedExpression, boundary) &&
             boundary.bits == 0);
        // Signed Win32/HRESULT rules apply to bit 31. Testing zero-extended
        // RAX/RBX would instead inspect bit 63 and can never detect a negative
        // 32-bit return unless an explicit sign-extension was proven.
        if (!signBoundary || comparedWidthBits != contractWidthBits)
            return result;
        if (contract.successRule == NetworkReturnSuccessRule::NonNegative ||
            contract.successRule == NetworkReturnSuccessRule::HResultSucceeded) {
            if (negativeBranch) assign(failure, NetworkReturnDisposition::Success);
            else assign(NetworkReturnDisposition::Success, failure);
        }
        return result;
    }

    AuthorizationIntegerLiteral expected;
    if (comparisonMnemonic == "test") {
        expected.bits = 0;
    } else if (!authorizationParseInteger(expectedExpression, expected)) {
        return result;
    }
    if (!zeroBranch && !nonzeroBranch) return result;

    NetworkReturnDisposition equal = NetworkReturnDisposition::Indeterminate;
    NetworkReturnDisposition different = NetworkReturnDisposition::Indeterminate;
    const uint64_t operandMask = comparedWidthBits == 64
        ? UINT64_MAX
        : comparedWidthBits == 32
        ? UINT64_C(0xFFFFFFFF)
        : (UINT64_C(1) << comparedWidthBits) - 1;
    const uint64_t expectedBits = expected.bits & operandMask;
    switch (contract.successRule) {
    case NetworkReturnSuccessRule::NonZero:
    case NetworkReturnSuccessRule::NonNull:
        if (expectedBits == 0) {
            equal = failure;
            different = NetworkReturnDisposition::Success;
        }
        break;
    case NetworkReturnSuccessRule::Zero:
        if (expectedBits == 0) {
            equal = NetworkReturnDisposition::Success;
            different = failure;
        }
        break;
    case NetworkReturnSuccessRule::NonNegative:
        // A 32-bit API return is zero-extended on x64. `cmp eax,-1` and
        // `cmp rax,0xffffffff` test SOCKET_ERROR; `cmp rax,-1` does not.
        if (expectedBits == UINT32_MAX) {
            equal = failure;
            // A not-equal predicate alone does not prove nonnegative: keep
            // other negative values conservative even when -1 is the API's
            // documented sentinel.
            different = NetworkReturnDisposition::Indeterminate;
        }
        break;
    case NetworkReturnSuccessRule::NotInvalidSocket:
        if (expectedBits == operandMask) {
            equal = failure;
            different = NetworkReturnDisposition::Success;
        }
        break;
    case NetworkReturnSuccessRule::HResultSucceeded:
        break;
    }
    if (zeroBranch) assign(equal, different);
    else assign(different, equal);
    return result;
}

struct AuthorizationPathScan {
    AuthorizationPathInput path;
    std::unordered_set<uint64_t> blockStarts;
};

static void authorizationMarkPathIncomplete(AuthorizationPathInput& path,
                                            std::string_view reason) {
    path.complete = false;
    if (reason.empty()) return;
    if (!path.incompleteReason.empty()) {
        if (path.incompleteReason.find(reason) == std::string::npos) {
            path.incompleteReason += "; ";
            path.incompleteReason.append(reason);
        }
    } else {
        path.incompleteReason.assign(reason);
    }
}

static bool authorizationApplicationContinuationContract(
    std::string_view qualifiedName) {
    const size_t bang = qualifiedName.rfind('!');
    if (bang == std::string_view::npos || bang == 0 ||
        bang + 1 >= qualifiedName.size()) return false;
    const std::string dll = NormalizeValidationDll(qualifiedName.substr(0, bang));
    const std::string name = NormalizeValidationApiName(
        qualifiedName.substr(bang + 1));
    if (dll != "user32") return false;
    static constexpr std::string_view kExactUser32Continuations[] = {
        "getmessagea", "getmessagew",
        "dispatchmessagea", "dispatchmessagew",
        "createwindowexa", "createwindowexw",
        "dialogboxparama", "dialogboxparamw",
        "showwindow",
    };
    return std::find(std::begin(kExactUser32Continuations),
                     std::end(kExactUser32Continuations), name) !=
           std::end(kExactUser32Continuations);
}

static AuthorizationPathScan scanAuthorizationPath(
    const BinaryFile& binary,
    const ControlFlowGraph& graph,
    uint64_t startAddress,
    bool startValid,
    uint64_t functionAddress,
    const std::string& functionName,
    const std::unordered_map<uint64_t, std::string>& namesByVA,
    const std::unordered_map<uint64_t, std::string>& stringsByVA,
    const std::unordered_set<uint64_t>& stateWriteCallsites,
    size_t maxBlocks = 64,
    const std::unordered_set<size_t>* excludedBlocks = nullptr) {
    AuthorizationPathScan result;
    result.path.entry = authorizationLocation(binary, startAddress, startValid,
                                              functionAddress, true, functionName);
    if (!startValid) {
        result.path.complete = false;
        result.path.incompleteReason = "branch successor address was unavailable";
        return result;
    }
    const BasicBlock* first = authorizationBlockForAddress(graph, startAddress);
    if (!first) {
        result.path.complete = false;
        result.path.incompleteReason = "branch successor was outside the retained CFG";
        return result;
    }
    const size_t firstIndex = static_cast<size_t>(first - graph.blocks.data());
    if (excludedBlocks && excludedBlocks->count(firstIndex)) return result;
    std::deque<size_t> queue{firstIndex};
    std::unordered_set<size_t> visited;
    std::unordered_set<std::string> evidenceKeys;
    auto addEvidence = [&](AuthorizationEvidenceKind kind,
                           const Instruction& instruction,
                           std::string text, float strength = 0.0f) {
        const std::string key = std::to_string(static_cast<unsigned>(kind)) + ':' +
                                std::to_string(instruction.address);
        if (!evidenceKeys.insert(key).second) return;
        if (result.path.evidence.size() >= 64) {
            authorizationMarkPathIncomplete(
                result.path, "64-effect outcome budget reached");
            return;
        }
        AuthorizationEvidence evidence;
        evidence.kind = kind;
        evidence.location = authorizationLocation(binary, instruction.address, true,
                                                   functionAddress, true, functionName);
        evidence.text = std::move(text);
        evidence.strength = strength;
        result.path.evidence.push_back(std::move(evidence));
    };
    bool successIndicatorFound = false;
    auto inspectLiteral = [&](uint64_t ref, const Instruction& instruction) {
        const auto found = stringsByVA.find(ref);
        if (found == stringsByVA.end()) return;
        const std::string lower = authorizationLower(found->second);
        static constexpr std::string_view failureWords[] = {
            "invalid", "denied", "failed", "failure", "rejected", "expired",
            "wrong", "unauthorized", "not valid"
        };
        static constexpr std::string_view successWords[] = {
            "access granted", "welcome", "activated", "valid license", "success",
            "accepted", "authorized"
        };
        for (std::string_view word : failureWords) {
            if (lower.find(word) == std::string::npos) continue;
            addEvidence(AuthorizationEvidenceKind::FailureIndicator, instruction,
                        "references failure text: " + found->second, 0.65f);
            break;
        }
        for (std::string_view word : successWords) {
            if (lower.find(word) == std::string::npos) continue;
            successIndicatorFound = true;
            addEvidence(AuthorizationEvidenceKind::SuccessIndicator, instruction,
                        "references success text: " + found->second, 0.65f);
            break;
        }
    };
    std::vector<std::pair<const Instruction*, std::string>> pendingContinuations;
    pendingContinuations.reserve(8);

    while (!queue.empty()) {
        const size_t blockIndex = queue.front();
        queue.pop_front();
        if (excludedBlocks && excludedBlocks->count(blockIndex)) continue;
        if (blockIndex >= graph.blocks.size() || !visited.insert(blockIndex).second) continue;
        if (visited.size() > maxBlocks) {
            authorizationMarkPathIncomplete(
                result.path, "64-block outcome budget reached");
            break;
        }
        const BasicBlock& block = graph.blocks[blockIndex];
        result.blockStarts.insert(block.start);
        for (size_t instructionIndex = 0; instructionIndex < block.insns.size();
             ++instructionIndex) {
            const Instruction& instruction = block.insns[instructionIndex];
            if (stateWriteCallsites.count(instruction.address))
                addEvidence(AuthorizationEvidenceKind::PersistentStateWrite, instruction,
                            "executes a cataloged durable-state write; written value and authorization direction are unproven");
            if (instruction.isCall && HasBranchTarget(instruction)) {
                const auto named = namesByVA.find(instruction.branchTarget);
                if (named != namesByVA.end()) {
                    if (IsKnownNoreturnApi(named->second))
                        addEvidence(AuthorizationEvidenceKind::ProcessTermination,
                                    instruction,
                                    "calls known non-returning terminator " + named->second,
                                    0.95f);
                    if (authorizationApplicationContinuationContract(named->second)) {
                        if (pendingContinuations.size() < 65)
                            pendingContinuations.emplace_back(&instruction,
                                                              named->second);
                        else
                            authorizationMarkPathIncomplete(
                                result.path,
                                "64-effect outcome budget reached");
                    }
                }
            }
            uint64_t ref = 0;
            if (TryGetInstrDataRef(instruction, ref) || TryGetInstrImmRef(instruction, ref))
                inspectLiteral(ref, instruction);
            if (!instruction.isRet || instructionIndex == 0) continue;
            const Instruction& previous = block.insns[instructionIndex - 1];
            if (authorizationReturnsInteger(previous, 0))
                addEvidence(AuthorizationEvidenceKind::Unknown, previous,
                            "returns integer zero; authorization direction is unknown without a proven caller contract");
            else if (authorizationReturnsInteger(previous, 1))
                addEvidence(AuthorizationEvidenceKind::Unknown, previous,
                            "returns integer one; authorization direction is unknown without a proven caller contract");
        }
        for (size_t successor : block.succ)
            if (successor < graph.blocks.size() &&
                (!excludedBlocks || !excludedBlocks->count(successor)) &&
                !visited.count(successor))
                queue.push_back(successor);
    }
    // UI-loop APIs are not intrinsically an allow effect: a denial dialog uses
    // the same APIs. Promote only an exact qualified User32 contract when this
    // same edge-exclusive path independently references explicit success text.
    if (successIndicatorFound) {
        for (const auto& [instruction, name] : pendingContinuations) {
            addEvidence(AuthorizationEvidenceKind::ApplicationContinuation,
                        *instruction,
                        "continues into application/UI initialization via " + name +
                            "; corroborated by explicit success text on this path",
                        0.85f);
        }
    }
    return result;
}

struct AuthorizationReachability {
    std::unordered_set<size_t> blocks;
    bool complete = true;
};

static AuthorizationReachability authorizationReachableBlocks(
    const ControlFlowGraph& graph,
    uint64_t startAddress,
    bool startValid,
    size_t forbiddenBlock,
    size_t maxBlocks) {
    AuthorizationReachability result;
    if (!startValid) return result;
    const BasicBlock* first = authorizationBlockForAddress(graph, startAddress);
    if (!first) return result;
    std::deque<size_t> queue{
        static_cast<size_t>(first - graph.blocks.data())};
    while (!queue.empty()) {
        const size_t block = queue.front();
        queue.pop_front();
        if (block >= graph.blocks.size() || block == forbiddenBlock ||
            result.blocks.count(block)) continue;
        if (result.blocks.size() >= maxBlocks) {
            result.complete = false;
            break;
        }
        result.blocks.insert(block);
        for (size_t successor : graph.blocks[block].succ)
            if (successor < graph.blocks.size() && successor != forbiddenBlock &&
                !result.blocks.count(successor))
                queue.push_back(successor);
    }
    if (!queue.empty()) result.complete = false;
    return result;
}

struct AuthorizationPathPairScan {
    AuthorizationPathScan taken;
    AuthorizationPathScan fallthrough;
};

static AuthorizationPathPairScan scanAuthorizationPathPair(
    const BinaryFile& binary,
    const ControlFlowGraph& graph,
    uint64_t decisionAddress,
    bool decisionValid,
    uint64_t takenAddress,
    bool takenValid,
    uint64_t fallthroughAddress,
    bool fallthroughValid,
    uint64_t functionAddress,
    const std::string& functionName,
    const std::unordered_map<uint64_t, std::string>& namesByVA,
    const std::unordered_map<uint64_t, std::string>& stringsByVA,
    const std::unordered_set<uint64_t>& stateWriteCallsites,
    size_t maxBlocks = 64) {
    const BasicBlock* decisionBlock = decisionValid
        ? authorizationBlockForAddress(graph, decisionAddress) : nullptr;
    const size_t forbidden = decisionBlock
        ? static_cast<size_t>(decisionBlock - graph.blocks.data())
        : graph.blocks.size();
    const AuthorizationReachability takenReach = authorizationReachableBlocks(
        graph, takenAddress, takenValid, forbidden, maxBlocks);
    const AuthorizationReachability fallthroughReach =
        authorizationReachableBlocks(graph, fallthroughAddress,
                                     fallthroughValid, forbidden, maxBlocks);

    std::unordered_set<size_t> excluded;
    excluded.reserve((std::min)(takenReach.blocks.size(),
                                fallthroughReach.blocks.size()) + 1);
    for (size_t block : takenReach.blocks)
        if (fallthroughReach.blocks.count(block)) excluded.insert(block);
    if (decisionBlock) excluded.insert(forbidden);

    AuthorizationPathPairScan result;
    result.taken = scanAuthorizationPath(
        binary, graph, takenAddress, takenValid, functionAddress, functionName,
        namesByVA, stringsByVA, stateWriteCallsites, maxBlocks, &excluded);
    result.fallthrough = scanAuthorizationPath(
        binary, graph, fallthroughAddress, fallthroughValid, functionAddress,
        functionName, namesByVA, stringsByVA, stateWriteCallsites, maxBlocks,
        &excluded);
    if (!takenReach.complete || !fallthroughReach.complete) {
        authorizationMarkPathIncomplete(
            result.taken.path,
            "edge-exclusive reachability exceeded the 64-block outcome budget");
        authorizationMarkPathIncomplete(
            result.fallthrough.path,
            "edge-exclusive reachability exceeded the 64-block outcome budget");
    }
    return result;
}

static size_t addBytes(size_t total, size_t amount) {
    return amount > (std::numeric_limits<size_t>::max)() - total
         ? (std::numeric_limits<size_t>::max)() : total + amount;
}

static size_t multiplyBytes(size_t count, size_t elementSize) {
    if (count != 0 && elementSize > (std::numeric_limits<size_t>::max)() / count)
        return (std::numeric_limits<size_t>::max)();
    return count * elementSize;
}

static size_t estimateAnalysisResultBytesImpl(const AnalysisResult& result) {
    size_t bytes = sizeof(AnalysisResult);
    bytes = addBytes(bytes, result.strings.size() * sizeof(StrResult));
    for (const StrResult& item : result.strings) bytes = addBytes(bytes, item.text.size());
    bytes = addBytes(bytes, result.functions.size() * sizeof(FuncResult));
    for (const FuncResult& item : result.functions) {
        bytes = addBytes(bytes, item.name.size());
        bytes = addBytes(bytes, item.reason.size());
        bytes = addBytes(bytes, item.callingConvention.size());
        bytes = addBytes(bytes, item.prototype.size());
        bytes = addBytes(bytes, item.chunks.size() * sizeof(FunctionChunk));
    }
    bytes = addBytes(bytes, result.summary.size());
    bytes = addBytes(bytes, result.listRows.size() * sizeof(ListRowR));
    bytes = addBytes(bytes, result.listingPrefixCheckpoints.size() *
                            sizeof(ListingPrefixCheckpoint));
    bytes = addBytes(bytes, result.callEdges.size() * sizeof(CallEdgeR));
    bytes = addBytes(bytes, result.decompText.size());
    bytes = addBytes(bytes, result.decompLineVA.size() * sizeof(uint64_t));
    bytes = addBytes(bytes, result.decompLineOrigins.size() * sizeof(SourceOrigin));
    bytes = addBytes(bytes, result.decompIncompleteReason.size());
    bytes = addBytes(bytes, result.decompDiagnostics.size() * sizeof(DecompileDiagnostic));
    for (const DecompileDiagnostic& diagnostic : result.decompDiagnostics)
        bytes = addBytes(bytes, diagnostic.message.size());
    if (result.codeData) {
        bytes = addBytes(bytes, sizeof(CodeDataMap));
        bytes = addBytes(bytes, result.codeData->spans.size() * sizeof(CodeDataSpan));
        for (const CodeDataSpan& span : result.codeData->spans)
            bytes = addBytes(bytes, span.evidence.size());
        bytes = addBytes(bytes, result.codeData->functionSeeds.size() *
                                sizeof(CodeDataFunctionSeed));
        for (const CodeDataFunctionSeed& seed : result.codeData->functionSeeds)
            bytes = addBytes(bytes, seed.evidence.size());
    }
    if (result.xref) {
        bytes = addBytes(bytes, sizeof(XrefIndex));
        bytes = addBytes(bytes, result.xref->toTarget.size() *
                                (sizeof(uint64_t) + sizeof(std::vector<uint64_t>) + 32));
        bytes = addBytes(bytes, result.xref->edgeCount() * sizeof(uint64_t));
        bytes = addBytes(bytes, result.xref->accessOf.size() *
                                (sizeof(uint64_t) + sizeof(uint8_t) + 24));
    }
    for (const AlgoMatch& match : result.algos) {
        bytes = addBytes(bytes, sizeof(AlgoMatch) + match.name.size() +
                                match.category.size() + match.section.size() +
                                match.detail.size() + match.alphabet.size() +
                                match.substitutionNote.size());
        bytes = addBytes(bytes, match.dataVAs.size() * sizeof(uint64_t));
        bytes = addBytes(bytes, match.referencedBy.size() * sizeof(AlgoXref));
        for (const AlgoXref& ref : match.referencedBy)
            bytes = addBytes(bytes, ref.funcName.size());
    }
    if (result.crackmeTriageValid) {
        const CrackmeTriageReport& report = result.crackmeTriage;
        auto addString = [&](const std::string& text) {
            // Counting capacity is conservative for the cache's resident bytes.
            // The string object itself is already included in its owning row.
            bytes = addBytes(bytes, addBytes(text.capacity(), size_t{1}));
        };
        auto addLiteralSource = [&](const CrackmeTriageLiteralSource& source) {
            addString(source.literal);
        };

        addString(report.label);
        bytes = addBytes(bytes, multiplyBytes(report.endpoints.capacity(),
                                               sizeof(CrackmeTriageEndpoint)));
        for (const auto& endpoint : report.endpoints) {
            addString(endpoint.display);
            addString(endpoint.host);
            addString(endpoint.scheme);
            addString(endpoint.confidenceLabel);
            addString(endpoint.honestyLabel);
            bytes = addBytes(bytes, multiplyBytes(endpoint.paths.capacity(),
                                                   sizeof(std::string)));
            for (const auto& path : endpoint.paths) addString(path);
            bytes = addBytes(bytes, multiplyBytes(endpoint.sources.capacity(),
                                                   sizeof(CrackmeTriageLiteralSource)));
            for (const auto& source : endpoint.sources) addLiteralSource(source);
            bytes = addBytes(bytes, multiplyBytes(endpoint.correlationIndices.capacity(),
                                                   sizeof(size_t)));
        }

        bytes = addBytes(bytes, multiplyBytes(report.routes.capacity(),
                                               sizeof(CrackmeTriageRoute)));
        for (const auto& route : report.routes) {
            addString(route.path);
            bytes = addBytes(bytes, multiplyBytes(route.sources.capacity(),
                                                   sizeof(CrackmeTriageLiteralSource)));
            for (const auto& source : route.sources) addLiteralSource(source);
        }

        bytes = addBytes(bytes, multiplyBytes(report.apis.capacity(),
                                               sizeof(CrackmeTriageApiEvidence)));
        for (const auto& api : report.apis) {
            addString(api.dll);
            addString(api.importName);
            addString(api.canonicalName);
            bytes = addBytes(bytes, multiplyBytes(api.callsites.capacity(),
                                                   sizeof(uint64_t)));
        }

        bytes = addBytes(bytes, multiplyBytes(report.correlations.capacity(),
                                               sizeof(CrackmeTriageCorrelation)));
        for (const auto& correlation : report.correlations) {
            addString(correlation.functionName);
            addString(correlation.endpointFunctionName);
            addString(correlation.confidenceLabel);
            addString(correlation.honestyLabel);
        }

        bytes = addBytes(bytes, multiplyBytes(report.returnFlows.capacity(),
                                               sizeof(NetworkReturnFlow)));
        auto addProvenanceHop = [&](const ValueProvenanceHop& hop) {
            addString(hop.functionName);
            addString(hop.instruction);
            addString(hop.fromExpression);
            addString(hop.toExpression);
            addString(hop.evidence);
        };
        for (const auto& flow : report.returnFlows) {
            addString(flow.functionName);
            addString(flow.useInstruction);
            addString(flow.useSummary);
            addString(flow.decisionInstruction);
            addString(flow.evidence);
            addString(flow.confidenceLabel);
            addString(flow.honestyLabel);
            addString(flow.lineageIncompleteReason);
            bytes = addBytes(bytes, multiplyBytes(flow.decisions.capacity(),
                sizeof(CrackmeTriageReturnDecisionInput)));
            for (const auto& decision : flow.decisions) {
                addString(decision.comparisonInstruction);
                addString(decision.predicate);
                addString(decision.expectedValue);
                addString(decision.decisionInstruction);
                addString(decision.evidence);
                bytes = addBytes(bytes, multiplyBytes(decision.hops.capacity(),
                                                       sizeof(ValueProvenanceHop)));
                for (const ValueProvenanceHop& hop : decision.hops)
                    addProvenanceHop(hop);
            }
        }

        bytes = addBytes(bytes, multiplyBytes(report.replyDecisionFlows.capacity(),
                                               sizeof(NetworkReplyDecisionFlow)));
        for (const auto& flow : report.replyDecisionFlows) {
            addString(flow.functionName);
            addString(flow.outputRole);
            addString(flow.outputExpression);
            addString(flow.comparisonInstruction);
            addString(flow.comparisonSummary);
            addString(flow.expectedValue);
            addString(flow.decisionInstruction);
            addString(flow.takenPathSummary);
            addString(flow.fallthroughPathSummary);
            addString(flow.evidence);
            addString(flow.confidenceLabel);
            addString(flow.honestyLabel);
        }

        const AuthorizationAnalysisReport& authorization = report.authorization;
        auto addAuthorizationLocation = [&](const AuthorizationLocation& location) {
            addString(location.functionName);
        };
        auto addAuthorizationEvidence = [&](const AuthorizationEvidence& evidence) {
            addAuthorizationLocation(evidence.location);
            addString(evidence.text);
        };
        auto addAuthorizationPath = [&](const AuthorizationPath& path) {
            addAuthorizationLocation(path.entry);
            addString(path.honestyLabel);
            bytes = addBytes(bytes, multiplyBytes(path.evidence.capacity(),
                                                   sizeof(AuthorizationEvidence)));
            for (const AuthorizationEvidence& evidence : path.evidence)
                addAuthorizationEvidence(evidence);
        };
        bytes = addBytes(bytes, multiplyBytes(authorization.stateOperations.capacity(),
                                               sizeof(PersistentStateOperation)));
        for (const PersistentStateOperation& operation : authorization.stateOperations) {
            addString(operation.identity.canonicalScope);
            addString(operation.identity.canonicalKey);
            addString(operation.identity.canonicalValue);
            addString(operation.identity.display);
            addAuthorizationLocation(operation.location);
            addString(operation.apiDll);
            addString(operation.apiName);
            addString(operation.evidence);
            addString(operation.outputExpression);
        }
        bytes = addBytes(bytes, multiplyBytes(authorization.flows.capacity(),
                                               sizeof(AuthorizationFlow)));
        for (const AuthorizationFlow& flow : authorization.flows) {
            addString(flow.id);
            addAuthorizationLocation(flow.inputLocation);
            addAuthorizationLocation(flow.comparisonLocation);
            addAuthorizationLocation(flow.decisionLocation);
            addAuthorizationPath(flow.takenPath);
            addAuthorizationPath(flow.fallthroughPath);
            bytes = addBytes(bytes, multiplyBytes(flow.stages.capacity(),
                                                   sizeof(AuthorizationStageRecord)));
            for (const AuthorizationStageRecord& stage : flow.stages) {
                addAuthorizationLocation(stage.location);
                addString(stage.evidence);
            }
            bytes = addBytes(bytes, multiplyBytes(flow.linkedStateWriteIndices.capacity(),
                                                   sizeof(size_t)));
            bytes = addBytes(bytes, multiplyBytes(flow.linkedStartupReadIndices.capacity(),
                                                   sizeof(size_t)));
            bytes = addBytes(bytes, multiplyBytes(flow.linkedStartupFlowIndices.capacity(),
                                                   sizeof(size_t)));
            addString(flow.honestyLabel);
            addString(flow.entitlementLabel);
            addString(flow.originExpression);
            addString(flow.expectedValue);
            addString(flow.provenanceIncompleteReason);
            bytes = addBytes(bytes, multiplyBytes(flow.provenance.capacity(),
                                                   sizeof(ValueProvenanceHop)));
            for (const ValueProvenanceHop& hop : flow.provenance)
                addProvenanceHop(hop);
        }
        bytes = addBytes(bytes, multiplyBytes(authorization.unlinkedOperationIndices.capacity(),
                                               sizeof(size_t)));
        addString(authorization.completeness.reason);

        const AuthorizationTrailReport& authorizationTrail =
            report.authorizationTrail;
        bytes = addBytes(bytes, multiplyBytes(
            authorizationTrail.stringAnchors.capacity(),
            sizeof(AuthorizationTrailStringAnchor)));
        for (const AuthorizationTrailStringAnchor& anchor :
             authorizationTrail.stringAnchors) {
            addString(anchor.label);
            addString(anchor.literal);
            addString(anchor.evidence);
            addAuthorizationLocation(anchor.source);
            bytes = addBytes(bytes, multiplyBytes(
                anchor.references.capacity(),
                sizeof(AuthorizationTrailStringReference)));
            for (const AuthorizationTrailStringReference& reference :
                 anchor.references) {
                addAuthorizationLocation(reference.reference);
                addAuthorizationLocation(reference.containingFunction);
                addAuthorizationLocation(reference.nearbyBranch);
                addString(reference.evidence);
            }
        }

        bytes = addBytes(bytes, multiplyBytes(report.artifacts.capacity(),
                                               sizeof(NetworkArtifact)));
        for (const auto& artifact : report.artifacts) {
            addString(artifact.value);
            bytes = addBytes(bytes, multiplyBytes(artifact.sources.capacity(),
                                                   sizeof(CrackmeTriageLiteralSource)));
            for (const auto& source : artifact.sources) addLiteralSource(source);
            bytes = addBytes(bytes, multiplyBytes(artifact.functionAddresses.capacity(),
                                                   sizeof(uint64_t)));
            addString(artifact.confidenceLabel);
            addString(artifact.honestyLabel);
        }

        bytes = addBytes(bytes, multiplyBytes(report.trails.capacity(), sizeof(CrackmeTrail)));
        for (const auto& trail : report.trails) {
            bytes = addBytes(bytes, multiplyBytes(trail.artifactIndices.capacity(),
                                                   sizeof(size_t)));
            bytes = addBytes(bytes, multiplyBytes(trail.correlationIndices.capacity(),
                                                   sizeof(size_t)));
            bytes = addBytes(bytes, multiplyBytes(trail.returnFlowIndices.capacity(),
                                                   sizeof(size_t)));
            bytes = addBytes(bytes, multiplyBytes(trail.replyDecisionFlowIndices.capacity(),
                                                   sizeof(size_t)));
            addString(trail.label);
            addString(trail.confidenceLabel);
            addString(trail.honestyLabel);
            for (const auto& stage : trail.stages) {
                addString(stage.confidenceLabel);
                addString(stage.honestyLabel);
            }
        }
        for (const auto& stage : report.stages) {
            addString(stage.confidenceLabel);
            addString(stage.honestyLabel);
        }
        addString(report.completeness.reason);
    }
    return bytes;
}

static std::shared_ptr<const AnalysisResult>
snapshotForCache(const AnalysisResult& result) {
    auto snapshot = std::make_shared<AnalysisResult>(result);
    // The consumer currently moves the pointed-to XrefIndex into its UI model.
    // Give the cache a distinct immutable backing object so that move cannot
    // drain a future cache hit.
    if (result.xref) snapshot->xref = std::make_shared<XrefIndex>(*result.xref);
    return snapshot;
}

static AnalysisResult materializeCached(const AnalysisResult& cached,
                                        uint64_t imageRevision) {
    AnalysisResult result = cached; // worker-side copy, never on the render thread
    if (cached.xref) {
        result.xref = std::make_shared<XrefIndex>(*cached.xref);
        result.xrefImageRevision = imageRevision;
    }
    if (cached.codeData && cached.codeData->imageRevision != imageRevision) {
        auto retagged = std::make_shared<CodeDataMap>(*cached.codeData);
        retagged->imageRevision = imageRevision;
        result.codeData = std::move(retagged);
    }
    return result;
}

} // namespace

size_t EstimateAnalysisResultBytes(const AnalysisResult& result) {
    return estimateAnalysisResultBytesImpl(result);
}

// Central admission keeps existing document-owned queues/lifetimes intact while
// preventing eight documents from each consuming a full eight-worker CPU pool.
// No scheduler lock is held while decoding or while acquiring an owner mutex.
struct AnalysisService::SharedScheduler {
    struct Owner {
        AnalysisService* service = nullptr;
        unsigned capacity = 0;
        unsigned admitted = 0; // includes the interval before the queue is claimed
    };
    std::mutex mutex;
    std::condition_variable changed;
    std::vector<Owner> owners;
    unsigned running = 0;
    // Only owners with an available local worker can consume shared admission.
    std::atomic<unsigned> bestRunnablePriority{3}; // interaction / active / background / idle

    static unsigned priority(const AnalysisService& service) {
        if (service.quit_.load(std::memory_order_acquire) ||
            !service.queuedJobs_.load(std::memory_order_acquire)) return 3;
        if (service.queuedInteractive_.load(std::memory_order_acquire)) return 0;
        return service.activeDocument_.load(std::memory_order_acquire) ? 1u : 2u;
    }
    void refreshLocked() {
        unsigned best = 3;
        for (const Owner& owner : owners)
            if (owner.admitted < owner.capacity)
                best = (std::min)(best, priority(*owner.service));
        bestRunnablePriority.store(best, std::memory_order_release);
    }
    void add(AnalysisService* service, unsigned capacity) {
        std::lock_guard<std::mutex> lock(mutex);
        owners.push_back({service, capacity, 0});
        refreshLocked();
    }
    void remove(AnalysisService* service) {
        std::lock_guard<std::mutex> lock(mutex);
        owners.erase(std::remove_if(owners.begin(), owners.end(),
            [service](const Owner& owner) { return owner.service == service; }), owners.end());
        refreshLocked();
        changed.notify_all();
    }
    void notify() {
        std::lock_guard<std::mutex> lock(mutex);
        refreshLocked();
        changed.notify_all();
    }
    bool acquire(AnalysisService& service) {
        std::unique_lock<std::mutex> lock(mutex);
        // Re-find after each wait: another service may register or unregister
        // while changed.wait releases the scheduler mutex.
        auto owner = [&]() -> Owner& {
            return *std::find_if(owners.begin(), owners.end(),
                [&service](const Owner& item) { return item.service == &service; });
        };
        changed.wait(lock, [&] {
            return service.quit_.load(std::memory_order_acquire) ||
                priority(service) == 3 ||
                (running < AnalysisService::globalWorkerLimit() &&
                 owner().admitted < owner().capacity &&
                 priority(service) <= bestRunnablePriority.load(std::memory_order_acquire));
        });
        if (service.quit_.load(std::memory_order_acquire) || priority(service) == 3)
            return false;
        ++owner().admitted;
        ++running;
        refreshLocked();
        return true;
    }
    void release(AnalysisService& service) {
        std::lock_guard<std::mutex> lock(mutex);
        auto owner = std::find_if(owners.begin(), owners.end(),
            [&service](const Owner& item) { return item.service == &service; });
        --owner->admitted;
        --running;
        refreshLocked();
        changed.notify_all();
    }
};

AnalysisService::SharedScheduler& AnalysisService::scheduler() {
    static SharedScheduler shared;
    return shared;
}

unsigned AnalysisService::globalWorkerLimit() {
    static const unsigned limit = [] {
        const unsigned cores = std::thread::hardware_concurrency();
        return (std::min)(cores > 3 ? cores - 2 : 1u, kMaxWorkerCount);
    }();
    return limit;
}

void AnalysisService::setActiveDocument(bool active) {
    activeDocument_.store(active, std::memory_order_release);
    scheduler().notify();
}

AnalysisService::AnalysisService(DecoderFactory factory, unsigned workerCount)
    : factory_(std::move(factory)) {
    unsigned n = workerCount;
    if (n == kAutomaticWorkerCount) {
        // ≈ cores-2 workers (leave one core for the render thread and one for
        // the OS). This remains the default for the app-global legacy owner.
        const unsigned hc = std::thread::hardware_concurrency();
        n = hc > 3 ? hc - 2 : 1;
    }
    n = (std::max)(1u, (std::min)(n, kMaxWorkerCount));
    threads_.reserve(n);
    scheduler().add(this, n);
    try {
        for (unsigned i = 0; i < n; ++i)
            threads_.emplace_back([this, i] { threadMain(i); });
    } catch (...) {
        // A partially constructed vector of joinable std::threads would invoke
        // std::terminate during unwinding. Stop and join every thread which did
        // start before propagating the resource/construction failure.
        quit_.store(true, std::memory_order_release);
        cv_.notify_all();
        scheduler().notify();
        for (auto& thread : threads_)
            if (thread.joinable()) thread.join();
        scheduler().remove(this);
        throw;
    }
}

AnalysisService::AnalysisService(LegacyDecoderFactory factory, unsigned workerCount)
    : AnalysisService(DecoderFactory(
          [legacy = std::move(factory)](const DecoderConfig& config) {
              return legacy && LegacyDecoderFactoryCanRepresent(config)
                   ? legacy(config.engine, config.arch) : nullptr;
          }), workerCount) {}

AnalysisService::~AnalysisService() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        quit_.store(true);
    }
    cv_.notify_all();
    scheduler().notify();
    for (auto& t : threads_) if (t.joinable()) t.join();
    scheduler().remove(this);
}

void AnalysisService::requestBulk(const BinaryFile* bin, const DecoderConfig& decoder,
                                  uint32_t kinds, bool guessNames, uint64_t epoch,
                                  uint64_t moduleBase, uint64_t regionLo, uint64_t regionHi,
                                  bool regionValid,
                                  std::shared_ptr<const DecompileNameMap> decompNames,
                                  std::string decompSignature, uint64_t decompContext,
                                  std::shared_ptr<const ProjectAnalysisOverrides> analysisOverrides,
                                  uint64_t orderedPatchDigest,
                                  std::shared_ptr<const std::vector<FunctionChunk>> decompChunks,
                                  bool decompOwnershipTruncated,
                                  std::shared_ptr<const std::vector<uint64_t>> noreturnTargets) {
    requestBulkImpl(bin, decoder, kinds, guessNames, epoch,
                    moduleBase, regionLo, regionHi, regionValid, std::move(decompNames),
                    std::move(decompSignature), decompContext, {}, 0, {}, 0, 0, {},
                    std::move(analysisOverrides), orderedPatchDigest,
                    std::move(decompChunks), decompOwnershipTruncated,
                    std::move(noreturnTargets));
}

void AnalysisService::requestBulk(const BinaryFile* bin, Engine engine, Arch arch,
                                  uint32_t kinds, bool guessNames, uint64_t epoch,
                                  uint64_t moduleBase, uint64_t regionLo, uint64_t regionHi,
                                  bool regionValid,
                                  std::shared_ptr<const DecompileNameMap> decompNames,
                                  std::string decompSignature, uint64_t decompContext,
                                  std::shared_ptr<const ProjectAnalysisOverrides> analysisOverrides,
                                  uint64_t orderedPatchDigest,
                                  std::shared_ptr<const std::vector<FunctionChunk>> decompChunks,
                                  bool decompOwnershipTruncated,
                                  std::shared_ptr<const std::vector<uint64_t>> noreturnTargets) {
    DecoderConfig decoder;
    decoder.engine = engine;
    decoder.arch = arch;
    requestBulk(bin, decoder, kinds, guessNames, epoch, moduleBase, regionLo,
                regionHi, regionValid, std::move(decompNames),
                std::move(decompSignature), decompContext,
                std::move(analysisOverrides), orderedPatchDigest,
                std::move(decompChunks), decompOwnershipTruncated,
                std::move(noreturnTargets));
}

void AnalysisService::requestBulkWithListing(const BinaryFile* bin, const DecoderConfig& decoder,
                                             uint32_t kinds, bool guessNames, uint64_t epoch,
                                             std::shared_ptr<const ListingLayout> listingLayout,
                                             uint64_t listingRevision,
                                             std::shared_ptr<const std::vector<StrResult>> listingStrings,
                                             uint64_t moduleBase,
                                             std::shared_ptr<const CodeDataMap> listingCodeData,
                                             std::shared_ptr<const ProjectAnalysisOverrides> analysisOverrides,
                                             uint64_t orderedPatchDigest) {
    requestBulkImpl(bin, decoder, kinds, guessNames, epoch,
                    moduleBase, 0, 0, false, {}, {}, 0,
                    std::move(listingLayout), listingRevision, std::move(listingStrings), 0, 0,
                    std::move(listingCodeData), std::move(analysisOverrides),
                    orderedPatchDigest);
}

void AnalysisService::requestBulkWithListing(const BinaryFile* bin, Engine engine, Arch arch,
                                             uint32_t kinds, bool guessNames, uint64_t epoch,
                                             std::shared_ptr<const ListingLayout> listingLayout,
                                             uint64_t listingRevision,
                                             std::shared_ptr<const std::vector<StrResult>> listingStrings,
                                             uint64_t moduleBase,
                                             std::shared_ptr<const CodeDataMap> listingCodeData,
                                             std::shared_ptr<const ProjectAnalysisOverrides> analysisOverrides,
                                             uint64_t orderedPatchDigest) {
    DecoderConfig decoder;
    decoder.engine = engine;
    decoder.arch = arch;
    requestBulkWithListing(bin, decoder, kinds, guessNames, epoch,
                           std::move(listingLayout), listingRevision,
                           std::move(listingStrings), moduleBase,
                           std::move(listingCodeData), std::move(analysisOverrides),
                           orderedPatchDigest);
}

void AnalysisService::requestListingPrefix(const BinaryFile* bin, const DecoderConfig& decoder,
                                           uint64_t epoch, uint64_t startVA,
                                           uint64_t pageBase, uint64_t targetPage,
                                           uint64_t listingRevision,
                                           uint64_t orderedPatchDigest,
                                           uint64_t listingTopologyGeneration) {
    requestBulkImpl(bin, decoder, K_ListingPrefix, false, epoch,
                    0, startVA, targetPage, true, {}, {}, 0, {}, listingRevision, {}, pageBase,
                    listingTopologyGeneration, {}, {}, orderedPatchDigest);
}

void AnalysisService::requestListingPrefix(const BinaryFile* bin, Engine engine, Arch arch,
                                           uint64_t epoch, uint64_t startVA,
                                           uint64_t pageBase, uint64_t targetPage,
                                           uint64_t listingRevision,
                                           uint64_t orderedPatchDigest,
                                           uint64_t listingTopologyGeneration) {
    DecoderConfig decoder;
    decoder.engine = engine;
    decoder.arch = arch;
    requestListingPrefix(bin, decoder, epoch, startVA, pageBase, targetPage,
                         listingRevision, orderedPatchDigest,
                         listingTopologyGeneration);
}

void AnalysisService::requestBulkImpl(const BinaryFile* bin, const DecoderConfig& decoder,
                                      uint32_t kinds, bool guessNames, uint64_t epoch,
                                      uint64_t moduleBase, uint64_t regionLo, uint64_t regionHi,
                                      bool regionValid,
                                      std::shared_ptr<const DecompileNameMap> decompNames,
                                      std::string decompSignature, uint64_t decompContext,
                                       std::shared_ptr<const ListingLayout> listingLayout,
                                       uint64_t listingRevision,
                                       std::shared_ptr<const std::vector<StrResult>> listingStrings,
                                       uint64_t listingPrefixPageBase,
                                       uint64_t listingTopologyGeneration,
                                       std::shared_ptr<const CodeDataMap> listingCodeData,
                                       std::shared_ptr<const ProjectAnalysisOverrides> analysisOverrides,
                                       uint64_t orderedPatchDigest,
                                       std::shared_ptr<const std::vector<FunctionChunk>> decompChunks,
                                       bool decompOwnershipTruncated,
                                       std::shared_ptr<const std::vector<uint64_t>> noreturnTargets) {
    // Triage is a self-contained request contract: callers need not know which
    // existing passes provide its correlation inputs.  These dependencies are
    // still delivered incrementally and can satisfy other consumers/caches.
    if (kinds & K_CrackmeTriage)
        kinds |= K_Strings | K_Funcs | K_Xref | K_CallGraph | K_Intent;
    BulkJob job;
    job.bin = bin;
    job.decoder = bin ? DecoderConfigForImage(*bin, decoder) : decoder;
    job.kinds = kinds;
    job.guess = guessNames;
    job.epoch = epoch;
    job.modBase = moduleBase;
    job.regionLo = regionLo;
    job.regionHi = regionHi;
    job.regionValid = regionValid;
    job.decompNames = std::move(decompNames);
    job.decompSignature = std::move(decompSignature);
    job.decompContext = decompContext;
    job.decompChunks = std::move(decompChunks);
    job.decompOwnershipTruncated = decompOwnershipTruncated;
    job.noreturnTargets = std::move(noreturnTargets);
    job.analysisOverrides = std::move(analysisOverrides);
    job.orderedPatchDigest = orderedPatchDigest;
    job.listingLayout = std::move(listingLayout);
    job.listingRevision = listingRevision;
    job.listingStrings = std::move(listingStrings);
    job.listingCodeData = std::move(listingCodeData);
    job.listingPrefixPageBase = listingPrefixPageBase;
    job.listingTopologyGeneration = listingTopologyGeneration;
    std::vector<BulkJob> rejected;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (epoch != epoch_.load(std::memory_order_acquire) || quit_.load()) return;
        constexpr uint32_t kTargeted = K_Synthesis | K_PathExplore | K_Decompile | K_ListingPrefix | K_ValueOrigin | K_StringActionTrace;
        // Do not let whole-image dependencies delay a requested function even
        // when a caller supplied both kinds in one request.
        if ((kinds & kTargeted) && (kinds & ~kTargeted)) {
            BulkJob bulk = job;
            bulk.kinds &= ~kTargeted;
            bulk.regionLo = bulk.regionHi = 0;
            bulk.regionValid = false;
            job.kinds &= kTargeted;
            enqueueLocked(std::move(job), rejected);
            enqueueLocked(std::move(bulk), rejected);
        } else if (kinds) {
            enqueueLocked(std::move(job), rejected);
        }
        for (const BulkJob& refused : rejected) finishModuleLocked(refused);
        refreshPendingLocked();
    }
    // Reporting takes mtx_ itself. Preserve exact prefix/failure identities so
    // the consumer can retire pending ownership and retry after overload.
    for (const BulkJob& refused : rejected)
        publishFailure(refused, "analysis scheduler capacity reached; retry the request");
    cv_.notify_all();
}

void AnalysisService::requestValueOrigin(const BinaryFile* bin, const DecoderConfig& decoder,
                                        uint64_t epoch, std::shared_ptr<const ValueOriginRequest> request) {
    if (!request) return;
    BulkJob job;
    job.bin = bin;
    job.decoder = bin ? DecoderConfigForImage(*bin, decoder) : decoder;
    job.epoch = epoch;
    job.kinds = K_ValueOrigin;
    job.regionLo = request->functionVA;
    job.regionHi = request->instructionVA;
    job.regionValid = true;
    job.valueOrigin = std::move(request);
    std::vector<BulkJob> rejected;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (epoch != epoch_.load(std::memory_order_acquire) || quit_.load()) return;
        enqueueLocked(std::move(job), rejected);
        for (const auto& refused : rejected) finishModuleLocked(refused);
        refreshPendingLocked();
    }
    for (const auto& refused : rejected)
        publishFailure(refused, "analysis scheduler capacity reached; retry the request");
    cv_.notify_all();
}

bool AnalysisService::interactive(const BulkJob& job) {
    constexpr uint32_t kTargeted = K_Synthesis | K_PathExplore | K_Decompile | K_ListingPrefix | K_ValueOrigin | K_StringActionTrace;
    return (job.kinds & kTargeted) != 0 || job.kinds == K_Listing;
}

void AnalysisService::requestStringActionTrace(const BinaryFile* bin, const DecoderConfig& decoder,
    uint64_t epoch, std::shared_ptr<const StringActionTraceRequest> request,
    std::shared_ptr<const std::vector<FuncResult>> functions) {
    if (!request || !functions) return;
    BulkJob job;
    job.bin = bin;
    job.decoder = bin ? DecoderConfigForImage(*bin, decoder) : decoder;
    job.epoch = epoch;
    job.kinds = K_StringActionTrace;
    job.regionLo = request->stringVA;
    job.regionValid = true;
    job.stringActionTrace = std::move(request);
    job.stringActionFunctions = std::move(functions);
    std::vector<BulkJob> rejected;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (epoch != epoch_.load(std::memory_order_acquire) || quit_.load()) return;
        enqueueLocked(std::move(job), rejected);
        for (const auto& refused : rejected) finishModuleLocked(refused);
        refreshPendingLocked();
    }
    for (const auto& refused : rejected)
        publishFailure(refused, "analysis scheduler capacity reached; retry the request");
    cv_.notify_all();
}

void AnalysisService::enqueueLocked(BulkJob job, std::vector<BulkJob>& rejected) {
    constexpr uint32_t kTargeted = K_Synthesis | K_PathExplore | K_Decompile | K_ListingPrefix | K_ValueOrigin | K_StringActionTrace;
    for (BulkJob& queued : queue_) {
        if (queued.bin != job.bin || queued.modBase != job.modBase ||
            queued.epoch != job.epoch || queued.decoder != job.decoder ||
            queued.guess != job.guess || queued.orderedPatchDigest != job.orderedPatchDigest ||
            interactive(queued) != interactive(job) ||
            (queued.kinds & kTargeted) != (job.kinds & kTargeted)) continue;
        if ((job.kinds & K_ListingPrefix) && queued.regionHi != job.regionHi) continue;
        // New snapshots win, including explicitly empty override definitions.
        // A request without project state must preserve the pending snapshot.
        if (!job.analysisOverrides) job.analysisOverrides = queued.analysisOverrides;
        constexpr uint32_t kNoreturnConsumers = K_CallGraph | K_CrackmeTriage |
                                               K_Decompile | K_Synthesis | K_PathExplore;
        // A string/listing/xref refresh says nothing about another pass's CFG
        // inputs. Only a newer consuming request may replace (or clear) them.
        if (!(job.kinds & kNoreturnConsumers))
            job.noreturnTargets = queued.noreturnTargets;
        if (!(job.kinds & K_Listing) && (queued.kinds & K_Listing)) {
            job.listingLayout = std::move(queued.listingLayout);
            job.listingRevision = queued.listingRevision;
            job.listingStrings = std::move(queued.listingStrings);
            job.listingCodeData = std::move(queued.listingCodeData);
        }
        job.kinds |= queued.kinds;
        queued = std::move(job);
        coalescedRequests_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (queue_.size() + static_cast<size_t>(inFlight_) >= kMaxOutstandingJobs) {
        auto displaced = queue_.end();
        if (interactive(job)) {
            // The newest bulk request has made the least progress. Do not evict
            // a resumed pass whose already-published dependency state is useful.
            for (auto it = queue_.begin(); it != queue_.end(); ++it)
                if (!interactive(*it) && !it->publishedKinds) displaced = it;
        }
        rejectedRequests_.fetch_add(1, std::memory_order_relaxed);
        if (displaced == queue_.end()) {
            rejected.push_back(std::move(job));
            return;
        }
        rejected.push_back(std::move(*displaced));
        queue_.erase(displaced);
    }
    queue_.push_back(std::move(job));
}

void AnalysisService::refreshPendingLocked() {
    uint32_t kinds = 0, interactions = 0;
    for (const BulkJob& job : queue_) {
        kinds |= job.kinds;
        interactions += interactive(job) ? 1u : 0u;
    }
    for (uint32_t running : inFlightKinds_) kinds |= running;
    queuedInteractive_.store(interactions, std::memory_order_release);
    queuedJobs_.store(static_cast<uint32_t>(queue_.size()), std::memory_order_relaxed);
    runningJobs_.store(static_cast<uint32_t>(inFlight_), std::memory_order_relaxed);
    pendingKinds_.store(kinds, std::memory_order_release);
    pending_.store(!queue_.empty() || inFlight_ != 0, std::memory_order_release);
    scheduler().notify();
}

void AnalysisService::finishModuleLocked(const BulkJob& job) {
    const uint32_t total = progModTotal_.load(std::memory_order_relaxed);
    if (job.modBase == 0 || total == 0) return;
    const uint32_t done = progModDone_.fetch_add(1, std::memory_order_relaxed) + 1;
    if (done >= total) {
        progModTotal_.store(0, std::memory_order_relaxed);
        progModDone_.store(0, std::memory_order_relaxed);
    }
}

bool AnalysisService::tryTakeBulk(AnalysisResult& out) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (results_.empty()) return false;
    out = std::move(results_.front());
    results_.pop_front();
    return true;
}

ProgressSnapshot AnalysisService::progress() const {
    ProgressSnapshot s;
    s.phase        = (AnalysisPhase)progPhase_.load(std::memory_order_acquire);
    s.current      = progCur_.load(std::memory_order_relaxed);
    s.total        = progTotal_.load(std::memory_order_relaxed);
    s.modulesDone  = progModDone_.load(std::memory_order_relaxed);
    s.modulesTotal = progModTotal_.load(std::memory_order_relaxed);
    s.moduleBase   = progModBase_.load(std::memory_order_relaxed);
    s.jobsFailed   = failedJobs_.load(std::memory_order_relaxed);
    s.resultsDropped = droppedResults_.load(std::memory_order_relaxed);
    s.requestsCoalesced = coalescedRequests_.load(std::memory_order_relaxed);
    s.requestsRejected = rejectedRequests_.load(std::memory_order_relaxed);
    s.jobsYielded = yieldedJobs_.load(std::memory_order_relaxed);
    s.queuedJobs = queuedJobs_.load(std::memory_order_relaxed);
    s.runningJobs = runningJobs_.load(std::memory_order_relaxed);
    s.cacheHits = cacheHits_.load(std::memory_order_relaxed);
    s.cacheMisses = cacheMisses_.load(std::memory_order_relaxed);
    return s;
}

void AnalysisService::cancelAndWaitIdle() {
    std::unique_lock<std::mutex> lk(mtx_);
    queue_.clear();                                  // drop all queued requests
    results_.clear();                                // and any finished-but-unpicked results
    epoch_.fetch_add(1, std::memory_order_acq_rel);  // supersede everything running
    refreshPendingLocked();
    progModTotal_.store(0, std::memory_order_relaxed);
    progModDone_.store(0, std::memory_order_relaxed);
    progPhase_.store((uint32_t)AnalysisPhase::Idle, std::memory_order_relaxed);
    cvIdle_.wait(lk, [this] { return inFlight_ == 0; });  // block until workers yield
}

void AnalysisService::cancelPending() {
    std::lock_guard<std::mutex> lk(mtx_);
    queue_.clear();                                  // drop all queued requests
    results_.clear();                                // and any finished-but-unpicked results
    epoch_.fetch_add(1, std::memory_order_acq_rel);  // supersede everything running (bails at a checkpoint)
    refreshPendingLocked();
    progModTotal_.store(0, std::memory_order_relaxed);
    progModDone_.store(0, std::memory_order_relaxed);
}

void AnalysisService::setPhase(AnalysisPhase p, uint32_t total, uint64_t modBase) {
    progPhase_.store((uint32_t)p, std::memory_order_release);
    progTotal_.store(total, std::memory_order_relaxed);
    progCur_.store(0, std::memory_order_relaxed);
    progModBase_.store(modBase, std::memory_order_relaxed);
}

void AnalysisService::publishResult(AnalysisResult&& result) {
    std::lock_guard<std::mutex> lk(mtx_);
    results_.push_back(std::move(result));
    if (results_.size() > 512) {
        results_.pop_front();
        droppedResults_.fetch_add(1, std::memory_order_relaxed);
    }
}

void AnalysisService::publishFailure(const BulkJob& job, const char* message) noexcept {
    failedJobs_.fetch_add(1, std::memory_order_relaxed);
    try {
        AnalysisResult failure;
        failure.epoch = job.epoch;
        failure.kinds = job.kinds;
        failure.moduleBase = job.modBase;
        failure.regionLo = job.regionLo;
        failure.regionHi = job.regionHi;
        failure.regionValid = job.regionValid;
        if (job.valueOrigin) failure.valueOriginRequestId = job.valueOrigin->requestId;
        if (job.stringActionTrace) failure.stringActionTraceRequestId = job.stringActionTrace->requestId;
        failure.listingRevision = job.listingRevision;
        failure.listingTopologyGeneration = job.listingTopologyGeneration;
        if (job.kinds & K_ListingPrefix) {
            // Preserve the exact pending-owner identity even on failure so the
            // UI can retire this attempt and allow a later visibility retry.
            failure.listingPrefixDone = true;
            failure.listingPrefixTarget = job.regionHi;
        }
        failure.failure = message && *message ? message : "unknown analysis worker error";
        failure.failureValid = true;
        publishResult(std::move(failure));
    } catch (...) {
        // Reporting must not let a second allocation failure escape the worker.
        droppedResults_.fetch_add(1, std::memory_order_relaxed);
    }
}

void AnalysisService::threadMain(unsigned workerIndex) {
    for (;;) {
        BulkJob job;
        {
            std::unique_lock<std::mutex> lk(mtx_);
            cv_.wait(lk, [this] { return quit_.load() || !queue_.empty(); });
            if (quit_.load()) return;
        }
        // Wait for shared CPU admission before claiming a job. A selected-view
        // request can therefore overtake bulk work even while this worker waits.
        if (!scheduler().acquire(*this)) continue;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (quit_.load() || queue_.empty()) {
                scheduler().release(*this);
                if (quit_.load()) return;
                continue;
            }
            auto next = std::find_if(queue_.begin(), queue_.end(), interactive);
            if (next == queue_.end()) next = queue_.begin();
            job = std::move(*next);
            queue_.erase(next);
            job.yielded = false;
            ++inFlight_;
            inFlightKinds_[workerIndex] = job.kinds;
            refreshPendingLocked();
        }

        try {
            runJob(job);
        } catch (const std::exception& e) {
            job.yielded = false;
            publishFailure(job, e.what());
        } catch (...) {
            job.yielded = false;
            publishFailure(job, "unknown analysis worker exception");
        }

        {
            std::lock_guard<std::mutex> lk(mtx_);
            --inFlight_;
            inFlightKinds_[workerIndex] = 0;
            const bool resume = job.yielded && !quit_.load() && job.epoch == epoch();
            if (resume) {
                // Keep original dependency kinds so their immutable cached facts
                // are restored on restart, but do not deliver completed passes twice.
                yieldedJobs_.fetch_add(1, std::memory_order_relaxed);
                queue_.push_front(std::move(job));
            }
            // Count a completed module-batch job (even when superseded, so a cancelled
            // batch still converges and resets its counters).
            if (!resume) finishModuleLocked(job);
            refreshPendingLocked();
            bool idle = queue_.empty() && inFlight_ == 0;
            if (idle) {
                progPhase_.store((uint32_t)AnalysisPhase::Idle, std::memory_order_relaxed);
            }
        }
        scheduler().release(*this);
        cv_.notify_all();
        cvIdle_.notify_all();
    }
}

void AnalysisService::runJob(BulkJob& job) {
    auto superseded = [this, &job] {
        if (quit_.load(std::memory_order_acquire) ||
            epoch_.load(std::memory_order_acquire) != job.epoch) return true;
        const unsigned priority = interactive(job) ? 0u :
            (activeDocument_.load(std::memory_order_acquire) ? 1u : 2u);
        // An interaction queued behind this owner's busy workers needs one of
        // those workers to yield. Other owners only yield to runnable work;
        // a full local pool cannot consume their free global slots yet.
        if ((!interactive(job) && queuedInteractive_.load(std::memory_order_acquire)) ||
            scheduler().bestRunnablePriority.load(std::memory_order_acquire) < priority)
            job.yielded = true;
        return job.yielded;
    };
    // Drop a job already superseded by a newer epoch before touching the (possibly
    // freed) binary.
    if (superseded() || !job.bin) return;
    std::unique_ptr<IDisassembler> dis = factory_ ? factory_(job.decoder) : nullptr;
    if (!dis) {
        publishFailure(job, "decoder factory returned no decoder");
        return;
    }
    if (job.decoder.arch == Arch::GML && job.bin->gameMakerArchive())
        AttachGameMakerArchive(*dis, job.bin->gameMakerArchive());
    if (!dis->ready()) {
        std::string message = "decoder initialization failed";
        if (!dis->errorMessage().empty()) {
            message += ": ";
            message.append(dis->errorMessage());
        }
        publishFailure(job, message.c_str());
        return;
    }
    // Java class: hand the worker's own decoder the parsed class so listing
    // operands symbolicate (constant pool) and switch padding is exact. The
    // shared_ptr keeps the class alive for the job even across a concurrent
    // unload (the epoch check still drops the stale result).
    if (job.decoder.arch == Arch::JVM && job.bin->javaClass())
        AttachJvmClass(*dis, job.bin->javaClass());

    // Emit one result per pass, the moment it finishes, so the consumer can apply the
    // cheap functions/strings immediately and the heavier listing/xref later.
    auto emit = [&](AnalysisResult&& r) {
        if (superseded()) return;
        uint32_t pass = 0;
        if (r.stringsValid) pass |= K_Strings;
        if (r.funcsValid) pass |= K_Funcs;
        if (r.listingValid) pass |= K_Listing;
        if (r.listingPrefixDone) pass |= K_ListingPrefix;
        if (r.xref) pass |= K_Xref;
        if (r.algosValid) pass |= K_Intent;
        if (r.callGraphValid) pass |= K_CallGraph;
        if (r.crackmeTriageValid) pass |= K_CrackmeTriage;
        if (r.synthValid) pass |= K_Synthesis;
        if (r.pathValid) pass |= K_PathExplore;
        if (r.decompValid) pass |= K_Decompile;
        if (r.valueOrigin) pass |= K_ValueOrigin;
        if (r.stringActionTrace) pass |= K_StringActionTrace;
        if (pass && (job.publishedKinds & pass) == pass) return;
        r.epoch   = job.epoch;
        r.kinds   = job.kinds;
        r.moduleBase = job.modBase;
        r.regionLo = job.regionLo;
        r.regionHi = job.regionHi;
        r.regionValid = job.regionValid;
        r.listingRevision = job.listingRevision;
        r.listingTopologyGeneration = job.listingTopologyGeneration;
        publishResult(std::move(r));
        job.publishedKinds |= pass;
    };

    if ((job.kinds & K_ValueOrigin) && job.valueOrigin) {
        const auto& request = *job.valueOrigin;
        auto cancelled = [&] {
            return superseded() || (request.cancellation && request.cancellation->load(std::memory_order_acquire));
        };
        auto value = BuildValueOrigin(*job.bin, *dis, job.decoder.arch, request, cancelled);
        if (!cancelled() && !value.cancelled) {
            AnalysisResult result;
            result.valueOrigin = std::make_shared<const ValueOriginResult>(std::move(value));
            result.valueOriginRequestId = request.requestId;
            emit(std::move(result));
        }
        if (job.kinds == K_ValueOrigin) return;
    }

    if ((job.kinds & K_StringActionTrace) && job.stringActionTrace) {
        auto request = *job.stringActionTrace;
        auto cancelled = [&] {
            return superseded() || (request.cancellation && request.cancellation->load(std::memory_order_acquire));
        };
        constexpr size_t kMaxFunctions = 100000;
        const auto& functions = job.stringActionFunctions;
        if (functions) {
            request.functions.clear();
            request.functions.reserve(std::min(functions->size(), kMaxFunctions));
            for (size_t i = 0; i < std::min(functions->size(), kMaxFunctions); ++i) {
                if (cancelled()) return;
                const auto& f = (*functions)[i];
                DiscoveredFunction next;
                next.address = f.address; next.size = f.size; next.name = f.name;
                next.isExport = f.isExport; next.noreturn = f.noreturn;
                const size_t chunks = std::min<size_t>(f.chunks.size(), 256);
                next.chunks.assign(f.chunks.begin(), f.chunks.begin() + chunks);
                next.ownershipTruncated = f.ownershipTruncated || chunks != f.chunks.size();
                next.seedKind = f.seedKind; next.boundaryConfidence = f.boundaryConfidence;
                request.functions.push_back(std::move(next));
            }
        }
        auto trace = BuildStringActionTrace(*job.bin, *dis, job.decoder.arch, request, cancelled);
        if (functions && functions->size() > kMaxFunctions) {
            trace.complete = false;
            trace.limitations.push_back("Function inventory limited to 100,000 entries.");
        }
        if (!cancelled() && !trace.cancelled) {
            AnalysisResult result;
            result.stringActionTrace = std::make_shared<const StringActionTraceResult>(std::move(trace));
            result.stringActionTraceRequestId = request.requestId;
            emit(std::move(result));
        }
        if (job.kinds == K_StringActionTrace) return;
    }

    const uint64_t pristineHash = job.bin->contentHash();
    const uint64_t mappingInputs = binaryMappingInputsDigest(*job.bin);
    const uint64_t overrideDigest = DigestAnalysisOverrides(job.analysisOverrides.get());
    const uint64_t noreturnDigest = noreturnInputsDigest(job.noreturnTargets.get());
    auto cacheKey = [&](AnalysisCachePass pass, uint64_t passInputs = 0) {
        PassDigest framedInputs;
        framedInputs.u64(mappingInputs);
        framedInputs.u64(passInputs);
        return MakeAnalysisCacheKey(pristineHash, job.orderedPatchDigest,
                                    job.decoder, job.guess,
                                    overrideDigest, pass, framedInputs.finish());
    };
    auto cacheLookup = [&](const AnalysisCacheKey& key, AnalysisResult& result) {
        try {
            if (auto cached = cache_.find<AnalysisResult>(key)) {
                result = materializeCached(*cached, job.bin->imageRevision());
                cacheHits_.fetch_add(1, std::memory_order_relaxed);
                return true;
            }
        } catch (...) {
            // Cache reuse is an optimization. Allocation pressure while cloning a
            // cached immutable snapshot falls back to the ordinary pass.
        }
        cacheMisses_.fetch_add(1, std::memory_order_relaxed);
        return false;
    };
    auto cacheRemember = [&](const AnalysisCacheKey& key,
                             const AnalysisResult& result) noexcept {
        try {
            const size_t bytes = EstimateAnalysisResultBytes(result);
            if (cache_.canStore(bytes))
                cache_.put<AnalysisResult>(key, snapshotForCache(result), bytes);
        } catch (...) {
            // Never convert a successful analysis pass into a worker failure just
            // because the bounded opportunistic cache could not retain it.
        }
    };

    std::vector<StrResult>  strings;  bool haveStrings = false;
    bool stringsTruncatedState = false;
    std::vector<FuncResult> funcs;
    std::vector<CallEdgeR> callEdges;
    std::vector<AlgoMatch> algos;
    std::shared_ptr<const CodeDataMap> codeData = job.listingCodeData;
    if (!(job.kinds & K_Funcs) && job.analysisOverrides)
        codeData = ApplyCodeDataOverrides(*job.bin, job.analysisOverrides->data, std::move(codeData));
    std::shared_ptr<XrefIndex> xrefIdx;   // built by K_Xref; reused by K_Intent for extent mapping

    auto ensureStrings = [&](bool publish) {
        if (haveStrings) return;
        const AnalysisCacheKey key = cacheKey(AnalysisCachePass::Strings,
                                               kDefaultStringScanCap);
        AnalysisResult cached;
        if (cacheLookup(key, cached) && cached.stringsValid) {
            strings = publish ? cached.strings : std::move(cached.strings);
            stringsTruncatedState = cached.stringsTruncated;
            haveStrings = true;
            if (publish && !superseded()) emit(std::move(cached));
            return;
        }
        strings = ScanStringsImage(*job.bin, kDefaultStringScanCap,
                                   publish ? &progCur_ : nullptr,
                                   &stringsTruncatedState, superseded);
        haveStrings = true;
        if (superseded()) return;
        AnalysisResult result;
        result.strings = strings;
        result.stringsValid = true;
        result.stringsTruncated = stringsTruncatedState;
        cacheRemember(key, result);
        if (publish) emit(std::move(result));
    };

    if ((job.kinds & K_Strings) && !superseded()) {
        const size_t imageBytes = job.bin->bytes().size();
        setPhase(AnalysisPhase::Strings,
                 (uint32_t)std::min(imageBytes, (size_t)std::numeric_limits<uint32_t>::max()),
                 job.modBase);
        ensureStrings(true);
    }

    bool haveFunctionAnalysis = false;
    auto ensureFunctionAnalysis = [&](bool publish) {
        if (haveFunctionAnalysis || superseded()) return;
        haveFunctionAnalysis = true;
        setPhase(AnalysisPhase::Functions, 0, job.modBase);
        const AnalysisCacheKey key = cacheKey(AnalysisCachePass::Functions);
        AnalysisResult cached;
        if (cacheLookup(key, cached) && cached.funcsValid) {
            funcs = publish ? cached.functions : std::move(cached.functions);
            codeData = cached.codeData;
            if (publish) emit(std::move(cached));
            // Combined function/listing requests historically include scanned
            // strings even without K_Strings. Preserve that layout on a hit.
            if ((job.kinds & K_Listing) && !haveStrings)
                ensureStrings(false);
        } else {
            // A cached Functions result already includes classification/naming.
            // Fetch strings only when those passes actually need recomputation.
            if (!haveStrings) ensureStrings(false);
            if (superseded()) return;
            AnalyzeOut a = AnalyzeFunctionsNamed(*job.bin, *dis, strings, job.guess, job.decoder,
                                                 superseded,
                                                 analystFunctionSeeds(*job.bin,
                                                                      job.analysisOverrides),
                                                 analystNoreturnDecisions(job.analysisOverrides));
            if (!superseded()) {
                if (job.analysisOverrides)
                    applyFunctionOverrides(*job.bin, *job.analysisOverrides, a.functions);
                funcs = std::move(a.functions);
                if (a.codeDataValid)
                    codeData = std::make_shared<CodeDataMap>(std::move(a.codeData));
                if (job.analysisOverrides)
                    codeData = ApplyCodeDataOverrides(*job.bin, job.analysisOverrides->data,
                                                  std::move(codeData));
                AnalysisResult result;
                result.functions = funcs;
                result.summary = std::move(a.summary);
                result.codeData = codeData;
                result.funcsValid = true;
                cacheRemember(key, result);
                if (publish) emit(std::move(result));
            }
        }
    };
    if ((job.kinds & K_Funcs) && !superseded()) ensureFunctionAnalysis(true);

    if ((job.kinds & K_Listing) && !superseded()) {
        uint64_t codeBytes = 0;
        for (const ListingRegionPlan& region : PlanListingRegions(*job.bin, job.listingLayout.get()))
            if (region.executable && !region.folded) codeBytes += region.mappedSize;
        setPhase(AnalysisPhase::Listing,
                 (uint32_t)std::min<uint64_t>(codeBytes, std::numeric_limits<uint32_t>::max()),
                 job.modBase);
        // This pass only describes fixed-size executable pages and static data
        // rows. It deliberately performs no instruction decode or local function
        // discovery; visible/on-demand pages materialize in Binary View.
        if (!haveStrings && job.listingStrings) {
            strings = *job.listingStrings;
            haveStrings = true;
        }
        const AnalysisCacheKey key = cacheKey(
            AnalysisCachePass::Listing,
            listingInputsDigest(job.listingLayout.get(), strings, codeData.get()));
        AnalysisResult cached;
        if (cacheLookup(key, cached) && cached.listingValid) {
            emit(std::move(cached));
        } else {
            // A listing-only fold/visibility rebuild stays proportional to the
            // number of descriptors. Without a caller snapshot, omit optional
            // string rows instead of silently rescanning the complete image.
            std::vector<ListRowR> rows = BuildListingRows(
                *job.bin, strings, superseded, &progCur_, job.listingLayout.get(),
                kDefaultListingDataByteCap, codeData.get());
            if (!superseded()) {
                uint64_t pages = 0, bytes = 0;
                for (const auto& row : rows) if (row.type == ListingRowType::CodePage) {
                    ++pages; bytes += row.aux;
                }
                AnalysisResult result; result.listRows = std::move(rows);
                result.listingCodeBytes = bytes;
                result.listingCodePages = pages;
                result.listingValid = true;
                cacheRemember(key, result);
                emit(std::move(result));
            }
        }
    }

    if ((job.kinds & K_ListingPrefix) && !superseded()) {
        const uint64_t distance = job.regionHi >= job.regionLo ? job.regionHi - job.regionLo : 0;
        setPhase(AnalysisPhase::ListingPrefix,
                 (uint32_t)std::min<uint64_t>(distance, std::numeric_limits<uint32_t>::max()),
                 job.modBase);
        const AnalysisCacheKey key = cacheKey(
            AnalysisCachePass::ListingPrefix,
            listingPrefixInputsDigest(job.regionLo, job.listingPrefixPageBase,
                                      job.regionHi));
        AnalysisResult cached;
        if (cacheLookup(key, cached) && cached.listingPrefixDone) {
            emit(std::move(cached));
        } else {
            size_t available = 0;
            const uint8_t* bytes = job.bin->ptrFromVA(job.regionLo, available);
            ListingPrefixResult prefix;
            if (bytes && job.regionHi >= job.regionLo) {
                const size_t lookahead = ListingArchMaxInstructionBytes(job.decoder.arch);
                prefix = BuildListingPrefixCheckpoints(
                    bytes, available, job.regionLo, job.listingPrefixPageBase,
                    job.regionHi, lookahead, *dis, superseded, &progCur_);
            }
            if (!superseded()) {
                AnalysisResult result;
                result.listingPrefixDone = true;
                result.listingPrefixValid = prefix.complete;
                result.listingPrefixTarget = job.regionHi;
                result.listingPrefixCheckpoints = std::move(prefix.checkpoints);
                cacheRemember(key, result);
                emit(std::move(result));
            }
        }
    }

    if ((job.kinds & K_CallGraph) && !superseded()) {
        const AnalysisCacheKey key = cacheKey(AnalysisCachePass::CallGraph, noreturnDigest);
        AnalysisResult cached;
        if (cacheLookup(key, cached) && cached.callGraphValid) {
            callEdges = cached.callEdges;
            emit(std::move(cached));
        } else {
            // Reuse this job's discovered functions when K_Funcs ran; otherwise
            // discover them locally without emitting a funcs result.
            ensureFunctionAnalysis(false);
            const std::vector<FuncResult>* fp = &funcs;
            JumpTableResolver jumpTables = [binary = job.bin, decoder = job.decoder,
                                            decoderInstance = dis.get()](
                                               const Instruction& instruction) {
                JumpTableResolution table = ResolveJumpTable(
                    *binary, *decoderInstance, decoder.arch, decoder.byteOrder,
                    instruction);
                ResolvedJumpTable resolved;
                if (table.valid) resolved.targets = std::move(table.targets);
                resolved.truncated = table.truncated;
                resolved.evidence = std::move(table.evidence);
                return resolved;
            };
            std::vector<CallEdgeR> edges = BuildCallEdges(
                *job.bin, *dis, *fp, jumpTables,
                noreturnResolver(job.bin, job.analysisOverrides,
                                 job.noreturnTargets, fp),
                [binary = job.bin](const Instruction& instruction, uint64_t& target) {
                    return binary->resolveInstructionTarget(instruction, target);
                }, superseded);
            if (!superseded()) {
                callEdges = edges;
                AnalysisResult result;
                result.callEdges = std::move(edges);
                result.callGraphValid = true;
                cacheRemember(key, result);
                emit(std::move(result));
            }
        }
    }

    if ((job.kinds & K_Xref) && !superseded()) {
        // Classification and xrefs have one direction of dependency. An xref-only
        // request reuses the Functions cache rather than inventing a second scope.
        ensureFunctionAnalysis(false);
        if (superseded()) return;
        const XrefRangePlan plan = PlanXrefRanges(*job.bin, codeData.get(), superseded);
        if (plan.cancelled || superseded()) return;
        PassDigest xrefInputs;
        xrefInputs.u64(xrefPolicyDigest());
        xrefInputs.u64(plan.scopeDigest);
        const AnalysisCacheKey key = cacheKey(AnalysisCachePass::Xref, xrefInputs.finish());
        AnalysisResult cached;
        if (cacheLookup(key, cached) && cached.xref) {
            xrefIdx = cached.xref;
            emit(std::move(cached));
        } else {
            setPhase(AnalysisPhase::Xref,
                     static_cast<uint32_t>(std::min<uint64_t>(plan.decodeBytes,
                         (std::numeric_limits<uint32_t>::max)())), job.modBase);
            xrefIdx = std::make_shared<XrefIndex>();
            xrefIdx->classificationApplied = plan.classificationApplied;
            xrefIdx->classificationScopeDigest = plan.scopeDigest;
            xrefIdx->classificationDataBytes = plan.classifiedDataBytes;
            xrefIdx->classificationTruncated = plan.classificationTruncated;
            XrefBuildLimits xrefLimits;
            xrefLimits.cancelled = superseded;
            xrefLimits.immediateTargetMapped = [binary = job.bin](uint64_t target) {
                size_t available = 0;
                return binary->ptrFromVA(target, available) != nullptr && available != 0;
            };
            for (const XrefCodeRange& range : plan.ranges) {
                if (superseded()) break;
                size_t available = 0;
                const uint8_t* bytes = job.bin->ptrFromVA(range.address, available);
                if (bytes && available &&
                    !BuildXrefInto(*xrefIdx, bytes, static_cast<size_t>(
                                      std::min<uint64_t>(available, range.size)),
                                   range.address, *dis, &progCur_,
                                   [binary = job.bin](const Instruction& instruction,
                                                      uint64_t& target) {
                                       return binary->resolveInstructionTarget(instruction, target);
                                   }, xrefLimits)) break;
            }
            FinalizeXrefIndex(*xrefIdx);
            if (!superseded()) {
                AnalysisResult result;
                result.xref = xrefIdx;
                result.codeData = codeData;
                result.xrefImageRevision = job.bin->imageRevision();
                result.xrefDecoderSignature = AnalysisIsaSignature(job.decoder);
                result.xrefOverrideDigest = overrideDigest;
                cacheRemember(key, result);
                emit(std::move(result));
            }
        }
    }

    // These immutable inputs are shared by both downstream cache keys. In
    // particular, sorting and hashing every xref target twice wastes load time.
    uint64_t downstreamFunctionsDigest = 0, downstreamXrefDigest = 0;
    if ((job.kinds & (K_Intent | K_CrackmeTriage)) && !superseded()) {
        downstreamFunctionsDigest = functionInputsDigest(funcs);
        downstreamXrefDigest = xrefInputsDigest(xrefIdx.get());
    }

    // Algorithm/crypto recognition (AlgoScan). Runs LAST so it can reuse this job's
    // function list (K_Funcs) and xref index (K_Xref) for extent mapping; either being
    // absent only drops the "referenced by" links, not the matches themselves.
    if ((job.kinds & K_Intent) && !superseded()) {
        PassDigest inputs;
        inputs.u64(downstreamFunctionsDigest);
        inputs.u64(downstreamXrefDigest);
        const AnalysisCacheKey key = cacheKey(AnalysisCachePass::Intent,
                                               inputs.finish());
        AnalysisResult cached;
        if (cacheLookup(key, cached) && cached.algosValid) {
            algos = cached.algos;
            emit(std::move(cached));
        } else {
            algos = ScanAlgorithmsJob(*job.bin, xrefIdx.get(), funcs, superseded);
            if (!superseded()) {
                AnalysisResult result;
                result.algos = algos;
                result.algosValid = true;
                cacheRemember(key, result);
                emit(std::move(result));
            }
        }
    }

    if ((job.kinds & K_CrackmeTriage) && !superseded()) {
        setPhase(AnalysisPhase::CrackmeTriage,
                 static_cast<uint32_t>((std::min<uint64_t>)(
                     job.bin->bytes().size(), (std::numeric_limits<uint32_t>::max)())),
                 job.modBase);
        PassDigest inputs;
        // Local decision CFGs also consume this snapshot even when their
        // changed fallthrough does not alter the function-level call edges.
        inputs.u64(noreturnDigest);
        inputs.u64(downstreamFunctionsDigest);
        inputs.u64(downstreamXrefDigest);
        inputs.u64(static_cast<uint64_t>(callEdges.size()));
        for (const CallEdgeR& edge : callEdges) {
            inputs.u64(edge.from);
            inputs.u64(edge.to);
        }
        inputs.u64(static_cast<uint64_t>(algos.size()));
        for (const AlgoMatch& match : algos) {
            inputs.text(match.name);
            inputs.text(match.category);
            inputs.u64(match.address);
            inputs.u8(match.addressValid ? 1u : 0u);
        }
        const AnalysisCacheKey key = cacheKey(AnalysisCachePass::CrackmeTriage,
                                               inputs.finish());
        AnalysisResult cached;
        if (cacheLookup(key, cached) && cached.crackmeTriageValid) {
            emit(std::move(cached));
        } else {
            CrackmeTriageInput triage;
            CodeByteSignatureBuilder codeSignatures(*job.bin);
            const std::vector<uint8_t>& bytes = job.bin->bytes();
            triage.bytes = bytes.data();
            triage.size = bytes.size();
            triage.offsetToVA = [binary = job.bin](uint64_t offset, uint64_t& va) {
                return binary->offsetToVA(offset, va);
            };
            triage.overlayOffset = job.bin->overlayOffset();
            triage.overlaySize = job.bin->overlaySize();
            triage.xrefs = xrefIdx.get();
            triage.cancelled = superseded;

            triage.imports.reserve((std::min)(job.bin->imports().size(),
                                              triage.limits.maxImports));
            for (const auto& imported : job.bin->imports()) {
                if (triage.imports.size() >= triage.limits.maxImports) break;
                CrackmeTriageImportInput item;
                item.dll = imported.dll;
                item.name = imported.name;
                item.address = imported.iatVA;
                item.addressValid = imported.addressKnown;
                triage.imports.push_back(std::move(item));
            }
            triage.importsComplete =
                triage.imports.size() == job.bin->imports().size();

            triage.functions.reserve((std::min)(funcs.size(),
                                                 triage.limits.maxOwnershipFunctions));
            bool ownershipRangesComplete = true;
            size_t retainedOwnershipRanges = 0;
            for (const FuncResult& function : funcs) {
                if (triage.functions.size() >= triage.limits.maxOwnershipFunctions) break;
                if (retainedOwnershipRanges >= triage.limits.maxOwnershipRanges) {
                    ownershipRangesComplete = false;
                    break;
                }
                CrackmeTriageFunctionInput item;
                item.address = function.address;
                item.size = function.size;
                item.name = function.name;
                if (function.chunks.empty()) {
                    ++retainedOwnershipRanges; // core will use address+size
                } else {
                    size_t rangeCount = (std::min)(
                        function.chunks.size(), triage.limits.maxRangesPerFunction);
                    rangeCount = (std::min)(
                        rangeCount,
                        triage.limits.maxOwnershipRanges - retainedOwnershipRanges);
                    if (rangeCount != function.chunks.size())
                        ownershipRangesComplete = false;
                    item.ranges.reserve(rangeCount);
                    for (size_t rangeIndex = 0; rangeIndex < rangeCount; ++rangeIndex) {
                        const FunctionChunk& chunk = function.chunks[rangeIndex];
                        item.ranges.push_back({ chunk.address, chunk.size });
                    }
                    retainedOwnershipRanges += rangeCount;
                }
                triage.functions.push_back(std::move(item));
            }
            triage.functionOwnershipComplete =
                funcs.size() <= triage.limits.maxOwnershipFunctions &&
                triage.functions.size() == funcs.size() && ownershipRangesComplete;
            triage.callEdges.reserve((std::min)(callEdges.size(), triage.limits.maxCallEdges));
            for (const CallEdgeR& edge : callEdges) {
                if (triage.callEdges.size() >= triage.limits.maxCallEdges) break;
                triage.callEdges.push_back({ edge.from, edge.to });
            }
            triage.callEdgesComplete =
                triage.callEdges.size() == callEdges.size();
            bool algorithmInputsComplete = true;
            for (const AlgoMatch& match : algos) {
                if (triage.algorithms.size() >= triage.limits.maxAlgorithmInputs) {
                    algorithmInputsComplete = false;
                    break;
                }
                if (match.referencedBy.empty()) {
                    CrackmeTriageAlgorithmInput item;
                    item.address = match.address;
                    item.addressValid = match.addressValid;
                    item.name = match.name;
                    item.category = match.category;
                    item.evidence = match.detail;
                    item.fileOffsetValid = match.addressValid &&
                        job.bin->vaToOffset(match.address, item.fileOffset);
                    triage.algorithms.push_back(std::move(item));
                    continue;
                }
                for (const AlgoXref& reference : match.referencedBy) {
                    if (triage.algorithms.size() >= triage.limits.maxAlgorithmInputs) {
                        algorithmInputsComplete = false;
                        break;
                    }
                    CrackmeTriageAlgorithmInput item;
                    item.address = match.address;
                    item.addressValid = match.addressValid;
                    item.functionAddress = reference.funcAddress;
                    item.functionAddressValid = reference.funcAddressValid;
                    item.name = match.name;
                    item.category = match.category;
                    item.evidence = match.detail;
                    item.fileOffsetValid = match.addressValid &&
                        job.bin->vaToOffset(match.address, item.fileOffset);
                    triage.algorithms.push_back(std::move(item));
                }
            }
            triage.algorithmsComplete = algorithmInputsComplete;

            CrackmeTriageReport report = RunCrackmeTriage(triage);
            AuthorizationAnalysisInput authorization;
            authorization.cancelled = superseded;
            authorization.functionsComplete = triage.functionOwnershipComplete;
            authorization.callEdgesComplete = triage.callEdgesComplete;
            authorization.decisionsComplete = true;
            authorization.stateOperationsComplete = true;
            authorization.functions.reserve((std::min)(
                triage.functions.size(), authorization.limits.maxFunctions));
            for (const CrackmeTriageFunctionInput& function : triage.functions) {
                if (authorization.functions.size() >= authorization.limits.maxFunctions) {
                    authorization.functionsComplete = false;
                    break;
                }
                authorization.functions.push_back(
                    {function.address, true, function.name});
            }
            authorization.callEdges.reserve((std::min)(
                triage.callEdges.size(), authorization.limits.maxCallEdges));
            for (const CrackmeTriageCallEdgeInput& edge : triage.callEdges) {
                if (authorization.callEdges.size() >= authorization.limits.maxCallEdges) {
                    authorization.callEdgesComplete = false;
                    break;
                }
                authorization.callEdges.push_back(
                    {edge.caller, true, edge.callee, true});
            }

            struct AuthorizationOwnershipRange {
                uint64_t lo = 0;
                uint64_t hi = 0;
                uint64_t owner = 0;
                std::string name;
            };
            std::vector<AuthorizationOwnershipRange> authorizationOwnership;
            authorizationOwnership.reserve((std::min)(
                triage.limits.maxOwnershipRanges, retainedOwnershipRanges));
            for (const CrackmeTriageFunctionInput& function : triage.functions) {
                auto retainRange = [&](uint64_t lo, uint64_t size) {
                    if (!size || lo > UINT64_MAX - size ||
                        authorizationOwnership.size() >= triage.limits.maxOwnershipRanges)
                        return;
                    authorizationOwnership.push_back(
                        {lo, lo + size, function.address, function.name});
                };
                if (function.ranges.empty()) retainRange(function.address, function.size);
                else for (const CrackmeTriageFunctionRange& range : function.ranges)
                    retainRange(range.address, range.size);
            }
            std::sort(authorizationOwnership.begin(), authorizationOwnership.end(),
                [](const AuthorizationOwnershipRange& left,
                   const AuthorizationOwnershipRange& right) {
                    if (left.lo != right.lo) return left.lo < right.lo;
                    if (left.hi != right.hi) return left.hi < right.hi;
                    return left.owner < right.owner;
                });
            auto authorizationOwner = [&](uint64_t address,
                                          uint64_t& owner,
                                          std::string& name) {
                const AuthorizationOwnershipRange* best = nullptr;
                auto it = std::upper_bound(authorizationOwnership.begin(),
                                           authorizationOwnership.end(), address,
                    [](uint64_t value, const AuthorizationOwnershipRange& range) {
                        return value < range.lo;
                    });
                size_t examined = 0;
                while (it != authorizationOwnership.begin() && examined++ < 128) {
                    --it;
                    if (it->lo > address) continue;
                    if (address >= it->hi) {
                        if (best) break;
                        continue;
                    }
                    if (!best || (it->hi - it->lo) < (best->hi - best->lo)) best = &*it;
                }
                if (!best) return false;
                owner = best->owner;
                name = best->name;
                return true;
            };
            auto addStartupRoot = [&](uint64_t address, const char* fallbackName) {
                uint64_t owner = 0;
                std::string name;
                const bool owned = authorizationOwner(address, owner, name);
                AuthorizationLocation root = authorizationLocation(
                    *job.bin, address, true, owned ? owner : address, true,
                    !name.empty() ? name : fallbackName);
                authorization.startupRoots.push_back(std::move(root));
                if (!owned) authorization.startupRootsComplete = false;
            };
            const BinFormat format = job.bin->format();
            const bool pe = format == BinFormat::PE32 || format == BinFormat::PE32Plus;
            if (pe && job.bin->hasEntryPoint())
                addStartupRoot(job.bin->entryPointVA(), "PE entry point");
            if (pe) {
                for (uint64_t callback : job.bin->peTls().callbacks)
                    addStartupRoot(callback, "PE TLS callback");
                if (job.bin->peTls().callbacksTruncated)
                    authorization.startupRootsComplete = false;
            }
            bool candidateFunctionsTruncated = false;
            bool networkCandidateNeighborhoodTruncated = false;
            bool predicateCandidateDiscoveryTruncated = false;
            size_t candidateFunctionsAvailable = 0;

            // Authorization candidates combine the existing network evidence
            // with exact persistence-API owners and the PE entry/TLS reachable
            // call graph. This pass intentionally runs even when no endpoint was
            // discovered so a remembered-access launch gate remains visible.
            if (!superseded() && pe && ArchIsX86_32Or64(job.decoder.arch)) {
                const CrackmeTriageCandidateSelection selection =
                    SelectCrackmeTriageAnnotationCandidates(
                        report, triage.functions, triage.limits.maxFunctions,
                        triage.limits.maxOwnershipFunctions,
                        triage.limits.maxRangesPerFunction,
                        triage.limits.maxOwnershipRanges);
                std::vector<uint64_t> candidatePriority;
                std::unordered_set<uint64_t> desiredCandidates;
                std::vector<uint64_t> exactNetworkOwners;
                constexpr size_t kMaxNetworkCandidateDepth = 4;
                constexpr size_t kMaxNetworkCandidateStates = 1024;
                auto addCandidate = [&](uint64_t address) {
                    if (desiredCandidates.insert(address).second)
                        candidatePriority.push_back(address);
                };

                // Direct owners of exact network, durable-state, and local
                // credential-input producer imports are placed before the cap.
                // Appending these owners after a full selection would silently
                // prevent reply or local input-buffer provenance.
                for (const auto& imported : job.bin->imports()) {
                    if (!imported.addressKnown) continue;
                    const bool exactNetwork =
                        LookupNetworkApi(imported.dll, imported.name).has_value();
                    const bool exactState =
                        LookupPersistentStateApi(imported.dll, imported.name)
                            .has_value();
                    const bool exactValidationProducer =
                        LookupValidationInputProducer(imported.dll,
                                                      imported.name)
                            .has_value();
                    const bool exactVerifier =
                        LookupVerificationApi(imported.dll, imported.name)
                            .has_value();
                    const bool exactMachineIdentity =
                        LookupMachineIdentityApi(imported.dll, imported.name)
                            .has_value();
                    if (!exactNetwork && !exactState &&
                        !exactValidationProducer && !exactVerifier &&
                        !exactMachineIdentity)
                        continue;
                    if (!xrefIdx) continue;
                    const auto references = xrefIdx->toTarget.find(imported.iatVA);
                    if (references == xrefIdx->toTarget.end()) continue;
                    for (uint64_t source : references->second) {
                        uint64_t owner = 0;
                        std::string ignored;
                        if (!authorizationOwner(source, owner, ignored)) continue;
                        addCandidate(owner);
                        if (exactNetwork &&
                            std::find(exactNetworkOwners.begin(),
                                      exactNetworkOwners.end(), owner) ==
                                exactNetworkOwners.end()) {
                            if (exactNetworkOwners.size() <
                                kMaxNetworkCandidateStates)
                                exactNetworkOwners.push_back(owner);
                            else
                                networkCandidateNeighborhoodTruncated = true;
                        }
                    }
                }

                // The scalar pass can cross direct helper calls and helper
                // returns only when both endpoint functions have summaries.
                // Retain a deterministic, bounded four-hop neighborhood around
                // exact network owners before applying the global function cap:
                // reverse callers cover wrapper returns; forward callees cover
                // values passed into helpers.
                std::unordered_map<uint64_t, std::vector<uint64_t>>
                    networkForward, networkReverse;
                for (const CrackmeTriageCallEdgeInput& edge : triage.callEdges) {
                    uint64_t caller = 0, callee = 0;
                    std::string ignored;
                    if (!authorizationOwner(edge.caller, caller, ignored) ||
                        !authorizationOwner(edge.callee, callee, ignored) ||
                        caller == callee)
                        continue;
                    networkForward[caller].push_back(callee);
                    networkReverse[callee].push_back(caller);
                }
                auto normalizeNeighbors = [](auto& graph) {
                    for (auto& [_, neighbors] : graph) {
                        std::sort(neighbors.begin(), neighbors.end());
                        neighbors.erase(std::unique(neighbors.begin(),
                                                    neighbors.end()),
                                        neighbors.end());
                    }
                };
                normalizeNeighbors(networkForward);
                normalizeNeighbors(networkReverse);
                std::deque<std::pair<uint64_t, size_t>> networkQueue;
                std::unordered_set<uint64_t> networkSeen;
                for (uint64_t owner : exactNetworkOwners) {
                    networkQueue.emplace_back(owner, 0);
                    networkSeen.insert(owner);
                }
                size_t networkStates = 0;
                while (!networkQueue.empty() &&
                       networkStates++ < kMaxNetworkCandidateStates) {
                    const auto [function, depth] = networkQueue.front();
                    networkQueue.pop_front();
                    if (depth >= kMaxNetworkCandidateDepth) continue;
                    auto enqueue = [&](const auto& graph) {
                        const auto found = graph.find(function);
                        if (found == graph.end()) return;
                        for (uint64_t neighbor : found->second) {
                            if (networkSeen.find(neighbor) != networkSeen.end())
                                continue;
                            if (networkSeen.size() >=
                                kMaxNetworkCandidateStates) {
                                networkCandidateNeighborhoodTruncated = true;
                                continue;
                            }
                            networkSeen.insert(neighbor);
                            addCandidate(neighbor);
                            networkQueue.emplace_back(neighbor, depth + 1);
                        }
                    };
                    enqueue(networkReverse);
                    enqueue(networkForward);
                }
                if (!networkQueue.empty())
                    networkCandidateNeighborhoodTruncated = true;

                // Predicate discovery has to happen before the annotation cap:
                // tiny, high-fan-out callees are the characteristic shape of a
                // shared IsPro()/feature gate even when they are far away from
                // networking and persistence owners.  The call graph supplies
                // the complete ranking key; CFG annotation below decides whether
                // the return is actually a conservative boolean.
                struct FanoutCandidate {
                    uint64_t function = 0;
                    uint64_t size = 0;
                    std::vector<uint64_t> callers;
                };
                std::unordered_map<uint64_t, std::unordered_set<uint64_t>>
                    fanoutCallers;
                for (const CrackmeTriageCallEdgeInput& edge : triage.callEdges) {
                    uint64_t caller = 0, callee = 0;
                    std::string ignored;
                    if (!authorizationOwner(edge.caller, caller, ignored) ||
                        !authorizationOwner(edge.callee, callee, ignored) ||
                        caller == callee)
                        continue;
                    fanoutCallers[callee].insert(caller);
                }
                std::vector<FanoutCandidate> fanoutCandidates;
                fanoutCandidates.reserve(fanoutCallers.size());
                for (const FuncResult& function : funcs) {
                    const auto incoming = fanoutCallers.find(function.address);
                    if (incoming == fanoutCallers.end() ||
                        incoming->second.size() < 2 || !function.size ||
                        function.size > 384)
                        continue;
                    FanoutCandidate candidate;
                    candidate.function = function.address;
                    candidate.size = function.size;
                    candidate.callers.assign(incoming->second.begin(),
                                             incoming->second.end());
                    std::sort(candidate.callers.begin(), candidate.callers.end());
                    fanoutCandidates.push_back(std::move(candidate));
                }
                std::sort(fanoutCandidates.begin(), fanoutCandidates.end(),
                    [](const FanoutCandidate& left, const FanoutCandidate& right) {
                        if (left.callers.size() != right.callers.size())
                            return left.callers.size() > right.callers.size();
                        if (left.size != right.size) return left.size < right.size;
                        return left.function < right.function;
                    });
                constexpr size_t kMaxFanoutPredicateCandidates = 64;
                if (fanoutCandidates.size() > kMaxFanoutPredicateCandidates) {
                    fanoutCandidates.resize(kMaxFanoutPredicateCandidates);
                    predicateCandidateDiscoveryTruncated = true;
                }
                for (const FanoutCandidate& candidate : fanoutCandidates) {
                    addCandidate(candidate.function);
                    for (uint64_t caller : candidate.callers) addCandidate(caller);
                }
                for (uint64_t candidate : selection.functionAddresses)
                    addCandidate(candidate);

                std::unordered_map<uint64_t, std::vector<uint64_t>> startupCalls;
                for (const CrackmeTriageCallEdgeInput& edge : triage.callEdges)
                    startupCalls[edge.caller].push_back(edge.callee);
                std::deque<std::pair<uint64_t, size_t>> startupQueue;
                std::unordered_set<uint64_t> startupSeen;
                bool startupCandidateTraversalTruncated = false;
                auto enqueueStartupCandidate = [&](uint64_t owner,
                                                   size_t depth) {
                    if (startupSeen.find(owner) != startupSeen.end())
                        return true;
                    if (startupSeen.size() >=
                        authorization.limits.maxFunctions) {
                        startupCandidateTraversalTruncated = true;
                        return false;
                    }
                    startupSeen.insert(owner);
                    addCandidate(owner);
                    startupQueue.emplace_back(owner, depth);
                    return true;
                };
                for (const AuthorizationLocation& root : authorization.startupRoots) {
                    const uint64_t owner = root.functionAddressValid
                        ? root.functionAddress : root.address;
                    if (root.functionAddressValid || root.addressValid)
                        enqueueStartupCandidate(owner, 0);
                }
                while (!startupQueue.empty()) {
                    const auto [caller, depth] = startupQueue.front();
                    startupQueue.pop_front();
                    if (depth >= authorization.limits.maxStartupDepth) continue;
                    const auto outgoing = startupCalls.find(caller);
                    if (outgoing == startupCalls.end()) continue;
                    for (uint64_t callee : outgoing->second) {
                        uint64_t owner = 0;
                        std::string ignored;
                        if (!authorizationOwner(callee, owner, ignored)) continue;
                        enqueueStartupCandidate(owner, depth + 1);
                    }
                }

                candidateFunctionsAvailable = (std::max)(
                    selection.availableFunctions, desiredCandidates.size());
                candidateFunctionsTruncated = selection.truncated ||
                    candidatePriority.size() > triage.limits.maxFunctions ||
                    networkCandidateNeighborhoodTruncated ||
                    startupCandidateTraversalTruncated ||
                    predicateCandidateDiscoveryTruncated;
                std::unordered_set<uint64_t> candidateAddresses;
                candidateAddresses.reserve((std::min)(candidatePriority.size(),
                                                       triage.limits.maxFunctions));
                for (uint64_t candidate : candidatePriority) {
                    if (candidateAddresses.size() >= triage.limits.maxFunctions) break;
                    candidateAddresses.insert(candidate);
                }
                for (const FanoutCandidate& candidate : fanoutCandidates) {
                    if (!candidateAddresses.count(candidate.function)) {
                        predicateCandidateDiscoveryTruncated = true;
                        continue;
                    }
                    for (uint64_t caller : candidate.callers)
                        if (!candidateAddresses.count(caller)) {
                            predicateCandidateDiscoveryTruncated = true;
                            break;
                        }
                }
                candidateFunctionsTruncated |=
                    predicateCandidateDiscoveryTruncated;
                authorization.functions.clear();
                authorization.functionsComplete = triage.functionOwnershipComplete &&
                    !candidateFunctionsTruncated;
                for (const FuncResult& function : funcs) {
                    if (!candidateAddresses.count(function.address)) continue;
                    authorization.functions.push_back(
                        {function.address, true, function.name});
                }

                std::unordered_map<uint64_t, std::string> namesByVA;
                namesByVA.reserve(funcs.size() + job.bin->imports().size());
                for (const FuncResult& function : funcs)
                    namesByVA[function.address] = function.name;
                for (const auto& imported : job.bin->imports()) {
                    if (!imported.addressKnown) continue;
                    namesByVA[imported.iatVA] = imported.dll.empty()
                        ? imported.name : imported.dll + "!" + imported.name;
                }
                std::unordered_map<uint64_t, std::string> stringsByVA;
                std::unordered_map<uint64_t, CrackmeLiteralEncoding> stringEncodingByVA;
                std::unordered_map<uint64_t, bool> stringTruncatedByVA;
                stringsByVA.reserve(strings.size());
                stringEncodingByVA.reserve(strings.size());
                stringTruncatedByVA.reserve(strings.size());
                for (const StrResult& text : strings) {
                    stringsByVA[text.address] = text.text;
                    stringEncodingByVA[text.address] = text.wide
                        ? CrackmeLiteralEncoding::Utf16Le
                        : CrackmeLiteralEncoding::Ascii;
                    stringTruncatedByVA[text.address] = text.textTruncated;
                }

                std::unordered_set<uint64_t> internalFunctionEntries;
                internalFunctionEntries.reserve(funcs.size());
                for (const FuncResult& function : funcs)
                    internalFunctionEntries.insert(function.address);

                AnnotateOptions options;
                options.x64 = job.decoder.arch == Arch::X64;
                options.nameFor = [&namesByVA](uint64_t va) {
                    const auto found = namesByVA.find(va);
                    return found == namesByVA.end() ? std::string() : found->second;
                };
                options.stringFor = [&stringsByVA](uint64_t va) {
                    const auto found = stringsByVA.find(va);
                    return found == stringsByVA.end() ? std::string() : found->second;
                };
                options.looksLikeVtable = [](uint64_t) { return false; };
                options.isInternalFunction = [&internalFunctionEntries](uint64_t va) {
                    return internalFunctionEntries.count(va) != 0;
                };
                options.internalFunctionMembershipComplete =
                    triage.functionOwnershipComplete;
                const JumpTableResolver jumpTables =
                    [binary = job.bin, decoder = job.decoder, decoderInstance = dis.get()](
                        const Instruction& instruction) {
                        JumpTableResolution table = ResolveJumpTable(
                            *binary, *decoderInstance, decoder.arch, decoder.byteOrder,
                            instruction);
                        ResolvedJumpTable resolved;
                        if (table.valid) resolved.targets = std::move(table.targets);
                        resolved.truncated = table.truncated;
                        resolved.evidence = std::move(table.evidence);
                        return resolved;
                    };
                const NoreturnCallResolver noreturnCalls =
                    noreturnResolver(job.bin, job.analysisOverrides,
                                     job.noreturnTargets, &funcs);

                struct AuthorizationReplyDecisionKey {
                    size_t decisionIndex = 0;
                    uint64_t callsite = 0;
                    uint64_t comparison = 0;
                    uint64_t decision = 0;
                    uint64_t function = 0;
                };
                std::vector<AuthorizationReplyDecisionKey> authorizationReplyKeys;

                struct AuthorizationFunctionSummary {
                    uint64_t address = 0;
                    std::string name;
                    ControlFlowGraph graph;
                    FuncAnnotations annotations;
                };
                std::vector<AuthorizationFunctionSummary> authorizationSummaries;
                authorizationSummaries.reserve(candidateAddresses.size());

                for (const FuncResult& function : funcs) {
                    if (superseded()) break;
                    if (!candidateAddresses.count(function.address)) continue;
                    std::vector<FunctionChunk> owned = function.chunks;
                    if (owned.empty() && function.size)
                        owned.push_back({ function.address, function.size });
                    std::vector<CFGCodeChunk> chunks;
                    chunks.reserve(owned.size());
                    for (const FunctionChunk& chunk : owned) {
                        size_t available = 0;
                        const uint8_t* data = job.bin->ptrFromVA(chunk.address, available);
                        if (data && chunk.size)
                            chunks.push_back({ data, (std::min<size_t>)(available, chunk.size),
                                               chunk.address });
                    }
                    if (chunks.empty()) continue;
                    options.chunks = function.chunks;
                    options.ownershipTruncated = function.ownershipTruncated;
                    options.seedKind = function.seedKind;
                    options.boundaryConfidence = function.boundaryConfidence;
                    ControlFlowGraph graph = BuildCFG(
                        chunks, *dis, 2000, jumpTables, noreturnCalls,
                        [binary = job.bin](const Instruction& instruction, uint64_t& target) {
                            return binary->resolveInstructionTarget(instruction, target);
                        });
                    FuncAnnotations annotations = AnnotateFunction(graph, options);
                    if (!annotations.complete)
                        authorization.decisionsComplete = false;
                    const bool functionStateComplete = annotations.complete &&
                        !annotations.ownershipTruncated;
                    if (!functionStateComplete)
                        authorization.stateOperationsComplete = false;
                    std::vector<const ApiCallObservation*> orderedApiCalls;
                    orderedApiCalls.reserve(annotations.apiCalls.size());
                    for (const ApiCallObservation& observation : annotations.apiCalls)
                        orderedApiCalls.push_back(&observation);
                    std::sort(orderedApiCalls.begin(), orderedApiCalls.end(),
                        [](const ApiCallObservation* left,
                           const ApiCallObservation* right) {
                            if (left->callVAValid != right->callVAValid)
                                return left->callVAValid > right->callVAValid;
                            return left->callVA < right->callVA;
                        });
                    std::unordered_map<std::string, PersistentStateIdentity>
                        registryHandleLineage;
                    std::unordered_map<std::string, PersistentStateIdentity>
                        fileHandleLineage;
                    std::unordered_map<uint64_t, size_t> stateOperationByCallsite;
                    std::unordered_set<uint64_t> stateWriteCallsites;
                    struct StateBufferRecord {
                        size_t operationIndex = 0;
                        uint64_t callsite = 0;
                        PersistentStateAccess access = PersistentStateAccess::Unknown;
                        PersistentStateKind kind = PersistentStateKind::Unknown;
                        std::string inputExpression;
                        std::string outputExpression;
                    };
                    std::vector<StateBufferRecord> stateBufferRecords;
                    for (const ApiCallObservation* observationPointer : orderedApiCalls) {
                        const ApiCallObservation& observation = *observationPointer;
                        CrackmeTriageApiCallInput typed;
                        typed.name = observation.resolvedName;
                        typed.callsite = observation.callVA;
                        typed.callsiteValid = observation.callVAValid;
                        typed.functionAddress = function.address;
                        typed.functionAddressValid = true;
                        typed.functionName = function.name;
                        if (observation.callVAValid) {
                            for (const BasicBlock& callBlock : graph.blocks) {
                                const auto callInstruction = std::find_if(
                                    callBlock.insns.begin(), callBlock.insns.end(),
                                    [&](const Instruction& instruction) {
                                        return instruction.address ==
                                            observation.callVA;
                                    });
                                if (callInstruction == callBlock.insns.end() ||
                                    !callInstruction->length ||
                                    callInstruction->address > UINT64_MAX -
                                        callInstruction->length)
                                    continue;
                                typed.continuationAddress =
                                    callInstruction->address +
                                    callInstruction->length;
                                typed.continuationAddressValid = true;
                                typed.continuationSignature =
                                    codeSignatures.capture(
                                        *dis, typed.continuationAddress);
                                typed.continuationFileOffsetValid =
                                    job.bin->vaToOffset(
                                        typed.continuationAddress,
                                        typed.continuationFileOffset);
                                break;
                            }
                        }
                        typed.returnValueUsed = observation.returnValueUsed;
                        typed.returnValueUseKnown = observation.returnValueUseKnown;
                        switch (observation.returnUseKind) {
                        case ApiReturnUseKind::Ignored:    typed.returnUseKind = NetworkReturnUseKind::Ignored; break;
                        case ApiReturnUseKind::Compared:   typed.returnUseKind = NetworkReturnUseKind::Compared; break;
                        case ApiReturnUseKind::Branched:   typed.returnUseKind = NetworkReturnUseKind::Branched; break;
                        case ApiReturnUseKind::Stored:     typed.returnUseKind = NetworkReturnUseKind::Stored; break;
                        case ApiReturnUseKind::Propagated: typed.returnUseKind = NetworkReturnUseKind::Propagated; break;
                        case ApiReturnUseKind::Consumed:   typed.returnUseKind = NetworkReturnUseKind::Consumed; break;
                        case ApiReturnUseKind::Returned:   typed.returnUseKind = NetworkReturnUseKind::Returned; break;
                        case ApiReturnUseKind::Unknown:    typed.returnUseKind = NetworkReturnUseKind::Unknown; break;
                        }
                        typed.returnUseAddress = observation.returnUseVA;
                        typed.returnUseAddressValid = observation.returnUseVAValid;
                        typed.returnUseInstruction = observation.returnUseInstruction;
                        typed.returnUseSummary = observation.returnUseSummary;
                        typed.resultInfluencesDecision = observation.resultInfluencesDecision;
                        typed.decisionAddress = observation.decisionVA;
                        typed.decisionAddressValid = observation.decisionVAValid;
                        typed.decisionTarget = observation.decisionTarget;
                        typed.decisionTargetValid = observation.decisionTargetValid;
                        typed.decisionInstruction = observation.decisionInstruction;
                        typed.returnUseEvidence = observation.returnUseEvidence;
                        typed.returnUseConfidence = observation.returnUseConfidence;
                        typed.replyDecisionAnalysisAttempted =
                            observation.replyDecisionAnalysisAttempted;
                        typed.replyDecisionsComplete = observation.replyDecisionsComplete;
                        typed.replyDecisionIncompleteReason =
                            observation.replyDecisionIncompleteReason;
                        typed.replyDecisions.reserve(observation.replyDecisions.size());
                        for (const ApiReplyDecisionObservation& reply :
                             observation.replyDecisions) {
                            if (reply.kind == ApiReplyDecisionKind::ComparisonCall) {
                                const auto comparator = std::find_if(
                                    annotations.apiCalls.begin(),
                                    annotations.apiCalls.end(),
                                    [&](const ApiCallObservation& candidate) {
                                        return reply.comparisonVAValid &&
                                            candidate.callVAValid &&
                                            candidate.callVA == reply.comparisonVA;
                                    });
                                if (comparator == annotations.apiCalls.end() ||
                                    !authorizationEqualityHelper(
                                        *job.bin, *comparator))
                                    continue;
                            }
                            CrackmeTriageReplyDecisionInput converted;
                            converted.kind = reply.kind == ApiReplyDecisionKind::ComparisonCall
                                ? NetworkReplyDecisionKind::ComparisonCall
                                : NetworkReplyDecisionKind::DirectComparison;
                            converted.outputArgumentIndex = reply.outputArgumentIndex;
                            converted.outputRole = reply.outputRole;
                            converted.outputExpression = reply.outputExpression;
                            converted.comparisonAddress = reply.comparisonVA;
                            converted.comparisonAddressValid = reply.comparisonVAValid;
                            converted.comparisonInstruction = reply.comparisonInstruction;
                            if (reply.comparisonVAValid)
                                converted.comparisonSignature =
                                    codeSignatures.capture(*dis, reply.comparisonVA);
                            converted.comparisonSummary = reply.comparisonSummary;
                            converted.expectedValue = reply.expectedValue;
                            converted.decisionAddress = reply.decisionVA;
                            converted.decisionAddressValid = reply.decisionVAValid;
                            converted.decisionTarget = reply.decisionTarget;
                            converted.decisionTargetValid = reply.decisionTargetValid;
                            converted.fallthroughAddress = reply.fallthroughVA;
                            converted.fallthroughAddressValid = reply.fallthroughVAValid;
                            converted.decisionInstruction = reply.decisionInstruction;
                            if (reply.decisionVAValid)
                                converted.decisionSignature =
                                    codeSignatures.capture(*dis, reply.decisionVA);
                            converted.takenPathSummary = reply.takenPathSummary;
                            converted.fallthroughPathSummary = reply.fallthroughPathSummary;
                            converted.matchAddress = reply.matchVA;
                            converted.matchAddressValid = reply.matchVAValid;
                            converted.mismatchAddress = reply.mismatchVA;
                            converted.mismatchAddressValid = reply.mismatchVAValid;
                            converted.evidence = reply.evidence;
                            converted.confidence = reply.confidence;
                            typed.replyDecisions.push_back(std::move(converted));
                        }

                        if (observation.targetVAValid) {
                            for (const auto& imported : job.bin->imports()) {
                                if (imported.addressKnown && imported.iatVA == observation.targetVA) {
                                    typed.dll = imported.dll;
                                    typed.name = imported.name;
                                    break;
                                }
                            }
                        }
                        if (typed.dll.empty()) {
                            const size_t bang = typed.name.find('!');
                            if (bang != std::string::npos) {
                                typed.dll = typed.name.substr(0, bang);
                                typed.name.erase(0, bang + 1);
                            }
                        }
                        for (const ApiArgumentObservation& argument : observation.arguments) {
                            CrackmeTriageApiArgumentInput converted;
                            converted.ordinal = argument.index;
                            converted.name = argument.parameter;
                            converted.literal = argument.stringLiteral;
                            converted.address = argument.referencedAddress;
                            converted.addressValid = argument.referencedAddressValid;
                            converted.immediate = argument.immediate;
                            converted.immediateValid = argument.immediateValid;
                            if (converted.addressValid) {
                                converted.fileOffsetValid = job.bin->vaToOffset(
                                    converted.address, converted.fileOffset);
                                const auto encoding = stringEncodingByVA.find(
                                    converted.address);
                                if (encoding != stringEncodingByVA.end()) {
                                    converted.encoding = encoding->second;
                                    converted.encodingValid = true;
                                }
                            }
                            if (!converted.literal.empty() || converted.immediateValid)
                                typed.arguments.push_back(std::move(converted));
                        }
                        const auto stateApi =
                            LookupPersistentStateApi(typed.dll, typed.name);
                        if (stateApi) {
                            auto argumentAt = [&](size_t index)
                                -> const ApiArgumentObservation* {
                                for (const ApiArgumentObservation& argument : observation.arguments)
                                    if (argument.index == index) return &argument;
                                return nullptr;
                            };
                            auto roleArgument = [&](PersistentStateArgumentRole role)
                                -> const ApiArgumentObservation* {
                                for (const PersistentStateApiArgument& argument : stateApi->arguments)
                                    if (argument.role == role)
                                        return argumentAt(argument.argumentIndex);
                                return nullptr;
                            };
                            auto literal = [](const ApiArgumentObservation* argument) {
                                return argument ? argument->stringLiteral : std::string();
                            };
                            auto expression = [](const ApiArgumentObservation* argument) {
                                if (!argument) return std::string();
                                if (!argument->sourceExpression.empty())
                                    return authorizationExpressionKey(argument->sourceExpression);
                                return authorizationExpressionKey(argument->renderedValue);
                            };
                            struct IdentityTextValue {
                                std::string text;
                                bool present = false;
                                bool exact = false;
                                bool explicitNull = false;
                                bool sourceTruncated = false;
                            };
                            auto catalogHasRole = [&](PersistentStateArgumentRole role) {
                                return std::any_of(stateApi->arguments.begin(),
                                    stateApi->arguments.end(),
                                    [&](const PersistentStateApiArgument& argument) {
                                        return argument.role == role;
                                    });
                            };
                            auto nullMeansEmptyIdentity = [&](PersistentStateArgumentRole role) {
                                const std::string& api = stateApi->normalizedName;
                                if (role == PersistentStateArgumentRole::Subkey)
                                    return api == "regopenkeyex" ||
                                           api == "reggetvalue" ||
                                           api == "regsetkeyvalue";
                                if (role == PersistentStateArgumentRole::ValueName)
                                    return api == "regqueryvalueex" ||
                                           api == "reggetvalue" ||
                                           api == "regsetvalueex" ||
                                           api == "regsetkeyvalue";
                                return false;
                            };
                            auto identityText = [&](PersistentStateArgumentRole role) {
                                IdentityTextValue value;
                                const ApiArgumentObservation* argument = roleArgument(role);
                                if (!argument) return value;
                                if (argument->immediateValid && argument->immediate == 0) {
                                    value.present = true;
                                    value.explicitNull = true;
                                    value.exact = nullMeansEmptyIdentity(role);
                                    return value;
                                }
                                if (argument->referencedAddressValid) {
                                    const auto full = stringsByVA.find(
                                        argument->referencedAddress);
                                    if (full != stringsByVA.end()) {
                                        value.text = full->second;
                                        value.present = true;
                                        const auto truncated = stringTruncatedByVA.find(
                                            argument->referencedAddress);
                                        value.sourceTruncated =
                                            truncated != stringTruncatedByVA.end() &&
                                            truncated->second;
                                        value.exact = !value.sourceTruncated;
                                        return value;
                                    }
                                }
                                if (!argument->stringLiteral.empty()) {
                                    value.text = argument->stringLiteral;
                                    value.present = true;
                                    value.sourceTruncated =
                                        argument->stringLiteralTruncated;
                                    value.exact = !value.sourceTruncated;
                                }
                                return value;
                            };
                            auto hive = [](const ApiArgumentObservation* argument) {
                                if (!argument || !argument->immediateValid) return std::string();
                                switch (static_cast<uint32_t>(argument->immediate)) {
                                case 0x80000000u: return std::string("HKEY_CLASSES_ROOT");
                                case 0x80000001u: return std::string("HKEY_CURRENT_USER");
                                case 0x80000002u: return std::string("HKEY_LOCAL_MACHINE");
                                case 0x80000003u: return std::string("HKEY_USERS");
                                case 0x80000005u: return std::string("HKEY_CURRENT_CONFIG");
                                default: return std::string();
                                }
                            };
                            PersistentStateOperationInput operation;
                            operation.access = stateApi->access;
                            operation.apiDll = typed.dll;
                            operation.apiName = stateApi->canonicalName;
                            operation.location = authorizationLocation(
                                *job.bin, observation.callVA, observation.callVAValid,
                                function.address, true, function.name);
                            operation.operationComplete = functionStateComplete;
                            bool identitySourceTruncated = false;
                            std::string identityLimitation;
                            auto addIdentityLimitation = [&](std::string text) {
                                if (text.empty()) return;
                                if (!identityLimitation.empty())
                                    identityLimitation += "; ";
                                identityLimitation += std::move(text);
                            };
                            if (!functionStateComplete) {
                                identityLimitation = annotations.incompleteReason.empty()
                                    ? "function CFG or ownership was incomplete"
                                    : annotations.incompleteReason;
                            }
                            const std::string dataBufferExpression = expression(
                                roleArgument(PersistentStateArgumentRole::DataBuffer));
                            const ApiArgumentObservation* outputBufferArgument =
                                roleArgument(PersistentStateArgumentRole::OutputBuffer);
                            const std::string outputBufferExpression =
                                authorizationOutputStorageExpression(
                                    outputBufferArgument);
                            if (!outputBufferExpression.empty()) {
                                operation.outputExpression = outputBufferExpression;
                                for (const PersistentStateApiArgument& argument :
                                     stateApi->arguments) {
                                    if (argument.role !=
                                        PersistentStateArgumentRole::OutputBuffer)
                                        continue;
                                    operation.outputArgumentIndex =
                                        argument.argumentIndex;
                                    operation.outputArgumentIndexValid = true;
                                    break;
                                }
                            }

                            if (stateApi->kind == PersistentStateKind::Registry) {
                                const ApiArgumentObservation* root =
                                    roleArgument(PersistentStateArgumentRole::RootHandle);
                                const ApiArgumentObservation* handle =
                                    roleArgument(PersistentStateArgumentRole::ResourceHandle);
                                const bool hasSubkey = catalogHasRole(
                                    PersistentStateArgumentRole::Subkey);
                                const bool hasValue = catalogHasRole(
                                    PersistentStateArgumentRole::ValueName);
                                const IdentityTextValue subkey = identityText(
                                    PersistentStateArgumentRole::Subkey);
                                const IdentityTextValue value = identityText(
                                    PersistentStateArgumentRole::ValueName);
                                identitySourceTruncated =
                                    subkey.sourceTruncated || value.sourceTruncated;

                                auto registryBase = [&](const ApiArgumentObservation* argument) {
                                    PersistentStateIdentity base;
                                    const std::string handleKey = expression(argument);
                                    if (!handleKey.empty()) {
                                        const auto found =
                                            registryHandleLineage.find(handleKey);
                                        if (found != registryHandleLineage.end())
                                            return found->second;
                                    }
                                    const std::string rootName = hive(argument);
                                    if (!rootName.empty())
                                        return CanonicalizeRegistryIdentity(
                                            rootName, std::string_view{},
                                            std::string_view{});
                                    return base;
                                };
                                PersistentStateIdentity base = registryBase(root);
                                if (!base.valid) base = registryBase(handle);
                                if (base.valid) {
                                    std::string combinedSubkey =
                                        base.canonicalKey;
                                    if (hasSubkey && !subkey.text.empty()) {
                                        if (!combinedSubkey.empty())
                                            combinedSubkey += "\\";
                                        combinedSubkey += subkey.text;
                                    }
                                    operation.identity = CanonicalizeRegistryIdentity(
                                        base.canonicalScope, combinedSubkey,
                                        hasValue ? value.text : std::string());
                                    const bool componentsExact =
                                        (!hasSubkey || (subkey.present && subkey.exact)) &&
                                        (!hasValue || (value.present && value.exact));
                                    operation.identity.exact =
                                        operation.identity.valid && base.exact &&
                                        componentsExact;
                                    if (hasSubkey &&
                                        !(subkey.present && subkey.exact))
                                        operation.identity.display +=
                                            " [subkey not exact]";
                                    if (hasValue &&
                                        !(value.present && value.exact))
                                        operation.identity.display +=
                                            " [value name not exact]";
                                }
                                if (!base.valid)
                                    addIdentityLimitation(
                                        "registry base handle/hive was not recovered");
                                if (hasSubkey && !subkey.present)
                                    addIdentityLimitation(
                                        "registry subkey argument was not recovered");
                                else if (hasSubkey && subkey.explicitNull &&
                                         !subkey.exact)
                                    addIdentityLimitation(
                                        "NULL is not an exact subkey for this API");
                                if (hasValue && !value.present)
                                    addIdentityLimitation(
                                        "registry value-name argument was not recovered");
                                else if (hasValue && value.explicitNull &&
                                         !value.exact)
                                    addIdentityLimitation(
                                        "NULL is not an exact value name for this API");
                                if (identitySourceTruncated)
                                    addIdentityLimitation(
                                        "registry identity source exceeded the bounded full-string cap");
                                if (stateApi->establishesHandleLineage) {
                                    const std::string outputKey = expression(
                                        roleArgument(PersistentStateArgumentRole::OutputHandle));
                                    if (!outputKey.empty() && operation.identity.valid)
                                        registryHandleLineage[outputKey] = operation.identity;
                                }
                            } else if (stateApi->kind == PersistentStateKind::File) {
                                const IdentityTextValue path = identityText(
                                    PersistentStateArgumentRole::ResourcePath);
                                identitySourceTruncated = path.sourceTruncated;
                                const std::string handleKey = expression(
                                    roleArgument(PersistentStateArgumentRole::ResourceHandle));
                                if (!path.text.empty()) {
                                    operation.identity =
                                        CanonicalizeFileIdentity(path.text);
                                    operation.identity.exact =
                                        operation.identity.exact && path.exact;
                                }
                                else if (!handleKey.empty()) {
                                    const auto base = fileHandleLineage.find(handleKey);
                                    if (base != fileHandleLineage.end())
                                        operation.identity = base->second;
                                }
                                if (catalogHasRole(
                                        PersistentStateArgumentRole::ResourcePath) &&
                                    !path.present)
                                    addIdentityLimitation(
                                        "file path argument was not recovered");
                                if (path.explicitNull)
                                    addIdentityLimitation(
                                        "NULL is not an exact file path");
                                if (identitySourceTruncated)
                                    addIdentityLimitation(
                                        "file path exceeded the bounded full-string cap");
                                const std::string normalized = stateApi->normalizedName;
                                if (stateApi->access == PersistentStateAccess::Open) {
                                    const std::string mode = authorizationLower(literal(
                                        roleArgument(PersistentStateArgumentRole::Mode)));
                                    if (!mode.empty()) {
                                        if (mode.find('w') != std::string::npos ||
                                            mode.find('a') != std::string::npos ||
                                            mode.find('+') != std::string::npos)
                                            operation.access = PersistentStateAccess::Write;
                                        else if (mode.find('r') != std::string::npos)
                                            operation.access = PersistentStateAccess::Read;
                                    } else if (normalized == "createfile") {
                                        const ApiArgumentObservation* desired = argumentAt(1);
                                        const ApiArgumentObservation* disposition = argumentAt(4);
                                        if (desired && desired->immediateValid &&
                                            (desired->immediate & 0x40000000ull))
                                            operation.access = PersistentStateAccess::Write;
                                        else if (disposition && disposition->immediateValid &&
                                                 disposition->immediate != 3)
                                            operation.access = PersistentStateAccess::Write;
                                        else if (desired && desired->immediateValid &&
                                                 (desired->immediate & 0x80000000ull))
                                            operation.access = PersistentStateAccess::Read;
                                    }
                                    // Secure CRT open functions return errno_t
                                    // and write FILE* through argument one. Other
                                    // open APIs return the handle directly; both
                                    // Stored and Propagated first uses retain a
                                    // simple destination expression.
                                    const std::string outputHandle = expression(
                                        roleArgument(PersistentStateArgumentRole::OutputHandle));
                                    if (!outputHandle.empty() && operation.identity.valid)
                                        fileHandleLineage[outputHandle] = operation.identity;
                                    if (outputHandle.empty() && operation.identity.valid) {
                                        for (const std::string& destination :
                                             authorizationReturnDestinations(observation))
                                            fileHandleLineage[destination] = operation.identity;
                                    }
                                }
                            } else if (stateApi->kind == PersistentStateKind::Ini) {
                                const IdentityTextValue path = identityText(
                                    PersistentStateArgumentRole::ResourcePath);
                                const IdentityTextValue section = identityText(
                                    PersistentStateArgumentRole::IniSection);
                                const IdentityTextValue key = identityText(
                                    PersistentStateArgumentRole::IniKey);
                                identitySourceTruncated = path.sourceTruncated ||
                                    section.sourceTruncated || key.sourceTruncated;
                                operation.identity = CanonicalizeIniIdentity(
                                    path.text, section.text, key.text);
                                operation.identity.exact = operation.identity.exact &&
                                    path.present && path.exact &&
                                    section.present && section.exact &&
                                    key.present && key.exact;
                                if (!path.present || !section.present || !key.present)
                                    addIdentityLimitation(
                                        "INI path, section, or key argument was not recovered");
                                if (path.explicitNull || section.explicitNull ||
                                    key.explicitNull)
                                    addIdentityLimitation(
                                        "NULL INI arguments are enumeration/deletion semantics, not an exact field identity");
                                if (identitySourceTruncated)
                                    addIdentityLimitation(
                                        "INI identity source exceeded the bounded full-string cap");
                            } else if (stateApi->kind == PersistentStateKind::Credential) {
                                const ApiArgumentObservation* type =
                                    roleArgument(PersistentStateArgumentRole::CredentialType);
                                std::string typeText;
                                if (type && type->immediateValid)
                                    typeText = std::to_string(type->immediate);
                                const IdentityTextValue target = identityText(
                                    PersistentStateArgumentRole::CredentialTarget);
                                identitySourceTruncated = target.sourceTruncated;
                                operation.identity = CanonicalizeCredentialIdentity(
                                    target.text, typeText);
                                operation.identity.exact = operation.identity.exact &&
                                    target.present && target.exact;
                                if (catalogHasRole(
                                        PersistentStateArgumentRole::CredentialTarget) &&
                                    !target.present)
                                    addIdentityLimitation(
                                        "credential target argument was not recovered");
                                if (target.explicitNull)
                                    addIdentityLimitation(
                                        "NULL is not an exact credential target");
                                if (identitySourceTruncated)
                                    addIdentityLimitation(
                                        "credential target exceeded the bounded full-string cap");
                                // CredWrite receives one CREDENTIALA/W pointer.
                                // Recover only the fixed Type and TargetName
                                // fields from a statically addressable mapped
                                // structure; all other layouts remain unlinked.
                                const ApiArgumentObservation* record =
                                    roleArgument(
                                        PersistentStateArgumentRole::CredentialRecord);
                                if (!operation.identity.valid && record &&
                                    record->referencedAddressValid) {
                                    size_t available = 0;
                                    const uint8_t* bytes = job.bin->ptrFromVA(
                                        record->referencedAddress, available);
                                    const size_t pointerBytes =
                                        job.decoder.arch == Arch::X64 ? 8u : 4u;
                                    if (bytes && available >= 8 + pointerBytes) {
                                        uint32_t credentialType = 0;
                                        uint64_t targetAddress = 0;
                                        std::memcpy(&credentialType, bytes + 4,
                                                    sizeof(credentialType));
                                        std::memcpy(&targetAddress, bytes + 8,
                                                    pointerBytes);
                                        const auto target =
                                            stringsByVA.find(targetAddress);
                                        if (credentialType != 0 &&
                                            target != stringsByVA.end() &&
                                            !target->second.empty()) {
                                            operation.identity =
                                                CanonicalizeCredentialIdentity(
                                                    target->second,
                                                    std::to_string(credentialType));
                                            const auto truncated =
                                                stringTruncatedByVA.find(targetAddress);
                                            if (truncated !=
                                                    stringTruncatedByVA.end() &&
                                                truncated->second) {
                                                operation.identity.exact = false;
                                                identitySourceTruncated = true;
                                                addIdentityLimitation(
                                                    "embedded credential target exceeded the bounded full-string cap");
                                                operation.evidence =
                                                    "bounded mapped CREDENTIAL structure exposes Type and a truncated TargetName prefix";
                                            } else {
                                                operation.evidence =
                                                    "bounded mapped CREDENTIAL structure exposes exact Type and TargetName";
                                            }
                                        }
                                    }
                                }
                                if (!operation.identity.valid) {
                                    operation.identity.kind = PersistentStateKind::Credential;
                                    operation.identity.display =
                                        "Credential Manager record with unresolved embedded target";
                                }
                            } else if (stateApi->kind ==
                                       PersistentStateKind::DpapiTransform) {
                                operation.identity = MakeDpapiTransformIdentity(
                                    stateApi->canonicalName);
                            }
                            if (identitySourceTruncated) {
                                operation.operationComplete = false;
                                authorization.stateOperationsComplete = false;
                            }
                            if (!operation.identity.valid) {
                                operation.identity.kind = stateApi->kind;
                                if (operation.identity.display.empty())
                                    operation.identity.display =
                                        std::string(PersistentStateKindText(stateApi->kind)) +
                                        " operation with unresolved identity";
                            }
                            const std::string recoveredIdentityEvidence =
                                operation.evidence;
                            operation.evidence = stateApi->dll + "!" +
                                stateApi->canonicalName + " is an exact cataloged " +
                                PersistentStateAccessText(operation.access) + " operation";
                            if (operation.identity.valid) {
                                operation.evidence += " for " + operation.identity.display;
                                if (!operation.identity.exact)
                                    operation.evidence +=
                                        "; identity is non-exact and cannot form a remembered-access link";
                            } else {
                                operation.evidence +=
                                    "; resource identity could not be proven and remains unlinked";
                            }
                            if (!recoveredIdentityEvidence.empty())
                                operation.evidence += "; " + recoveredIdentityEvidence;
                            if (!identityLimitation.empty())
                                operation.evidence += "; " + identityLimitation;
                            if (authorization.stateOperations.size() <
                                authorization.limits.maxOperations) {
                                const size_t operationIndex =
                                    authorization.stateOperations.size();
                                authorization.stateOperations.push_back(std::move(operation));
                                if (observation.callVAValid)
                                    stateOperationByCallsite[observation.callVA] = operationIndex;
                                const PersistentStateOperationInput& retained =
                                    authorization.stateOperations.back();
                                if (retained.access == PersistentStateAccess::Write &&
                                    retained.location.addressValid)
                                    stateWriteCallsites.insert(retained.location.address);

                                // A DPAPI row is attached only when the exact
                                // recovered buffer expression reaches the
                                // surrounding store through simple bounded
                                // register/stack lineage. Merely appearing in
                                // the same function is insufficient.
                                if (observation.callVAValid) {
                                    if (retained.access == PersistentStateAccess::Write &&
                                        retained.identity.kind !=
                                            PersistentStateKind::DpapiTransform &&
                                        !dataBufferExpression.empty()) {
                                        for (auto it = stateBufferRecords.rbegin();
                                             it != stateBufferRecords.rend(); ++it) {
                                            if (it->kind != PersistentStateKind::DpapiTransform ||
                                                it->access != PersistentStateAccess::Protect ||
                                                it->outputExpression.empty()) continue;
                                            if (!authorizationExpressionsShareLineage(
                                                    graph, it->callsite,
                                                    it->outputExpression,
                                                    observation.callVA,
                                                    dataBufferExpression)) continue;
                                            authorization.stateOperations[operationIndex]
                                                .transformOperationIndex = it->operationIndex;
                                            authorization.stateOperations[operationIndex]
                                                .transformOperationIndexValid = true;
                                            break;
                                        }
                                    } else if (retained.identity.kind ==
                                                   PersistentStateKind::DpapiTransform &&
                                               retained.access ==
                                                   PersistentStateAccess::Unprotect &&
                                               !dataBufferExpression.empty()) {
                                        for (auto it = stateBufferRecords.rbegin();
                                             it != stateBufferRecords.rend(); ++it) {
                                            if ((it->access != PersistentStateAccess::Read &&
                                                 it->access != PersistentStateAccess::Open) ||
                                                it->kind ==
                                                    PersistentStateKind::DpapiTransform ||
                                                it->outputExpression.empty()) continue;
                                            if (!authorizationExpressionsShareLineage(
                                                    graph, it->callsite,
                                                    it->outputExpression,
                                                    observation.callVA,
                                                    dataBufferExpression)) continue;
                                            authorization.stateOperations[it->operationIndex]
                                                .transformOperationIndex = operationIndex;
                                            authorization.stateOperations[it->operationIndex]
                                                .transformOperationIndexValid = true;
                                            break;
                                        }
                                    }
                                    stateBufferRecords.push_back({
                                        operationIndex, observation.callVA,
                                        retained.access, retained.identity.kind,
                                        dataBufferExpression, outputBufferExpression});
                                }
                            } else {
                                authorization.stateOperationsComplete = false;
                            }
                        } else {
                            const PersistentStateAccess hint =
                                authorizationCustomPersistenceHint(typed.name);
                            if (hint != PersistentStateAccess::Unknown) {
                                if (authorization.stateOperations.size() >=
                                    authorization.limits.maxOperations) {
                                    authorization.stateOperationsComplete = false;
                                } else {
                                    PersistentStateOperationInput operation;
                                    // The name is only a candidate hint, so do
                                    // not promote it to a typed Read/Write that
                                    // could influence outcome or correlation.
                                    operation.access = PersistentStateAccess::Unknown;
                                    operation.identity.kind = PersistentStateKind::Unknown;
                                    operation.identity.display =
                                        "custom persistence candidate " + typed.name;
                                    operation.apiDll = typed.dll;
                                    operation.apiName = typed.name;
                                    operation.location = authorizationLocation(
                                        *job.bin, observation.callVA,
                                        observation.callVAValid, function.address,
                                        true, function.name);
                                    operation.evidence = "heuristic function name suggests " +
                                        std::string(PersistentStateAccessText(hint)) +
                                        " persistence; no exact API contract or resource identity was proven";
                                    authorization.stateOperations.push_back(
                                        std::move(operation));
                                }
                            }
                        }
                        if (LookupNetworkApi(typed.dll, typed.name)) {
                            if (triage.apiCalls.size() < triage.limits.maxTypedCalls)
                                triage.apiCalls.push_back(std::move(typed));
                            else
                                triage.apiCallsComplete = false;
                        }
                    }

                    // Build authorization decisions only after every state call
                    // in this function has been cataloged, so a durable write on
                    // either successor can participate in outcome scoring.
                    for (const ApiCallObservation* observationPointer : orderedApiCalls) {
                        const ApiCallObservation& observation = *observationPointer;
                        auto retainDecision = [&](AuthorizationDecisionInput decision,
                                                  bool networkDecision,
                                                  uint64_t networkCallsite,
                                                  uint64_t comparisonAddress) {
                            if (authorization.decisions.size() >=
                                authorization.limits.maxDecisions) {
                                authorization.decisionsComplete = false;
                                return static_cast<size_t>(-1);
                            }
                            const size_t decisionIndex = authorization.decisions.size();
                            authorization.decisions.push_back(std::move(decision));
                            if (networkDecision) authorizationReplyKeys.push_back({
                                decisionIndex, networkCallsite, comparisonAddress,
                                authorization.decisions.back().location.address,
                                function.address});
                            return decisionIndex;
                        };
                        auto pathsFor = [&](uint64_t decision,
                                            bool decisionValid,
                                            uint64_t taken,
                                            bool takenValid,
                                            uint64_t fallthrough,
                                            bool fallthroughValid) {
                            return scanAuthorizationPathPair(
                                *job.bin, graph, decision, decisionValid,
                                taken, takenValid, fallthrough,
                                fallthroughValid, function.address,
                                function.name, namesByVA, stringsByVA,
                                stateWriteCallsites);
                        };
                        auto assignControlledWrites = [&](
                            size_t decisionIndex,
                            const AuthorizationPathScan& taken,
                            const AuthorizationPathScan& fallthrough) {
                            if (decisionIndex == static_cast<size_t>(-1) ||
                                !taken.path.complete ||
                                !fallthrough.path.complete) return;
                            for (PersistentStateOperationInput& operation :
                                 authorization.stateOperations) {
                                if (operation.access != PersistentStateAccess::Write ||
                                    !operation.location.addressValid ||
                                    !operation.location.functionAddressValid ||
                                    operation.location.functionAddress != function.address)
                                    continue;
                                const BasicBlock* owner = authorizationBlockForAddress(
                                    graph, operation.location.address);
                                if (!owner) continue;
                                const bool inTaken = taken.blockStarts.count(owner->start) != 0;
                                const bool inFallthrough =
                                    fallthrough.blockStarts.count(owner->start) != 0;
                                if (inTaken == inFallthrough) continue;
                                operation.controllingDecisionIndex = decisionIndex;
                                operation.controllingDecisionIndexValid = true;
                                operation.controllingBranch = inTaken
                                    ? AuthorizationBranch::Taken
                                    : AuthorizationBranch::Fallthrough;
                            }
                        };

                        for (const ApiReplyDecisionObservation& reply :
                             observation.replyDecisions) {
                            if (!reply.decisionVAValid) continue;
                            AuthorizationPathPairScan paths = pathsFor(
                                reply.decisionVA, true,
                                reply.decisionTarget, reply.decisionTargetValid,
                                reply.fallthroughVA, reply.fallthroughVAValid);
                            AuthorizationDecisionInput decision;
                            decision.location = authorizationLocation(
                                *job.bin, reply.decisionVA, true,
                                function.address, true, function.name);
                            decision.comparison = reply.comparisonSummary.empty()
                                ? reply.comparisonInstruction : reply.comparisonSummary;
                            decision.takenPath = std::move(paths.taken.path);
                            decision.fallthroughPath =
                                std::move(paths.fallthrough.path);
                            decision.evidence = reply.evidence;
                            const size_t decisionIndex = retainDecision(
                                std::move(decision), true,
                                observation.callVAValid ? observation.callVA : 0,
                                reply.comparisonVAValid ? reply.comparisonVA : 0);
                            assignControlledWrites(decisionIndex, paths.taken,
                                                   paths.fallthrough);
                        }

                        if (observation.localInputDecisionAnalysisAttempted &&
                            !observation.localInputDecisionsComplete)
                            authorization.decisionsComplete = false;
                        for (const ApiLocalInputDecisionObservation& local :
                             observation.localInputDecisions) {
                            if (!local.decisionVAValid) continue;
                            AuthorizationPathPairScan paths = pathsFor(
                                local.decisionVA, true,
                                local.decisionTarget, local.decisionTargetValid,
                                local.fallthroughVA, local.fallthroughVAValid);
                            AuthorizationDecisionInput decision;
                            decision.localInputFlow = true;
                            decision.gateSource = AuthorizationGateSource::LocalInput;
                            const AuthorizationLocation inputCallLocation =
                                authorizationLocation(
                                *job.bin, observation.callVA,
                                observation.callVAValid, function.address,
                                true, function.name);
                            uint64_t inputReadyAddress = 0;
                            bool inputReadyAddressValid = false;
                            if (observation.callVAValid) {
                                for (const BasicBlock& block : graph.blocks) {
                                    const auto call = std::find_if(
                                        block.insns.begin(), block.insns.end(),
                                        [&](const Instruction& instruction) {
                                            return instruction.address ==
                                                   observation.callVA;
                                        });
                                    if (call == block.insns.end()) continue;
                                    inputReadyAddressValid = call->length != 0 &&
                                        call->address <= UINT64_MAX - call->length;
                                    if (inputReadyAddressValid)
                                        inputReadyAddress = call->address +
                                                            call->length;
                                    break;
                                }
                            }
                            // The guided watch stops after the producer returns,
                            // when its output buffer is ready to inspect. The
                            // exact producer call remains the Origin provenance
                            // hop below, so neither coordinate is lost.
                            decision.inputLocation = authorizationLocation(
                                *job.bin, inputReadyAddress,
                                inputReadyAddressValid, function.address,
                                true, function.name);
                            decision.comparisonLocation = authorizationLocation(
                                *job.bin, local.comparisonVA,
                                local.comparisonVAValid, function.address,
                                true, function.name);
                            decision.location = authorizationLocation(
                                *job.bin, local.decisionVA, true,
                                function.address, true, function.name);
                            decision.comparison = local.comparisonSummary.empty()
                                ? local.comparisonInstruction
                                : local.comparisonSummary;
                            decision.inputEvidence = observation.resolvedName +
                                " has returned; fixed output argument " +
                                std::to_string(local.outputArgumentIndex + 1) +
                                " is ready to inspect";
                            decision.evidence = local.evidence;
                            if (!local.takenPathSummary.empty() ||
                                !local.fallthroughPathSummary.empty()) {
                                decision.evidence += "; taken: " +
                                    (local.takenPathSummary.empty()
                                        ? std::string("unclassified")
                                        : local.takenPathSummary) +
                                    "; fallthrough: " +
                                    (local.fallthroughPathSummary.empty()
                                        ? std::string("unclassified")
                                        : local.fallthroughPathSummary);
                            }
                            decision.originExpression = local.outputExpression;
                            decision.expectedValue = local.expectedValue;
                            decision.takenPath = std::move(paths.taken.path);
                            decision.fallthroughPath =
                                std::move(paths.fallthrough.path);
                            decision.provenanceComplete =
                                observation.localInputDecisionsComplete;
                            decision.provenanceIncompleteReason =
                                observation.localInputDecisionIncompleteReason;

                            auto appendLocalHop = [&decision](
                                    ValueProvenanceHopKind kind,
                                    const AuthorizationLocation& location,
                                    std::string instruction,
                                    std::string from,
                                    std::string to,
                                    std::string evidence,
                                    float confidence) {
                                ValueProvenanceHop hop;
                                hop.kind = kind;
                                hop.address = location.address;
                                hop.addressValid = location.addressValid;
                                hop.functionAddress = location.functionAddress;
                                hop.functionAddressValid =
                                    location.functionAddressValid;
                                hop.functionName = location.functionName;
                                hop.instruction = std::move(instruction);
                                hop.fromExpression = std::move(from);
                                hop.toExpression = std::move(to);
                                hop.evidence = std::move(evidence);
                                hop.confidence = confidence;
                                decision.provenance.push_back(std::move(hop));
                            };
                            appendLocalHop(
                                ValueProvenanceHopKind::Origin,
                                inputCallLocation,
                                "call " + observation.resolvedName,
                                {}, local.outputExpression,
                                "exact cataloged input API writes this fixed output argument",
                                local.confidence);
                            appendLocalHop(
                                ValueProvenanceHopKind::Compare,
                                decision.comparisonLocation,
                                local.comparisonInstruction,
                                local.outputExpression, local.expectedValue,
                                local.comparisonSummary,
                                local.confidence);
                            appendLocalHop(
                                ValueProvenanceHopKind::Branch,
                                decision.location,
                                local.decisionInstruction,
                                local.outputExpression, "control flow",
                                "conditional branch consumes the local comparison result",
                                local.confidence);

                            const size_t decisionIndex = retainDecision(
                                std::move(decision), false, 0, 0);
                            assignControlledWrites(decisionIndex, paths.taken,
                                                   paths.fallthrough);
                        }

                        const auto stateOperation = observation.callVAValid
                            ? stateOperationByCallsite.find(observation.callVA)
                            : stateOperationByCallsite.end();
                        if (stateOperation == stateOperationByCallsite.end() ||
                            stateOperation->second >= authorization.stateOperations.size() ||
                            !observation.resultInfluencesDecision ||
                            !observation.decisionVAValid) continue;
                        const PersistentStateOperationInput& operation =
                            authorization.stateOperations[stateOperation->second];
                        if (operation.access != PersistentStateAccess::Read &&
                            operation.access != PersistentStateAccess::Open) continue;
                        bool fallthroughValid = false;
                        const uint64_t fallthroughAddress = authorizationFallthrough(
                            graph, observation.decisionVA,
                            observation.decisionTarget, fallthroughValid);
                        AuthorizationPathPairScan paths = pathsFor(
                            observation.decisionVA, true,
                            observation.decisionTarget,
                            observation.decisionTargetValid,
                            fallthroughAddress, fallthroughValid);
                        AuthorizationDecisionInput decision;
                        decision.location = authorizationLocation(
                            *job.bin, observation.decisionVA, true,
                            function.address, true, function.name);
                        decision.comparison = observation.returnUseSummary;
                        decision.takenPath = std::move(paths.taken.path);
                        decision.fallthroughPath =
                            std::move(paths.fallthrough.path);
                        decision.stateReadOperationIndex = stateOperation->second;
                        decision.stateReadOperationIndexValid = true;
                        decision.gateSource = AuthorizationGateSource::ApiReturn;
                        decision.originExpression = "rax";
                        decision.entitlementKind = authorizationEntitlementKind({
                            operation.identity.canonicalKey,
                            operation.identity.canonicalValue,
                            operation.identity.display});
                        if (decision.entitlementKind !=
                            AuthorizationEntitlementKind::Unknown)
                            decision.entitlementLabel =
                                AuthorizationEntitlementKindText(
                                    decision.entitlementKind);
                        decision.evidence = operation.apiDll + "!" + operation.apiName +
                            " result controls this startup branch; only downstream effects determine allow/deny";
                        if (decision.entitlementKind !=
                            AuthorizationEntitlementKind::Unknown)
                            decision.evidence +=
                                "; exact persistent identity tokens label the checked entitlement as " +
                                decision.entitlementLabel +
                                ", while this branch still represents API status/presence rather than output-content acceptance";
                        retainDecision(std::move(decision), false, 0, 0);
                    }
                    authorizationSummaries.push_back({
                        function.address, function.name,
                        std::move(graph), std::move(annotations)});
                }

                // Extend the local FuncAnnotate reply-buffer proof across at
                // most four direct helper boundaries.  This adapter tracks only
                // exact argument/register/stack expressions through simple
                // moves. Indirect calls, state explosion, and a fifth helper
                // boundary are disclosed as incomplete rather than guessed.
                std::unordered_map<uint64_t, size_t> summaryByFunction;
                for (size_t i = 0; i < authorizationSummaries.size(); ++i)
                    summaryByFunction[authorizationSummaries[i].address] = i;
                auto summaryForTarget = [&](uint64_t target,
                                            size_t& summaryIndex) {
                    auto exact = summaryByFunction.find(target);
                    if (exact != summaryByFunction.end()) {
                        summaryIndex = exact->second;
                        return true;
                    }
                    uint64_t owner = 0;
                    std::string ignored;
                    if (!authorizationOwner(target, owner, ignored)) return false;
                    exact = summaryByFunction.find(owner);
                    if (exact == summaryByFunction.end()) return false;
                    summaryIndex = exact->second;
                    return true;
                };
                std::unordered_map<uint64_t, std::unordered_set<uint64_t>>
                    writeCallsitesByFunction;
                for (const PersistentStateOperationInput& operation :
                     authorization.stateOperations) {
                    if (operation.access == PersistentStateAccess::Write &&
                        operation.location.addressValid &&
                        operation.location.functionAddressValid)
                        writeCallsitesByFunction[operation.location.functionAddress]
                            .insert(operation.location.address);
                }

                // A bounded scalar-provenance engine shared by network API
                // status returns and persisted output values.  It deliberately
                // tracks only exact register/stack expressions, direct helper
                // calls, and return-to-caller edges.  Unknown indirect calls or
                // exhausted budgets are reported as incomplete, never guessed.
                struct ScalarDecisionRecord {
                    CrackmeTriageReturnDecisionInput decision;
                    size_t sinkSummaryIndex = 0;
                };
                struct ScalarTraceResult {
                    std::vector<ScalarDecisionRecord> decisions;
                    bool complete = true;
                    std::string incompleteReason;
                };
                auto traceScalarLineage = [&]
                    (size_t sourceSummaryIndex,
                     uint64_t sourceAddress,
                     std::set<std::string> origins,
                     const NetworkApiReturnContract* networkContract,
                     std::string sourceEvidence) {
                    constexpr size_t kMaxTraceStates = 64;
                    constexpr size_t kMaxBlockStates = 64;
                    constexpr size_t kMaxHelperDepth = 4;
                    constexpr size_t kMaxAliases = 16;
                    constexpr size_t kMaxHops = 32;
                    constexpr size_t kMaxSinks = 4;
                    ScalarTraceResult result;
                    auto incomplete = [&](std::string reason) {
                        result.complete = false;
                        if (result.incompleteReason.empty())
                            result.incompleteReason = std::move(reason);
                    };
                    auto instructionFor = [](const AuthorizationFunctionSummary& summary,
                                             uint64_t address)
                        -> const Instruction* {
                        for (const BasicBlock& block : summary.graph.blocks)
                            for (const Instruction& instruction : block.insns)
                                if (instruction.address == address) return &instruction;
                        return nullptr;
                    };
                    auto makeHop = [&](ValueProvenanceHopKind kind,
                                       size_t summaryIndex,
                                       uint64_t address,
                                       bool addressValid,
                                       std::string instruction,
                                       std::string from,
                                       std::string to,
                                       std::string evidence,
                                       float confidence) {
                        ValueProvenanceHop hop;
                        hop.kind = kind;
                        hop.address = address;
                        hop.addressValid = addressValid;
                        if (summaryIndex < authorizationSummaries.size()) {
                            const auto& summary =
                                authorizationSummaries[summaryIndex];
                            hop.functionAddress = summary.address;
                            hop.functionAddressValid = true;
                            hop.functionName = summary.name;
                        }
                        hop.instruction = std::move(instruction);
                        hop.fromExpression = std::move(from);
                        hop.toExpression = std::move(to);
                        hop.evidence = std::move(evidence);
                        hop.confidence = confidence;
                        return hop;
                    };
                    auto appendHop = [&](std::vector<ValueProvenanceHop>& hops,
                                         ValueProvenanceHop hop) {
                        if (hops.size() >= kMaxHops) {
                            incomplete("scalar provenance hop cap retained the first 32 hops");
                            return false;
                        }
                        hops.push_back(std::move(hop));
                        return true;
                    };
                    auto trimAliases = [&](std::set<std::string>& aliases) {
                        while (aliases.size() > kMaxAliases) {
                            aliases.erase(std::prev(aliases.end()));
                            incomplete("scalar provenance alias cap retained 16 expressions");
                        }
                    };
                    auto callObservationAt = [](const AuthorizationFunctionSummary& summary,
                                                uint64_t address)
                        -> const ApiCallObservation* {
                        for (const ApiCallObservation& call :
                             summary.annotations.apiCalls)
                            if (call.callVAValid && call.callVA == address)
                                return &call;
                        return nullptr;
                    };

                    std::vector<ValueProvenanceHop> initialHops;
                    const AuthorizationFunctionSummary* sourceSummary =
                        sourceSummaryIndex < authorizationSummaries.size()
                        ? &authorizationSummaries[sourceSummaryIndex] : nullptr;
                    const Instruction* sourceInstruction = sourceSummary
                        ? instructionFor(*sourceSummary, sourceAddress) : nullptr;
                    appendHop(initialHops, makeHop(
                        ValueProvenanceHopKind::Origin, sourceSummaryIndex,
                        sourceAddress, true,
                        sourceInstruction
                            ? authorizationInstructionText(*sourceInstruction)
                            : std::string(),
                        {}, origins.empty() ? std::string() : *origins.begin(),
                        std::move(sourceEvidence), 1.0f));

                    struct TraceState {
                        size_t summaryIndex = 0;
                        uint64_t startAddress = 0;
                        bool fromEntry = false;
                        size_t depth = 0;
                        std::set<std::string> tainted;
                        std::vector<ValueProvenanceHop> hops;
                    };
                    struct ReturnedState {
                        size_t summaryIndex = 0;
                        size_t depth = 0;
                        std::vector<ValueProvenanceHop> hops;
                    };
                    std::deque<TraceState> traces;
                    std::deque<ReturnedState> returned;
                    std::unordered_set<std::string> visitedTraces;
                    std::unordered_set<std::string> visitedReturns;
                    std::unordered_set<std::string> retainedSinks;
                    size_t scheduledTraceStates = 0;
                    size_t processedTraceStates = 0;
                    auto enqueueTrace = [&](TraceState state) {
                        if (scheduledTraceStates >= kMaxTraceStates) {
                            incomplete("scalar provenance state cap retained 64 scheduled states");
                            return false;
                        }
                        ++scheduledTraceStates;
                        traces.push_back(std::move(state));
                        return true;
                    };
                    auto enqueueReturned = [&](ReturnedState state) {
                        if (scheduledTraceStates >= kMaxTraceStates) {
                            incomplete("scalar provenance state cap retained 64 scheduled states");
                            return false;
                        }
                        ++scheduledTraceStates;
                        returned.push_back(std::move(state));
                        return true;
                    };
                    enqueueTrace({sourceSummaryIndex, sourceAddress, false, 0,
                                  std::move(origins), initialHops});

                    auto dispositionAddress = [](NetworkReturnDisposition disposition,
                                                  uint64_t address,
                                                  bool addressValid,
                                                  CrackmeTriageReturnDecisionInput& decision) {
                        if (!addressValid) return;
                        if (disposition == NetworkReturnDisposition::Success) {
                            decision.successAddress = address;
                            decision.successAddressValid = true;
                        } else if (disposition == NetworkReturnDisposition::Failure) {
                            decision.failureAddress = address;
                            decision.failureAddressValid = true;
                        }
                    };
                    auto retainDecision = [&](size_t summaryIndex,
                                              CrackmeTriageReturnDecisionInput decision) {
                        if (!decision.decisionAddressValid) return;
                        const std::string key = std::to_string(summaryIndex) + ':' +
                            std::to_string(decision.comparisonAddress) + ':' +
                            std::to_string(decision.decisionAddress);
                        if (retainedSinks.find(key) != retainedSinks.end()) return;
                        if (result.decisions.size() >= kMaxSinks) {
                            incomplete("scalar provenance sink cap retained the first four checks");
                            return;
                        }
                        retainedSinks.insert(key);
                        result.decisions.push_back(
                            {std::move(decision), summaryIndex});
                    };
                    auto decisionFromComparison = [&]
                        (size_t summaryIndex,
                         const Instruction& comparison,
                         const Instruction& branch,
                         int matchedOperand,
                         std::vector<ValueProvenanceHop> hops,
                         size_t depth) {
                        if (summaryIndex >= authorizationSummaries.size()) return;
                        const auto& summary = authorizationSummaries[summaryIndex];
                        const std::vector<std::string> operands =
                            authorizationSplitOperands(comparison.operands);
                        CrackmeTriageReturnDecisionInput decision;
                        decision.comparisonAddress = comparison.address;
                        decision.comparisonAddressValid = true;
                        decision.comparisonInstruction =
                            authorizationInstructionText(comparison);
                        decision.comparisonSignature =
                            codeSignatures.capture(*dis, comparison.address);
                        decision.predicate = decision.comparisonInstruction;
                        if (operands.size() == 2 && matchedOperand >= 0)
                            decision.expectedValue = operands[
                                matchedOperand == 0 ? 1 : 0];
                        decision.decisionAddress = branch.address;
                        decision.decisionAddressValid = true;
                        decision.decisionInstruction =
                            authorizationInstructionText(branch);
                        decision.decisionSignature =
                            codeSignatures.capture(*dis, branch.address);
                        decision.decisionTarget = branch.branchTarget;
                        decision.decisionTargetValid = HasBranchTarget(branch);
                        decision.fallthroughAddress = authorizationFallthrough(
                            summary.graph, branch.address, branch.branchTarget,
                            decision.fallthroughAddressValid);
                        if (networkContract) {
                            const StaticNetworkBranchOutcome outcomes =
                                authorizationClassifyNetworkBranch(
                                    *networkContract, comparison.mnemonic,
                                    decision.expectedValue, branch.mnemonic,
                                    job.decoder.arch == Arch::X64 ? 64u : 32u,
                                    operands.size() == 2 &&
                                        operands[0] == operands[1],
                                    matchedOperand,
                                    matchedOperand >= 0
                                        ? authorizationOperandWidthBits(
                                            comparison,
                                            static_cast<size_t>(matchedOperand))
                                        : 0);
                            decision.takenDisposition = outcomes.taken;
                            decision.fallthroughDisposition = outcomes.fallthrough;
                        }
                        dispositionAddress(decision.takenDisposition,
                                           decision.decisionTarget,
                                           decision.decisionTargetValid,
                                           decision);
                        dispositionAddress(decision.fallthroughDisposition,
                                           decision.fallthroughAddress,
                                           decision.fallthroughAddressValid,
                                           decision);
                        appendHop(hops, makeHop(
                            ValueProvenanceHopKind::Compare, summaryIndex,
                            comparison.address, true,
                            decision.comparisonInstruction,
                            matchedOperand >= 0 &&
                                static_cast<size_t>(matchedOperand) < operands.size()
                                ? operands[static_cast<size_t>(matchedOperand)]
                                : std::string(),
                            decision.expectedValue,
                            "comparison reads the tracked scalar provenance",
                            depth <= 1 ? 0.90f : 0.78f));
                        appendHop(hops, makeHop(
                            ValueProvenanceHopKind::Branch, summaryIndex,
                            branch.address, true, decision.decisionInstruction,
                            decision.comparisonInstruction, {},
                            "conditional branch consumes the comparison flags",
                            depth <= 1 ? 0.90f : 0.78f));
                        decision.hops = std::move(hops);
                        decision.evidence =
                            "bounded exact-expression lineage reaches this comparison at helper/caller depth " +
                            std::to_string(depth);
                        decision.confidence = depth <= 1 ? 0.90f : 0.76f;
                        retainDecision(summaryIndex, std::move(decision));
                    };
                    auto decisionFromCall = [&]
                        (size_t summaryIndex,
                         const ApiCallObservation& call,
                         const std::vector<size_t>& taintedArguments,
                         std::vector<ValueProvenanceHop> hops,
                         size_t depth) {
                        if (!authorizationEqualityHelper(*job.bin, call) ||
                            !call.resultInfluencesDecision ||
                            !call.decisionVAValid ||
                            summaryIndex >= authorizationSummaries.size()) return;
                        const auto& summary = authorizationSummaries[summaryIndex];
                        CrackmeTriageReturnDecisionInput decision;
                        decision.comparisonAddress = call.callVA;
                        decision.comparisonAddressValid = call.callVAValid;
                        decision.comparisonInstruction = "call " + call.resolvedName;
                        if (call.callVAValid)
                            decision.comparisonSignature =
                                codeSignatures.capture(*dis, call.callVA);
                        decision.predicate = call.returnUseSummary;
                        for (const ApiArgumentObservation& argument : call.arguments) {
                            if (std::find(taintedArguments.begin(),
                                          taintedArguments.end(), argument.index) !=
                                taintedArguments.end()) continue;
                            if (!argument.stringLiteral.empty()) {
                                decision.expectedValue =
                                    "\"" + argument.stringLiteral + "\"";
                                break;
                            }
                            if (decision.expectedValue.empty() &&
                                argument.immediateValid)
                                decision.expectedValue =
                                    std::to_string(argument.immediate);
                        }
                        decision.decisionAddress = call.decisionVA;
                        decision.decisionAddressValid = call.decisionVAValid;
                        decision.decisionInstruction = call.decisionInstruction;
                        decision.decisionSignature =
                            codeSignatures.capture(*dis, call.decisionVA);
                        decision.decisionTarget = call.decisionTarget;
                        decision.decisionTargetValid = call.decisionTargetValid;
                        decision.fallthroughAddress = authorizationFallthrough(
                            summary.graph, call.decisionVA, call.decisionTarget,
                            decision.fallthroughAddressValid);
                        // The helper returns zero on equality, but when this is
                        // tracing a network status scalar the relation between
                        // equality and the API contract may still be unknown.
                        appendHop(hops, makeHop(
                            ValueProvenanceHopKind::Compare, summaryIndex,
                            call.callVA, call.callVAValid,
                            decision.comparisonInstruction, {},
                            decision.expectedValue,
                            "exact equality helper consumes the tracked value",
                            depth <= 1 ? 0.84f : 0.72f));
                        appendHop(hops, makeHop(
                            ValueProvenanceHopKind::Branch, summaryIndex,
                            call.decisionVA, true, call.decisionInstruction,
                            call.returnUseInstruction, {},
                            "conditional branch consumes the equality-helper result",
                            depth <= 1 ? 0.84f : 0.72f));
                        decision.hops = std::move(hops);
                        decision.evidence =
                            "tracked scalar reaches exact equality helper " +
                            call.resolvedName;
                        decision.confidence = depth <= 1 ? 0.84f : 0.72f;
                        retainDecision(summaryIndex, std::move(decision));
                    };

                    while ((!traces.empty() || !returned.empty()) &&
                           processedTraceStates < kMaxTraceStates && !superseded()) {
                        while (!returned.empty() &&
                               processedTraceStates < kMaxTraceStates) {
                            ReturnedState value = std::move(returned.front());
                            returned.pop_front();
                            ++processedTraceStates;
                            const std::string returnKey =
                                std::to_string(value.summaryIndex) + ':' +
                                std::to_string(value.depth);
                            if (!visitedReturns.insert(returnKey).second ||
                                value.summaryIndex >= authorizationSummaries.size())
                                continue;
                            if (value.depth >= kMaxHelperDepth) {
                                incomplete("scalar provenance reached the four-helper/caller depth cap");
                                continue;
                            }
                            for (size_t callerIndex = 0;
                                 callerIndex < authorizationSummaries.size();
                                 ++callerIndex) {
                                const auto& caller =
                                    authorizationSummaries[callerIndex];
                                for (const ApiCallObservation& call :
                                     caller.annotations.apiCalls) {
                                    size_t targetSummary = 0;
                                    if (!call.targetVAValid ||
                                        !summaryForTarget(call.targetVA,
                                                          targetSummary) ||
                                        targetSummary != value.summaryIndex)
                                        continue;
                                    std::vector<ValueProvenanceHop> hops =
                                        value.hops;
                                    appendHop(hops, makeHop(
                                        ValueProvenanceHopKind::ReturnToCaller,
                                        callerIndex, call.callVA,
                                        call.callVAValid,
                                        "call " + call.resolvedName, "rax", "rax",
                                        "direct caller receives the tracked helper return",
                                        0.82f));
                                    enqueueTrace({callerIndex, call.callVA,
                                        false, value.depth + 1, {"rax"},
                                        std::move(hops)});
                                }
                            }
                        }
                        if (traces.empty()) continue;
                        TraceState trace = std::move(traces.front());
                        traces.pop_front();
                        ++processedTraceStates;
                        if (trace.summaryIndex >= authorizationSummaries.size()) {
                            incomplete("scalar provenance function summary was unavailable");
                            continue;
                        }
                        trimAliases(trace.tainted);
                        std::string traceKey =
                            std::to_string(trace.summaryIndex) + ':' +
                            std::to_string(trace.startAddress) + ':' +
                            std::to_string(trace.depth);
                        for (const std::string& alias : trace.tainted)
                            traceKey += '|' + alias;
                        if (!visitedTraces.insert(std::move(traceKey)).second)
                            continue;
                        const auto& summary =
                            authorizationSummaries[trace.summaryIndex];
                        size_t firstBlock = summary.graph.blocks.size();
                        for (size_t i = 0; i < summary.graph.blocks.size(); ++i) {
                            const BasicBlock& block = summary.graph.blocks[i];
                            if (trace.startAddress >= block.start &&
                                trace.startAddress < block.end) {
                                firstBlock = i;
                                break;
                            }
                        }
                        if (firstBlock >= summary.graph.blocks.size()) {
                            incomplete("scalar provenance start was outside the retained CFG");
                            continue;
                        }
                        struct BlockState {
                            size_t block = 0;
                            bool first = false;
                            bool flagsTainted = false;
                            std::set<std::string> tainted;
                            std::vector<ValueProvenanceHop> hops;
                        };
                        std::deque<BlockState> blocks;
                        std::unordered_set<std::string> visitedBlocks;
                        size_t scheduledBlockStates = 0;
                        size_t blockStates = 0;
                        auto enqueueBlock = [&](BlockState state) {
                            if (scheduledBlockStates >= kMaxBlockStates) {
                                incomplete("scalar provenance block-state cap retained 64 scheduled states");
                                return false;
                            }
                            ++scheduledBlockStates;
                            blocks.push_back(std::move(state));
                            return true;
                        };
                        enqueueBlock({firstBlock, true, false,
                                      trace.tainted, trace.hops});
                        while (!blocks.empty() &&
                               blockStates++ < kMaxBlockStates) {
                            BlockState state = std::move(blocks.front());
                            blocks.pop_front();
                            if (state.block >= summary.graph.blocks.size())
                                continue;
                            trimAliases(state.tainted);
                            std::string blockKey = std::to_string(state.block) +
                                (state.flagsTainted ? ":f" : ":n");
                            for (const std::string& alias : state.tainted)
                                blockKey += '|' + alias;
                            if (!visitedBlocks.insert(std::move(blockKey)).second)
                                continue;
                            const BasicBlock& block = summary.graph.blocks[state.block];
                            for (size_t instructionIndex = 0;
                                 instructionIndex < block.insns.size();
                                 ++instructionIndex) {
                                const Instruction& instruction =
                                    block.insns[instructionIndex];
                                if (state.first && !trace.fromEntry &&
                                    instruction.address <= trace.startAddress)
                                    continue;
                                const std::string mnemonic =
                                    authorizationLower(instruction.mnemonic);
                                const std::vector<std::string> operands =
                                    authorizationSplitOperands(instruction.operands);

                                if ((mnemonic == "cmp" || mnemonic == "test") &&
                                    !state.tainted.empty()) {
                                    int matched = -1;
                                    bool trackedAddressOnly = false;
                                    for (size_t operandIndex = 0;
                                         operandIndex < operands.size();
                                         ++operandIndex) {
                                        const bool addressOnly =
                                            authorizationExpressionUsesTaintedAddress(
                                                operands[operandIndex],
                                                state.tainted);
                                        trackedAddressOnly |= addressOnly;
                                        if (networkContract && addressOnly)
                                            continue;
                                        if (authorizationExpressionTainted(
                                                operands[operandIndex],
                                                state.tainted)) {
                                            matched = static_cast<int>(operandIndex);
                                            break;
                                        }
                                    }
                                    if (trackedAddressOnly && networkContract)
                                        incomplete(
                                            "network return was used only as a pointee address; pointee contents do not inherit the API return contract");
                                    state.flagsTainted = matched >= 0;
                                    const Instruction* branch = matched >= 0
                                        ? authorizationNearbyConditionalBranch(
                                            block, instructionIndex)
                                        : nullptr;
                                    if (branch)
                                        decisionFromComparison(
                                            trace.summaryIndex, instruction,
                                            *branch, matched, state.hops,
                                            trace.depth);
                                    continue;
                                }

                                if (state.flagsTainted &&
                                    mnemonic.rfind("set", 0) == 0 &&
                                    !operands.empty()) {
                                    const std::string destination = operands[0];
                                    if (networkContract) {
                                        state.tainted.erase(destination);
                                        state.flagsTainted = false;
                                        incomplete(
                                            "setcc transformed tracked status flags without preserving the original API contract");
                                        continue;
                                    }
                                    state.tainted.insert(destination);
                                    appendHop(state.hops, makeHop(
                                        ValueProvenanceHopKind::Copy,
                                        trace.summaryIndex,
                                        instruction.address, true,
                                        authorizationInstructionText(instruction),
                                        "comparison flags", destination,
                                        "setcc materializes a tracked comparison result",
                                        0.72f));
                                    trimAliases(state.tainted);
                                    continue;
                                }

                                if (instruction.isRet) {
                                    if (authorizationExpressionTainted(
                                            "rax", state.tainted)) {
                                        std::vector<ValueProvenanceHop> hops =
                                            state.hops;
                                        appendHop(hops, makeHop(
                                            ValueProvenanceHopKind::ReturnFromHelper,
                                            trace.summaryIndex,
                                            instruction.address, true,
                                            authorizationInstructionText(instruction),
                                            "rax", "caller rax",
                                            "function returns the tracked scalar",
                                            0.82f));
                                        enqueueReturned({trace.summaryIndex,
                                                         trace.depth,
                                                         std::move(hops)});
                                    }
                                    continue;
                                }

                                if (instruction.isCall) {
                                    const ApiCallObservation* call =
                                        callObservationAt(summary,
                                                          instruction.address);
                                    std::vector<size_t> taintedArguments;
                                    if (call) {
                                        for (const ApiArgumentObservation& argument :
                                             call->arguments) {
                                            bool tainted = false;
                                            bool addressOnly = false;
                                            for (const std::string& expression :
                                                 authorizationArgumentExpressions(argument)) {
                                                const bool usesTrackedAddress =
                                                    authorizationExpressionUsesTaintedAddress(
                                                        expression,
                                                        state.tainted);
                                                addressOnly |= usesTrackedAddress;
                                                if (networkContract &&
                                                    usesTrackedAddress)
                                                    continue;
                                                tainted |=
                                                    authorizationExpressionTainted(
                                                        expression,
                                                        state.tainted);
                                            }
                                            if (networkContract && addressOnly &&
                                                !tainted)
                                                incomplete(
                                                    "network return reached a call argument only as a pointee address");
                                            if (tainted)
                                                taintedArguments.push_back(
                                                    argument.index);
                                        }
                                    }
                                    if (call && !taintedArguments.empty()) {
                                        std::vector<ValueProvenanceHop> callHops =
                                            state.hops;
                                        appendHop(callHops, makeHop(
                                            ValueProvenanceHopKind::PassArgument,
                                            trace.summaryIndex,
                                            instruction.address, true,
                                            authorizationInstructionText(instruction),
                                            *state.tainted.begin(),
                                            "arg" + std::to_string(
                                                taintedArguments.front() + 1),
                                            "tracked scalar is passed to this direct call",
                                            0.78f));
                                        decisionFromCall(trace.summaryIndex,
                                                         *call,
                                                         taintedArguments,
                                                         callHops,
                                                         trace.depth);
                                        size_t targetSummary = 0;
                                        if (call->targetVAValid &&
                                            summaryForTarget(call->targetVA,
                                                             targetSummary)) {
                                            if (trace.depth >= kMaxHelperDepth) {
                                                incomplete("scalar provenance reached the four-helper depth cap");
                                            } else {
                                                std::set<std::string> incoming;
                                                for (size_t argumentIndex :
                                                     taintedArguments) {
                                                    const auto expressions =
                                                        authorizationIncomingParameterExpressions(
                                                            argumentIndex,
                                                            job.decoder.arch == Arch::X64);
                                                    incoming.insert(expressions.begin(),
                                                                    expressions.end());
                                                }
                                                appendHop(callHops, makeHop(
                                                    ValueProvenanceHopKind::EnterHelper,
                                                    targetSummary,
                                                    authorizationSummaries[targetSummary]
                                                        .address,
                                                    true, {}, {},
                                                    incoming.empty()
                                                        ? std::string()
                                                        : *incoming.begin(),
                                                    "direct helper receives the tracked argument",
                                                    0.78f));
                                                enqueueTrace({targetSummary,
                                                    authorizationSummaries[targetSummary]
                                                        .address,
                                                    true, trace.depth + 1,
                                                    std::move(incoming),
                                                    std::move(callHops)});
                                            }
                                        } else if (!authorizationEqualityHelper(
                                                       *job.bin, *call)) {
                                            incomplete("tracked scalar reached an unresolved or indirect call");
                                        }
                                    } else if (!HasBranchTarget(instruction) &&
                                               authorizationExpressionTainted(
                                                   authorizationExpressionKey(
                                                       instruction.operands),
                                                   state.tainted)) {
                                        incomplete("tracked scalar reached an unresolved indirect call");
                                    }
                                    authorizationApplyLineageInstruction(
                                        instruction, state.tainted);
                                    state.flagsTainted = false;
                                    continue;
                                }

                                const bool zeroingSelf =
                                    (mnemonic == "xor" || mnemonic == "sub") &&
                                    operands.size() == 2 &&
                                    operands[0] == operands[1];
                                if (!networkContract && mnemonic == "lea" &&
                                    operands.size() >= 2 &&
                                    authorizationExpressionTainted(
                                        operands[1], state.tainted)) {
                                    // LEA materializes the address of persisted
                                    // storage, not the value read from it. Keep
                                    // the storage origin live for a later MOV/
                                    // MOVZX load, but never taint the pointer.
                                    state.tainted.erase(operands[0]);
                                    state.flagsTainted = false;
                                    continue;
                                }
                                if (networkContract && mnemonic == "mov" &&
                                    operands.size() >= 2 &&
                                    authorizationExpressionUsesTaintedAddress(
                                        operands[1], state.tainted)) {
                                    state.tainted.erase(operands[0]);
                                    state.flagsTainted = false;
                                    incomplete(
                                        "network return was dereferenced; pointee contents do not inherit the API return contract");
                                    continue;
                                }
                                if (networkContract && mnemonic == "mov" &&
                                    operands.size() >= 2 &&
                                    authorizationExpressionTainted(
                                        operands[1], state.tainted)) {
                                    const uint16_t contractWidth =
                                        networkContract->returnKind ==
                                                NetworkReturnKind::SocketHandle ||
                                            networkContract->returnKind ==
                                                NetworkReturnKind::InternetHandle ||
                                            networkContract->returnKind ==
                                                NetworkReturnKind::Pointer
                                        ? (job.decoder.arch == Arch::X64 ? 64u : 32u)
                                        : 32u;
                                    uint16_t destinationWidth =
                                        authorizationOperandWidthBits(
                                            instruction, 0);
                                    uint16_t sourceWidth =
                                        authorizationOperandWidthBits(
                                            instruction, 1);
                                    if (!destinationWidth) destinationWidth = sourceWidth;
                                    if (!sourceWidth) sourceWidth = destinationWidth;
                                    if (!destinationWidth || !sourceWidth ||
                                        destinationWidth < contractWidth ||
                                        sourceWidth < contractWidth) {
                                        state.tainted.erase(operands[0]);
                                        state.flagsTainted = false;
                                        incomplete(
                                            "tracked network return was narrowed or copied at an unknown width");
                                        continue;
                                    }
                                }
                                if (networkContract && mnemonic == "xchg" &&
                                    operands.size() == 2 &&
                                    (authorizationExpressionUsesTaintedAddress(
                                         operands[0], state.tainted) ||
                                     authorizationExpressionUsesTaintedAddress(
                                         operands[1], state.tainted))) {
                                    state.tainted.clear();
                                    state.flagsTainted = false;
                                    incomplete(
                                        "network return participated in an address-dependent exchange; scalar provenance was discarded");
                                    continue;
                                }
                                if (networkContract && mnemonic == "xchg" &&
                                    operands.size() == 2 &&
                                    (authorizationExpressionTainted(
                                         operands[0], state.tainted) ||
                                     authorizationExpressionTainted(
                                         operands[1], state.tainted))) {
                                    const uint16_t contractWidth =
                                        networkContract->returnKind ==
                                                NetworkReturnKind::SocketHandle ||
                                            networkContract->returnKind ==
                                                NetworkReturnKind::InternetHandle ||
                                            networkContract->returnKind ==
                                                NetworkReturnKind::Pointer
                                        ? (job.decoder.arch == Arch::X64 ? 64u : 32u)
                                        : 32u;
                                    uint16_t leftWidth =
                                        authorizationOperandWidthBits(
                                            instruction, 0);
                                    uint16_t rightWidth =
                                        authorizationOperandWidthBits(
                                            instruction, 1);
                                    if (!leftWidth) leftWidth = rightWidth;
                                    if (!rightWidth) rightWidth = leftWidth;
                                    if (!leftWidth || !rightWidth ||
                                        leftWidth < contractWidth ||
                                        rightWidth < contractWidth) {
                                        state.tainted.erase(operands[0]);
                                        state.tainted.erase(operands[1]);
                                        state.flagsTainted = false;
                                        incomplete(
                                            "tracked network return reached a narrowed or unknown-width exchange");
                                        continue;
                                    }
                                }
                                const bool valueTransform =
                                    (networkContract &&
                                     (mnemonic == "movzx" ||
                                      mnemonic == "movsx" ||
                                      mnemonic == "movsxd")) ||
                                    mnemonic == "add" ||
                                    mnemonic == "adc" || mnemonic == "sub" ||
                                    mnemonic == "sbb" || mnemonic == "and" ||
                                    mnemonic == "or" || mnemonic == "xor" ||
                                    mnemonic == "imul" || mnemonic == "mul" ||
                                    mnemonic == "idiv" || mnemonic == "div" ||
                                    mnemonic == "shl" || mnemonic == "sal" ||
                                    mnemonic == "shr" || mnemonic == "sar" ||
                                    mnemonic == "rol" || mnemonic == "ror" ||
                                    mnemonic == "inc" || mnemonic == "dec" ||
                                    mnemonic == "neg" || mnemonic == "not" ||
                                    mnemonic == "bswap" ||
                                    (networkContract && mnemonic == "lea");
                                bool transformsTrackedValue = false;
                                if (valueTransform && !zeroingSelf) {
                                    for (const std::string& operand : operands)
                                        transformsTrackedValue |=
                                            authorizationExpressionTainted(
                                                operand, state.tainted);
                                }
                                if (transformsTrackedValue) {
                                    if (!operands.empty())
                                        state.tainted.erase(operands[0]);
                                    state.flagsTainted = false;
                                    incomplete(
                                        "tracked scalar was transformed before a contract-safe comparison");
                                    continue;
                                }

                                const bool modeledInstruction =
                                    mnemonic == "mov" || mnemonic == "lea" ||
                                    mnemonic == "xchg" || mnemonic == "push" ||
                                    mnemonic == "pop" || mnemonic == "nop" ||
                                    mnemonic == "endbr32" ||
                                    mnemonic == "endbr64" ||
                                    (!networkContract &&
                                     (mnemonic == "movzx" ||
                                      mnemonic == "movsx" ||
                                      mnemonic == "movsxd")) ||
                                    zeroingSelf;
                                if (!modeledInstruction) {
                                    bool touchesTrackedValue = false;
                                    for (const std::string& operand : operands)
                                        touchesTrackedValue |=
                                            authorizationExpressionTainted(
                                                operand, state.tainted);
                                    if (touchesTrackedValue) {
                                        bool erasedDestination = false;
                                        for (size_t operandIndex = 0;
                                             operandIndex <
                                                 instruction.typedOperands.size();
                                             ++operandIndex) {
                                            const TypedOperand& typed =
                                                instruction.typedOperands[
                                                    operandIndex];
                                            if (!OperandWrites(typed.access))
                                                continue;
                                            std::string destination;
                                            if (typed.kind == OperandKind::Register)
                                                destination =
                                                    authorizationExpressionKey(
                                                        typed.registerName);
                                            else if (operandIndex < operands.size())
                                                destination = operands[operandIndex];
                                            if (!destination.empty()) {
                                                state.tainted.erase(destination);
                                                erasedDestination = true;
                                            }
                                        }
                                        if (!erasedDestination &&
                                            !operands.empty() &&
                                            (mnemonic.rfind("cmov", 0) == 0 ||
                                             mnemonic.rfind("set", 0) == 0))
                                            state.tainted.erase(operands[0]);
                                        state.flagsTainted = false;
                                        incomplete(
                                            "tracked scalar reached an unsupported read/write transformation");
                                        continue;
                                    }
                                }

                                bool copied = false;
                                if ((mnemonic == "mov" || mnemonic == "lea" ||
                                     (!networkContract &&
                                      (mnemonic == "movzx" ||
                                       mnemonic == "movsx" ||
                                       mnemonic == "movsxd"))) &&
                                    operands.size() >= 2 &&
                                    authorizationExpressionTainted(
                                        operands[1], state.tainted)) {
                                    ValueProvenanceHopKind kind =
                                        ValueProvenanceHopKind::Copy;
                                    if (operands[0].find('[') != std::string::npos)
                                        kind = ValueProvenanceHopKind::Store;
                                    else if (operands[1].find('[') !=
                                             std::string::npos)
                                        kind = ValueProvenanceHopKind::Reload;
                                    appendHop(state.hops, makeHop(
                                        kind, trace.summaryIndex,
                                        instruction.address, true,
                                        authorizationInstructionText(instruction),
                                        operands[1], operands[0],
                                        "simple exact-expression transfer",
                                        0.88f));
                                    copied = true;
                                }
                                authorizationApplyLineageInstruction(
                                    instruction, state.tainted);
                                if (copied) trimAliases(state.tainted);
                                if (mnemonic == "add" || mnemonic == "sub" ||
                                    mnemonic == "and" || mnemonic == "or" ||
                                    mnemonic == "xor")
                                    state.flagsTainted = false;
                            }
                            for (size_t successor : block.succ) {
                                if (successor < summary.graph.blocks.size())
                                    enqueueBlock({successor, false,
                                        state.flagsTainted, state.tainted,
                                        state.hops});
                            }
                        }
                        if (!blocks.empty())
                            incomplete("scalar provenance reached the 64-block-state cap");
                    }
                    if (!traces.empty() || !returned.empty())
                        incomplete("scalar provenance reached the 64-state cap");
                    if (superseded()) incomplete("scalar provenance was cancelled");
                    std::stable_sort(result.decisions.begin(),
                        result.decisions.end(), [](const auto& left,
                                                   const auto& right) {
                            if (left.decision.confidence !=
                                right.decision.confidence)
                                return left.decision.confidence >
                                       right.decision.confidence;
                            if (left.decision.comparisonAddress !=
                                right.decision.comparisonAddress)
                                return left.decision.comparisonAddress <
                                       right.decision.comparisonAddress;
                            return left.decision.decisionAddress <
                                   right.decision.decisionAddress;
                        });
                    return result;
                };

                size_t networkStatusSources = 0;
                constexpr size_t kMaxNetworkStatusSources = 64;
                for (CrackmeTriageApiCallInput& source : triage.apiCalls) {
                    const auto network = LookupNetworkApi(source.dll,
                                                          source.name);
                    const auto contract = LookupNetworkApiReturnContract(
                        source.dll, source.name);
                    if (!network || !contract || !source.callsiteValid ||
                        !source.functionAddressValid) continue;
                    source.returnLineageAnalysisAttempted = true;
                    if (networkStatusSources++ >= kMaxNetworkStatusSources) {
                        source.returnLineageComplete = false;
                        source.returnLineageIncompleteReason =
                            "network status provenance cap retained the first 64 callsites";
                        triage.apiCallsComplete = false;
                        continue;
                    }
                    const auto summary = summaryByFunction.find(
                        source.functionAddress);
                    if (summary == summaryByFunction.end()) {
                        source.returnLineageComplete = false;
                        source.returnLineageIncompleteReason =
                            "network API owner was outside the retained authorization candidates";
                        continue;
                    }
                    ScalarTraceResult traced = traceScalarLineage(
                        summary->second, source.callsite, {"rax"}, &*contract,
                        source.dll + "!" + source.name +
                            " immediate ABI return register");
                    source.returnLineageComplete = traced.complete;
                    source.returnLineageIncompleteReason =
                        traced.incompleteReason;
                    for (ScalarDecisionRecord& decision : traced.decisions)
                        source.returnDecisions.push_back(
                            std::move(decision.decision));
                }

                // State API output values are authorization candidates only
                // when their exact expression reaches a comparison/branch.
                // RunAuthorizationAnalysis later enforces startup reachability
                // and classifies allow/deny solely from downstream effects.
                for (size_t operationIndex = 0;
                     operationIndex < authorization.stateOperations.size();
                     ++operationIndex) {
                    const PersistentStateOperationInput& operation =
                        authorization.stateOperations[operationIndex];
                    if ((operation.access != PersistentStateAccess::Read &&
                         operation.access != PersistentStateAccess::Open) ||
                        operation.outputExpression.empty() ||
                        !operation.location.addressValid ||
                        !operation.location.functionAddressValid)
                        continue;
                    const auto summary = summaryByFunction.find(
                        operation.location.functionAddress);
                    if (summary == summaryByFunction.end()) {
                        authorization.decisionsComplete = false;
                        continue;
                    }
                    ScalarTraceResult traced = traceScalarLineage(
                        summary->second, operation.location.address,
                        {authorizationExpressionKey(operation.outputExpression)},
                        nullptr,
                        operation.apiDll + "!" + operation.apiName +
                            " persisted output expression");
                    for (ScalarDecisionRecord& terminal : traced.decisions) {
                        if (terminal.sinkSummaryIndex >=
                            authorizationSummaries.size()) continue;
                        if (authorization.decisions.size() >=
                            authorization.limits.maxDecisions) {
                            authorization.decisionsComplete = false;
                            break;
                        }
                        const auto& sink = authorizationSummaries[
                            terminal.sinkSummaryIndex];
                        AuthorizationPathPairScan paths =
                            scanAuthorizationPathPair(
                                *job.bin, sink.graph,
                                terminal.decision.decisionAddress,
                                terminal.decision.decisionAddressValid,
                                terminal.decision.decisionTarget,
                                terminal.decision.decisionTargetValid,
                                terminal.decision.fallthroughAddress,
                                terminal.decision.fallthroughAddressValid,
                                sink.address, sink.name, namesByVA, stringsByVA,
                                writeCallsitesByFunction[sink.address]);
                        AuthorizationDecisionInput decision;
                        decision.location = authorizationLocation(
                            *job.bin, terminal.decision.decisionAddress, true,
                            sink.address, true, sink.name);
                        decision.comparison =
                            terminal.decision.comparisonInstruction;
                        decision.takenPath = std::move(paths.taken.path);
                        decision.fallthroughPath =
                            std::move(paths.fallthrough.path);
                        decision.stateReadOperationIndex = operationIndex;
                        decision.stateReadOperationIndexValid = true;
                        decision.gateSource =
                            AuthorizationGateSource::PersistentOutput;
                        decision.originExpression = operation.outputExpression;
                        decision.expectedValue =
                            terminal.decision.expectedValue;
                        decision.entitlementKind = authorizationEntitlementKind({
                            operation.identity.canonicalKey,
                            operation.identity.canonicalValue,
                            operation.identity.display,
                            decision.expectedValue});
                        if (decision.entitlementKind !=
                            AuthorizationEntitlementKind::Unknown)
                            decision.entitlementLabel =
                                AuthorizationEntitlementKindText(
                                    decision.entitlementKind);
                        decision.provenance =
                            std::move(terminal.decision.hops);
                        decision.provenanceComplete = traced.complete;
                        decision.provenanceIncompleteReason =
                            traced.incompleteReason;
                        decision.evidence = operation.apiDll + "!" +
                            operation.apiName + " output " +
                            operation.outputExpression +
                            " reaches a bounded comparison/branch";
                        if (decision.entitlementKind !=
                            AuthorizationEntitlementKind::Unknown)
                            decision.evidence += "; exact token/compared value labels this as " +
                                decision.entitlementLabel;
                        authorization.decisions.push_back(
                            std::move(decision));
                    }
                }

                size_t interproceduralSources = 0;
                constexpr size_t kMaxInterproceduralSources = 64;
                constexpr size_t kMaxHelperStatesPerSource = 64;
                constexpr size_t kMaxBlockStatesPerHelper = 64;
                constexpr size_t kMaxHelperDepth = 4;
                for (CrackmeTriageApiCallInput& source : triage.apiCalls) {
                    const auto network = LookupNetworkApi(source.dll, source.name);
                    if (!network || network->stage != NetworkStage::Read ||
                        !source.callsiteValid || !source.functionAddressValid)
                        continue;
                    const auto contract = LookupNetworkApiReturnContract(
                        source.dll, source.name);
                    if (!contract) continue;
                    std::vector<NetworkApiOutParameter> contentOutputs;
                    for (uint8_t outputIndex = 0;
                         outputIndex < contract->outParameterCount; ++outputIndex) {
                        const NetworkApiOutParameter& output =
                            contract->outParameters[outputIndex];
                        if (output.role == NetworkOutParameterRole::PayloadBuffer ||
                            output.role == NetworkOutParameterRole::HeaderBuffer)
                            contentOutputs.push_back(output);
                    }
                    if (contentOutputs.empty()) continue;
                    source.replyDecisionAnalysisAttempted = true;
                    if (interproceduralSources++ >= kMaxInterproceduralSources) {
                        source.replyDecisionsComplete = false;
                        source.replyDecisionIncompleteReason =
                            "interprocedural reply-source cap retained the first 64 read callsites";
                        triage.apiCallsComplete = false;
                        continue;
                    }
                    const auto sourceSummaryFound =
                        summaryByFunction.find(source.functionAddress);
                    if (sourceSummaryFound == summaryByFunction.end()) {
                        source.replyDecisionsComplete = false;
                        source.replyDecisionIncompleteReason =
                            "reply producer function was outside the retained authorization candidates";
                        continue;
                    }
                    const size_t sourceSummaryIndex = sourceSummaryFound->second;
                    const AuthorizationFunctionSummary& sourceSummary =
                        authorizationSummaries[sourceSummaryIndex];
                    const ApiCallObservation* sourceObservation = nullptr;
                    for (const ApiCallObservation& observation :
                         sourceSummary.annotations.apiCalls) {
                        if (observation.callVAValid &&
                            observation.callVA == source.callsite) {
                            sourceObservation = &observation;
                            break;
                        }
                    }
                    if (!sourceObservation) {
                        source.replyDecisionsComplete = false;
                        source.replyDecisionIncompleteReason =
                            "typed reply producer observation was not retained";
                        continue;
                    }

                    for (const NetworkApiOutParameter& output : contentOutputs) {
                        const auto originArgument = std::find_if(
                            sourceObservation->arguments.begin(),
                            sourceObservation->arguments.end(),
                            [&](const ApiArgumentObservation& argument) {
                                return argument.index == output.argumentIndex;
                            });
                        if (originArgument == sourceObservation->arguments.end()) {
                            source.replyDecisionsComplete = false;
                            if (source.replyDecisionIncompleteReason.empty())
                                source.replyDecisionIncompleteReason =
                                    "cataloged reply output argument was not recovered";
                            continue;
                        }
                        const std::string provenStorage =
                            authorizationOutputStorageExpression(
                                &*originArgument);
                        if (provenStorage.empty()) {
                            source.replyDecisionsComplete = false;
                            if (source.replyDecisionIncompleteReason.empty())
                                source.replyDecisionIncompleteReason =
                                    "cataloged reply output was recovered only as an unproven pointer, not pointee storage";
                            continue;
                        }
                        const std::vector<std::string> origins{provenStorage};
                        const std::string originDisplay = provenStorage;

                        struct ReplyTraceState {
                            size_t summaryIndex = 0;
                            uint64_t startAddress = 0;
                            bool fromEntry = false;
                            bool derivedResult = false;
                            size_t depth = 0;
                            std::set<std::string> tainted;
                            std::set<std::string> pointers;
                        };
                        struct ReturnedState {
                            size_t summaryIndex = 0;
                            size_t depth = 0;
                        };
                        std::deque<ReplyTraceState> traceQueue;
                        traceQueue.push_back({sourceSummaryIndex, source.callsite,
                                              false, false, 0,
                                              std::set<std::string>(origins.begin(),
                                                                    origins.end()),
                                              {}});
                        std::deque<ReturnedState> returnedQueue;
                        std::unordered_set<std::string> traceVisited;
                        std::unordered_set<std::string> returnedVisited;
                        size_t helperStates = 0;
                        bool traceComplete = true;

                        auto retainSynthetic = [&]
                            (size_t sinkSummaryIndex,
                             CrackmeTriageReplyDecisionInput candidate) {
                            if (!candidate.decisionAddressValid ||
                                sinkSummaryIndex >= authorizationSummaries.size())
                                return;
                            if (candidate.comparisonAddressValid)
                                candidate.comparisonSignature =
                                    codeSignatures.capture(
                                        *dis, candidate.comparisonAddress);
                            if (candidate.decisionAddressValid)
                                candidate.decisionSignature =
                                    codeSignatures.capture(
                                        *dis, candidate.decisionAddress);
                            for (const CrackmeTriageReplyDecisionInput& existing :
                                 source.replyDecisions) {
                                if (existing.outputArgumentIndex ==
                                        candidate.outputArgumentIndex &&
                                    existing.comparisonAddressValid ==
                                        candidate.comparisonAddressValid &&
                                    (!existing.comparisonAddressValid ||
                                     existing.comparisonAddress ==
                                         candidate.comparisonAddress) &&
                                    existing.decisionAddressValid &&
                                    existing.decisionAddress ==
                                        candidate.decisionAddress)
                                    return;
                            }
                            if (source.replyDecisions.size() >= 4) {
                                traceComplete = false;
                                if (source.replyDecisionIncompleteReason.empty())
                                    source.replyDecisionIncompleteReason =
                                        "reply comparison sink cap retained the four strongest candidates";
                                return;
                            }
                            const AuthorizationFunctionSummary& sink =
                                authorizationSummaries[sinkSummaryIndex];
                            AuthorizationPathPairScan paths =
                                scanAuthorizationPathPair(
                                    *job.bin, sink.graph,
                                    candidate.decisionAddress,
                                    candidate.decisionAddressValid,
                                    candidate.decisionTarget,
                                    candidate.decisionTargetValid,
                                    candidate.fallthroughAddress,
                                    candidate.fallthroughAddressValid,
                                    sink.address, sink.name, namesByVA,
                                    stringsByVA,
                                    writeCallsitesByFunction[sink.address]);
                            AuthorizationDecisionInput decision;
                            decision.location = authorizationLocation(
                                *job.bin, candidate.decisionAddress, true,
                                sink.address, true, sink.name);
                            decision.comparison = candidate.comparisonSummary.empty()
                                ? candidate.comparisonInstruction
                                : candidate.comparisonSummary;
                            decision.takenPath = paths.taken.path;
                            decision.fallthroughPath = paths.fallthrough.path;
                            decision.evidence = candidate.evidence;
                            if (authorization.decisions.size() >=
                                authorization.limits.maxDecisions) {
                                authorization.decisionsComplete = false;
                                traceComplete = false;
                                return;
                            }
                            const size_t decisionIndex =
                                authorization.decisions.size();
                            authorization.decisions.push_back(std::move(decision));
                            authorizationReplyKeys.push_back({
                                decisionIndex, source.callsite,
                                candidate.comparisonAddressValid
                                    ? candidate.comparisonAddress : 0,
                                candidate.decisionAddress,
                                source.functionAddress});
                            for (PersistentStateOperationInput& operation :
                                 authorization.stateOperations) {
                                if (!paths.taken.path.complete ||
                                    !paths.fallthrough.path.complete) break;
                                if (operation.access != PersistentStateAccess::Write ||
                                    !operation.location.addressValid ||
                                    !operation.location.functionAddressValid ||
                                    operation.location.functionAddress != sink.address)
                                    continue;
                                const BasicBlock* owner =
                                    authorizationBlockForAddress(
                                        sink.graph, operation.location.address);
                                if (!owner) continue;
                                const bool inTaken =
                                    paths.taken.blockStarts.count(owner->start) != 0;
                                const bool inFallthrough =
                                    paths.fallthrough.blockStarts.count(owner->start) != 0;
                                if (inTaken == inFallthrough) continue;
                                operation.controllingDecisionIndex = decisionIndex;
                                operation.controllingDecisionIndexValid = true;
                                operation.controllingBranch = inTaken
                                    ? AuthorizationBranch::Taken
                                    : AuthorizationBranch::Fallthrough;
                            }
                            source.replyDecisions.push_back(std::move(candidate));
                        };

                        auto candidateForCall = [&](size_t sinkSummaryIndex,
                                                    const ApiCallObservation& call,
                                                    size_t depth,
                                                    bool derivedResult) {
                            CrackmeTriageReplyDecisionInput candidate;
                            candidate.kind = NetworkReplyDecisionKind::ComparisonCall;
                            candidate.outputArgumentIndex = output.argumentIndex;
                            candidate.outputRole = NetworkOutParameterRoleText(output.role);
                            candidate.outputExpression = originDisplay;
                            candidate.comparisonAddress = call.callVA;
                            candidate.comparisonAddressValid = call.callVAValid;
                            candidate.comparisonInstruction = "call " + call.resolvedName;
                            candidate.comparisonSummary = "reply-derived " +
                                candidate.outputRole + " reaches " + call.resolvedName +
                                "; its return controls a conditional branch";
                            candidate.decisionAddress = call.decisionVA;
                            candidate.decisionAddressValid = call.decisionVAValid;
                            candidate.decisionTarget = call.decisionTarget;
                            candidate.decisionTargetValid = call.decisionTargetValid;
                            candidate.decisionInstruction = call.decisionInstruction;
                            if (sinkSummaryIndex < authorizationSummaries.size()) {
                                const AuthorizationFunctionSummary& sink =
                                    authorizationSummaries[sinkSummaryIndex];
                                candidate.fallthroughAddress = authorizationFallthrough(
                                    sink.graph, call.decisionVA,
                                    call.decisionTarget,
                                    candidate.fallthroughAddressValid);
                            }
                            candidate.takenPathSummary =
                                "helper result takes the conditional branch";
                            candidate.fallthroughPathSummary =
                                "helper result follows the fallthrough path";
                            for (const ApiArgumentObservation& argument : call.arguments) {
                                bool isOrigin = false;
                                for (const std::string& expression :
                                     authorizationArgumentExpressions(argument))
                                    isOrigin |= authorizationExpressionTainted(
                                        expression, std::set<std::string>(
                                            origins.begin(), origins.end()));
                                if (!isOrigin && !argument.stringLiteral.empty()) {
                                    candidate.expectedValue =
                                        "\"" + argument.stringLiteral + "\"";
                                    break;
                                }
                            }
                            candidate.evidence = source.dll + "!" + source.name +
                                " writes cataloged " + candidate.outputRole +
                                "; exact expression lineage reaches a direct helper" +
                                (depth ? " at bounded depth " + std::to_string(depth)
                                       : std::string()) +
                                (derivedResult
                                    ? "; a helper-derived return value is checked"
                                    : "; the helper return controls this branch") +
                                "; helper semantics alone do not prove authorization";
                            candidate.confidence = depth <= 1 ? 0.78f : 0.68f;
                            retainSynthetic(sinkSummaryIndex, std::move(candidate));
                        };

                        auto enqueueReturnedCallers = [&](size_t returnedSummary,
                                                          size_t depth) {
                            if (depth >= kMaxHelperDepth) {
                                traceComplete = false;
                                return;
                            }
                            returnedQueue.push_back({returnedSummary, depth});
                        };

                        while ((!traceQueue.empty() || !returnedQueue.empty()) &&
                               helperStates < kMaxHelperStatesPerSource &&
                               !superseded()) {
                            while (!returnedQueue.empty() &&
                                   helperStates < kMaxHelperStatesPerSource) {
                                const ReturnedState returned = returnedQueue.front();
                                returnedQueue.pop_front();
                                const std::string returnedKey =
                                    std::to_string(returned.summaryIndex) + ':' +
                                    std::to_string(returned.depth);
                                if (!returnedVisited.insert(returnedKey).second ||
                                    returned.summaryIndex >=
                                        authorizationSummaries.size()) continue;
                                for (size_t callerIndex = 0;
                                     callerIndex < authorizationSummaries.size();
                                     ++callerIndex) {
                                    const auto& caller =
                                        authorizationSummaries[callerIndex];
                                    for (const ApiCallObservation& call :
                                         caller.annotations.apiCalls) {
                                        size_t targetSummary = 0;
                                        if (!call.targetVAValid ||
                                            !summaryForTarget(call.targetVA,
                                                              targetSummary) ||
                                            targetSummary != returned.summaryIndex)
                                            continue;
                                        if (call.resultInfluencesDecision &&
                                            call.decisionVAValid) {
                                            candidateForCall(callerIndex, call,
                                                returned.depth + 1, true);
                                            continue;
                                        }
                                        const std::vector<std::string> destinations =
                                            authorizationReturnDestinations(call);
                                        if (!destinations.empty()) {
                                            traceQueue.push_back({
                                                callerIndex, call.callVA, false, true,
                                                returned.depth + 1,
                                                std::set<std::string>(
                                                    destinations.begin(),
                                                    destinations.end()),
                                                {}});
                                        } else if (call.returnUseKind ==
                                                   ApiReturnUseKind::Returned) {
                                            enqueueReturnedCallers(
                                                callerIndex, returned.depth + 1);
                                        }
                                    }
                                }
                            }
                            if (traceQueue.empty()) continue;
                            ReplyTraceState trace =
                                std::move(traceQueue.front());
                            traceQueue.pop_front();
                            ++helperStates;
                            if (trace.summaryIndex >= authorizationSummaries.size())
                                continue;
                            std::string traceKey =
                                std::to_string(trace.summaryIndex) + ':' +
                                std::to_string(trace.startAddress) + ':' +
                                std::to_string(trace.depth) + ':' +
                                (trace.derivedResult ? "r" : "b");
                            for (const std::string& expression : trace.tainted)
                                traceKey += "|c:" + expression;
                            for (const std::string& expression : trace.pointers)
                                traceKey += "|p:" + expression;
                            if (!traceVisited.insert(std::move(traceKey)).second)
                                continue;
                            const AuthorizationFunctionSummary& summary =
                                authorizationSummaries[trace.summaryIndex];
                            size_t firstBlock = summary.graph.blocks.size();
                            for (size_t blockIndex = 0;
                                 blockIndex < summary.graph.blocks.size(); ++blockIndex) {
                                const BasicBlock& block = summary.graph.blocks[blockIndex];
                                if (trace.startAddress >= block.start &&
                                    trace.startAddress < block.end) {
                                    firstBlock = blockIndex;
                                    break;
                                }
                            }
                            if (firstBlock >= summary.graph.blocks.size()) {
                                traceComplete = false;
                                continue;
                            }
                            struct BlockTraceState {
                                size_t block = 0;
                                bool first = false;
                                std::set<std::string> tainted;
                                std::set<std::string> pointers;
                            };
                            std::deque<BlockTraceState> blocks;
                            blocks.push_back({firstBlock, true, trace.tainted,
                                              trace.pointers});
                            std::unordered_set<std::string> blockVisited;
                            size_t blockStates = 0;
                            while (!blocks.empty() &&
                                   blockStates++ < kMaxBlockStatesPerHelper) {
                                BlockTraceState state = std::move(blocks.front());
                                blocks.pop_front();
                                if (state.block >= summary.graph.blocks.size()) continue;
                                std::string blockStateKey = std::to_string(state.block);
                                for (const std::string& expression : state.tainted)
                                    blockStateKey += "|c:" + expression;
                                for (const std::string& expression : state.pointers)
                                    blockStateKey += "|p:" + expression;
                                if (!blockVisited.insert(std::move(blockStateKey)).second)
                                    continue;
                                const BasicBlock& block = summary.graph.blocks[state.block];
                                for (size_t instructionIndex = 0;
                                     instructionIndex < block.insns.size();
                                     ++instructionIndex) {
                                    const Instruction& instruction =
                                        block.insns[instructionIndex];
                                    if (state.first && !trace.fromEntry &&
                                        instruction.address <= trace.startAddress)
                                        continue;
                                    if (instruction.isRet &&
                                        state.tainted.count("rax") != 0) {
                                        // This is a proven scalar content return: unlike
                                        // passing a reply-buffer pointer, the ABI return
                                        // register itself was loaded from reply storage.
                                        enqueueReturnedCallers(trace.summaryIndex,
                                                               trace.depth);
                                    }
                                    if ((instruction.mnemonic == "cmp" ||
                                         instruction.mnemonic == "test") &&
                                        (!state.tainted.empty() ||
                                         !state.pointers.empty())) {
                                        const std::vector<std::string> operands =
                                            authorizationSplitOperands(
                                                instruction.operands);
                                        int matched = -1;
                                        for (size_t operandIndex = 0;
                                             operandIndex < operands.size(); ++operandIndex)
                                            if (authorizationReplyContentExpression(
                                                    operands[operandIndex],
                                                    state.tainted,
                                                    state.pointers)) {
                                                matched = static_cast<int>(operandIndex);
                                                break;
                                            }
                                        const Instruction* branch = matched >= 0
                                            ? authorizationNearbyConditionalBranch(
                                                block, instructionIndex)
                                            : nullptr;
                                        if (branch) {
                                            CrackmeTriageReplyDecisionInput candidate;
                                            candidate.kind =
                                                NetworkReplyDecisionKind::DirectComparison;
                                            candidate.outputArgumentIndex =
                                                output.argumentIndex;
                                            candidate.outputRole =
                                                NetworkOutParameterRoleText(output.role);
                                            candidate.outputExpression = originDisplay;
                                            candidate.comparisonAddress = instruction.address;
                                            candidate.comparisonAddressValid = true;
                                            candidate.comparisonInstruction =
                                                instruction.mnemonic + " " +
                                                instruction.operands;
                                            candidate.comparisonSummary =
                                                "reply-derived value is checked by `" +
                                                candidate.comparisonInstruction + "`";
                                            if (operands.size() == 2)
                                                candidate.expectedValue = operands[
                                                    matched == 0 ? 1 : 0];
                                            candidate.decisionAddress = branch->address;
                                            candidate.decisionAddressValid = true;
                                            candidate.decisionTarget = branch->branchTarget;
                                            candidate.decisionTargetValid =
                                                HasBranchTarget(*branch);
                                            candidate.fallthroughAddress =
                                                authorizationFallthrough(
                                                    summary.graph, branch->address,
                                                    branch->branchTarget,
                                                    candidate.fallthroughAddressValid);
                                            candidate.decisionInstruction =
                                                branch->mnemonic + " " +
                                                branch->operands;
                                            candidate.takenPathSummary =
                                                "reply-derived comparison takes the branch";
                                            candidate.fallthroughPathSummary =
                                                "reply-derived comparison follows fallthrough";
                                            candidate.evidence = source.dll + "!" +
                                                source.name + " writes cataloged " +
                                                candidate.outputRole +
                                                "; bounded direct-helper expression lineage reaches this comparison at depth " +
                                                std::to_string(trace.depth) +
                                                "; branch direction is classified only from downstream effects";
                                            candidate.confidence = trace.depth <= 1
                                                ? 0.82f : 0.70f;
                                            retainSynthetic(trace.summaryIndex,
                                                            std::move(candidate));
                                        }
                                    }

                                    if (instruction.isCall) {
                                        const ApiCallObservation* call = nullptr;
                                        for (const ApiCallObservation& candidate :
                                             summary.annotations.apiCalls)
                                            if (candidate.callVAValid &&
                                                candidate.callVA == instruction.address) {
                                                call = &candidate;
                                                break;
                                            }
                                        std::vector<size_t> taintedArguments;
                                        std::vector<size_t> contentArguments;
                                        std::vector<size_t> pointerArguments;
                                        if (call) {
                                            for (const ApiArgumentObservation& argument :
                                                 call->arguments) {
                                                bool contentArgument = false;
                                                bool pointerArgument = false;
                                                for (const std::string& expression :
                                                     authorizationArgumentExpressions(argument)) {
                                                    if (argument.sourceIsAddress) {
                                                        pointerArgument |=
                                                            state.tainted.count(expression) != 0 ||
                                                            state.pointers.count(expression) != 0 ||
                                                            authorizationExpressionUsesTaintedAddress(
                                                                expression,
                                                                state.pointers);
                                                    } else {
                                                        contentArgument |=
                                                            authorizationReplyContentExpression(
                                                                expression,
                                                                state.tainted,
                                                                state.pointers);
                                                        pointerArgument |=
                                                            state.pointers.count(expression) != 0;
                                                    }
                                                }
                                                if (pointerArgument) {
                                                    pointerArguments.push_back(argument.index);
                                                    taintedArguments.push_back(argument.index);
                                                } else if (contentArgument) {
                                                    contentArguments.push_back(argument.index);
                                                    taintedArguments.push_back(
                                                        argument.index);
                                                }
                                            }
                                        }
                                        if (call && !taintedArguments.empty()) {
                                            // A pointer-only argument proves only that the helper can
                                            // address the reply buffer.  It does not prove that an
                                            // arbitrary helper's return is derived from reply content.
                                            // Exact comparison helpers are the narrow exception because
                                            // their cataloged semantics consume the pointee bytes.
                                            const bool exactEqualityComparator =
                                                authorizationEqualityHelper(
                                                    *job.bin, *call);
                                            const bool callResultContentDerived =
                                                exactEqualityComparator &&
                                                (!contentArguments.empty() ||
                                                 !pointerArguments.empty());
                                            if (callResultContentDerived &&
                                                call->resultInfluencesDecision &&
                                                call->decisionVAValid)
                                                candidateForCall(trace.summaryIndex,
                                                    *call, trace.depth + 1,
                                                    trace.derivedResult);
                                            size_t targetSummary = 0;
                                            if (call->targetVAValid &&
                                                summaryForTarget(call->targetVA,
                                                                 targetSummary)) {
                                                if (trace.depth >= kMaxHelperDepth) {
                                                    traceComplete = false;
                                                } else {
                                                    std::set<std::string> incomingContent;
                                                    std::set<std::string> incomingPointers;
                                                    for (size_t argumentIndex : contentArguments) {
                                                        const auto values =
                                                            authorizationIncomingParameterExpressions(
                                                                argumentIndex,
                                                                job.decoder.arch == Arch::X64);
                                                        incomingContent.insert(values.begin(),
                                                                               values.end());
                                                    }
                                                    for (size_t argumentIndex : pointerArguments) {
                                                        const auto values =
                                                            authorizationIncomingParameterExpressions(
                                                                argumentIndex,
                                                                job.decoder.arch == Arch::X64);
                                                        incomingPointers.insert(values.begin(),
                                                                                values.end());
                                                    }
                                                    traceQueue.push_back({
                                                        targetSummary,
                                                        authorizationSummaries[targetSummary]
                                                            .address,
                                                        true, trace.derivedResult,
                                                        trace.depth + 1,
                                                        std::move(incomingContent),
                                                        std::move(incomingPointers)});
                                                }
                                            }
                                            if (callResultContentDerived &&
                                                call->returnUseKind ==
                                                ApiReturnUseKind::Returned)
                                                enqueueReturnedCallers(
                                                    trace.summaryIndex,
                                                    trace.depth + 1);
                                        } else if (!HasBranchTarget(instruction) &&
                                                   (authorizationReplyContentExpression(
                                                        authorizationExpressionKey(
                                                            instruction.operands),
                                                        state.tainted,
                                                        state.pointers) ||
                                                    state.pointers.count(
                                                        authorizationExpressionKey(
                                                            instruction.operands)) != 0)) {
                                            traceComplete = false;
                                        }
                                        authorizationApplyReplyLineageInstruction(
                                            instruction, state.tainted,
                                            state.pointers);
                                        if (call && !taintedArguments.empty() &&
                                            authorizationEqualityHelper(
                                                *job.bin, *call) &&
                                            (!contentArguments.empty() ||
                                             !pointerArguments.empty())) {
                                            const std::vector<std::string> destinations =
                                                authorizationReturnDestinations(*call);
                                            for (const std::string& destination : destinations) {
                                                state.pointers.erase(destination);
                                                state.tainted.insert(destination);
                                            }
                                        }
                                        continue;
                                    }
                                    authorizationApplyReplyLineageInstruction(
                                        instruction, state.tainted,
                                        state.pointers);
                                }
                                for (size_t successor : block.succ)
                                    if (successor < summary.graph.blocks.size())
                                        blocks.push_back({successor, false,
                                                          state.tainted,
                                                          state.pointers});
                            }
                            if (!blocks.empty()) traceComplete = false;
                        }
                        if (!traceQueue.empty() || !returnedQueue.empty())
                            traceComplete = false;
                        source.replyDecisionsComplete =
                            source.replyDecisionsComplete && traceComplete;
                        if (!traceComplete &&
                            source.replyDecisionIncompleteReason.empty())
                            source.replyDecisionIncompleteReason =
                                "bounded four-helper reply lineage reached an indirect call, depth, state, or sink cap";
                    }
                }
                if (!triage.apiCalls.empty() && !superseded())
                    report = RunCrackmeTriage(triage);
                for (const AuthorizationReplyDecisionKey& key : authorizationReplyKeys) {
                    if (key.decisionIndex >= authorization.decisions.size()) continue;
                    bool matched = false;
                    for (size_t flowIndex = 0;
                         flowIndex < report.replyDecisionFlows.size(); ++flowIndex) {
                        const NetworkReplyDecisionFlow& flow =
                            report.replyDecisionFlows[flowIndex];
                        if (!flow.decisionAddressValid ||
                            flow.decisionAddress != key.decision ||
                            !flow.functionAddressValid ||
                            flow.functionAddress != key.function)
                            continue;
                        if (flow.callsiteValid && flow.callsite != key.callsite) continue;
                        if (flow.comparisonAddressValid &&
                            flow.comparisonAddress != key.comparison) continue;
                        AuthorizationDecisionInput& decision =
                            authorization.decisions[key.decisionIndex];
                        decision.networkReplyFlowIndex = flowIndex;
                        decision.networkReplyFlowIndexValid = true;
                        matched = true;
                        break;
                    }
                    if (!matched) authorization.decisionsComplete = false;
                }
                if (!superseded()) {
                    report.authorization = RunAuthorizationAnalysis(authorization);

                    AuthorizationTrailInput trail;
                    trail.cancelled = superseded;
                    trail.completeness.stringAnchorsComplete =
                        report.completeness.xrefsComplete &&
                        !report.completeness.stringsTruncated &&
                        !report.completeness.endpointsTruncated &&
                        !report.completeness.routesTruncated &&
                        !report.completeness.sourcesTruncated;
                    trail.completeness.predicateCandidatesComplete =
                        triage.callEdgesComplete &&
                        triage.functionOwnershipComplete &&
                        !predicateCandidateDiscoveryTruncated;
                    trail.completeness.predicateUsesComplete =
                        trail.completeness.predicateCandidatesComplete;
                    trail.completeness.fieldAccessesComplete = true;
                    // Interprocedural secondary-gate recovery depends on the
                    // complete direct-call/ownership scope.  Individual exact
                    // relations may still be retained for review when this is
                    // false, but role promotion must fail closed.
                    trail.completeness.predicateRelationsComplete =
                        triage.callEdgesComplete &&
                        triage.functionOwnershipComplete &&
                        !candidateFunctionsTruncated;
                    trail.completeness.operationsComplete = true;
                    trail.completeness.operationGuardsComplete = true;
                    trail.completeness.stageEvidenceComplete =
                        !report.completeness.bytesTruncated &&
                        !report.completeness.stringsTruncated &&
                        !report.completeness.sourcesTruncated;
                    trail.completeness.conclusionEvidenceComplete =
                        trail.completeness.stageEvidenceComplete &&
                        report.authorization.completeness.decisionsComplete &&
                        report.authorization.completeness.pathsComplete;

                    struct AuthorizationImportIdentity {
                        std::string dll;
                        std::string name;
                    };
                    std::unordered_map<uint64_t, AuthorizationImportIdentity>
                        authorizationImports;
                    authorizationImports.reserve(job.bin->imports().size());
                    for (const auto& imported : job.bin->imports()) {
                        if (!imported.addressKnown) continue;
                        authorizationImports.emplace(imported.iatVA,
                            AuthorizationImportIdentity{imported.dll,
                                                        imported.name});
                    }
                    auto verificationFor = [&](const ApiCallObservation& call)
                        -> std::optional<VerificationApiMatch> {
                        if (call.targetVAValid) {
                            const auto imported = authorizationImports.find(
                                call.targetVA);
                            if (imported != authorizationImports.end())
                                return LookupVerificationApi(imported->second.dll,
                                                             imported->second.name);
                        }
                        return LookupVerificationApi({}, call.resolvedName);
                    };
                    auto machineIdentityFor = [&](const ApiCallObservation& call)
                        -> std::optional<MachineIdentityApiMatch> {
                        if (!call.targetVAValid) return std::nullopt;
                        const auto imported = authorizationImports.find(
                            call.targetVA);
                        if (imported == authorizationImports.end())
                            return std::nullopt;
                        return LookupMachineIdentityApi(imported->second.dll,
                                                        imported->second.name);
                    };
                    auto loaderVerificationFor = [&](const ApiCallObservation& call)
                        -> std::optional<VerificationApiMatch> {
                        if (!call.targetVAValid) return std::nullopt;
                        const auto imported = authorizationImports.find(
                            call.targetVA);
                        if (imported == authorizationImports.end())
                            return std::nullopt;
                        return LookupVerificationApi(imported->second.dll,
                                                     imported->second.name);
                    };
                    auto networkFor = [&](const ApiCallObservation& call)
                        -> std::optional<NetworkApiMatch> {
                        if (call.targetVAValid) {
                            const auto imported = authorizationImports.find(
                                call.targetVA);
                            if (imported != authorizationImports.end())
                                return LookupNetworkApi(imported->second.dll,
                                                        imported->second.name);
                        }
                        return std::nullopt;
                    };
                    auto resolveCallOwner = [&](const ApiCallObservation& call,
                                                uint64_t& owner) {
                        owner = 0;
                        if (!call.targetVAValid) return false;
                        std::string ignored;
                        return authorizationOwner(call.targetVA, owner, ignored);
                    };

                    std::unordered_map<uint64_t, size_t> trailCandidateByFunction;
                    std::unordered_map<size_t, size_t> trailSummaryByCandidate;
                    auto returnContractFor = [&](
                            const AuthorizationFunctionSummary& summary) {
                        const FunctionReturnObservation& returned =
                            summary.annotations.returnObservation;
                        switch (returned.kind) {
                        case FunctionReturnKind::CanonicalBoolean:
                        case FunctionReturnKind::MaterializedCondition:
                            return AuthorizationTrailBooleanContract::CanonicalZeroOrOne;
                        case FunctionReturnKind::FieldBackedBoolean:
                            return AuthorizationTrailBooleanContract::NonzeroIsTrue;
                        case FunctionReturnKind::ForwardedCall:
                            if (!returned.exits.empty()) {
                                const FunctionReturnExitObservation& exit =
                                    returned.exits.front();
                                ApiCallObservation forwarded;
                                forwarded.targetVA = exit.forwardedTargetVA;
                                forwarded.targetVAValid =
                                    exit.forwardedTargetVAValid;
                                forwarded.resolvedName = exit.forwardedName;
                                const auto verifier = verificationFor(forwarded);
                                if (verifier) {
                                    switch (verifier->returnRule) {
                                    case VerificationReturnRule::ZeroIsVerified:
                                        return AuthorizationTrailBooleanContract::ZeroIsTrue;
                                    case VerificationReturnRule::NonzeroIsVerified:
                                        return AuthorizationTrailBooleanContract::NonzeroIsTrue;
                                    case VerificationReturnRule::OneIsVerified:
                                        return AuthorizationTrailBooleanContract::OneIsTrue;
                                    }
                                }
                            }
                            break;
                        case FunctionReturnKind::Unknown:
                            break;
                        }
                        return AuthorizationTrailBooleanContract::Unknown;
                    };

                    for (size_t summaryIndex = 0;
                         summaryIndex < authorizationSummaries.size();
                         ++summaryIndex) {
                        const AuthorizationFunctionSummary& summary =
                            authorizationSummaries[summaryIndex];
                        const FunctionReturnObservation& returned =
                            summary.annotations.returnObservation;
                        if (!returned.complete ||
                            returned.kind == FunctionReturnKind::Unknown)
                            continue;
                        const AuthorizationTrailBooleanContract contract =
                            returnContractFor(summary);
                        if (contract == AuthorizationTrailBooleanContract::Unknown)
                            continue;
                        AuthorizationTrailPredicateCandidateInput candidate;
                        candidate.function = authorizationLocation(
                            *job.bin, summary.address, true, summary.address,
                            true, summary.name);
                        candidate.returnContract = contract;
                        candidate.returnAnalysisComplete = returned.complete;
                        candidate.sideEffectLight =
                            authorizationPredicateSideEffectLight(
                                summary.graph, summary.annotations);
                        candidate.complete = summary.graph.complete &&
                            summary.annotations.complete;
                        candidate.confidence = returned.confidence;
                        candidate.evidence = returned.evidence.empty()
                            ? std::string("all reachable returns have a typed boolean shape")
                            : returned.evidence;
                        const size_t candidateIndex =
                            trail.predicateCandidates.size();
                        trail.predicateCandidates.push_back(std::move(candidate));
                        trailCandidateByFunction[summary.address] = candidateIndex;
                        trailSummaryByCandidate[candidateIndex] = summaryIndex;
                        if (!trail.predicateCandidates.back().complete)
                            trail.completeness.predicateCandidatesComplete = false;
                    }

                    // A wrapper which returns another retained predicate
                    // unchanged inherits that predicate's truth contract. The
                    // source is still not authorization-linked until a separate
                    // control/data-flow proof below reaches it.
                    bool inherited = true;
                    for (size_t pass = 0;
                         inherited && pass < trail.predicateCandidates.size();
                         ++pass) {
                        inherited = false;
                        for (size_t summaryIndex = 0;
                             summaryIndex < authorizationSummaries.size();
                             ++summaryIndex) {
                            const AuthorizationFunctionSummary& summary =
                                authorizationSummaries[summaryIndex];
                            if (trailCandidateByFunction.count(summary.address))
                                continue;
                            const FunctionReturnObservation& returned =
                                summary.annotations.returnObservation;
                            if (!returned.complete ||
                                returned.kind != FunctionReturnKind::ForwardedCall ||
                                returned.exits.empty() ||
                                !returned.exits.front().forwardedTargetVAValid)
                                continue;
                            uint64_t owner = 0;
                            std::string ignored;
                            if (!authorizationOwner(
                                    returned.exits.front().forwardedTargetVA,
                                    owner, ignored))
                                continue;
                            const auto target = trailCandidateByFunction.find(owner);
                            if (target == trailCandidateByFunction.end()) continue;
                            AuthorizationTrailPredicateCandidateInput candidate;
                            candidate.function = authorizationLocation(
                                *job.bin, summary.address, true, summary.address,
                                true, summary.name);
                            candidate.returnContract =
                                trail.predicateCandidates[target->second]
                                    .returnContract;
                            candidate.returnAnalysisComplete = true;
                            candidate.sideEffectLight = false;
                            candidate.complete = summary.graph.complete &&
                                summary.annotations.complete;
                            candidate.confidence = returned.confidence;
                            candidate.evidence = returned.evidence +
                                "; truth contract inherited from exact forwarded predicate";
                            const size_t candidateIndex =
                                trail.predicateCandidates.size();
                            trail.predicateCandidates.push_back(std::move(candidate));
                            trailCandidateByFunction[summary.address] = candidateIndex;
                            trailSummaryByCandidate[candidateIndex] = summaryIndex;
                            inherited = true;
                        }
                    }

                    struct AuthorizationTrailUseContext {
                        size_t inputIndex = 0;
                        size_t summaryIndex = 0;
                        const ApiCallObservation* call = nullptr;
                        AuthorizationBooleanBranchDestinations destinations;
                    };
                    std::vector<AuthorizationTrailUseContext> trailUseContexts;
                    std::unordered_map<size_t, std::unordered_set<uint64_t>>
                        observedCallers;
                    for (size_t summaryIndex = 0;
                         summaryIndex < authorizationSummaries.size();
                         ++summaryIndex) {
                        const AuthorizationFunctionSummary& summary =
                            authorizationSummaries[summaryIndex];
                        for (const ApiCallObservation& call :
                             summary.annotations.apiCalls) {
                            uint64_t targetOwner = 0;
                            if (!resolveCallOwner(call, targetOwner)) continue;
                            const auto predicate =
                                trailCandidateByFunction.find(targetOwner);
                            if (predicate == trailCandidateByFunction.end()) continue;
                            AuthorizationTrailPredicateUseInput use;
                            use.predicateIndex = predicate->second;
                            use.predicateIndexValid = true;
                            use.callsite = authorizationLocation(
                                *job.bin, call.callVA, call.callVAValid,
                                summary.address, true, summary.name);
                            uint64_t continuation = 0;
                            bool continuationValid = false;
                            if (call.callVAValid) {
                                const Instruction* callInstruction =
                                    authorizationInstructionAt(summary.graph,
                                                               call.callVA);
                                continuationValid = callInstruction &&
                                    callInstruction->length != 0 &&
                                    callInstruction->address <=
                                        UINT64_MAX - callInstruction->length;
                                if (continuationValid)
                                    continuation = callInstruction->address +
                                                   callInstruction->length;
                            }
                            use.continuation = authorizationLocation(
                                *job.bin, continuation, continuationValid,
                                summary.address, true, summary.name);
                            use.caller = authorizationLocation(
                                *job.bin, summary.address, true,
                                summary.address, true, summary.name);
                            use.comparison = authorizationLocation(
                                *job.bin, call.returnUseVA,
                                call.returnUseVAValid, summary.address,
                                true, summary.name);
                            use.branch = authorizationLocation(
                                *job.bin, call.decisionVA,
                                call.decisionVAValid, summary.address,
                                true, summary.name);
                            switch (call.returnUseKind) {
                            case ApiReturnUseKind::Ignored:
                                use.useKind = AuthorizationTrailUseKind::Ignored;
                                break;
                            case ApiReturnUseKind::Compared:
                                use.useKind = AuthorizationTrailUseKind::Compared;
                                break;
                            case ApiReturnUseKind::Branched:
                                use.useKind = AuthorizationTrailUseKind::Branched;
                                break;
                            case ApiReturnUseKind::Stored:
                            case ApiReturnUseKind::Propagated:
                            case ApiReturnUseKind::Consumed:
                                use.useKind = AuthorizationTrailUseKind::Stored;
                                break;
                            case ApiReturnUseKind::Returned:
                                use.useKind = AuthorizationTrailUseKind::Returned;
                                break;
                            case ApiReturnUseKind::Unknown:
                                use.useKind = AuthorizationTrailUseKind::Unknown;
                                break;
                            }
                            const AuthorizationBooleanBranchDestinations destinations =
                                authorizationBooleanDestinations(
                                    summary.graph, call,
                                    trail.predicateCandidates[predicate->second]
                                        .returnContract);
                            use.trueDestination = authorizationLocation(
                                *job.bin, destinations.trueDestination,
                                destinations.trueDestinationValid,
                                summary.address, true, summary.name);
                            use.falseDestination = authorizationLocation(
                                *job.bin, destinations.falseDestination,
                                destinations.falseDestinationValid,
                                summary.address, true, summary.name);
                            use.resultWidthBits = destinations.comparedWidthBits
                                ? destinations.comparedWidthBits
                                : static_cast<uint8_t>((std::min<uint16_t>)(
                                      summary.annotations.returnObservation
                                          .validWidthBits,
                                      255));
                            use.flagsPreserved = destinations.trueDestinationValid;
                            use.branchUseProven = call.resultInfluencesDecision &&
                                destinations.trueDestinationValid &&
                                destinations.falseDestinationValid;
                            use.complete = summary.graph.complete &&
                                summary.annotations.complete;
                            use.confidence = call.returnUseConfidence;
                            use.evidence = call.returnUseEvidence;
                            if (use.branchUseProven) {
                                if (!use.evidence.empty()) use.evidence += "; ";
                                use.evidence +=
                                    "this function returns the boolean used by this caller to select the logical true/false paths; authorization meaning requires separate source linkage; " +
                                    destinations.evidence;
                            }
                            const size_t inputIndex = trail.predicateUses.size();
                            trail.predicateUses.push_back(std::move(use));
                            trailUseContexts.push_back({inputIndex, summaryIndex,
                                                        &call, destinations});
                            observedCallers[predicate->second].insert(
                                summary.address);
                            if (!trail.predicateUses.back().complete)
                                trail.completeness.predicateUsesComplete = false;
                        }
                    }

                    // The call graph is the fan-out ground truth. Missing a
                    // retained caller observation makes the displayed count a
                    // lower bound and prevents Global/Secondary role promotion.
                    for (const auto& [functionAddress, candidateIndex] :
                         trailCandidateByFunction) {
                        const auto expected = fanoutCallers.find(functionAddress);
                        if (expected == fanoutCallers.end()) continue;
                        const auto observed = observedCallers.find(candidateIndex);
                        for (uint64_t caller : expected->second) {
                            if (observed == observedCallers.end() ||
                                !observed->second.count(caller)) {
                                trail.completeness.predicateUsesComplete = false;
                                break;
                            }
                        }
                    }

                    auto provenAllowPathContains = [&](
                            const AuthorizationFunctionSummary& summary,
                            uint64_t address, bool addressValid,
                            bool& analysisComplete,
                            const AuthorizationFlow** matchedFlow = nullptr) {
                        analysisComplete = true;
                        if (matchedFlow) *matchedFlow = nullptr;
                        if (!addressValid) return false;
                        const BasicBlock* containing =
                            authorizationBlockForAddress(summary.graph, address);
                        if (!containing) return false;
                        const size_t containingIndex = static_cast<size_t>(
                            containing - summary.graph.blocks.data());
                        for (const AuthorizationFlow& flow :
                             report.authorization.flows) {
                            // A local key-format comparison is not an
                            // authorization source.  Promote only an exact
                            // reply-content decision, or a typed persisted
                            // entitlement read, into downstream gate lineage.
                            const bool strongAuthorizationSource =
                                flow.networkReplyFlowIndexValid ||
                                (flow.stateReadOperationIndexValid &&
                                 flow.entitlementKind !=
                                     AuthorizationEntitlementKind::Unknown);
                            if (!strongAuthorizationSource) continue;
                            if (!flow.decisionLocation.functionAddressValid ||
                                flow.decisionLocation.functionAddress !=
                                    summary.address ||
                                !flow.decisionLocation.addressValid)
                                continue;
                            const bool takenAllow =
                                flow.takenPath.outcome ==
                                    AuthorizationOutcome::LikelyAllow &&
                                flow.fallthroughPath.outcome ==
                                    AuthorizationOutcome::LikelyDeny;
                            const bool fallthroughAllow =
                                flow.fallthroughPath.outcome ==
                                    AuthorizationOutcome::LikelyAllow &&
                                flow.takenPath.outcome ==
                                    AuthorizationOutcome::LikelyDeny;
                            if (!takenAllow && !fallthroughAllow) continue;
                            const BasicBlock* decisionBlock =
                                authorizationBlockForAddress(
                                    summary.graph,
                                    flow.decisionLocation.address);
                            if (!decisionBlock) {
                                analysisComplete = false;
                                continue;
                            }
                            const size_t forbidden = static_cast<size_t>(
                                decisionBlock - summary.graph.blocks.data());
                            const AuthorizationPath& allowPath = takenAllow
                                ? flow.takenPath : flow.fallthroughPath;
                            const AuthorizationPath& denyPath = takenAllow
                                ? flow.fallthroughPath : flow.takenPath;
                            const AuthorizationReachability allowReach =
                                authorizationReachableBlocks(
                                    summary.graph, allowPath.entry.address,
                                    allowPath.entry.addressValid, forbidden, 96);
                            const AuthorizationReachability denyReach =
                                authorizationReachableBlocks(
                                    summary.graph, denyPath.entry.address,
                                    denyPath.entry.addressValid, forbidden, 96);
                            analysisComplete &= allowReach.complete &&
                                denyReach.complete && allowPath.complete &&
                                denyPath.complete && flow.provenanceComplete;
                            if (allowReach.blocks.count(containingIndex) &&
                                !denyReach.blocks.count(containingIndex) &&
                                analysisComplete) {
                                if (matchedFlow) *matchedFlow = &flow;
                                return true;
                            }
                        }
                        return false;
                    };

                    for (const AuthorizationTrailUseContext& context :
                         trailUseContexts) {
                        if (!context.call ||
                            context.inputIndex >= trail.predicateUses.size() ||
                            context.summaryIndex >= authorizationSummaries.size())
                            continue;
                        AuthorizationTrailPredicateUseInput& use =
                            trail.predicateUses[context.inputIndex];
                        bool sourcePathComplete = true;
                        if (provenAllowPathContains(
                                authorizationSummaries[context.summaryIndex],
                                context.call->callVA,
                                context.call->callVAValid,
                                sourcePathComplete)) {
                            AuthorizationTrailPredicateCandidateInput& candidate =
                                trail.predicateCandidates[use.predicateIndex];
                            candidate.authorizationSourceLinked = true;
                            if (!candidate.evidence.empty())
                                candidate.evidence += "; ";
                            candidate.evidence +=
                                "a branch-exclusive likely-allow authorization path reaches this predicate call";
                        }
                        if (!sourcePathComplete)
                            trail.completeness.predicateCandidatesComplete = false;
                    }

                    // Correlate exact formal-root fields across direct internal
                    // calls before adapting them into the trail. Displacement
                    // alone never identifies a field: the pure pass accepts
                    // only zero-bias caller-root -> callee-formal bindings and
                    // retains ambiguous/conflicting bindings as rejections.
                    struct AuthorizationFieldAccessContext {
                        size_t summaryIndex = 0;
                        size_t fieldIndex = 0;
                    };
                    AuthorizationFieldAliasInput aliasInput;
                    aliasInput.cancelled = superseded;
                    std::vector<AuthorizationFieldAccessContext>
                        aliasAccessContexts;
                    for (size_t summaryIndex = 0;
                         summaryIndex < authorizationSummaries.size();
                         ++summaryIndex) {
                        const AuthorizationFunctionSummary& summary =
                            authorizationSummaries[summaryIndex];
                        const size_t before = aliasInput.accesses.size();
                        AppendAuthorizationFieldAliasFacts(
                            aliasInput, summary.annotations);
                        const size_t appended =
                            aliasInput.accesses.size() - before;
                        aliasAccessContexts.reserve(
                            aliasAccessContexts.size() + appended);
                        for (size_t fieldIndex = 0;
                             fieldIndex < appended; ++fieldIndex)
                            aliasAccessContexts.push_back(
                                { summaryIndex, fieldIndex });
                    }
                    if (candidateFunctionsTruncated ||
                        !triage.functionOwnershipComplete) {
                        aliasInput.accessesComplete = false;
                        aliasInput.bindingsComplete = false;
                        const std::string reason = candidateFunctionsTruncated
                            ? "candidate-function scope was capped"
                            : "internal function ownership was incomplete";
                        aliasInput.accessesIncompleteReason = reason;
                        aliasInput.bindingsIncompleteReason = reason;
                    }
                    const AuthorizationFieldAliasReport aliasReport =
                        CorrelateAuthorizationFieldAliases(aliasInput);
                    trail.completeness.fieldAccessesComplete =
                        aliasReport.completeness.complete &&
                        aliasReport.completeness.accessesScopeComplete &&
                        aliasReport.completeness.bindingsScopeComplete &&
                        aliasReport.completeness.allBindingsResolved;

                    std::unordered_map<size_t,
                        const AuthorizationAcceptedFieldBinding*>
                        acceptedBindingByInput;
                    acceptedBindingByInput.reserve(
                        aliasReport.acceptedBindings.size());
                    for (const AuthorizationAcceptedFieldBinding& binding :
                         aliasReport.acceptedBindings)
                        acceptedBindingByInput[binding.inputIndex] = &binding;

                    for (const AuthorizationStableFieldIdentity& stableField :
                         aliasReport.fields) {
                        if (stableField.objectIndex >=
                            aliasReport.objects.size()) {
                            trail.completeness.fieldAccessesComplete = false;
                            continue;
                        }
                        const AuthorizationStableObjectIdentity& object =
                            aliasReport.objects[stableField.objectIndex];
                        if (!object.canonicalRoot.functionVAValid ||
                            !object.canonicalRoot.formalParameterIndexValid) {
                            trail.completeness.fieldAccessesComplete = false;
                            continue;
                        }

                        AuthorizationTrailFieldIdentity identity;
                        identity.base =
                            AuthorizationTrailFieldBaseKind::RootParameter;
                        identity.rootAddress =
                            object.canonicalRoot.functionVA;
                        identity.rootAddressValid = true;
                        identity.rootOrdinal =
                            object.canonicalRoot.formalParameterIndex;
                        identity.rootOrdinalValid = true;
                        identity.displacement = stableField.displacement;
                        identity.widthBits = stableField.widthBits;
                        identity.exact = true;
                        char fieldText[192]{};
                        const uint64_t magnitude =
                            stableField.displacement < 0
                                ? static_cast<uint64_t>(
                                      -(stableField.displacement + 1)) + 1
                                : static_cast<uint64_t>(
                                      stableField.displacement);
                        std::snprintf(fieldText, sizeof(fieldText),
                            "%s%s0x%llx (%u-bit, %zu formal alias%s)",
                            object.stableId.c_str(),
                            stableField.displacement < 0 ? "-" : "+",
                            static_cast<unsigned long long>(magnitude),
                            static_cast<unsigned>(stableField.widthBits),
                            object.aliases.size(),
                            object.aliases.size() == 1 ? "" : "es");
                        identity.display = fieldText;

                        std::vector<ValueProvenanceHop> bindingHops;
                        bindingHops.reserve(
                            object.acceptedBindingInputIndices.size());
                        for (size_t bindingIndex :
                             object.acceptedBindingInputIndices) {
                            const auto found =
                                acceptedBindingByInput.find(bindingIndex);
                            if (found == acceptedBindingByInput.end()) continue;
                            const AuthorizationFieldRootBindingInput& binding =
                                found->second->binding;
                            ValueProvenanceHop hop;
                            hop.kind = ValueProvenanceHopKind::PassArgument;
                            hop.address = binding.callVA;
                            hop.addressValid = binding.callVAValid;
                            hop.functionAddress =
                                binding.callerRoot.functionVA;
                            hop.functionAddressValid =
                                binding.callerRoot.functionVAValid;
                            const auto callerName = namesByVA.find(
                                binding.callerRoot.functionVA);
                            if (callerName != namesByVA.end())
                                hop.functionName = callerName->second;
                            hop.fromExpression = "arg" + std::to_string(
                                binding.callerRoot.formalParameterIndex + 1);
                            hop.toExpression = "arg" + std::to_string(
                                binding.calleeFormal.formalParameterIndex + 1) +
                                "@0x";
                            char calleeAddress[32]{};
                            std::snprintf(calleeAddress,
                                sizeof(calleeAddress), "%llx",
                                static_cast<unsigned long long>(
                                    binding.calleeFormal.functionVA));
                            hop.toExpression += calleeAddress;
                            hop.instruction = "direct call passes unchanged object root";
                            hop.evidence = found->second->evidence;
                            hop.confidence = binding.confidence;
                            bindingHops.push_back(std::move(hop));
                        }

                        // Provenance belongs to the stable field, not merely
                        // to the function containing a particular write.  A
                        // constructor/loader commonly writes object.active in
                        // one routine and a tiny IsPro() routine reads it. Find
                        // that exact field-backed nonzero predicate across the
                        // accepted formal-root aliases before classifying any
                        // write to the field.
                        bool stableFieldFeedsNonzeroPredicate = false;
                        for (const AuthorizationStableFieldAccess& read :
                             stableField.reads) {
                            if (read.inputIndex >=
                                aliasAccessContexts.size())
                                continue;
                            const AuthorizationFieldAccessContext& readContext =
                                aliasAccessContexts[read.inputIndex];
                            if (readContext.summaryIndex >=
                                authorizationSummaries.size())
                                continue;
                            const AuthorizationFunctionSummary& readSummary =
                                authorizationSummaries[
                                    readContext.summaryIndex];
                            const auto readCandidate =
                                trailCandidateByFunction.find(
                                    readSummary.address);
                            if (readCandidate ==
                                    trailCandidateByFunction.end() ||
                                readCandidate->second >=
                                    trail.predicateCandidates.size() ||
                                trail.predicateCandidates[
                                    readCandidate->second].returnContract !=
                                    AuthorizationTrailBooleanContract::NonzeroIsTrue)
                                continue;
                            for (const FunctionReturnExitObservation& exit :
                                 readSummary.annotations.returnObservation.exits) {
                                if (exit.fieldAccessIndexValid &&
                                    exit.fieldAccessIndex ==
                                        readContext.fieldIndex) {
                                    stableFieldFeedsNonzeroPredicate = true;
                                    break;
                                }
                            }
                            if (stableFieldFeedsNonzeroPredicate) break;
                        }

                        // Access input indices are the immutable edge identity
                        // consumed by AuthorizationTrail. Reads are retained
                        // first below, allowing each derived write to name the
                        // one exact read/predicate pair proved by the bounded
                        // temporal pass.
                        std::unordered_map<size_t, size_t>
                            trailFieldAccessByAliasInput;
                        trailFieldAccessByAliasInput.reserve(
                            stableField.reads.size() +
                            stableField.writes.size());
                        auto retainStableAccess = [&] (
                                const AuthorizationStableFieldAccess& access,
                                AuthorizationTrailFieldAccessKind accessKind) {
                            if (access.inputIndex >=
                                    aliasAccessContexts.size() ||
                                access.inputIndex >= aliasInput.accesses.size()) {
                                trail.completeness.fieldAccessesComplete = false;
                                return;
                            }
                            const AuthorizationFieldAccessContext& context =
                                aliasAccessContexts[access.inputIndex];
                            if (context.summaryIndex >=
                                authorizationSummaries.size()) {
                                trail.completeness.fieldAccessesComplete = false;
                                return;
                            }
                            const AuthorizationFunctionSummary& summary =
                                authorizationSummaries[context.summaryIndex];
                            const auto candidate =
                                trailCandidateByFunction.find(summary.address);
                            bool contributesToReturn = false;
                            if (candidate !=
                                trailCandidateByFunction.end()) {
                                for (const FunctionReturnExitObservation& exit :
                                     summary.annotations.returnObservation.exits)
                                    contributesToReturn |=
                                        exit.fieldAccessIndexValid &&
                                        exit.fieldAccessIndex ==
                                            context.fieldIndex;
                            }

                            const bool fieldPredicateIsNonzeroTrue =
                                stableFieldFeedsNonzeroPredicate;
                            const Instruction* fieldInstruction =
                                access.instructionVAValid
                                    ? authorizationInstructionAt(
                                          summary.graph,
                                          access.instructionVA)
                                    : nullptr;
                            std::string writeSourceExpression;
                            bool writesLogicalTrueConstant = false;
                            if (accessKind ==
                                    AuthorizationTrailFieldAccessKind::Write &&
                                fieldInstruction) {
                                const std::string mnemonic =
                                    authorizationLower(
                                        fieldInstruction->mnemonic);
                                const std::vector<std::string> operands =
                                    authorizationSplitOperands(
                                        fieldInstruction->operands);
                                // Only a simple, exact memory-destination MOV
                                // has one unambiguous new field value. RMW,
                                // XCHG, and text with reordered operands remain
                                // visible writes but cannot establish active=1.
                                if (mnemonic == "mov" &&
                                    access.operandIndexValid &&
                                    access.operandIndex == 0 &&
                                    operands.size() == 2) {
                                    writeSourceExpression = operands[1];
                                    AuthorizationIntegerLiteral literal;
                                    writesLogicalTrueConstant =
                                        authorizationParseInteger(
                                            writeSourceExpression, literal) &&
                                        literal.bits != 0;
                                }
                            }

                            std::vector<ValueProvenanceHop> sourceHops;
                            auto appendSourceHop = [&](ValueProvenanceHopKind kind,
                                                       uint64_t address,
                                                       bool addressValid,
                                                       std::string instruction,
                                                       std::string from,
                                                       std::string to,
                                                       std::string evidence,
                                                       float confidence) {
                                ValueProvenanceHop hop;
                                hop.kind = kind;
                                hop.address = address;
                                hop.addressValid = addressValid;
                                hop.functionAddress = summary.address;
                                hop.functionAddressValid = true;
                                hop.functionName = summary.name;
                                hop.instruction = std::move(instruction);
                                hop.fromExpression = std::move(from);
                                hop.toExpression = std::move(to);
                                hop.evidence = std::move(evidence);
                                hop.confidence = confidence;
                                sourceHops.push_back(std::move(hop));
                            };

                            bool sourcePathComplete = true;
                            bool derivedWrite = false;
                            const AuthorizationFlow* matchedFlow = nullptr;
                            if (accessKind ==
                                    AuthorizationTrailFieldAccessKind::Write &&
                                fieldPredicateIsNonzeroTrue &&
                                writesLogicalTrueConstant &&
                                provenAllowPathContains(
                                    summary, access.instructionVA,
                                    access.instructionVAValid,
                                    sourcePathComplete, &matchedFlow)) {
                                derivedWrite = true;
                                if (matchedFlow)
                                    sourceHops.insert(sourceHops.end(),
                                        matchedFlow->provenance.begin(),
                                        matchedFlow->provenance.end());
                                appendSourceHop(
                                    ValueProvenanceHopKind::Store,
                                    access.instructionVA,
                                    access.instructionVAValid,
                                    fieldInstruction
                                        ? authorizationInstructionText(
                                              *fieldInstruction)
                                        : std::string(),
                                    writeSourceExpression,
                                    identity.display,
                                    "a branch-exclusive exact reply/persisted-entitlement allow path stores a nonzero value consumed by this field-backed boolean predicate",
                                    0.92f);
                            }
                            if (!sourcePathComplete)
                                trail.completeness.fieldAccessesComplete = false;

                            // Independently recognize the requested
                            // signature-result -> status/boolean -> object
                            // field chain. A raw verifier status is accepted
                            // only for an exact nonzero-is-success contract;
                            // zero/one status APIs must first select a proven
                            // true branch which stores a nonzero field value.
                            if (!derivedWrite &&
                                accessKind ==
                                    AuthorizationTrailFieldAccessKind::Write &&
                                fieldPredicateIsNonzeroTrue &&
                                fieldInstruction) {
                                const BasicBlock* writeBlock =
                                    authorizationBlockForAddress(
                                        summary.graph,
                                        access.instructionVA);
                                const size_t writeBlockIndex = writeBlock
                                    ? static_cast<size_t>(
                                          writeBlock -
                                          summary.graph.blocks.data())
                                    : summary.graph.blocks.size();
                                for (const ApiCallObservation& call :
                                     summary.annotations.apiCalls) {
                                    const auto verifier = verificationFor(call);
                                    if (!verifier ||
                                        !verifier->directSignatureVerdict ||
                                        !call.callVAValid ||
                                        call.callVA >= access.instructionVA)
                                        continue;

                                    const bool directNonzeroResult =
                                        verifier->returnRule ==
                                            VerificationReturnRule::NonzeroIsVerified &&
                                        !writeSourceExpression.empty() &&
                                        authorizationExpressionsShareLineage(
                                            summary.graph, call.callVA,
                                            "rax", access.instructionVA,
                                            writeSourceExpression);
                                    bool verifiedTrueBranch = false;
                                    AuthorizationBooleanBranchDestinations
                                        destinations;
                                    if (!directNonzeroResult &&
                                        writesLogicalTrueConstant &&
                                        writeBlock) {
                                        AuthorizationTrailBooleanContract
                                            verifierContract =
                                                AuthorizationTrailBooleanContract::Unknown;
                                        switch (verifier->returnRule) {
                                        case VerificationReturnRule::ZeroIsVerified:
                                            verifierContract =
                                                AuthorizationTrailBooleanContract::ZeroIsTrue;
                                            break;
                                        case VerificationReturnRule::NonzeroIsVerified:
                                            verifierContract =
                                                AuthorizationTrailBooleanContract::NonzeroIsTrue;
                                            break;
                                        case VerificationReturnRule::OneIsVerified:
                                            verifierContract =
                                                AuthorizationTrailBooleanContract::OneIsTrue;
                                            break;
                                        }
                                        destinations =
                                            authorizationBooleanDestinations(
                                                summary.graph, call,
                                                verifierContract);
                                        const BasicBlock* decisionBlock =
                                            destinations.trueDestinationValid &&
                                                    destinations.falseDestinationValid &&
                                                    call.decisionVAValid
                                                ? authorizationBlockForAddress(
                                                      summary.graph,
                                                      call.decisionVA)
                                                : nullptr;
                                        if (decisionBlock) {
                                            const size_t forbidden =
                                                static_cast<size_t>(
                                                    decisionBlock -
                                                    summary.graph.blocks.data());
                                            const AuthorizationReachability truth =
                                                authorizationReachableBlocks(
                                                    summary.graph,
                                                    destinations.trueDestination,
                                                    true, forbidden, 96);
                                            const AuthorizationReachability falsity =
                                                authorizationReachableBlocks(
                                                    summary.graph,
                                                    destinations.falseDestination,
                                                    true, forbidden, 96);
                                            verifiedTrueBranch = truth.complete &&
                                                falsity.complete &&
                                                truth.blocks.count(
                                                    writeBlockIndex) &&
                                                !falsity.blocks.count(
                                                    writeBlockIndex);
                                        }
                                    }
                                    if (!directNonzeroResult &&
                                        !verifiedTrueBranch)
                                        continue;

                                    derivedWrite = true;
                                    appendSourceHop(
                                        ValueProvenanceHopKind::Origin,
                                        call.callVA, true,
                                        "call " + verifier->canonicalName,
                                        "signature/message",
                                        "rax",
                                        verifier->meaning,
                                        0.96f);
                                    if (verifiedTrueBranch) {
                                        appendSourceHop(
                                            ValueProvenanceHopKind::Compare,
                                            call.returnUseVA,
                                            call.returnUseVAValid,
                                            call.returnUseInstruction,
                                            "rax", "verification status",
                                            destinations.evidence,
                                            0.95f);
                                        appendSourceHop(
                                            ValueProvenanceHopKind::Branch,
                                            call.decisionVA,
                                            call.decisionVAValid,
                                            call.decisionInstruction,
                                            "verification status",
                                            "verified path",
                                            "the exact documented verifier result selects this branch",
                                            0.95f);
                                    }
                                    appendSourceHop(
                                        ValueProvenanceHopKind::Store,
                                        access.instructionVA, true,
                                        authorizationInstructionText(
                                            *fieldInstruction),
                                        writeSourceExpression,
                                        identity.display,
                                        directNonzeroResult
                                            ? "the exact nonzero-is-verified result reaches this field store"
                                            : "the verifier-success-only path stores the nonzero status/boolean consumed by the field-backed predicate",
                                        0.95f);
                                    break;
                                }
                            }

                            // Object identity and field displacement prove that
                            // two accesses name the same storage, but do not
                            // prove that this particular authorization-derived
                            // write is the value later observed by IsPro().  For
                            // the strong source link, require one exact sequence:
                            //
                            //   store field; ...; direct call Predicate(same root)
                            //                         Predicate: load field; ret
                            //
                            // The store and call must share one basic block,
                            // there may be no intervening call or field write,
                            // the accepted formal binding must pass the unchanged
                            // object root, and every predicate return must depend
                            // on that exact entry load.  More general lifecycle
                            // relationships stay visible as candidates rather
                            // than being promoted from spatial coincidence.
                            bool reachesPredicateRead = false;
                            size_t reachedReadAliasInputIndex = 0;
                            size_t reachedPredicateInputIndex = 0;
                            bool temporalProofScopeComplete = true;
                            if (derivedWrite &&
                                accessKind ==
                                    AuthorizationTrailFieldAccessKind::Write &&
                                access.instructionVAValid &&
                                stableField.complete && object.complete &&
                                summary.graph.complete &&
                                summary.annotations.fieldAccessesComplete &&
                                summary.annotations
                                    .directCallFormalBindingsComplete) {
                                constexpr size_t kTemporalReadScanCap = 256;
                                constexpr size_t kTemporalBindingScanCap = 256;
                                if (stableField.reads.size() >
                                        kTemporalReadScanCap ||
                                    object.acceptedBindingInputIndices.size() >
                                        kTemporalBindingScanCap) {
                                    temporalProofScopeComplete = false;
                                } else {
                                    const BasicBlock* writeBlock =
                                        authorizationBlockForAddress(
                                            summary.graph,
                                            access.instructionVA);
                                    size_t writeInstructionIndex =
                                        (std::numeric_limits<size_t>::max)();
                                    if (writeBlock) {
                                        for (size_t i = 0;
                                             i < writeBlock->insns.size(); ++i)
                                            if (writeBlock->insns[i].address ==
                                                access.instructionVA) {
                                                writeInstructionIndex = i;
                                                break;
                                            }
                                    }

                                    for (const AuthorizationStableFieldAccess& read :
                                         stableField.reads) {
                                        if (reachesPredicateRead) break;
                                        if (!read.exact ||
                                            !read.instructionVAValid ||
                                            read.inputIndex >=
                                                aliasAccessContexts.size())
                                            continue;
                                        const AuthorizationFieldAccessContext&
                                            readContext = aliasAccessContexts[
                                                read.inputIndex];
                                        if (readContext.summaryIndex >=
                                            authorizationSummaries.size()) {
                                            temporalProofScopeComplete = false;
                                            continue;
                                        }
                                        const AuthorizationFunctionSummary&
                                            readSummary = authorizationSummaries[
                                                readContext.summaryIndex];
                                        const auto readCandidate =
                                            trailCandidateByFunction.find(
                                                readSummary.address);
                                        if (readCandidate ==
                                                trailCandidateByFunction.end() ||
                                            readCandidate->second >=
                                                trail.predicateCandidates.size() ||
                                            trail.predicateCandidates[
                                                readCandidate->second]
                                                    .returnContract !=
                                                AuthorizationTrailBooleanContract::
                                                    NonzeroIsTrue)
                                            continue;
                                        if (!readSummary.graph.complete ||
                                            !readSummary.annotations.complete ||
                                            !readSummary.annotations
                                                 .fieldAccessesComplete ||
                                            !readSummary.annotations
                                                 .returnObservation.complete ||
                                            readSummary.annotations
                                                .returnObservation.exits.empty()) {
                                            temporalProofScopeComplete = false;
                                            continue;
                                        }

                                        // Every reachable return must use this
                                        // exact field access. A predicate with a
                                        // constant/alternate exit is not wholly
                                        // sourced by the stored entitlement bit.
                                        bool everyExitUsesRead = true;
                                        for (const FunctionReturnExitObservation& exit :
                                             readSummary.annotations
                                                 .returnObservation.exits)
                                            everyExitUsesRead &=
                                                exit.fieldAccessIndexValid &&
                                                exit.fieldAccessIndex ==
                                                    readContext.fieldIndex;
                                        if (!everyExitUsesRead) continue;

                                        // The predicate itself must load before
                                        // any unknown call and must not write the
                                        // same stable field anywhere in its
                                        // retained complete body.
                                        const BasicBlock* readBlock =
                                            authorizationBlockForAddress(
                                                readSummary.graph,
                                                read.instructionVA);
                                        if (!readBlock ||
                                            readBlock->start !=
                                                readSummary.address)
                                            continue;
                                        size_t readInstructionIndex =
                                            (std::numeric_limits<size_t>::max)();
                                        for (size_t i = 0;
                                             i < readBlock->insns.size(); ++i) {
                                            if (readBlock->insns[i].address ==
                                                read.instructionVA) {
                                                readInstructionIndex = i;
                                                break;
                                            }
                                        }
                                        if (readInstructionIndex ==
                                            (std::numeric_limits<size_t>::max)())
                                            continue;
                                        bool predicateClobberRisk = false;
                                        for (size_t i = 0;
                                             i < readInstructionIndex; ++i)
                                            predicateClobberRisk |=
                                                readBlock->insns[i].isCall;
                                        for (const AuthorizationStableFieldAccess&
                                                 otherWrite : stableField.writes) {
                                            if (otherWrite.inputIndex >=
                                                aliasAccessContexts.size()) {
                                                temporalProofScopeComplete = false;
                                                predicateClobberRisk = true;
                                                break;
                                            }
                                            const AuthorizationFieldAccessContext&
                                                otherContext =
                                                    aliasAccessContexts[
                                                        otherWrite.inputIndex];
                                            if (otherContext.summaryIndex ==
                                                readContext.summaryIndex) {
                                                predicateClobberRisk = true;
                                                break;
                                            }
                                        }
                                        if (predicateClobberRisk) continue;

                                        for (size_t bindingInputIndex :
                                             object.acceptedBindingInputIndices) {
                                            if (reachesPredicateRead) break;
                                            const auto accepted =
                                                acceptedBindingByInput.find(
                                                    bindingInputIndex);
                                            if (accepted ==
                                                acceptedBindingByInput.end()) {
                                                temporalProofScopeComplete = false;
                                                continue;
                                            }
                                            const AuthorizationFieldRootBindingInput&
                                                binding = accepted->second->binding;
                                            if (!AuthorizationFieldRootEquivalentExact(
                                                    binding.callerRoot,
                                                    access.observedRoot) ||
                                                !AuthorizationFieldRootEquivalentExact(
                                                    binding.calleeFormal,
                                                    read.observedRoot) ||
                                                !binding.callVAValid ||
                                                !binding.directTargetVAValid ||
                                                binding.directTargetVA !=
                                                    readSummary.address ||
                                                binding.callVA <=
                                                    access.instructionVA ||
                                                !writeBlock ||
                                                writeInstructionIndex ==
                                                    (std::numeric_limits<size_t>::max)())
                                                continue;

                                            const BasicBlock* callBlock =
                                                authorizationBlockForAddress(
                                                    summary.graph,
                                                    binding.callVA);
                                            if (callBlock != writeBlock) continue;
                                            size_t callInstructionIndex =
                                                (std::numeric_limits<size_t>::max)();
                                            for (size_t i = 0;
                                                 i < writeBlock->insns.size(); ++i)
                                                if (writeBlock->insns[i].address ==
                                                    binding.callVA) {
                                                    callInstructionIndex = i;
                                                    break;
                                                }
                                            if (callInstructionIndex <=
                                                    writeInstructionIndex ||
                                                callInstructionIndex ==
                                                    (std::numeric_limits<size_t>::max)())
                                                continue;

                                            bool clobberedBetween = false;
                                            for (size_t i =
                                                     writeInstructionIndex + 1;
                                                 i < callInstructionIndex; ++i)
                                                clobberedBetween |=
                                                    writeBlock->insns[i].isCall;
                                            for (const AuthorizationStableFieldAccess&
                                                     otherWrite : stableField.writes) {
                                                if (!otherWrite.instructionVAValid ||
                                                    otherWrite.inputIndex >=
                                                        aliasAccessContexts.size())
                                                    continue;
                                                const AuthorizationFieldAccessContext&
                                                    otherContext =
                                                        aliasAccessContexts[
                                                            otherWrite.inputIndex];
                                                if (otherContext.summaryIndex ==
                                                        context.summaryIndex &&
                                                    otherWrite.instructionVA >
                                                        access.instructionVA &&
                                                    otherWrite.instructionVA <
                                                        binding.callVA)
                                                    clobberedBetween = true;
                                            }
                                            if (clobberedBetween) continue;

                                            reachesPredicateRead = true;
                                            reachedReadAliasInputIndex =
                                                read.inputIndex;
                                            reachedPredicateInputIndex =
                                                readCandidate->second;
                                            ValueProvenanceHop pass;
                                            pass.kind =
                                                ValueProvenanceHopKind::PassArgument;
                                            pass.address = binding.callVA;
                                            pass.addressValid = true;
                                            pass.functionAddress = summary.address;
                                            pass.functionAddressValid = true;
                                            pass.functionName = summary.name;
                                            pass.instruction =
                                                "direct call passes unchanged object root";
                                            pass.fromExpression = identity.display;
                                            pass.toExpression = "arg" +
                                                std::to_string(
                                                    binding.argumentIndex + 1) +
                                                " of " + readSummary.name;
                                            pass.evidence =
                                                "the authorization-derived store and exact predicate call are ordered in one basic block with no intervening call or write";
                                            pass.confidence = 0.96f;
                                            sourceHops.push_back(std::move(pass));

                                            ValueProvenanceHop reload;
                                            reload.kind =
                                                ValueProvenanceHopKind::Reload;
                                            reload.address = read.instructionVA;
                                            reload.addressValid = true;
                                            reload.functionAddress =
                                                readSummary.address;
                                            reload.functionAddressValid = true;
                                            reload.functionName = readSummary.name;
                                            if (const Instruction* instruction =
                                                    authorizationInstructionAt(
                                                        readSummary.graph,
                                                        read.instructionVA))
                                                reload.instruction =
                                                    authorizationInstructionText(
                                                        *instruction);
                                            reload.fromExpression = identity.display;
                                            reload.toExpression = "predicate return";
                                            reload.evidence =
                                                "every retained predicate return depends on this exact entry field load, with no predicate-side field write or preceding call";
                                            reload.confidence = 0.96f;
                                            sourceHops.push_back(std::move(reload));
                                        }
                                    }
                                }
                            }
                            AuthorizationTrailFieldAccessInput input;
                            input.field = identity;
                            input.access = accessKind;
                            input.location = authorizationLocation(
                                *job.bin, access.instructionVA,
                                access.instructionVAValid, summary.address,
                                true, summary.name);
                            input.authorizationDerived = derivedWrite;
                            if (reachesPredicateRead) {
                                const auto reachedRead =
                                    trailFieldAccessByAliasInput.find(
                                        reachedReadAliasInputIndex);
                                if (reachedRead ==
                                    trailFieldAccessByAliasInput.end()) {
                                    temporalProofScopeComplete = false;
                                } else {
                                    input.reachedReadAccessInputIndex =
                                        reachedRead->second;
                                    input.reachedReadAccessInputIndexValid =
                                        true;
                                    input.reachedPredicateInputIndex =
                                        reachedPredicateInputIndex;
                                    input.reachedPredicateInputIndexValid =
                                        true;
                                }
                            }
                            input.predicateIndex = candidate !=
                                    trailCandidateByFunction.end()
                                ? candidate->second : 0;
                            input.predicateIndexValid =
                                candidate != trailCandidateByFunction.end() &&
                                contributesToReturn;
                            input.contributesToPredicateReturn =
                                input.predicateIndexValid &&
                                accessKind ==
                                    AuthorizationTrailFieldAccessKind::Read;
                            input.provenance = bindingHops;
                            input.provenance.insert(input.provenance.end(),
                                sourceHops.begin(), sourceHops.end());
                            input.complete = stableField.complete &&
                                object.complete && access.exact &&
                                summary.annotations.fieldAccessesComplete &&
                                summary.annotations
                                    .directCallFormalBindingsComplete &&
                                summary.graph.complete && sourcePathComplete &&
                                temporalProofScopeComplete;
                            input.evidence = access.evidence;
                            if (!object.stableId.empty()) {
                                if (!input.evidence.empty())
                                    input.evidence += "; ";
                                input.evidence +=
                                    "stable object root " + object.stableId;
                            }
                            if (derivedWrite) {
                                if (!input.evidence.empty())
                                    input.evidence += "; ";
                                input.evidence +=
                                    "typed authorization-result provenance reaches the stored logical-true value";
                                input.evidence += reachesPredicateRead
                                    ? "; an exact ordered clobber-free object binding carries that stored value into every return of the field predicate"
                                    : "; no exact ordered clobber-free path from this write into every predicate return was proved";
                            }
                            if (!temporalProofScopeComplete)
                                trail.completeness.fieldAccessesComplete = false;
                            const size_t trailAccessInputIndex =
                                trail.fieldAccesses.size();
                            trail.fieldAccesses.push_back(std::move(input));
                            if (!trailFieldAccessByAliasInput.emplace(
                                    access.inputIndex,
                                    trailAccessInputIndex).second)
                                trail.completeness.fieldAccessesComplete = false;
                        };
                        for (const AuthorizationStableFieldAccess& access :
                             stableField.reads)
                            retainStableAccess(
                                access,
                                AuthorizationTrailFieldAccessKind::Read);
                        for (const AuthorizationStableFieldAccess& access :
                             stableField.writes)
                            retainStableAccess(
                                access,
                                AuthorizationTrailFieldAccessKind::Write);
                    }

                    struct AuthorizationUseReachability {
                        AuthorizationReachability truth;
                        AuthorizationReachability falsity;
                        size_t forbidden = 0;
                        bool valid = false;
                    };
                    std::vector<AuthorizationUseReachability> useReachability(
                        trailUseContexts.size());
                    for (size_t contextIndex = 0;
                         contextIndex < trailUseContexts.size();
                         ++contextIndex) {
                        const AuthorizationTrailUseContext& context =
                            trailUseContexts[contextIndex];
                        if (context.inputIndex >= trail.predicateUses.size() ||
                            context.summaryIndex >= authorizationSummaries.size())
                            continue;
                        const AuthorizationTrailPredicateUseInput& use =
                            trail.predicateUses[context.inputIndex];
                        if (!use.branchUseProven ||
                            !use.trueDestination.addressValid ||
                            !use.falseDestination.addressValid ||
                            !use.branch.addressValid)
                            continue;
                        const AuthorizationFunctionSummary& summary =
                            authorizationSummaries[context.summaryIndex];
                        const BasicBlock* decision =
                            authorizationBlockForAddress(summary.graph,
                                                         use.branch.address);
                        if (!decision) {
                            trail.completeness.operationsComplete = false;
                            trail.completeness.predicateRelationsComplete = false;
                            continue;
                        }
                        AuthorizationUseReachability& reach =
                            useReachability[contextIndex];
                        reach.forbidden = static_cast<size_t>(
                            decision - summary.graph.blocks.data());
                        reach.truth = authorizationReachableBlocks(
                            summary.graph, use.trueDestination.address, true,
                            reach.forbidden, 96);
                        reach.falsity = authorizationReachableBlocks(
                            summary.graph, use.falseDestination.address, true,
                            reach.forbidden, 96);
                        reach.valid = reach.truth.complete &&
                            reach.falsity.complete && summary.graph.complete;
                        if (!reach.valid) {
                            trail.completeness.operationsComplete = false;
                            trail.completeness.operationGuardsComplete = false;
                            trail.completeness.predicateRelationsComplete = false;
                        }
                    }

                    auto cosmeticName = [](std::string name) {
                        name = authorizationLower(std::move(name));
                        return name.find("brand") != std::string::npos ||
                               name.find("title") != std::string::npos ||
                               name.find("label") != std::string::npos ||
                               name.find("banner") != std::string::npos;
                    };
                    auto cleanupName = [](std::string name) {
                        name = authorizationLower(std::move(name));
                        static constexpr std::string_view rejected[] = {
                            "free", "delete", "destroy", "close", "release",
                            "cleanup", "cookie", "fail", "error", "throw",
                            "abort"
                        };
                        for (std::string_view token : rejected)
                            if (name.find(token) != std::string::npos) return true;
                        return false;
                    };
                    auto exactProtectedImport = [&] (
                            uint64_t target, std::string& label) {
                        label.clear();
                        const auto found = authorizationImports.find(target);
                        if (found == authorizationImports.end()) return false;
                        std::string dll = authorizationLower(found->second.dll);
                        const size_t slash = dll.find_last_of("/\\");
                        if (slash != std::string::npos) dll.erase(0, slash + 1);
                        if (dll.size() > 4 &&
                            dll.compare(dll.size() - 4, 4, ".dll") == 0)
                            dll.resize(dll.size() - 4);
                        std::string name = authorizationLower(found->second.name);
                        while (!name.empty() &&
                               (name.front() == '_' || name.front() == '@'))
                            name.erase(name.begin());
                        const size_t decoration = name.find_last_of('@');
                        if (decoration != std::string::npos &&
                            decoration + 1 < name.size() &&
                            std::all_of(name.begin() +
                                    static_cast<std::ptrdiff_t>(decoration + 1),
                                name.end(), [](unsigned char value) {
                                    return std::isdigit(value) != 0;
                                }))
                            name.resize(decoration);
                        const auto oneOf = [&](
                                std::initializer_list<std::string_view> values) {
                            return std::find(values.begin(), values.end(), name) !=
                                   values.end();
                        };
                        bool protectedOperation = false;
                        // This classifier underwrites a Supported protected-
                        // operation conclusion, so the module half of the
                        // contract must be exact too.  Broad API-set prefixes
                        // are not a substitute for an enumerated DLL+symbol
                        // contract: a similarly named or future API set must
                        // stay unclassified until it is added deliberately.
                        if (dll == "kernel32" || dll == "kernelbase") {
                            protectedOperation = oneOf({
                                "writefile", "deletefilea", "deletefilew",
                                "movefilea", "movefilew", "movefileexa",
                                "movefileexw", "copyfilea", "copyfilew",
                                "copyfileexa", "copyfileexw",
                                "createprocessa", "createprocessw", "winexec",
                                "writeprocessmemory", "createremotethread",
                                "createremotethreadex", "terminateprocess"
                            });
                        } else if (dll == "advapi32") {
                            protectedOperation = oneOf({
                                "regsetvaluea", "regsetvaluew",
                                "regsetvalueexa", "regsetvalueexw",
                                "regcreatekeya", "regcreatekeyw",
                                "regcreatekeyexa", "regcreatekeyexw",
                                "createservicea", "createservicew",
                                "startservicea", "startservicew"
                            });
                        } else if (dll == "shell32") {
                            protectedOperation = oneOf({
                                "shellexecutea", "shellexecutew",
                                "shellexecuteexa", "shellexecuteexw"
                            });
                        } else if (dll == "msvcrt" || dll == "ucrtbase") {
                            protectedOperation = oneOf({
                                "fwrite", "_wfopen", "fopen", "system",
                                "_wsystem", "_spawnl", "_wspawnl",
                                "_spawnv", "_wspawnv"
                            });
                        }
                        if (!protectedOperation) return false;
                        label = dll + "!" + found->second.name;
                        return true;
                    };

                    for (size_t contextIndex = 0;
                         contextIndex < trailUseContexts.size();
                         ++contextIndex) {
                        const AuthorizationTrailUseContext& context =
                            trailUseContexts[contextIndex];
                        if (context.inputIndex >= trail.predicateUses.size() ||
                            context.summaryIndex >= authorizationSummaries.size())
                            continue;
                        const AuthorizationTrailPredicateUseInput& use =
                            trail.predicateUses[context.inputIndex];
                        const AuthorizationUseReachability& reach =
                            useReachability[contextIndex];
                        if (!use.branchUseProven || !reach.valid) continue;
                        const AuthorizationFunctionSummary& summary =
                            authorizationSummaries[context.summaryIndex];

                        const Instruction* selectedOperation = nullptr;
                        uint64_t selectedOwner = 0;
                        std::string selectedName;
                        bool selectedProtectedImport = false;
                        for (size_t blockIndex : reach.truth.blocks) {
                            if (reach.falsity.blocks.count(blockIndex) ||
                                blockIndex >= summary.graph.blocks.size())
                                continue;
                            for (const Instruction& instruction :
                                 summary.graph.blocks[blockIndex].insns) {
                                if (!instruction.isCall) continue;
                                uint64_t target = 0;
                                if (!TryGetDirectTarget(instruction, target))
                                    continue;
                                std::string protectedLabel;
                                bool protectedImport =
                                    exactProtectedImport(target,
                                                         protectedLabel);
                                if (protectedImport) {
                                    for (const PersistentStateOperation& state :
                                         report.authorization.stateOperations) {
                                        if (state.location.addressValid &&
                                            state.location.address ==
                                                instruction.address) {
                                            // A license/config write belongs in
                                            // State persistence; its side
                                            // effect alone is not a protected
                                            // feature operation.
                                            protectedImport = false;
                                            break;
                                        }
                                    }
                                }
                                if (authorizationImports.count(target)) {
                                    if (!protectedImport) continue;
                                    if (!selectedOperation ||
                                        !selectedProtectedImport ||
                                        instruction.address <
                                            selectedOperation->address) {
                                        selectedOperation = &instruction;
                                        selectedOwner = target;
                                        selectedName =
                                            std::move(protectedLabel);
                                        selectedProtectedImport = true;
                                    }
                                    continue;
                                }
                                uint64_t owner = 0;
                                std::string name;
                                if (!authorizationOwner(target, owner, name) ||
                                    trailCandidateByFunction.count(owner) ||
                                    cleanupName(name))
                                    continue;
                                if ((!selectedOperation ||
                                     (!selectedProtectedImport &&
                                    instruction.address <
                                        selectedOperation->address))) {
                                    selectedOperation = &instruction;
                                    selectedOwner = owner;
                                    selectedName = name;
                                    selectedProtectedImport = false;
                                }
                            }
                        }

                        AuthorizationTrailFeatureOperationInput operation;
                        if (selectedOperation) {
                            operation.location = authorizationLocation(
                                *job.bin, selectedOperation->address, true,
                                summary.address, true, summary.name);
                            operation.kind = selectedProtectedImport
                                ? AuthorizationTrailOperationKind::ProtectedOperation
                                : (cosmeticName(selectedName)
                                    ? AuthorizationTrailOperationKind::BrandingOrCosmetic
                                    : AuthorizationTrailOperationKind::FeatureAction);
                            operation.feature = selectedName.empty()
                                ? "gated call at " +
                                      std::to_string(selectedOwner)
                                : selectedName;
                            operation.evidence = selectedProtectedImport
                                ? "this exact DLL-qualified state-changing API call is reachable only from the proved predicate-true edge"
                                : "this direct internal call is reachable only from the proved predicate-true edge; its application semantics remain analyst-reviewable";
                            operation.confidence = selectedProtectedImport
                                ? 0.96f : 0.88f;
                        } else {
                            operation.location = use.trueDestination;
                            operation.kind =
                                AuthorizationTrailOperationKind::UserInterface;
                            operation.feature = "gated path in " + summary.name;
                            operation.evidence =
                                "the true successor is branch-exclusive, but no non-cleanup internal feature call was identified";
                            operation.confidence = 0.62f;
                        }
                        operation.complete = true;
                        const size_t operationIndex = trail.operations.size();
                        trail.operations.push_back(std::move(operation));

                        AuthorizationTrailOperationGuardInput guard;
                        guard.predicateIndex = use.predicateIndex;
                        guard.predicateIndexValid = true;
                        guard.operationIndex = operationIndex;
                        guard.operationIndexValid = true;
                        guard.location = use.branch;
                        guard.branchExclusive = true;
                        guard.permitsOperation = true;
                        guard.complete = true;
                        guard.evidence =
                            "exact boolean branch maps the predicate-true edge to this exclusive downstream path";
                        trail.operationGuards.push_back(std::move(guard));

                        if (trail.operations.back().kind ==
                                AuthorizationTrailOperationKind::FeatureAction ||
                            trail.operations.back().kind ==
                                AuthorizationTrailOperationKind::ProtectedOperation) {
                            AuthorizationTrailConclusionEvidenceInput conclusion;
                            conclusion.conclusion =
                                AuthorizationTrailConclusionKind::FeaturePermitted;
                            conclusion.kind =
                                AuthorizationTrailEvidenceKind::FeatureControl;
                            conclusion.location =
                                trail.operations.back().location;
                            conclusion.evidence =
                                trail.operations.back().evidence;
                            conclusion.confidence =
                                trail.operations.back().confidence;
                            conclusion.complete = true;
                            trail.conclusionEvidence.push_back(
                                std::move(conclusion));
                        }
                    }

                    // A secondary gate may live in a helper reached from the
                    // first predicate's logical true arm.  Compute paired
                    // true/false closures over exact direct internal calls and
                    // retain only downstream predicate uses absent from the
                    // false closure.  Function summaries are deliberately an
                    // over-approximation after a helper boundary: every block
                    // reachable from the callee entry participates.  This can
                    // reject a real relation, but cannot promote a gate merely
                    // because of a name or an unproved argument condition.
                    struct AuthorizationInterprocReachability {
                        std::vector<uint8_t> reachableUses;
                        std::vector<size_t> reachedUseIndices;
                        std::vector<std::vector<uint64_t>> callChains;
                        bool complete = true;
                    };
                    struct AuthorizationInterprocScope {
                        size_t summaryIndex = 0;
                        size_t depth = 0;
                        std::vector<size_t> blocks;
                        std::vector<uint64_t> callChain;
                    };
                    constexpr size_t kMaxSecondaryHelperDepth = 6;
                    constexpr size_t kMaxSecondarySummaries = 256;
                    constexpr size_t kMaxSecondaryCallEdges = 2048;
                    constexpr size_t kMaxSecondaryBlocksPerSummary = 128;

                    std::vector<std::vector<size_t>> useContextsBySummary(
                        authorizationSummaries.size());
                    for (size_t contextIndex = 0;
                         contextIndex < trailUseContexts.size(); ++contextIndex) {
                        if (trailUseContexts[contextIndex].summaryIndex <
                            useContextsBySummary.size())
                            useContextsBySummary[
                                trailUseContexts[contextIndex].summaryIndex]
                                .push_back(contextIndex);
                    }

                    auto executableAddress = [&](uint64_t address) {
                        for (const Section& section : job.bin->sections()) {
                            if (!section.executable ||
                                section.virtualAddress >
                                    UINT64_MAX - job.bin->imageBase())
                                continue;
                            const uint64_t begin = job.bin->imageBase() +
                                                   section.virtualAddress;
                            const uint64_t size = (std::max)(
                                section.virtualSize, section.rawSize);
                            if (size && begin <= address &&
                                address - begin < size)
                                return true;
                        }
                        return false;
                    };
                    auto addressText = [](uint64_t address) {
                        char text[32]{};
                        std::snprintf(text, sizeof(text), "0x%llx",
                            static_cast<unsigned long long>(address));
                        return std::string(text);
                    };

                    auto traverseSecondaryClosure = [&] (
                            size_t rootSummaryIndex,
                            const std::unordered_set<size_t>& rootBlocks) {
                        AuthorizationInterprocReachability result;
                        result.reachableUses.assign(
                            trailUseContexts.size(), uint8_t{0});
                        result.callChains.resize(trailUseContexts.size());
                        if (rootSummaryIndex >= authorizationSummaries.size()) {
                            result.complete = false;
                            return result;
                        }

                        AuthorizationInterprocScope root;
                        root.summaryIndex = rootSummaryIndex;
                        root.blocks.assign(rootBlocks.begin(), rootBlocks.end());
                        std::sort(root.blocks.begin(), root.blocks.end());
                        std::deque<AuthorizationInterprocScope> pending;
                        pending.push_back(std::move(root));
                        std::set<std::pair<size_t, uint64_t>> expandedEntries;
                        size_t callEdgesExamined = 0;

                        while (!pending.empty()) {
                            if (superseded()) {
                                result.complete = false;
                                break;
                            }
                            AuthorizationInterprocScope scope =
                                std::move(pending.front());
                            pending.pop_front();
                            if (scope.summaryIndex >=
                                authorizationSummaries.size()) {
                                result.complete = false;
                                continue;
                            }
                            const AuthorizationFunctionSummary& summary =
                                authorizationSummaries[scope.summaryIndex];
                            if (!summary.graph.complete ||
                                !summary.annotations.complete ||
                                summary.annotations.ownershipTruncated) {
                                result.complete = false;
                                continue;
                            }

                            for (size_t contextIndex :
                                 useContextsBySummary[scope.summaryIndex]) {
                                if (contextIndex >= trailUseContexts.size()) {
                                    result.complete = false;
                                    continue;
                                }
                                const AuthorizationTrailUseContext& context =
                                    trailUseContexts[contextIndex];
                                if (!context.call ||
                                    !context.call->callVAValid ||
                                    context.inputIndex >=
                                        trail.predicateUses.size()) {
                                    result.complete = false;
                                    continue;
                                }
                                const BasicBlock* block =
                                    authorizationBlockForAddress(
                                        summary.graph,
                                        context.call->callVA);
                                if (!block) {
                                    result.complete = false;
                                    continue;
                                }
                                const size_t blockIndex =
                                    static_cast<size_t>(
                                        block - summary.graph.blocks.data());
                                if (!std::binary_search(scope.blocks.begin(),
                                                        scope.blocks.end(),
                                                        blockIndex))
                                    continue;
                                const AuthorizationTrailPredicateUseInput& use =
                                    trail.predicateUses[context.inputIndex];
                                if (!use.complete || !use.branchUseProven ||
                                    contextIndex >= useReachability.size() ||
                                    !useReachability[contextIndex].valid) {
                                    if (use.branchUseProven)
                                        result.complete = false;
                                    continue;
                                }
                                if (!result.reachableUses[contextIndex]) {
                                    result.reachableUses[contextIndex] = 1;
                                    result.reachedUseIndices.push_back(
                                        contextIndex);
                                }
                                if (result.callChains[contextIndex].empty())
                                    result.callChains[contextIndex] =
                                        scope.callChain;
                            }

                            for (size_t blockIndex : scope.blocks) {
                                if (blockIndex >= summary.graph.blocks.size()) {
                                    result.complete = false;
                                    continue;
                                }
                                for (const Instruction& instruction :
                                     summary.graph.blocks[blockIndex].insns) {
                                    if (!instruction.isCall) continue;
                                    uint64_t target = 0;
                                    if (!TryGetDirectTarget(instruction, target)) {
                                        // An indirect call on either closure can
                                        // conceal a downstream gate.
                                        result.complete = false;
                                        continue;
                                    }
                                    if (authorizationImports.count(target) ||
                                        !executableAddress(target))
                                        continue;
                                    if (++callEdgesExamined >
                                        kMaxSecondaryCallEdges) {
                                        result.complete = false;
                                        continue;
                                    }

                                    uint64_t owner = 0;
                                    std::string ignored;
                                    if (!authorizationOwner(target, owner,
                                                            ignored)) {
                                        result.complete = false;
                                        continue;
                                    }
                                    size_t calleeSummary = 0;
                                    if (!summaryForTarget(target,
                                                          calleeSummary) ||
                                        calleeSummary >=
                                            authorizationSummaries.size()) {
                                        // The target is internal, but its
                                        // retained summary was capped or lost.
                                        result.complete = false;
                                        continue;
                                    }
                                    if (scope.depth >=
                                        kMaxSecondaryHelperDepth) {
                                        result.complete = false;
                                        continue;
                                    }
                                    const AuthorizationFunctionSummary& callee =
                                        authorizationSummaries[calleeSummary];
                                    const BasicBlock* calleeEntry =
                                        authorizationBlockForAddress(
                                            callee.graph, target);
                                    if (!callee.graph.complete ||
                                        !callee.annotations.complete ||
                                        callee.annotations.ownershipTruncated ||
                                        !calleeEntry ||
                                        calleeEntry->start != target) {
                                        result.complete = false;
                                        continue;
                                    }
                                    const auto entryKey = std::make_pair(
                                        calleeSummary, target);
                                    if (expandedEntries.count(entryKey))
                                        continue;
                                    if (expandedEntries.size() >=
                                        kMaxSecondarySummaries) {
                                        result.complete = false;
                                        continue;
                                    }
                                    const AuthorizationReachability entryReach =
                                        authorizationReachableBlocks(
                                            callee.graph, target, true,
                                            (std::numeric_limits<size_t>::max)(),
                                            kMaxSecondaryBlocksPerSummary);
                                    if (!entryReach.complete ||
                                        entryReach.blocks.empty()) {
                                        result.complete = false;
                                        continue;
                                    }

                                    AuthorizationInterprocScope next;
                                    next.summaryIndex = calleeSummary;
                                    next.depth = scope.depth + 1;
                                    next.blocks.assign(entryReach.blocks.begin(),
                                                       entryReach.blocks.end());
                                    std::sort(next.blocks.begin(),
                                              next.blocks.end());
                                    next.callChain = scope.callChain;
                                    next.callChain.push_back(
                                        instruction.address);
                                    expandedEntries.insert(entryKey);
                                    pending.push_back(std::move(next));
                                }
                            }
                        }
                        if (!pending.empty()) result.complete = false;
                        return result;
                    };

                    constexpr size_t kMaxSecondaryUpstreamUses = 512;
                    std::vector<size_t> secondaryUpstreamUses;
                    secondaryUpstreamUses.reserve((std::min)(
                        trailUseContexts.size(),
                        kMaxSecondaryUpstreamUses));
                    for (size_t contextIndex = 0;
                         contextIndex < trailUseContexts.size();
                         ++contextIndex) {
                        const AuthorizationTrailUseContext& context =
                            trailUseContexts[contextIndex];
                        if (context.inputIndex >= trail.predicateUses.size() ||
                            contextIndex >= useReachability.size() ||
                            !useReachability[contextIndex].valid ||
                            !trail.predicateUses[context.inputIndex]
                                 .branchUseProven)
                            continue;
                        secondaryUpstreamUses.push_back(contextIndex);
                    }
                    std::stable_sort(secondaryUpstreamUses.begin(),
                        secondaryUpstreamUses.end(),
                        [&](size_t left, size_t right) {
                            const size_t leftPredicate = trail.predicateUses[
                                trailUseContexts[left].inputIndex].predicateIndex;
                            const size_t rightPredicate = trail.predicateUses[
                                trailUseContexts[right].inputIndex].predicateIndex;
                            const bool leftLinked = leftPredicate <
                                    trail.predicateCandidates.size() &&
                                trail.predicateCandidates[leftPredicate]
                                    .authorizationSourceLinked;
                            const bool rightLinked = rightPredicate <
                                    trail.predicateCandidates.size() &&
                                trail.predicateCandidates[rightPredicate]
                                    .authorizationSourceLinked;
                            return leftLinked != rightLinked
                                ? leftLinked : left < right;
                        });
                    if (secondaryUpstreamUses.size() >
                        kMaxSecondaryUpstreamUses) {
                        secondaryUpstreamUses.resize(
                            kMaxSecondaryUpstreamUses);
                        trail.completeness.predicateRelationsComplete = false;
                    }

                    std::set<std::pair<size_t, size_t>> retainedRelations;
                    for (size_t upstreamIndex : secondaryUpstreamUses) {
                        const AuthorizationTrailUseContext& upstream =
                            trailUseContexts[upstreamIndex];
                        if (upstream.inputIndex >= trail.predicateUses.size() ||
                            upstream.summaryIndex >=
                                authorizationSummaries.size() ||
                            !useReachability[upstreamIndex].valid)
                            continue;
                        const AuthorizationTrailPredicateUseInput& upstreamUse =
                            trail.predicateUses[upstream.inputIndex];
                        if (!upstreamUse.branchUseProven) continue;

                        const AuthorizationInterprocReachability truth =
                            traverseSecondaryClosure(
                                upstream.summaryIndex,
                                useReachability[upstreamIndex].truth.blocks);
                        const AuthorizationInterprocReachability falsity =
                            traverseSecondaryClosure(
                                upstream.summaryIndex,
                                useReachability[upstreamIndex].falsity.blocks);
                        if (!truth.complete || !falsity.complete)
                            trail.completeness.predicateRelationsComplete =
                                false;

                        for (size_t downstreamIndex :
                             truth.reachedUseIndices) {
                            if (downstreamIndex == upstreamIndex ||
                                downstreamIndex >= truth.reachableUses.size() ||
                                downstreamIndex >= falsity.reachableUses.size() ||
                                !truth.reachableUses[downstreamIndex] ||
                                falsity.reachableUses[downstreamIndex])
                                continue;
                            const AuthorizationTrailUseContext& downstream =
                                trailUseContexts[downstreamIndex];
                            if (downstream.inputIndex >=
                                trail.predicateUses.size())
                                continue;
                            const AuthorizationTrailPredicateUseInput& downstreamUse =
                                trail.predicateUses[downstream.inputIndex];
                            if (!downstreamUse.branchUseProven ||
                                upstreamUse.predicateIndex ==
                                    downstreamUse.predicateIndex)
                                continue;
                            if (!retainedRelations.emplace(
                                    upstreamUse.predicateIndex,
                                    downstreamUse.predicateIndex).second)
                                continue;
                            if (trail.predicateRelations.size() >=
                                trail.limits.maxPredicateRelations) {
                                trail.completeness.predicateRelationsComplete =
                                    false;
                                break;
                            }

                            AuthorizationTrailPredicateRelationInput relation;
                            relation.upstreamPredicateIndex =
                                upstreamUse.predicateIndex;
                            relation.upstreamPredicateIndexValid = true;
                            relation.downstreamPredicateIndex =
                                downstreamUse.predicateIndex;
                            relation.downstreamPredicateIndexValid = true;
                            relation.location = downstreamUse.callsite;
                            relation.branchExclusive = true;
                            relation.onPermittedPath = true;
                            relation.downstreamResultRequired = true;
                            relation.complete = truth.complete &&
                                                falsity.complete;
                            relation.evidence =
                                "exact predicate branch " +
                                addressText(upstreamUse.branch.address) +
                                " reaches the downstream call only through its proved logical-true closure; the paired logical-false closure does not reach that call";
                            const std::vector<uint64_t>& chain =
                                truth.callChains[downstreamIndex];
                            if (!chain.empty()) {
                                relation.evidence += "; exact direct-internal helper chain";
                                for (uint64_t callsite : chain)
                                    relation.evidence += " -> " +
                                                         addressText(callsite);
                            }
                            relation.evidence +=
                                "; the downstream predicate return controls branch " +
                                addressText(downstreamUse.branch.address);
                            if (relation.complete &&
                                downstreamUse.predicateIndex <
                                    trail.predicateCandidates.size()) {
                                AuthorizationTrailPredicateCandidateInput& candidate =
                                    trail.predicateCandidates[
                                        downstreamUse.predicateIndex];
                                if (!candidate.evidence.empty())
                                    candidate.evidence += "; ";
                                candidate.evidence +=
                                    "secondary-path proof: " +
                                    relation.evidence;
                            }
                            trail.predicateRelations.push_back(
                                std::move(relation));
                        }
                    }

                    auto appendStage = [&trail](
                            AuthorizationTrailStageKind stage,
                            AuthorizationTrailEvidenceKind kind,
                            const AuthorizationLocation& location,
                            std::string label, std::string evidence,
                            float confidence, bool complete,
                            uint32_t order = 0) {
                        // Retain one overflow sentinel so the pure trail layer
                        // can publish an explicit truncation bit without the
                        // adapter materializing an attacker-controlled number
                        // of per-occurrence stage rows.
                        if (trail.stageEvidence.size() >
                            trail.limits.maxStageEvidence) {
                            trail.completeness.stageEvidenceComplete = false;
                            return;
                        }
                        AuthorizationTrailStageEvidenceInput input;
                        input.stage = stage;
                        input.kind = kind;
                        input.location = location;
                        input.label = std::move(label);
                        input.evidence = std::move(evidence);
                        input.confidence = confidence;
                        input.complete = complete;
                        input.orderWithinStage = order;
                        trail.stageEvidence.push_back(std::move(input));
                        if (!complete)
                            trail.completeness.stageEvidenceComplete = false;
                    };
                    auto appendConclusion = [&trail](
                            AuthorizationTrailConclusionKind conclusion,
                            AuthorizationTrailEvidenceKind kind,
                            const AuthorizationLocation& location,
                            std::string evidence, float confidence,
                            bool complete) {
                        AuthorizationTrailConclusionEvidenceInput input;
                        input.conclusion = conclusion;
                        input.kind = kind;
                        input.location = location;
                        input.evidence = std::move(evidence);
                        input.confidence = confidence;
                        input.complete = complete;
                        trail.conclusionEvidence.push_back(std::move(input));
                        if (!complete)
                            trail.completeness.conclusionEvidenceComplete = false;
                    };
                    auto literalLocation = [&](
                            const CrackmeTriageLiteralSource& source) {
                        AuthorizationLocation location;
                        location.address = source.literalAddressValid
                            ? source.literalAddress : source.address;
                        location.addressValid = source.literalAddressValid ||
                            source.addressValid;
                        location.fileOffset = source.literalFileOffset;
                        location.fileOffsetValid = source.fileOffsetValid;
                        if (location.addressValid) {
                            uint64_t owner = 0;
                            std::string name;
                            if (authorizationOwner(location.address, owner, name)) {
                                location.functionAddress = owner;
                                location.functionAddressValid = true;
                                location.functionName = std::move(name);
                            }
                        }
                        return location;
                    };

                    // Cache each retained CFG's instructions in exact code
                    // order. A literal xref can then expose the closest branch
                    // in a small window without rerunning a decoder or claiming
                    // that proximity is data-flow proof.
                    std::vector<std::vector<const Instruction*>>
                        authorizationInstructions(authorizationSummaries.size());
                    std::vector<bool> authorizationInstructionsBuilt(
                        authorizationSummaries.size(), false);
                    auto orderedInstructionsFor = [&](size_t summaryIndex)
                        -> const std::vector<const Instruction*>& {
                        std::vector<const Instruction*>& ordered =
                            authorizationInstructions[summaryIndex];
                        if (authorizationInstructionsBuilt[summaryIndex])
                            return ordered;
                        authorizationInstructionsBuilt[summaryIndex] = true;
                        for (const BasicBlock& block :
                             authorizationSummaries[summaryIndex].graph.blocks)
                            for (const Instruction& instruction : block.insns)
                                ordered.push_back(&instruction);
                        std::sort(ordered.begin(), ordered.end(),
                            [](const Instruction* left,
                               const Instruction* right) {
                                return left->address < right->address;
                            });
                        ordered.erase(std::unique(ordered.begin(), ordered.end(),
                            [](const Instruction* left,
                               const Instruction* right) {
                                return left->address == right->address;
                            }), ordered.end());
                        return ordered;
                    };
                    auto isConditionalBranch = [](const Instruction& instruction) {
                        if (instruction.flow.kind != FlowKind::None)
                            return instruction.flow.kind ==
                                FlowKind::ConditionalBranch;
                        return instruction.isBranch && !instruction.isCall &&
                            !instruction.isRet && !instruction.mnemonic.empty() &&
                            instruction.mnemonic != "jmp" &&
                            instruction.mnemonic.front() == 'j';
                    };
                    constexpr size_t kStringBranchInstructionWindow = 12;
                    constexpr uint64_t kStringBranchByteWindow = 256;
                    size_t generatedStringReferences = 0;
                    auto appendStringAnchor = [&] (
                            AuthorizationTrailStringAnchorKind kind,
                            const std::string& label,
                            const CrackmeTriageLiteralSource& source,
                            const std::string& evidence) {
                        // Retain one overflow sentinel. RunAuthorizationTrail
                        // applies its configured and hard caps deterministically.
                        if (trail.stringAnchors.size() >
                            trail.limits.maxStringAnchors) {
                            trail.completeness.stringAnchorsComplete = false;
                            return;
                        }
                        AuthorizationTrailStringAnchorInput anchor;
                        anchor.kind = kind;
                        anchor.label = label;
                        anchor.literal = source.literal;
                        anchor.source = literalLocation(source);
                        anchor.xrefScopeComplete = xrefIdx && xrefIdx->complete;
                        anchor.complete = anchor.source.addressValid ||
                                          anchor.source.fileOffsetValid;
                        anchor.complete = anchor.complete &&
                                          !source.textTruncated;
                        anchor.evidence = evidence;
                        if (source.textTruncated) {
                            trail.completeness.stringAnchorsComplete = false;
                            anchor.evidence += anchor.evidence.empty() ? "" : "; ";
                            anchor.evidence +=
                                "the extracted containing string was truncated";
                        }
                        if (!anchor.xrefScopeComplete) {
                            anchor.complete = false;
                            trail.completeness.stringAnchorsComplete = false;
                            anchor.evidence += anchor.evidence.empty() ? "" : "; ";
                            anchor.evidence += xrefIdx
                                ? std::string("whole-image xref index is partial: ") +
                                      xrefIdx->incompleteReason()
                                : "whole-image xref index is unavailable";
                        }

                        std::array<uint64_t, 2> targets{};
                        size_t targetCount = 0;
                        auto addTarget = [&](uint64_t address, bool valid) {
                            if (!valid) return;
                            for (size_t i = 0; i < targetCount; ++i)
                                if (targets[i] == address) return;
                            targets[targetCount++] = address;
                        };
                        // Code commonly takes the address of the containing
                        // URL/string rather than the parsed host/path substring,
                        // so query both exact validity-bearing coordinates.
                        addTarget(source.literalAddress,
                                  source.literalAddressValid);
                        addTarget(source.address, source.addressValid);
                        if (!targetCount) {
                            anchor.xrefScopeComplete = false;
                            anchor.complete = false;
                            trail.completeness.stringAnchorsComplete = false;
                            anchor.evidence += anchor.evidence.empty() ? "" : "; ";
                            anchor.evidence +=
                                "this file-only literal has no mapped address, so code xrefs cannot be queried";
                        }

                        std::unordered_set<uint64_t> seenReferences;
                        bool referenceCapReached = false;
                        for (size_t targetIndex = 0;
                             targetIndex < targetCount &&
                                 !referenceCapReached;
                             ++targetIndex) {
                            if (!xrefIdx) break;
                            const std::vector<uint64_t>* references =
                                xrefIdx->sources(targets[targetIndex]);
                            if (!references) continue;
                            for (uint64_t referenceAddress : *references) {
                                if (!seenReferences.insert(referenceAddress).second)
                                    continue;
                                if (anchor.references.size() >
                                        trail.limits.maxStringReferencesPerAnchor ||
                                    generatedStringReferences >
                                        trail.limits.maxStringReferences) {
                                    anchor.referencesTruncated = true;
                                    anchor.complete = false;
                                    trail.completeness.stringAnchorsComplete = false;
                                    referenceCapReached = true;
                                    break;
                                }

                                AuthorizationTrailStringReferenceInput reference;
                                uint64_t owner = 0;
                                std::string ownerName;
                                const bool owned = authorizationOwner(
                                    referenceAddress, owner, ownerName);
                                reference.reference = authorizationLocation(
                                    *job.bin, referenceAddress, true,
                                    owner, owned, ownerName);
                                if (owned) {
                                    reference.containingFunction =
                                        authorizationLocation(
                                            *job.bin, owner, true, owner,
                                            true, ownerName);
                                    reference.containingFunctionExact = true;
                                } else {
                                    reference.branchSearchComplete = false;
                                    trail.completeness.stringAnchorsComplete = false;
                                }

                                const auto summaryFound = owned
                                    ? summaryByFunction.find(owner)
                                    : summaryByFunction.end();
                                if (summaryFound == summaryByFunction.end() ||
                                    summaryFound->second >=
                                        authorizationSummaries.size()) {
                                    reference.branchSearchComplete = false;
                                    reference.evidence = owned
                                        ? "exact owner was retained, but no bounded CFG summary was available for nearby-branch search"
                                        : "the retained whole-image xref has no exact containing function in the bounded ownership scope";
                                } else {
                                    const size_t summaryIndex =
                                        summaryFound->second;
                                    const AuthorizationFunctionSummary& summary =
                                        authorizationSummaries[summaryIndex];
                                    const std::vector<const Instruction*>& ordered =
                                        orderedInstructionsFor(summaryIndex);
                                    auto position = std::lower_bound(
                                        ordered.begin(), ordered.end(),
                                        referenceAddress,
                                        [](const Instruction* instruction,
                                           uint64_t address) {
                                            return instruction->address < address;
                                        });
                                    if (position == ordered.end() ||
                                        (*position)->address != referenceAddress) {
                                        reference.branchSearchComplete = false;
                                        reference.evidence =
                                            "xref owner is exact, but the referencing instruction was absent from the bounded CFG summary";
                                    } else {
                                        const size_t origin = static_cast<size_t>(
                                            position - ordered.begin());
                                        const Instruction* nearest = nullptr;
                                        size_t nearestDistance = 0;
                                        bool nearestAfter = false;
                                        for (size_t distance = 0;
                                             distance <=
                                                 kStringBranchInstructionWindow &&
                                             !nearest;
                                             ++distance) {
                                            auto admit = [&](size_t candidate,
                                                             bool after) {
                                                if (candidate >= ordered.size() ||
                                                    !isConditionalBranch(
                                                        *ordered[candidate]))
                                                    return;
                                                const uint64_t candidateAddress =
                                                    ordered[candidate]->address;
                                                const uint64_t byteDistance =
                                                    candidateAddress >=
                                                            referenceAddress
                                                        ? candidateAddress -
                                                              referenceAddress
                                                        : referenceAddress -
                                                              candidateAddress;
                                                if (byteDistance >
                                                    kStringBranchByteWindow)
                                                    return;
                                                nearest = ordered[candidate];
                                                nearestDistance = distance;
                                                nearestAfter = after;
                                            };
                                            // A tie favors the forward branch,
                                            // matching the usual load/compare/jcc
                                            // layout while remaining explicit.
                                            if (origin <=
                                                (std::numeric_limits<size_t>::max)() -
                                                    distance)
                                                admit(origin + distance, true);
                                            if (!nearest && distance <= origin)
                                                admit(origin - distance, false);
                                        }
                                        reference.branchSearchComplete =
                                            summary.graph.complete;
                                        if (nearest) {
                                            reference.nearbyBranch =
                                                authorizationLocation(
                                                    *job.bin, nearest->address,
                                                    true, owner, true,
                                                    ownerName);
                                            reference.instructionDistance =
                                                static_cast<uint32_t>(
                                                    nearestDistance);
                                            reference.nearbyBranchAfterReference =
                                                nearestAfter;
                                            reference.nearbyByCodeOrder = true;
                                            reference.evidence =
                                                "nearest conditional branch within the bounded 12-instruction/256-byte code-order window; proximity is a navigation lead, not proof that the literal reaches the branch condition";
                                        } else {
                                            reference.evidence =
                                                "no conditional branch was retained within the bounded 12-instruction/256-byte code-order window; this is not proof that the literal is decision-irrelevant";
                                        }
                                        if (!summary.graph.complete) {
                                            trail.completeness.stringAnchorsComplete =
                                                false;
                                            reference.evidence +=
                                                "; the containing CFG is partial";
                                        }
                                    }
                                }
                                anchor.references.push_back(
                                    std::move(reference));
                                ++generatedStringReferences;
                            }
                        }
                        if (!anchor.complete || anchor.referencesTruncated)
                            trail.completeness.stringAnchorsComplete = false;
                        trail.stringAnchors.push_back(std::move(anchor));
                    };

                    // Local input remains separate from format acceptance. A
                    // comparison alone is shown as a candidate format stage;
                    // only an exact recovered constraint is allowed to support
                    // the LocalFormatValid conclusion below.
                    uint32_t inputOrder = 0;
                    for (const AuthorizationFlow& flow :
                         report.authorization.flows) {
                        if (!flow.localInputFlow) continue;
                        appendStage(
                            AuthorizationTrailStageKind::Input,
                            AuthorizationTrailEvidenceKind::InputRead,
                            flow.inputLocation,
                            flow.inputLocation.functionName.empty()
                                ? "local credential/key input"
                                : "input in " +
                                      flow.inputLocation.functionName,
                            flow.honestyLabel, flow.confidence,
                            flow.provenanceComplete, inputOrder++);
                        const AuthorizationLocation comparison =
                            flow.comparisonLocation.addressValid ||
                                    flow.comparisonLocation.fileOffsetValid
                                ? flow.comparisonLocation
                                : flow.decisionLocation;
                        std::string detail = "input reaches local comparison";
                        if (!flow.expectedValue.empty())
                            detail += " against " + flow.expectedValue;
                        appendStage(
                            AuthorizationTrailStageKind::FormatValidation,
                            AuthorizationTrailEvidenceKind::Generic,
                            comparison, "local comparison", std::move(detail),
                            flow.confidence, flow.provenanceComplete, inputOrder);
                    }

                    auto normalizedImportedCall = [&](
                            const ApiCallObservation& call,
                            std::string& dll, std::string& name) {
                        dll.clear();
                        name.clear();
                        if (!call.targetVAValid) return false;
                        const auto imported = authorizationImports.find(
                            call.targetVA);
                        if (imported == authorizationImports.end()) return false;
                        dll = authorizationLower(imported->second.dll);
                        const size_t slash = dll.find_last_of("/\\");
                        if (slash != std::string::npos) dll.erase(0, slash + 1);
                        if (dll.size() > 4 &&
                            dll.compare(dll.size() - 4, 4, ".dll") == 0)
                            dll.resize(dll.size() - 4);
                        name = authorizationLower(imported->second.name);
                        while (!name.empty() &&
                               (name.front() == '_' || name.front() == '@'))
                            name.erase(name.begin());
                        const size_t decoration = name.find_last_of('@');
                        if (decoration != std::string::npos &&
                            decoration + 1 < name.size() &&
                            std::all_of(name.begin() +
                                    static_cast<std::ptrdiff_t>(decoration + 1),
                                name.end(), [](unsigned char c) {
                                    return std::isdigit(c) != 0;
                                }))
                            name.resize(decoration);
                        return !dll.empty() && !name.empty();
                    };
                    auto knownCrt = [](const std::string& dll) {
                        return dll == "msvcrt" || dll == "ucrtbase" ||
                               dll == "kernel32" ||
                               dll.rfind("api-ms-win-crt-string-", 0) == 0 ||
                               dll.rfind("api-ms-win-crt-runtime-", 0) == 0;
                    };
                    auto sameInputLineage = [&](
                            const AuthorizationFunctionSummary& summary,
                            const AuthorizationFlow& flow,
                            const ApiCallObservation& call,
                            const ApiArgumentObservation& argument) {
                        if (!flow.inputLocation.addressValid ||
                            !call.callVAValid || flow.originExpression.empty())
                            return false;
                        const std::string destination =
                            argument.sourceExpression.empty()
                                ? argument.renderedValue
                                : argument.sourceExpression;
                        return !destination.empty() &&
                            authorizationExpressionsShareLineage(
                                summary.graph, flow.inputLocation.address,
                                flow.originExpression, call.callVA,
                                destination);
                    };
                    auto comparesLength32 = [&](
                            const AuthorizationFunctionSummary& summary,
                            const ApiCallObservation& call) {
                        if (!call.resultInfluencesDecision ||
                            !call.returnUseVAValid ||
                            !call.decisionVAValid)
                            return false;
                        const Instruction* comparison = authorizationInstructionAt(
                            summary.graph, call.returnUseVA);
                        if (!comparison ||
                            authorizationLower(comparison->mnemonic) != "cmp")
                            return false;
                        const std::vector<std::string> operands =
                            authorizationSplitOperands(comparison->operands);
                        if (operands.size() != 2) return false;
                        for (const std::string& operand : operands) {
                            AuthorizationIntegerLiteral literal;
                            if (authorizationParseInteger(operand, literal) &&
                                literal.bits == 32)
                                return true;
                        }
                        return false;
                    };
                    for (const AuthorizationFlow& flow :
                         report.authorization.flows) {
                        if (!flow.localInputFlow ||
                            !flow.decisionLocation.functionAddressValid)
                            continue;
                        const auto found = summaryByFunction.find(
                            flow.decisionLocation.functionAddress);
                        if (found == summaryByFunction.end()) continue;
                        const AuthorizationFunctionSummary& summary =
                            authorizationSummaries[found->second];
                        const ApiCallObservation* lengthCall = nullptr;
                        const ApiCallObservation* hexCall = nullptr;
                        for (const ApiCallObservation& call :
                             summary.annotations.apiCalls) {
                            std::string dll, name;
                            if (!normalizedImportedCall(call, dll, name) ||
                                !knownCrt(dll) || call.arguments.empty())
                                continue;
                            if ((name == "strlen" || name == "wcslen" ||
                                 name == "lstrlena" || name == "lstrlenw") &&
                                comparesLength32(summary, call) &&
                                sameInputLineage(summary, flow, call,
                                                 call.arguments.front()))
                                lengthCall = &call;
                            if ((name == "isxdigit" || name == "iswxdigit") &&
                                sameInputLineage(summary, flow, call,
                                                 call.arguments.front()))
                                hexCall = &call;
                        }
                        if (!lengthCall) continue;
                        const AuthorizationLocation location =
                            authorizationLocation(
                                *job.bin, lengthCall->returnUseVA,
                                lengthCall->returnUseVAValid,
                                summary.address, true, summary.name);
                        const bool hasHexPredicate = hexCall != nullptr;
                        const std::string label = hasHexPredicate
                            ? "candidate key format: 32 hexadecimal characters"
                            : "candidate key length: 32 characters";
                        const std::string evidence = hasHexPredicate
                            ? "the exact local-input lineage reaches a length == 32 branch and an exact CRT hex-digit predicate; bounded analysis did not prove that the predicate dominates every one of the 32 characters"
                            : "the exact local-input lineage reaches a length == 32 branch; a complete per-character hexadecimal constraint was not proved";
                        appendStage(
                            AuthorizationTrailStageKind::FormatValidation,
                            AuthorizationTrailEvidenceKind::FormatConstraint,
                            location, label, evidence,
                            hasHexPredicate ? 0.84f : 0.72f,
                            false, 0);
                        appendConclusion(
                            AuthorizationTrailConclusionKind::LocalFormatValid,
                            AuthorizationTrailEvidenceKind::FormatConstraint,
                            location, evidence,
                            hasHexPredicate ? 0.84f : 0.72f,
                            false);
                    }

                    // Endpoint/request evidence describes transport only. It is
                    // deliberately also the weakest ServerAccepted evidence so
                    // the conclusion card cannot confuse a request with reply
                    // acceptance.
                    uint32_t requestOrder = 0;
                    bool emittedTransportConclusion = false;
                    for (const CrackmeTriageEndpoint& endpoint :
                         report.endpoints) {
                        std::string label = endpoint.display;
                        if (!endpoint.paths.empty()) label += endpoint.paths.front();
                        const std::string evidence =
                            endpoint.honestyLabel.empty()
                                ? "endpoint/request literal is correlated with exact networking APIs"
                                : endpoint.honestyLabel;
                        const float endpointConfidence =
                            endpoint.confidence == CrackmeTriageConfidence::High
                                ? 0.9f
                                : endpoint.confidence ==
                                      CrackmeTriageConfidence::Medium
                                    ? 0.7f : 0.5f;
                        AuthorizationLocation conclusionLocation;
                        if (endpoint.sources.empty()) {
                            appendStage(
                                AuthorizationTrailStageKind::RemoteRequest,
                                AuthorizationTrailEvidenceKind::TransportOperation,
                                {}, label, evidence, endpointConfidence, false,
                                requestOrder++);
                        } else {
                            for (const CrackmeTriageLiteralSource& source :
                                 endpoint.sources) {
                                const AuthorizationLocation location =
                                    literalLocation(source);
                                if (!conclusionLocation.addressValid &&
                                    !conclusionLocation.fileOffsetValid)
                                    conclusionLocation = location;
                                appendStringAnchor(
                                    AuthorizationTrailStringAnchorKind::Endpoint,
                                    label, source,
                                    "retained endpoint literal occurrence; every retained whole-image xref is listed independently");
                                appendStage(
                                    AuthorizationTrailStageKind::RemoteRequest,
                                    AuthorizationTrailEvidenceKind::TransportOperation,
                                    location, label, evidence,
                                    endpointConfidence,
                                    !source.textTruncated,
                                    requestOrder++);
                            }
                        }
                        if (!emittedTransportConclusion) {
                            appendConclusion(
                                AuthorizationTrailConclusionKind::ServerAccepted,
                                AuthorizationTrailEvidenceKind::TransportOperation,
                                conclusionLocation,
                                "a remote request path exists; this is not evidence that the server accepted the supplied key",
                                0.45f, true);
                            emittedTransportConclusion = true;
                        }
                    }
                    for (const CrackmeTriageRoute& route : report.routes) {
                        if (route.sources.empty()) {
                            appendStage(
                                AuthorizationTrailStageKind::RemoteRequest,
                                AuthorizationTrailEvidenceKind::TransportOperation,
                                {}, route.path,
                                "request route literal correlated with the network trail",
                                0.8f, false, requestOrder++);
                            continue;
                        }
                        for (const CrackmeTriageLiteralSource& source :
                             route.sources) {
                            const AuthorizationLocation location =
                                literalLocation(source);
                            appendStringAnchor(
                                AuthorizationTrailStringAnchorKind::Route,
                                route.path, source,
                                "retained request-route literal occurrence; every retained whole-image xref is listed independently");
                            appendStage(
                                AuthorizationTrailStageKind::RemoteRequest,
                                AuthorizationTrailEvidenceKind::TransportOperation,
                                location, route.path,
                                "request route literal correlated with the network trail",
                                0.8f, !source.textTruncated,
                                requestOrder++);
                        }
                    }

                    for (const NetworkArtifact& artifact : report.artifacts) {
                        if (artifact.kind != NetworkArtifactKind::License &&
                            artifact.kind != NetworkArtifactKind::Validation &&
                            artifact.kind != NetworkArtifactKind::Authentication &&
                            artifact.kind != NetworkArtifactKind::Success &&
                            artifact.kind != NetworkArtifactKind::Failure &&
                            artifact.kind != NetworkArtifactKind::ReplyMarker)
                            continue;
                        AuthorizationTrailStringAnchorKind anchorKind =
                            AuthorizationTrailStringAnchorKind::ValidationArtifact;
                        if (artifact.kind == NetworkArtifactKind::License)
                            anchorKind =
                                AuthorizationTrailStringAnchorKind::LicenseArtifact;
                        else if (artifact.kind ==
                                 NetworkArtifactKind::Authentication)
                            anchorKind = AuthorizationTrailStringAnchorKind::AuthenticationArtifact;
                        else if (artifact.kind == NetworkArtifactKind::Success)
                            anchorKind =
                                AuthorizationTrailStringAnchorKind::SuccessArtifact;
                        else if (artifact.kind == NetworkArtifactKind::Failure)
                            anchorKind =
                                AuthorizationTrailStringAnchorKind::FailureArtifact;
                        else if (artifact.kind ==
                                 NetworkArtifactKind::ReplyMarker)
                            anchorKind = AuthorizationTrailStringAnchorKind::ReplyMarkerArtifact;
                        const std::string evidence =
                            artifact.honestyLabel.empty()
                                ? "authorization-related literal; parsing/data flow is not yet proved"
                                : artifact.honestyLabel;
                        const float artifactConfidence =
                            artifact.confidence == CrackmeTriageConfidence::High
                                ? 0.85f : 0.6f;
                        if (artifact.sources.empty()) {
                            appendStage(
                                AuthorizationTrailStageKind::EntitlementParsing,
                                AuthorizationTrailEvidenceKind::Generic,
                                {}, artifact.value, evidence,
                                artifactConfidence, false, 0);
                            continue;
                        }
                        for (const CrackmeTriageLiteralSource& source :
                             artifact.sources) {
                            const AuthorizationLocation location =
                                literalLocation(source);
                            appendStringAnchor(
                                anchorKind, artifact.value, source,
                                "retained authorization-artifact literal occurrence; every retained whole-image xref is listed independently");
                            appendStage(
                                AuthorizationTrailStageKind::EntitlementParsing,
                                AuthorizationTrailEvidenceKind::Generic,
                                location, artifact.value, evidence,
                                artifactConfidence,
                                !source.textTruncated, 0);
                        }
                    }

                    for (const AuthorizationFlow& flow :
                         report.authorization.flows) {
                        if (!flow.networkReplyFlowIndexValid) continue;
                        const bool asymmetric =
                            (flow.takenPath.outcome ==
                                 AuthorizationOutcome::LikelyAllow &&
                             flow.fallthroughPath.outcome ==
                                 AuthorizationOutcome::LikelyDeny) ||
                            (flow.fallthroughPath.outcome ==
                                 AuthorizationOutcome::LikelyAllow &&
                             flow.takenPath.outcome ==
                                 AuthorizationOutcome::LikelyDeny);
                        const bool complete = asymmetric &&
                            flow.provenanceComplete &&
                            flow.takenPath.complete &&
                            flow.fallthroughPath.complete;
                        const AuthorizationLocation location =
                            flow.comparisonLocation.addressValid
                                ? flow.comparisonLocation
                                : flow.decisionLocation;
                        if (complete) {
                            appendStage(
                                AuthorizationTrailStageKind::EntitlementParsing,
                                AuthorizationTrailEvidenceKind::ReplyContentAcceptance,
                                location, "reply-content authorization decision",
                                flow.honestyLabel, flow.confidence, true, 1);
                            appendConclusion(
                                AuthorizationTrailConclusionKind::ServerAccepted,
                                AuthorizationTrailEvidenceKind::ReplyContentAcceptance,
                                location,
                                "network reply contents reach an asymmetric likely-allow/likely-deny application branch",
                                flow.confidence, true);
                        }
                    }

                    std::unordered_set<size_t> linkedStateOperations;
                    for (const AuthorizationFlow& flow :
                         report.authorization.flows) {
                        for (size_t index : flow.linkedStateWriteIndices)
                            linkedStateOperations.insert(index);
                        for (size_t index : flow.linkedStartupReadIndices)
                            linkedStateOperations.insert(index);
                    }
                    for (size_t index = 0;
                         index < report.authorization.stateOperations.size();
                         ++index) {
                        const PersistentStateOperation& operation =
                            report.authorization.stateOperations[index];
                        const bool exactLinked = operation.operationComplete &&
                            operation.identity.exact &&
                            linkedStateOperations.count(index) != 0;
                        appendStage(
                            AuthorizationTrailStageKind::StatePersistence,
                            exactLinked
                                ? AuthorizationTrailEvidenceKind::PersistentState
                                : AuthorizationTrailEvidenceKind::Generic,
                            operation.location,
                            operation.identity.display.empty()
                                ? std::string(PersistentStateAccessText(
                                      operation.access)) +
                                      " persistent-state candidate"
                                : operation.identity.display,
                            operation.evidence, exactLinked ? 0.92f : 0.55f,
                            operation.operationComplete, 0);
                    }

                    // Exact machine-identity APIs are capability evidence at
                    // the callsite, never proof of a machine-bound license by
                    // themselves. Supported evidence is deliberately narrow:
                    // an exact loader-backed API must write a fixed-size direct
                    // output through a decoder-proved address, its exact ABI
                    // success arm must exclusively reach a loader-backed direct
                    // signature verifier, and the unchanged address plus exact
                    // extent must reach that verifier's message argument. The
                    // verifier's documented success arm must then exclusively
                    // reach an exact protected operation while already on a
                    // strong authorization allow path. Any missing CFG,
                    // ownership, annotation, or bounded-lineage scope prevents
                    // MachineIdentityFlow from being published.
                    auto observedArgument = [](
                            const ApiCallObservation& call,
                            uint8_t index) -> const ApiArgumentObservation* {
                        const auto found = std::find_if(
                            call.arguments.begin(), call.arguments.end(),
                            [&](const ApiArgumentObservation& argument) {
                                return argument.index == index;
                            });
                        return found == call.arguments.end() ? nullptr : &*found;
                    };
                    auto directRequestPayloadArgument = [](
                            const NetworkApiMatch& network)
                            -> std::optional<uint8_t> {
                        // Composite WSABUF/INTERNET_BUFFERS and file-handle
                        // transports are deliberately omitted: the current
                        // expression model cannot prove their nested payload.
                        if (network.normalizedName == "send" ||
                            network.normalizedName == "sendto" ||
                            network.normalizedName == "winhttpwritedata" ||
                            network.normalizedName == "internetwritefile")
                            return 1;
                        if (network.normalizedName == "winhttpsendrequest")
                            return 3; // lpOptional; argument 4 is its byte count
                        if (network.normalizedName == "httpsendrequest")
                            return 3;
                        return std::nullopt;
                    };
                    struct MachineAddressIdentity {
                        std::string baseRegister;
                        int64_t displacement = 0;
                        bool valid = false;
                    };
                    struct MachineArmOwnership {
                        AuthorizationBooleanBranchDestinations branch;
                        size_t decisionBlock =
                            (std::numeric_limits<size_t>::max)();
                        bool proved = false;
                        bool scopeComplete = true;
                    };
                    struct MachineLineageResult {
                        bool proved = false;
                        bool scopeComplete = true;
                    };
                    struct MachineAuthorizationSink {
                        const Instruction* operation = nullptr;
                        std::string operationLabel;
                        bool proved = false;
                        bool scopeComplete = true;
                    };
                    auto stableMachineAddressBase = [](std::string value) {
                        value = authorizationExpressionKey(std::move(value));
                        static constexpr std::string_view stable[] = {
                            "rsp", "rbp", "rbx", "rsi", "rdi",
                            "r12", "r13", "r14", "r15"
                        };
                        return std::find(std::begin(stable), std::end(stable),
                                         value) != std::end(stable);
                    };
                    auto instructionWritesRegister = [&] (
                            const Instruction& instruction,
                            std::string_view wanted) {
                        for (const std::string& name :
                             instruction.registersWritten)
                            if (authorizationExpressionKey(name) == wanted)
                                return true;
                        for (const TypedOperand& operand :
                             instruction.typedOperands)
                            if (operand.kind == OperandKind::Register &&
                                OperandWrites(operand.access) &&
                                authorizationExpressionKey(
                                    operand.registerName) == wanted)
                                return true;
                        const std::vector<std::string> operands =
                            authorizationSplitOperands(instruction.operands);
                        if (operands.empty() || operands.front() != wanted)
                            return false;
                        const std::string mnemonic =
                            authorizationLower(instruction.mnemonic);
                        return mnemonic == "mov" || mnemonic == "movzx" ||
                            mnemonic == "movsx" || mnemonic == "movsxd" ||
                            mnemonic == "lea" || mnemonic == "xor" ||
                            mnemonic == "sub" || mnemonic == "add" ||
                            mnemonic == "and" || mnemonic == "or" ||
                            mnemonic == "pop";
                    };
                    auto exactAddressArgument = [&] (
                            const AuthorizationFunctionSummary& summary,
                            const ApiCallObservation& call,
                            const ApiArgumentObservation* argument) {
                        MachineAddressIdentity result;
                        if (job.decoder.arch != Arch::X64 || !argument ||
                            !argument->sourceIsAddress ||
                            argument->abiLocation.empty() || !call.callVAValid)
                            return result;
                        const std::string argumentRegister =
                            authorizationExpressionKey(argument->abiLocation);
                        if (authorizationRegisterWidthBits(argumentRegister) !=
                            64)
                            return result;
                        const BasicBlock* block = authorizationBlockForAddress(
                            summary.graph, call.callVA);
                        if (!block) return result;
                        size_t callIndex = block->insns.size();
                        for (size_t i = 0; i < block->insns.size(); ++i)
                            if (block->insns[i].address == call.callVA) {
                                callIndex = i;
                                break;
                            }
                        if (callIndex >= block->insns.size()) return result;
                        for (size_t cursor = callIndex; cursor-- > 0;) {
                            const Instruction& producer = block->insns[cursor];
                            if (!instructionWritesRegister(
                                    producer, argumentRegister))
                                continue;
                            if (authorizationLower(producer.mnemonic) != "lea" ||
                                producer.typedOperands.size() < 2)
                                return result;
                            const TypedOperand& destination =
                                producer.typedOperands[0];
                            const TypedOperand& source = producer.typedOperands[1];
                            if (destination.kind != OperandKind::Register ||
                                authorizationExpressionKey(
                                    destination.registerName) !=
                                    argumentRegister ||
                                source.kind != OperandKind::Memory ||
                                !source.segmentRegister.empty() ||
                                !source.indexRegister.empty() ||
                                source.pcRelative ||
                                !source.displacementValid ||
                                !stableMachineAddressBase(source.baseRegister))
                                return result;
                            const std::string observed =
                                authorizationExpressionKey(
                                    argument->sourceExpression.empty()
                                        ? argument->renderedValue
                                        : argument->sourceExpression);
                            const std::string decoded =
                                authorizationExpressionKey(
                                    authorizationRawOperand(
                                        producer.operands, 1));
                            if (observed.empty() || decoded.empty() ||
                                observed != decoded)
                                return result;
                            result.baseRegister = authorizationExpressionKey(
                                source.baseRegister);
                            result.displacement = source.displacement;
                            result.valid = true;
                            return result;
                        }
                        return result;
                    };
                    auto exactMachineOutputBytes = [](
                            const MachineIdentityApiOutput& output)
                            -> std::optional<size_t> {
                        // The catalog currently has one fixed-width directly
                        // written scalar: a DWORD volume serial. Text buffers
                        // require a post-call count proof, structure members
                        // require member/length lineage, and firmware bytes use
                        // a return count. Those intentionally remain Candidate.
                        if (output.extent ==
                                MachineIdentityOutputExtent::FixedWidthScalar &&
                            output.encoding ==
                                MachineIdentityDataEncoding::Unsigned32)
                            return 4;
                        return std::nullopt;
                    };
                    auto machineSuccessOwns = [&] (
                            const AuthorizationFunctionSummary& summary,
                            const ApiCallObservation& source,
                            const MachineIdentityApiMatch& machine,
                            uint64_t sinkAddress) {
                        MachineArmOwnership result;
                        if (!summary.graph.complete ||
                            !summary.annotations.complete ||
                            summary.annotations.ownershipTruncated) {
                            result.scopeComplete = false;
                            return result;
                        }
                        if (!source.callVAValid || sinkAddress <= source.callVA ||
                            !source.resultInfluencesDecision ||
                            !source.returnUseVAValid ||
                            !source.decisionVAValid ||
                            !(source.callVA < source.returnUseVA &&
                              source.returnUseVA < source.decisionVA &&
                              source.decisionVA < sinkAddress))
                            return result;
                        AuthorizationTrailBooleanContract contract =
                            AuthorizationTrailBooleanContract::Unknown;
                        switch (machine.returnRule) {
                        case MachineIdentityReturnRule::NonzeroBoolIsSuccess:
                            contract = AuthorizationTrailBooleanContract::NonzeroIsTrue;
                            break;
                        case MachineIdentityReturnRule::ZeroErrorCodeIsSuccess:
                            contract = AuthorizationTrailBooleanContract::ZeroIsTrue;
                            break;
                        case MachineIdentityReturnRule::ByteCountOrRequiredSize:
                            // A positive firmware-table result can be only the
                            // required-size query.  No supported output flow is
                            // formed without a runtime buffer/capacity proof.
                            return result;
                        }
                        result.branch =
                            authorizationBooleanDestinations(
                                summary.graph, source, contract);
                        // Every catalogued Win32 machine API returns a 32-bit
                        // BOOL, DWORD, or LONG status even under the x64 ABI.
                        if (!result.branch.complete ||
                            !result.branch.trueDestinationValid ||
                            !result.branch.falseDestinationValid ||
                            result.branch.comparedWidthBits != 32)
                            return result;
                        const BasicBlock* sink = authorizationBlockForAddress(
                            summary.graph, sinkAddress);
                        const BasicBlock* decision =
                            authorizationBlockForAddress(
                                summary.graph, source.decisionVA);
                        if (!sink || !decision) {
                            result.scopeComplete = false;
                            return result;
                        }
                        const size_t sinkBlock = static_cast<size_t>(
                            sink - summary.graph.blocks.data());
                        result.decisionBlock = static_cast<size_t>(
                            decision - summary.graph.blocks.data());
                        constexpr size_t kMachineReachabilityBlocks = 128;
                        const AuthorizationReachability success =
                            authorizationReachableBlocks(
                                summary.graph, result.branch.trueDestination,
                                true, result.decisionBlock,
                                kMachineReachabilityBlocks);
                        const AuthorizationReachability failure =
                            authorizationReachableBlocks(
                                summary.graph, result.branch.falseDestination,
                                true, result.decisionBlock,
                                kMachineReachabilityBlocks);
                        result.scopeComplete = success.complete && failure.complete;
                        result.proved = result.scopeComplete &&
                            success.blocks.count(sinkBlock) != 0 &&
                            failure.blocks.count(sinkBlock) == 0;
                        return result;
                    };
                    auto exactMemoryWritePreserves = [&] (
                            const Instruction& instruction,
                            const MachineAddressIdentity& storage,
                            size_t storageBytes) {
                        bool sawTypedMemoryWrite = false;
                        for (const TypedOperand& operand :
                             instruction.typedOperands) {
                            if (operand.kind != OperandKind::Memory ||
                                !OperandWrites(operand.access))
                                continue;
                            sawTypedMemoryWrite = true;
                            if (!operand.segmentRegister.empty() ||
                                !operand.indexRegister.empty() ||
                                operand.pcRelative ||
                                !operand.displacementValid ||
                                !operand.widthBits ||
                                (operand.widthBits % 8) != 0 ||
                                authorizationExpressionKey(
                                    operand.baseRegister) !=
                                    storage.baseRegister)
                                return false;
                            const uint64_t bytes = operand.widthBits / 8;
                            if (!bytes || bytes >
                                    static_cast<uint64_t>(INT64_MAX) ||
                                operand.displacement >
                                    INT64_MAX - static_cast<int64_t>(bytes) ||
                                storage.displacement >
                                    INT64_MAX -
                                        static_cast<int64_t>(storageBytes))
                                return false;
                            const int64_t writeEnd = operand.displacement +
                                static_cast<int64_t>(bytes);
                            const int64_t storageEnd = storage.displacement +
                                static_cast<int64_t>(storageBytes);
                            if (operand.displacement < storageEnd &&
                                storage.displacement < writeEnd)
                                return false;
                        }
                        if (sawTypedMemoryWrite) return true;
                        if (instruction.isRepString) return false;
                        const std::vector<std::string> operands =
                            authorizationSplitOperands(instruction.operands);
                        const std::string mnemonic =
                            authorizationLower(instruction.mnemonic);
                        if (!operands.empty() &&
                            operands.front().find('[') != std::string::npos &&
                            mnemonic != "cmp" && mnemonic != "test" &&
                            mnemonic != "lea")
                            return false;
                        return true;
                    };
                    auto machineAddressMustReach = [&] (
                            const AuthorizationFunctionSummary& summary,
                            const MachineArmOwnership& ownership,
                            const MachineAddressIdentity& storage,
                            size_t storageBytes, uint64_t sinkAddress) {
                        MachineLineageResult result;
                        if (!ownership.proved || !ownership.scopeComplete ||
                            !storage.valid || !storageBytes ||
                            !summary.graph.complete ||
                            ownership.decisionBlock >=
                                summary.graph.blocks.size()) {
                            result.scopeComplete = ownership.scopeComplete &&
                                summary.graph.complete;
                            return result;
                        }
                        const BasicBlock* first = authorizationBlockForAddress(
                            summary.graph, ownership.branch.trueDestination);
                        if (!first) {
                            result.scopeComplete = false;
                            return result;
                        }
                        struct State { size_t block = 0; bool dirty = false; };
                        std::deque<State> queue;
                        queue.push_back({static_cast<size_t>(
                            first - summary.graph.blocks.data()), false});
                        std::unordered_set<size_t> visited;
                        bool cleanReached = false;
                        bool dirtyReached = false;
                        constexpr size_t kMachineLineageStates = 128;
                        size_t states = 0;
                        while (!queue.empty()) {
                            if (states++ >= kMachineLineageStates) {
                                result.scopeComplete = false;
                                break;
                            }
                            State state = queue.front();
                            queue.pop_front();
                            if (state.block >= summary.graph.blocks.size()) {
                                result.scopeComplete = false;
                                continue;
                            }
                            const size_t key = state.block * 2u +
                                static_cast<size_t>(state.dirty);
                            if (!visited.insert(key).second) continue;
                            if (state.block == ownership.decisionBlock) continue;
                            const BasicBlock& block =
                                summary.graph.blocks[state.block];
                            bool reachedSink = false;
                            for (const Instruction& instruction : block.insns) {
                                if (state.block == static_cast<size_t>(
                                        first - summary.graph.blocks.data()) &&
                                    instruction.address <
                                        ownership.branch.trueDestination)
                                    continue;
                                if (instruction.address == sinkAddress) {
                                    reachedSink = true;
                                    if (state.dirty) dirtyReached = true;
                                    else cleanReached = true;
                                    break;
                                }
                                if (instruction.address > sinkAddress &&
                                    block.start <= sinkAddress &&
                                    sinkAddress < block.end)
                                    break;
                                if (instruction.isCall ||
                                    instructionWritesRegister(
                                        instruction, storage.baseRegister) ||
                                    !exactMemoryWritePreserves(
                                        instruction, storage, storageBytes))
                                    state.dirty = true;
                            }
                            if (reachedSink) continue;
                            for (size_t successor : block.succ) {
                                if (successor >= summary.graph.blocks.size()) {
                                    result.scopeComplete = false;
                                    continue;
                                }
                                queue.push_back({successor, state.dirty});
                            }
                        }
                        result.proved = result.scopeComplete && cleanReached &&
                            !dirtyReached;
                        return result;
                    };
                    auto persistentStateCallsite = [&] (uint64_t address) {
                        return std::any_of(
                            report.authorization.stateOperations.begin(),
                            report.authorization.stateOperations.end(),
                            [&](const PersistentStateOperation& operation) {
                                return operation.location.addressValid &&
                                    operation.location.address == address;
                            });
                    };
                    auto verifierAuthorizationSink = [&] (
                            const AuthorizationFunctionSummary& summary,
                            const ApiCallObservation& verifierCall,
                            const VerificationApiMatch& verifier) {
                        MachineAuthorizationSink result;
                        if (!summary.graph.complete ||
                            !summary.annotations.complete ||
                            summary.annotations.ownershipTruncated) {
                            result.scopeComplete = false;
                            return result;
                        }
                        if (!verifier.directSignatureVerdict ||
                            !verifierCall.callVAValid ||
                            !verifierCall.resultInfluencesDecision ||
                            !verifierCall.returnUseVAValid ||
                            !verifierCall.decisionVAValid ||
                            !(verifierCall.callVA <
                                  verifierCall.returnUseVA &&
                              verifierCall.returnUseVA <
                                  verifierCall.decisionVA))
                            return result;
                        bool allowScopeComplete = true;
                        if (!provenAllowPathContains(
                                summary, verifierCall.callVA, true,
                                allowScopeComplete)) {
                            result.scopeComplete = allowScopeComplete;
                            return result;
                        }
                        AuthorizationTrailBooleanContract contract =
                            AuthorizationTrailBooleanContract::Unknown;
                        switch (verifier.returnRule) {
                        case VerificationReturnRule::ZeroIsVerified:
                            contract =
                                AuthorizationTrailBooleanContract::ZeroIsTrue;
                            break;
                        case VerificationReturnRule::NonzeroIsVerified:
                            contract =
                                AuthorizationTrailBooleanContract::NonzeroIsTrue;
                            break;
                        case VerificationReturnRule::OneIsVerified:
                            contract =
                                AuthorizationTrailBooleanContract::OneIsTrue;
                            break;
                        }
                        const AuthorizationBooleanBranchDestinations branch =
                            authorizationBooleanDestinations(
                                summary.graph, verifierCall, contract);
                        // These verifier catalogs return int/NTSTATUS/LONG;
                        // using AL or comparing an x64 pointer-width value is
                        // not an exact observation of that ABI contract.
                        if (!branch.complete ||
                            !branch.trueDestinationValid ||
                            !branch.falseDestinationValid ||
                            branch.comparedWidthBits != 32)
                            return result;
                        const BasicBlock* decision =
                            authorizationBlockForAddress(
                                summary.graph, verifierCall.decisionVA);
                        if (!decision) {
                            result.scopeComplete = false;
                            return result;
                        }
                        const size_t forbidden = static_cast<size_t>(
                            decision - summary.graph.blocks.data());
                        constexpr size_t kVerifierReachabilityBlocks = 128;
                        const AuthorizationReachability verified =
                            authorizationReachableBlocks(
                                summary.graph, branch.trueDestination, true,
                                forbidden, kVerifierReachabilityBlocks);
                        const AuthorizationReachability rejected =
                            authorizationReachableBlocks(
                                summary.graph, branch.falseDestination, true,
                                forbidden, kVerifierReachabilityBlocks);
                        result.scopeComplete = allowScopeComplete &&
                            verified.complete && rejected.complete;
                        if (!result.scopeComplete) return result;
                        for (size_t blockIndex : verified.blocks) {
                            if (rejected.blocks.count(blockIndex) ||
                                blockIndex >= summary.graph.blocks.size())
                                continue;
                            for (const Instruction& instruction :
                                 summary.graph.blocks[blockIndex].insns) {
                                if (!instruction.isCall ||
                                    instruction.address <=
                                        verifierCall.decisionVA)
                                    continue;
                                uint64_t target = 0;
                                std::string label;
                                if (!TryGetDirectTarget(instruction, target) ||
                                    !exactProtectedImport(target, label) ||
                                    persistentStateCallsite(
                                        instruction.address))
                                    continue;
                                if (!result.operation ||
                                    instruction.address <
                                        result.operation->address) {
                                    result.operation = &instruction;
                                    result.operationLabel = std::move(label);
                                }
                            }
                        }
                        result.proved = result.operation != nullptr;
                        return result;
                    };
                    struct PendingMachineFlow {
                        AuthorizationLocation location;
                        std::string evidence;
                    };
                    struct MachineSource {
                        size_t summaryIndex = 0;
                        const ApiCallObservation* call = nullptr;
                        MachineIdentityApiMatch api;
                        MachineIdentityApiOutput output;
                        MachineAddressIdentity storage;
                        size_t outputBytes = 0;
                        std::string qualified;
                    };
                    constexpr size_t kMachineLineageComparisonLimit = 4096;
                    size_t machineLineageComparisons = 0;
                    bool machineApiObserved = false;
                    bool machineProofScopeComplete =
                        !candidateFunctionsTruncated &&
                        triage.functionOwnershipComplete &&
                        triage.callEdgesComplete &&
                        report.authorization.completeness.complete;
                    std::vector<MachineSource> machineSources;
                    std::vector<PendingMachineFlow> pendingMachineFlows;
                    for (size_t summaryIndex = 0;
                         summaryIndex < authorizationSummaries.size();
                         ++summaryIndex) {
                        const AuthorizationFunctionSummary& summary =
                            authorizationSummaries[summaryIndex];
                        for (const ApiCallObservation& source :
                             summary.annotations.apiCalls) {
                            const auto machine = machineIdentityFor(source);
                            if (!machine) continue;
                            machineApiObserved = true;
                            const bool summaryComplete =
                                summary.graph.complete &&
                                summary.annotations.complete &&
                                !summary.annotations.ownershipTruncated;
                            machineProofScopeComplete &= summaryComplete;
                            const AuthorizationLocation sourceLocation =
                                authorizationLocation(
                                    *job.bin, source.callVA,
                                    source.callVAValid, summary.address, true,
                                    summary.name);
                            const std::string qualified = machine->dll + "!" +
                                machine->canonicalName;
                            appendConclusion(
                                AuthorizationTrailConclusionKind::MachineBound,
                                AuthorizationTrailEvidenceKind::MachineIdentityCapability,
                                sourceLocation,
                                qualified + " can produce " +
                                    (machine->outputs.empty()
                                         ? std::string("machine-identity material")
                                         : std::string(MachineIdentityOutputKindText(
                                               machine->outputs.front().kind))) +
                                    "; catalog caveat: " + machine->meaning +
                                    "; exact call presence is capability only and does not prove successful output or authorization use",
                                0.68f, source.callVAValid && summaryComplete);

                            for (const MachineIdentityApiOutput& output :
                                 machine->outputs) {
                                const auto outputBytes =
                                    exactMachineOutputBytes(output);
                                if (!outputBytes) continue;
                                const ApiArgumentObservation* outputArgument =
                                    observedArgument(source,
                                                     output.argumentIndex);
                                const MachineAddressIdentity storage =
                                    exactAddressArgument(
                                        summary, source, outputArgument);
                                if (!storage.valid) continue;
                                machineSources.push_back({
                                    summaryIndex, &source, *machine, output,
                                    storage, *outputBytes, qualified
                                });
                            }
                        }
                    }

                    for (const MachineSource& machineSource : machineSources) {
                        if (!machineProofScopeComplete) break;
                        const AuthorizationFunctionSummary& summary =
                            authorizationSummaries[
                                machineSource.summaryIndex];
                        const ApiCallObservation& source =
                            *machineSource.call;
                        for (const ApiCallObservation& sink :
                             summary.annotations.apiCalls) {
                            if (!sink.callVAValid ||
                                sink.callVA <= source.callVA)
                                continue;
                            if (machineLineageComparisons++ >=
                                kMachineLineageComparisonLimit) {
                                machineProofScopeComplete = false;
                                break;
                            }
                            const MachineArmOwnership ownership =
                                machineSuccessOwns(
                                    summary, source, machineSource.api,
                                    sink.callVA);
                            machineProofScopeComplete &=
                                ownership.scopeComplete;
                            if (!ownership.proved) continue;

                                    const auto network = networkFor(sink);
                                    if (network &&
                                        network->stage == NetworkStage::Write) {
                                        const auto payloadIndex =
                                            directRequestPayloadArgument(*network);
                                        const ApiArgumentObservation* payload =
                                            payloadIndex
                                                ? observedArgument(sink,
                                                                   *payloadIndex)
                                                : nullptr;
                                        const MachineAddressIdentity payloadStorage =
                                            exactAddressArgument(
                                                summary, sink, payload);
                                        const MachineLineageResult lineage =
                                            payloadStorage.valid &&
                                                    payloadStorage.baseRegister ==
                                                        machineSource.storage.baseRegister &&
                                                    payloadStorage.displacement ==
                                                        machineSource.storage.displacement
                                                ? machineAddressMustReach(
                                                      summary, ownership,
                                                      machineSource.storage,
                                                      machineSource.outputBytes,
                                                      sink.callVA)
                                                : MachineLineageResult{};
                                        machineProofScopeComplete &=
                                            lineage.scopeComplete;
                                        if (payload && lineage.proved) {
                                            appendConclusion(
                                                AuthorizationTrailConclusionKind::MachineBound,
                                                AuthorizationTrailEvidenceKind::MachineIdentityCapability,
                                                authorizationLocation(
                                                    *job.bin, sink.callVA, true,
                                                    summary.address, true,
                                                    summary.name),
                                                std::string(MachineIdentityOutputKindText(
                                                    machineSource.output.kind)) +
                                                    " from " + machineSource.qualified +
                                                    " reaches the direct payload argument of " +
                                                    network->dll + "!" +
                                                    network->canonicalName +
                                                    " as an unchanged " +
                                                    std::to_string(
                                                        machineSource.outputBytes) +
                                                    "-byte direct output only on the exact API-success arm; catalog caveat: " +
                                                    machineSource.api.meaning +
                                                    "; request inclusion alone does not prove the server signed or enforced that identity",
                                                0.82f,
                                                machineProofScopeComplete);
                                        }
                                    }

                                    const auto verifier =
                                        loaderVerificationFor(sink);
                                    if (!verifier ||
                                        !verifier->directSignatureVerdict ||
                                        !sink.resultInfluencesDecision ||
                                        !sink.decisionVAValid)
                                        continue;
                                    const ApiArgumentObservation* message = nullptr;
                                    const ApiArgumentObservation* messageLength =
                                        nullptr;
                                    for (const VerificationApiArgument& role :
                                         verifier->arguments) {
                                        if (role.role ==
                                            VerificationArgumentRole::DigestOrMessage)
                                            message = observedArgument(
                                                sink, role.index);
                                        else if (role.role ==
                                            VerificationArgumentRole::DigestOrMessageLength)
                                            messageLength = observedArgument(
                                                sink, role.index);
                                    }
                                    if (!message || !messageLength ||
                                        !messageLength->immediateValid ||
                                        messageLength->immediate !=
                                            machineSource.outputBytes)
                                        continue;
                                    const MachineAddressIdentity messageStorage =
                                        exactAddressArgument(
                                            summary, sink, message);
                                    if (!messageStorage.valid ||
                                        messageStorage.baseRegister !=
                                            machineSource.storage.baseRegister ||
                                        messageStorage.displacement !=
                                            machineSource.storage.displacement)
                                        continue;
                                    const MachineLineageResult lineage =
                                        machineAddressMustReach(
                                            summary, ownership,
                                            machineSource.storage,
                                            machineSource.outputBytes,
                                            sink.callVA);
                                    machineProofScopeComplete &=
                                        lineage.scopeComplete;
                                    if (!lineage.proved) continue;
                                    const MachineAuthorizationSink authSink =
                                        verifierAuthorizationSink(
                                            summary, sink, *verifier);
                                    machineProofScopeComplete &=
                                        authSink.scopeComplete;
                                    if (!authSink.proved) continue;
                                    pendingMachineFlows.push_back({
                                        authorizationLocation(
                                            *job.bin, sink.callVA, true,
                                            summary.address, true,
                                            summary.name),
                                        std::string(MachineIdentityOutputKindText(
                                            machineSource.output.kind)) +
                                            " from " + machineSource.qualified +
                                            " is a decoder-proved direct " +
                                            std::to_string(
                                                machineSource.outputBytes) +
                                            "-byte output; the exact 32-bit API-success arm preserves its address and bytes without an intervening overwrite or unknown call into the exact message/digest argument and compatible length of " +
                                            verifier->dll + "!" +
                                            verifier->canonicalName +
                                            "; that verifier's exact documented 32-bit success arm alone reaches " +
                                            authSink.operationLabel +
                                            " on a strong authorization allow path; catalog caveat: " +
                                            machineSource.api.meaning
                                    });
                        }
                    }
                    if (machineProofScopeComplete) {
                        for (const PendingMachineFlow& flow :
                             pendingMachineFlows) {
                            appendConclusion(
                                AuthorizationTrailConclusionKind::MachineBound,
                                AuthorizationTrailEvidenceKind::MachineIdentityFlow,
                                flow.location, flow.evidence, 0.98f, true);
                        }
                    } else if (machineApiObserved) {
                        trail.completeness.conclusionEvidenceComplete = false;
                    }

                    // Exact verifier contracts distinguish cryptographic API
                    // presence from a verifier return which actually controls
                    // an authorization branch. A supported result additionally
                    // requires reply-buffer lineage into the verifier's message
                    // or signature argument.
                    for (const AuthorizationFunctionSummary& summary :
                         authorizationSummaries) {
                        for (const ApiCallObservation& call :
                             summary.annotations.apiCalls) {
                            const auto verifier = verificationFor(call);
                            if (!verifier) continue;
                            const AuthorizationLocation location =
                                authorizationLocation(
                                    *job.bin, call.callVA,
                                    call.callVAValid, summary.address, true,
                                    summary.name);
                            const std::string qualified = verifier->dll + "!" +
                                verifier->canonicalName;
                            appendStage(
                                AuthorizationTrailStageKind::CryptoVerification,
                                AuthorizationTrailEvidenceKind::CryptoPrimitivePresence,
                                location, qualified,
                                verifier->meaning +
                                    "; import/call presence alone is not an entitlement verdict",
                                0.72f, call.callVAValid, 0);
                            appendConclusion(
                                AuthorizationTrailConclusionKind::SignatureVerified,
                                AuthorizationTrailEvidenceKind::CryptoPrimitivePresence,
                                location,
                                qualified +
                                    " is called, but static presence alone does not prove which data was verified or the runtime result",
                                0.6f, true);

                            if (!verifier->directSignatureVerdict ||
                                !call.callVAValid ||
                                !call.resultInfluencesDecision ||
                                !call.decisionVAValid)
                                continue;
                            bool replyArgumentLinked = false;
                            for (const NetworkReplyDecisionFlow& reply :
                                 report.replyDecisionFlows) {
                                if (!reply.functionAddressValid ||
                                    reply.functionAddress != summary.address ||
                                    !reply.callsiteValid ||
                                    reply.outputExpression.empty() ||
                                    reply.callsite >= call.callVA)
                                    continue;
                                for (const VerificationApiArgument& role :
                                     verifier->arguments) {
                                    if (role.role !=
                                            VerificationArgumentRole::DigestOrMessage &&
                                        role.role !=
                                            VerificationArgumentRole::Signature)
                                        continue;
                                    const auto argument = std::find_if(
                                        call.arguments.begin(),
                                        call.arguments.end(),
                                        [&](const ApiArgumentObservation& value) {
                                            return value.index == role.index;
                                        });
                                    if (argument == call.arguments.end()) continue;
                                    std::string expression =
                                        argument->sourceExpression.empty()
                                            ? argument->renderedValue
                                            : argument->sourceExpression;
                                    if (authorizationExpressionsShareLineage(
                                            summary.graph, reply.callsite,
                                            reply.outputExpression, call.callVA,
                                            std::move(expression))) {
                                        replyArgumentLinked = true;
                                        break;
                                    }
                                }
                                if (replyArgumentLinked) break;
                            }
                            if (!replyArgumentLinked) continue;
                            AuthorizationTrailBooleanContract contract =
                                AuthorizationTrailBooleanContract::Unknown;
                            switch (verifier->returnRule) {
                            case VerificationReturnRule::ZeroIsVerified:
                                contract =
                                    AuthorizationTrailBooleanContract::ZeroIsTrue;
                                break;
                            case VerificationReturnRule::NonzeroIsVerified:
                                contract =
                                    AuthorizationTrailBooleanContract::NonzeroIsTrue;
                                break;
                            case VerificationReturnRule::OneIsVerified:
                                contract =
                                    AuthorizationTrailBooleanContract::OneIsTrue;
                                break;
                            }
                            const AuthorizationBooleanBranchDestinations result =
                                authorizationBooleanDestinations(
                                    summary.graph, call, contract);
                            if (!result.trueDestinationValid ||
                                !result.falseDestinationValid)
                                continue;
                            appendStage(
                                AuthorizationTrailStageKind::CryptoVerification,
                                AuthorizationTrailEvidenceKind::SignatureVerificationResult,
                                location, qualified + " result",
                                "an exact reply-buffer value reaches the verifier message/signature argument and the documented verifier result controls a boolean branch",
                                0.95f, result.complete, 1);
                            appendConclusion(
                                AuthorizationTrailConclusionKind::SignatureVerified,
                                AuthorizationTrailEvidenceKind::SignatureVerificationResult,
                                location,
                                "reply data reaches an exact direct-signature verifier and its documented success result controls the static path",
                                0.95f, result.complete);
                        }
                    }

                    // Look for an exact 32-hex expected literal only when it is
                    // an argument to an exact equality comparator alongside the
                    // recovered local input expression. Random hashes elsewhere
                    // in the image are intentionally ignored.
                    bool embeddedExpectedKey = false;
                    for (const AuthorizationFlow& flow :
                         report.authorization.flows) {
                        if (!flow.localInputFlow ||
                            !flow.decisionLocation.functionAddressValid)
                            continue;
                        const auto summaryFound = summaryByFunction.find(
                            flow.decisionLocation.functionAddress);
                        if (summaryFound == summaryByFunction.end()) continue;
                        const AuthorizationFunctionSummary& summary =
                            authorizationSummaries[summaryFound->second];
                        const std::string inputExpression =
                            authorizationExpressionKey(flow.originExpression);
                        for (const ApiCallObservation& call :
                             summary.annotations.apiCalls) {
                            if (!authorizationEqualityHelper(*job.bin, call))
                                continue;
                            bool hasInput = false;
                            const ApiArgumentObservation* expected = nullptr;
                            for (const ApiArgumentObservation& argument :
                                 call.arguments) {
                                const std::string source =
                                    authorizationExpressionKey(
                                        argument.sourceExpression.empty()
                                            ? argument.renderedValue
                                            : argument.sourceExpression);
                                hasInput |= !inputExpression.empty() &&
                                    (source == inputExpression ||
                                     authorizationTokenContains(
                                         source, inputExpression));
                                if (authorizationIsHexToken32(
                                        argument.stringLiteral))
                                    expected = &argument;
                            }
                            if (!hasInput || !expected) continue;
                            const AuthorizationLocation location =
                                authorizationLocation(
                                    *job.bin,
                                    expected->referencedAddressValid
                                        ? expected->referencedAddress
                                        : call.callVA,
                                    expected->referencedAddressValid ||
                                        call.callVAValid,
                                    summary.address, true, summary.name);
                            appendConclusion(
                                AuthorizationTrailConclusionKind::EmbeddedExpectedKey,
                                AuthorizationTrailEvidenceKind::ExpectedKeyLiteral,
                                location,
                                "an exact equality comparator receives both the local input and a literal containing 32 hexadecimal digits",
                                0.98f, true);
                            embeddedExpectedKey = true;
                        }
                    }
                    trail.completeness.expectedKeySearchComplete =
                        !report.completeness.bytesTruncated &&
                        !report.completeness.stringsTruncated &&
                        report.authorization.completeness.decisionsComplete &&
                        trail.completeness.predicateCandidatesComplete;
                    if (!embeddedExpectedKey) {
                        appendConclusion(
                            AuthorizationTrailConclusionKind::EmbeddedExpectedKey,
                            AuthorizationTrailEvidenceKind::ExpectedKeySearchNegative,
                            {},
                            "no 32-hex literal was found as the expected-value argument of an exact local-input equality comparator in the complete retained authorization scope",
                            0.9f,
                            trail.completeness.expectedKeySearchComplete);
                    }

                    bool privateKeyMarker = false;
                    for (const StrResult& text : strings) {
                        const std::string lower =
                            authorizationLower(text.text);
                        if (lower.find("-----begin private key-----") !=
                                std::string::npos ||
                            lower.find("-----begin rsa private key-----") !=
                                std::string::npos ||
                            lower.find("-----begin ec private key-----") !=
                                std::string::npos) {
                            privateKeyMarker = true;
                            break;
                        }
                    }
                    // This is explicitly a textual-marker scope, not a claim
                    // that every possible encoded or obfuscated key was parsed.
                    trail.completeness.privateMaterialSearchComplete =
                        !report.completeness.bytesTruncated &&
                        !report.completeness.stringsTruncated;
                    if (!privateKeyMarker) {
                        appendConclusion(
                            AuthorizationTrailConclusionKind::PrivateSigningMaterial,
                            AuthorizationTrailEvidenceKind::PrivateMaterialSearchNegative,
                            {},
                            "no visible PEM private-key marker was found in the complete extracted-string scope; therefore static analysis cannot manufacture a real server-signed entitlement",
                            0.8f,
                            trail.completeness.privateMaterialSearchComplete);
                    }

                    report.authorizationTrail = RunAuthorizationTrail(trail);

                    // Convert each retained ranked predicate into inert patch
                    // advice.  This adapter deliberately fails closed: the
                    // advisor sees exact section, return, entry, side-effect,
                    // and authorization-link facts, and emits bytes only when
                    // every one of them is present.  Nothing is applied here.
                    report.authorizationPatchAdvice.clear();
                    report.authorizationPatchAdvice.reserve(
                        report.authorizationTrail.predicates.size());
                    for (const AuthorizationTrailPredicate& predicate :
                         report.authorizationTrail.predicates) {
                        if (!predicate.function.functionAddressValid &&
                            !predicate.function.addressValid)
                            continue;
                        const uint64_t functionAddress =
                            predicate.function.functionAddressValid
                                ? predicate.function.functionAddress
                                : predicate.function.address;
                        const auto summaryFound =
                            summaryByFunction.find(functionAddress);
                        if (summaryFound == summaryByFunction.end() ||
                            summaryFound->second >=
                                authorizationSummaries.size())
                            continue;
                        const AuthorizationFunctionSummary& summary =
                            authorizationSummaries[summaryFound->second];
                        const FunctionReturnObservation& returned =
                            summary.annotations.returnObservation;
                        const auto analyzedFunction = std::find_if(
                            funcs.begin(), funcs.end(),
                            [functionAddress](const FuncResult& function) {
                                return function.address == functionAddress;
                            });
                        if (analyzedFunction == funcs.end()) continue;
                        std::vector<FunctionChunk> ownedChunks =
                            analyzedFunction->chunks;
                        if (ownedChunks.empty() && analyzedFunction->size)
                            ownedChunks.push_back({ functionAddress,
                                                    analyzedFunction->size });
                        auto ownedAddress = [&](uint64_t address) {
                            for (const FunctionChunk& chunk : ownedChunks)
                                if (chunk.size && address >= chunk.address &&
                                    address - chunk.address < chunk.size)
                                    return true;
                            return false;
                        };
                        auto ownedSpan = [&](uint64_t address,
                                             uint64_t size) {
                            if (!size) return false;
                            for (const FunctionChunk& chunk : ownedChunks) {
                                if (!chunk.size || address < chunk.address)
                                    continue;
                                const uint64_t offset = address - chunk.address;
                                if (offset <= chunk.size &&
                                    size <= static_cast<uint64_t>(chunk.size) -
                                                offset)
                                    return true;
                            }
                            return false;
                        };

                        AuthorizationPatchAdvisorInput adviceInput;
                        if (job.decoder.arch == Arch::X86)
                            adviceInput.architecture =
                                AuthorizationPatchArchitecture::X86;
                        else if (job.decoder.arch == Arch::X64)
                            adviceInput.architecture =
                                AuthorizationPatchArchitecture::X64;
                        adviceInput.functionAddress = functionAddress;
                        adviceInput.functionAddressValid = true;

                        // Decode ownership, not adjacent file availability,
                        // bounds the replacement bytes.  In particular, an
                        // entry block containing `xor eax,eax; ret` owns only
                        // those three bytes even when another function follows
                        // immediately in the same executable section.
                        uint64_t contiguousEntryBytes = 0;
                        bool entryBlockExact = false;
                        for (const BasicBlock& block : summary.graph.blocks) {
                            if (block.start != functionAddress ||
                                block.insns.empty())
                                continue;
                            uint64_t cursor = functionAddress;
                            bool contiguous = true;
                            for (const Instruction& instruction : block.insns) {
                                if (!instruction.length ||
                                    instruction.address != cursor ||
                                    instruction.length > UINT64_MAX - cursor) {
                                    contiguous = false;
                                    break;
                                }
                                cursor += instruction.length;
                            }
                            if (contiguous && cursor == block.end &&
                                cursor > functionAddress) {
                                contiguousEntryBytes =
                                    cursor - functionAddress;
                                entryBlockExact = ownedSpan(
                                    functionAddress, contiguousEntryBytes);
                            }
                            break;
                        }
                        adviceInput.contiguousEntryOwnedBytes =
                            contiguousEntryBytes;
                        adviceInput.replacementExtentOwned =
                            entryBlockExact && summary.graph.complete &&
                            !analyzedFunction->ownershipTruncated &&
                            analyzedFunction->boundaryConfidence !=
                                FunctionBoundaryConfidence::Heuristic;

                        size_t entryAvailable = 0;
                        if (const uint8_t* entry = job.bin->ptrFromVA(
                                functionAddress, entryAvailable)) {
                            const size_t captured =
                                (std::min<size_t>)(entryAvailable, 8);
                            adviceInput.functionBytes.assign(entry,
                                entry + captured);
                        }

                        for (const Section& section : job.bin->sections()) {
                            if (section.virtualAddress >
                                UINT64_MAX - job.bin->imageBase())
                                continue;
                            const uint64_t sectionAddress =
                                job.bin->imageBase() +
                                section.virtualAddress;
                            const uint64_t sectionSize = (std::max)(
                                section.virtualSize, section.rawSize);
                            if (!sectionSize || functionAddress < sectionAddress)
                                continue;
                            const uint64_t displacement =
                                functionAddress - sectionAddress;
                            if (displacement >= sectionSize) continue;
                            adviceInput.sectionExecutionKnown = true;
                            adviceInput.sectionExecutable = section.executable;
                            break;
                        }
                        adviceInput.replacementExtentOwned &=
                            adviceInput.sectionExecutionKnown &&
                            adviceInput.sectionExecutable;

                        adviceInput.returnAnalysisComplete = returned.complete;
                        switch (predicate.returnContract) {
                        case AuthorizationTrailBooleanContract::CanonicalZeroOrOne:
                            adviceInput.booleanContract =
                                AuthorizationPatchBooleanContract::CanonicalZeroOrOne;
                            break;
                        case AuthorizationTrailBooleanContract::NonzeroIsTrue:
                            adviceInput.booleanContract =
                                AuthorizationPatchBooleanContract::NonzeroIsTrue;
                            break;
                        case AuthorizationTrailBooleanContract::ZeroIsTrue:
                            adviceInput.booleanContract =
                                AuthorizationPatchBooleanContract::ZeroIsTrue;
                            break;
                        case AuthorizationTrailBooleanContract::OneIsTrue:
                            adviceInput.booleanContract =
                                AuthorizationPatchBooleanContract::OneIsTrue;
                            break;
                        case AuthorizationTrailBooleanContract::Unknown:
                            adviceInput.booleanContract =
                                AuthorizationPatchBooleanContract::Unknown;
                            break;
                        }
                        if (returned.validWidthKnown &&
                            returned.validWidthBits <= 255)
                            adviceInput.returnWidthBits =
                                static_cast<uint8_t>(returned.validWidthBits);
                        adviceInput.authorizationStateLinked =
                            predicate.authorizationSourceLinked;
                        adviceInput.centralizedPredicate =
                            predicate.role !=
                                AuthorizationTrailPredicateRole::Candidate &&
                            predicate.uniqueCallerCount >= 2;

                        // Entry coverage is a bounded static claim over every
                        // retained exact source, not merely direct calls. Check
                        // overlapping discovered function roots (loader
                        // symbols, exports, unwind entries, callbacks, pointer
                        // tables/classifier roots), explicit landmarks, and the
                        // complete whole-image xref index. An external branch,
                        // tail transfer, or any address-taken data reference to
                        // an interior byte is an alternate entry/refusal.
                        adviceInput.entryCoverageComplete =
                            triage.callEdgesComplete && xrefIdx &&
                            xrefIdx->complete &&
                            triage.functionOwnershipComplete &&
                            !candidateFunctionsTruncated &&
                            summary.graph.complete &&
                            summary.annotations.complete &&
                            !summary.annotations.ownershipTruncated &&
                            !analyzedFunction->ownershipTruncated &&
                            summary.annotations.boundaryConfidence !=
                                FunctionBoundaryConfidence::Heuristic &&
                            !ownedChunks.empty();

                        for (const FuncResult& possibleEntry : funcs) {
                            if (possibleEntry.address != functionAddress &&
                                ownedAddress(possibleEntry.address)) {
                                adviceInput.alternateEntryPresent = true;
                                break;
                            }
                        }
                        if (!adviceInput.alternateEntryPresent) {
                            for (const BinaryFile::Export& exported :
                                 job.bin->exports()) {
                                if (exported.mapped &&
                                    exported.va != functionAddress &&
                                    ownedAddress(exported.va)) {
                                    adviceInput.alternateEntryPresent = true;
                                    break;
                                }
                            }
                        }
                        if (!adviceInput.alternateEntryPresent) {
                            for (const BinaryFile::PeRuntimeFunction& unwind :
                                 job.bin->runtimeFunctions()) {
                                if (unwind.rangeValid &&
                                    unwind.beginVA != functionAddress &&
                                    ownedAddress(unwind.beginVA)) {
                                    adviceInput.alternateEntryPresent = true;
                                    break;
                                }
                            }
                        }
                        if (!adviceInput.alternateEntryPresent) {
                            for (const AnalysisLandmark& landmark :
                                 job.bin->analysisLandmarks()) {
                                if (landmark.address != functionAddress &&
                                    ownedAddress(landmark.address)) {
                                    adviceInput.alternateEntryPresent = true;
                                    break;
                                }
                            }
                        }
                        if (!adviceInput.alternateEntryPresent && xrefIdx) {
                            for (const auto& [target, sources] :
                                 xrefIdx->toTarget) {
                                if (target == functionAddress ||
                                    !ownedAddress(target))
                                    continue;
                                for (uint64_t source : sources) {
                                    const bool dataReference =
                                        xrefIdx->accessOf.find(source) !=
                                        xrefIdx->accessOf.end();
                                    if (!ownedAddress(source) || dataReference) {
                                        adviceInput.alternateEntryPresent = true;
                                        break;
                                    }
                                }
                                if (adviceInput.alternateEntryPresent) break;
                            }
                        }

                        bool returnStyleComplete = returned.complete &&
                            !returned.exits.empty();
                        bool returnStyleSet = false;
                        AuthorizationPatchReturnStyle commonStyle =
                            AuthorizationPatchReturnStyle::Unknown;
                        uint16_t commonPop = 0;
                        for (const FunctionReturnExitObservation& exit :
                             returned.exits) {
                            if (!exit.returnVAValid) {
                                returnStyleComplete = false;
                                continue;
                            }
                            const Instruction* instruction =
                                authorizationInstructionAt(summary.graph,
                                                           exit.returnVA);
                            if (!instruction ||
                                (authorizationLower(instruction->mnemonic) !=
                                     "ret" &&
                                 authorizationLower(instruction->mnemonic) !=
                                     "retn")) {
                                returnStyleComplete = false;
                                continue;
                            }
                            bool popValid = false;
                            uint64_t popValue = 0;
                            for (const TypedOperand& operand :
                                 instruction->typedOperands) {
                                if (operand.kind != OperandKind::Immediate)
                                    continue;
                                if (popValid || operand.immediate > 0xffffu) {
                                    returnStyleComplete = false;
                                    break;
                                }
                                popValid = true;
                                popValue = operand.immediate;
                            }
                            if (!popValid && !instruction->operands.empty()) {
                                AuthorizationIntegerLiteral parsed;
                                if (!authorizationParseInteger(
                                        instruction->operands, parsed) ||
                                    parsed.bits > 0xffffu) {
                                    returnStyleComplete = false;
                                    continue;
                                }
                                popValid = true;
                                popValue = parsed.bits;
                            }
                            const AuthorizationPatchReturnStyle style =
                                popValid
                                    ? AuthorizationPatchReturnStyle::NearReturnPop
                                    : AuthorizationPatchReturnStyle::NearReturn;
                            const uint16_t pop =
                                static_cast<uint16_t>(popValue);
                            if (!returnStyleSet) {
                                commonStyle = style;
                                commonPop = pop;
                                returnStyleSet = true;
                            } else if (commonStyle != style ||
                                       commonPop != pop) {
                                returnStyleComplete = false;
                            }
                        }
                        adviceInput.returnStyleAnalysisComplete =
                            returnStyleComplete && returnStyleSet;
                        adviceInput.returnStyle = commonStyle;
                        adviceInput.stackPopBytes = commonPop;

                        bool sawCall = false;
                        bool callsOnlyTransport = true;
                        auto normalizedCallName = [](std::string value) {
                            value = authorizationLower(std::move(value));
                            if (const size_t bang = value.rfind('!');
                                bang != std::string::npos)
                                value.erase(0, bang + 1);
                            while (!value.empty() &&
                                   (value.front() == '_' ||
                                    value.front() == '@'))
                                value.erase(value.begin());
                            if (const size_t suffix = value.rfind('@');
                                suffix != std::string::npos &&
                                suffix + 1 < value.size() &&
                                std::all_of(value.begin() + suffix + 1,
                                            value.end(), [](unsigned char c) {
                                                return std::isdigit(c) != 0;
                                            }))
                                value.erase(suffix);
                            return value;
                        };
                        static constexpr std::string_view kCleanupCalls[] = {
                            "free", "cfree", "heapfree", "localfree",
                            "globalfree", "closehandle", "closesocket",
                            "regclosekey", "winhttpclosehandle",
                            "internetclosehandle", "deletedcriticalsection"
                        };
                        static constexpr std::string_view kSecurityCalls[] = {
                            "security_check_cookie", "report_gsfailure",
                            "fastfail", "failfast"
                        };
                        for (const ApiCallObservation& call :
                             summary.annotations.apiCalls) {
                            sawCall = true;
                            bool exactNetwork = false;
                            if (call.targetVAValid) {
                                const auto imported =
                                    authorizationImports.find(call.targetVA);
                                if (imported != authorizationImports.end())
                                    exactNetwork = LookupNetworkApi(
                                        imported->second.dll,
                                        imported->second.name).has_value();
                            }
                            callsOnlyTransport &= exactNetwork;
                            const std::string normalized =
                                normalizedCallName(call.resolvedName);
                            for (std::string_view cleanup : kCleanupCalls)
                                if (normalized == cleanup) {
                                    adviceInput.stringOrHeapCleanupPresent = true;
                                    break;
                                }
                            for (std::string_view security : kSecurityCalls)
                                if (normalized.find(security) !=
                                    std::string::npos) {
                                    adviceInput.stackCookieOrSecurityEpiloguePresent =
                                        true;
                                    break;
                                }
                        }
                        adviceInput.sideEffectAnalysisComplete =
                            summary.graph.complete &&
                            summary.annotations.complete;
                        const bool sideEffectLight =
                            authorizationPredicateSideEffectLight(
                                summary.graph, summary.annotations);
                        adviceInput.otherSideEffectsPresent =
                            !sideEffectLight;
                        adviceInput.transportBehaviorOnly =
                            sawCall && callsOnlyTransport;

                        adviceInput.proofConfidence = predicate.confidence;
                        adviceInput.evidence = predicate.evidence;
                        if (!adviceInput.evidence.empty())
                            adviceInput.evidence += "; ";
                        adviceInput.evidence +=
                            std::to_string(predicate.uniqueCallerCount) +
                            " unique caller(s), " +
                            std::to_string(predicate.guardedOperationCount) +
                            " guarded operation(s); bounded entry and return safety checks applied";

                        AuthorizationPredicatePatchAdvice retained;
                        retained.function = predicate.function;
                        retained.advice =
                            AdviseAuthorizationPredicatePatch(adviceInput);
                        report.authorizationPatchAdvice.push_back(
                            std::move(retained));
                    }
                }
            }
            if (candidateFunctionsTruncated) {
                report.completeness.candidateFunctionsTruncated = true;
                report.completeness.complete = false;
                if (report.completeness.stopReason == CrackmeTriageStopReason::None)
                    report.completeness.stopReason = CrackmeTriageStopReason::SourceLimit;
                std::string detail;
                if (networkCandidateNeighborhoodTruncated) {
                    detail =
                        "exact-network direct-call neighborhood retained the first 1024 states at depth <= 4";
                }
                if (candidateFunctionsAvailable > triage.limits.maxFunctions) {
                    const std::string capDetail =
                        "candidate-function annotation cap retained " +
                        std::to_string((std::min)(
                            triage.limits.maxFunctions,
                            candidateFunctionsAvailable)) + " of " +
                        std::to_string(candidateFunctionsAvailable) +
                        " implicated functions";
                    if (!detail.empty()) detail += "; ";
                    detail += capDetail;
                }
                if (report.completeness.reason.empty()) report.completeness.reason = detail;
                else if (report.completeness.reason.find(detail) == std::string::npos)
                    report.completeness.reason += "; " + detail;
            }
            if (!superseded()) {
                AnalysisResult result;
                result.crackmeTriage = std::move(report);
                result.crackmeTriageValid = true;
                cacheRemember(key, result);
                emit(std::move(result));
            }
        }
    }

    // F1 clean-room synthesis of the requested region (off the render thread). With the
    // stub engine the result is "engine unavailable"; with DS_HAVE_SYMENGINE it is real.
    if ((job.kinds & K_Synthesis) && !superseded() && job.regionValid &&
        job.regionHi > job.regionLo) {
        SynthResult sr;
        if (!ArchIsX86_32Or64(job.decoder.arch)) {
            // Reject at the service boundary as well as in SynthesizeJob.  A
            // future/non-UI caller must never feed ARM/Thumb/AArch64 bytes into
            // the x86 symbolic register model merely because it can enqueue F1.
            sr.regionStart = job.regionLo;
            sr.regionSize = static_cast<uint32_t>(std::min<uint64_t>(
                job.regionHi - job.regionLo, (std::numeric_limits<uint32_t>::max)()));
            sr.rejectedReason = std::string("synthesis is x86/x64-only; unsupported architecture: ") +
                                ArchName(job.decoder.arch);
        } else {
            SynthesisOptions opt; opt.samples = 256;
            sr = SynthesizeJob(*job.bin, *dis, job.decoder.arch, job.regionLo, job.regionHi, opt);
        }
        if (!superseded()) {
            AnalysisResult r; r.synth = std::move(sr); r.synthValid = true;
            r.regionLo = job.regionLo; r.regionHi = job.regionHi;
            emit(std::move(r));
        }
    }

    // F3 STATIC path exploration from the region start (structural CFG look-ahead; the
    // live-debugger concolic explore is the own-thread follow-up).
    if ((job.kinds & K_PathExplore) && !superseded() && job.regionValid) {
        PathTree pt = PathExploreJob(*job.bin, *dis, job.decoder.arch, job.regionLo, {},
                                     noreturnResolver(job.bin, job.analysisOverrides,
                                                      job.noreturnTargets, &funcs));
        if (!superseded()) {
            AnalysisResult r; r.pathTree = std::move(pt); r.pathValid = true;
            r.regionLo = job.regionLo; r.regionHi = job.regionHi;
            emit(std::move(r));
        }
    }

    // Structured pseudo-C for [regionLo, regionHi), off the render thread. The job
    // owns an immutable name/signature snapshot, including analyst renames and the
    // current discovered/guessed function names.
    if ((job.kinds & K_Decompile) && !superseded() && job.regionValid &&
        job.regionHi > job.regionLo) {
        const AnalysisCacheKey key = cacheKey(
            AnalysisCachePass::Decompile,
            decompileInputsDigest(job.regionLo, job.regionHi,
                                  job.decompNames.get(), job.decompSignature,
                                  job.decompChunks.get(),
                                  job.decompOwnershipTruncated,
                                  job.noreturnTargets.get()));
        AnalysisResult cached;
        if (cacheLookup(key, cached) && cached.decompValid) {
            cached.decompContext = job.decompContext;
            emit(std::move(cached));
        } else {
            DecompResult t = DecompileRegion(
                *job.bin, *dis, job.decoder, job.regionLo, job.regionHi,
                job.decompNames.get(), job.decompSignature,
                noreturnResolver(job.bin, job.analysisOverrides, job.noreturnTargets, &funcs),
                job.decompChunks.get(),
                job.decompOwnershipTruncated,
                analystCallingConvention(job.analysisOverrides, job.regionLo));
            if (!superseded()) {
                AnalysisResult result;
                result.decompText = std::move(t.text);
                result.decompLineVA = std::move(t.lineVA);
                result.decompLineOrigins = std::move(t.lineOrigins);
                result.decompComplete = t.complete;
                result.decompIncompleteReason = std::move(t.incompleteReason);
                result.decompDiagnostics = std::move(t.diagnostics);
                result.decompValid = true;
                result.decompVA = job.regionLo;
                result.decompContext = job.decompContext;
                result.regionLo = job.regionLo;
                result.regionHi = job.regionHi;
                cacheRemember(key, result);
                emit(std::move(result));
            }
        }
    }
}

} // namespace ds
