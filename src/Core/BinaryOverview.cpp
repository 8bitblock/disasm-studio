#include "BinaryOverview.h"

#include "AnalysisJobs.h"
#include "BinaryFile.h"

#include <algorithm>
#include <string_view>

namespace ds {
namespace {

std::string boundedText(std::string_view text, size_t limit) {
    if (text.size() <= limit) return std::string(text);
    // Avoid splitting a UTF-8 sequence in a symbol or analyst-provided name.
    size_t end = limit;
    while (end && (static_cast<unsigned char>(text[end]) & 0xC0u) == 0x80u)
        --end;
    return std::string(text.substr(0, end)) + "...";
}

struct Mapping {
    bool backed = false;
    bool executable = false;
};

Mapping mappingAt(const BinaryFile& binary, uint64_t va) {
    if (va < binary.imageBase()) return {};
    const uint64_t rva = va - binary.imageBase();
    const auto& sections = binary.sections();
    const size_t count = std::min(sections.size(), kBinaryOverviewSourceLimit);
    for (size_t i = 0; i < count; ++i) {
        const Section& section = sections[i];
        const uint64_t extent = section.virtualSize
            ? section.virtualSize : section.rawSize;
        if (rva < section.virtualAddress ||
            rva - section.virtualAddress >= extent) continue;
        // Match ptrFromVA's first virtual owner, including virtual padding.
        // Later overlapping executable sections cannot promote a data owner.
        size_t available = 0;
        const bool backed = binary.ptrFromVA(va, available) && available;
        return {backed, backed && section.executable};
    }
    if (count != sections.size()) return {}; // Never scan past the section cap.
    // Header-resident PE entries are file-backed data, not executable roots.
    size_t available = 0;
    return {binary.ptrFromVA(va, available) && available, false};
}

} // namespace

BinaryOverview BuildBinaryOverview(const BinaryFile& binary,
                                  const std::vector<FuncResult>* functions,
                                  std::optional<Arch> activeArch) {
    BinaryOverview result;
    if (!binary.loaded()) return result;
    result.leads.reserve(kBinaryOverviewLeadLimit);
    result.candidatesLimited = binary.sections().size() > kBinaryOverviewSourceLimit;
    const bool thumb = activeArch ? *activeArch == Arch::THUMB
                                 : binary.machine() == MachineArch::THUMB;
    auto codeAddress = [thumb](uint64_t va) { return thumb ? va & ~uint64_t{1} : va; };
    auto full = [&] {
        if (result.leads.size() < kBinaryOverviewLeadLimit) return false;
        result.candidatesLimited = true;
        return true;
    };

    auto sourceCount = [&](size_t count) {
        result.candidatesLimited |= count > kBinaryOverviewSourceLimit;
        return std::min(count, kBinaryOverviewSourceLimit);
    };
    auto add = [&](uint64_t va, bool code, bool inferred,
                   std::string label, std::string evidence) {
        const Mapping mapping = mappingAt(binary, va);
        if (!mapping.backed || (code && !mapping.executable)) return;
        if (std::any_of(result.leads.begin(), result.leads.end(),
                        [&](const BinaryOverviewLead& lead) { return lead.va == va; }))
            return;
        if (result.leads.size() == kBinaryOverviewLeadLimit) {
            result.candidatesLimited = true;
            return;
        }
        result.leads.push_back({boundedText(label, 160), boundedText(evidence, 768),
                                va, code, inferred});
    };

    result.entryDeclared = binary.hasEntryPoint();
    if (result.entryDeclared) {
        const uint64_t va = codeAddress(binary.entryPointVA());
        const Mapping mapping = mappingAt(binary, va);
        result.entryMapped = mapping.backed;
        if (mapping.backed) {
            std::string evidence = binary.rawEntryExplicit()
                ? "Explicit entry selected for this Raw mapping."
                : "Entry declared by the image header; it can be runtime initialization code.";
            if (!mapping.executable)
                evidence += " The destination is not executable; inspect its bytes in Hex.";
            add(va, mapping.executable, false, "Declared entry", std::move(evidence));
        }
    }

    const auto& exports = binary.exports();
    for (size_t i = 0, count = sourceCount(exports.size()); i < count; ++i) {
        if (full()) break;
        const BinaryFile::Export& symbol = exports[i];
        if (!symbol.mapped || symbol.forwarded || !symbol.isCode) continue;
        const std::string label = symbol.name.empty()
            ? "Export ordinal " + std::to_string(symbol.ordinal)
            : boundedText(symbol.name, 160);
        add(codeAddress(symbol.va), true, false, label,
            symbol.elfSymbol || symbol.machoSymbol
                ? "Loader symbol in executable bytes; a navigation anchor, not proof of execution."
                : "Local code export in executable bytes; a public entry, not proof it is called.");
    }

    const auto& landmarks = binary.analysisLandmarks();
    for (size_t i = 0, count = sourceCount(landmarks.size()); i < count; ++i) {
        if (full()) break;
        const AnalysisLandmark& landmark = landmarks[i];
        std::string evidence = "Named analysis root in this mapping.";
        if (!landmark.evidence.empty()) evidence += " " + boundedText(landmark.evidence, 640);
        add(codeAddress(landmark.address), true, false,
            landmark.name.empty() ? "Named analysis root" : boundedText(landmark.name, 160),
            std::move(evidence));
    }

    if (functions && !full()) {
        std::vector<const FuncResult*> candidates;
        const size_t count = sourceCount(functions->size());
        candidates.reserve(count);
        for (size_t i = 0; i < count; ++i) candidates.push_back(&(*functions)[i]);
        auto rank = [](const FuncResult& function) {
            if (function.analystDefined) return 3;
            if (function.boundaryConfidence == FunctionBoundaryConfidence::Authoritative) return 2;
            if (function.boundaryConfidence == FunctionBoundaryConfidence::Reconciled) return 1;
            return 0;
        };
        std::stable_sort(candidates.begin(), candidates.end(),
            [&](const FuncResult* a, const FuncResult* b) { return rank(*a) > rank(*b); });
        for (const FuncResult* function : candidates) {
            if (full()) break;
            const bool inferred = function->guessed ||
                (!function->analystDefined && function->boundaryConfidence !=
                                              FunctionBoundaryConfidence::Authoritative);
            std::string evidence = "Function start: ";
            evidence += FunctionSeedKindName(function->seedKind);
            evidence += " / ";
            evidence += FunctionBoundaryConfidenceName(function->boundaryConfidence);
            evidence += ".";
            if (function->guessed) {
                evidence += " Name is inferred";
                if (!function->reason.empty()) evidence += ": " + boundedText(function->reason, 480);
                evidence += ".";
            }
            if (function->ownershipTruncated) evidence += " Function coverage is partial.";
            add(codeAddress(function->address), true, inferred,
                function->name.empty() ? "Discovered function" : boundedText(function->name, 160),
                std::move(evidence));
        }
    }

    if (result.leads.empty()) {
        const auto& sections = binary.sections();
        for (size_t i = 0, count = sourceCount(sections.size()); i < count; ++i) {
            const Section& section = sections[i];
            if (!section.executable) continue;
            uint64_t va = 0;
            if (!CheckedAddressAdd(binary.imageBase(), section.virtualAddress, va)) continue;
            add(va, true, false, "Browse executable section",
                "Section " + boundedText(section.name, 160) +
                " has file-backed executable bytes. Its start is not a proven function or program entry.");
            if (!result.leads.empty()) break;
        }
    }
    return result;
}

} // namespace ds
