#include "AddressInspector.h"

#include "AddressSpan.h"
#include "BinaryFile.h"
#include "XrefIndex.h"

#include <algorithm>
#include <cctype>

namespace ds {
namespace {

bool contains(uint64_t start, uint64_t size, uint64_t address) {
    return size != 0 && address >= start && address - start < size;
}

bool staticAddressMapped(const BinaryFile& binary, uint64_t address,
                         uint64_t& fileOffset, bool& fileBacked) {
    fileBacked = binary.vaToOffset(address, fileOffset);
    if (fileBacked) return true;
    if (!binary.loaded() || address < binary.imageBase()) return false;

    const uint64_t rva = address - binary.imageBase();
    for (const Section& section : binary.sections()) {
        if (contains(section.virtualAddress, section.virtualSize, rva)) return true;
    }
    return false;
}

std::string normalizeIdentityPath(std::string value) {
    for (char& ch : value) {
        if (ch == '\\') ch = '/';
        else ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    while (value.size() > 1 && value.back() == '/') value.pop_back();
    return value;
}

std::string leafName(const std::string& value) {
    const std::string normalized = normalizeIdentityPath(value);
    const size_t slash = normalized.find_last_of('/');
    return slash == std::string::npos ? normalized : normalized.substr(slash + 1);
}

void appendEvidence(std::string& destination, const std::string& text) {
    if (text.empty()) return;
    if (!destination.empty()) destination += ' ';
    destination += text;
}

CodeDataKind projectKind(PjDataKind kind) {
    switch (kind) {
        case PjDataKind::Code:         return CodeDataKind::Code;
        case PjDataKind::Data:         return CodeDataKind::Data;
        case PjDataKind::String:       return CodeDataKind::String;
        case PjDataKind::PointerTable: return CodeDataKind::PointerTable;
        case PjDataKind::JumpTable:    return CodeDataKind::JumpTable;
    }
    return CodeDataKind::Unknown;
}

const CodeDataSpan* findClassification(const CodeDataMap& map, uint64_t address) {
    // CodeDataMap's public contract is a sorted, non-overlapping partition. Use
    // one logarithmic lookup rather than sweeping a potentially large map.
    const auto after = std::upper_bound(
        map.spans.begin(), map.spans.end(), address,
        [](uint64_t value, const CodeDataSpan& span) { return value < span.address; });
    if (after == map.spans.begin()) return nullptr;
    const CodeDataSpan& candidate = *std::prev(after);
    return contains(candidate.address, candidate.size, address) ? &candidate : nullptr;
}

void inspectIdentity(const BinaryFile& binary,
                     const AddressInspectorSnapshots& snapshots,
                     AddressInspection& result) {
    const AddressLiveModuleSnapshot* live = snapshots.liveModule;
    result.fileIdentity = binary.path();
    if (!live || !live->valid) {
        result.identity = AddressIdentityState::FileOnly;
        result.identityEvidence = "No live module snapshot was supplied.";
        return;
    }

    result.liveIdentity = !live->path.empty() ? live->path : live->moduleName;
    if (live->size == 0) {
        result.identity = AddressIdentityState::Unverified;
        result.identityEvidence = "The live module snapshot has no mapped extent.";
        return;
    }

    bool staticHashValid = snapshots.staticContentHashValid;
    uint64_t staticHash = snapshots.staticContentHash;
    if (!staticHashValid && snapshots.project && snapshots.project->hash != 0) {
        staticHashValid = true;
        staticHash = snapshots.project->hash;
    }

    if (staticHashValid && live->contentHashValid) {
        if (staticHash != live->contentHash) {
            result.identity = AddressIdentityState::Mismatch;
            result.identityEvidence = "The pristine FILE and LIVE content hashes differ.";
            return;
        }
        result.identity = AddressIdentityState::Match;
        result.mappingConfidence = AddressMappingConfidence::High;
        result.identityEvidence = "Matched FILE and LIVE by pristine content hash.";
    } else {
        const std::string filePath = normalizeIdentityPath(binary.path());
        const std::string livePath = normalizeIdentityPath(live->path);
        if (!filePath.empty() && !livePath.empty() && filePath == livePath) {
            result.identity = AddressIdentityState::Match;
            result.mappingConfidence = AddressMappingConfidence::Medium;
            result.identityEvidence = "Matched FILE and LIVE by normalized full path; no common content hash was supplied.";
        } else {
            const std::string fileLeaf = leafName(binary.path());
            const std::string liveLeaf = leafName(!live->path.empty() ? live->path : live->moduleName);
            if (!fileLeaf.empty() && fileLeaf == liveLeaf) {
                result.identity = AddressIdentityState::Match;
                result.mappingConfidence = AddressMappingConfidence::Low;
                result.identityEvidence = "Matched FILE and LIVE by module filename only; content identity is unverified.";
            } else if (!fileLeaf.empty() && !liveLeaf.empty()) {
                result.identity = AddressIdentityState::Mismatch;
                result.identityEvidence = "The FILE and LIVE module identities do not match.";
                return;
            } else {
                result.identity = AddressIdentityState::Unverified;
                result.identityEvidence = "Insufficient FILE/LIVE identity evidence for runtime translation.";
                return;
            }
        }
    }

    if (!result.staticMapped || !result.rva.valid) {
        appendEvidence(result.identityEvidence,
                       "The queried static address is outside the mapped file image.");
        return;
    }
    if (result.rva.value >= live->size) {
        appendEvidence(result.identityEvidence,
                       "The static RVA is outside the supplied LIVE module extent.");
        return;
    }

    uint64_t runtime = 0;
    if (!CheckedAddressAdd(live->base, result.rva.value, runtime)) {
        appendEvidence(result.identityEvidence,
                       "The LIVE base plus module offset overflows the address space.");
        return;
    }
    result.runtimeModuleOffset = { true, result.rva.value };
    result.runtimeVA = { true, runtime };
}

void inspectXrefs(const XrefIndex* xrefs, uint64_t address,
                  AddressXrefSummary& result) {
    if (!xrefs) return;
    result.valid = true;
    const std::vector<uint64_t>* sources = xrefs->sources(address);
    if (!sources) return;
    result.total = sources->size();
    for (uint64_t source : *sources) {
        const auto access = xrefs->accessOf.find(source);
        if (access == xrefs->accessOf.end()) {
            ++result.controlFlow;
            continue;
        }
        switch (access->second) {
            case 1: ++result.writers; break;
            case 2: ++result.addressReferences; break;
            default: ++result.readers; break;
        }
    }
}

void inspectClassification(const BinaryFile& binary, const CodeDataMap* map,
                           uint64_t address, AddressClassificationInfo& result) {
    if (!map) return;
    if (map->imageRevision != 0 && map->imageRevision != binary.imageRevision()) {
        result.staleSnapshot = true;
        result.evidence = "Classification belongs to an older binary image revision.";
        return;
    }
    const CodeDataSpan* span = findClassification(*map, address);
    if (!span) return;
    result.valid = true;
    result.start = span->address;
    result.size = span->size;
    result.kind = span->kind;
    result.confidence = span->confidence;
    result.evidence = span->evidence;
}

void inspectProject(const ProjectState* project, uint64_t address,
                    AddressInspection& result) {
    if (!project) return;

    if (const auto name = project->names.find(address); name != project->names.end()) {
        result.userNameValid = true;
        result.userName = name->second;
    }
    if (const auto comment = project->comments.find(address); comment != project->comments.end()) {
        result.userCommentValid = true;
        result.userComment = comment->second;
    }

    bool functionExact = false;
    for (size_t i = 0; i < project->functionOverrides.size(); ++i) {
        const PjFunctionOverride& candidate = project->functionOverrides[i];
        const bool exact = candidate.address == address;
        const bool within = candidate.action == PjFunctionAction::Define &&
                            candidate.exactExtentValid &&
                            contains(candidate.address, candidate.exactSize, address);
        if (!exact && !within) continue;
        // An exact record is more specific than an enclosing extent. Within the
        // same specificity, retain vector order and let the later record win.
        if (result.functionOverride.valid && functionExact && !exact) continue;
        result.functionOverride.valid = true;
        result.functionOverride.exactStart = exact;
        result.functionOverride.offset = address - candidate.address;
        result.functionOverride.projectIndex = i;
        result.functionOverride.value = candidate;
        functionExact = exact;
    }

    for (size_t i = 0; i < project->dataOverrides.size(); ++i) {
        const PjDataOverride& candidate = project->dataOverrides[i];
        if (!contains(candidate.address, candidate.size, address)) continue;
        result.dataOverride.valid = true;
        result.dataOverride.offset = address - candidate.address;
        result.dataOverride.projectIndex = i;
        result.dataOverride.value = candidate;
    }

    result.patches.snapshotValid = true;
    for (size_t i = 0; i < project->patches.size(); ++i) {
        const PjPatch& patch = project->patches[i];
        if (patch.bytes.empty() || address < patch.address) continue;
        const uint64_t offset = address - patch.address;
        if (offset >= static_cast<uint64_t>(patch.bytes.size())) continue;

        AddressPatchHit hit;
        hit.applicationIndex = i;
        hit.patchAddress = patch.address;
        hit.patchSize = static_cast<uint64_t>(patch.bytes.size());
        hit.byteOffset = offset;
        hit.patchedByte = patch.bytes[static_cast<size_t>(offset)];
        if (offset < static_cast<uint64_t>(patch.orig.size())) {
            hit.originalByteValid = true;
            hit.originalByte = patch.orig[static_cast<size_t>(offset)];
            if (!result.patches.pristineByteValid) {
                result.patches.pristineByteValid = true;
                result.patches.pristineByte = hit.originalByte;
            }
        }
        result.patches.hits.push_back(hit);
    }
    if (!result.patches.hits.empty()) {
        result.patches.patched = true;
        result.patches.hits.back().winner = true;
        result.patches.effectiveByteValid = true;
        result.patches.effectiveByte = result.patches.hits.back().patchedByte;
    }
}

} // namespace

AddressInspection InspectAddress(const BinaryFile& binary, uint64_t staticVA,
                                 const AddressInspectorSnapshots& snapshots) {
    AddressInspection result;
    result.staticVA = { true, staticVA };

    uint64_t fileOffset = 0;
    bool fileBacked = false;
    result.staticMapped = staticAddressMapped(binary, staticVA, fileOffset, fileBacked);
    if (fileBacked) result.fileOffset = { true, fileOffset };
    if (result.staticMapped && staticVA >= binary.imageBase())
        result.rva = { true, staticVA - binary.imageBase() };

    inspectXrefs(snapshots.xrefs, staticVA, result.xrefs);
    inspectClassification(binary, snapshots.classification, staticVA,
                          result.derivedClassification);
    inspectProject(snapshots.project, staticVA, result);

    result.effectiveClassification = result.derivedClassification;
    if (result.dataOverride.valid) {
        result.effectiveClassification.valid = true;
        result.effectiveClassification.staleSnapshot = false;
        result.effectiveClassification.analyst = true;
        result.effectiveClassification.start = result.dataOverride.value.address;
        result.effectiveClassification.size = result.dataOverride.value.size;
        result.effectiveClassification.kind = projectKind(result.dataOverride.value.kind);
        result.effectiveClassification.confidence = CodeDataConfidence::High;
        result.effectiveClassification.type = result.dataOverride.value.type;
        result.effectiveClassification.evidence = "Authoritative analyst data/type override.";
    }

    inspectIdentity(binary, snapshots, result);
    return result;
}

const char* AddressIdentityStateName(AddressIdentityState state) {
    switch (state) {
        case AddressIdentityState::FileOnly:  return "FILE only";
        case AddressIdentityState::Match:     return "FILE/LIVE match";
        case AddressIdentityState::Mismatch:  return "FILE/LIVE mismatch";
        case AddressIdentityState::Unverified:return "FILE/LIVE unverified";
    }
    return "FILE/LIVE unverified";
}

const char* AddressMappingConfidenceName(AddressMappingConfidence confidence) {
    switch (confidence) {
        case AddressMappingConfidence::None:   return "none";
        case AddressMappingConfidence::Low:    return "low";
        case AddressMappingConfidence::Medium: return "medium";
        case AddressMappingConfidence::High:   return "high";
    }
    return "none";
}

} // namespace ds
