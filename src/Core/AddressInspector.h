#pragma once
//
// AddressInspector.h
// Pure, bounded address-identity projection for the investigation UI.  The
// caller supplies immutable snapshots; this module never reads a process,
// opens a file, hashes the image, or decodes instructions.
//

#include "CodeDataClassifier.h"
#include "Project.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

class BinaryFile;
struct XrefIndex;

struct AddressValue {
    bool     valid = false;
    uint64_t value = 0;
};

enum class AddressIdentityState : uint8_t {
    FileOnly = 0,
    Match,
    Mismatch,
    Unverified,
};

enum class AddressMappingConfidence : uint8_t {
    None = 0,
    Low,
    Medium,
    High,
};

// A UI/worker-owned snapshot of one live module. `valid` is explicit because a
// runtime base of zero is legitimate. A content hash, when available on both
// sides, is authoritative; otherwise path/name matching is conservative.
struct AddressLiveModuleSnapshot {
    bool        valid = false;
    uint64_t    base = 0;
    uint64_t    size = 0;
    std::string moduleName;
    std::string path;
    bool        contentHashValid = false;
    uint64_t    contentHash = 0;
};

struct AddressInspectorSnapshots {
    const ProjectState* project = nullptr;
    const XrefIndex*    xrefs = nullptr;
    const CodeDataMap*  classification = nullptr;
    const AddressLiveModuleSnapshot* liveModule = nullptr;

    // Supplying the already-known pristine hash avoids accidentally turning an
    // address lookup into a whole-image hashing operation. If omitted, a
    // non-zero ProjectState::hash is used as the persisted file identity.
    bool     staticContentHashValid = false;
    uint64_t staticContentHash = 0;
};

struct AddressXrefSummary {
    bool   valid = false;
    size_t total = 0;
    size_t readers = 0;
    size_t writers = 0;
    size_t addressReferences = 0;
    size_t controlFlow = 0;
};

struct AddressClassificationInfo {
    bool               valid = false;
    bool               staleSnapshot = false;
    bool               analyst = false;
    uint64_t           start = 0;
    uint64_t           size = 0;
    CodeDataKind       kind = CodeDataKind::Unknown;
    CodeDataConfidence confidence = CodeDataConfidence::Low;
    std::string        type;
    std::string        evidence;
};

struct AddressFunctionOverrideInfo {
    bool               valid = false;
    bool               exactStart = false;
    uint64_t           offset = 0;
    size_t             projectIndex = 0;
    PjFunctionOverride value;
};

struct AddressDataOverrideInfo {
    bool           valid = false;
    uint64_t       offset = 0;
    size_t         projectIndex = 0;
    PjDataOverride value;
};

// One patch touching the queried byte. Entries retain ProjectState::patches
// order, which is application order. Exactly the final entry has `winner=true`.
struct AddressPatchHit {
    size_t   applicationIndex = 0;
    uint64_t patchAddress = 0;
    uint64_t patchSize = 0;
    uint64_t byteOffset = 0;
    bool     originalByteValid = false;
    uint8_t  originalByte = 0;
    uint8_t  patchedByte = 0;
    bool     winner = false;
};

struct AddressPatchSummary {
    bool                         snapshotValid = false;
    bool                         patched = false;
    bool                         pristineByteValid = false;
    uint8_t                      pristineByte = 0;
    bool                         effectiveByteValid = false;
    uint8_t                      effectiveByte = 0;
    std::vector<AddressPatchHit> hits;
};

struct AddressInspection {
    // The query itself is always explicit and therefore always valid, including
    // VA zero. `staticMapped` states whether the BinaryFile owns that address.
    AddressValue staticVA{ true, 0 };
    bool         staticMapped = false;
    AddressValue rva;
    AddressValue fileOffset;
    AddressValue runtimeVA;
    AddressValue runtimeModuleOffset;

    AddressIdentityState      identity = AddressIdentityState::FileOnly;
    AddressMappingConfidence mappingConfidence = AddressMappingConfidence::None;
    std::string               fileIdentity;
    std::string               liveIdentity;
    std::string               identityEvidence;

    AddressXrefSummary            xrefs;
    AddressClassificationInfo     derivedClassification;
    AddressClassificationInfo     effectiveClassification;
    AddressFunctionOverrideInfo   functionOverride;
    AddressDataOverrideInfo       dataOverride;
    AddressPatchSummary           patches;

    bool        userNameValid = false;
    std::string userName;
    bool        userCommentValid = false;
    std::string userComment;
};

// Project/xref/classification vectors are user-sized or bounded metadata
// snapshots and are assumed to obey their normal contracts. Binary bytes are
// never swept; classification lookup is logarithmic and xrefs are target-local.
AddressInspection InspectAddress(const BinaryFile& binary, uint64_t staticVA,
                                 const AddressInspectorSnapshots& snapshots = {});

const char* AddressIdentityStateName(AddressIdentityState state);
const char* AddressMappingConfidenceName(AddressMappingConfidence confidence);

} // namespace ds
