#pragma once
//
// InvestigationIndex.h
// Pure, bounded search foundation for the unified investigation omnibox.
//
// Callers take immutable snapshots of UI-owned/static/live state and rebuild the
// index on a worker.  This module never reads BinaryFile, Project, Debugger, or
// sockets, and makes no assumptions about a render thread.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "DebugTargetIdentity.h"

namespace ds {

enum class InvestigationIdentity : uint8_t {
    File,
    Live,
};

// Address validity is explicit: zero is a normal, navigable VA.
struct InvestigationAddress {
    InvestigationIdentity identity = InvestigationIdentity::File;
    bool valid = false;
    uint64_t value = 0;
};

struct InvestigationFunction {
    InvestigationAddress location;
    std::string name;
    std::string prototype;
    std::string evidence;
};

struct InvestigationString {
    InvestigationAddress location;
    std::string text;
    std::string encoding;
    std::string evidence;
};

struct InvestigationImport {
    InvestigationAddress location;
    std::string name;
    std::string module;
    bool delayed = false;
    std::string evidence;
};

struct InvestigationComment {
    InvestigationAddress location;
    std::string text;
    std::string evidence;
};

struct InvestigationResource {
    InvestigationAddress location;
    std::string type;
    std::string name;
    std::string language;
    std::string evidence;
};

struct InvestigationByteResult {
    InvestigationAddress location;
    std::string preview;
    std::string evidence;
};

struct InvestigationXref {
    InvestigationAddress source;
    InvestigationAddress target;
    std::string context;
    std::string evidence;
};

struct InvestigationLiveModule {
    InvestigationAddress base;
    uint64_t size = 0;
    std::string name;
    std::string path;
    std::string evidence;
};

// One offline endpoint/server clue from the crackme-triage pass. A FILE
// location is optional because overlay-only strings are still useful evidence
// but cannot be navigated as a virtual address.
struct InvestigationNetworkTrail {
    InvestigationAddress location;
    uint64_t fileOffset = 0;
    bool fileOffsetValid = false;
    std::string endpoint;
    std::string role;
    std::string evidence;
};

// One searchable stage in an authorization chain. `flowId` is an opaque,
// producer-stable identity used to focus the complete flow in Triage;
// address/file-offset validity remain independent so zero is representable.
struct InvestigationAuthorization {
    InvestigationAddress location;
    uint64_t fileOffset = 0;
    bool fileOffsetValid = false;
    std::string flowId;
    std::string label;
    std::string stage;
    std::string outcome;
    std::string stateIdentity;
    std::string evidence;
    // Exact write/read/startup-gate correlation from AuthorizationAnalysis.
    // The index uses this typed fact to add the deterministic "remembered"
    // search alias without confusing explicitly unlinked operations.
    bool rememberedAccessLinked = false;
};

struct InvestigationRecentQuery {
    InvestigationIdentity identity = InvestigationIdentity::File;
    std::string query;
};

struct InvestigationSnapshot {
    std::vector<InvestigationFunction> functions;
    std::vector<InvestigationString> strings;
    std::vector<InvestigationImport> imports;
    std::vector<InvestigationComment> comments;
    std::vector<InvestigationResource> resources;
    std::vector<InvestigationByteResult> byteResults;
    std::vector<InvestigationXref> xrefs;
    std::vector<InvestigationLiveModule> liveModules;
    std::vector<InvestigationNetworkTrail> networkTrail;
    std::vector<InvestigationAuthorization> authorization;
    std::vector<InvestigationRecentQuery> recentQueries;
    // Owner of every LIVE address in this immutable snapshot. Empty means the
    // snapshot contains no live navigation authority.
    DebugTargetIdentity liveTarget;
};

// These ceilings cannot be raised by a caller.  Lower values are useful for a
// document-specific policy and for deterministic low-memory tests.
inline constexpr size_t kInvestigationHardMaxRecords = 250000;
inline constexpr size_t kInvestigationHardMaxResults = 256;
inline constexpr size_t kInvestigationHardMaxFieldBytes = 16 * 1024;
inline constexpr size_t kInvestigationHardMaxSearchBytes = 32 * 1024;
inline constexpr size_t kInvestigationHardMaxQueryBytes = 1024;
inline constexpr size_t kInvestigationHardMaxTotalTextBytes = 64 * 1024 * 1024;

struct InvestigationLimits {
    size_t maxFunctions = 50000;
    size_t maxStrings = 75000;
    size_t maxImports = 25000;
    size_t maxComments = 50000;
    size_t maxResources = 25000;
    size_t maxByteResults = 50000;
    size_t maxXrefs = 100000;
    size_t maxLiveModules = 4096;
    size_t maxNetworkTrail = 4096;
    size_t maxAuthorization = 4096;
    size_t maxRecentQueries = 256;
    size_t maxTotalRecords = 150000;
    size_t maxResults = 128;
    size_t maxFieldBytes = 4096;
    size_t maxSearchBytes = 8192;
    size_t maxQueryBytes = 512;
    // Counts all retained display/evidence strings and normalized search keys.
    size_t maxTotalTextBytes = 32 * 1024 * 1024;
};

InvestigationLimits BoundInvestigationLimits(const InvestigationLimits& requested) noexcept;

enum class InvestigationAddressParseStatus : uint8_t {
    NotAddress,
    Valid,
    Malformed,
    Overflow,
};

struct InvestigationParsedAddress {
    InvestigationAddressParseStatus status = InvestigationAddressParseStatus::NotAddress;
    InvestigationIdentity identity = InvestigationIdentity::File;
    uint64_t value = 0;
};

// Accepted exact forms are 0x401000, 401000h, bare hexadecimal beginning with
// a digit, and 0d1234.  file:/va: and live: select the address identity.
InvestigationParsedAddress ParseInvestigationAddress(std::string_view query) noexcept;

enum class InvestigationCategory : uint8_t {
    Address,
    Function,
    StringLiteral,
    Import,
    Comment,
    Resource,
    ByteResult,
    Xref,
    LiveModule,
    NetworkTrail,
    Authorization,
    RecentQuery,
};

enum class InvestigationMatchKind : uint8_t {
    ExactAddress,
    ExactText,
    Prefix,
    TokenPrefix,
    Substring,
    Fuzzy,
};

struct InvestigationResult {
    InvestigationCategory category = InvestigationCategory::Address;
    InvestigationAddress location;
    uint64_t fileOffset = 0;
    bool fileOffsetValid = false;
    InvestigationMatchKind match = InvestigationMatchKind::Fuzzy;
    uint32_t score = 0;
    uint64_t stableOrder = 0;
    std::string label;
    std::string detail;
    std::string evidence;
    std::string focusId; // opaque stable identity for a compound result
};

using InvestigationCancel = std::function<bool()>;

struct InvestigationBuildStats {
    uint64_t inputRecords = 0;
    uint64_t acceptedRecords = 0;
    uint64_t droppedRecords = 0;
    uint64_t truncatedStrings = 0;
    uint64_t retainedTextBytes = 0;
};

class InvestigationIndex;

struct InvestigationBuildResult {
    bool complete = false;
    bool cancelled = false;
    bool truncated = false;
    std::string error;
    InvestigationBuildStats stats;
    std::shared_ptr<const InvestigationIndex> index;
};

struct InvestigationSearchOptions {
    size_t maxResults = 64;
};

struct InvestigationSearchResult {
    bool complete = false;
    bool cancelled = false;
    bool truncated = false;
    bool invalidQuery = false;
    std::string error;
    InvestigationParsedAddress parsedAddress;
    std::vector<InvestigationResult> results;
};

class InvestigationIndex {
public:
    InvestigationIndex(const InvestigationIndex&) = delete;
    InvestigationIndex& operator=(const InvestigationIndex&) = delete;

    static InvestigationBuildResult Build(
        const InvestigationSnapshot& snapshot,
        const InvestigationLimits& limits = {},
        const InvestigationCancel& cancelled = {}) noexcept;

    InvestigationSearchResult search(
        std::string_view query,
        const InvestigationSearchOptions& options = {},
        const InvestigationCancel& cancelled = {}) const noexcept;

    size_t size() const noexcept;
    const InvestigationLimits& limits() const noexcept;
    const InvestigationBuildStats& stats() const noexcept;

private:
    InvestigationIndex() = default;

    struct Record {
        InvestigationCategory category = InvestigationCategory::Address;
        InvestigationAddress location;
        InvestigationAddress relatedLocation;
        uint64_t fileOffset = 0;
        bool fileOffsetValid = false;
        uint64_t spanSize = 0;
        uint64_t stableOrder = 0;
        std::string label;
        std::string detail;
        std::string evidence;
        std::string focusId;
        std::string searchKey;
    };

    InvestigationLimits limits_;
    InvestigationBuildStats stats_;
    std::vector<Record> records_;
};

} // namespace ds
