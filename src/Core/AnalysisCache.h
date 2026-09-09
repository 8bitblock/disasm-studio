#pragma once
//
// AnalysisCache.h
// Bounded, thread-safe in-memory cache for deterministic derived-analysis passes.
// Keys deliberately describe every input which may change a result: pristine
// binary identity, ordered patch history, ISA/effective decoder, analysis schema,
// name-guess policy, authoritative analyst overrides, and pass-specific inputs.
//
// The cache is type-erased internally so AnalysisService can retain immutable
// pass snapshots without coupling this dependency-light container to every result
// model. Typed find/put wrappers reject an accidental payload-type mismatch.
//

#include "../Disasm/IDisassembler.h"

#include <cstddef>
#include <cstdint>
#include <list>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace ds {

struct PjPatch;
struct ProjectAnalysisOverrides;

// Bump whenever the meaning or serialization of a cached derived result changes.
// This is intentionally independent of the on-disk project format version.
inline constexpr uint32_t kAnalysisSchemaVersion = 7;

enum class AnalysisCachePass : uint8_t {
    Strings = 0,
    Functions,
    Listing,
    ListingPrefix,
    Xref,
    Intent,
    CallGraph,
    CrackmeTriage,
    Decompile,
};

struct AnalysisCacheKey {
    uint64_t pristineHash = 0;
    uint64_t orderedPatchDigest = 0;
    uint64_t analystOverrideDigest = 0;
    uint64_t passInputsDigest = 0;
    uint32_t schemaVersion = kAnalysisSchemaVersion;
    Arch arch = Arch::X64;
    Engine effectiveEngine = Engine::Zydis;
    ByteOrder byteOrder = ByteOrder::Little;
    uint32_t decoderFeatureBits = 0;
    AnalysisCachePass pass = AnalysisCachePass::Strings;
    bool guessNames = false;

    bool operator==(const AnalysisCacheKey& other) const noexcept;
};

struct AnalysisCacheKeyHash {
    size_t operator()(const AnalysisCacheKey& key) const noexcept;
};

// Normalizes a requested backend through EffectiveDisasmEngine(). Non-x86
// Zydis/Capstone menu choices therefore share one Capstone/JVM cache identity.
AnalysisCacheKey MakeAnalysisCacheKey(uint64_t pristineHash,
                                      uint64_t orderedPatchDigest,
                                      const DecoderConfig& decoder,
                                      bool guessNames,
                                      uint64_t analystOverrideDigest,
                                      AnalysisCachePass pass,
                                      uint64_t passInputsDigest = 0,
                                      uint32_t schemaVersion = kAnalysisSchemaVersion);

// Compatibility shorthand for callers whose inputs are inherently
// little-endian and use the default decoder feature set.
AnalysisCacheKey MakeAnalysisCacheKey(uint64_t pristineHash,
                                      uint64_t orderedPatchDigest,
                                      Arch arch, Engine requestedEngine,
                                      bool guessNames,
                                      uint64_t analystOverrideDigest,
                                      AnalysisCachePass pass,
                                      uint64_t passInputsDigest = 0,
                                      uint32_t schemaVersion = kAnalysisSchemaVersion);

// Order and record boundaries are load-bearing. Later overlapping patches win,
// so swapping two records must produce a different digest even when their final
// address set is identical. Empty histories use the compact canonical value 0.
uint64_t DigestOrderedPatches(const std::vector<PjPatch>& patches);

// Digest an immutable ProjectAnalysisOverrides worker snapshot. Every persisted
// authority field participates; nullptr and an empty snapshot are equivalent.
uint64_t DigestAnalysisOverrides(const ProjectAnalysisOverrides* overrides);

struct AnalysisCacheStats {
    uint64_t hits = 0;
    uint64_t misses = 0;
    uint64_t inserts = 0;
    uint64_t evictions = 0;
    size_t entries = 0;
    size_t bytes = 0;
};

class AnalysisCache {
public:
    explicit AnalysisCache(size_t maxEntries = 96,
                           size_t maxBytes = 256u * 1024u * 1024u);

    AnalysisCache(const AnalysisCache&) = delete;
    AnalysisCache& operator=(const AnalysisCache&) = delete;

    template <typename T>
    std::shared_ptr<const T> find(const AnalysisCacheKey& key) {
        std::shared_ptr<const void> erased = findErased(key, typeToken<T>());
        return std::static_pointer_cast<const T>(std::move(erased));
    }

    template <typename T>
    void put(const AnalysisCacheKey& key, std::shared_ptr<const T> value,
             size_t approximateBytes) {
        putErased(key, std::move(value), typeToken<T>(), approximateBytes);
    }

    void clear();
    AnalysisCacheStats stats() const;

    // Check immutable capacity before allocating a potentially large snapshot.
    // Current occupancy does not matter: put() evicts old entries as needed.
    bool canStore(size_t approximateBytes) const noexcept {
        return maxEntries_ && maxBytes_ && approximateBytes <= maxBytes_;
    }

private:
    template <typename T>
    static const void* typeToken() {
        static const int token = 0;
        return &token;
    }

    struct Entry {
        AnalysisCacheKey key;
        std::shared_ptr<const void> value;
        const void* type = nullptr;
        size_t bytes = 0;
    };
    using Lru = std::list<Entry>;

    std::shared_ptr<const void> findErased(const AnalysisCacheKey& key,
                                           const void* type);
    void putErased(const AnalysisCacheKey& key,
                   std::shared_ptr<const void> value,
                   const void* type, size_t approximateBytes);
    void eraseEntry(Lru::iterator it, bool eviction);

    const size_t maxEntries_;
    const size_t maxBytes_;
    mutable std::mutex mutex_;
    Lru lru_; // most recently used at front
    std::unordered_map<AnalysisCacheKey, Lru::iterator, AnalysisCacheKeyHash> index_;
    AnalysisCacheStats stats_;
};

} // namespace ds
