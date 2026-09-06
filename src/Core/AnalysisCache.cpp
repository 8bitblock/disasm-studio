// AnalysisCache.cpp — see AnalysisCache.h.
#include "AnalysisCache.h"

#include "Project.h"

#include <algorithm>
#include <limits>
#include <string_view>

namespace ds {

namespace {

// A small deterministic framed hasher. Length prefixes keep adjacent variable
// fields unambiguous ("ab"+"c" cannot alias "a"+"bc").
class DigestBuilder {
public:
    void u8(uint8_t value) { byte(value); }
    void u32(uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) byte(static_cast<uint8_t>(value >> (i * 8)));
    }
    void u64(uint64_t value) {
        for (unsigned i = 0; i < 8; ++i) byte(static_cast<uint8_t>(value >> (i * 8)));
    }
    void bytes(const uint8_t* data, size_t size) {
        u64(static_cast<uint64_t>(size));
        if (!data) return;
        for (size_t i = 0; i < size; ++i) byte(data[i]);
    }
    void string(std::string_view value) {
        bytes(reinterpret_cast<const uint8_t*>(value.data()), value.size());
    }
    uint64_t finish() const { return value_; }

private:
    void byte(uint8_t value) {
        value_ ^= value;
        value_ *= 1099511628211ull;
    }
    uint64_t value_ = 1469598103934665603ull;
};

static size_t mix(size_t seed, uint64_t value) noexcept {
    constexpr uint64_t k = 0x9E3779B97F4A7C15ull;
    const uint64_t widened = static_cast<uint64_t>(seed);
    return static_cast<size_t>(widened ^ (value + k + (widened << 6) + (widened >> 2)));
}

} // namespace

bool AnalysisCacheKey::operator==(const AnalysisCacheKey& other) const noexcept {
    return pristineHash == other.pristineHash &&
           orderedPatchDigest == other.orderedPatchDigest &&
           analystOverrideDigest == other.analystOverrideDigest &&
           passInputsDigest == other.passInputsDigest &&
           schemaVersion == other.schemaVersion && arch == other.arch &&
           effectiveEngine == other.effectiveEngine && byteOrder == other.byteOrder &&
           decoderFeatureBits == other.decoderFeatureBits && pass == other.pass &&
           guessNames == other.guessNames;
}

size_t AnalysisCacheKeyHash::operator()(const AnalysisCacheKey& key) const noexcept {
    size_t out = static_cast<size_t>(key.pristineHash);
    out = mix(out, key.orderedPatchDigest);
    out = mix(out, key.analystOverrideDigest);
    out = mix(out, key.passInputsDigest);
    out = mix(out, key.schemaVersion);
    out = mix(out, static_cast<uint64_t>(key.arch));
    out = mix(out, static_cast<uint64_t>(key.effectiveEngine));
    out = mix(out, static_cast<uint64_t>(key.byteOrder));
    out = mix(out, key.decoderFeatureBits);
    out = mix(out, static_cast<uint64_t>(key.pass));
    out = mix(out, key.guessNames ? 1u : 0u);
    return out;
}

AnalysisCacheKey MakeAnalysisCacheKey(uint64_t pristineHash,
                                      uint64_t orderedPatchDigest,
                                      const DecoderConfig& decoder,
                                      bool guessNames,
                                      uint64_t analystOverrideDigest,
                                      AnalysisCachePass pass,
                                      uint64_t passInputsDigest,
                                      uint32_t schemaVersion) {
    AnalysisCacheKey key;
    key.pristineHash = pristineHash;
    key.orderedPatchDigest = orderedPatchDigest;
    key.analystOverrideDigest = analystOverrideDigest;
    key.passInputsDigest = passInputsDigest;
    key.schemaVersion = schemaVersion;
    key.arch = decoder.arch;
    key.effectiveEngine = EffectiveDisasmEngine(decoder.engine, decoder.arch);
    key.byteOrder = decoder.byteOrder;
    key.decoderFeatureBits = DecoderFeatureBits(decoder.features);
    key.pass = pass;
    key.guessNames = guessNames;
    return key;
}

AnalysisCacheKey MakeAnalysisCacheKey(uint64_t pristineHash,
                                      uint64_t orderedPatchDigest,
                                      Arch arch, Engine requestedEngine,
                                      bool guessNames,
                                      uint64_t analystOverrideDigest,
                                      AnalysisCachePass pass,
                                      uint64_t passInputsDigest,
                                      uint32_t schemaVersion) {
    DecoderConfig decoder;
    decoder.engine = requestedEngine;
    decoder.arch = arch;
    return MakeAnalysisCacheKey(pristineHash, orderedPatchDigest, decoder,
                                guessNames, analystOverrideDigest, pass,
                                passInputsDigest, schemaVersion);
}

uint64_t DigestOrderedPatches(const std::vector<PjPatch>& patches) {
    if (patches.empty()) return 0;
    DigestBuilder digest;
    digest.u64(static_cast<uint64_t>(patches.size()));
    uint64_t ordinal = 0;
    for (const PjPatch& patch : patches) {
        digest.u64(ordinal++); // explicitly bind application order
        digest.u64(patch.address);
        digest.bytes(patch.orig.data(), patch.orig.size());
        digest.bytes(patch.bytes.data(), patch.bytes.size());
    }
    return digest.finish();
}

uint64_t DigestAnalysisOverrides(const ProjectAnalysisOverrides* overrides) {
    if (!overrides || overrides->empty()) return 0;
    DigestBuilder digest;
    digest.u64(static_cast<uint64_t>(overrides->functions.size()));
    for (const PjFunctionOverride& fn : overrides->functions) {
        digest.u64(fn.address);
        digest.u8(static_cast<uint8_t>(fn.action));
        digest.u8(fn.exactExtentValid ? 1u : 0u);
        digest.u64(fn.exactSize);
        digest.u8(static_cast<uint8_t>(fn.noreturn));
        digest.string(fn.callingConvention);
        digest.string(fn.prototype);
        digest.u8(static_cast<uint8_t>(fn.mode));
    }
    digest.u64(static_cast<uint64_t>(overrides->data.size()));
    for (const PjDataOverride& span : overrides->data) {
        digest.u64(span.address);
        digest.u64(span.size);
        digest.u8(static_cast<uint8_t>(span.kind));
        digest.string(span.type);
    }
    return digest.finish();
}

AnalysisCache::AnalysisCache(size_t maxEntries, size_t maxBytes)
    : maxEntries_(maxEntries), maxBytes_(maxBytes) {}

std::shared_ptr<const void> AnalysisCache::findErased(const AnalysisCacheKey& key,
                                                       const void* type) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = index_.find(key);
    if (found == index_.end() || found->second->type != type) {
        ++stats_.misses;
        return {};
    }
    lru_.splice(lru_.begin(), lru_, found->second);
    ++stats_.hits;
    return found->second->value;
}

void AnalysisCache::eraseEntry(Lru::iterator it, bool eviction) {
    if (it == lru_.end()) return;
    stats_.bytes = it->bytes > stats_.bytes ? 0 : stats_.bytes - it->bytes;
    index_.erase(it->key);
    lru_.erase(it);
    if (eviction) ++stats_.evictions;
    stats_.entries = lru_.size();
}

void AnalysisCache::putErased(const AnalysisCacheKey& key,
                              std::shared_ptr<const void> value,
                              const void* type, size_t approximateBytes) {
    if (!value || !maxEntries_ || !maxBytes_) return;
    approximateBytes = std::max<size_t>(1, approximateBytes);
    if (approximateBytes > maxBytes_) return; // one result cannot monopolize the cache

    std::lock_guard<std::mutex> lock(mutex_);
    if (const auto found = index_.find(key); found != index_.end())
        eraseEntry(found->second, false);

    while (!lru_.empty() &&
           (lru_.size() >= maxEntries_ || approximateBytes > maxBytes_ - stats_.bytes))
        eraseEntry(std::prev(lru_.end()), true);

    lru_.push_front({ key, std::move(value), type, approximateBytes });
    index_[key] = lru_.begin();
    stats_.bytes += approximateBytes;
    stats_.entries = lru_.size();
    ++stats_.inserts;
}

void AnalysisCache::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    lru_.clear();
    index_.clear();
    stats_.entries = 0;
    stats_.bytes = 0;
}

AnalysisCacheStats AnalysisCache::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

} // namespace ds
