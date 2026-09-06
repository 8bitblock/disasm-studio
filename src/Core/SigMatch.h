#pragma once
//
// SigMatch.h
// Masked byte-pattern search (signature scanning). A signature is a sequence of
// concrete bytes plus a wildcard mask: mask[i] == false means the i-th position
// is a '??' wildcard that matches any byte. The matcher uses a Boyer-Moore-
// Horspool skip table anchored on the last *concrete* byte (wildcards near the
// tail are skipped so the anchor lands on real data), and falls back to a safe
// linear scan when the pattern is all-wildcards or too short to benefit.
//
// Pure logic over a raw byte span (no BinaryFile / ImGui deps) so it is
// unit-testable and shared by the file scan, the live-memory scan, and the
// capability/byte-pattern detector.
//
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ds {

struct SigPattern {
    std::vector<uint8_t> bytes;   // pattern bytes (wildcard slots hold 0)
    std::vector<bool>    mask;    // mask[i] == true -> concrete byte, false -> '??' wildcard
    size_t size() const { return bytes.size(); }
    bool   empty() const { return bytes.empty(); }
};

// Parse "48 89 ?? 24" / "4889??24" into bytes + mask. A single '?' or a double
// '??' both denote one wildcard byte; spaces are ignored; hex pairs are bytes.
// Returns false on a malformed pattern (bad hex, lone hex nibble) or empty input.
bool ParseSignature(const std::string& text, SigPattern& out);

// Find the first match offset of `pat` in [data, data+n) at or after `from`,
// or SIZE_MAX if none. Wildcard positions match any byte.
size_t FindFirstMasked(const uint8_t* data, size_t n, const SigPattern& pat, size_t from = 0);

// Find all (non-overlapping-by-default? -> overlapping) match offsets of `pat`
// in [data, data+n). Matches may overlap: every starting offset where the
// pattern matches is reported, in ascending order. When `maxHits` > 0 the
// search stops after collecting that many hits.
std::vector<size_t> FindAllMasked(const uint8_t* data, size_t n, const SigPattern& pat, size_t maxHits = 0);

// Apply admission before the hit limit, so file gaps or other excluded spans
// cannot consume the visible-result budget and hide later eligible matches.
// An empty admission callback accepts every match. Offsets remain relative to
// this input span; accepted matches may overlap and remain in ascending order.
std::vector<size_t> FindAllMaskedAccepted(
    const uint8_t* data, size_t n, const SigPattern& pat, size_t maxHits,
    const std::function<bool(size_t)>& admit);

} // namespace ds
