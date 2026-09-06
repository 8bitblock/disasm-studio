#include "SigMatch.h"

#include <cctype>
#include <cstdio>

namespace ds {

bool ParseSignature(const std::string& in, SigPattern& out) {
    out.bytes.clear();
    out.mask.clear();
    for (size_t i = 0; i < in.size();) {
        unsigned char ch = (unsigned char)in[i];
        if (std::isspace(ch)) { ++i; continue; }
        if (in[i] == '?') {
            // A lone '?' or a '??' pair both mean one wildcard byte.
            out.bytes.push_back(0);
            out.mask.push_back(false);
            i += (i + 1 < in.size() && in[i + 1] == '?') ? 2 : 1;
        } else {
            // Require a full two-hex-digit byte. sscanf("%x") on "4Z" would read
            // only the '4', report success, and then `i += 2` would skip past the
            // bad nibble -- silently accepting a malformed pattern. Reject instead.
            if (i + 1 >= in.size() ||
                !std::isxdigit((unsigned char)in[i]) || !std::isxdigit((unsigned char)in[i + 1]))
                return false;
            char buf[3] = { in[i], in[i + 1], 0 };
            unsigned v = 0;
            if (std::sscanf(buf, "%x", &v) != 1) return false;
            out.bytes.push_back((uint8_t)v);
            out.mask.push_back(true);
            i += 2;
        }
    }
    return !out.bytes.empty();
}

namespace {

// Does `pat` match the window starting at data[pos]? Caller guarantees the
// whole pattern fits (pos + m <= n).
inline bool matchAt(const uint8_t* data, const SigPattern& pat, size_t pos) {
    const size_t m = pat.bytes.size();
    for (size_t j = 0; j < m; ++j)
        if (pat.mask[j] && data[pos + j] != pat.bytes[j]) return false;
    return true;
}

} // namespace

size_t FindFirstMasked(const uint8_t* data, size_t n, const SigPattern& pat, size_t from) {
    const size_t m = pat.bytes.size();
    if (m == 0 || n < m) return SIZE_MAX;
    if (from > n - m) return SIZE_MAX;

    // Anchor on the last concrete (non-wildcard) byte. Wildcards at the tail are
    // skipped so the BMH skip table keys off real data; the anchor is the index
    // of the rightmost mask[]==true within the pattern.
    size_t anchor = m;                 // m == "no concrete byte found"
    for (size_t j = m; j-- > 0;) {
        if (pat.mask[j]) { anchor = j; break; }
    }

    // All-wildcard pattern: every window of length m matches. The first match at
    // or after `from` is simply `from` itself.
    if (anchor == m) return from;

    // Patterns short enough that BMH gives no benefit (anchor too close to the
    // front) just use the safe linear scan.
    if (anchor < 1) {
        for (size_t i = from; i + m <= n; ++i)
            if (matchAt(data, pat, i)) return i;
        return SIZE_MAX;
    }

    // Bad-character skip table keyed by the text byte that landed on the anchor.
    // For text byte `tc` we want the *smallest* safe shift s>=1 such that after
    // shifting, the pattern position now under the anchor (index anchor-s) can
    // still match `tc` — i.e. that position is a wildcard OR its concrete byte
    // equals `tc`. Wildcards therefore CAP the shift (they could align anything),
    // which is what makes BMH correct in the presence of '??'. If no prefix
    // position can host `tc`, shift the whole pattern past it (anchor+1).
    //
    // Build it in one O(256 + anchor) pass: walk j from anchor-1 down to 0; the
    // first time we see byte v we record skip[v]=anchor-j (smallest shift for v),
    // and the first wildcard we see caps EVERY still-default entry at that shift
    // and ends the walk (no earlier position can give a larger safe shift).
    size_t skip[256];
    for (size_t k = 0; k < 256; ++k) skip[k] = anchor + 1;   // provisional: past the prefix
    bool set[256] = { false };
    for (size_t j = anchor; j-- > 0;) {
        size_t s = anchor - j;
        if (!pat.mask[j]) {                 // wildcard: caps all unset entries, then stop
            for (size_t k = 0; k < 256; ++k) if (!set[k]) { skip[k] = s; set[k] = true; }
            break;
        }
        uint8_t v = pat.bytes[j];
        if (!set[v]) { skip[v] = s; set[v] = true; }
    }

    const uint8_t anchorByte = pat.bytes[anchor];
    // i is the candidate start; the anchor byte sits at data[i + anchor].
    for (size_t i = from; i + m <= n;) {
        uint8_t tc = data[i + anchor];
        if (tc == anchorByte && matchAt(data, pat, i)) return i;
        i += skip[tc];
    }
    return SIZE_MAX;
}

std::vector<size_t> FindAllMasked(const uint8_t* data, size_t n, const SigPattern& pat, size_t maxHits) {
    return FindAllMaskedAccepted(data, n, pat, maxHits, {});
}

std::vector<size_t> FindAllMaskedAccepted(
    const uint8_t* data, size_t n, const SigPattern& pat, size_t maxHits,
    const std::function<bool(size_t)>& admit) {
    std::vector<size_t> hits;
    const size_t m = pat.bytes.size();
    if (m == 0 || n < m) return hits;

    size_t pos = 0;
    while (pos + m <= n) {
        size_t at = FindFirstMasked(data, n, pat, pos);
        if (at == SIZE_MAX) break;
        if (!admit || admit(at)) {
            hits.push_back(at);
            if (maxHits && hits.size() >= maxHits) break;
        }
        // Allow overlapping matches: resume one byte past this match's start.
        pos = at + 1;
    }
    return hits;
}

} // namespace ds
