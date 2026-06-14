#include "Inflate.h"

#include <cstring>

// RFC 1951 raw DEFLATE, the classic zlib/puff construct+decode shape:
// canonical Huffman tables as per-bit-length count/offset arrays, bit-by-bit
// canonical walk for decode (correctness over speed). Every read is bounds-
// checked, every loop consumes at least one bit, output is capped at maxOut,
// so malformed input fails instead of crashing or spinning.

namespace {

constexpr int kMaxBits   = 15;  // longest Huffman code
constexpr int kMaxLCodes = 286; // literal/length symbols
constexpr int kMaxDCodes = 30;  // distance symbols
constexpr int kFixLCodes = 288; // fixed litlen table size (286/287 decode then fail)

struct BitReader {
    const uint8_t* d;
    size_t n;
    size_t pos    = 0;
    uint32_t buf  = 0;
    int      cnt  = 0;
    // LSB-first; loads bytes lazily, so leftover after a read is always < 8 bits.
    bool get(int need, uint32_t& v) {
        while (cnt < need) {
            if (pos >= n) return false;
            buf |= (uint32_t)d[pos++] << cnt;
            cnt += 8;
        }
        v = buf & (((uint32_t)1 << need) - 1);
        buf >>= need;
        cnt -= need;
        return true;
    }
    void alignByte() { buf = 0; cnt = 0; }  // drop the partial byte (cnt < 8 invariant)
};

struct Huffman {
    int count[kMaxBits + 1];   // codes per bit length
    int symbol[kFixLCodes];    // canonically sorted symbols
};

// Build the canonical decode tables. Returns 0 = complete, < 0 = oversubscribed,
// > 0 = number of unfilled codes (incomplete; caller decides if that's legal).
// All-zero lengths return 0 like puff does (decode of any symbol then fails).
int construct(Huffman& h, const uint8_t* length, int n) {
    for (int len = 0; len <= kMaxBits; ++len) h.count[len] = 0;
    for (int sym = 0; sym < n; ++sym) ++h.count[length[sym]];
    if (h.count[0] == n) return 0;
    int left = 1;
    for (int len = 1; len <= kMaxBits; ++len) {
        left <<= 1;
        left -= h.count[len];
        if (left < 0) return left;
    }
    int offs[kMaxBits + 1];
    offs[1] = 0;
    for (int len = 1; len < kMaxBits; ++len) offs[len + 1] = offs[len] + h.count[len];
    for (int sym = 0; sym < n; ++sym)
        if (length[sym]) h.symbol[offs[length[sym]]++] = sym;
    return left;
}

// Bit-by-bit canonical walk; -1 = invalid code or input exhausted.
int decode(BitReader& br, const Huffman& h) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= kMaxBits; ++len) {
        uint32_t bit;
        if (!br.get(1, bit)) return -1;
        code |= (int)bit;
        const int cnt = h.count[len];
        if (code - cnt < first) return h.symbol[index + (code - first)];
        index += cnt;
        first = (first + cnt) << 1;
        code <<= 1;
    }
    return -1;
}

// Shared literal/length+distance loop for fixed and dynamic blocks.
bool codes(BitReader& br, const Huffman& lit, const Huffman& dist,
           std::vector<uint8_t>& out, size_t maxOut) {
    static const uint16_t lenBase[29] = {
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31,
        35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
    static const uint8_t lenExtra[29] = {
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
    static const uint16_t distBase[30] = {
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193,
        257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577 };
    static const uint8_t distExtra[30] = {
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };
    for (;;) {
        int sym = decode(br, lit);
        if (sym < 0) return false;
        if (sym < 256) {
            if (out.size() >= maxOut) return false;
            out.push_back((uint8_t)sym);
        } else if (sym == 256) {
            return true;                              // end of block
        } else {
            sym -= 257;
            if (sym >= 29) return false;              // 286/287 are invalid
            uint32_t extra;
            if (!br.get(lenExtra[sym], extra)) return false;
            const size_t len = (size_t)lenBase[sym] + extra;
            const int dsym = decode(br, dist);
            if (dsym < 0 || dsym >= 30) return false; // 30/31 are invalid
            if (!br.get(distExtra[dsym], extra)) return false;
            const size_t d = (size_t)distBase[dsym] + extra;
            if (d > out.size()) return false;         // before the start of output
            if (out.size() > maxOut || len > maxOut - out.size()) return false;
            // byte-at-a-time so overlapping copies (d < len) replicate correctly
            size_t from = out.size() - d;
            for (size_t i = 0; i < len; ++i) out.push_back(out[from + i]);
        }
    }
}

bool storedBlock(BitReader& br, std::vector<uint8_t>& out, size_t maxOut) {
    br.alignByte();
    if (br.pos + 4 > br.n) return false;
    const uint16_t len  = (uint16_t)(br.d[br.pos] | (br.d[br.pos + 1] << 8));
    const uint16_t nlen = (uint16_t)(br.d[br.pos + 2] | (br.d[br.pos + 3] << 8));
    if (len != (uint16_t)~nlen) return false;
    br.pos += 4;
    if (len > br.n - br.pos) return false;
    if (out.size() > maxOut || len > maxOut - out.size()) return false;
    out.insert(out.end(), br.d + br.pos, br.d + br.pos + len);
    br.pos += len;
    return true;
}

struct FixedTables { Huffman lit, dist; };

bool fixedBlock(BitReader& br, std::vector<uint8_t>& out, size_t maxOut) {
    // magic-static: built once, thread-safe
    static const FixedTables t = [] {
        FixedTables f;
        uint8_t lengths[kFixLCodes];
        int sym = 0;
        for (; sym < 144; ++sym) lengths[sym] = 8;
        for (; sym < 256; ++sym) lengths[sym] = 9;
        for (; sym < 280; ++sym) lengths[sym] = 7;
        for (; sym < kFixLCodes; ++sym) lengths[sym] = 8;
        construct(f.lit, lengths, kFixLCodes);
        for (sym = 0; sym < kMaxDCodes; ++sym) lengths[sym] = 5;
        construct(f.dist, lengths, kMaxDCodes);  // incomplete by design (30 of 32)
        return f;
    }();
    return codes(br, t.lit, t.dist, out, maxOut);
}

bool dynamicBlock(BitReader& br, std::vector<uint8_t>& out, size_t maxOut) {
    static const uint8_t order[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    uint32_t hlit, hdist, hclen;
    if (!br.get(5, hlit) || !br.get(5, hdist) || !br.get(4, hclen)) return false;
    const int nlen  = (int)hlit + 257;
    const int ndist = (int)hdist + 1;
    const int ncode = (int)hclen + 4;
    if (nlen > kMaxLCodes || ndist > kMaxDCodes) return false;

    uint8_t lengths[kMaxLCodes + kMaxDCodes] = {};
    for (int i = 0; i < ncode; ++i) {
        uint32_t v;
        if (!br.get(3, v)) return false;
        lengths[order[i]] = (uint8_t)v;
    }
    for (int i = ncode; i < 19; ++i) lengths[order[i]] = 0;
    Huffman clcode;
    if (construct(clcode, lengths, 19) != 0) return false;  // CL code must be complete

    int index = 0;
    const int total = nlen + ndist;
    while (index < total) {
        const int sym = decode(br, clcode);
        if (sym < 0) return false;
        if (sym < 16) {
            lengths[index++] = (uint8_t)sym;
            continue;
        }
        uint8_t rptLen = 0;  // 17/18 repeat zero
        uint32_t rep;
        if (sym == 16) {
            if (index == 0) return false;              // nothing to repeat
            rptLen = lengths[index - 1];
            if (!br.get(2, rep)) return false;
            rep += 3;
        } else if (sym == 17) {
            if (!br.get(3, rep)) return false;
            rep += 3;
        } else {
            if (!br.get(7, rep)) return false;
            rep += 11;
        }
        if ((int)rep > total - index) return false;    // repeat across end
        while (rep--) lengths[index++] = rptLen;
    }
    if (lengths[256] == 0) return false;               // no end-of-block code

    // Incomplete sets are legal only as the RFC single-code edge case (one
    // 1-bit code, zlib-compat); oversubscribed always fails.
    Huffman lit, dist;
    int err = construct(lit, lengths, nlen);
    if (err && (err < 0 || nlen != lit.count[0] + lit.count[1])) return false;
    err = construct(dist, lengths + nlen, ndist);
    if (err && (err < 0 || ndist != dist.count[0] + dist.count[1])) return false;
    return codes(br, lit, dist, out, maxOut);
}

} // namespace

bool InflateRaw(const uint8_t* src, size_t srcLen, std::vector<uint8_t>& out, size_t maxOut) {
    out.clear();
    if (!src && srcLen) return false;
    BitReader br{ src, srcLen };
    uint32_t bfinal;
    do {
        uint32_t btype;
        if (!br.get(1, bfinal) || !br.get(2, btype)) return false;
        bool ok;
        switch (btype) {
            case 0:  ok = storedBlock(br, out, maxOut); break;
            case 1:  ok = fixedBlock(br, out, maxOut); break;
            case 2:  ok = dynamicBlock(br, out, maxOut); break;
            default: return false;                     // BTYPE 11 reserved
        }
        if (!ok) return false;
    } while (!bfinal);
    return true;
}
