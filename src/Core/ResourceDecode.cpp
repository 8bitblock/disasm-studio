//
// ResourceDecode.cpp
// See ResourceDecode.h. Pure decoders for PE resource payloads. Every walk is
// bounded by the passed-in size so a malformed resource cannot over-read.
//
#include "Core/ResourceDecode.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>

namespace ds {

namespace {

inline uint16_t rd16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0] | (p[1] << 8));
}
inline uint32_t rd32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) |
                                 (static_cast<uint32_t>(p[3]) << 24));
}
inline int32_t rds32(const uint8_t* p) { return static_cast<int32_t>(rd32(p)); }

inline void appendUtf8(std::string& out, uint32_t cp) {
    if (cp <= 0x7F) out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

// Round `x` up to a 4-byte boundary (version-info nodes are DWORD aligned).
inline size_t align4(size_t x) { return (x + 3) & ~static_cast<size_t>(3); }

} // namespace

const char* ResourceTypeName(uint32_t typeId) {
    switch (typeId) {
        case 1:  return "RT_CURSOR";
        case 2:  return "RT_BITMAP";
        case 3:  return "RT_ICON";
        case 4:  return "RT_MENU";
        case 5:  return "RT_DIALOG";
        case 6:  return "RT_STRING";
        case 7:  return "RT_FONTDIR";
        case 8:  return "RT_FONT";
        case 9:  return "RT_ACCELERATOR";
        case 10: return "RT_RCDATA";
        case 11: return "RT_MESSAGETABLE";
        case 12: return "RT_GROUP_CURSOR";
        case 14: return "RT_GROUP_ICON";
        case 16: return "RT_VERSION";
        case 17: return "RT_DLGINCLUDE";
        case 19: return "RT_PLUGPLAY";
        case 20: return "RT_VXD";
        case 21: return "RT_ANICURSOR";
        case 22: return "RT_ANIICON";
        case 23: return "RT_HTML";
        case 24: return "RT_MANIFEST";
        default: return nullptr;
    }
}

std::string Utf16LeToUtf8(const uint8_t* p, size_t byteLen, size_t maxUnits) {
    std::string s;
    if (!p) return s;
    const size_t units = std::min(maxUnits, byteLen / 2);
    for (size_t i = 0; i < units;) {
        const uint16_t w = rd16(p + i * 2);
        if (w == 0) break;
        if (w >= 0xD800 && w <= 0xDBFF && i + 1 < units) {
            const uint16_t lo = rd16(p + (i + 1) * 2);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                appendUtf8(s, 0x10000u + ((w - 0xD800u) << 10) + (lo - 0xDC00u));
                i += 2;
                continue;
            }
        }
        appendUtf8(s, w);
        ++i;
    }
    return s;
}

bool LooksLikeText(const uint8_t* data, size_t size) {
    if (!data || size == 0) return false;
    // A UTF-16LE blob (ASCII text with NUL high bytes) is text too; sample it.
    const size_t sample = std::min<size_t>(size, 4096);
    size_t printable = 0, control = 0;
    for (size_t i = 0; i < sample; ++i) {
        const uint8_t c = data[i];
        if (c == 0x09 || c == 0x0A || c == 0x0D) { ++printable; continue; }
        if (c == 0x00) { ++control; continue; }               // UTF-16 padding / binary
        if (c >= 0x20) { ++printable; continue; }
        ++control;
    }
    // Treat as text when almost everything is printable/whitespace. UTF-16 text
    // trips the NUL branch on half its bytes, so allow up to ~55% "control".
    return printable > 0 && control <= (sample * 11) / 20;
}

std::string DecodeVersionInfo(const uint8_t* data, size_t size) {
    if (!data || size < 6) return {};
    const size_t rootLen = rd16(data);
    if (rootLen < 6 || rootLen > size) return {};
    std::string out;
    char line[256];
    auto isStructural = [](const std::string& k) {
        return k == "VS_VERSION_INFO" || k == "StringFileInfo" ||
               k == "VarFileInfo" || k == "StringTable" || k == "Translation";
    };
    size_t collected = 0, visited = 0;
    // Each child is bounded by its own wLength AND its parent's extent. The
    // root's 16-bit length bounds total input work; explicit depth/node caps
    // also prevent pathological nesting. Bytes after the root are not nodes.
    auto walk = [&](auto&& self, size_t off, size_t parentEnd, unsigned depth) -> bool {
        if (depth > 8 || ++visited > 4096 || off > parentEnd || parentEnd - off < 6)
            return false;
        const size_t nodeLen = rd16(data + off);
        const size_t valLen = rd16(data + off + 2);
        const uint16_t type = rd16(data + off + 4);
        if (nodeLen < 6 || nodeLen > parentEnd - off || type > 1) return false;
        const size_t nodeEnd = off + nodeLen;
        const size_t keyStart = off + 6;
        size_t keyEnd = keyStart;
        while (nodeEnd - keyEnd >= 2 && rd16(data + keyEnd) != 0) keyEnd += 2;
        if (nodeEnd - keyEnd < 2) return false; // no key terminator inside this node
        const std::string key = Utf16LeToUtf8(data + keyStart, keyEnd - keyStart);
        const size_t valOff = align4(keyEnd + 2);
        const size_t valueBytes = valLen * (type == 1 ? 2 : 1);
        // Empty values need no alignment padding when the node ends at its key.
        if (valueBytes && (valOff > nodeEnd || valueBytes > nodeEnd - valOff))
            return false;
        if (type == 1 && valueBytes && rd16(data + valOff + valueBytes - 2) != 0)
            return false;
        if (depth == 0) {
            if (key != "VS_VERSION_INFO" || type != 0) return false;
            if (valueBytes >= 52 && rd32(data + valOff) == 0xFEEF04BDu) {
                const uint32_t fileMS = rd32(data + valOff + 8);
                const uint32_t fileLS = rd32(data + valOff + 12);
                const uint32_t prodMS = rd32(data + valOff + 16);
                const uint32_t prodLS = rd32(data + valOff + 20);
                std::snprintf(line, sizeof(line), "File version:    %u.%u.%u.%u\n",
                              fileMS >> 16, fileMS & 0xFFFF, fileLS >> 16, fileLS & 0xFFFF);
                out += line;
                std::snprintf(line, sizeof(line), "Product version: %u.%u.%u.%u\n",
                              prodMS >> 16, prodMS & 0xFFFF, prodLS >> 16, prodLS & 0xFFFF);
                out += line;
            }
        } else if (type == 1 && valLen > 0 && !isStructural(key) && !key.empty() &&
                   collected < 512) {
            const std::string val = Utf16LeToUtf8(data + valOff, valueBytes);
            if (!val.empty()) {
                if (collected == 0) out += "--\n";
                out += key;
                out += ": ";
                out += val;
                out.push_back('\n');
                ++collected;
            }
        }
        // wValueLength is measured in words for text and bytes for binary.
        // Advance by that extent, never by the first NUL in a displayed value.
        for (size_t child = align4(valOff + valueBytes); child < nodeEnd;) {
            if (nodeEnd - child < 6) {
                return nodeEnd - child <= 3 &&
                    std::all_of(data + child, data + nodeEnd, [](uint8_t b) { return b == 0; });
            }
            if (!self(self, child, nodeEnd, depth + 1)) return false;
            child = align4(child + rd16(data + child));
        }
        return true;
    };
    if (!walk(walk, 0, rootLen, 0)) return {};
    return out;
}

std::vector<std::pair<uint32_t, std::string>>
DecodeStringTable(const uint8_t* data, size_t size, uint32_t blockId) {
    std::vector<std::pair<uint32_t, std::string>> out;
    if (!data) return out;
    const uint32_t baseId = (blockId > 0 ? blockId - 1 : 0) * 16;
    size_t off = 0;
    for (uint32_t i = 0; i < 16 && off + 2 <= size; ++i) {
        const uint16_t len = rd16(data + off); // length in UTF-16 code units
        off += 2;
        if (len == 0) continue; // an unused slot
        const size_t avail = (size - off) / 2;
        const size_t units = std::min<size_t>(len, avail);
        std::string s = Utf16LeToUtf8(data + off, units * 2, units);
        out.emplace_back(baseId + i, std::move(s));
        off += units * 2;
    }
    return out;
}

DibInfo DescribeDib(const uint8_t* data, size_t size) {
    DibInfo info;
    if (!data || size < 8) return info;
    // Large icons may embed a PNG instead of a DIB (\x89PNG).
    if (size >= 8 && data[0] == 0x89 && data[1] == 'P' && data[2] == 'N' && data[3] == 'G') {
        info.valid = true;
        info.png = true;
        if (size >= 24 && std::memcmp(data + 12, "IHDR", 4) == 0) {
            // PNG stores width/height big-endian.
            info.width  = (data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19];
            info.height = (data[20] << 24) | (data[21] << 16) | (data[22] << 8) | data[23];
        }
        return info;
    }
    const uint32_t headerSize = rd32(data);
    if (headerSize < 40 || headerSize > size) return info; // only BITMAPINFOHEADER+
    info.valid       = true;
    info.headerSize  = headerSize;
    info.width       = rds32(data + 4);
    info.height      = rds32(data + 8);
    info.bitCount    = rd16(data + 14);
    info.compression = rd32(data + 16);
    uint32_t clrUsed = rd32(data + 32);
    if (info.bitCount > 0 && info.bitCount <= 8) {
        if (clrUsed == 0) clrUsed = 1u << info.bitCount;
    }
    // V4/V5 (and the extended V2/V3 headers) contain their channel masks.
    // Only the 40-byte INFOHEADER stores BI_BITFIELDS masks after the header;
    // any optional optimization palette follows those masks.
    const uint32_t maskBytes = headerSize == 40 && info.compression == 3 ? 12 : 0;
    const uint64_t paletteBytes = static_cast<uint64_t>(clrUsed) * 4 + maskBytes;
    if (paletteBytes > std::numeric_limits<uint32_t>::max()) return {};
    info.paletteBytes = static_cast<uint32_t>(paletteBytes);
    return info;
}

std::vector<uint8_t> ReconstructBmp(const uint8_t* data, size_t size) {
    // BITMAPFILEHEADER has 32-bit file-size and pixel-offset fields. Reject
    // unrepresentable input before allocating or copying its payload.
    if (size > std::numeric_limits<uint32_t>::max() - 14u) return {};
    DibInfo info = DescribeDib(data, size);
    if (!info.valid || info.png) return {}; // a PNG icon image is not a BMP DIB
    const uint64_t pixelOffset = static_cast<uint64_t>(info.headerSize) + info.paletteBytes;
    if (pixelOffset >= size) return {}; // palette/masks must precede actual image data
    const uint32_t offBits = 14 + static_cast<uint32_t>(pixelOffset);
    const uint64_t total = static_cast<uint64_t>(14) + size;
    std::vector<uint8_t> bmp;
    bmp.reserve(static_cast<size_t>(total));
    auto put16 = [&](uint16_t v) { bmp.push_back(v & 0xFF); bmp.push_back((v >> 8) & 0xFF); };
    auto put32 = [&](uint32_t v) {
        bmp.push_back(v & 0xFF); bmp.push_back((v >> 8) & 0xFF);
        bmp.push_back((v >> 16) & 0xFF); bmp.push_back((v >> 24) & 0xFF);
    };
    bmp.push_back('B'); bmp.push_back('M');           // bfType
    put32(static_cast<uint32_t>(total));              // bfSize
    put16(0); put16(0);                               // bfReserved1/2
    put32(offBits);                                   // bfOffBits
    bmp.insert(bmp.end(), data, data + size);         // the DIB verbatim
    return bmp;
}

GroupIconDir ParseGroupIcon(const uint8_t* data, size_t size) {
    GroupIconDir dir;
    if (!data || size < 6) return dir;
    const uint16_t type  = rd16(data + 2);   // 1 = icon, 2 = cursor
    const uint16_t count = rd16(data + 4);
    if (type != 1 && type != 2) return dir;
    dir.isCursor = (type == 2);
    // GRPICONDIRENTRY is 14 bytes.
    const size_t maxCount = (size - 6) / 14;
    const size_t n = std::min<size_t>(count, maxCount);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t* e = data + 6 + i * 14;
        GroupIconEntry g;
        g.width      = e[0];
        g.height     = e[1];
        g.colorCount = e[2];
        g.planes     = rd16(e + 4);
        g.bitCount   = rd16(e + 6);
        g.bytesInRes = rd32(e + 8);
        g.id         = rd16(e + 12);
        dir.entries.push_back(g);
    }
    dir.valid = !dir.entries.empty();
    return dir;
}

std::vector<uint8_t> ReconstructIcon(
    const GroupIconDir& dir,
    const std::function<bool(uint16_t, const uint8_t*&, size_t&)>& resolve) {
    if (!dir.valid || dir.isCursor) return {}; // cursors: raw-save fallback
    struct Img { const uint8_t* p; size_t n; const GroupIconEntry* e; };
    std::vector<Img> imgs;
    for (const GroupIconEntry& e : dir.entries) {
        const uint8_t* p = nullptr;
        size_t n = 0;
        if (resolve(e.id, p, n) && p && n) imgs.push_back({p, n, &e});
    }
    if (imgs.empty()) return {};

    const size_t count = imgs.size();
    const size_t dirBytes = 6 + count * 16;
    std::vector<uint8_t> ico;
    auto put16 = [&](uint16_t v) { ico.push_back(v & 0xFF); ico.push_back((v >> 8) & 0xFF); };
    auto put32 = [&](uint32_t v) {
        ico.push_back(v & 0xFF); ico.push_back((v >> 8) & 0xFF);
        ico.push_back((v >> 16) & 0xFF); ico.push_back((v >> 24) & 0xFF);
    };
    // ICONDIR
    put16(0);                                  // idReserved
    put16(1);                                  // idType = icon
    put16(static_cast<uint16_t>(count));       // idCount
    // ICONDIRENTRY[count]
    size_t offset = dirBytes;
    for (const Img& im : imgs) {
        ico.push_back(im.e->width);
        ico.push_back(im.e->height);
        ico.push_back(im.e->colorCount);
        ico.push_back(0);                       // bReserved
        put16(im.e->planes);
        put16(im.e->bitCount);
        put32(static_cast<uint32_t>(im.n));     // dwBytesInRes (real image size)
        put32(static_cast<uint32_t>(offset));   // dwImageOffset
        offset += im.n;
    }
    // Image data
    for (const Img& im : imgs) ico.insert(ico.end(), im.p, im.p + im.n);
    return ico;
}

} // namespace ds
