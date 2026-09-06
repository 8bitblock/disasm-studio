#pragma once
//
// ResourceDecode.h
// Pure, dependency-light decoders for the common PE resource payload formats,
// used by the Binary View's Resources tab. Everything here operates on a raw
// (bytes, size) span carved out of the resource directory by BinaryFile, so it
// has no ImGui/Win32/BinaryFile dependency and is unit-tested in the sandbox.
//
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ds {

// Human-readable RT_* name for a numeric resource type, e.g. 24 -> "RT_MANIFEST".
// Returns nullptr for an unknown / user-defined numeric type.
const char* ResourceTypeName(uint32_t typeId);

// Decode `units` UTF-16LE code units at `p` (bounded by `byteLen`) to UTF-8,
// stopping at a NUL. Handles surrogate pairs. `maxUnits` caps the scan.
std::string Utf16LeToUtf8(const uint8_t* p, size_t byteLen, size_t maxUnits = SIZE_MAX);

// Heuristic: does this blob look like UTF-8/ASCII text (manifest, HTML, plain
// RCDATA)? Used to decide between a text preview and a hex dump.
bool LooksLikeText(const uint8_t* data, size_t size);

// Decode a VS_VERSIONINFO blob (RT_VERSION) into readable lines: the fixed
// file/product version numbers followed by the StringFileInfo key/value pairs
// (CompanyName, FileDescription, ...). Empty string on malformed input.
std::string DecodeVersionInfo(const uint8_t* data, size_t size);

// Decode one RT_STRING string-table block into (stringId, text) pairs. A block
// holds up to 16 length-prefixed UTF-16 strings; string ids run from
// (blockId-1)*16. Empty (zero-length) slots are skipped.
std::vector<std::pair<uint32_t, std::string>>
DecodeStringTable(const uint8_t* data, size_t size, uint32_t blockId);

// Parsed DIB header fields (from RT_BITMAP / an icon image), for a metadata line.
struct DibInfo {
    bool     valid       = false;
    int32_t  width       = 0;
    int32_t  height      = 0;   // may be negative (top-down) in the raw header
    uint16_t bitCount    = 0;
    uint32_t compression = 0;
    uint32_t headerSize  = 0;
    uint32_t paletteBytes= 0;   // external channel masks + color table after the header
    bool     png         = false; // PNG-compressed image (common for large icons)
};
DibInfo DescribeDib(const uint8_t* data, size_t size);

// Reconstruct a standalone .bmp file from an RT_BITMAP payload (which is a DIB
// with no 14-byte BITMAPFILEHEADER). Returns the .bmp bytes, or empty when the
// DIB header is malformed, its palette/masks lack backing bytes, or its total
// size cannot be represented by the BMP file header.
std::vector<uint8_t> ReconstructBmp(const uint8_t* data, size_t size);

// One GRPICONDIRENTRY of an RT_GROUP_ICON directory.
struct GroupIconEntry {
    uint8_t  width      = 0;
    uint8_t  height     = 0;
    uint8_t  colorCount = 0;
    uint16_t planes     = 0;
    uint16_t bitCount   = 0;
    uint32_t bytesInRes = 0;
    uint16_t id         = 0;   // RT_ICON resource NAME id holding this image
};
struct GroupIconDir {
    bool                        valid    = false;
    bool                        isCursor = false;
    std::vector<GroupIconEntry> entries;
};
// Parse an RT_GROUP_ICON (or RT_GROUP_CURSOR) directory blob.
GroupIconDir ParseGroupIcon(const uint8_t* data, size_t size);

// Reconstruct a standalone .ico from a parsed group directory. `resolve(id)`
// must return the raw RT_ICON image bytes for a given entry id (the DIB or PNG
// stored in that RT_ICON), or set found=false. Returns empty when nothing
// resolves. Cursors are not reconstructed here (their .cur hotspot layout
// differs) — callers fall back to a raw save.
std::vector<uint8_t> ReconstructIcon(
    const GroupIconDir& dir,
    const std::function<bool(uint16_t id, const uint8_t*& bytes, size_t& size)>& resolve);

} // namespace ds
