#pragma once
//
// MemoryScan.h
// Pure value codecs and incremental scan-state storage for live-memory tools.
// The caller owns process reads and supplies page/chunk byte buffers; this layer
// has no Win32, Debugger, or ImGui dependency.  Candidate starts are retained in
// a compact bitmap while each chunk keeps the previous bytes needed by relative
// scans (changed/increased/etc.).
//
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

enum class MemoryValueType : uint8_t {
    UInt8 = 0,
    Int8,
    UInt16,
    Int16,
    UInt32,
    Int32,
    UInt64,
    Int64,
    Float32,
    Float64,
    ByteArray,
    Utf8,
    Utf16Le,
};

bool   MemoryValueTypeIsNumeric(MemoryValueType type) noexcept;
bool   MemoryValueTypeIsFloat(MemoryValueType type) noexcept;
size_t MemoryValueTypeFixedSize(MemoryValueType type) noexcept;

struct MemoryScanValue {
    MemoryValueType      type = MemoryValueType::UInt32;
    std::vector<uint8_t> bytes; // canonical little-endian bytes
    // Empty means every byte is significant.  Byte-array parsing uses 0x00 for
    // ?? and 0xFF for an exact byte; other codecs always leave this empty.
    std::vector<uint8_t> mask;
    // String codecs can append a terminator without losing how the value should
    // be presented. FormatMemoryScanValue omits this synthetic terminator.
    bool nullTerminated = false;

    bool valid() const noexcept;
    size_t size() const noexcept { return bytes.size(); }
};

struct MemoryValueParseOptions {
    // Integers: raw-width hexadecimal bit pattern. Floats: raw IEEE-754 bits.
    // Byte arrays and text codecs ignore this flag.
    bool hexadecimal = false;
    bool nullTerminateText = false;
};

struct MemoryValueFormatOptions {
    // Integers and finite floats can be rendered as fixed-width raw bits.
    bool hexadecimal = false;
};

// Strict, locale-independent codecs. On failure `out` is left untouched and
// error receives a concise reason. Byte arrays accept compact/spaced hex and ??
// wildcards. UTF-8 is validated; UTF-16 is encoded little-endian with surrogate
// pairs as needed.
bool ParseMemoryScanValue(MemoryValueType type, std::string_view text,
                          const MemoryValueParseOptions& options,
                          MemoryScanValue& out, std::string* error = nullptr);
inline bool ParseMemoryScanValue(MemoryValueType type, std::string_view text,
                                 MemoryScanValue& out,
                                 std::string* error = nullptr) {
    return ParseMemoryScanValue(type, text, {}, out, error);
}

// Numeric decimal formatting uses enough digits to reproduce the exact finite
// float/double bit pattern. Non-finite floats are emitted as `bits:0x...`, which
// ParseMemoryScanValue accepts even without the hexadecimal option.
std::string FormatMemoryScanValue(
    const MemoryScanValue& value,
    const MemoryValueFormatOptions& options = {});

enum class MemoryScanMode : uint8_t {
    Exact = 0,
    NotEqual,
    GreaterThanValue,
    LessThanValue,
    Between,
    Changed,
    Unchanged,
    Increased,
    Decreased,
    IncreasedBy,
    DecreasedBy,
    UnknownInitial,
};

struct MemoryFloatTolerance {
    bool   enabled = false;
    double absolute = 0.0;
    double relative = 0.0;
};

struct MemoryScanConfig {
    MemoryValueType type = MemoryValueType::UInt32;
    MemoryScanMode  mode = MemoryScanMode::Exact;
    MemoryScanValue value;       // needle, lower bound, or relative delta
    MemoryScanValue secondValue; // inclusive upper bound for Between
    MemoryFloatTolerance tolerance;

    // Candidate addresses must be an absolute multiple of alignment. A value of
    // one examines every byte. Variable-width codecs use elementSize for
    // previous-value modes; exact scans can derive it from `value`.
    uint32_t alignment = 1;
    size_t   elementSize = 0;
};

bool   ValidateMemoryScanConfig(const MemoryScanConfig& config,
                                std::string* error = nullptr);
size_t MemoryScanElementSize(const MemoryScanConfig& config) noexcept;

// Evaluate one candidate. `previous` is required only for relative modes.
// Buffers must contain at least MemoryScanElementSize(config) bytes.
bool MemoryScanPredicate(const MemoryScanConfig& config,
                         const uint8_t* current, size_t currentSize,
                         const uint8_t* previous, size_t previousSize) noexcept;

struct MemoryScanChunk {
    uint64_t base = 0;
    // This chunk owns candidate starts in [base, base + candidateSpan). `bytes`
    // may contain elementSize-1 lookahead bytes so a value spanning the next
    // page/read boundary is still tested exactly once.
    size_t candidateSpan = 0;
    std::vector<uint8_t> bytes;
    std::vector<uint64_t> candidateBitmap;
    uint64_t candidateCount = 0;

    bool candidateAtOffset(size_t offset) const noexcept;
};

struct MemoryScanMatch {
    uint64_t address = 0;
    std::vector<uint8_t> bytes; // most recently captured value bytes
};

struct MemoryScanPage {
    uint64_t first = 0;      // requested ordinal (clamped to total)
    uint64_t next = 0;       // ordinal for the next page
    uint64_t total = 0;
    bool hasMore = false;
    std::vector<MemoryScanMatch> matches;
};

class MemoryScanSnapshot {
public:
    static constexpr size_t kWholeSample = (std::numeric_limits<size_t>::max)();

    void clear() noexcept;

    // Initial chunks must be appended in ascending, non-overlapping ownership
    // order with one consistent config. `candidateSpan` defaults to sampleSize;
    // pass the unique page size when `sample` includes boundary lookahead.
    bool appendInitialChunk(const MemoryScanConfig& config, uint64_t base,
                            const uint8_t* sample, size_t sampleSize,
                            size_t candidateSpan = kWholeSample,
                            std::string* error = nullptr);
    bool appendInitialChunk(const MemoryScanConfig& config, uint64_t base,
                            const std::vector<uint8_t>& sample,
                            size_t candidateSpan = kWholeSample,
                            std::string* error = nullptr) {
        return appendInitialChunk(config, base, sample.data(), sample.size(),
                                  candidateSpan, error);
    }

    // Refines only candidates retained in `index`, then atomically swaps that
    // chunk on success. A shorter current sample drops candidates whose complete
    // value is no longer readable. Type, element width, and alignment cannot
    // change within one snapshot; the comparison mode and needles can.
    bool refineChunk(size_t index, const MemoryScanConfig& config,
                     const uint8_t* current, size_t currentSize,
                     std::string* error = nullptr);
    bool refineChunk(size_t index, const MemoryScanConfig& config,
                     const std::vector<uint8_t>& current,
                     std::string* error = nullptr) {
        return refineChunk(index, config, current.data(), current.size(), error);
    }

    uint64_t candidateCount() const noexcept { return candidateCount_; }
    size_t chunkCount() const noexcept { return chunks_.size(); }
    const std::vector<MemoryScanChunk>& chunks() const noexcept { return chunks_; }
    MemoryValueType valueType() const noexcept { return type_; }
    size_t elementSize() const noexcept { return elementSize_; }
    uint32_t alignment() const noexcept { return alignment_; }

    // Enumerate by stable result ordinal without materializing all addresses.
    MemoryScanPage page(uint64_t first, size_t limit) const;

private:
    bool shapeSet_ = false;
    MemoryValueType type_ = MemoryValueType::UInt32;
    size_t elementSize_ = 0;
    uint32_t alignment_ = 1;
    MemoryScanConfig initialConfig_{};
    std::vector<MemoryScanChunk> chunks_;
    uint64_t candidateCount_ = 0;
    bool hasLastOwnedRange_ = false;
    uint64_t lastOwnedEnd_ = 0;
};

} // namespace ds
