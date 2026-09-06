#include "StaticUnpack.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <sstream>
#include <thread>
#include <utility>

namespace ds {
namespace {

constexpr uint16_t kMaxPeSections = 96;
constexpr size_t kHardInputBytes = 512u * 1024u * 1024u;
constexpr size_t kHardOutputBytes = 512u * 1024u * 1024u;
constexpr size_t kHardDictionaryBytes = 64u * 1024u * 1024u;
constexpr size_t kHardBlocks = 256;
constexpr size_t kHardLzmaCandidates = 64;
constexpr uint64_t kHardEstimatedPeakBytes = 1024ull * 1024ull * 1024ull;
constexpr uint32_t kScnUninitialized = 0x00000080u;
constexpr uint32_t kScnExecutable = 0x20000000u;
constexpr uint32_t kRangeTop = 1u << 24;
constexpr uint32_t kBitModelTotal = 1u << 11;
constexpr unsigned kMoveBits = 5;
constexpr uint16_t kProbInit = kBitModelTotal / 2;

template <typename T>
bool readLe(const std::vector<uint8_t>& bytes, uint64_t offset, T& value) {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - static_cast<size_t>(offset)) return false;
    std::memcpy(&value, bytes.data() + static_cast<size_t>(offset), sizeof(T));
    return true;
}

template <typename T>
bool writeLe(std::vector<uint8_t>& bytes, uint64_t offset, T value) {
    if (offset > bytes.size() || sizeof(T) > bytes.size() - static_cast<size_t>(offset)) return false;
    std::memcpy(bytes.data() + static_cast<size_t>(offset), &value, sizeof(T));
    return true;
}

bool checkedAdd(uint64_t a, uint64_t b, uint64_t& out) {
    if (a > (std::numeric_limits<uint64_t>::max)() - b) return false;
    out = a + b;
    return true;
}

void addIssue(std::vector<StaticUnpackIssue>& issues, StaticUnpackSeverity severity,
              std::string code, std::string message) {
    if (issues.size() < 256)
        issues.push_back({ severity, std::move(code), std::move(message) });
}

void publish(const StaticUnpackProgressFn& fn, StaticUnpackPhase phase,
             uint64_t current = 0, uint64_t total = 0, uint64_t output = 0,
             uint32_t block = 0, uint32_t blocks = 0) {
    if (fn) fn({ phase, current, total, output, block, blocks });
}

bool wasCancelled(const StaticUnpackCancelFn& fn) { return fn && fn(); }

bool validCaps(const StaticUnpackOptions& options) {
    return options.maxInputBytes && options.maxInputBytes <= kHardInputBytes &&
           options.maxOutputBytes && options.maxOutputBytes <= kHardOutputBytes &&
           options.maxDictionaryBytes && options.maxDictionaryBytes <= kHardDictionaryBytes &&
           options.maxBlocks && options.maxBlocks <= kHardBlocks &&
           options.maxLzmaCandidates && options.maxLzmaCandidates <= kHardLzmaCandidates;
}

std::string hexValue(uint64_t value) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << value;
    return s.str();
}

uint64_t contentIdentity(const std::vector<uint8_t>& bytes) {
    uint64_t hash = 1469598103934665603ull;
    for (uint8_t value : bytes) {
        hash ^= value;
        hash *= 1099511628211ull;
    }
    hash ^= bytes.size();
    hash *= 1099511628211ull;
    return hash;
}

struct PeSection {
    std::string name;
    uint32_t virtualSize = 0;
    uint32_t rva = 0;
    uint32_t rawSize = 0;
    uint32_t rawOffset = 0;
    uint32_t characteristics = 0;
};

struct PeView {
    bool is64 = false;
    uint64_t preferredBase = 0;
    uint32_t entryRVA = 0;
    uint32_t sizeImage = 0;
    uint32_t sizeHeaders = 0;
    uint32_t sectionAlignment = 0;
    uint32_t fileAlignment = 0;
    uint32_t optionalOffset = 0;
    uint32_t sectionTable = 0;
    std::vector<PeSection> sections;
};

bool isPowerOfTwo(uint32_t value) { return value && (value & (value - 1)) == 0; }

bool parseDiskPe(const std::vector<uint8_t>& input, const StaticUnpackOptions& options,
                 PeView& pe, std::vector<StaticUnpackIssue>& issues) {
    uint16_t mz = 0, count = 0, optionalSize = 0, magic = 0;
    uint32_t nt = 0, signature = 0;
    if (!readLe(input, 0, mz) || mz != 0x5a4d) {
        addIssue(issues, StaticUnpackSeverity::Error, "not-pe", "Input does not begin with an MZ header.");
        return false;
    }
    if (!readLe(input, 0x3c, nt) || nt > input.size() || 24 > input.size() - nt ||
        !readLe(input, nt, signature) || signature != 0x00004550u ||
        !readLe(input, static_cast<uint64_t>(nt) + 6, count) ||
        !readLe(input, static_cast<uint64_t>(nt) + 20, optionalSize)) {
        addIssue(issues, StaticUnpackSeverity::Error, "pe-header", "PE/COFF headers are truncated or invalid.");
        return false;
    }
    if (!count || count > kMaxPeSections) {
        addIssue(issues, StaticUnpackSeverity::Error, "section-count", "PE section count is zero or exceeds the safety cap.");
        return false;
    }
    const uint64_t optional = static_cast<uint64_t>(nt) + 24;
    if (optional > input.size() || optionalSize > input.size() - optional ||
        !readLe(input, optional, magic) || (magic != 0x10b && magic != 0x20b)) {
        addIssue(issues, StaticUnpackSeverity::Error, "optional-header", "Only bounded PE32/PE32+ inputs are supported.");
        return false;
    }
    pe.optionalOffset = static_cast<uint32_t>(optional);
    pe.is64 = magic == 0x20b;
    const uint32_t minimum = pe.is64 ? 112u : 96u;
    if (optionalSize < minimum ||
        !readLe(input, optional + 16, pe.entryRVA) ||
        !readLe(input, optional + 32, pe.sectionAlignment) ||
        !readLe(input, optional + 36, pe.fileAlignment) ||
        !readLe(input, optional + 56, pe.sizeImage) ||
        !readLe(input, optional + 60, pe.sizeHeaders)) {
        addIssue(issues, StaticUnpackSeverity::Error, "optional-header", "Optional header is too small for required fields.");
        return false;
    }
    if (pe.is64) {
        if (!readLe(input, optional + 24, pe.preferredBase)) return false;
    } else {
        uint32_t base = 0;
        if (!readLe(input, optional + 28, base)) return false;
        pe.preferredBase = base;
    }
    if (!pe.sizeImage || pe.sizeImage > options.maxOutputBytes || pe.sizeHeaders > input.size() ||
        pe.sizeHeaders > pe.sizeImage || !isPowerOfTwo(pe.sectionAlignment) ||
        !isPowerOfTwo(pe.fileAlignment)) {
        addIssue(issues, StaticUnpackSeverity::Error, "pe-layout", "PE image/header sizes or alignments are invalid or exceed configured caps.");
        return false;
    }

    uint64_t table = optional + optionalSize;
    uint64_t tableEnd = 0;
    if (!checkedAdd(table, static_cast<uint64_t>(count) * 40, tableEnd) || tableEnd > input.size() ||
        table > UINT32_MAX) {
        addIssue(issues, StaticUnpackSeverity::Error, "section-table", "PE section table is truncated.");
        return false;
    }
    if (pe.sizeHeaders < tableEnd) {
        addIssue(issues, StaticUnpackSeverity::Error, "header-size",
                 "SizeOfHeaders does not cover the complete PE section table.");
        return false;
    }
    pe.sectionTable = static_cast<uint32_t>(table);
    pe.sections.reserve(count);
    std::vector<std::pair<uint64_t, uint64_t>> virtualSpans;
    for (uint16_t i = 0; i < count; ++i) {
        const uint64_t sh = table + static_cast<uint64_t>(i) * 40;
        char name[9]{};
        std::memcpy(name, input.data() + sh, 8);
        PeSection section;
        section.name.assign(name, strnlen(name, 8));
        if (!readLe(input, sh + 8, section.virtualSize) ||
            !readLe(input, sh + 12, section.rva) ||
            !readLe(input, sh + 16, section.rawSize) ||
            !readLe(input, sh + 20, section.rawOffset) ||
            !readLe(input, sh + 36, section.characteristics)) return false;
        const uint64_t span = std::max<uint32_t>(section.virtualSize, section.rawSize);
        uint64_t virtualEnd = 0, rawEnd = 0;
        if ((span && (!checkedAdd(section.rva, span, virtualEnd) || virtualEnd > pe.sizeImage)) ||
            (section.rawSize && (!section.rawOffset ||
             !checkedAdd(section.rawOffset, section.rawSize, rawEnd) || rawEnd > input.size()))) {
            addIssue(issues, StaticUnpackSeverity::Error, "section-layout",
                     "Section " + section.name + " has an out-of-range raw or virtual span.");
            return false;
        }
        if (span) virtualSpans.emplace_back(section.rva, virtualEnd);
        pe.sections.push_back(std::move(section));
    }
    std::sort(virtualSpans.begin(), virtualSpans.end());
    for (size_t i = 1; i < virtualSpans.size(); ++i) {
        if (virtualSpans[i].first < virtualSpans[i - 1].second) {
            addIssue(issues, StaticUnpackSeverity::Error, "section-overlap", "PE virtual section spans overlap.");
            return false;
        }
    }
    return true;
}

const PeSection* sectionForRva(const PeView& pe, uint32_t rva, bool rawBacked) {
    for (const auto& section : pe.sections) {
        const uint64_t span = rawBacked ? section.rawSize :
            std::max<uint32_t>(section.virtualSize, section.rawSize);
        if (rva >= section.rva && static_cast<uint64_t>(rva) - section.rva < span)
            return &section;
    }
    return nullptr;
}

bool rvaToRaw(const std::vector<uint8_t>& input, const PeView& pe, uint32_t rva,
              uint64_t& raw, uint64_t* contiguous = nullptr) {
    if (rva < pe.sizeHeaders && rva < input.size()) {
        raw = rva;
        if (contiguous) *contiguous = std::min<uint64_t>(pe.sizeHeaders, input.size()) - rva;
        return true;
    }
    const PeSection* section = sectionForRva(pe, rva, true);
    if (!section) return false;
    const uint64_t delta = static_cast<uint64_t>(rva) - section->rva;
    raw = static_cast<uint64_t>(section->rawOffset) + delta;
    if (raw >= input.size()) return false;
    const uint64_t remain = static_cast<uint64_t>(section->rawSize) - delta;
    if (remain > input.size() - raw) return false;
    if (contiguous) *contiguous = remain;
    return true;
}

bool buildMappedImage(const std::vector<uint8_t>& input, const PeView& pe,
                      std::vector<uint8_t>& mapped) {
    mapped.assign(pe.sizeImage, 0);
    const size_t headers = std::min<size_t>({ pe.sizeHeaders, input.size(), mapped.size() });
    std::copy_n(input.begin(), headers, mapped.begin());
    for (const auto& section : pe.sections) {
        if (!section.rawSize) continue;
        if (section.rawOffset > input.size() || section.rawSize > input.size() - section.rawOffset ||
            section.rva > mapped.size()) return false;
        const size_t count = std::min<size_t>(section.rawSize, mapped.size() - section.rva);
        std::copy_n(input.begin() + section.rawOffset, count, mapped.begin() + section.rva);
    }
    return true;
}

bool vmpName(const std::string& name) {
    std::string lower;
    lower.reserve(name.size());
    for (unsigned char c : name) lower.push_back(static_cast<char>(std::tolower(c)));
    return lower == ".vmp0" || lower == ".vmp1" || lower == ".vmp2" ||
           lower.find("vmp") != std::string::npos;
}

void initializeEntryAssessment(const PeView& pe, StaticUnpackResult& result) {
    result.entryRVA = pe.entryRVA;
    result.oepTrusted = false;
    if (!pe.entryRVA) {
        result.oepAssessment = "The original PE has no non-zero entry point; no unpacked OEP was established.";
        return;
    }
    const PeSection* owner = sectionForRva(pe, pe.entryRVA, false);
    if (!owner) {
        result.oepAssessment = "The original entry point is not owned by a modeled PE section.";
        return;
    }
    if (!(owner->characteristics & kScnExecutable)) {
        result.oepAssessment = "The unchanged original entry point lies in non-executable section " + owner->name + ".";
        return;
    }
    result.oepAssessment = "The original entry point is structurally valid but has not yet been tied to a recovered destination block.";
}

void assessRecoveredEntry(const PeView& pe, const std::vector<StaticUnpackBlock>& blocks,
                          StaticUnpackResult& result) {
    initializeEntryAssessment(pe, result);
    if (!pe.entryRVA) return;
    const PeSection* owner = sectionForRva(pe, pe.entryRVA, false);
    if (!owner || !(owner->characteristics & kScnExecutable)) return;
    if (vmpName(owner->name)) {
        result.oepAssessment = "The unchanged original entry point remains inside packer section " + owner->name + ".";
        return;
    }
    for (const auto& block : blocks) {
        uint64_t end = 0;
        if (!block.complete || !block.outputSize ||
            !checkedAdd(block.destinationRVA, block.outputSize, end)) continue;
        if (pe.entryRVA >= block.destinationRVA && pe.entryRVA < end) {
            result.oepTrusted = true;
            result.oepAssessment = "The PE header entry lies inside recovered executable destination section " +
                                   owner->name + "; the container-to-destination evidence validates it as the recovered OEP.";
            return;
        }
    }
    result.oepAssessment = "The unchanged entry point is executable, but it was not inside any recovered destination block; it may still be the packer loader OEP.";
}

struct LzmaProperties {
    unsigned lc = 0, lp = 0, pb = 0;
    uint32_t dictionary = 0;
};

bool parseLzmaProperties(const uint8_t* bytes, size_t size, size_t dictionaryCap,
                         LzmaProperties& props) {
    if (!bytes || size < 5 || bytes[0] >= 9 * 5 * 5) return false;
    unsigned value = bytes[0];
    props.lc = value % 9;
    value /= 9;
    props.lp = value % 5;
    props.pb = value / 5;
    props.dictionary = static_cast<uint32_t>(bytes[1]) |
        (static_cast<uint32_t>(bytes[2]) << 8) |
        (static_cast<uint32_t>(bytes[3]) << 16) |
        (static_cast<uint32_t>(bytes[4]) << 24);
    const uint64_t effective = std::max<uint32_t>(props.dictionary, 4096u);
    return props.pb <= 4 && props.lp <= 4 && props.lc <= 8 &&
           props.lc + props.lp <= 8 && effective <= dictionaryCap;
}

class RangeDecoder {
public:
    RangeDecoder(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    bool initialize() {
        if (!data_ || size_ < 5 || data_[0] != 0) return false;
        range_ = 0xffffffffu;
        code_ = 0;
        for (unsigned i = 0; i < 5; ++i) code_ = (code_ << 8) | data_[pos_++];
        return true;
    }

    bool bit(uint16_t& probability, unsigned& value) {
        const uint32_t bound = (range_ >> 11) * probability;
        if (code_ < bound) {
            range_ = bound;
            probability = static_cast<uint16_t>(probability + ((kBitModelTotal - probability) >> kMoveBits));
            value = 0;
        } else {
            range_ -= bound;
            code_ -= bound;
            probability = static_cast<uint16_t>(probability - (probability >> kMoveBits));
            value = 1;
        }
        return normalize();
    }

    bool direct(unsigned count, uint32_t& value) {
        value = 0;
        for (unsigned i = 0; i < count; ++i) {
            range_ >>= 1;
            unsigned bit = 0;
            if (code_ >= range_) { code_ -= range_; bit = 1; }
            value = (value << 1) | bit;
            if (!normalize()) return false;
        }
        return true;
    }

    size_t consumed() const { return pos_; }

private:
    bool normalize() {
        if (range_ >= kRangeTop) return true;
        if (pos_ >= size_) return false;
        range_ <<= 8;
        code_ = (code_ << 8) | data_[pos_++];
        return true;
    }

    const uint8_t* data_ = nullptr;
    size_t size_ = 0, pos_ = 0;
    uint32_t range_ = 0xffffffffu, code_ = 0;
};

bool decodeTree(RangeDecoder& rd, uint16_t* probabilities, unsigned bits, uint32_t& value) {
    uint32_t symbol = 1;
    for (unsigned i = 0; i < bits; ++i) {
        unsigned bit = 0;
        if (!rd.bit(probabilities[symbol], bit)) return false;
        symbol = (symbol << 1) | bit;
    }
    value = symbol - (1u << bits);
    return true;
}

bool decodeReverseTree(RangeDecoder& rd, uint16_t* probabilities, int base,
                       unsigned bits, uint32_t& value, size_t probabilityCount) {
    uint32_t symbol = 1;
    value = 0;
    for (unsigned i = 0; i < bits; ++i) {
        const int index = base + static_cast<int>(symbol);
        if (index < 0 || static_cast<size_t>(index) >= probabilityCount) return false;
        unsigned bit = 0;
        if (!rd.bit(probabilities[index], bit)) return false;
        symbol = (symbol << 1) | bit;
        value |= static_cast<uint32_t>(bit) << i;
    }
    return true;
}

struct LengthDecoder {
    uint16_t choice = kProbInit, choice2 = kProbInit;
    std::array<std::array<uint16_t, 8>, 16> low{};
    std::array<std::array<uint16_t, 8>, 16> mid{};
    std::array<uint16_t, 256> high{};

    LengthDecoder() {
        for (auto& row : low) row.fill(kProbInit);
        for (auto& row : mid) row.fill(kProbInit);
        high.fill(kProbInit);
    }

    bool decode(RangeDecoder& rd, uint32_t posState, uint32_t& value) {
        unsigned bit = 0;
        if (!rd.bit(choice, bit)) return false;
        if (!bit) return decodeTree(rd, low[posState].data(), 3, value);
        if (!rd.bit(choice2, bit)) return false;
        if (!bit) {
            if (!decodeTree(rd, mid[posState].data(), 3, value)) return false;
            value += 8;
            return true;
        }
        if (!decodeTree(rd, high.data(), 8, value)) return false;
        value += 16;
        return true;
    }
};

enum class LzmaStatus { Ok, Cancelled, Invalid, Truncated, OutputLimit };

struct LzmaDecodeResult {
    LzmaStatus status = LzmaStatus::Invalid;
    std::vector<uint8_t> output;
    size_t consumed = 0;
    bool endMarker = false;
    std::string message;
};

LzmaDecodeResult decodeLzma1(const uint8_t* input, size_t inputSize,
                            const std::array<uint8_t, 5>& encodedProps,
                            size_t dictionaryCap, size_t outputLimit,
                            std::optional<size_t> expectedSize,
                            const StaticUnpackCancelFn& cancelled,
                            const std::function<void(uint64_t)>& onProgress) {
    LzmaDecodeResult result;
    LzmaProperties props;
    if (!outputLimit || !parseLzmaProperties(encodedProps.data(), encodedProps.size(), dictionaryCap, props)) {
        result.message = "Invalid or over-cap LZMA1 properties.";
        return result;
    }
    if (expectedSize && *expectedSize > outputLimit) {
        result.message = "Declared LZMA output exceeds its destination bound.";
        return result;
    }
    RangeDecoder rd(input, inputSize);
    if (!rd.initialize()) {
        result.status = LzmaStatus::Truncated;
        result.message = "LZMA range stream is truncated or lacks its initial zero byte.";
        return result;
    }

    constexpr size_t kStates = 12, kPosStates = 16;
    std::array<std::array<uint16_t, kPosStates>, kStates> isMatch{}, isRep0Long{};
    std::array<uint16_t, kStates> isRep{}, isRepG0{}, isRepG1{}, isRepG2{};
    std::array<std::array<uint16_t, 64>, 4> posSlot{};
    std::array<uint16_t, 114> posDecoders{};
    std::array<uint16_t, 16> posAlign{};
    for (auto& row : isMatch) row.fill(kProbInit);
    for (auto& row : isRep0Long) row.fill(kProbInit);
    isRep.fill(kProbInit); isRepG0.fill(kProbInit); isRepG1.fill(kProbInit); isRepG2.fill(kProbInit);
    for (auto& row : posSlot) row.fill(kProbInit);
    posDecoders.fill(kProbInit); posAlign.fill(kProbInit);
    LengthDecoder lenDecoder, repLenDecoder;
    const size_t literalContexts = size_t{1} << (props.lc + props.lp);
    std::vector<uint16_t> literal(0x300u * literalContexts, kProbInit);

    // outputLimit is already bounded and included as one full decoder workspace
    // in admission. Reserving it exactly prevents vector growth from briefly
    // retaining old+new 300+ MiB allocations and violating that peak contract.
    result.output.reserve(outputLimit);
    uint32_t state = 0, rep0 = 0, rep1 = 0, rep2 = 0, rep3 = 0;
    const uint32_t posMask = (1u << props.pb) - 1;
    const uint32_t literalPosMask = (1u << props.lp) - 1;
    const uint64_t dictionary = std::max<uint32_t>(props.dictionary, 4096u);
    uint64_t nextProgress = 0;

    auto failBitstream = [&](const char* text) {
        result.status = LzmaStatus::Truncated;
        result.message = text;
        result.consumed = rd.consumed();
        return result;
    };

    while (true) {
        if (expectedSize && result.output.size() == *expectedSize) {
            result.status = LzmaStatus::Ok;
            result.message = "Decoded the exact declared LZMA output size.";
            break;
        }
        if (result.output.size() >= outputLimit) {
            result.status = LzmaStatus::OutputLimit;
            result.message = "LZMA stream reached the destination limit before an end marker.";
            break;
        }
        if ((result.output.size() & 0xfffu) == 0) {
            if (wasCancelled(cancelled)) {
                result.status = LzmaStatus::Cancelled;
                result.message = "Cancelled during LZMA decoding.";
                break;
            }
            if (result.output.size() >= nextProgress) {
                if (onProgress) onProgress(result.output.size());
                nextProgress = result.output.size() + 64u * 1024u;
            }
        }

        const uint32_t posState = static_cast<uint32_t>(result.output.size()) & posMask;
        unsigned bit = 0;
        if (!rd.bit(isMatch[state][posState], bit)) return failBitstream("Truncated LZMA match model.");
        if (!bit) {
            const uint8_t previous = result.output.empty() ? 0 : result.output.back();
            const uint32_t context =
                ((static_cast<uint32_t>(result.output.size()) & literalPosMask) << props.lc) |
                (previous >> (8 - props.lc));
            uint16_t* probs = literal.data() + static_cast<size_t>(context) * 0x300u;
            uint32_t symbol = 1;
            if (state >= 7 && rep0 < result.output.size()) {
                uint8_t matchByte = result.output[result.output.size() - rep0 - 1];
                do {
                    const unsigned matchBit = (matchByte >> 7) & 1u;
                    matchByte <<= 1;
                    if (!rd.bit(probs[((1u + matchBit) << 8) + symbol], bit))
                        return failBitstream("Truncated LZMA matched literal.");
                    symbol = (symbol << 1) | bit;
                    if (matchBit != bit) {
                        while (symbol < 0x100) {
                            if (!rd.bit(probs[symbol], bit)) return failBitstream("Truncated LZMA literal.");
                            symbol = (symbol << 1) | bit;
                        }
                        break;
                    }
                } while (symbol < 0x100);
            } else {
                while (symbol < 0x100) {
                    if (!rd.bit(probs[symbol], bit)) return failBitstream("Truncated LZMA literal.");
                    symbol = (symbol << 1) | bit;
                }
            }
            result.output.push_back(static_cast<uint8_t>(symbol));
            state = state < 4 ? 0 : (state < 10 ? state - 3 : state - 6);
            continue;
        }

        uint32_t length = 0;
        if (!rd.bit(isRep[state], bit)) return failBitstream("Truncated LZMA repetition model.");
        if (!bit) {
            rep3 = rep2; rep2 = rep1; rep1 = rep0;
            state = state < 7 ? 7 : 10;
            if (!lenDecoder.decode(rd, posState, length)) return failBitstream("Truncated LZMA match length.");
            length += 2;
            const uint32_t lenState = std::min<uint32_t>(length - 2, 3);
            uint32_t slot = 0;
            if (!decodeTree(rd, posSlot[lenState].data(), 6, slot)) return failBitstream("Truncated LZMA distance slot.");
            if (slot < 4) rep0 = slot;
            else {
                const unsigned directBits = (slot >> 1) - 1;
                rep0 = (2u | (slot & 1u)) << directBits;
                uint32_t distanceTail = 0;
                if (slot < 14) {
                    const int base = static_cast<int>(rep0) - static_cast<int>(slot) - 1;
                    if (!decodeReverseTree(rd, posDecoders.data(), base, directBits,
                                           distanceTail, posDecoders.size()))
                        return failBitstream("Truncated LZMA special distance.");
                    rep0 += distanceTail;
                } else {
                    if (!rd.direct(directBits - 4, distanceTail)) return failBitstream("Truncated LZMA direct distance.");
                    rep0 += distanceTail << 4;
                    if (!decodeReverseTree(rd, posAlign.data(), 0, 4, distanceTail, posAlign.size()))
                        return failBitstream("Truncated LZMA alignment distance.");
                    rep0 += distanceTail;
                    if (rep0 == 0xffffffffu) {
                        result.status = LzmaStatus::Ok;
                        result.endMarker = true;
                        result.message = "Decoded a bounded LZMA stream through its end marker.";
                        break;
                    }
                }
            }
        } else {
            if (!rd.bit(isRepG0[state], bit)) return failBitstream("Truncated LZMA rep0 model.");
            if (!bit) {
                if (!rd.bit(isRep0Long[state][posState], bit)) return failBitstream("Truncated LZMA short-rep model.");
                if (!bit) {
                    state = state < 7 ? 9 : 11;
                    if (rep0 >= result.output.size() || rep0 + 1ull > dictionary) {
                        result.status = LzmaStatus::Invalid;
                        result.message = "LZMA short repetition points outside initialized dictionary history.";
                        break;
                    }
                    result.output.push_back(result.output[result.output.size() - rep0 - 1]);
                    continue;
                }
            } else {
                uint32_t distance = 0;
                if (!rd.bit(isRepG1[state], bit)) return failBitstream("Truncated LZMA rep1 model.");
                if (!bit) distance = rep1;
                else {
                    if (!rd.bit(isRepG2[state], bit)) return failBitstream("Truncated LZMA rep2 model.");
                    if (!bit) distance = rep2;
                    else { distance = rep3; rep3 = rep2; }
                    rep2 = rep1;
                }
                rep1 = rep0;
                rep0 = distance;
            }
            state = state < 7 ? 8 : 11;
            if (!repLenDecoder.decode(rd, posState, length)) return failBitstream("Truncated LZMA repetition length.");
            length += 2;
        }

        if (rep0 >= result.output.size() || rep0 + 1ull > dictionary) {
            result.status = LzmaStatus::Invalid;
            result.message = "LZMA match distance points outside initialized dictionary history.";
            break;
        }
        if (length > outputLimit - result.output.size() ||
            (expectedSize && length > *expectedSize - result.output.size())) {
            result.status = LzmaStatus::OutputLimit;
            result.message = "LZMA match exceeds the declared destination extent.";
            break;
        }
        for (uint32_t i = 0; i < length; ++i)
            result.output.push_back(result.output[result.output.size() - rep0 - 1]);
    }

    result.consumed = rd.consumed();
    if (onProgress) onProgress(result.output.size());
    return result;
}

std::vector<const PeSection*> emptyPackedTargets(const PeView& pe,
                                                const StaticUnpackOptions& options) {
    std::vector<const PeSection*> targets;
    for (const auto& section : pe.sections) {
        if (!section.rawSize && !section.rawOffset && section.virtualSize &&
            !(section.characteristics & kScnUninitialized)) {
            targets.push_back(&section);
            if (targets.size() > options.maxBlocks) {
                targets.clear(); // never recover a misleading prefix of the table
                return targets;
            }
        }
    }
    return targets;
}

struct TableCandidate {
    uint64_t tableOffset = 0;
    uint64_t propertiesOffset = 0;
    std::array<uint8_t, 5> properties{};
    bool validProperties = false;
    bool stored = false;
    float confidence = 0.0f;
    std::vector<StaticUnpackBlock> blocks;
};

bool fillSourceBounds(const std::vector<uint8_t>& input, const PeView& pe,
                      uint64_t tableOffset, uint64_t propertiesOffset,
                      std::vector<StaticUnpackBlock>& blocks) {
    std::vector<uint64_t> boundaries;
    boundaries.reserve(blocks.size() + 2);
    boundaries.push_back(tableOffset);
    boundaries.push_back(propertiesOffset);
    for (const auto& block : blocks) boundaries.push_back(block.sourceOffset);
    std::sort(boundaries.begin(), boundaries.end());
    boundaries.erase(std::unique(boundaries.begin(), boundaries.end()), boundaries.end());

    for (auto& block : blocks) {
        uint64_t raw = 0, contiguous = 0;
        if (!rvaToRaw(input, pe, block.sourceRVA, raw, &contiguous) || raw != block.sourceOffset || !contiguous)
            return false;
        uint64_t end = raw + contiguous;
        const auto next = std::upper_bound(boundaries.begin(), boundaries.end(), raw);
        if (next != boundaries.end() && *next < end) end = *next;
        if (end <= raw) return false;
        block.compressedSize = end - raw;
    }
    return true;
}

std::optional<TableCandidate> recoverPackerInfo(const std::vector<uint8_t>& input,
                                                const PeView& pe,
                                                const StaticUnpackOptions& options,
                                                const StaticUnpackCancelFn& cancelled,
                                                const StaticUnpackProgressFn& progress) {
    const auto targets = emptyPackedTargets(pe, options);
    if (targets.empty() || targets.size() > options.maxBlocks) return std::nullopt;
    const uint64_t tableBytes = static_cast<uint64_t>(targets.size()) * 8;
    if (tableBytes > input.size() || input.size() - tableBytes < 8) return std::nullopt;

    bool packerSection = false;
    for (const auto& section : pe.sections) packerSection = packerSection || vmpName(section.name);
    std::optional<TableCandidate> best;
    const uint64_t last = input.size() - tableBytes;
    for (uint64_t offset = 8; offset <= last; ++offset) {
        if ((offset & 0xffffu) == 0) {
            if (wasCancelled(cancelled)) return std::nullopt;
            publish(progress, StaticUnpackPhase::Probing, offset, input.size());
        }
        uint32_t firstDestination = 0;
        if (!readLe(input, offset + 4, firstDestination) || firstDestination != targets[0]->rva) continue;

        TableCandidate candidate;
        candidate.tableOffset = offset;
        bool valid = true;
        for (size_t i = 0; i < targets.size(); ++i) {
            uint32_t source = 0, destination = 0;
            const uint64_t descriptor = offset + static_cast<uint64_t>(i) * 8;
            if (!readLe(input, descriptor, source) || !readLe(input, descriptor + 4, destination) ||
                destination != targets[i]->rva) { valid = false; break; }
            uint64_t raw = 0;
            if (!rvaToRaw(input, pe, source, raw)) { valid = false; break; }
            StaticUnpackBlock block;
            block.descriptorOffset = descriptor;
            block.sourceRVA = source;
            block.destinationRVA = destination;
            block.sourceOffset = raw;
            block.outputLimit = targets[i]->virtualSize;
            block.confidence = 0.70f;
            block.evidence = "PACKER_INFO destination equals virtual-only section " + targets[i]->name;
            candidate.blocks.push_back(std::move(block));
        }
        if (!valid || candidate.blocks.size() != targets.size()) continue;

        uint32_t propertiesRva = 0, propertiesSize = 0;
        uint64_t propertiesRaw = 0, propertiesRemain = 0;
        readLe(input, offset - 8, propertiesRva);
        readLe(input, offset - 4, propertiesSize);
        candidate.propertiesOffset = offset - 8;
        LzmaProperties decodedProps;
        if (propertiesSize == 5 &&
            rvaToRaw(input, pe, propertiesRva, propertiesRaw, &propertiesRemain) && propertiesRemain >= 5 &&
            parseLzmaProperties(input.data() + propertiesRaw, 5, options.maxDictionaryBytes, decodedProps)) {
            std::copy_n(input.data() + propertiesRaw, 5, candidate.properties.begin());
            candidate.validProperties = true;
            candidate.propertiesOffset = propertiesRaw;
            candidate.confidence = 0.82f + (packerSection ? 0.12f : 0.0f) +
                (targets.size() > 1 ? 0.04f : 0.0f);
            for (auto& block : candidate.blocks) {
                block.codec = StaticUnpackCodec::Lzma1;
                block.lzmaProperties = candidate.properties;
                block.hasLzmaProperties = true;
                block.confidence = candidate.confidence;
                block.evidence += "; preceding descriptor resolves to valid five-byte LZMA1 properties";
            }
        }

        if (!fillSourceBounds(input, pe, candidate.tableOffset - 8,
                              candidate.propertiesOffset, candidate.blocks))
            continue;

        if (!candidate.validProperties) {
            // Some packer tables describe blocks that were deliberately left
            // stored.  Admit that interpretation only when every finite source
            // extent exactly equals its destination section; never guess by
            // copying a prefix of a larger compressed range.
            bool exactStored = true;
            for (auto& block : candidate.blocks) {
                if (!block.outputLimit || block.compressedSize != block.outputLimit) {
                    exactStored = false;
                    break;
                }
                block.codec = StaticUnpackCodec::Stored;
                block.confidence = 0.62f + (packerSection ? 0.10f : 0.0f);
                block.evidence += "; exact finite source/destination extents select stored recovery";
            }
            if (!exactStored) continue;
            candidate.stored = true;
            candidate.confidence = 0.62f + (packerSection ? 0.10f : 0.0f);
        }
        candidate.confidence = std::min(candidate.confidence, 0.99f);
        if (!best || candidate.confidence > best->confidence ||
            (candidate.confidence == best->confidence && candidate.tableOffset < best->tableOffset))
            best = std::move(candidate);
    }
    return best;
}

std::optional<StaticUnpackBlock> recoverLzmaAlone(const std::vector<uint8_t>& input,
                                                  const PeView& pe,
                                                  const StaticUnpackOptions& options,
                                                  const StaticUnpackCancelFn& cancelled,
                                                  const StaticUnpackProgressFn& progress,
                                                  float& confidence,
                                                  uint64_t& headerOffset,
                                                  bool& candidateCapReached) {
    const auto targets = emptyPackedTargets(pe, options);
    std::optional<StaticUnpackBlock> best;
    confidence = 0.0f;
    headerOffset = 0;
    candidateCapReached = false;
    size_t candidates = 0;
    if (!options.maxLzmaCandidates) return best;
    for (const auto& section : pe.sections) {
        if (!vmpName(section.name) || !section.rawSize) continue;
        const uint64_t begin = section.rawOffset;
        const uint64_t end = static_cast<uint64_t>(section.rawOffset) + section.rawSize;
        if (end > input.size() || end < begin + 18) continue;
        for (uint64_t offset = begin; offset + 18 <= end; ++offset) {
            if ((offset & 0xffffu) == 0) {
                if (wasCancelled(cancelled)) return std::nullopt;
                publish(progress, StaticUnpackPhase::Probing, offset, input.size());
            }
            LzmaProperties props;
            if (!parseLzmaProperties(input.data() + offset, 5, options.maxDictionaryBytes, props) ||
                input[offset + 13] != 0) continue;
            uint64_t outputSize = 0;
            std::memcpy(&outputSize, input.data() + offset + 5, 8);
            if (!outputSize || outputSize == UINT64_MAX || outputSize > options.maxOutputBytes) continue;
            if (candidates >= options.maxLzmaCandidates) {
                candidateCapReached = true;
                return best;
            }
            ++candidates;
            StaticUnpackBlock block;
            block.sourceOffset = offset + 13;
            block.compressedSize = end - block.sourceOffset;
            block.outputLimit = outputSize;
            block.codec = StaticUnpackCodec::Lzma1;
            std::copy_n(input.data() + offset, 5, block.lzmaProperties.begin());
            block.hasLzmaProperties = true;
            block.confidence = 0.58f;
            block.evidence = "Finite LZMA-alone header inside VMProtect-named section " + section.name;
            if (props.dictionary >= 4096) block.confidence += 0.08f;
            if (input[offset] == 0x5d) block.confidence += 0.08f; // common lc=3/lp=0/pb=2 profile
            if (outputSize >= 256) block.confidence += 0.04f;
            if (targets.size() == 1 && outputSize <= targets[0]->virtualSize) {
                block.destinationRVA = targets[0]->rva;
                block.confidence += 0.12f;
                block.evidence += "; declared output fits the sole virtual-only target section";
            }
            block.confidence = std::min(block.confidence, 0.94f);
            if (!best || block.confidence > confidence ||
                (block.confidence == confidence && offset < headerOffset)) {
                best = block;
                confidence = block.confidence;
                headerOffset = offset;
            }
        }
    }
    return best;
}

bool validateManualBlocks(const std::vector<uint8_t>& input, const PeView& pe,
                          const StaticUnpackOptions& options,
                          std::vector<StaticUnpackBlock>& blocks,
                          std::vector<StaticUnpackIssue>& issues) {
    if (options.manualBlocks.empty() || options.manualBlocks.size() > options.maxBlocks) {
        addIssue(issues, StaticUnpackSeverity::Error, "manual-block-count",
                 "Manual strategy requires one or more blocks within the configured cap.");
        return false;
    }
    blocks = options.manualBlocks;
    std::vector<std::pair<uint64_t, uint64_t>> destinations;
    for (auto& block : blocks) {
        uint64_t sourceEnd = 0, destinationEnd = 0;
        if (!block.compressedSize || !block.outputLimit ||
            !checkedAdd(block.sourceOffset, block.compressedSize, sourceEnd) || sourceEnd > input.size() ||
            !checkedAdd(block.destinationRVA, block.outputLimit, destinationEnd) || destinationEnd > pe.sizeImage) {
            addIssue(issues, StaticUnpackSeverity::Error, "manual-block-range",
                     "A manual block has an empty, overflowing, or out-of-image source/destination range.");
            return false;
        }
        const PeSection* target = sectionForRva(pe, block.destinationRVA, false);
        if (!target || destinationEnd > static_cast<uint64_t>(target->rva) +
            std::max<uint32_t>(target->virtualSize, target->rawSize)) {
            addIssue(issues, StaticUnpackSeverity::Error, "manual-block-target",
                     "A manual block crosses a PE section boundary.");
            return false;
        }
        if (block.codec == StaticUnpackCodec::Stored && block.compressedSize != block.outputLimit) {
            addIssue(issues, StaticUnpackSeverity::Error, "manual-stored-size",
                     "Stored blocks require exact equal source and destination sizes.");
            return false;
        }
        LzmaProperties parsed;
        if (block.codec == StaticUnpackCodec::Lzma1 &&
            (!block.hasLzmaProperties ||
             !parseLzmaProperties(block.lzmaProperties.data(), 5, options.maxDictionaryBytes, parsed))) {
            addIssue(issues, StaticUnpackSeverity::Error, "manual-lzma-properties",
                     "A manual LZMA1 block lacks valid bounded properties.");
            return false;
        }
        destinations.emplace_back(block.destinationRVA, destinationEnd);
        block.confidence = 1.0f;
        block.evidence = "Analyst-supplied finite block descriptor";
    }
    std::sort(destinations.begin(), destinations.end());
    for (size_t i = 1; i < destinations.size(); ++i) {
        if (destinations[i].first < destinations[i - 1].second) {
            addIssue(issues, StaticUnpackSeverity::Error, "manual-block-overlap",
                     "Manual destination blocks overlap; recovery was refused transactionally.");
            return false;
        }
    }
    return true;
}

std::string buildReport(const StaticUnpackResult& result) {
    std::ostringstream s;
    s << "DisasmStudio static packed-output recovery report\n"
      << "strategy: " << StaticUnpackStrategyName(result.strategy) << "\n"
      << "confidence: " << std::fixed << std::setprecision(2) << result.confidence << "\n"
      << "decoded: " << (result.decoded ? "yes" : "no") << "\n"
      << "disk PE ready: " << (result.diskImageReady ? "yes" : "no") << "\n"
      << "cancelled: " << (result.cancelled ? "yes" : "no") << "\n"
      << "entry RVA: " << hexValue(result.entryRVA) << "\n"
      << "OEP trust: " << (result.oepTrusted ? "trusted" : "UNVERIFIED") << "\n"
      << "OEP assessment: " << (result.oepAssessment.empty() ? "not established" : result.oepAssessment) << "\n"
      << "blocks: " << result.blocks.size() << "\n";
    if (!result.probe.summary.empty()) s << "detection: " << result.probe.summary << "\n";
    s << "VMProtect attribution: " << (result.probe.likelyVmProtect ? "supported by format evidence" : "not established") << "\n";
    if (result.probe.packerInfoOffset)
        s << "PACKER_INFO descriptor offset: " << hexValue(result.probe.packerInfoOffset) << "\n";
    if (result.probe.lzmaPropertiesOffset)
        s << "LZMA properties file offset: " << hexValue(result.probe.lzmaPropertiesOffset) << "\n";
    for (size_t i = 0; i < result.blocks.size(); ++i) {
        const auto& b = result.blocks[i];
        s << "  [" << i << "] " << StaticUnpackCodecName(b.codec)
          << " src-rva=" << hexValue(b.sourceRVA)
          << " src-file=" << hexValue(b.sourceOffset)
          << " input-bound=" << b.compressedSize
          << " dst-rva=" << hexValue(b.destinationRVA)
          << " output=" << b.outputSize << "/" << b.outputLimit
          << " status=" << (b.status.empty() ? "not attempted" : b.status) << "\n"
          << "      evidence: " << b.evidence << "\n";
    }
    if (!result.probe.evidence.empty()) {
        s << "evidence:\n";
        for (const auto& evidence : result.probe.evidence)
            s << "  - [" << std::fixed << std::setprecision(2) << evidence.confidence << "] "
              << evidence.detail << " @ " << hexValue(evidence.fileOffset) << "\n";
    }
    if (result.diskImageReady) {
        s << "PE repairs: sections=" << result.repairs.sectionsRebuilt
          << ", relocations=" << result.repairs.relocationEntriesNormalized
          << ", restored-IAT=" << result.repairs.importSlotsRestored
          << ", load-config-fixed=" << result.repairs.loadConfigPointersRepaired
          << ", load-config-cleared=" << result.repairs.loadConfigPointersCleared << "\n";
    }
    if (!result.issues.empty()) {
        s << "diagnostics:\n";
        for (const auto& issue : result.issues)
            s << "  - " << issue.code << ": " << issue.message << "\n";
    }
    return s.str();
}

void appendPeIssues(const PeUnpackResult& pe, std::vector<StaticUnpackIssue>& issues) {
    for (const auto& item : pe.issues) {
        StaticUnpackSeverity severity = StaticUnpackSeverity::Info;
        if (item.severity == PeUnpackSeverity::Warning) severity = StaticUnpackSeverity::Warning;
        else if (item.severity == PeUnpackSeverity::Error) severity = StaticUnpackSeverity::Error;
        addIssue(issues, severity, "pe-" + item.code, item.message);
    }
}

} // namespace

const char* StaticUnpackStrategyName(StaticUnpackStrategy strategy) {
    switch (strategy) {
    case StaticUnpackStrategy::Auto: return "automatic";
    case StaticUnpackStrategy::VmprotectPackerInfo: return "VMProtect PACKER_INFO";
    case StaticUnpackStrategy::EmbeddedLzmaAlone: return "embedded LZMA-alone";
    case StaticUnpackStrategy::ManualBlocks: return "manual bounded blocks";
    }
    return "unknown";
}

const char* StaticUnpackCodecName(StaticUnpackCodec codec) {
    return codec == StaticUnpackCodec::Stored ? "stored" : "LZMA1";
}

const char* StaticUnpackPhaseName(StaticUnpackPhase phase) {
    switch (phase) {
    case StaticUnpackPhase::Idle: return "Idle";
    case StaticUnpackPhase::Probing: return "Probing";
    case StaticUnpackPhase::MappingImage: return "Mapping image";
    case StaticUnpackPhase::Decompressing: return "Decompressing";
    case StaticUnpackPhase::ReconstructingPe: return "Reconstructing PE";
    case StaticUnpackPhase::Complete: return "Complete";
    case StaticUnpackPhase::Failed: return "Failed";
    case StaticUnpackPhase::Cancelled: return "Cancelled";
    }
    return "Unknown";
}

StaticUnpackProbe ProbeStaticPackedPe(const std::vector<uint8_t>& input,
                                      const StaticUnpackOptions& options,
                                      const StaticUnpackCancelFn& cancelled,
                                      const StaticUnpackProgressFn& progress) {
    StaticUnpackProbe probe;
    publish(progress, StaticUnpackPhase::Probing, 0, input.size());
    if (!validCaps(options)) {
        addIssue(probe.issues, StaticUnpackSeverity::Error, "invalid-caps",
                 "Static-unpack caps are zero or exceed the fixed 512 MiB image, 64 MiB dictionary, 256-block, or 64-candidate limits.");
        probe.summary = "Invalid safety caps.";
        return probe;
    }
    if (input.empty() || input.size() > options.maxInputBytes) {
        addIssue(probe.issues, StaticUnpackSeverity::Error, "input-size",
                 "Input is empty or exceeds the configured static-unpack cap.");
        probe.summary = "Input rejected by the bounded static-unpack probe.";
        return probe;
    }
    if (options.strategy == StaticUnpackStrategy::ManualBlocks) {
        probe.recognized = !options.manualBlocks.empty() && options.manualBlocks.size() <= options.maxBlocks;
        probe.confidence = probe.recognized ? 1.0f : 0.0f;
        probe.recommended = StaticUnpackStrategy::ManualBlocks;
        probe.blocks = options.manualBlocks;
        probe.evidence.push_back({ "manual-plan", "Analyst supplied an explicit finite block plan.", 0,
                                   probe.confidence });
        probe.summary = probe.recognized ? "Explicit bounded manual recovery plan." : "Manual plan is empty or over cap.";
        return probe;
    }

    PeView pe;
    if (!parseDiskPe(input, options, pe, probe.issues)) {
        probe.summary = "The input is not a structurally bounded PE32/PE32+ image.";
        return probe;
    }
    size_t packedTargetCount = 0;
    for (const auto& section : pe.sections)
        if (!section.rawSize && !section.rawOffset && section.virtualSize &&
            !(section.characteristics & kScnUninitialized)) ++packedTargetCount;
    if (packedTargetCount > options.maxBlocks) {
        addIssue(probe.issues, StaticUnpackSeverity::Error, "block-cap",
                 "Virtual-only packed target count exceeds the configured block cap; partial table recovery was refused.");
        probe.summary = "Packed target count exceeds the configured block cap.";
        return probe;
    }
    const auto table = options.strategy == StaticUnpackStrategy::EmbeddedLzmaAlone
        ? std::optional<TableCandidate>{}
        : recoverPackerInfo(input, pe, options, cancelled, progress);
    if (wasCancelled(cancelled)) {
        addIssue(probe.issues, StaticUnpackSeverity::Info, "cancelled", "Probe cancelled before completion.");
        probe.summary = "Probe cancelled.";
        return probe;
    }
    if (table) {
        probe.recognized = true;
        probe.likelyVmProtect = table->validProperties;
        probe.confidence = table->confidence;
        probe.recommended = StaticUnpackStrategy::VmprotectPackerInfo;
        probe.packerInfoOffset = table->tableOffset - 8; // entry zero is the properties descriptor
        probe.lzmaPropertiesOffset = table->propertiesOffset;
        probe.blocks = table->blocks;
        probe.evidence.push_back({ "packer-info-table",
            "Ordered PACKER_INFO destinations exactly match every virtual-only non-BSS PE section.",
            table->tableOffset, table->confidence });
        if (table->validProperties)
            probe.evidence.push_back({ "lzma-properties",
                "The preceding PACKER_INFO entry resolves to valid bounded LZMA1 properties.",
                table->propertiesOffset, 0.90f });
        if (table->stored)
            probe.evidence.push_back({ "stored-extents",
                "No valid properties record exists, but every source extent exactly equals its destination extent.",
                table->tableOffset, table->confidence });
        probe.summary = table->validProperties
            ? "High-confidence VMProtect-style PACKER_INFO/LZMA block table recovered."
            : "VMProtect-style descriptor table recovered as exact stored blocks.";
        return probe;
    }

    float lzmaConfidence = 0.0f;
    uint64_t lzmaHeader = 0;
    bool lzmaCandidateCapReached = false;
    const auto lzma = options.strategy == StaticUnpackStrategy::VmprotectPackerInfo
        ? std::optional<StaticUnpackBlock>{}
        : recoverLzmaAlone(input, pe, options, cancelled, progress,
                           lzmaConfidence, lzmaHeader, lzmaCandidateCapReached);
    if (lzmaCandidateCapReached) {
        addIssue(probe.issues, StaticUnpackSeverity::Warning, "lzma-candidate-cap",
                 "Embedded LZMA probing reached the configured plausible-header candidate cap; later candidates were not inspected.");
    }
    if (lzma) {
        probe.recognized = true;
        probe.likelyVmProtect = true;
        probe.confidence = lzmaConfidence;
        probe.recommended = StaticUnpackStrategy::EmbeddedLzmaAlone;
        probe.lzmaPropertiesOffset = lzmaHeader;
        probe.blocks.push_back(*lzma);
        probe.evidence.push_back({ "lzma-alone",
            "Finite LZMA-alone container header was found inside a VMProtect-named section.",
            lzmaHeader, lzmaConfidence });
        probe.summary = "Embedded bounded LZMA-alone stream is the best available static strategy.";
    } else {
        probe.summary = "No bounded PACKER_INFO table or finite LZMA-alone container was recovered.";
        addIssue(probe.issues, StaticUnpackSeverity::Warning, "no-container",
                 "Static recovery found no supported container; live Adaptive Unpack remains appropriate.");
    }
    return probe;
}

static StaticUnpackResult staticUnpackPeImpl(const std::vector<uint8_t>& input,
                                             const StaticUnpackOptions& options,
                                             const StaticUnpackCancelFn& cancelled,
                                             const StaticUnpackProgressFn& progress) {
    StaticUnpackResult result;
    if (!validCaps(options)) {
        addIssue(result.issues, StaticUnpackSeverity::Error, "invalid-caps",
                 "Static-unpack caps exceed fixed safety ceilings or are zero.");
        publish(progress, StaticUnpackPhase::Failed);
        result.report = buildReport(result);
        return result;
    }
    if (input.empty() || input.size() > options.maxInputBytes) {
        addIssue(result.issues, StaticUnpackSeverity::Error, "input-size",
                 "Input is empty or exceeds the configured static-unpack cap.");
        publish(progress, StaticUnpackPhase::Failed);
        result.report = buildReport(result);
        return result;
    }

    result.probe = ProbeStaticPackedPe(input, options, cancelled, progress);
    if (wasCancelled(cancelled)) {
        result.cancelled = true;
        result.issues = result.probe.issues;
        addIssue(result.issues, StaticUnpackSeverity::Info, "cancelled", "Static unpack cancelled during container probing.");
        publish(progress, StaticUnpackPhase::Cancelled);
        result.report = buildReport(result);
        return result;
    }
    result.issues = result.probe.issues;
    result.confidence = result.probe.confidence;
    result.strategy = options.strategy == StaticUnpackStrategy::Auto
        ? result.probe.recommended : options.strategy;

    PeView pe;
    std::vector<StaticUnpackIssue> peParseIssues;
    if (!parseDiskPe(input, options, pe, peParseIssues)) {
        for (auto& issue : peParseIssues) result.issues.push_back(std::move(issue));
        publish(progress, StaticUnpackPhase::Failed);
        result.report = buildReport(result);
        return result;
    }
    initializeEntryAssessment(pe, result);
    if (options.hasOep) {
        result.oepTrusted = false;
        result.oepAssessment = "An analyst-selected OEP was supplied but has not yet passed mapped-PE reconstruction validation.";
    }
    if (!options.retainPackedSections) {
        addIssue(result.issues, StaticUnpackSeverity::Warning, "strip-unsupported",
                 "Packer-section removal is not implemented safely; sections will be retained despite the request.");
    }

    if (result.strategy == StaticUnpackStrategy::ManualBlocks) {
        if (!validateManualBlocks(input, pe, options, result.blocks, result.issues)) {
            publish(progress, StaticUnpackPhase::Failed);
            result.report = buildReport(result);
            return result;
        }
        result.confidence = 1.0f;
    } else {
        if (!result.probe.recognized || result.probe.blocks.empty() ||
            result.probe.recommended != result.strategy) {
            addIssue(result.issues, StaticUnpackSeverity::Error, "strategy-unavailable",
                     "The selected static strategy has no validated finite block plan for this input.");
            publish(progress, StaticUnpackPhase::Failed);
            result.report = buildReport(result);
            return result;
        }
        result.blocks = result.probe.blocks;
    }
    if (result.blocks.size() > options.maxBlocks) {
        addIssue(result.issues, StaticUnpackSeverity::Error, "block-cap", "Recovered block count exceeds the configured cap.");
        publish(progress, StaticUnpackPhase::Failed);
        result.report = buildReport(result);
        return result;
    }

    uint64_t totalOutput = 0;
    uint64_t largestBlock = 0;
    for (const auto& block : result.blocks) {
        if (!checkedAdd(totalOutput, block.outputLimit, totalOutput) || totalOutput > options.maxOutputBytes) {
            addIssue(result.issues, StaticUnpackSeverity::Error, "output-cap",
                     "Aggregate decompressed output exceeds the configured cap.");
            publish(progress, StaticUnpackPhase::Failed);
            result.report = buildReport(result);
            return result;
        }
        largestBlock = std::max(largestBlock, block.outputLimit);
    }
    uint64_t transientOutputBytes = 0;
    if (!checkedAdd(pe.sizeImage, largestBlock, transientOutputBytes) ||
        transientOutputBytes > options.maxOutputBytes) {
        addIssue(result.issues, StaticUnpackSeverity::Error, "workspace-cap",
                 "Mapped image plus the largest decoder block exceeds the configured output-workspace cap.");
        publish(progress, StaticUnpackPhase::Failed);
        result.report = buildReport(result);
        return result;
    }
    uint64_t decodePeak = input.size();
    if (!checkedAdd(decodePeak, pe.sizeImage, decodePeak) ||
        !checkedAdd(decodePeak, largestBlock, decodePeak)) decodePeak = UINT64_MAX;
    uint64_t rebuildPeak = input.size();
    const unsigned imageCopies = options.rebuildDiskPe
        ? ((options.runtimeImageBase && options.runtimeImageBase != pe.preferredBase) ? 4u : 3u)
        : 1u;
    for (unsigned i = 0; i < imageCopies && rebuildPeak != UINT64_MAX; ++i)
        if (!checkedAdd(rebuildPeak, pe.sizeImage, rebuildPeak)) rebuildPeak = UINT64_MAX;
    if (std::max(decodePeak, rebuildPeak) > kHardEstimatedPeakBytes) {
        addIssue(result.issues, StaticUnpackSeverity::Error, "memory-budget",
                 "Estimated decoder/reconstruction peak exceeds the fixed 1 GiB worker budget.");
        publish(progress, StaticUnpackPhase::Failed);
        result.report = buildReport(result);
        return result;
    }

    publish(progress, StaticUnpackPhase::MappingImage, 0, pe.sizeImage, 0,
            0, static_cast<uint32_t>(result.blocks.size()));
    std::vector<uint8_t> mapped;
    if (!buildMappedImage(input, pe, mapped)) {
        addIssue(result.issues, StaticUnpackSeverity::Error, "map-image",
                 "File-backed PE sections could not be copied into a bounded mapped image.");
        publish(progress, StaticUnpackPhase::Failed);
        result.report = buildReport(result);
        return result;
    }

    uint64_t outputDone = 0;
    std::vector<uint8_t> standalone;
    bool allBlocks = true;
    for (size_t i = 0; i < result.blocks.size(); ++i) {
        auto& block = result.blocks[i];
        publish(progress, StaticUnpackPhase::Decompressing, 0, block.outputLimit,
                outputDone, static_cast<uint32_t>(i), static_cast<uint32_t>(result.blocks.size()));
        if (wasCancelled(cancelled)) {
            result.cancelled = true;
            block.status = "cancelled before block start";
            allBlocks = false;
            break;
        }
        uint64_t sourceEnd = 0;
        if (!block.compressedSize || !block.outputLimit ||
            !checkedAdd(block.sourceOffset, block.compressedSize, sourceEnd) || sourceEnd > input.size()) {
            block.status = "invalid finite source/output bounds";
            addIssue(result.issues, StaticUnpackSeverity::Error, "block-bounds",
                     "Block " + std::to_string(i) + " exceeds its validated file/output extent.");
            allBlocks = false;
            break;
        }

        std::vector<uint8_t> decoded;
        if (block.codec == StaticUnpackCodec::Stored) {
            if (block.compressedSize != block.outputLimit) {
                block.status = "stored sizes differ";
                addIssue(result.issues, StaticUnpackSeverity::Error, "stored-size",
                         "Stored block source and destination lengths differ.");
                allBlocks = false;
                break;
            }
            decoded.assign(input.begin() + static_cast<size_t>(block.sourceOffset),
                           input.begin() + static_cast<size_t>(sourceEnd));
            block.status = "copied exact stored extent";
        } else {
            const bool exactOutput = result.strategy == StaticUnpackStrategy::EmbeddedLzmaAlone;
            const auto lzma = decodeLzma1(input.data() + static_cast<size_t>(block.sourceOffset),
                static_cast<size_t>(block.compressedSize), block.lzmaProperties,
                options.maxDictionaryBytes, static_cast<size_t>(block.outputLimit),
                exactOutput ? std::optional<size_t>(static_cast<size_t>(block.outputLimit)) : std::nullopt,
                cancelled,
                [&](uint64_t current) {
                    publish(progress, StaticUnpackPhase::Decompressing, current, block.outputLimit,
                            outputDone + current, static_cast<uint32_t>(i),
                            static_cast<uint32_t>(result.blocks.size()));
                });
            if (lzma.status == LzmaStatus::Cancelled) {
                result.cancelled = true;
                block.status = lzma.message;
                allBlocks = false;
                break;
            }
            if (lzma.status != LzmaStatus::Ok || lzma.output.empty()) {
                block.status = lzma.message;
                addIssue(result.issues, StaticUnpackSeverity::Error, "lzma-decode",
                         "Block " + std::to_string(i) + " failed bounded LZMA1 validation: " + lzma.message);
                allBlocks = false;
                break;
            }
            decoded = lzma.output;
            block.status = lzma.message + " Input consumed " + std::to_string(lzma.consumed) +
                " of bounded " + std::to_string(block.compressedSize) + " bytes.";
        }
        block.outputSize = decoded.size();
        block.complete = true;
        outputDone += decoded.size();

        if (result.strategy == StaticUnpackStrategy::EmbeddedLzmaAlone) {
            // A finite container may hold either one omitted PE section or an
            // entire disk PE.  Prefer the latter only after a full structural
            // parse; an incidental "MZ" prefix is not sufficient evidence.
            PeView standalonePe;
            std::vector<StaticUnpackIssue> ignored;
            if (parseDiskPe(decoded, options, standalonePe, ignored)) {
                block.destinationRVA = 0;
                block.status += " Decoded payload is a structurally valid complete disk PE.";
                standalone = std::move(decoded);
                continue;
            }
            if (block.destinationRVA == 0) {
                standalone = std::move(decoded);
                continue;
            }
        }
        uint64_t destinationEnd = 0;
        if (!checkedAdd(block.destinationRVA, decoded.size(), destinationEnd) || destinationEnd > mapped.size()) {
            block.complete = false;
            block.status = "decoded output exceeded mapped destination";
            addIssue(result.issues, StaticUnpackSeverity::Error, "block-destination",
                     "Decoded block does not fit its mapped PE destination.");
            allBlocks = false;
            break;
        }
        std::copy(decoded.begin(), decoded.end(), mapped.begin() + block.destinationRVA);
    }

    if (result.cancelled) {
        addIssue(result.issues, StaticUnpackSeverity::Info, "cancelled", "Static unpack cancelled at a decoder checkpoint.");
        publish(progress, StaticUnpackPhase::Cancelled, 0, 0, outputDone);
        result.report = buildReport(result);
        return result;
    }
    if (!allBlocks) {
        if (options.strategy == StaticUnpackStrategy::Auto &&
            result.strategy == StaticUnpackStrategy::VmprotectPackerInfo) {
            // The fallback is a new full decode/reconstruction attempt. Release
            // the failed attempt's image-sized workspaces before recursion so
            // the advertised aggregate worker-memory budget still describes
            // the real peak rather than only one side of the fallback.
            std::vector<uint8_t>().swap(mapped);
            std::vector<uint8_t>().swap(standalone);
            StaticUnpackOptions fallbackOptions = options;
            fallbackOptions.strategy = StaticUnpackStrategy::EmbeddedLzmaAlone;
            StaticUnpackResult fallback = staticUnpackPeImpl(input, fallbackOptions, cancelled,
                                                             progress);
            if (fallback.cancelled) return fallback;
            if (fallback.success || fallback.decoded) {
                fallback.probe.evidence.insert(fallback.probe.evidence.begin(), StaticUnpackEvidence{
                    "auto-strategy-fallback",
                    "The higher-confidence PACKER_INFO plan failed bounded decoding; automatic mode validated the embedded LZMA-alone alternative.",
                    result.probe.packerInfoOffset, 0.75f
                });
                addIssue(fallback.issues, StaticUnpackSeverity::Warning, "strategy-fallback",
                         "PACKER_INFO recovery failed validation, so automatic mode selected the independently bounded LZMA-alone result.");
                fallback.report = buildReport(fallback);
                return fallback;
            }
            addIssue(result.issues, StaticUnpackSeverity::Warning, "strategy-fallback-failed",
                     "PACKER_INFO decoding failed and no independently valid LZMA-alone fallback completed.");
        }
        // Transactional contract: do not expose a partly patched mapping as a
        // decoded artifact.  The original packed bytes remain available.
        publish(progress, StaticUnpackPhase::Failed, 0, 0, outputDone);
        result.report = buildReport(result);
        return result;
    }
    result.decoded = true;
    // Once a decoded disk image or mapped image exists, retaining the original
    // packed input as a second image-sized vector adds no failure-analysis value.
    std::vector<uint8_t>().swap(result.rawArtifact);

    if (!standalone.empty()) {
        std::vector<StaticUnpackIssue> decodedIssues;
        PeView decodedPe;
        if (!parseDiskPe(standalone, options, decodedPe, decodedIssues)) {
            for (auto& issue : decodedIssues) result.issues.push_back(std::move(issue));
            addIssue(result.issues, StaticUnpackSeverity::Error, "standalone-not-pe",
                     "The decoded standalone stream is not a structurally valid disk PE.");
            result.rawArtifact = std::move(standalone);
            result.success = !options.rebuildDiskPe;
            publish(progress, result.success ? StaticUnpackPhase::Complete : StaticUnpackPhase::Failed,
                    0, 0, outputDone);
            result.report = buildReport(result);
            return result;
        }
        result.entryRVA = decodedPe.entryRVA;
        result.oepTrusted = false;
        result.oepAssessment = "A complete disk PE was decoded from the container, but structural validity alone does not prove that its entry is an unpacked OEP.";
        if (options.hasOep) {
            // A complete decoded PE owns a distinct address space. The outer
            // packer's runtime base is unrelated and must never skew its OEP RVA.
            const uint64_t runtimeBase = decodedPe.preferredBase;
            if (options.oepVA < runtimeBase || options.oepVA - runtimeBase > UINT32_MAX) {
                addIssue(result.issues, StaticUnpackSeverity::Error, "oep-range",
                         "The analyst-selected OEP is outside the decoded standalone PE address range.");
                result.rawArtifact = std::move(standalone);
                publish(progress, StaticUnpackPhase::Failed, 0, 0, outputDone);
                result.report = buildReport(result);
                return result;
            }
            const uint32_t selectedRva = static_cast<uint32_t>(options.oepVA - runtimeBase);
            const PeSection* owner = sectionForRva(decodedPe, selectedRva, false);
            if (!owner || !(owner->characteristics & kScnExecutable) ||
                !writeLe<uint32_t>(standalone,
                                   static_cast<uint64_t>(decodedPe.optionalOffset) + 16,
                                   selectedRva)) {
                addIssue(result.issues, StaticUnpackSeverity::Error, "oep-section",
                         "The analyst-selected OEP is not inside an executable section of the decoded standalone PE.");
                result.rawArtifact = std::move(standalone);
                publish(progress, StaticUnpackPhase::Failed, 0, 0, outputDone);
                result.report = buildReport(result);
                return result;
            }
            result.entryRVA = selectedRva;
            result.oepTrusted = true;
            result.oepAssessment = "The analyst-selected OEP was validated against the decoded standalone PE and written to its optional header.";
        } else {
            addIssue(result.issues, StaticUnpackSeverity::Warning, "oep-unverified",
                     "The complete decoded PE is structurally valid, but its entry is not proven to be an unpacked OEP. Treat it as analysis-only or provide a validated OEP.");
        }
        result.image = std::move(standalone);
        result.diskImageReady = true;
        result.success = true;
        publish(progress, StaticUnpackPhase::Complete, outputDone, totalOutput, outputDone,
                static_cast<uint32_t>(result.blocks.size()), static_cast<uint32_t>(result.blocks.size()));
        result.report = buildReport(result);
        return result;
    }

    assessRecoveredEntry(pe, result.blocks, result);
    result.mappedImage = std::move(mapped);
    if (!options.rebuildDiskPe) {
        result.success = true;
        publish(progress, StaticUnpackPhase::Complete, outputDone, totalOutput, outputDone,
                static_cast<uint32_t>(result.blocks.size()), static_cast<uint32_t>(result.blocks.size()));
        result.report = buildReport(result);
        return result;
    }

    publish(progress, StaticUnpackPhase::ReconstructingPe, 0, result.mappedImage.size(), outputDone,
            static_cast<uint32_t>(result.blocks.size()), static_cast<uint32_t>(result.blocks.size()));
    PeUnpackOptions peOptions;
    peOptions.runtimeImageBase = options.runtimeImageBase ? options.runtimeImageBase : pe.preferredBase;
    peOptions.hasOep = options.hasOep;
    peOptions.oepVA = options.oepVA;
    peOptions.rebuildObservedImports = false; // static container metadata supplies no resolved live IAT evidence
    peOptions.retainRawMappedImage = false;   // result.mappedImage already owns this failure artifact
    PeUnpackResult rebuilt = RebuildMappedPe(result.mappedImage, peOptions);
    result.repairs = rebuilt.repairs;
    appendPeIssues(rebuilt, result.issues);
    if (rebuilt.success) {
        result.image = std::move(rebuilt.image);
        result.diskImageReady = true;
        result.entryRVA = rebuilt.entryRVA;
        if (options.hasOep) {
            result.oepTrusted = true;
            result.oepAssessment = "The analyst-selected OEP was validated against the decoded mapped PE and written to the disk image.";
        }
        if (!result.oepTrusted) {
            addIssue(result.issues, StaticUnpackSeverity::Warning, "oep-unverified",
                     "The PE was reconstructed for analysis, but its unchanged entry point is not a trusted unpacked OEP. Use a manual OEP or live Adaptive Unpack before calling it runnable/clean.");
        }
        addIssue(result.issues, StaticUnpackSeverity::Info, "packer-sections-retained",
                 "Packer sections were retained; safe reference-aware stripping is outside this static pass.");
        result.success = true;
        publish(progress, StaticUnpackPhase::Complete, result.image.size(), result.image.size(), outputDone,
                static_cast<uint32_t>(result.blocks.size()), static_cast<uint32_t>(result.blocks.size()));
    } else {
        addIssue(result.issues, StaticUnpackSeverity::Error, "pe-reconstruction",
                 "Blocks decoded, but safe disk-layout PE reconstruction failed; the mapped artifact was retained.");
        publish(progress, StaticUnpackPhase::Failed, 0, 0, outputDone);
    }
    result.report = buildReport(result);
    return result;
}

StaticUnpackResult StaticUnpackPe(const std::vector<uint8_t>& input,
                                  const StaticUnpackOptions& options,
                                  const StaticUnpackCancelFn& cancelled,
                                  const StaticUnpackProgressFn& progress) {
    StaticUnpackResult result = staticUnpackPeImpl(input, options, cancelled, progress);
    // Pure callers still receive the original failure artifact, but only after
    // recovery has failed. Successful calls never pay for an eager full-input
    // duplicate. The service can move its already-owned input instead.
    if (!result.decoded && result.rawArtifact.empty() && validCaps(options) &&
        !input.empty() && input.size() <= options.maxInputBytes)
        result.rawArtifact = input;
    return result;
}

static bool readWorkerInputPath(const std::string& inputPath, size_t cap,
                                std::vector<uint8_t>& bytes,
                                std::string& errorCode, std::string& errorMessage,
                                bool& cancelled,
                                const StaticUnpackCancelFn& cancelFn,
                                const StaticUnpackProgressFn& progressFn) {
    cancelled = false;
    try {
        std::u8string utf8Path(inputPath.size(), u8'\0');
        if (!inputPath.empty()) std::memcpy(utf8Path.data(), inputPath.data(), inputPath.size());
        const std::filesystem::path path(utf8Path);
        std::ifstream input(path, std::ios::binary | std::ios::ate);
        if (!input) {
            errorCode = "input-open";
            errorMessage = "The worker could not open the packed input path.";
            return false;
        }
        const std::streamoff end = input.tellg();
        if (end <= 0) {
            errorCode = "input-size";
            errorMessage = "The packed input file is empty or its size could not be queried.";
            return false;
        }
        const uint64_t size = static_cast<uint64_t>(end);
        if (size > cap || size > kHardInputBytes || size > static_cast<uint64_t>(SIZE_MAX)) {
            errorCode = "input-size";
            errorMessage = "The packed input file exceeds the configured 512 MiB ceiling.";
            return false;
        }
        input.seekg(0, std::ios::beg);
        if (!input) {
            errorCode = "input-seek";
            errorMessage = "The worker could not seek to the beginning of the packed input file.";
            return false;
        }
        bytes.resize(static_cast<size_t>(size)); // bad_alloc intentionally reaches the worker boundary
        size_t done = 0;
        constexpr size_t kReadChunk = 1u * 1024u * 1024u;
        while (done < bytes.size()) {
            if (wasCancelled(cancelFn)) {
                std::vector<uint8_t>().swap(bytes);
                cancelled = true;
                errorCode = "cancelled";
                errorMessage = "Static recovery was cancelled during the worker-side input read.";
                return false;
            }
            const size_t count = std::min(kReadChunk, bytes.size() - done);
            input.read(reinterpret_cast<char*>(bytes.data() + done),
                       static_cast<std::streamsize>(count));
            if (static_cast<size_t>(input.gcount()) != count) {
                std::vector<uint8_t>().swap(bytes);
                errorCode = "input-read";
                errorMessage = "The packed input file changed or became unreadable during the bounded worker read.";
                return false;
            }
            done += count;
            publish(progressFn, StaticUnpackPhase::Probing, done, bytes.size());
        }
        return true;
    } catch (const std::bad_alloc&) {
        throw;
    } catch (const std::exception& e) {
        errorCode = "input-path";
        errorMessage = std::string("The packed input path could not be read: ") + e.what();
        return false;
    } catch (...) {
        errorCode = "input-path";
        errorMessage = "The packed input path could not be read due to an unknown filesystem error.";
        return false;
    }
}

static void makeWorkerFailure(StaticUnpackResult& result,
                              StaticUnpackStrategy strategy,
                              const char* code, const char* message) noexcept {
    try {
        result = {};
        result.strategy = strategy;
        addIssue(result.issues, StaticUnpackSeverity::Error, code, message);
        result.report = buildReport(result);
    } catch (...) {
        // Moving an empty result through the service is still preferable to a
        // process-terminating exception when the allocator is exhausted.
        try { result = {}; result.strategy = strategy; } catch (...) {}
    }
}

struct StaticUnpackService::Impl {
    mutable std::mutex mutex;
    std::condition_variable wake;
    std::condition_variable idle;
    std::optional<StaticUnpackRequest> queued;
    std::optional<StaticUnpackResult> finished;
    StaticUnpackProgress currentProgress{};
    std::thread worker;
    std::atomic<bool> cancelRequested{false};
    bool running = false;
    bool quit = false;
    StaticUnpackStrategy activeStrategy = StaticUnpackStrategy::Auto;

    Impl() {
        // The worker may wake immediately, so launch it only after the complete
        // queue/progress/cancellation state has been constructed.
        worker = std::thread([this] { guardedThreadMain(); });
    }

    ~Impl() {
        {
            std::lock_guard<std::mutex> lock(mutex);
            quit = true;
            cancelRequested.store(true, std::memory_order_release);
        }
        wake.notify_all();
        if (worker.joinable()) worker.join();
    }

    void setProgress(const StaticUnpackProgress& value) {
        std::lock_guard<std::mutex> lock(mutex);
        currentProgress = value;
    }

    void publishFatalWorkerFailure() noexcept {
        StaticUnpackResult result;
        makeWorkerFailure(result, activeStrategy, "worker-boundary",
                          "Static recovery stopped safely after an unexpected worker-boundary exception.");
        try {
            std::lock_guard<std::mutex> lock(mutex);
            queued.reset();
            running = false;
            quit = true;
            currentProgress = { StaticUnpackPhase::Failed, 0, 0, 0, 0, 0 };
            finished = std::move(result);
        } catch (...) {
            cancelRequested.store(true, std::memory_order_release);
        }
        idle.notify_all();
        wake.notify_all();
    }

    void guardedThreadMain() noexcept {
        try {
            threadMain();
        } catch (...) {
            publishFatalWorkerFailure();
        }
    }

    void threadMain() {
        for (;;) {
            StaticUnpackRequest request;
            {
                std::unique_lock<std::mutex> lock(mutex);
                wake.wait(lock, [&] { return quit || queued.has_value(); });
                if (quit) break;
                request = std::move(*queued);
                queued.reset();
                running = true;
                activeStrategy = request.options.strategy;
                currentProgress = { StaticUnpackPhase::Probing, 0, request.input.size(), 0, 0, 0 };
            }
            StaticUnpackResult result;
            try {
                bool sourceReady = true;
                if (request.input.empty()) {
                    std::string code, message;
                    bool readCancelled = false;
                    sourceReady = readWorkerInputPath(request.inputPath,
                                                      request.options.maxInputBytes,
                                                      request.input, code, message,
                                                      readCancelled,
                                                      [this] { return cancelRequested.load(std::memory_order_acquire); },
                                                      [this](const StaticUnpackProgress& p) { setProgress(p); });
                    if (!sourceReady) {
                        result.strategy = request.options.strategy;
                        result.cancelled = readCancelled;
                        addIssue(result.issues, readCancelled ? StaticUnpackSeverity::Info : StaticUnpackSeverity::Error,
                                 std::move(code), std::move(message));
                        result.report = buildReport(result);
                    }
                }
                if (sourceReady && request.verifySourceIdentity &&
                    (request.input.size() != request.expectedSourceSize ||
                     contentIdentity(request.input) != request.expectedSourceHash)) {
                    result.strategy = request.options.strategy;
                    addIssue(result.issues, StaticUnpackSeverity::Error, "input-identity",
                             "The packed file changed after it was loaded; static recovery refused to analyze bytes under a stale source identity.");
                    result.report = buildReport(result);
                    sourceReady = false;
                    std::vector<uint8_t>().swap(request.input);
                }
                if (sourceReady) {
                    result = staticUnpackPeImpl(request.input, request.options,
                        [this] { return cancelRequested.load(std::memory_order_acquire); },
                        [this](const StaticUnpackProgress& p) { setProgress(p); });
                }
                if (!result.decoded && result.rawArtifact.empty() && !request.input.empty())
                    result.rawArtifact = std::move(request.input);
            } catch (const std::bad_alloc&) {
                makeWorkerFailure(result, request.options.strategy, "worker-memory",
                                  "Static recovery ran out of memory; the worker stopped without terminating the application.");
                if (result.rawArtifact.empty() && !request.input.empty())
                    result.rawArtifact = std::move(request.input);
            } catch (const std::exception& e) {
                try {
                    const std::string message = std::string("Static recovery worker failed safely: ") + e.what();
                    makeWorkerFailure(result, request.options.strategy, "worker-exception", message.c_str());
                } catch (...) {
                    makeWorkerFailure(result, request.options.strategy, "worker-exception",
                                      "Static recovery worker failed safely with a standard exception.");
                }
                if (result.rawArtifact.empty() && !request.input.empty())
                    result.rawArtifact = std::move(request.input);
            } catch (...) {
                makeWorkerFailure(result, request.options.strategy, "worker-exception",
                                  "Static recovery worker failed safely with an unknown exception.");
                if (result.rawArtifact.empty() && !request.input.empty())
                    result.rawArtifact = std::move(request.input);
            }
            if (result.cancelled)
                setProgress({ StaticUnpackPhase::Cancelled, 0, 0, 0, 0, 0 });
            else if (!result.success)
                setProgress({ StaticUnpackPhase::Failed, 0, 0, 0, 0, 0 });
            {
                std::lock_guard<std::mutex> lock(mutex);
                finished = std::move(result);
                running = false;
            }
            idle.notify_all();
        }
    }
};

StaticUnpackService::StaticUnpackService() : impl_(std::make_unique<Impl>()) {}
StaticUnpackService::~StaticUnpackService() = default;

bool StaticUnpackService::request(StaticUnpackRequest request) {
    const bool hasBytes = !request.input.empty();
    const bool hasPath = !request.inputPath.empty();
    if (!impl_ || !validCaps(request.options) || hasBytes == hasPath ||
        (hasBytes && request.input.size() > request.options.maxInputBytes)) return false;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (impl_->quit || impl_->running || impl_->queued) return false;
        impl_->finished.reset();
        impl_->cancelRequested.store(false, std::memory_order_release);
        impl_->currentProgress = { StaticUnpackPhase::Probing, 0, request.input.size(), 0, 0, 0 };
        impl_->queued = std::move(request);
    }
    impl_->wake.notify_one();
    return true;
}

bool StaticUnpackService::pending() const {
    if (!impl_) return false;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->running || impl_->queued.has_value();
}

StaticUnpackProgress StaticUnpackService::progress() const {
    if (!impl_) return {};
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->currentProgress;
}

bool StaticUnpackService::tryTakeResult(StaticUnpackResult& out) {
    if (!impl_) return false;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (!impl_->finished) return false;
    out = std::move(*impl_->finished);
    impl_->finished.reset();
    return true;
}

void StaticUnpackService::cancel() {
    if (!impl_) return;
    impl_->cancelRequested.store(true, std::memory_order_release);
    impl_->wake.notify_one();
}

void StaticUnpackService::cancelAndWaitIdle() {
    if (!impl_) return;
    impl_->cancelRequested.store(true, std::memory_order_release);
    std::unique_lock<std::mutex> lock(impl_->mutex);
    impl_->queued.reset();
    impl_->idle.wait(lock, [&] { return !impl_->running; });
    impl_->finished.reset();
    impl_->currentProgress = {};
}

} // namespace ds
