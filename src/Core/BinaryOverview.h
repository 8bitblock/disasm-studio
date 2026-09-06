#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ds {

class BinaryFile;
struct FuncResult;
enum class Arch;

inline constexpr size_t kBinaryOverviewLeadLimit = 12;
inline constexpr size_t kBinaryOverviewSourceLimit = 2048;

struct BinaryOverviewLead {
    std::string label;
    std::string evidence;
    uint64_t va = 0; // Every emitted lead is file-backed; VA zero is valid.
    bool code = true;
    bool inferred = false;
};

struct BinaryOverview {
    std::vector<BinaryOverviewLead> leads;
    bool entryDeclared = false;
    bool entryMapped = false;
    bool candidatesLimited = false;
};

// Metadata-only starting points: no decoding, byte scanning, or target execution.
// Results are deterministic in loader order, with authoritative function starts
// ahead of inferred ones. Candidate examination and retained text are bounded.
// The caller owns image/analysis identity checks and should cache the result.
BinaryOverview BuildBinaryOverview(
    const BinaryFile& binary,
    const std::vector<FuncResult>* functions = nullptr,
    std::optional<Arch> activeArch = std::nullopt);

} // namespace ds
