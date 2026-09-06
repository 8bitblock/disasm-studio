#pragma once

// Durable, platform-neutral Cheat-Engine-style address records.  This layer
// deliberately owns no process handle and performs no writes: callers provide
// the current module snapshot and an identity-bound reader, then apply a
// returned freeze write through ProcessMemorySession's transactional policy.

#include "MemoryScan.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

enum class MemoryTableBaseKind : uint8_t {
    Absolute = 0,
    ModuleRelative,
};

// Offsets use the same root-to-target convention as MemoryPointer:
//
//   cursor = absoluteAddress OR moduleBase + moduleOffset
//   for (offset : pointerOffsets) cursor = read_pointer(cursor) + offset
//
// Signed offsets are retained because real object layouts can point at an
// interior field and walk back to a containing object.
struct MemoryTableAddress {
    MemoryTableBaseKind kind = MemoryTableBaseKind::Absolute;
    uint64_t absoluteAddress = 0;

    std::string moduleName; // basename captured when the record was made
    std::string modulePath; // full path when known; preferred during lookup
    uint64_t moduleOffset = 0;

    std::vector<int64_t> pointerOffsets;
};

enum class MemoryFreezeMode : uint8_t {
    None = 0,
    Constant,
    Minimum,
    Maximum,
};

struct MemoryTableRecord {
    std::string description;
    std::string group;
    MemoryValueType type = MemoryValueType::UInt32;
    bool displayHex = false;
    bool nullTerminateText = false;
    MemoryTableAddress address;
    std::string desiredValueText;
    MemoryFreezeMode freezeMode = MemoryFreezeMode::None;

    // This is explicit authority for ProcessMemorySession to temporarily make
    // a read-only/executable page writable.  It is configuration and therefore
    // persists; it never bypasses that session's guard/no-access denial.
    bool allowProtectionChange = false;

    // Runtime-only authority.  Serialization writes these as false and loading
    // forcibly clears them, even if an untrusted table says true.  A table file
    // can therefore never cause reads/writes merely by being opened.
    bool enabled = false;
    bool freezeActive = false;
};

inline constexpr uint32_t kMemoryTableVersion = 1;
inline constexpr size_t kMemoryTableMaxSerializedBytes = 4u * 1024u * 1024u;
inline constexpr size_t kMemoryTableMaxRecords = 16'384;
inline constexpr size_t kMemoryTableMaxPointerDepth = 16;
inline constexpr size_t kMemoryTableMaxTitleBytes = 1024;
inline constexpr size_t kMemoryTableMaxDescriptionBytes = 4096;
inline constexpr size_t kMemoryTableMaxGroupBytes = 1024;
inline constexpr size_t kMemoryTableMaxModuleNameBytes = 1024;
inline constexpr size_t kMemoryTableMaxModulePathBytes = 32u * 1024u;
inline constexpr size_t kMemoryTableMaxDesiredValueBytes = 64u * 1024u;

struct MemoryTableDocument {
    uint32_t version = kMemoryTableVersion;
    std::string title;
    std::vector<MemoryTableRecord> records;
};

// A stable projection of a process module list. The resolver never consults the
// filesystem. Windows path separators and ASCII case are normalized locally.
struct MemoryTableModuleView {
    std::string name;
    std::string path;
    uint64_t base = 0;
    uint64_t size = 0; // zero means unknown
};

using MemoryTableReader =
    std::function<size_t(uint64_t address, void* output, size_t size)>;

enum class MemoryTableResolveStatus : uint8_t {
    Resolved = 0,
    InvalidAddress,
    InvalidPointerWidth,
    PointerDepthLimit,
    ModuleNotFound,
    AmbiguousModule,
    ModuleOffsetOutsideImage,
    NonCanonicalAddress,
    ReadFailure,
    ReaderException,
    NullPointer,
    NonCanonicalPointer,
    ArithmeticOverflow,
};

struct MemoryTableResolveResult {
    MemoryTableResolveStatus status = MemoryTableResolveStatus::InvalidAddress;
    uint64_t address = 0;       // last successfully established address
    uint64_t moduleBase = 0;    // zero for an absolute record
    size_t moduleIndex = static_cast<size_t>(-1);
    bool moduleMatchedByPath = false;
    size_t stepsResolved = 0;
    std::vector<uint64_t> pointerValues;
    std::vector<uint64_t> addresses; // base expression, then completed steps

    bool resolved() const noexcept {
        return status == MemoryTableResolveStatus::Resolved;
    }
};

// Exact normalized path identity wins over all basename matches. If no path
// matches, a unique case-insensitive module name/basename may be used. Multiple
// distinct-base matches are rejected rather than depending on enumeration
// order. The reader must return exactly pointerWidth bytes for each step.
MemoryTableResolveResult ResolveMemoryTableAddress(
    const MemoryTableAddress& address,
    std::span<const MemoryTableModuleView> modules,
    const MemoryTableReader& reader,
    uint8_t pointerWidth,
    bool requireCanonical = true);

inline MemoryTableResolveResult ResolveMemoryTableAddress(
    const MemoryTableRecord& record,
    std::span<const MemoryTableModuleView> modules,
    const MemoryTableReader& reader,
    uint8_t pointerWidth,
    bool requireCanonical = true) {
    return ResolveMemoryTableAddress(record.address, modules, reader,
                                     pointerWidth, requireCanonical);
}

enum class MemoryFreezeDecisionCode : uint8_t {
    Inactive = 0,
    AlreadySatisfied,
    WriteDesired,
    InvalidDesiredValue,
    InvalidCurrentValue,
    UnsupportedMode,
};

struct MemoryFreezeDecision {
    MemoryFreezeDecisionCode code = MemoryFreezeDecisionCode::Inactive;
    std::vector<uint8_t> bytes; // populated only for WriteDesired
    std::string error;

    bool shouldWrite() const noexcept {
        return code == MemoryFreezeDecisionCode::WriteDesired;
    }
};

// Low-level policy evaluator independent of the record's runtime switches.
// Constant compares canonical bytes exactly. Minimum/Maximum use the signedness
// encoded by MemoryValueType and IEEE-754 numeric ordering for floats; a NaN
// current value is outside either bound and is replaced by the finite limit.
MemoryFreezeDecision EvaluateMemoryFreezeValue(
    MemoryValueType type,
    MemoryFreezeMode mode,
    bool displayHex,
    std::string_view desiredValueText,
    std::span<const uint8_t> currentValue,
    bool nullTerminateText = false);

// Runtime-gated overload. Both enabled and freezeActive must be true.
MemoryFreezeDecision EvaluateMemoryFreeze(
    const MemoryTableRecord& record,
    std::span<const uint8_t> currentValue);

// Strict, bounded JSON codec. Output objects are changed only after complete
// validation. Unknown object fields are ignored for forward-compatible minor
// additions, while malformed known fields and unsupported versions fail.
bool SerializeMemoryTable(const MemoryTableDocument& document,
                          std::string& output,
                          std::string* error = nullptr);
bool DeserializeMemoryTable(std::string_view input,
                            MemoryTableDocument& output,
                            std::string* error = nullptr);

// Naming aliases make call sites read naturally when loading/saving text.
inline bool ParseMemoryTable(std::string_view input,
                             MemoryTableDocument& output,
                             std::string* error = nullptr) {
    return DeserializeMemoryTable(input, output, error);
}

} // namespace ds
