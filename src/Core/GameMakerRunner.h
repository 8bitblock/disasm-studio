#pragma once

// Built-in adapter for the exact inspected x64 runner. No runner functions are
// called: every projection uses a checked read supplied by the debugger/helper.
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace ds {

using GmlRunnerRead = bool (*)(void* owner, uint64_t address, void* output, size_t size);
struct GmlRunnerReader {
    void* owner = nullptr;
    GmlRunnerRead read = nullptr;
    bool copy(uint64_t address, void* output, size_t size) const noexcept;
};
struct GmlRunnerHookSite {
    uint32_t rva = 0, byteCount = 0;
    std::array<uint8_t, 16> original{};
};
enum class GmlRunnerCapability : uint32_t {
    InstructionStops=1u<<0, CallAwareSteps=1u<<1, Frames=1u<<2,
    Globals=1u<<3, Instances=1u<<4, Locals=1u<<5, NumericEdits=1u<<6,
    OperandStackValues=1u<<7, ComplexEdits=1u<<8
};
constexpr uint32_t GmlCapabilityBit(GmlRunnerCapability value) {return static_cast<uint32_t>(value);}
struct GmlRunnerCapabilities {
    uint32_t adapterId=0;
    uint32_t supported=0; // exact compiled profile; no claim of current pause authority
    uint32_t observed=0; // validated evidence obtained in this connection
    bool executableVerified=false,archiveVerified=false,runtimeVerified=false;
    bool supports(GmlRunnerCapability value)const noexcept{return runtimeVerified && (supported&GmlCapabilityBit(value));}
};
struct GmlRunnerProfile {
    uint32_t adapterId = 0;
    std::string_view name;
    std::string_view sha256;
    uint32_t imageSize = 0;
    GmlRunnerHookSite interpreterEntry, instructionDispatch;
    uint32_t debuggerObjectRva = 0;
    uint32_t globalObjectRva = 0;
    uint32_t variableNamesRva = 0, variableNameCountRva = 0;
    uint32_t modernNamesFlagRva = 0;
    uint32_t instanceVtableRva = 0, objectVtableRva = 0;
    uint32_t instanceRegistryRva = 0;
    GmlRunnerHookSite instanceConstructor, instanceDestructor;
    uint32_t capabilityMask=0;
};
const GmlRunnerProfile& NubbyGameMakerRunner() noexcept;
const GmlRunnerProfile* MatchGameMakerRunner(std::string_view sha256) noexcept;
// Dispatch relay has already entered the original interpreter's full native
// frame. Register this body-state unwind record for the relay range (offsets
// normalized to zero). The entry relay is leaf state before the first prolog op.
inline constexpr std::array<uint8_t, 24> kNubbyDispatchRelayUnwind {
    0x01,0x00,0x09,0x00,0x00,0x01,0x8a,0x00,0x00,0xf0,0x00,0xe0,
    0x00,0xd0,0x00,0xc0,0x00,0x70,0x00,0x60,0x00,0x30,0x00,0x00
};
inline constexpr uint32_t kNubbyInterpreterUnwindRva = 0x68ad20;
inline constexpr uint32_t kNubbyInterpreterEndRva = 0x286007;
inline constexpr uint32_t kNubbyInterpreterNativeFrameBytes = 0x488;
// Requires the disk hash match separately. Checks image headers and exact live
// hook bytes; refuses a concurrently enabled GameMaker IDE debugger.
bool ValidateGmlRunnerImage(const GmlRunnerReader&, uint64_t imageBase,
                          const GmlRunnerProfile&, const char** error = nullptr) noexcept;

inline constexpr uint32_t kGmlRunnerFrameMagic = 0xaabbccddu;
inline constexpr uint32_t kGmlRunnerMaxOperandCapacity = 64u * 1024u * 1024u;
inline constexpr uint32_t kGmlRunnerMaxObjectSlots = 65536;
inline constexpr uint32_t kGmlRunnerMaxCodeBytes = 64u * 1024u * 1024u;

struct GmlRunnerCodeView {
    uint64_t address = 0, blob = 0, bytecodeBase = 0, nameAddress = 0;
    uint32_t codeIndex = 0, entryOffset = 0, bytecodeLength = 0;
    uint32_t localsCount = 0, argumentsCount = 0;
};
bool ReadGmlRunnerCode(const GmlRunnerReader&, uint64_t imageBase, uint64_t codeAddress,
                       GmlRunnerCodeView&) noexcept;
// Code index, root blob/entry offset/length and name must then be compared with
// the exact archive by the host. Heap bytecode contains resolved operands, so a
// byte-for-byte comparison with data.win is intentionally not an identity test.

struct GmlRunnerContextView {
    uint64_t address = 0, nativeParent = 0, operandBuffer = 0, operandBufferEnd = 0;
    uint64_t localObject = 0, self = 0, other = 0, arguments = 0;
    uint64_t anchor = 0, operandStackTop = 0;
    uint32_t operandCapacity = 0, argumentCount = 0, logicalDepth = 0, byteOffset = 0;
    GmlRunnerCodeView code;
};
// preInstructionOffset and operandStackTop come from ECX and RDI at the exact
// normal dispatch site, where RBX is contextAddress. A parent context may instead
// be read with its spilled PC and a zero operandStackTop (unavailable).
bool ReadGmlRunnerContext(const GmlRunnerReader&, uint64_t imageBase,
    uint64_t contextAddress, uint32_t preInstructionOffset, uint64_t operandStackTop,
    GmlRunnerContextView&) noexcept;

struct GmlRunnerSavedFrameView {
    uint64_t anchor = 0, previousAnchor = 0, localObject = 0, self = 0, other = 0;
    uint64_t arguments = 0;
    uint32_t argumentCount = 0, returnOffset = 0;
    GmlRunnerCodeView code;
};
// Saved PC is the return continuation, not the call instruction. Root anchor is
// a sentinel; only call this logicalDepth times, stopping before that sentinel.
bool ReadGmlRunnerSavedFrame(const GmlRunnerReader&, uint64_t imageBase,
    const GmlRunnerContextView&, uint64_t anchor, GmlRunnerSavedFrameView&) noexcept;

struct GmlRunnerObjectView {
    uint64_t address = 0, directValues = 0, variableMap = 0;
    uint32_t variableCapacity = 0, type = 0;
    uint32_t instanceNumber = 0, objectIndex = UINT32_MAX;
    bool isInstance = false;
};
bool ReadGmlRunnerObject(const GmlRunnerReader&, uint64_t imageBase,
    uint64_t objectAddress, GmlRunnerObjectView&) noexcept;

// This is the runner's raw-instance-ID registry, rather than the current GML
// self. Read only while the target is stopped at a verified VM boundary. A
// complete traversal proves registry membership, not allocation lifetime: IDs
// and heap addresses can be reused. Incarnations require constructor/destructor
// observation, including an initial generation for preexisting instances.
inline constexpr uint32_t kGmlRunnerMaxInstanceBuckets = 65536;
inline constexpr uint32_t kGmlRunnerMaxInstances = 65536;
struct GmlRunnerInstanceRegistryView {
    uint64_t address = 0, buckets = 0;
    uint32_t mask = 0, count = 0;
};
struct GmlRunnerInstanceRecord {
    uint64_t nodeAddress = 0;
    GmlRunnerObjectView object;
};
struct GmlRunnerInstanceEnumeration {
    uint32_t registryCount = 0, visited = 0;
    bool complete = false, truncated = false;
};
using GmlRunnerInstanceVisitor = bool (*)(void* owner, const GmlRunnerInstanceRecord&);
bool ReadGmlRunnerInstanceRegistry(const GmlRunnerReader&, uint64_t imageBase,
    GmlRunnerInstanceRegistryView&) noexcept;
// No allocation. Each callback receives a validated instance. Returning false
// from the visitor or exhausting maxRecords produces a valid truncated result.
// A false return means unreadable/inconsistent links, object, or registry;
// previously delivered records must then remain explicitly incomplete.
bool EnumerateGmlRunnerInstances(const GmlRunnerReader&, uint64_t imageBase,
    uint32_t maxRecords, GmlRunnerInstanceVisitor, void* visitorOwner,
    GmlRunnerInstanceEnumeration&) noexcept;
struct GmlRunnerVariableMapView {
    uint64_t address = 0, entries = 0;
    uint32_t capacity = 0, count = 0, mask = 0;
};
struct GmlRunnerVariableEntry { uint64_t valueAddress = 0; uint32_t runtimeId = 0; };
bool ReadGmlRunnerVariableMap(const GmlRunnerReader&, uint64_t address,
    GmlRunnerVariableMapView&) noexcept;
// Empty/deleted entries return success with valueAddress zero. Values are the
// canonical 16-byte RValue slots. This never allocates an unmaterialized member.
bool ReadGmlRunnerVariableEntry(const GmlRunnerReader&, const GmlRunnerVariableMapView&,
    uint32_t slot, GmlRunnerVariableEntry&) noexcept;
// Fixed modern runtime name table, verified for this adapter. Returns false for
// dynamic/unrepresented names; never guesses a VARI id from a runtime id.
bool ReadGmlRunnerVariableName(const GmlRunnerReader&, uint64_t imageBase,
    uint32_t runtimeId, char* output, size_t capacity) noexcept;
bool ReadGmlRunnerString(const GmlRunnerReader&, uint64_t address,
    char* output, size_t capacity) noexcept;

} // namespace ds
