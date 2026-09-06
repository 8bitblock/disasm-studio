#pragma once

// Private, fixed-layout x64 helper protocol. This is not a scripting/plugin API.
// Both sides copy records; no STL objects, target-owned strings, vtables or native
// HANDLE values cross this boundary. Stop records are immutable while their
// Win32 debug event is held. Control publication occurs under that same event.
#include <cstddef>
#include <cstdint>
#include <type_traits>

namespace ds {

inline constexpr uint64_t kGmlProtocolMagic = 0x314742444D474453ull; // DSGMDBG1
inline constexpr uint32_t kGmlProtocolVersion = 1;
inline constexpr uint32_t kGmlStopExceptionCode = 0xE0474D01u;
inline constexpr uint32_t kGmlNoCodeIndex = UINT32_MAX;
inline constexpr uint32_t kGmlMaxBreakpoints = 4096;
inline constexpr uint32_t kGmlMaxFrames = 128;
inline constexpr uint32_t kGmlMaxNumericSlots = 1024;
inline constexpr uint32_t kGmlMaxInstances = 4096;
inline constexpr uint32_t kGmlMaxInstanceLifetimes = 16384;

struct GmlCodeLocation {
    uint64_t archiveHash = 0;
    uint32_t codeIndex = 0;
    uint32_t byteOffset = 0; // relative to shared root bytecode base, never a process VA
    uint32_t parentCodeIndex = kGmlNoCodeIndex;
    uint32_t reserved = 0;
    bool operator==(const GmlCodeLocation&) const = default;
};

struct GmlPauseIdentity {
    uint32_t pid = 0;
    uint32_t tid = 0;
    uint64_t sessionGeneration = 0;
    uint64_t helperGeneration = 0;
    uint64_t stopSequence = 0;
    bool operator==(const GmlPauseIdentity&) const = default;
};

enum class GmlControlCommand : uint32_t {
    None = 0, Continue, Pause, StepInto, StepOver, StepOut, Disable
};
enum class GmlStopReason : uint32_t {
    None = 0, Breakpoint, Pause, Step, Entry, Error
};
enum class GmlNumericKind : uint32_t { None = 0, Real, Int32, Int64, Boolean };
enum class GmlVariableScope : uint32_t { Global = 0, UniqueObject, SessionInstance, FrameLocal };
enum class GmlValueAvailability : uint32_t { Unavailable = 0, Available, Truncated };
enum class GmlSlotStorage : uint32_t { Unavailable = 0, Canonical, Copied };
inline constexpr uint32_t kGmlFrameAddressValid = 1u;
inline constexpr uint32_t kGmlFrameStackTopValid = 2u;
inline constexpr uint32_t kGmlFrameLocalsAvailable = 4u;
inline constexpr uint32_t kGmlFrameLocationIsContinuation = 8u; // suspended caller, not current opcode
inline constexpr uint32_t kGmlFrameKnownFlags = 15u;

// Exact 16-byte runner value projection for the validated first x64 adapter.
// The adapter supplies the numeric tag mapping; unrecognized tags stay opaque.
struct GmlRValue {
    uint64_t payload = 0;
    uint32_t flags = 0;
    uint32_t typeTag = 0;
    bool operator==(const GmlRValue&) const = default;
};

struct GmlHelperFrame {
    uint64_t frameId = 0; // session-local monotonic incarnation, not stack address
    uint64_t parentFrameId = 0;
    uint64_t instanceId = 0; // session-local instance incarnation
    GmlCodeLocation location;
    uint32_t depth = 0; // root frame = 0
    uint32_t reserved = 0;
    uint64_t frameAddress = 0; // evidence only; frameId is the incarnation identity
    uint64_t operandStackTop = 0; // captured register when runner has not spilled it
    uint32_t flags = 0;
    GmlValueAvailability localsAvailability = GmlValueAvailability::Unavailable;
    uint64_t localObject = 0; // transient canonical owner; host revalidates under held event
    uint64_t selfObject = 0;
    uint64_t logicalAnchor = 0; // exact saved-record anchor within frameAddress's native context
    uint64_t arguments = 0;
    uint32_t argumentCount = 0;
    GmlValueAvailability selfAvailability = GmlValueAvailability::Unavailable;
    uint32_t runtimeInstanceNumber = 0; // exact observed CInstance raw id; zero for ordinary YYObject
    uint32_t ownerReserved = 0;
};

struct GmlHelperNumericSlot {
    uint64_t address = 0; // runtime address, meaningful only for the enclosing stop
    uint64_t frameId = 0;
    uint64_t instanceId = 0;
    GmlRValue value;
    uint32_t variableIndex = 0;
    GmlNumericKind kind = GmlNumericKind::None;
    uint32_t writable = 0; // exactly 0/1; adapter proves a plain numeric value slot
    uint32_t reserved = 0;
    GmlSlotStorage storage = GmlSlotStorage::Unavailable;
    GmlValueAvailability availability = GmlValueAvailability::Unavailable;
    uint32_t runtimeVariableId = 0;
    GmlVariableScope scope = GmlVariableScope::Global;
    uint32_t objectIndex = kGmlNoCodeIndex;
    uint32_t nameLength = 0; // 0 unavailable; 1..63 exact; 64 truncated, not an identity
    char name[64]{};
    uint64_t ownerObject = 0; // canonical map owner; never a durable watch identity
    uint32_t runtimeInstanceNumber = 0;
    uint32_t ownerReserved = 0;
};

struct GmlHelperControl {
    uint64_t magic = kGmlProtocolMagic;
    uint32_t version = kGmlProtocolVersion;
    uint32_t byteSize = sizeof(GmlHelperControl);
    uint64_t nonce = 0;
    uint64_t commandSequence = 0;
    GmlPauseIdentity expectedStop;
    GmlControlCommand command = GmlControlCommand::None;
    uint32_t breakpointCount = 0;
    uint64_t anchorFrameId = 0;
    uint64_t anchorParentFrameId = 0;
    GmlCodeLocation anchorLocation;
    uint32_t anchorDepth = 0;
    uint32_t reserved = 0;
    uint32_t selectedObjectIndex = kGmlNoCodeIndex; // all registry instances of this object
    uint32_t selectionReserved = 0;
    uint64_t selectedInstanceId = 0; // mutually exclusive with selectedObjectIndex
    GmlCodeLocation breakpoints[kGmlMaxBreakpoints]{};
};

struct GmlHelperInstance {
    uint64_t instanceId = 0;
    uint64_t objectAddress = 0;
    uint32_t runtimeInstanceNumber = 0;
    uint32_t objectIndex = kGmlNoCodeIndex;
    GmlValueAvailability variablesAvailability = GmlValueAvailability::Unavailable;
    uint32_t reserved = 0;
};
// Helper-owned live table, published by initialize for frozen host validation.
// Even nonzero sequence commits objectAddress/instanceId; odd is mid-transition.
// Destruction retains the address with instanceId zero. Never persist this table.
struct GmlHelperInstanceLifetime {
    uint64_t objectAddress = 0;
    uint64_t instanceId = 0;
    uint64_t sequence = 0;
};

struct GmlHelperStop {
    uint64_t magic = kGmlProtocolMagic;
    uint32_t version = kGmlProtocolVersion;
    uint32_t byteSize = sizeof(GmlHelperStop);
    uint64_t nonce = 0;
    GmlPauseIdentity identity;
    GmlCodeLocation location;
    GmlStopReason reason = GmlStopReason::None;
    uint32_t frameCount = 0;
    uint32_t numericSlotCount = 0;
    uint32_t framesComplete = 0;
    uint32_t variablesComplete = 0;
    uint32_t reserved = 0;
    uint32_t adapterId = 0;
    uint32_t dispatchSiteId = 0; // matched normal/debug interpreter dispatch site
    uint32_t globalsComplete = 0; // bounded canonical global-map enumeration completed
    uint32_t scopeReserved = 0;
    uint32_t instanceCount = 0;
    uint32_t instancesComplete = 0; // complete registry, including deactivated instances
    uint32_t instanceVariablesComplete = 0; // exact selected instance/object domain only
    uint32_t instancesReserved = 0;
    uint32_t selectedObjectIndex = kGmlNoCodeIndex;
    uint32_t selectionReserved = 0;
    uint64_t selectedInstanceId = 0;
    GmlHelperFrame frames[kGmlMaxFrames]{}; // current frame first, then ancestors
    GmlHelperNumericSlot numericSlots[kGmlMaxNumericSlots]{};
    GmlHelperInstance instances[kGmlMaxInstances]{};
};

struct GmlHelperMailbox {
    GmlHelperControl control;
    GmlHelperStop stop;
};

inline constexpr uint32_t kGmlMaxHelperCodes = 32768;
inline constexpr uint32_t kGmlNubbyAdapterId = 1;
enum class GmlHelperInitStatus : uint32_t { Pending = 0, Ready, InvalidConfig, UnsupportedRunner, ResourceFailure, AlreadyInitialized };
struct GmlHelperCodeMap {
    uint32_t codeIndex = 0;
    uint32_t parentCodeIndex = kGmlNoCodeIndex;
    uint32_t entryOffset = 0;
    uint32_t byteSize = 0; // shared root blob extent
};
// Fixed one-time initialization entry. The host owns this remote allocation and
// may free it only after its initialization thread has exited. hostProcessHandle
// is the one handle exception: a SYNCHRONIZE-only handle duplicated INTO target.
// On successful Ready, the helper owns it. The helper borrows mailboxAddress until
// process exit; normal detach disables the resident gates before releasing events.
struct GmlHelperInitConfig {
    uint64_t magic = kGmlProtocolMagic;
    uint32_t version = kGmlProtocolVersion;
    uint32_t byteSize = sizeof(GmlHelperInitConfig);
    uint64_t nonce = 0;
    uint32_t pid = 0;
    uint32_t adapterId = kGmlNubbyAdapterId;
    uint64_t sessionGeneration = 0;
    uint64_t helperGeneration = 0;
    uint64_t archiveHash = 0;
    uint64_t runnerBase = 0;
    uint64_t runnerSize = 0;
    uint64_t mailboxAddress = 0;
    uint64_t hostProcessHandle = 0;
    uint64_t dispatchContinuation = 0;
    uint64_t entryContinuation = 0;
    uint64_t dispatchRelayAddress = 0; // optional host-owned 14-byte near FF25 relay
    uint64_t entryRelayAddress = 0;
    uint64_t instanceConstructorContinuation = 0;
    uint64_t instanceDestructorContinuation = 0;
    uint64_t instanceConstructorRelayAddress = 0;
    uint64_t instanceDestructorRelayAddress = 0;
    uint64_t instanceLifetimesAddress = 0; // output on Ready; borrowed until shutdown
    uint32_t instanceLifetimesCapacity = 0; // output, exactly kGmlMaxInstanceLifetimes
    uint32_t lifetimeReserved = 0;
    uint32_t codeCount = 0;
    uint32_t reserved = 0;
    GmlHelperInitStatus status = GmlHelperInitStatus::Pending;
    uint32_t errorCode = 0;
    GmlHelperCodeMap codes[kGmlMaxHelperCodes]{};
};

// Small stack-safe reader view for the bootstrap entry. Keep the full code map
// in its host/helper-owned allocation; remote thread stack reserves vary by EXE.
struct GmlHelperInitPrefix {
    uint64_t magic = 0;
    uint32_t version = 0, byteSize = 0;
    uint64_t nonce = 0;
    uint32_t pid = 0, adapterId = 0;
    uint64_t sessionGeneration = 0, helperGeneration = 0, archiveHash = 0;
    uint64_t runnerBase = 0, runnerSize = 0, mailboxAddress = 0, hostProcessHandle = 0;
    uint64_t dispatchContinuation = 0, entryContinuation = 0;
    uint64_t dispatchRelayAddress = 0, entryRelayAddress = 0;
    uint64_t instanceConstructorContinuation = 0, instanceDestructorContinuation = 0;
    uint64_t instanceConstructorRelayAddress = 0, instanceDestructorRelayAddress = 0;
    uint64_t instanceLifetimesAddress = 0;
    uint32_t instanceLifetimesCapacity = 0, lifetimeReserved = 0;
    uint32_t codeCount = 0, reserved = 0;
    GmlHelperInitStatus status = GmlHelperInitStatus::Pending;
    uint32_t errorCode = 0;
};
static_assert(sizeof(GmlHelperInitPrefix) == offsetof(GmlHelperInitConfig, codes));
static_assert(offsetof(GmlHelperInitPrefix, instanceConstructorContinuation) == offsetof(GmlHelperInitConfig, instanceConstructorContinuation));
static_assert(offsetof(GmlHelperInitPrefix, status) == offsetof(GmlHelperInitConfig, status));

static_assert(sizeof(GmlCodeLocation) == 24);
static_assert(sizeof(GmlPauseIdentity) == 32);
static_assert(sizeof(GmlRValue) == 16 && offsetof(GmlRValue, typeTag) == 12);
static_assert(sizeof(GmlHelperFrame) == 128 && sizeof(GmlHelperNumericSlot) == 160);
static_assert(std::is_trivially_copyable_v<GmlHelperMailbox>);
static_assert(std::is_standard_layout_v<GmlHelperMailbox>);
static_assert(sizeof(GmlHelperMailbox) < 512u * 1024u);

} // namespace ds
