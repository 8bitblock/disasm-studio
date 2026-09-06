#include <windows.h>
#include "Core/GameMakerDebug.h"
#include "Core/GameMakerRunner.h"
#include "GameMakerFastGate.h"
#include "GameMakerXState.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <new>

using namespace ds;

extern "C" {
volatile long gDsGmlEnabled = 0;
volatile long long gDsGmlActiveGates = 0;
unsigned long long gDsGmlXsaveMask = 0;
unsigned long gDsGmlXsaveBytes = 512;
unsigned long long gDsGmlDispatchContinuation = 0;
unsigned long long gDsGmlEntryContinuation = 0;
unsigned long long gDsGmlInstanceConstructorContinuation = 0;
unsigned long long gDsGmlInstanceDestructorContinuation = 0;
unsigned long long gDsGmlFastControlSequenceAddress = 0;
volatile long long gDsGmlFastAcceptedSequence = 0;
volatile long gDsGmlFastAlwaysSlow = 1;
alignas(64) DsGmlFastThread gDsGmlFastThreads[kDsGmlFastThreads]{};
alignas(64) unsigned char gDsGmlBreakpointBloom[kDsGmlBreakpointBloomBytes]{};
}

namespace {
// Layout mirrors GameMakerGates.asm after its complete register save.
struct GateRegisters {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rdi, rsi, rbp, rbx, rdx, rcx, rax, flags;
};
static_assert(sizeof(GateRegisters) == 128 && offsetof(GateRegisters, rbx) == 88);
constexpr size_t kMaxThreads = 16, kMaxContexts = 64;
struct ContextTrack {
    uint64_t address = 0, invocationId = 0, codeAddress = 0;
    uint64_t frames[kGmlMaxFrames]{};
    uint64_t anchors[kGmlMaxFrames]{};
    uint32_t depth = 0;
    bool entryObserved = false;
    GmlRunnerCodeView code;
};
struct ThreadTrack {
    volatile LONG tid = 0;
    uint64_t progress = 0;
    uint64_t stepCommand = 0;
    GmlStepPlan step;
    ContextTrack contexts[kMaxContexts]{};
    GmlHelperStop projected;
};
struct RelayUnwind {
    RUNTIME_FUNCTION function{};
    void* allocation = nullptr;
    bool registered = false;
};
constexpr uint32_t kBreakpointPages = 8192;
struct BreakpointPage {
    uint32_t codeIndex = 0, page = 0;
    uint64_t wordBits = 0; // exact four-byte instruction offsets in a 256-byte page
    uint32_t occupied = 0;
};
struct State {
    uint64_t nonce = 0, session = 0, generation = 0, archive = 0, runnerBase = 0;
    HANDLE host = nullptr;
    GmlHelperMailbox* mailbox = nullptr;
    uint32_t codeCount = 0;
    GmlHelperCodeMap codes[kGmlMaxHelperCodes]{};
    SRWLOCK controlsLock = SRWLOCK_INIT;
    GmlHelperControl controls;
    GmlHelperControl controlScratch;
    BreakpointPage breakpointPages[kBreakpointPages]{};
    volatile LONG64 sequence = 0, nextIdentity = 0, nextStop = 0;
    volatile LONG stopOwner = 0;
    ThreadTrack threads[kMaxThreads]{};
    SRWLOCK instancesLock = SRWLOCK_INIT;
    GmlHelperInstanceLifetime lifetimes[kGmlMaxInstanceLifetimes]{};
    bool lifetimesComplete = true;
    RelayUnwind relays[4];
};
State* gState = nullptr;
HMODULE gModule = nullptr;
volatile LONG gInitializing = 0;
__declspec(thread) ThreadTrack* gThread = nullptr;

bool copyBytes(uint64_t address, void* output, size_t size) noexcept {
    __try { std::memcpy(output, reinterpret_cast<const void*>(address), size); return true; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
}
bool checkedRead(void*, uint64_t address, void* output, size_t size) {
    if (!address || !output || !size || address > 0x00007FFFFFFFFFFFull ||
        size - 1 > 0x00007FFFFFFFFFFFull - address) return false;
    const uint64_t end = address + size;
    for (uint64_t cursor = address; cursor < end;) {
        MEMORY_BASIC_INFORMATION region{};
        if (!VirtualQuery(reinterpret_cast<const void*>(cursor), &region, sizeof(region)) ||
            region.State != MEM_COMMIT || (region.Protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
        const DWORD protection = region.Protect & 0xff;
        if (protection != PAGE_READONLY && protection != PAGE_READWRITE && protection != PAGE_WRITECOPY &&
            protection != PAGE_EXECUTE_READ && protection != PAGE_EXECUTE_READWRITE && protection != PAGE_EXECUTE_WRITECOPY)
            return false;
        const uint64_t next = reinterpret_cast<uint64_t>(region.BaseAddress) + region.RegionSize;
        if (next <= cursor) return false;
        cursor = (std::min)(end, next);
    }
    return copyBytes(address, output, size);
}
GmlRunnerReader reader() { return { nullptr, checkedRead }; }
uint64_t nextId() { return static_cast<uint64_t>(InterlockedIncrement64(&gState->nextIdentity)); }
// Caller holds instancesLock. Even sequence commits the pair for frozen host
// reads; a native event may interrupt this transition, which then stays odd.
void publishLifetime(GmlHelperInstanceLifetime& slot, uint64_t address, uint64_t token) {
    InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&slot.sequence));
    slot.objectAddress = address;
    slot.instanceId = token;
    InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&slot.sequence));
}
GmlHelperInstanceLifetime* lifetimeSlot(uint64_t address, bool create) {
    GmlHelperInstanceLifetime* retired = nullptr;
    const size_t first = (address >> 4) & (kGmlMaxInstanceLifetimes - 1);
    for (size_t i = 0; i < kGmlMaxInstanceLifetimes; ++i) {
        auto& slot = gState->lifetimes[(first + i) & (kGmlMaxInstanceLifetimes - 1)];
        if (slot.objectAddress == address) return &slot;
        if (!slot.instanceId && !retired) retired = &slot;
        if (!slot.objectAddress) break;
    }
    if (create && retired) return retired;
    if (create && gState->lifetimesComplete) {
        gState->lifetimesComplete = false;
        for (auto& slot : gState->lifetimes)
            if (slot.instanceId) publishLifetime(slot, slot.objectAddress, 0);
    }
    return nullptr;
}
uint64_t instanceToken(uint64_t address, bool fresh = false) {
    if (!address || !gState->lifetimesComplete) return 0;
    auto* slot = lifetimeSlot(address, true);
    if (!slot) return 0;
    if (slot->objectAddress == address && !slot->instanceId && !fresh) return 0; // observed destructor, not a new allocation
    if (slot->objectAddress != address || fresh)
        publishLifetime(*slot, address, nextId());
    return slot->instanceId;
}
bool hostAlive() {
    if (gState && WaitForSingleObject(gState->host, 0) == WAIT_TIMEOUT) return true;
    InterlockedExchange(&gDsGmlEnabled, 0);
    return false;
}
ThreadTrack* threadTrack() {
    if (gThread) return gThread;
    const LONG tid = static_cast<LONG>(GetCurrentThreadId());
    for (auto& thread : gState->threads) {
        if (thread.tid == tid || InterlockedCompareExchange(&thread.tid, tid, 0) == 0) {
            gThread = &thread;
            return gThread;
        }
    }
    return nullptr;
}
ContextTrack* contextTrack(ThreadTrack& thread, uint64_t context, bool create) {
    ContextTrack* empty = nullptr;
    for (auto& track : thread.contexts) {
        if (track.address == context) return &track;
        if (!track.address && !empty) empty = &track;
    }
    if (!create || !empty) return nullptr;
    *empty = {};
    empty->address = context;
    empty->invocationId = nextId();
    empty->frames[0] = empty->invocationId;
    return empty;
}
const GmlHelperCodeMap* codeMap(uint32_t index) {
    const auto* begin = gState->codes;
    const auto* end = begin + gState->codeCount;
    const auto* it = std::lower_bound(begin, end, index, [](const auto& code, uint32_t key) { return code.codeIndex < key; });
    return it != end && it->codeIndex == index ? it : nullptr;
}
bool locationOf(const GmlRunnerCodeView& code, uint32_t offset, bool continuation, GmlCodeLocation& output) {
    const auto* map = codeMap(code.codeIndex);
    if (!map || map->entryOffset != code.entryOffset || map->byteSize != code.bytecodeLength ||
        offset < map->entryOffset || (continuation ? offset > map->byteSize : offset >= map->byteSize)) return false;
    output = { gState->archive, map->codeIndex, offset, map->parentCodeIndex };
    return true;
}
bool updateTrack(ContextTrack& track, const GmlRunnerContextView& context) {
    if (context.logicalDepth >= kGmlMaxFrames) return false;
    const uint64_t anchor = context.operandBufferEnd - context.anchor;
    const uint32_t depth = context.logicalDepth;
    // Every dispatch passes here while enabled. Popping retires deeper ids;
    // another call at the same buffer offset receives a fresh incarnation.
    if (depth < track.depth) {
        for (uint32_t i = depth + 1; i <= track.depth; ++i) track.frames[i] = track.anchors[i] = 0;
    }
    for (uint32_t i = 1; i <= depth; ++i)
        if (!track.frames[i]) track.frames[i] = nextId();
    if (depth && track.anchors[depth] && track.anchors[depth] != anchor)
        track.frames[depth] = nextId();
    track.anchors[depth] = anchor;
    track.depth = depth;
    return true;
}
BreakpointPage* breakpointPage(uint32_t codeIndex, uint32_t page, bool create) {
    const uint32_t first = ((codeIndex * 0x9e3779b1u) ^ page) & (kBreakpointPages - 1);
    for (uint32_t i = 0; i < kBreakpointPages; ++i) {
        auto& record = gState->breakpointPages[(first + i) & (kBreakpointPages - 1)];
        if (record.occupied && record.codeIndex == codeIndex && record.page == page) return &record;
        if (!record.occupied) {
            if (!create) return nullptr;
            record.codeIndex = codeIndex; record.page = page; record.occupied = 1;
            return &record;
        }
    }
    return nullptr;
}
bool refreshControls() {
    const uint64_t before = static_cast<uint64_t>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(&gState->mailbox->control.commandSequence), 0, 0));
    if (!before || before == static_cast<uint64_t>(InterlockedCompareExchange64(&gState->sequence, 0, 0))) return true;
    if (!TryAcquireSRWLockExclusive(&gState->controlsLock)) return false;
    // The host commits sequence last. A native pause can interrupt this copy;
    // matching before/copy/after sequence observations reject every torn copy.
    auto* scratch = &gState->controlScratch;
    bool valid = copyBytes(reinterpret_cast<uint64_t>(&gState->mailbox->control), scratch, sizeof(*scratch));
    const uint64_t after = static_cast<uint64_t>(InterlockedCompareExchange64(
        reinterpret_cast<volatile LONG64*>(&gState->mailbox->control.commandSequence), 0, 0));
    valid = valid && before == after && scratch->commandSequence == before &&
        scratch->magic == kGmlProtocolMagic && scratch->version == kGmlProtocolVersion && scratch->byteSize == sizeof(*scratch) &&
        scratch->nonce == gState->nonce && scratch->breakpointCount <= kGmlMaxBreakpoints &&
        scratch->command <= GmlControlCommand::Disable && !scratch->reserved && !scratch->selectionReserved &&
        (!scratch->selectedInstanceId || scratch->selectedObjectIndex == kGmlNoCodeIndex) &&
        before > static_cast<uint64_t>(InterlockedCompareExchange64(&gState->sequence, 0, 0));
    if (valid && scratch->expectedStop.stopSequence) {
        const auto& expected = scratch->expectedStop;
        valid = expected.pid == GetCurrentProcessId() && expected.sessionGeneration == gState->session &&
            expected.helperGeneration == gState->generation && expected.stopSequence ==
            static_cast<uint64_t>(InterlockedCompareExchange64(&gState->nextStop, 0, 0));
    }
    for (uint32_t i = 0; valid && i < scratch->breakpointCount; ++i) {
        const auto& breakpoint = scratch->breakpoints[i];
        const auto* map = codeMap(breakpoint.codeIndex);
        valid = GmlLocationHasIdentity(breakpoint) && breakpoint.archiveHash == gState->archive &&
            map && map->parentCodeIndex == breakpoint.parentCodeIndex && !(breakpoint.byteOffset & 3) &&
            breakpoint.byteOffset >= map->entryOffset && breakpoint.byteOffset < map->byteSize;
    }
    if (valid) {
        std::sort(scratch->breakpoints, scratch->breakpoints + scratch->breakpointCount,
            [](const auto& a, const auto& b) { return a.codeIndex < b.codeIndex || (a.codeIndex == b.codeIndex && a.byteOffset < b.byteOffset); });
        gState->controls = *scratch;
        std::memset(gDsGmlBreakpointBloom, 0, sizeof(gDsGmlBreakpointBloom));
        std::memset(gState->breakpointPages, 0, sizeof(gState->breakpointPages));
        for (uint32_t i = 0; i < scratch->breakpointCount; ++i) {
            const auto& breakpoint = scratch->breakpoints[i];
            // At most 4096 distinct pages enter this 8192-row table.
            auto* page = breakpointPage(breakpoint.codeIndex, breakpoint.byteOffset >> 8, true);
            page->wordBits |= uint64_t(1) << ((breakpoint.byteOffset >> 2) & 63);
            const auto bit = DsGmlBreakpointBloomBit(breakpoint.codeIndex, breakpoint.byteOffset);
            gDsGmlBreakpointBloom[bit >> 3] |= static_cast<unsigned char>(1u << (bit & 7));
        }
        InterlockedExchange(&gDsGmlFastAlwaysSlow,
            scratch->command >= GmlControlCommand::Pause && scratch->command <= GmlControlCommand::StepOut ? 1 : 0);
        InterlockedExchange64(&gState->sequence, static_cast<LONG64>(before));
        InterlockedExchange64(&gDsGmlFastAcceptedSequence, static_cast<LONG64>(before));
        if (scratch->command == GmlControlCommand::Disable) InterlockedExchange(&gDsGmlEnabled, 0);
    }
    ReleaseSRWLockExclusive(&gState->controlsLock);
    return valid;
}
bool breakpointAt(const GmlCodeLocation& current) {
    if (current.byteOffset & 3) return false;
    auto matchCode = [&](uint32_t index) {
        const auto* page = breakpointPage(index, current.byteOffset >> 8, false);
        return page && (page->wordBits & (uint64_t(1) << ((current.byteOffset >> 2) & 63))) != 0;
    };
    return matchCode(current.codeIndex) || (current.parentCodeIndex != kGmlNoCodeIndex && matchCode(current.parentCodeIndex));
}
bool appendVariables(GmlHelperStop& stop, uint64_t objectAddress, GmlVariableScope scope,
                     uint64_t frameId, uint64_t instanceId) {
    if (!objectAddress) return false;
    GmlRunnerObjectView object;
    GmlRunnerVariableMapView map;
    if (!ReadGmlRunnerObject(reader(), gState->runnerBase, objectAddress, object) || !object.variableMap ||
        !ReadGmlRunnerVariableMap(reader(), object.variableMap, map)) { stop.variablesComplete = 0; return false; }
    uint32_t found = 0;
    bool complete = true;
    for (uint32_t i = 0; i < map.capacity; ++i) {
        GmlRunnerVariableEntry entry;
        if (!ReadGmlRunnerVariableEntry(reader(), map, i, entry)) { stop.variablesComplete = 0; return false; }
        if (!entry.valueAddress) continue;
        ++found;
        GmlRValue value;
        if (!checkedRead(nullptr, entry.valueAddress, &value, sizeof(value))) { complete = false; stop.variablesComplete = 0; continue; }
        GmlNumericKind kind = GmlNumericKind::None;
        if (value.typeTag == 0) kind = GmlNumericKind::Real;
        else if (value.typeTag == 7) kind = GmlNumericKind::Int32;
        else if (value.typeTag == 10) kind = GmlNumericKind::Int64;
        else if (value.typeTag == 13) kind = GmlNumericKind::Boolean;
        else continue;
        if (stop.numericSlotCount == kGmlMaxNumericSlots) { stop.variablesComplete = 0; return false; }
        auto& slot = stop.numericSlots[stop.numericSlotCount++];
        slot = {};
        slot.address = entry.valueAddress;
        slot.ownerObject = objectAddress;
        slot.frameId = frameId;
        slot.instanceId = instanceId;
        slot.value = value;
        slot.kind = kind;
        slot.writable = 1;
        slot.storage = GmlSlotStorage::Canonical;
        slot.availability = GmlValueAvailability::Available;
        slot.variableIndex = UINT32_MAX;
        slot.runtimeVariableId = entry.runtimeId;
        slot.scope = scope;
        slot.objectIndex = object.objectIndex;
        slot.runtimeInstanceNumber = object.instanceNumber;
        if (ReadGmlRunnerVariableName(reader(), gState->runnerBase, entry.runtimeId, slot.name, sizeof(slot.name)))
            slot.nameLength = static_cast<uint32_t>(std::strlen(slot.name));
        else complete = false;
    }
    if (found != map.count) stop.variablesComplete = 0;
    return complete && found == map.count;
}
bool projectFrames(ThreadTrack& thread, const GmlRunnerContextView& initial,
                   GmlHelperStop& stop, bool collectVariables) {
    GmlRunnerContextView context = initial;
    uint64_t seenContexts[kGmlMaxFrames]{};
    size_t contextCount = 0;
    stop.framesComplete = 1;
    stop.variablesComplete = collectVariables ? 1 : 0;
    while (context.address && stop.frameCount < kGmlMaxFrames) {
        for (size_t i = 0; i < contextCount; ++i)
            if (seenContexts[i] == context.address) return false;
        seenContexts[contextCount++] = context.address;
        auto* track = contextTrack(thread, context.address, true);
        if (!track || !updateTrack(*track, context)) return false;
        if (!track->entryObserved) stop.framesComplete = 0;
        GmlRunnerCodeView code = context.code;
        uint32_t offset = context.byteOffset;
        uint64_t anchor = context.anchor, local = context.localObject, self = context.self, arguments = context.arguments;
        uint32_t argumentCount = context.argumentCount;
        for (uint32_t remaining = context.logicalDepth + 1; remaining > 0; --remaining) {
            if (stop.frameCount == kGmlMaxFrames) { stop.framesComplete = 0; break; }
            const uint32_t logicalDepth = remaining - 1;
            auto& frame = stop.frames[stop.frameCount];
            frame = {};
            if (!locationOf(code, offset, stop.frameCount != 0, frame.location)) { stop.framesComplete = 0; goto finish; }
            frame.frameId = track->frames[logicalDepth];
            frame.frameAddress = context.address;
            frame.logicalAnchor = anchor;
            frame.localObject = local;
            frame.selfObject = self;
            frame.arguments = arguments;
            frame.argumentCount = argumentCount;
            frame.flags = kGmlFrameAddressValid;
            if (stop.frameCount == 0 && context.operandStackTop) {
                frame.operandStackTop = context.operandStackTop;
                frame.flags |= kGmlFrameStackTopValid;
            } else frame.flags |= kGmlFrameLocationIsContinuation;
            if (collectVariables && self) {
                GmlRunnerObjectView selfView;
                if (ReadGmlRunnerObject(reader(), gState->runnerBase, self, selfView)) {
                    frame.runtimeInstanceNumber = selfView.instanceNumber;
                    if (selfView.isInstance) frame.instanceId = instanceToken(self);
                }
            }
            ++stop.frameCount;
            if (collectVariables) {
                const bool localsComplete = appendVariables(stop, local, GmlVariableScope::FrameLocal, frame.frameId, 0);
                frame.localsAvailability = localsComplete ? GmlValueAvailability::Available : GmlValueAvailability::Unavailable;
                if (localsComplete) frame.flags |= kGmlFrameLocalsAvailable;
                if (stop.frameCount == 1 && frame.instanceId && appendVariables(stop, self, GmlVariableScope::SessionInstance, 0, frame.instanceId))
                    frame.selfAvailability = GmlValueAvailability::Available;
            }
            if (!logicalDepth) break;
            GmlRunnerSavedFrameView saved;
            if (!ReadGmlRunnerSavedFrame(reader(), gState->runnerBase, context, anchor, saved)) {
                stop.framesComplete = 0; remaining = 1; break;
            }
            anchor = saved.previousAnchor;
            code = saved.code;
            offset = saved.returnOffset;
            local = saved.localObject;
            self = saved.self;
            arguments = saved.arguments;
            argumentCount = saved.argumentCount;
        }
        if (!context.nativeParent) break;
        uint32_t parentPc = 0;
        if (!checkedRead(nullptr, context.nativeParent + 0x8c, &parentPc, sizeof(parentPc)) ||
            !ReadGmlRunnerContext(reader(), gState->runnerBase, context.nativeParent, parentPc, 0, context)) {
            stop.framesComplete = 0; break;
        }
    }
    if (context.nativeParent && stop.frameCount == kGmlMaxFrames) stop.framesComplete = 0;
finish:
    for (uint32_t i = 0; i < stop.frameCount; ++i) {
        stop.frames[i].depth = stop.frameCount - i - 1;
        stop.frames[i].parentFrameId = i + 1 < stop.frameCount ? stop.frames[i + 1].frameId : 0;
    }
    return stop.frameCount != 0;
}
struct InstanceProjection {
    GmlHelperStop* stop;
    uint32_t selectedObjectIndex;
    uint64_t selectedInstanceId;
    bool selectedComplete = true;
};
bool projectInstance(void* owner, const GmlRunnerInstanceRecord& record) {
    auto& projection = *static_cast<InstanceProjection*>(owner);
    auto& stop = *projection.stop;
    if (stop.instanceCount == kGmlMaxInstances) return false;
    auto& instance = stop.instances[stop.instanceCount];
    instance = {};
    instance.instanceId = instanceToken(record.object.address);
    instance.objectAddress = record.object.address;
    instance.runtimeInstanceNumber = record.object.instanceNumber;
    instance.objectIndex = record.object.objectIndex;
    if (!instance.instanceId) { projection.selectedComplete = false; return false; }
    ++stop.instanceCount;
    const bool selected = (projection.selectedInstanceId && projection.selectedInstanceId == instance.instanceId) ||
        (projection.selectedObjectIndex != kGmlNoCodeIndex && projection.selectedObjectIndex == instance.objectIndex);
    const bool currentSelf = stop.frameCount && stop.frames[0].instanceId == instance.instanceId;
    if (currentSelf) instance.variablesAvailability = stop.frames[0].selfAvailability;
    if (selected && !currentSelf)
        instance.variablesAvailability = appendVariables(stop, record.object.address, GmlVariableScope::SessionInstance,
            0, instance.instanceId) ? GmlValueAvailability::Available : GmlValueAvailability::Unavailable;
    if (selected && instance.variablesAvailability != GmlValueAvailability::Available) projection.selectedComplete = false;
    return true;
}
int privateExceptionFilter(DWORD code) {
    return code == kGmlStopExceptionCode ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}
void notifyDebugger(uint64_t sequence) {
    ULONG_PTR parameters[] = { static_cast<ULONG_PTR>(kGmlProtocolMagic), static_cast<ULONG_PTR>(gState->nonce),
        reinterpret_cast<ULONG_PTR>(gState->mailbox), static_cast<ULONG_PTR>(gState->generation), static_cast<ULONG_PTR>(sequence) };
    __try { RaiseException(kGmlStopExceptionCode, 0, 5, parameters); }
    __except (privateExceptionFilter(GetExceptionCode())) { InterlockedExchange(&gDsGmlEnabled, 0); }
}

bool registerRelay(RelayUnwind& output, uint64_t relay, bool dispatch) {
    if (!relay) return true;
    // A small owned RW metadata allocation is placed within 32-bit RVA distance
    // above the relay. Runtime unwind metadata never changes executable bytes.
    SYSTEM_INFO info{}; GetSystemInfo(&info);
    const uint64_t granularity = info.dwAllocationGranularity;
    uint64_t start = (relay + 0x10000 + granularity - 1) & ~(granularity - 1);
    void* memory = nullptr;
    for (uint32_t i = 0; i < 4096 && !memory; ++i)
        memory = VirtualAlloc(reinterpret_cast<void*>(start + uint64_t(i) * granularity), 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!memory) return false;
    if (dispatch) std::memcpy(memory, kNubbyDispatchRelayUnwind.data(), kNubbyDispatchRelayUnwind.size());
    else { const uint8_t leaf[] = {1, 0, 0, 0}; std::memcpy(memory, leaf, sizeof(leaf)); }
    output.allocation = memory;
    output.function.BeginAddress = 0;
    output.function.EndAddress = 14;
    output.function.UnwindData = static_cast<DWORD>(reinterpret_cast<uint64_t>(memory) - relay);
    output.registered = RtlAddFunctionTable(&output.function, 1, relay) != FALSE;
    return output.registered;
}
void freeState(State* state) {
    if (!state) return;
    for (auto& relay : state->relays) {
        if (relay.registered) RtlDeleteFunctionTable(&relay.function);
        if (relay.allocation) VirtualFree(relay.allocation, 0, MEM_RELEASE);
    }
    state->~State();
    VirtualFree(state, 0, MEM_RELEASE);
}
} // namespace

extern "C" void DsGmlOnEntry(const GateRegisters* registers) noexcept {
    if (!gState || !hostAlive()) return;
    auto* thread = threadTrack();
    if (!thread) return;
    auto& fast = gDsGmlFastThreads[GetCurrentThreadId() & (kDsGmlFastThreads - 1)];
    if (fast.tid == GetCurrentThreadId()) fast.context = 0;
    auto* track = contextTrack(*thread, registers->rcx, true);
    if (!track) return;
    *track = {};
    track->address = registers->rcx;
    track->invocationId = nextId();
    track->frames[0] = track->invocationId;
    track->entryObserved = true;
}

extern "C" void DsGmlOnInstanceConstructor(const GateRegisters* registers) noexcept {
    if (!gState || !gDsGmlEnabled) return;
    AcquireSRWLockExclusive(&gState->instancesLock);
    instanceToken(registers->rcx, true);
    ReleaseSRWLockExclusive(&gState->instancesLock);
}
extern "C" void DsGmlOnInstanceDestructor(const GateRegisters* registers) noexcept {
    if (!gState || !gDsGmlEnabled) return;
    AcquireSRWLockExclusive(&gState->instancesLock);
    if (auto* slot = lifetimeSlot(registers->rcx, false)) publishLifetime(*slot, registers->rcx, 0);
    ReleaseSRWLockExclusive(&gState->instancesLock);
}

extern "C" void DsGmlOnDispatch(const GateRegisters* registers) noexcept {
    if (!gState || !gDsGmlEnabled) return;
    auto* thread = threadTrack();
    if (!thread) return;
    if ((++thread->progress & 1023u) == 0 && !hostAlive()) return;
    if (!refreshControls() || !gDsGmlEnabled) return;
    // The exact profile gates these immutable layouts. A tiny SEH guarded copy
    // tracks call incarnation changes without VirtualQuery or object projection
    // at every opcode. Full checked projection follows only a stop/step match.
    uint64_t raw[20];
    if (!copyBytes(registers->rbx, raw, sizeof(raw))) return;
    GmlRunnerContextView context;
    context.address = registers->rbx;
    context.operandBuffer = raw[2];
    context.operandCapacity = static_cast<uint32_t>(raw[17]);
    context.operandBufferEnd = context.operandBuffer + context.operandCapacity;
    context.anchor = raw[11];
    context.logicalDepth = static_cast<uint32_t>(raw[18] >> 32);
    context.byteOffset = static_cast<uint32_t>(registers->rcx);
    if (!context.operandBuffer || context.operandCapacity > kGmlRunnerMaxOperandCapacity ||
        context.operandBufferEnd < context.operandBuffer || context.anchor < context.operandBuffer ||
        context.anchor > context.operandBufferEnd) return;
    auto* track = contextTrack(*thread, context.address, true);
    if (!track || !updateTrack(*track, context)) return;
    if (track->codeAddress != raw[7]) {
        if (!ReadGmlRunnerCode(reader(), gState->runnerBase, raw[7], track->code)) return;
        track->codeAddress = raw[7];
    }
    context.code = track->code;
    GmlCodeLocation location;
    if (!locationOf(context.code, context.byteOffset, false, location)) return;
    auto& fast = gDsGmlFastThreads[GetCurrentThreadId() & (kDsGmlFastThreads - 1)];
    const LONG tid = static_cast<LONG>(GetCurrentThreadId());
    if (fast.tid == static_cast<uint32_t>(tid) ||
        InterlockedCompareExchange(reinterpret_cast<volatile LONG*>(&fast.tid), tid, 0) == 0) {
        fast.depth = context.logicalDepth;
        fast.code = track->codeAddress;
        fast.anchor = context.anchor;
        fast.activeCodeIndex = location.codeIndex;
        fast.rootCodeIndex = location.parentCodeIndex == kGmlNoCodeIndex ? location.codeIndex : location.parentCodeIndex;
        fast.context = context.address; // published last to this thread's assembly path
    }
    if (!TryAcquireSRWLockShared(&gState->controlsLock)) return;
    const auto& controls = gState->controls;
    GmlStopReason reason = GmlStopReason::None;
    const uint64_t commandSequence = controls.commandSequence;
    const auto command = controls.command;
    const uint32_t selectedObjectIndex = controls.selectedObjectIndex;
    const uint64_t selectedInstanceId = controls.selectedInstanceId;
    const bool ownThread = !controls.expectedStop.tid || controls.expectedStop.tid == GetCurrentThreadId();
    if (breakpointAt(location)) reason = GmlStopReason::Breakpoint;
    if (command == GmlControlCommand::Pause && commandSequence != thread->stepCommand) reason = GmlStopReason::Pause;
    const bool step = ownThread && command >= GmlControlCommand::StepInto && command <= GmlControlCommand::StepOut;
    GmlPauseIdentity stepOwner = controls.expectedStop;
    ReleaseSRWLockShared(&gState->controlsLock);

    // Frame projection has a fixed size and no allocations. Numeric/object
    // enumeration occurs only after a real stop matches, never per instruction.
    auto& projected = thread->projected;
    if (step || reason != GmlStopReason::None) {
        if (!ReadGmlRunnerContext(reader(), gState->runnerBase, registers->rbx,
                                 static_cast<uint32_t>(registers->rcx), registers->rdi, context)) return;
        projected.frameCount = projected.numericSlotCount = 0;
        if (!projectFrames(*thread, context, projected, false)) return;
    }
    if (step) {
        std::array<uint64_t, kGmlMaxFrames> ancestors{};
        for (uint32_t i = 1; i < projected.frameCount; ++i) ancestors[i - 1] = projected.frames[i].frameId;
        GmlExecutionPoint point{ stepOwner, location, projected.frames[0].frameId,
            projected.frames[0].parentFrameId, thread->progress, projected.frames[0].depth,
            projected.framesComplete != 0, { ancestors.data(), projected.frameCount - 1 } };
        if (thread->stepCommand != commandSequence) {
            // A step command is captured while handling the held notification,
            // below. If another thread attempted to install it, never guess.
            reason = GmlStopReason::Error;
        } else {
            const auto decision = EvaluateGmlStep(thread->step, point);
            if (decision == GmlStepDecision::Stop) reason = GmlStopReason::Step;
            else if (decision == GmlStepDecision::Invalid || decision == GmlStepDecision::Stale) reason = GmlStopReason::Error;
        }
    }
    if (reason == GmlStopReason::None || !hostAlive() ||
        InterlockedCompareExchange(&gState->stopOwner, static_cast<LONG>(GetCurrentThreadId()), 0) != 0) return;
    // Assigning a default aggregate here materializes a >300 KiB automatic
    // temporary on MSVC. Clear the owned scratch directly instead.
    std::memset(&projected, 0, sizeof(projected));
    projected.magic = kGmlProtocolMagic;
    projected.version = kGmlProtocolVersion;
    projected.byteSize = sizeof(projected);
    projected.selectedObjectIndex = kGmlNoCodeIndex;
    AcquireSRWLockExclusive(&gState->instancesLock);
    if (!projectFrames(*thread, context, projected, true)) {
        ReleaseSRWLockExclusive(&gState->instancesLock);
        InterlockedExchange(&gState->stopOwner, 0); return;
    }
    uint64_t globalObject = 0;
    if (checkedRead(nullptr, gState->runnerBase + NubbyGameMakerRunner().globalObjectRva, &globalObject, sizeof(globalObject)))
        projected.globalsComplete = appendVariables(projected, globalObject, GmlVariableScope::Global, 0, 0) ? 1u : 0u;
    projected.variablesComplete = 0; // this is active frames/self/global, not every world instance
    InstanceProjection instanceProjection{ &projected, selectedObjectIndex, selectedInstanceId };
    GmlRunnerInstanceEnumeration enumeration;
    projected.instancesComplete = EnumerateGmlRunnerInstances(reader(), gState->runnerBase, kGmlMaxInstances,
        projectInstance, &instanceProjection, enumeration) && enumeration.complete && gState->lifetimesComplete ? 1u : 0u;
    projected.selectedObjectIndex = selectedObjectIndex;
    projected.selectedInstanceId = selectedInstanceId;
    projected.instanceVariablesComplete = projected.instancesComplete && instanceProjection.selectedComplete &&
        (selectedInstanceId || selectedObjectIndex != kGmlNoCodeIndex) ? 1u : 0u;
    ReleaseSRWLockExclusive(&gState->instancesLock);
    const uint64_t sequence = static_cast<uint64_t>(InterlockedIncrement64(&gState->nextStop));
    projected.nonce = gState->nonce;
    projected.identity = { GetCurrentProcessId(), GetCurrentThreadId(), gState->session, gState->generation, sequence };
    projected.location = location;
    projected.reason = reason;
    projected.adapterId = kGmlNubbyAdapterId;
    projected.dispatchSiteId = 1;
    gState->mailbox->stop = projected;
    MemoryBarrier();
    notifyDebugger(sequence); // no helper mutex is held; host owns the process-wide pause

    // Executed only AFTER ContinueDebugEvent. Commands and writes never need a
    // target-side RPC while Windows has stopped all target threads.
    if (gDsGmlEnabled && refreshControls() && TryAcquireSRWLockShared(&gState->controlsLock)) {
        const auto& next = gState->controls;
        thread->stepCommand = next.commandSequence;
        if (next.command >= GmlControlCommand::StepInto && next.command <= GmlControlCommand::StepOut &&
            GmlPauseIdentityMatches(next.expectedStop, projected.identity)) {
            std::array<uint64_t, kGmlMaxFrames> ancestors{};
            for (uint32_t i = 1; i < projected.frameCount; ++i) ancestors[i - 1] = projected.frames[i].frameId;
            const GmlExecutionPoint anchor{ projected.identity, location, projected.frames[0].frameId,
                projected.frames[0].parentFrameId, thread->progress, projected.frames[0].depth,
                projected.framesComplete != 0, { ancestors.data(), projected.frameCount - 1 } };
            if (!MakeGmlStepPlan(next.command, anchor, thread->step)) thread->step = {};
        } else thread->step = {};
        ReleaseSRWLockShared(&gState->controlsLock);
    }
    InterlockedExchange(&gState->stopOwner, 0);
}

extern "C" DWORD WINAPI DsGmlInitialize(void* parameter) noexcept {
    auto* config = static_cast<GmlHelperInitConfig*>(parameter);
    GmlHelperInitPrefix header;
    constexpr size_t prefix = offsetof(GmlHelperInitConfig, codes);
    if (!checkedRead(nullptr, reinterpret_cast<uint64_t>(parameter), &header, prefix)) return ERROR_INVALID_PARAMETER;
    auto reject = [&](GmlHelperInitStatus status, DWORD error) { config->status = status; config->errorCode = error; return error; };
    if (header.magic != kGmlProtocolMagic || header.version != kGmlProtocolVersion || header.byteSize != sizeof(GmlHelperInitConfig) ||
        !header.nonce || header.pid != GetCurrentProcessId() || !header.sessionGeneration || !header.helperGeneration ||
        !header.archiveHash || !header.mailboxAddress || !header.hostProcessHandle || header.reserved ||
        !header.codeCount || header.codeCount > kGmlMaxHelperCodes) return reject(GmlHelperInitStatus::InvalidConfig, ERROR_INVALID_PARAMETER);
    if (InterlockedCompareExchange(&gInitializing, 1, 0) != 0) return reject(GmlHelperInitStatus::AlreadyInitialized, ERROR_ALREADY_EXISTS);
    DsGmlXStateLayout xstate;
    if(!DsGmlReadXStateLayout(xstate)) {
        InterlockedExchange(&gInitializing,0);
        return reject(GmlHelperInitStatus::UnsupportedRunner,ERROR_NOT_SUPPORTED);
    }
    gDsGmlXsaveMask=xstate.mask;gDsGmlXsaveBytes=xstate.bytes;
    const auto& profile = NubbyGameMakerRunner();
    if (header.adapterId != profile.adapterId || header.runnerSize != profile.imageSize ||
        header.dispatchContinuation != header.runnerBase + profile.instructionDispatch.rva + profile.instructionDispatch.byteCount ||
        header.entryContinuation != header.runnerBase + profile.interpreterEntry.rva + profile.interpreterEntry.byteCount ||
        header.instanceConstructorContinuation != header.runnerBase + profile.instanceConstructor.rva + profile.instanceConstructor.byteCount ||
        header.instanceDestructorContinuation != header.runnerBase + profile.instanceDestructor.rva + profile.instanceDestructor.byteCount ||
        !ValidateGmlRunnerImage(reader(), header.runnerBase, profile)) {
        InterlockedExchange(&gInitializing, 0);
        return reject(GmlHelperInitStatus::UnsupportedRunner, ERROR_NOT_SUPPORTED);
    }
    auto* stateMemory = VirtualAlloc(nullptr, sizeof(State), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!stateMemory) { InterlockedExchange(&gInitializing, 0); return reject(GmlHelperInitStatus::ResourceFailure, ERROR_NOT_ENOUGH_MEMORY); }
    auto* state = new (stateMemory) State{};
    state->nonce = header.nonce; state->session = header.sessionGeneration;
    state->generation = header.helperGeneration; state->archive = header.archiveHash;
    state->runnerBase = header.runnerBase; state->host = reinterpret_cast<HANDLE>(header.hostProcessHandle);
    state->mailbox = reinterpret_cast<GmlHelperMailbox*>(header.mailboxAddress);
    state->codeCount = header.codeCount;
    bool valid = checkedRead(nullptr, reinterpret_cast<uint64_t>(config->codes), state->codes,
        size_t(header.codeCount) * sizeof(GmlHelperCodeMap));
    auto& mailboxHeader = state->controlScratch;
    valid = valid && checkedRead(nullptr, header.mailboxAddress, &mailboxHeader, offsetof(GmlHelperControl, breakpoints)) &&
        mailboxHeader.magic == kGmlProtocolMagic && mailboxHeader.version == kGmlProtocolVersion &&
        mailboxHeader.byteSize == sizeof(GmlHelperControl) && mailboxHeader.nonce == header.nonce &&
        WaitForSingleObject(state->host, 0) == WAIT_TIMEOUT;
    for (uint32_t i = 0; valid && i < state->codeCount; ++i) {
        const auto& code = state->codes[i];
        valid = code.codeIndex != UINT32_MAX && code.parentCodeIndex != code.codeIndex &&
            code.byteSize && code.byteSize <= kGmlRunnerMaxCodeBytes && code.entryOffset < code.byteSize &&
            (!i || state->codes[i - 1].codeIndex < code.codeIndex);
    }
    if (!valid || !registerRelay(state->relays[0], header.dispatchRelayAddress, true) ||
        !registerRelay(state->relays[1], header.entryRelayAddress, false) ||
        !registerRelay(state->relays[2], header.instanceConstructorRelayAddress, false) ||
        !registerRelay(state->relays[3], header.instanceDestructorRelayAddress, false)) {
        freeState(state); InterlockedExchange(&gInitializing, 0);
        return reject(GmlHelperInitStatus::InvalidConfig, ERROR_INVALID_DATA);
    }
    gDsGmlDispatchContinuation = header.dispatchContinuation;
    gDsGmlEntryContinuation = header.entryContinuation;
    gDsGmlInstanceConstructorContinuation = header.instanceConstructorContinuation;
    gDsGmlInstanceDestructorContinuation = header.instanceDestructorContinuation;
    gState = state;
    gDsGmlFastControlSequenceAddress = reinterpret_cast<uint64_t>(&state->mailbox->control.commandSequence);
    InterlockedExchange(&gDsGmlEnabled, 1);
    config->instanceLifetimesAddress = reinterpret_cast<uint64_t>(state->lifetimes);
    config->instanceLifetimesCapacity = kGmlMaxInstanceLifetimes;
    config->errorCode = ERROR_SUCCESS;
    config->status = GmlHelperInitStatus::Ready;
    return ERROR_SUCCESS;
}

extern "C" DWORD WINAPI DsGmlShutdown(void*) noexcept {
    State* state = gState;
    if (!state) return ERROR_INVALID_STATE;
    if (InterlockedCompareExchange64(&gDsGmlActiveGates, 0, 0) != 0 ||
        state->mailbox->control.nonce != state->nonce || state->mailbox->control.command != GmlControlCommand::Disable)
        return ERROR_BUSY;
    // Host has restored both entry sites and checked stopped RIPs before calling
    // this export. An idle callback counter alone does not prove no gate-exit RIP.
    InterlockedExchange(&gDsGmlEnabled, 0);
    CloseHandle(state->host);
    gState = nullptr;
    freeState(state);
    FreeLibraryAndExitThread(gModule, 0);
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) gModule = module;
    return TRUE;
}
