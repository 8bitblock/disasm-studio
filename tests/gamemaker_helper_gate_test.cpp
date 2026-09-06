#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <float.h>
#include <intrin.h>
#include <initializer_list>
#include "../src/GameMakerHelper/GameMakerFastGate.h"
#include "../src/GameMakerHelper/GameMakerXState.h"

// Link this fixture with the production GameMakerGates.asm, not the helper DLL.
// A synthetic interpreter body supplies real unwind metadata and both original
// displaced-instruction continuations, without attaching to any process.
extern "C" {
volatile long gDsGmlEnabled = 1;
volatile long long gDsGmlActiveGates = 0;
unsigned long long gDsGmlXsaveMask = 0;
unsigned long gDsGmlXsaveBytes = 512;
unsigned long long gDsGmlDispatchContinuation = 0, gDsGmlEntryContinuation = 0;
unsigned long long gDsGmlInstanceConstructorContinuation = 0, gDsGmlInstanceDestructorContinuation = 0;
unsigned long long gDsGmlFastControlSequenceAddress = 0;
volatile long long gDsGmlFastAcceptedSequence = 1;
volatile long gDsGmlFastAlwaysSlow = 1;
alignas(64) DsGmlFastThread gDsGmlFastThreads[kDsGmlFastThreads]{};
alignas(64) unsigned char gDsGmlBreakpointBloom[kDsGmlBreakpointBloomBytes]{};
alignas(16) unsigned char gGateBefore[640]{}, gGateAfter[640]{}, gGateOriginalFx[512]{};
alignas(64) unsigned char gGateXBefore[16384]{},gGateXAfter[16384]{},gGateXOriginal[16384]{};
alignas(16) unsigned char gGateDummyContext[160]{};
unsigned long long gGateEntryWrite = 0;
unsigned long long gGateLifetimeWrites[2]{};
unsigned long gGateMode = 0;
void TestGateFixture(unsigned long mode);
void TestDispatchContinuation();
void TestEntryContinuation();
void TestConstructorContinuation();
void TestDestructorContinuation();
}
static int failures = 0, callbacks = 0;
static bool callbackUnwind = false;

extern "C" void TestGateCallback(const void* saved) {
    ++callbacks;
    if (std::memcmp(saved, gGateBefore, 128)) ++failures;
    unsigned __int64 flags = __readeflags();
    if (flags & 0x400) ++failures; // C++/CRT must receive the ABI-required clear DF.
    void* trace[32]{};
    const USHORT count = RtlCaptureStackBackTrace(0, 32, trace, nullptr);
    const auto start = reinterpret_cast<uintptr_t>(&TestGateFixture);
    const auto end = reinterpret_cast<uintptr_t>(&TestDestructorContinuation) + 1024;
    for (USHORT i = 0; i < count; ++i) {
        const auto address = reinterpret_cast<uintptr_t>(trace[i]);
        callbackUnwind = callbackUnwind || (address >= start && address < end);
    }
    unsigned int ignored = 0;
    _controlfp_s(&ignored, _RC_DOWN, _MCW_RC); // gate must restore the original FP state.
}

int main() {
    DsGmlXStateLayout xstate;
    if(!DsGmlReadXStateLayout(xstate))return 2;
    gDsGmlXsaveMask=xstate.mask;gDsGmlXsaveBytes=xstate.bytes;
    std::printf("Gate XSTATE mask=%llx bytes=%lu\n",gDsGmlXsaveMask,gDsGmlXsaveBytes);
    gDsGmlDispatchContinuation = reinterpret_cast<uintptr_t>(&TestDispatchContinuation);
    gDsGmlEntryContinuation = reinterpret_cast<uintptr_t>(&TestEntryContinuation);
    gDsGmlInstanceConstructorContinuation = reinterpret_cast<uintptr_t>(&TestConstructorContinuation);
    gDsGmlInstanceDestructorContinuation = reinterpret_cast<uintptr_t>(&TestDestructorContinuation);
    for (unsigned long mode = 0; mode < 4; ++mode) {
        callbackUnwind = false;
        TestGateFixture(mode);
        if (std::memcmp(gGateBefore, gGateAfter, 128)) {
            std::printf("GPR/flags mismatch in mode %lu\n", mode); ++failures;
        }
        // FXSAVE reserved bytes are unspecified; compare architectural MXCSR and XMM0-15.
        if (std::memcmp(gGateBefore + 128 + 24, gGateAfter + 128 + 24, 4) ||
            std::memcmp(gGateBefore + 128 + 160, gGateAfter + 128 + 160, 256)) {
            std::printf("FP/SIMD mismatch in mode %lu\n", mode); ++failures;
        }
        if (!callbackUnwind) { std::printf("Unwind did not reach fixture\n"); ++failures; }
        for(unsigned component=2;component<32;++component)if(gDsGmlXsaveMask&(uint64_t(1)<<component)) {
            int cpuid[4]{};__cpuidex(cpuid,13,component);
            const auto bytes=uint32_t(cpuid[0]),offset=uint32_t(cpuid[1]);
            if(offset>sizeof(gGateXBefore) || bytes>sizeof(gGateXBefore)-offset ||
               std::memcmp(gGateXBefore+offset,gGateXAfter+offset,bytes)) {
                std::printf("Extended SIMD component %u mismatch in mode %lu\n",component,mode);++failures;
            }
        }
        if (gDsGmlActiveGates) ++failures;
    }
    uint32_t dispatched = 0;
    std::memcpy(&dispatched, gGateDummyContext + 0x9c, sizeof(dispatched));
    if (dispatched != 0x2468 || gGateEntryWrite != 0x3333333333333333ull || callbacks != 4 ||
        gGateLifetimeWrites[0] != reinterpret_cast<uintptr_t>(gGateDummyContext) ||
        gGateLifetimeWrites[1] != reinterpret_cast<uintptr_t>(gGateDummyContext)) ++failures;
    // The real bitmap path must preserve the identical machine state while
    // avoiding all callbacks; parent-root and exact-child bits both admit slow.
    gDsGmlFastControlSequenceAddress = reinterpret_cast<uintptr_t>(&gDsGmlFastAcceptedSequence);
    gDsGmlFastAlwaysSlow = 0;
    auto& fast = gDsGmlFastThreads[GetCurrentThreadId() & (kDsGmlFastThreads - 1)];
    fast.tid = GetCurrentThreadId();
    fast.context = reinterpret_cast<uintptr_t>(gGateDummyContext);
    fast.rootCodeIndex = 3;
    fast.activeCodeIndex = 345;
    TestGateFixture(0);
    if (callbacks != 4 || std::memcmp(gGateBefore, gGateAfter, 128) ||
        std::memcmp(gGateBefore + 288, gGateAfter + 288, 256)) ++failures;
    for (uint32_t code : { 3u, 345u }) {
        const uint32_t bit = DsGmlBreakpointBloomBit(code, 0x2468);
        gDsGmlBreakpointBloom[bit >> 3] |= static_cast<unsigned char>(1u << (bit & 7));
        const int previous = callbacks;
        TestGateFixture(0);
        if (callbacks != previous + 1) ++failures;
        std::memset(gDsGmlBreakpointBloom, 0, sizeof(gDsGmlBreakpointBloom));
    }
    fast.depth = 1;
    const int previous = callbacks;
    TestGateFixture(0);
    if (callbacks != previous + 1) ++failures;
    std::printf("gamemaker_helper_gate_test: %s\n", failures ? "FAILED" : "all checks passed");
    return failures ? 1 : 0;
}
