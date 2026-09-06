#include "Core/AntiDebug.h"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <vector>

using namespace ds;

int main() {
    AntiDebugPolicy off;
    assert(!off.enabled());
    assert(!off.requiresNtdllHooks());
    assert(!DecideAntiDebugCall(off, AntiDebugCall::NtQueryInformationProcess, 7, 8).intercept);

    AntiDebugPolicy p;
    p.normalizePeb = true;
    p.normalizeProcessHeap = true;
    p.hideProcessDebugQueries = true;
    p.hideKernelDebuggerQuery = true;
    p.acceptThreadHideRequests = true;
    p.neutralizeInvalidHandleClose = true;
    p.maskDebugRegisters = true;
    p.syntheticClock = true;
    p.rdtsc = RdtscInterception::MainExecutable;
    assert(p.enabled());
    assert(p.requiresNtdllHooks());

    auto port = DecideAntiDebugCall(p, AntiDebugCall::NtQueryInformationProcess, 7, 8);
    assert(port.intercept && port.status == 0 && port.output == AntiDebugOutput::ZeroPointer);
    assert(!DecideAntiDebugCall(p, AntiDebugCall::NtQueryInformationProcess, 7, 8,
                               false, 8, false).intercept); // foreign/invalid process handle
    assert(!DecideAntiDebugCall(p, AntiDebugCall::NtQueryInformationProcess, 7, 8,
                               false, 8, true, false).intercept); // null output
    assert(!DecideAntiDebugCall(p, AntiDebugCall::NtQueryInformationProcess, 7, 4,
                               false, 8).intercept);
    assert(DecideAntiDebugCall(p, AntiDebugCall::NtQueryInformationProcess, 7, 4,
                              false, 4).intercept);
    auto object = DecideAntiDebugCall(p, AntiDebugCall::NtQueryInformationProcess, 30, 8);
    assert(object.intercept && object.status == 0xC0000353u);
    auto flags = DecideAntiDebugCall(p, AntiDebugCall::NtQueryInformationProcess, 31, 4);
    assert(flags.intercept && flags.output == AntiDebugOutput::OneU32);
    assert(!DecideAntiDebugCall(p, AntiDebugCall::NtQueryInformationProcess, 31, 3).intercept);
    auto kernel = DecideAntiDebugCall(p, AntiDebugCall::NtQuerySystemInformation, 35, 2);
    assert(kernel.intercept && kernel.output == AntiDebugOutput::KernelDebuggerInfo);
    assert(DecideAntiDebugCall(p, AntiDebugCall::NtSetInformationThread, 17, 0,
                              false, 8, true, false).intercept);
    assert(!DecideAntiDebugCall(p, AntiDebugCall::NtSetInformationThread, 17, 0,
                               false, 8, true, true).intercept);
    assert(!DecideAntiDebugCall(p, AntiDebugCall::NtSetInformationThread, 17, 1,
                               false, 8, true, false).intercept);
    assert(DecideAntiDebugCall(p, AntiDebugCall::NtQueryInformationThread, 17, 1).intercept);
    assert(!DecideAntiDebugCall(p, AntiDebugCall::NtQueryInformationThread, 17, 2).intercept);
    assert(!DecideAntiDebugCall(p, AntiDebugCall::NtQueryInformationThread, 17, 1,
                               false, 8, false).intercept);
    assert(DecideAntiDebugCall(p, AntiDebugCall::NtGetContextThread).intercept);
    assert(DecideAntiDebugCall(p, AntiDebugCall::NtSetContextThread).intercept);
    assert(DecideAntiDebugCall(p, AntiDebugCall::NtQueryPerformanceCounter).intercept);
    assert(DecideAntiDebugCall(p, AntiDebugCall::NtQuerySystemTime).intercept);
    assert(AntiDebugX86StackArgumentBytes(AntiDebugCall::NtQueryInformationProcess) == 20);
    assert(AntiDebugX86StackArgumentBytes(AntiDebugCall::NtQueryInformationThread) == 20);
    assert(AntiDebugX86StackArgumentBytes(AntiDebugCall::NtQuerySystemInformation) == 16);
    assert(AntiDebugX86StackArgumentBytes(AntiDebugCall::NtSetInformationThread) == 16);
    assert(AntiDebugX86StackArgumentBytes(AntiDebugCall::NtGetContextThread) == 8);
    assert(AntiDebugX86StackArgumentBytes(AntiDebugCall::NtQueryPerformanceCounter) == 8);
    assert(AntiDebugX86StackArgumentBytes(AntiDebugCall::NtClose) == 4);
    assert(AntiDebugX86StackArgumentBytes(AntiDebugCall::NtQuerySystemTime) == 4);
    assert(!DecideAntiDebugCall(p, AntiDebugCall::NtClose, 0, 0, false).intercept);
    assert(DecideAntiDebugCall(p, AntiDebugCall::NtClose, 0, 0, true).status == 0xC0000008u);

    assert(NormalizeNtGlobalFlag(0x123470u) == 0x123400u);
    assert((NormalizeHeapFlags(0x40000060u) & 0x40000060u) == 0);
    assert((NormalizeHeapFlags(0) & 2u) != 0);
    assert(NormalizeHeapForceFlags(0xA0000162u) == 0xA0000102u);

    PristinePatchSet book;
    assert(book.remember(0x1000, {1, 2}, {0, 0}, "PEB"));
    assert(!book.remember(0x1000, {0, 0}, {0, 0}, "second observation"));
    const auto* patch = book.find(0x1000);
    assert(patch && patch->original == std::vector<uint8_t>({1, 2}));
    assert(PristinePatchSet::shouldRestore(*patch, {0, 0}));
    assert(!PristinePatchSet::shouldRestore(*patch, {9, 9}));
    assert(book.forget(0x1000) && !book.find(0x1000) && !book.forget(0x1000));

    DebugRegisterState dr;
    dr.address = {1, 2, 3, 4}; dr.dr6 = 0xF; dr.dr7 = 0x555;
    auto hidden = MaskDebugRegisters(dr);
    const std::array<uint64_t, 4> noDebugAddresses{};
    assert(hidden.address == noDebugAddresses);
    assert(hidden.dr6 == 0 && hidden.dr7 == 0);
    assert(CanMediateSetContext(true, 0x00100010u));
    assert(!CanMediateSetContext(true, 0x00100013u)); // control/integer self update
    assert(CanMediateSetContext(false, 0x00100013u)); // another stopped thread is safe
    assert(AntiDebugTrapRangeValid(0x1000, 0x1000, 0x1000, 1));
    assert(AntiDebugTrapRangeValid(0x1000, 0x1000, 0x1FFE, 2));
    assert(!AntiDebugTrapRangeValid(0x1000, 0x1000, 0x1FFF, 2));
    assert(!AntiDebugTrapRangeValid(UINT64_MAX - 3, 8, UINT64_MAX - 2, 1));
    assert(!AntiDebugTrapRangeValid(0x1000, 0, 0x1000, 1));

    AntiDebugRearmState rearms;
    assert(rearms.begin(11, 0x1000, 0x1000));
    assert(rearms.begin(22, 0x1000, 0x1000)); // two already-queued hits at one hook
    assert(rearms.begin(33, 0x2000, 0x2000));
    assert(!rearms.begin(11, 0x3000, 0x3000)); // never overwrite a thread's first pending hook
    assert(rearms.size() == 3 && rearms.hasAddress(0x1000));
    auto firstRearm = rearms.take(11);
    assert(firstRearm && firstRearm->address == 0x1000 &&
           firstRearm->ownerImageBase == 0x1000);
    assert(!rearms.find(11) && rearms.hasAddress(0x1000)); // lease 22 still owns the byte
    assert(rearms.take(22) && !rearms.hasAddress(0x1000));
    assert(rearms.begin(44, 0x2100, 0x2000));
    assert(rearms.takeOwner(0x2000) && rearms.takeOwner(0x2000));
    assert(!rearms.takeOwner(0x2000) && rearms.size() == 0);
    assert(rearms.begin(44, 0x4000, 0x4000));
    assert(rearms.takeAny() && !rearms.takeAny() && rearms.size() == 0);

    SyntheticClockConfig cfg;
    cfg.qpcStart = 100; cfg.qpcFrequency = 1'000'000; cfg.qpcQuantum = 10;
    cfg.systemTimeStart100ns = 1'000; cfg.tscStart = 0x0000000200000003ULL;
    cfg.tscQuantum = 5; cfg.rdtscpAux = 7;
    SyntheticClock clock(cfg);
    assert(clock.nextQpc() == 100);
    assert(clock.nextQpc() == 110);
    const uint64_t st0 = clock.nextSystemTime100ns();
    const uint64_t st1 = clock.nextSystemTime100ns();
    assert(st0 == 1'200 && st1 == 1'300);
    auto t0 = clock.nextTsc(false);
    auto t1 = clock.nextTsc(true);
    assert(t0.eax == 23 && t0.edx == 2 && t0.ecx == 0);
    assert(t1.eax == 28 && t1.edx == 2 && t1.ecx == 7);
    clock.reset(cfg);
    assert(clock.nextQpc() == cfg.qpcStart); // caller-provided production/test seed is honored
    clock.advanceRunningQpcTicks(1'000'000); // e.g. one resumed second at this frequency
    assert(clock.nextQpc() == cfg.qpcStart + cfg.qpcQuantum + 1'000'000);
    clock.reset(cfg);
    clock.advanceRunningQpcTicks(1'000'000);
    assert(clock.nextSystemTime100ns() == cfg.systemTimeStart100ns + 10'000'000);
    clock.reset(cfg);
    clock.advanceRunningQpcTicks(1'000'000);
    auto resumedTsc = clock.nextTsc(false);
    const uint64_t resumedTsc64 = (uint64_t{resumedTsc.edx} << 32) | resumedTsc.eax;
    assert(resumedTsc64 == cfg.tscStart + 500'000);

    auto report = BuildAntiDebugCapabilityReport(p);
    assert(!report.userModeCoverage.empty());
    assert(report.beyondUserMode.size() >= 4);

    AntiDebugSessionStats stats;
    assert(AddAntiDebugWarning(stats, "one", 2));
    assert(!AddAntiDebugWarning(stats, "one", 2));
    assert(stats.warningsDeduplicated == 1 && stats.warningsDropped == 0);
    assert(AddAntiDebugWarning(stats, "two", 2));
    assert(!AddAntiDebugWarning(stats, "three", 2));
    assert(stats.warnings.size() == 2 && stats.warningsDropped == 1);
    assert(!AddAntiDebugWarning(stats, std::string(400, 'x'), 2));
    assert(stats.warningsDropped == 2);

    std::cout << "anti_debug_test: ok\n";
    return 0;
}
