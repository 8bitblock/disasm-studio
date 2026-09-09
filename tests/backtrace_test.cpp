#include "Core/Backtrace.h"
#include <cstdio>
#include <limits>

static int failures = 0;
#define CHECK(value) do { if (!(value)) { std::printf("FAIL %d: %s\n", __LINE__, #value); ++failures; } } while (0)

class SuffixDecoder final : public ds::IDisassembler {
public:
    bool lengths[16]{};
    bool typedNonCall = false;
    size_t calls = 0;
    ds::Engine engine() const override { return ds::Engine::Zydis; }
    const char* engineName() const override { return "bounded suffix fixture"; }
    std::vector<ds::Instruction> disassemble(const uint8_t*, size_t, uint64_t, size_t) override { return {}; }
    bool decodeOne(const uint8_t*, size_t size, uint64_t address, ds::Instruction& out) override {
        ++calls;
        if (size > 15 || !lengths[size]) return false;
        out.address = address; out.length = static_cast<uint32_t>(size);
        out.isCall = true;
        out.flow.kind = typedNonCall ? ds::FlowKind::ConditionalBranch : ds::FlowKind::IndirectCall;
        return true;
    }
};

int main() {
    using namespace ds;
    DbgSnapshot snap;
    snap.state = DbgState::Paused;
    snap.pid = 123; snap.sessionGeneration = 4;
    snap.activeTid = 456; snap.tid = 999; // displayed thread must win over event thread
    snap.regs.rip = 0x1040; snap.regs.rsp = 0x8000; snap.regs.rbp = 0x8100;
    snap.stackRevision = 11; snap.stackTid = snap.activeTid;
    snap.stackRip = snap.regs.rip; snap.stackRsp = snap.regs.rsp; snap.stackRbp = snap.regs.rbp;
    snap.frames = {{0x1040, 0x8100, 0x8000, "leaf"}, {0x1205, 0x8180, 0x8120, "caller"}};
    DbgModule module; module.name = "fixture.exe"; module.base = 0x1000;
    module.size = 0x1000; module.loadGeneration = 7;
    snap.modules.push_back(module);
    const auto stop = CaptureBacktraceStop(snap);
    CHECK(stop.tid == 456);
    CHECK(BacktraceStopMatches(stop, snap));
    CHECK(BacktraceUnwindCurrent(snap));

    auto changed = [&](const auto& change) {
        auto other = snap; change(other); CHECK(!BacktraceStopMatches(stop, other));
    };
    changed([](auto& s) { ++s.pid; });
    changed([](auto& s) { ++s.sessionGeneration; });
    changed([](auto& s) { ++s.activeTid; });
    changed([](auto& s) { ++s.regs.rip; });
    changed([](auto& s) { ++s.regs.rsp; });
    changed([](auto& s) { ++s.regs.rbp; });
    changed([](auto& s) { ++s.stackRevision; }); // same-PC/SP later stop is distinct
    changed([](auto& s) { s.is32 = true; });
    changed([](auto& s) { s.state = DbgState::Running; });
    changed([](auto& s) { s.cleanupOnly = true; });
    changed([](auto& s) { ++s.modules.front().base; });
    changed([](auto& s) { ++s.modules.front().size; });
    changed([](auto& s) { ++s.modules.front().loadGeneration; });
    changed([](auto& s) { s.modules.clear(); });
    CHECK(!BacktraceStopMatches({}, snap));
    auto other = snap; other.tid = 22;
    CHECK(BacktraceStopMatches(stop, other)); // event thread has no display authority
    other = snap; other.stackTid = snap.tid;
    CHECK(!BacktraceUnwindCurrent(other));
    other = snap; ++other.stackRip;
    CHECK(!BacktraceUnwindCurrent(other));
    other = snap; ++other.stackRsp;
    CHECK(!BacktraceUnwindCurrent(other));
    other = snap; ++other.stackRbp;
    CHECK(!BacktraceUnwindCurrent(other));
    other = snap; other.frames.erase(other.frames.begin());
    CHECK(!BacktraceUnwindCurrent(other)); // first result may not substitute for seed
    other = snap; other.frames.front().pc++;
    CHECK(!BacktraceUnwindCurrent(other));
    other = snap; other.frames.front().stackPtr++;
    CHECK(!BacktraceUnwindCurrent(other));
    other = snap; other.stackRevision = 0;
    CHECK(!BacktraceUnwindCurrent(other));

    CHECK(BacktraceModuleAt(snap, 0x1000));
    CHECK(BacktraceModuleAt(snap, 0x1fff));
    CHECK(!BacktraceModuleAt(snap, 0x2000));
    CHECK(BacktraceModuleLabel(snap, 0x1204) == "fixture.exe+0x204");
    other = snap; other.modules.push_back(module);
    CHECK(!BacktraceModuleAt(other, 0x1040));
    other = snap; other.modules.front().base = UINT64_MAX - 32;
    other.modules.front().size = 64;
    CHECK(!BacktraceModuleAt(other, 5));
    CHECK(BacktraceModuleAt(other, UINT64_MAX));

    SuffixDecoder decoder;
    uint8_t prefix[15]{};
    decoder.lengths[5] = true;
    auto candidate = FindBacktraceCallCandidate(decoder, prefix, sizeof(prefix), 0x1205);
    CHECK(candidate.unique() && candidate.address == 0x1200);
    CHECK(decoder.calls == 14);
    decoder.lengths[7] = true; // overlapping plausible CALL boundaries cannot become exact
    candidate = FindBacktraceCallCandidate(decoder, prefix, sizeof(prefix), 0x1205);
    CHECK(!candidate.unique() && candidate.matches == 2 && candidate.address == 0);
    decoder.lengths[5] = decoder.lengths[7] = false;
    decoder.lengths[15] = true;
    candidate = FindBacktraceCallCandidate(decoder, prefix, sizeof(prefix), 15);
    CHECK(candidate.unique() && candidate.address == 0); // valid zero call-site address
    decoder.typedNonCall = true;
    candidate = FindBacktraceCallCandidate(decoder, prefix, sizeof(prefix), 0x1205);
    CHECK(candidate.matches == 0); // authoritative typed flow wins over legacy isCall
    decoder.calls = 0;
    CHECK(!FindBacktraceCallCandidate(decoder, nullptr, 15, 99).unique());
    CHECK(!FindBacktraceCallCandidate(decoder, prefix, 16, 99).unique());
    CHECK(!FindBacktraceCallCandidate(decoder, prefix, 15, 14).unique());
    CHECK(decoder.calls == 0);
    std::printf("backtrace_test: %s (%d failures)\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
