//
// livescan_service_test.cpp
// Unit-tests LiveScanService: the worker-pool mechanics + the three job kinds
// (Strings / Xref / ReadImage) driven by a STUB memory reader and a STUB decoder, so
// none of Windows / a real Debugger / Zydis is needed.
//
// Compile + run (MSVC dev shell), from the repo root:
//   cl /nologo /std:c++20 /EHsc /D_CRT_SECURE_NO_WARNINGS /I src ^
//      tests\livescan_service_test.cpp src\Core\LiveScanService.cpp src\Core\AnalysisJobs.cpp ^
//      src\Core\XrefIndex.cpp src\Core\BinaryFile.cpp src\Core\FunctionAnalyzer.cpp ^
//      src\Core\FunctionNamer.cpp src\Core\AlgoScan.cpp src\Core\SigMatch.cpp
//
#include "Core/LiveScanService.h"
#include "Disasm/IDisassembler.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <thread>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

// Decoder stub: 0xE8 => a 5-byte "call" with a FIXED branchTarget; anything else a
// 1-byte nop. Lets us plant a known cross-reference for the Xref job.
static const uint64_t kCallTarget = 0xCAFEBABEull;
struct StubDisasm : IDisassembler {
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "stub"; }
    bool decodeOne(const uint8_t* data, size_t size, uint64_t va, Instruction& out) override {
        if (!data || size == 0) return false;
        out = Instruction{};
        out.address = va;
        if (data[0] == 0xE8 && size >= 5) { out.length = 5; out.mnemonic = "call"; out.branchTarget = kCallTarget; }
        else                              { out.length = 1; out.mnemonic = "nop"; }
        return true;
    }
    std::vector<Instruction> disassemble(const uint8_t*, size_t, uint64_t, size_t) override { return {}; }
};

int main() {
    const uint64_t imgBase = 0x140000000ull;
    // Fake debuggee image: nops, an ASCII string at +0x10, a 0xE8 "call" at +0x40.
    std::vector<uint8_t> mem(0x100, 0x90);
    const char* str = "HelloLiveWorld";
    std::memcpy(mem.data() + 0x10, str, std::strlen(str));
    mem[0x10 + (int)std::strlen(str)] = 0x00;     // terminate the run
    mem[0x40] = 0xE8; mem[0x41] = mem[0x42] = mem[0x43] = mem[0x44] = 0x00;
    const char* str2 = "SecondLiveString";
    std::memcpy(mem.data() + 0x70, str2, std::strlen(str2));
    mem[0x70 + (int)std::strlen(str2)] = 0x00;

    // Stub MemReader over the fake image.
    MemReader reader = [imgBase, &mem](uint64_t va, void* out, size_t n) -> size_t {
        if (va < imgBase) return 0;
        size_t off = (size_t)(va - imgBase);
        if (off >= mem.size()) return 0;
        size_t k = std::min(n, mem.size() - off);
        std::memcpy(out, mem.data() + off, k);
        return k;
    };

    LiveScanService svc([](Engine, Arch) -> std::unique_ptr<IDisassembler> {
        return std::make_unique<StubDisasm>();
    });

    auto collect = [&](int ms, uint64_t token, LiveScanResult& got) -> bool {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
        while (std::chrono::steady_clock::now() < deadline) {
            LiveScanResult tmp;
            while (svc.tryTake(tmp)) {
                if (tmp.token == token && tmp.epoch == svc.epoch()) { got = std::move(tmp); return true; }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        return false;
    };

    // ---- Strings ----
    {
        std::vector<LiveRange> ranges = { { imgBase, mem.size() } };
        uint64_t tok = svc.requestStrings(ranges, reader, svc.epoch());
        LiveScanResult got;
        CHECK(collect(3000, tok, got), "strings job produced a result");
        bool found = false;
        for (auto& s : got.strings) if (s.text == "HelloLiveWorld" && s.address == imgBase + 0x10) found = true;
        CHECK(found, "live string scan found the planted ASCII string at the right VA");
    }

    // Exactly filling the cap is complete, while a real omitted result is surfaced.
    {
        std::vector<LiveRange> ranges = { { imgBase, mem.size() } };
        uint64_t tok = svc.requestStrings(ranges, reader, svc.epoch(), 2);
        LiveScanResult got;
        CHECK(collect(3000, tok, got), "exact-cap strings job produced a result");
        CHECK(got.strings.size() == 2 && !got.truncated,
              "exactly filling the live string cap is not falsely marked truncated");

        tok = svc.requestStrings(ranges, reader, svc.epoch(), 1);
        got = LiveScanResult{};
        CHECK(collect(3000, tok, got), "over-cap strings job produced a result");
        CHECK(got.strings.size() == 1 && got.truncated,
              "live string result reports a genuinely omitted match");

        tok = svc.requestStrings(ranges, reader, svc.epoch(), 100, 0x60);
        got = LiveScanResult{};
        CHECK(collect(3000, tok, got), "byte-capped strings job produced a result");
        CHECK(got.truncated, "a partial final range reports byte-cap truncation");
    }

    // ---- Xref ----
    {
        std::vector<LiveRange> ranges = { { imgBase, mem.size() } };
        uint64_t tok = svc.requestXref(ranges, kCallTarget, Engine::Zydis, Arch::X64, reader, svc.epoch());
        LiveScanResult got;
        CHECK(collect(3000, tok, got), "xref job produced a result");
        bool hit = false;
        for (uint64_t a : got.hits) if (a == imgBase + 0x40) hit = true;
        CHECK(hit, "live xref found the call referencing the target at +0x40");
        CHECK(got.target == kCallTarget, "xref result echoes the target");
    }

    // ---- ReadImage ----
    {
        uint64_t tok = svc.requestReadImage(imgBase, 0x80, /*moduleBase=*/imgBase, reader, svc.epoch());
        LiveScanResult got;
        CHECK(collect(3000, tok, got), "read-image job produced a result");
        CHECK(got.image.size() == 0x80, "read-image returned the requested span");
        CHECK(got.moduleBase == imgBase, "read-image echoes the module base");
        CHECK(!got.image.empty() && got.image[0x10] == (uint8_t)'H', "read-image bytes match the source");
    }

    // ---- Epoch gating: a bumped epoch means no result is accepted as current ----
    {
        std::vector<LiveRange> ranges = { { imgBase, mem.size() } };
        svc.requestStrings(ranges, reader, svc.epoch());
        svc.bumpEpoch();
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(400);
        while (std::chrono::steady_clock::now() < deadline) {
            LiveScanResult got;
            if (svc.tryTake(got)) CHECK(got.epoch != svc.epoch(), "superseded live result not current-epoch");
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    }

    // ---- cancelAndWaitIdle leaves the pool idle ----
    {
        std::vector<LiveRange> ranges = { { imgBase, mem.size() } };
        svc.requestStrings(ranges, reader, svc.epoch());
        svc.cancelAndWaitIdle();
        CHECK(!svc.busy(), "not busy after cancelAndWaitIdle");
    }

    if (g_fail == 0) std::printf("livescan_service_test: all checks passed\n");
    else             std::printf("livescan_service_test: %d FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
