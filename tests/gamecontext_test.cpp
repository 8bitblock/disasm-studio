//
// gamecontext_test.cpp
// Pure tests for the additions.md D/H framework: game string grouping, likely
// gameplay/crackme functions, runtime boundary carry-through, and algorithm hints.
//
#include "Core/GameContext.h"

#include <cstdio>
#include <string>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static bool hasStringCat(const GameContextReport& r, GameStringCategory c) {
    for (const auto& s : r.strings) if (s.category == c) return true;
    return false;
}

static bool hasFuncKind(const GameContextReport& r, GameFunctionKind k) {
    for (const auto& f : r.functions) if (f.kind == k) return true;
    return false;
}

static bool hasFuncKindAt(const GameContextReport& r, uint64_t address,
                          GameFunctionKind kind) {
    for (const auto& f : r.functions)
        if (f.address == address && f.kind == kind) return true;
    return false;
}

static bool hasHint(const GameContextReport& r, const std::string& needle) {
    for (const auto& h : r.crackmeHints)
        if (h.title.find(needle) != std::string::npos || h.detail.find(needle) != std::string::npos)
            return true;
    return false;
}

int main() {
    GameContextInput in;
    in.strings.push_back({ 0x1000, "assets/player.dds", false });
    in.strings.push_back({ 0x1010, "config/settings.json", false });
    in.strings.push_back({ 0x1020, "savegame_slot1.sav", false });
    in.strings.push_back({ 0x1030, "https://example.invalid/api", false });
    in.strings.push_back({ 0x1040, "Wrong password", false });
    in.strings.push_back({ 0x1050, "http://localhost:8080/auth?key=abc&keep-alive=1", false });
    in.functions.push_back({ 0x2000, 32, "game_update_tick", false, "" });
    in.functions.push_back({ 0x2100, 32, "render_frame", false, "" });
    in.functions.push_back({ 0x2200, 32, "read_user_input", true, "reads user input" });
    in.functions.push_back({ 0x2300, 32, "check_license", true, "string compare controls branch" });
    in.functions.push_back({ 0x2400, 32, "send_ui_message", true, "calls USER32!SendMessageW" });
    in.functions.push_back({ 0x2500, 32, "connect_pipe", true, "calls KERNEL32!ConnectNamedPipeW" });
    in.functions.push_back({ 0x2600, 32, "socket_wrapper", true,
                             "calls WS2_32!connect and WS2_32!send" });

    Finding rt;
    rt.analyzer = "RuntimeScan";
    rt.title = "Unity engine";
    rt.category = "runtime";
    rt.confidence = 0.85f;
    rt.detail = "UnityPlayer.dll string";
    rt.evidence.push_back({ "string: UnityPlayer.dll", 0, 0x500 });
    in.runtime.findings.push_back(rt);
    in.runtime.wrapperLikely = true;
    in.runtime.wrapperRuntime = "Unity engine";
    in.runtime.wrapperConfidence = 0.85f;
    in.runtime.wrapperDetail = "UnityPlayer.dll string";

    AlgoMatch a;
    a.name = "CRC32 table";
    a.category = "checksum";
    a.confidence = 0.80f;
    a.address = 0x3000;
    a.addressValid = true;
    a.referencedBy.push_back({ 0x2300, "check_license", 0x2310, true, true });
    in.algorithms.push_back(a);

    GameContextReport r = BuildGameContext(in);
    CHECK(!r.empty());
    CHECK(hasStringCat(r, GameStringCategory::Asset));
    CHECK(hasStringCat(r, GameStringCategory::Config));
    CHECK(hasStringCat(r, GameStringCategory::Save));
    CHECK(hasStringCat(r, GameStringCategory::Network));
    CHECK(hasFuncKind(r, GameFunctionKind::UpdateLoop));
    CHECK(hasFuncKind(r, GameFunctionKind::Render));
    CHECK(hasFuncKind(r, GameFunctionKind::Input));
    CHECK(hasFuncKind(r, GameFunctionKind::Validation));
    CHECK(hasFuncKind(r, GameFunctionKind::Encoding));
    CHECK(!hasFuncKindAt(r, 0x2400, GameFunctionKind::Network));
    CHECK(!hasFuncKindAt(r, 0x2500, GameFunctionKind::Network));
    CHECK(hasFuncKindAt(r, 0x2600, GameFunctionKind::Network));
    CHECK(r.runtimeBoundaries.size() == 1 && r.runtimeBoundaries[0].title == "Unity engine");
    CHECK(hasHint(r, "Runtime handoff"));
    CHECK(hasHint(r, "Wrong password"));
    CHECK(hasHint(r, "Localhost handoff"));
    CHECK(hasHint(r, "Algorithm-backed"));

    GameContextInput clean;
    GameContextReport empty = BuildGameContext(clean);
    CHECK(empty.empty());

    if (g_fail) { std::printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("gamecontext_test: all checks passed\n");
    return 0;
}
