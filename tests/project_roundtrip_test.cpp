//
// project_roundtrip_test.cpp
// Off-target unit test for the project sidecar (de)serialization in
// src/Core/Project.cpp, focused on the per-project engine + arch persistence
// added so a binary reopens with its last-used disassembler/architecture, plus a
// general round-trip of the existing annotation fields (64-bit address precision).
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\project_roundtrip_test.cpp src\Core\Project.cpp src\Core\Json.cpp
//   .\project_roundtrip_test.exe
//
#include "Core/Project.h"
#include "Disasm/IDisassembler.h"

#include <cstdint>
#include <cstdio>
#include <string>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main() {
    ProjectState st;
    st.hash       = 0xDEADBEEFCAFEF00Dull;     // exercise full 64-bit precision
    st.binaryPath = "C:/work/blob.bin";
    st.arch       = "ARM64";
    st.engine     = "Capstone";
    st.name       = "blob.bin";
    st.lastCursor = 0x1400123456ull;
    st.lastCursorValid = true;
    st.notes      = "raw firmware @ 0";
    st.comments[0x1400001000ull] = "entry";
    st.names[0x1400002000ull]    = "decrypt";
    st.bookmarks.push_back({ 0x1400003000ull, "table" });
    st.breakpoints.push_back(0x1400004000ull);
    st.bpConditions[0x1400004000ull] = "x0 == 0";
    st.patches.push_back({ 0x1400005000ull, { 0x01, 0x02 }, { 0x90, 0x90 } });
    st.watches.push_back("rax");
    st.watches.push_back("[rsp+8]");
    st.labels.push_back({ "java_method", "Crackme.check:(Ljava/lang/String;)Z", "check_password", 0.8f, "analyst label" });
    st.connection.enabled = true;
    st.connection.authEnabled = true;
    st.connection.accessToken = "tok";
    st.connectionEvents.push_back({ "event", "tool", "proj", "artifact", "0x1400002000",
                                    "breakpoint.hit", "{\"tid\":7}", "2026-06-12T00:00:00Z" });

    std::string text = SerializeProject(st);
    ProjectState rt;
    CHECK(DeserializeProject(text, rt));

    // The new per-project disassembler settings survive the round-trip.
    CHECK(rt.engine == "Capstone");
    CHECK(rt.arch   == "ARM64");

    // ArchFromName / EngineFromName reconstruct the enums the App reapplies.
    Arch a; CHECK(ArchFromName(rt.arch.c_str(), a) && a == Arch::ARM64);
    Engine e; CHECK(EngineFromName(rt.engine.c_str(), e) && e == Engine::Capstone);
    CHECK(std::string(ArchName(Arch::ARM64)) == "ARM64");
    CHECK(std::string(EngineNameOf(Engine::Capstone)) == "Capstone");
    // Round-trip every arch name through ArchFromName.
    for (Arch x : { Arch::X86, Arch::X64, Arch::ARM, Arch::ARM64, Arch::MIPS,
                    Arch::MIPS64, Arch::PPC, Arch::PPC64, Arch::RISCV32, Arch::RISCV64 }) {
        Arch back; CHECK(ArchFromName(ArchName(x), back) && back == x);
    }
    Arch junk; CHECK(!ArchFromName("nonsense", junk));

    // The rest of the state still round-trips (incl. 64-bit hash/cursor/addresses).
    CHECK(rt.hash == st.hash);
    CHECK(rt.lastCursor == st.lastCursor);
    CHECK(rt.lastCursorValid == st.lastCursorValid);
    CHECK(rt.notes == st.notes);
    CHECK(rt.comments.size() == 1 && rt.comments[0x1400001000ull] == "entry");
    CHECK(rt.names.size() == 1 && rt.names[0x1400002000ull] == "decrypt");
    CHECK(rt.bookmarks.size() == 1 && rt.bookmarks[0].address == 0x1400003000ull);
    CHECK(rt.breakpoints.size() == 1 && rt.breakpoints[0] == 0x1400004000ull);
    CHECK(rt.bpConditions[0x1400004000ull] == "x0 == 0");
    CHECK(rt.patches.size() == 1 && rt.patches[0].address == 0x1400005000ull
          && rt.patches[0].bytes.size() == 2 && rt.patches[0].bytes[0] == 0x90);
    CHECK(rt.watches.size() == 2 && rt.watches[0] == "rax" && rt.watches[1] == "[rsp+8]");
    CHECK(rt.labels.size() == 1 && rt.labels[0].targetKind == "java_method"
          && rt.labels[0].label == "check_password");
    CHECK(rt.connection.enabled && rt.connection.authEnabled
          && rt.connection.localhostOnly && rt.connection.accessToken == "tok");
    CHECK(rt.connectionEvents.size() == 1 && rt.connectionEvents[0].type == "event"
          && rt.connectionEvents[0].address == "0x1400002000"
          && rt.connectionEvents[0].payloadJson.find("\"tid\"") != std::string::npos);

    // watches alone count as content (so a watch-only project still saves).
    ProjectState w; w.hash = 2; w.watches.push_back("rcx");
    CHECK(w.hasContent());
    ProjectState ev; ev.hash = 3; ev.connectionEvents.push_back({ "event", "tool" });
    CHECK(ev.hasContent());
    ProjectState zeroCursor; zeroCursor.hash = 4;
    zeroCursor.lastCursor = 0; zeroCursor.lastCursorValid = true;
    CHECK(zeroCursor.hasContent());
    ProjectState zeroCursorRt;
    CHECK(DeserializeProject(SerializeProject(zeroCursor), zeroCursorRt));
    CHECK(zeroCursorRt.lastCursorValid && zeroCursorRt.lastCursor == 0);

    // hasContent() gates the empty-project save guard.
    ProjectState empty; empty.hash = 1; empty.arch = "x64"; empty.engine = "Zydis";
    CHECK(!empty.hasContent());        // metadata alone is not "content"
    empty.comments[0x10] = "x";
    CHECK(empty.hasContent());

    if (g_fail) { std::printf("\n%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("project_roundtrip_test: all checks passed\n");
    return 0;
}
