//
// cortex_test.cpp
// Unit test for the Cortex reasoning engine (src/Core/Cortex.cpp). Cortex is pure:
// it consumes already-computed TechScan capabilities / AlgoScan matches / discovered
// functions / strings and produces a plain-English verdict, merged behaviours,
// per-function briefs, and a deterministic Q&A (AskCortex). We build those inputs by
// hand (no BinaryFile needed — bin is null here) and assert the reasoning.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\cortex_test.cpp ^
//      src\Core\Cortex.cpp src\Core\BinaryFile.cpp src\Core\JvmClass.cpp
//   .\cortex_test.exe
//
#include "Core/Cortex.h"
#include "Core/TechScan.h"      // Capability
#include "Core/AlgoScan.h"      // AlgoMatch, AlgoXref
#include "Core/AnalysisJobs.h"  // FuncResult, StrResult

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

static bool has(const std::string& s, const char* sub) { return s.find(sub) != std::string::npos; }

// A lowercase-insensitive contains.
static bool ihas(std::string s, std::string sub) {
    for (char& c : s)   c = (char)std::tolower((unsigned char)c);
    for (char& c : sub) c = (char)std::tolower((unsigned char)c);
    return s.find(sub) != std::string::npos;
}

static const CortexBehavior* behavior(const CortexReport& r, const char* cat) {
    for (const CortexBehavior& b : r.behaviors) if (b.category == cat) return &b;
    return nullptr;
}
static const CortexFuncBrief* funcAt(const CortexReport& r, uint64_t va) {
    for (const CortexFuncBrief& f : r.functions) if (f.address == va) return &f;
    return nullptr;
}

int main() {
    // ---- Build a synthetic "network + AES + packed + anti-debug" binary ----
    std::vector<Capability> caps;
    caps.push_back({ "Network I/O", "network", 0.62f, 0x401000, "Imports: connect, send, recv", "TechScan", {}, 0 });
    caps.push_back({ "UPX packer", "packer", 0.80f, 0x402000, "Section names: UPX0, UPX1", "TechScan", {}, 0 });
    caps.push_back({ "Anti-debugging checks", "anti-debug", 0.66f, 0x403000, "Imports: IsDebuggerPresent", "TechScan", {}, 0 });

    std::vector<AlgoMatch> algos;
    {
        AlgoMatch a;
        a.name = "AES Rijndael S-box"; a.category = "crypto"; a.confidence = 0.9f;
        a.address = 0x410000; a.section = ".rdata"; a.detail = "256-byte AES S-box in .rdata";
        AlgoXref x; x.funcAddress = 0x401500; x.funcName = "sub_401500"; x.refInsn = 0x401520;
        a.referencedBy.push_back(x);
        algos.push_back(a);
    }
    {
        AlgoMatch a;
        a.name = "CRC32 table"; a.category = "checksum"; a.confidence = 0.72f;
        a.address = 0x411000; a.section = ".rdata"; a.detail = "CRC32 lookup table";
        AlgoXref x; x.funcAddress = 0x401B00; x.funcName = "sub_401B00"; x.refInsn = 0x401B20;
        a.referencedBy.push_back(x);
        algos.push_back(a);
    }

    std::vector<FuncResult> funcs = {
        { 0x401000, 120, "start",      false, "" },
        { 0x401500, 400, "sub_401500", false, "" },                 // crypto-referencing
        { 0x401800,  60, "read_file",  true,  "calls CreateFileW, ReadFile" },
        { 0x401900,  16, "j_send",     true,  "thunk to ws2_32.send" },
        { 0x401A00, 300, "sub_401A00", false, "" },                 // described only by annotations
        { 0x401B00, 220, "sub_401B00", false, "" },                 // checksum-referencing
        { 0x401C00,  80, "SendMessageWrapper", false, "calls user32.SendMessageW" },
        { 0x401D00,  80, "RegisterWindowClass", false, "calls user32.RegisterClassW" },
        { 0x401E00, 120, "decode_blob", false, "" },
    };

    std::vector<StrResult> strings = {
        { 0x420000, "http://c2.example.com/beacon", false },
        { 0x420100, "hello world", false },
    };

    // Per-function annotation facts (as CortexTab distils them from FuncAnnotate).
    std::vector<CortexFuncInfo> infos;
    { CortexFuncInfo fi; fi.address = 0x401A00;
      fi.summary = "reads user input and compares two strings";
      fi.patterns = { "reads user input", "string comparison" };
      fi.convention = "Microsoft x64"; infos.push_back(fi); }
    { CortexFuncInfo fi; fi.address = 0x401500;
      fi.summary = "expands the AES key schedule";
      fi.convention = "Microsoft x64"; infos.push_back(fi); }
    { CortexFuncInfo fi; fi.address = 0x401E00;
      fi.summary = "decodes a buffer";
      fi.patterns = { "XOR decode loop" }; infos.push_back(fi); }

    CortexInput in;
    in.capabilities = &caps;
    in.algorithms   = &algos;
    in.functions    = &funcs;
    in.strings      = &strings;
    in.funcInfo     = &infos;
    in.effectiveArchitecture = "x64";

    CortexReport rep = BuildCortexReport(in);

    // ---- Behaviour merge ----
    CHECK(behavior(rep, "network")   != nullptr);
    CHECK(behavior(rep, "crypto")    != nullptr);
    CHECK(behavior(rep, "packer")    != nullptr);
    CHECK(behavior(rep, "anti-debug")!= nullptr);
    if (const CortexBehavior* c = behavior(rep, "crypto")) {
        CHECK(c->confidence >= 0.9f);
        bool aes = false; for (auto& s : c->specifics) if (has(s, "AES")) aes = true;
        CHECK(aes);                                   // algorithm name folded in as a specific
        CHECK(!c->addresses.empty());                 // referencing insn carried through
    }
    // Behaviours are sorted by descending confidence (crypto 0.9 first).
    CHECK(!rep.behaviors.empty() && rep.behaviors.front().category == "crypto");

    // ---- Headline / verdict ----
    CHECK(ihas(rep.headline, "network"));
    CHECK(ihas(rep.headline, "cryptograph") || ihas(rep.headline, "aes"));
    CHECK(ihas(rep.verdict,  "packed"));              // packer caveat present
    CHECK(ihas(rep.verdict,  "debug"));               // anti-debug note present
    CHECK(has(rep.verdict, "http://c2.example.com/beacon"));  // URL surfaced from strings

    // ---- Per-function briefs ----
    if (const CortexFuncBrief* f = funcAt(rep, 0x401000)) {
        CHECK(ihas(f->brief, "entry"));
        bool entryTag = false; for (auto& t : f->tags) if (t == "entry") entryTag = true;
        CHECK(entryTag);
    } else CHECK(false);
    if (const CortexFuncBrief* f = funcAt(rep, 0x401500)) {
        CHECK(ihas(f->brief, "aes") || ihas(f->brief, "crypto"));
        bool cryptoTag = false; for (auto& t : f->tags) if (t == "crypto") cryptoTag = true;
        CHECK(cryptoTag);
    } else CHECK(false);
    if (const CortexFuncBrief* f = funcAt(rep, 0x401800)) {
        CHECK(ihas(f->brief, "file"));                // canned brief for read_file
        CHECK(f->guessed);
    } else CHECK(false);
    if (const CortexFuncBrief* f = funcAt(rep, 0x401900)) {
        CHECK(ihas(f->brief, "thunk"));
    } else CHECK(false);
    if (const CortexFuncBrief* f = funcAt(rep, 0x401B00)) {
        CHECK(ihas(f->brief, "checksum") || ihas(f->brief, "crc32"));
        bool checksumTag = false, cryptoTag = false;
        for (auto& t : f->tags) { if (t == "checksum") checksumTag = true; if (t == "crypto") cryptoTag = true; }
        CHECK(checksumTag);
        CHECK(!cryptoTag);
    } else CHECK(false);
    // Annotation-described function: the FuncAnnotate summary becomes the brief
    // (sentence-cased), a pattern adds a tag, and the convention is carried through.
    if (const CortexFuncBrief* f = funcAt(rep, 0x401A00)) {
        CHECK(ihas(f->brief, "reads user input"));
        CHECK(f->brief.size() > 0 && f->brief[0] == 'R');       // sentence-cased
        bool inputTag = false; for (auto& t : f->tags) if (t == "input") inputTag = true;
        CHECK(inputTag);
        CHECK(f->convention == "Microsoft x64");
    } else CHECK(false);
    // Convention propagates even when the brief comes from a stronger signal (crypto).
    if (const CortexFuncBrief* f = funcAt(rep, 0x401500))
        CHECK(f->convention == "Microsoft x64");
    // Token-aware category matching: GUI APIs are not socket/registry evidence,
    // while XOR decode is encoding rather than cryptography.
    if (const CortexFuncBrief* f = funcAt(rep, 0x401C00))
        CHECK(std::find(f->tags.begin(), f->tags.end(), "network") == f->tags.end());
    else CHECK(false);
    if (const CortexFuncBrief* f = funcAt(rep, 0x401D00))
        CHECK(std::find(f->tags.begin(), f->tags.end(), "registry") == f->tags.end());
    else CHECK(false);
    if (const CortexFuncBrief* f = funcAt(rep, 0x401E00)) {
        CHECK(std::find(f->tags.begin(), f->tags.end(), "encoding") != f->tags.end());
        CHECK(std::find(f->tags.begin(), f->tags.end(), "crypto") == f->tags.end());
    } else CHECK(false);
    CHECK(ihas(rep.headline, "x64")); // effective decoder arch works without a file header

    // Highlights: entry + crypto func should rank in.
    {
        bool sawEntry = false, sawCrypto = false;
        for (const CortexFuncBrief& f : rep.highlights) {
            if (f.address == 0x401000) sawEntry = true;
            if (f.address == 0x401500) sawCrypto = true;
        }
        CHECK(sawEntry);
        CHECK(sawCrypto);
    }

    // ---- AskCortex routing ----
    CHECK(ihas(AskCortex(rep, in, "does it use crypto?"), "cryptographic"));
    CHECK(ihas(AskCortex(rep, in, "does it use crypto?"), "aes"));
    CHECK(ihas(AskCortex(rep, in, "does it use a checksum?"), "crc32"));
    CHECK(ihas(AskCortex(rep, in, "what network apis does it call?"), "network"));
    CHECK(ihas(AskCortex(rep, in, "is it packed?"), "packed"));
    CHECK(ihas(AskCortex(rep, in, "anti debugging?"), "debugger"));
    CHECK(ihas(AskCortex(rep, in, "where is the entry point"), "start"));
    CHECK(ihas(AskCortex(rep, in, "show me notable strings"), "c2.example.com"));
    CHECK(ihas(AskCortex(rep, in, "what does it do?"), "network"));    // overview -> verdict
    // Unknown intent -> fallback carries the verdict + the "Ask about" hint.
    CHECK(ihas(AskCortex(rep, in, "flibbertigibbet"), "ask about"));

    // A category that is ABSENT answers in the negative, not a fabricated yes.
    CHECK(ihas(AskCortex(rep, in, "does it touch the registry?"), "no "));

    // Per-function Q&A: by name and by explicit hex address.
    CHECK(ihas(AskCortex(rep, in, "what does sub_401A00 do?"), "sub_401a00"));
    CHECK(ihas(AskCortex(rep, in, "what does sub_401A00 do?"), "reads user input"));
    CHECK(ihas(AskCortex(rep, in, "explain 0x401a00"), "sub_401a00"));
    CHECK(ihas(AskCortex(rep, in, "explain 0x401a00"), "microsoft x64"));   // convention surfaced
    CHECK(ihas(AskCortex(rep, in, "explain this function sub_401A00"), "reads user input"));

    // Confidence is an API contract (0..1), even when an upstream source is bad.
    {
        std::vector<Capability> badCaps = {
            { "Bad confidence", "network", 4.0f, 1, "synthetic", "test", {}, 0 }
        };
        CortexInput ci; ci.capabilities = &badCaps;
        CortexReport cr = BuildCortexReport(ci);
        CHECK(!cr.behaviors.empty() && cr.behaviors.front().confidence == 1.0f);
    }

    // A checksum-only image must not disappear from the headline or become
    // contradictory crypto evidence.
    {
        std::vector<AlgoMatch> checksumOnly(1);
        checksumOnly[0].name = "CRC32 table";
        checksumOnly[0].category = "checksum";
        checksumOnly[0].confidence = 0.8f;
        CortexInput ci; ci.algorithms = &checksumOnly;
        CortexReport cr = BuildCortexReport(ci);
        CHECK(ihas(cr.headline, "checksum") || ihas(cr.headline, "crc"));
        CHECK(ihas(AskCortex(cr, ci, "does it use crypto?"), "no "));
    }

    // ---- Clean / empty binary: no fabricated behaviours ----
    {
        CortexInput empty;
        CortexReport er = BuildCortexReport(empty);
        CHECK(er.behaviors.empty());
        CHECK(ihas(er.headline, "no notable") || ihas(er.headline, "program"));
        CHECK(!AskCortex(er, empty, "what does it do").empty());
    }

    // ---- Markdown render ----
    std::string md = RenderCortexMarkdown(rep);
    CHECK(has(md, "# Cortex analysis"));
    CHECK(ihas(md, "AES"));
    std::string html = RenderCortexHtml(rep);
    CHECK(has(html, "<!doctype html>"));
    CHECK(ihas(html, "AES"));
    {
        CortexReport escaped;
        escaped.headline = "<script>alert('x') & stop</script>";
        std::string safe = RenderCortexHtml(escaped);
        CHECK(has(safe, "&lt;script&gt;"));
        CHECK(has(safe, "&amp; stop"));
        CHECK(!has(safe, "<script>"));
    }

    if (g_fail == 0) std::printf("cortex_test: ALL PASSED\n");
    else             std::printf("cortex_test: %d CHEC(s) FAILED\n", g_fail);
    return g_fail != 0;
}
