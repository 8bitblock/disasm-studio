#pragma once
//
// Cortex.h
// The "reverse-engineering brain" for DisasmStudio (additions.md idea #3). Cortex
// does NOT run its own scans — it is a pure *reasoning layer* that consumes the
// products the analysis pipeline already computed (TechScan capabilities, AlgoScan
// crypto/algorithm matches, discovered + heuristically-named functions, imports,
// strings) and turns them into things a human reverse-engineer wants on a first
// pass:
//   - a one-sentence headline + a plain-English verdict of what the program does,
//   - merged behaviour findings (one line per capability class, with the concrete
//     evidence and representative addresses folded in),
//   - a per-function plain-English brief ("what this function looks like it does"),
//   - a ranked shortlist of the notable functions, and
//   - AskCortex(): a deterministic natural-ish-language Q&A over that fact base
//     ("does it use crypto?", "what network APIs?", "is it packed?", ...).
//
// Honesty contract (same as TechScan / FuncAnnotate): nothing here is asserted as
// fact. Every behaviour carries a confidence and its evidence; the verdict is
// hedged ("appears to", "likely"); guessed function names stay flagged. Cortex is
// a *deterministic* reasoning engine over static evidence — there is deliberately
// no model dependency. The seam for a future local-LLM backend is AskCortex() /
// the verdict text: a model could be swapped in behind them without changing any
// caller, because Cortex already hands it a structured, grounded fact base.
//
// Pure logic: no ImGui / Win32 / disassembler includes, so it compiles and
// unit-tests in isolation exactly like TechScan / AlgoScan / FuncAnnotate
// (tests/cortex_test.cpp).
//
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

class BinaryFile;
struct Capability;   // Core/TechScan.h
struct AlgoMatch;    // Core/AlgoScan.h
struct FuncResult;   // Core/AnalysisJobs.h (address, size, name, guessed, reason)
struct StrResult;    // Core/AnalysisJobs.h (address, text, wide)
struct CrackmeTriageReport; // Core/CrackmeTriage.h (ranked offline endpoint trails)

// Per-function facts distilled from the annotation engine (Core/FuncAnnotate). Kept
// as a plain struct so Cortex stays decoupled from FuncAnnotate.h and testable: the
// caller (CortexTab) builds these by running AnnotateFunction over each function and
// copying out the human-readable bits.
struct CortexFuncInfo {
    uint64_t                 address = 0;
    std::string              summary;     // FuncAnnotations::summary (compact one-liner)
    std::vector<std::string> patterns;    // function-level Pattern-note texts (what it does)
    std::string              convention;  // inferred calling convention ("Microsoft x64", ...)
};

// Everything Cortex reasons over. All pointers are OPTIONAL (null == empty); pass
// whatever the caller has already computed. Cortex never mutates any of it.
struct CortexInput {
    const BinaryFile*                  bin          = nullptr; // format/arch/entry/imports/sections
    // Architecture selected by the UI/decoder. This can intentionally differ
    // from the file header (most notably for raw blobs and manual overrides).
    // Empty keeps the legacy header-derived fallback for pure-logic callers.
    std::string                        effectiveArchitecture;
    const std::vector<Capability>*     capabilities = nullptr; // ScanCapabilities (TechScan)
    const std::vector<AlgoMatch>*      algorithms   = nullptr; // ScanAlgorithms (AlgoScan)
    const std::vector<FuncResult>*     functions    = nullptr; // discovered + guessed functions
    const std::vector<StrResult>*      strings      = nullptr; // extracted string literals
    const std::vector<CortexFuncInfo>* funcInfo     = nullptr; // per-function annotation facts
    const CrackmeTriageReport*         crackmeTriage = nullptr; // bounded offline endpoint evidence
};

// One merged behaviour conclusion (e.g. "Network communication", "Cryptography").
// Several pieces of evidence of the same class fold into a single behaviour so the
// report reads like a person's notes, not a raw signature dump.
struct CortexBehavior {
    std::string category;                 // canonical bucket ("network"/"crypto"/...)
    std::string title;                    // human title ("Network communication")
    float       confidence = 0.0f;        // 0..1, max over folded-in evidence
    std::string explanation;              // plain-English meaning of this behaviour
    std::string evidence;                 // concrete APIs / constants / sections behind it
    std::vector<std::string> specifics;   // named specifics (e.g. "AES", "UPX", "SHA-256")
    std::vector<uint64_t>    addresses;   // representative VAs to navigate to (bounded)
};

// One function's plain-English brief.
struct CortexFuncBrief {
    uint64_t    address = 0;
    std::string name;                     // display name (guessed or real)
    bool        guessed = false;          // name is a heuristic guess (render tinted)
    std::string brief;                    // "what this function looks like it does"
    std::string basis;                    // why (evidence / reason)
    std::string convention;               // calling convention if known (from annotations)
    std::vector<std::string> tags;        // {"entry","crypto","network",...}
    float       interest = 0.0f;          // ranking score for the highlights shortlist
};

struct CortexReport {
    std::string headline;                 // one sentence: what kind of program this is
    std::string verdict;                  // a short paragraph: what it appears to do
    std::vector<std::string>     facts;   // quick facts (format/arch/entry/#funcs/packed/...)
    std::vector<CortexBehavior>  behaviors;   // sorted by descending confidence
    std::vector<CortexFuncBrief> functions;   // per-function briefs (input order)
    std::vector<CortexFuncBrief> highlights;  // notable functions, ranked (subset)
    const char* analyzer = "Cortex";
};

// Reason over `in` and produce the report. Deterministic; returns a benign
// "nothing notable" verdict (no fabricated behaviours) for a clean/trivial image.
CortexReport BuildCortexReport(const CortexInput& in);

// Deterministic "chat with the binary": answer `question` from the report + input.
// Recognises intent by keyword (crypto / network / files / registry / packed /
// inject / debug / authorization / remembered startup access / strings / imports /
// entry / functions / summary) and answers in
// plain English grounded in the evidence. Always returns something useful (falls
// back to the verdict + a hint). Case-insensitive.
std::string AskCortex(const CortexReport& rep, const CortexInput& in,
                      const std::string& question);

// Render the report as Markdown (for File > Export Analysis and the tab's copy
// button). Pure text; safe to call on an empty report.
std::string RenderCortexMarkdown(const CortexReport& rep);
// Standalone, escaped HTML counterpart used when the export dialog selects .html.
std::string RenderCortexHtml(const CortexReport& rep);

} // namespace ds
