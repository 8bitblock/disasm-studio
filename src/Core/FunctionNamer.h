#pragma once
//
// FunctionNamer.h
// Heuristic function-name inference. Discovery (FunctionAnalyzer) only ever
// gives a function a real name when it is an export or has a PDB symbol;
// everything else is "sub_<addr>". This module *guesses* a meaningful name for
// those anonymous functions the way a human reverse-engineer does on a first
// pass:
//   - thunks/wrappers that tail-jump to one import      -> j_<API>
//   - the image entry point / selected raw base         -> start
//   - empty / return-only stubs                         -> nullsub / ret_zero
//   - a recognizable set of imported APIs               -> a semantic verb
//                                                          (read_file, net_send,
//                                                           inject_thread, ...)
//   - a single notable API call                         -> <api>_wrapper
//   - a distinctive identifier-like referenced string   -> that string
//
// Two layers, so the interesting part is unit-testable without a disassembler:
//   GuessFromEvidence()  - PURE: FuncEvidence -> a name + human-readable reason.
//   FunctionNamer::name() - collects FuncEvidence per function by disassembling
//                           its body, then calls GuessFromEvidence and de-dups.
//
// Guesses are best-effort and always flagged (GuessedName::guessed) so the UI
// can show them in a distinct colour with the reason as a tooltip. They never
// override an export, a PDB symbol, or a user rename (the caller only feeds in
// anonymous sub_ functions and resolves real names at a higher priority).
//
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ds {

class BinaryFile;
class IDisassembler;

// One anonymous function to consider naming.
struct NamerInput {
    uint64_t address = 0;
    uint32_t size    = 0;     // estimated body size in bytes (0 => scan a window)
    bool     isExport = false; // already named: kept as-is, only seeds de-dup
    std::string name;          // current name (export name, or sub_<addr>)
};

// The result for one function (parallel to the NamerInput list).
struct GuessedName {
    std::string name;          // guessed name, or the original sub_ when no guess
    std::string reason;        // human-readable basis ("calls CreateFileW, ReadFile")
    bool        guessed = false;
};

// Evidence gathered about one function body. Kept deliberately small and free of
// engine types so the synthesis below is pure and testable.
struct FuncEvidence {
    int  instrCount = 0;
    int  callCount  = 0;                // direct + indirect calls
    std::vector<std::string> apis;      // bare imported-API names called (in order, de-duped)
    std::vector<std::string> strings;   // referenced string literals (raw text)
    bool isThunk      = false;          // body is essentially one jmp to a single target
    std::string thunkApi;               // API a thunk tail-jumps to ("" if its target isn't an API)
    bool selfRecursive = false;
    bool isEntry      = false;          // this is the image entry point
    bool isRawStart   = false;          // analyst-selected base of a raw mapping
    bool retOnly      = false;          // body is just ret / leave;ret / nop*;ret  (no calls)
    bool retZero      = false;          // sets eax/rax=0 then returns, no calls
};

// PURE: synthesize a name + reason from evidence. Returns guessed=false (empty
// name) when no confident guess can be made. Exposed for unit testing.
GuessedName GuessFromEvidence(const FuncEvidence& e);

// Convert an API/identifier (CamelCase or with A/W suffix) to a valid snake_case
// identifier, e.g. "CreateFileW" -> "create_file", "GetTickCount" ->
// "get_tick_count". Import/stdcall decoration is removed. Returns empty when
// the input carries no usable name (for example an ordinal import).
std::string ToSnakeIdentifier(const std::string& api);

class FunctionNamer {
public:
    // Guess names for every input function (result is parallel to `funcs`).
    //   entryVA       - image entry point VA (function there is named "start").
    //   importNameFor - va -> imported API ("dll.func" or bare name) for an IAT
    //                   slot / import target; "" if the address isn't an import.
    //   stringRefFor  - va -> string literal text at a data address; "" if none.
    std::vector<GuessedName>
    name(const BinaryFile& bin, IDisassembler& dis,
         const std::vector<NamerInput>& funcs, uint64_t entryVA,
         const std::function<std::string(uint64_t)>& importNameFor,
         const std::function<std::string(uint64_t)>& stringRefFor);

    // Explicit-validity form for analysis roots whose address may legitimately
    // be zero. `rawAnalysisStart` changes only the evidence wording: the result
    // is still `start`, but it never claims the blob had a header entry point.
    std::vector<GuessedName>
    name(const BinaryFile& bin, IDisassembler& dis,
         const std::vector<NamerInput>& funcs, uint64_t startVA,
         bool startValid, bool rawAnalysisStart,
         const std::function<std::string(uint64_t)>& importNameFor,
         const std::function<std::string(uint64_t)>& stringRefFor);

    int guessedCount() const { return guessed_; }

private:
    int guessed_ = 0;
};

} // namespace ds
