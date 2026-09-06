#pragma once
//
// AlgoScan.h
// Deterministic algorithm / crypto recognizer (FindCrypt / capa style). Scans a
// loaded image for known constant tables (AES S-boxes + round tables, SHA-1/256/512
// and MD5 init/round constants, CRC32 tables/polynomials, TEA/XTEA deltas, ChaCha/
// Salsa20 sigma) and for Base64 alphabets (standard, URL-safe, and *mutated*
// permutations), then maps each constant hit to the function(s) that reference it
// using a prebuilt XrefIndex.
//
// The bar is intentionally EVIDENCE-ONLY: a match means "these constants are present
// (and referenced from function X)", never "this binary provably runs AES". Confidence
// reflects how distinctive the signature is, not whether the code path executes —
// statically-linked-but-unused crypto still has its tables in .rdata.
//
// Pure logic: no ImGui / Win32 / disassembler includes, so it compiles and unit-tests
// in the sandbox with cl/g++ exactly like TechScan.cpp / AnalysisJobs.cpp. Extent
// mapping consumes an already-built XrefIndex (no live decode here).
//
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ds {

class BinaryFile;
struct XrefIndex;    // full def in XrefIndex.h
struct FuncResult;   // full def in AnalysisJobs.h (address, size, name, guessed, reason)

enum class AlgoKind : uint8_t {
    ConstantTable,    // matched a known constant / S-box / round table
    AlphabetStd,      // standard or URL-safe Base64 alphabet
    AlphabetMutated,  // a permutation of the standard 64-symbol Base64 set
    Structural        // reserved (RC4 etc.) — not emitted in Tier A
};

// One referencing function for a constant hit (the extent-mapping result).
struct AlgoXref {
    uint64_t    funcAddress = 0;   // enclosing function start (VA 0 is valid)
    std::string funcName;          // function name (sub_/export/guess)
    uint64_t    refInsn     = 0;   // a representative referencing instruction VA
    bool        funcAddressValid = false;
    bool        refInsnValid = false;
};

struct AlgoMatch {
    std::string name;        // "AES Rijndael S-box", "SHA-256 K[64]", "Base64 (mutated)"
    std::string category;    // "crypto" / "hash" / "encoding" / "checksum"
    AlgoKind    kind = AlgoKind::ConstantTable;
    float       confidence = 0.0f;        // 0..1, signature distinctiveness (NOT usage)
    uint64_t    address = 0;              // primary data VA (== dataVAs.front() when any)
    std::vector<uint64_t> dataVAs;        // every matched data VA (bounded)
    std::string section;                  // section the (first) hit landed in (".rdata")
    std::string detail;                   // human-readable evidence + orientation note
    std::vector<AlgoXref> referencedBy;   // extent mapping (de-duped by func, capped)
    std::string alphabet;                 // 64-char alphabet (alphabet matches only)
    std::string substitutionNote;         // AlphabetMutated only ("k of 64 positions differ")
    bool        addressValid = false;
};

// Scan `bin` for recognized algorithms. `xref` and `functions` are OPTIONAL: when
// BOTH are non-null each match's referencedBy[] is filled (constant hit -> referencing
// function); when either is null matches come back with empty referencedBy[] (the cheap
// synchronous path the Binary Tech tab uses). Results are sorted by descending
// confidence. Returns empty for a clean image (no fabricated rows).
std::vector<AlgoMatch> ScanAlgorithms(const BinaryFile& bin,
                                      const XrefIndex* xref = nullptr,
                                      const std::vector<FuncResult>* functions = nullptr,
                                      const std::function<bool()>& cancelled = {});

} // namespace ds
