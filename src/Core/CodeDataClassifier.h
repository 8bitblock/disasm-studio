#pragma once
//
// CodeDataClassifier.h
// Bounded, engine-neutral recursive code/data classification for executable
// sections.  The result is a complete, sorted partition of every file-backed
// executable range: proven reachable code, typed data, or explicitly Unknown.
// Unknown bytes stay decodable in the UI; only positively classified non-code
// spans are rendered as data directives.
//

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ds {

class BinaryFile;
class IDisassembler;
enum class Arch;
struct DecoderConfig;

enum class CodeDataKind : uint8_t {
    Unknown = 0,
    Code,
    String,
    LiteralPool,
    JumpTable,
    PointerTable,
    Padding,
    Data,
};

enum class CodeDataConfidence : uint8_t { Low = 0, Medium, High };

struct CodeDataSpan {
    uint64_t           address = 0;
    uint64_t           size = 0;
    CodeDataKind       kind = CodeDataKind::Unknown;
    uint8_t            elementWidth = 1; // db/dw/dd/dq rendering width
    CodeDataConfidence confidence = CodeDataConfidence::Low;
    std::string        evidence;
};

struct CodeDataFunctionInput {
    uint64_t address = 0;
    uint32_t size = 0;
};

struct CodeDataStringInput {
    uint64_t address = 0;
    uint64_t byteSize = 0; // includes a known terminator when one is mapped
    bool     wide = false;
};

struct CodeDataFunctionSeed {
    uint64_t    address = 0;
    std::string evidence;
};

struct CodeDataStats {
    uint64_t executableBytes = 0;
    uint64_t codeBytes = 0;
    uint64_t dataBytes = 0;
    uint64_t unknownBytes = 0;
    uint64_t stringBytes = 0;
    uint64_t literalBytes = 0;
    uint64_t jumpTableBytes = 0;
    uint64_t pointerTableBytes = 0;
    uint64_t paddingBytes = 0;
    uint64_t decodedInstructions = 0;
    uint64_t visitedBlocks = 0;
};

struct CodeDataMap {
    // Revision of the immutable BinaryFile image used to build this map. A zero
    // value is reserved for hand-authored/test maps; production classifiers
    // always stamp the current revision so stale results cannot reshape a newer
    // listing after a patch or reload.
    uint64_t                         imageRevision = 0;
    uint64_t                         scopeDigest = 0; // stamped on workers after analyst overrides
    // Sorted, non-overlapping spans that partition every mapped executable byte.
    std::vector<CodeDataSpan>        spans;
    // Strong indirect-only entries (vtable/callback pointers and CET landing pads)
    // which callers may feed back into FunctionAnalyzer for one bounded fixed point.
    std::vector<CodeDataFunctionSeed> functionSeeds;
    CodeDataStats                     stats;
    bool                              truncated = false;
    std::string                       truncationReason;

    const CodeDataSpan* find(uint64_t address) const;
};

const char* CodeDataKindName(CodeDataKind kind);
const char* CodeDataConfidenceName(CodeDataConfidence confidence);
bool        CodeDataKindIsData(CodeDataKind kind);
std::string CodeDataSummary(const CodeDataMap& map);

// Classify the current image. All work has explicit caps, polls `cancelled`, and
// never mutates BinaryFile or uses shared decoder state. `functions` are trusted
// recursive-descent roots; `strings` are scanner findings whose byte extents have
// already been checked by the caller.
CodeDataMap ClassifyCodeData(const BinaryFile& bin, IDisassembler& dis,
                             const DecoderConfig& decoder,
                             const std::vector<CodeDataFunctionInput>& functions,
                             const std::vector<CodeDataStringInput>& strings,
                             const std::function<bool()>& cancelled = {});

} // namespace ds
