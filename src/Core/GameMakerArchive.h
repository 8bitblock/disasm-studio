#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace ds {

inline constexpr uint32_t GmlNoIndex = UINT32_MAX;

struct GameMakerChunk {
    std::string tag;
    uint64_t fileOffset = 0; // payload, excluding the eight-byte chunk header
    uint64_t length = 0;
};
struct GameMakerString {
    uint32_t index = 0;
    uint64_t fileOffset = 0; // UTF-8 text, excluding length prefix
    std::string text;
};
struct GameMakerCode {
    uint32_t index = 0;
    std::string name;
    uint64_t recordOffset = 0, bytecodeOffset = 0;
    uint32_t bytecodeLength = 0, entryOffset = 0;
    uint32_t parentIndex = GmlNoIndex;
    uint16_t localsCount = 0, argumentsCount = 0;
    bool localFlag = false;
    bool instructionsComplete = false;
    uint32_t decodedLength = 0;
    uint64_t entryFileOffset() const { return bytecodeOffset + entryOffset; }
    // This is the shared blob's remaining extent, NOT an exact child function size.
    uint32_t entryLength() const { return entryOffset <= bytecodeLength ? bytecodeLength - entryOffset : 0; }
};
struct GameMakerVariable {
    uint32_t index = 0;
    std::string name;
    uint64_t recordOffset = 0;
    int32_t instanceType = 0, variableId = 0;
    uint32_t occurrences = 0, firstOccurrence = UINT32_MAX;
    bool referencesComplete = false;
};
struct GameMakerFunction {
    uint32_t index = 0;
    std::string name;
    uint64_t recordOffset = 0;
    uint32_t occurrences = 0, firstOccurrence = UINT32_MAX;
    uint32_t codeIndex = GmlNoIndex;
    bool referencesComplete = false;
};
struct GameMakerScript {
    std::string name;
    uint32_t codeIndex = GmlNoIndex;
    bool constructor = false;
};
struct GameMakerEvent {
    uint32_t type = 0, subtype = 0, codeIndex = GmlNoIndex;
    std::string actionName;
};
struct GameMakerObject {
    uint32_t index = 0;
    std::string name;
    uint64_t recordOffset = 0;
    int32_t parentIndex = -1;
    bool eventsComplete = false;
    std::vector<GameMakerEvent> events;
};
struct GameMakerLocal {
    uint32_t index = 0;
    std::string name;
};
struct GameMakerCodeLocals {
    std::string codeName;
    std::vector<GameMakerLocal> locals;
};
enum class GmlReferenceKind : uint8_t { Variable, Function, String };
struct GameMakerReference {
    uint64_t instructionOffset = 0;
    GmlReferenceKind kind = GmlReferenceKind::Variable;
    uint32_t symbolIndex = 0;
    uint8_t referenceType = 0;
};

// Immutable after publication. Contains no borrowed file or runtime pointers.
struct GameMakerArchive {
    bool ok = false, cancelled = false, bytecodeSupported = false;
    bool referencesComplete = true;
    uint8_t bytecodeVersion = 0;
    uint32_t versionMajor = 0, versionMinor = 0, versionRelease = 0, versionBuild = 0;
    uint64_t declaredFileSize = 0;
    std::string gameName, error;
    std::vector<std::string> warnings;
    std::vector<GameMakerChunk> chunks;
    std::vector<GameMakerString> strings;
    std::vector<GameMakerCode> code;
    std::vector<GameMakerVariable> variables;
    std::vector<GameMakerFunction> functions;
    std::vector<GameMakerScript> scripts;
    std::vector<GameMakerObject> objects;
    std::vector<GameMakerCodeLocals> codeLocals;
    std::vector<uint32_t> globalCodeIndices;
    std::vector<GameMakerReference> references; // sorted by instruction file offset
    std::vector<uint64_t> instructionOffsets; // exact validated starts, sorted/unique
    std::vector<uint32_t> rootCodeIndices; // sorted by bytecode file offset

    const GameMakerCode* codeAtOffset(uint64_t fileOffset) const; // containing root blob
    const GameMakerReference* referenceAtOffset(uint64_t fileOffset) const;
    bool isInstructionOffset(uint64_t fileOffset) const;
};

bool IsGameMakerArchiveImage(const uint8_t* data, size_t size);
GameMakerArchive ParseGameMakerArchive(const uint8_t* data, size_t size,
                                      const std::function<bool()>& cancelled = {});

// Structural word length for supported modern bytecode (15..17). Zero means
// unsupported opcode/type; never guess an operand length from native decoders.
uint32_t GmlEncodedInstructionLength(uint32_t word, uint8_t bytecodeVersion = 17);
const char* GmlScopeName(int32_t instanceType);
const char* GmlEventName(uint32_t eventType);

} // namespace ds
