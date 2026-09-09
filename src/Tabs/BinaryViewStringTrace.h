#pragma once
#include "../Core/StringActionTrace.h"
#include "../Disasm/IDisassembler.h"

namespace ds {
struct StringTraceViewState {
    bool open = false, focus = false, pending = false, waiting = false;
    bool sourceLive = false;
    uint64_t sourceVA = 0, fileVA = 0, requestId = 0;
    uint64_t imageSerial = 0, imageRevision = 0, epoch = 0, functionsGeneration = 0;
    uint32_t pid = 0;
    uint64_t session = 0;
    DecoderConfig decoder;
    unsigned idleFrames = 0;
    int selected = 0;
    std::string text, status;
    std::shared_ptr<std::atomic<bool>> cancellation;
    std::shared_ptr<const StringActionTraceResult> result;
    std::shared_ptr<const XrefIndex> xrefs;
};
} // namespace ds
