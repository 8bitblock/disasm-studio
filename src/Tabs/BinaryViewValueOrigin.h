#pragma once
#include "../Core/ValueOrigin.h"
#include <unordered_set>
namespace ds {
struct ValueOriginViewState {
    uint64_t requestId = 0;
    uint64_t imageSerial = 0, imageRevision = 0, epoch = 0, functionsGeneration = 0;
    DecoderConfig decoder;
    std::string selectedRegister;
    std::string status;
    bool pending = false;
    unsigned idleFrames = 0;
    bool reveal = false;
    std::shared_ptr<std::atomic<bool>> cancellation;
    std::shared_ptr<const ValueOriginResult> result;
    std::unordered_set<uint64_t> highlighted;
};
} // namespace ds
