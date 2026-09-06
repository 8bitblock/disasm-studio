// Tiny local analysis bridge. Never loaded in a target process.
#include <Zydis/Zydis.h>
#include <cstdint>
#include <cstring>

struct AnalysisInstruction {
    uint64_t address;
    uint32_t size;
    char text[256];
};

extern "C" __declspec(dllexport) uint32_t DecodeX64(
    const uint8_t* data, uint32_t size, uint64_t address,
    AnalysisInstruction* output, uint32_t capacity) {
    uint32_t count = 0;
    while (size && count < capacity) {
        ZydisDisassembledInstruction instruction{};
        if (!ZYAN_SUCCESS(ZydisDisassembleIntel(ZYDIS_MACHINE_MODE_LONG_64,
                address, data, size, &instruction))) break;
        auto& item = output[count++];
        item.address = address;
        item.size = instruction.info.length;
        std::strncpy(item.text, instruction.text, sizeof(item.text)-1);
        item.text[sizeof(item.text)-1] = '\0';
        data += item.size;
        size -= item.size;
        address += item.size;
    }
    return count;
}
