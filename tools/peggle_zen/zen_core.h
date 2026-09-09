#pragma once
// The console's read-only signature resolver and checked one-charge write plan.
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace zen {
struct Range { uint32_t address; std::vector<uint8_t> bytes; };
struct Pattern {
    std::vector<int> bytes;
    explicit Pattern(const char* text) {
        std::istringstream input(text);
        for (std::string token; input >> token;) {
            if (token == "??") { bytes.push_back(-1); continue; }
            if (token.size() != 2 || token.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                throw std::runtime_error("Invalid built-in signature.");
            bytes.push_back(std::stoi(token, nullptr, 16));
        }
        if (bytes.empty()) throw std::runtime_error("Empty signature.");
    }
};
inline constexpr const char* kBoardAob = "A1 ?? ?? ?? ?? 8B 80 B8 07 00 00 C3";
inline constexpr const char* kLayoutAob = "8B 87 B8 07 00 00 3B C3 74 ?? 8B 80 54 01 00 00 83 78 04 05";
inline constexpr const char* kZenAob = "8B 96 28 01 00 00 88 86 A9 00 00 00 39 9C 96 0C 02 00 00 0F 8E ?? ?? ?? ?? 6A 0A 8B CE E8 ?? ?? ?? ??";

inline uint32_t unique(const std::vector<Range>& ranges, const Pattern& pattern, const char* name) {
    uint32_t address = 0;
    size_t count = 0;
    for (const auto& range : ranges) {
        if (range.bytes.size() < pattern.bytes.size()) continue;
        for (size_t i = 0; i <= range.bytes.size() - pattern.bytes.size(); ++i) {
            bool equal = true;
            for (size_t j = 0; j < pattern.bytes.size(); ++j)
                if (pattern.bytes[j] >= 0 && range.bytes[i+j] != pattern.bytes[j]) { equal = false; break; }
            if (equal) {
                if (++count > 1) throw std::runtime_error(std::string(name) + " AOB is ambiguous; no write allowed.");
                const uint64_t candidate = static_cast<uint64_t>(range.address) + i;
                if (candidate > UINT32_MAX) throw std::runtime_error("Signature address overflow.");
                address = static_cast<uint32_t>(candidate);
            }
        }
    }
    if (count != 1) throw std::runtime_error(std::string(name) + " AOB not found. This build or its code is unsupported.");
    return address;
}
inline uint32_t operand(const std::vector<Range>& ranges, uint32_t address) {
    for (const auto& range : ranges) {
        if (address < range.address) continue;
        const size_t offset = address - range.address;
        if (offset <= range.bytes.size() && range.bytes.size() - offset >= 4) {
            uint32_t value = 0;
            std::memcpy(&value, range.bytes.data()+offset, 4);
            return value;
        }
    }
    throw std::runtime_error("Incomplete signature operand.");
}
struct Layout {
    uint32_t boardSite=0, layoutSite=0, zenSite=0;
    uint32_t appGlobal=0, boardOffset=0, logicOffset=0, playerOffset=0, countOffset=0;
};
inline Layout resolve(const std::vector<Range>& ranges) {
    Layout result;
    result.boardSite = unique(ranges, Pattern(kBoardAob), "Board pointer");
    result.layoutSite = unique(ranges, Pattern(kLayoutAob), "Object layout");
    result.zenSite = unique(ranges, Pattern(kZenAob), "Zen shot consumer");
    result.appGlobal = operand(ranges, result.boardSite+1);
    result.boardOffset = operand(ranges, result.boardSite+7);
    result.logicOffset = operand(ranges, result.layoutSite+12);
    result.playerOffset = operand(ranges, result.zenSite+2);
    result.countOffset = operand(ranges, result.zenSite+15);
    if (operand(ranges, result.layoutSite+2) != result.boardOffset ||
        result.boardOffset != 0x7b8 || result.logicOffset != 0x154 ||
        result.playerOffset != 0x128 || result.countOffset != 0x20c)
        throw std::runtime_error("The AOBs disagree with the supported object layout.");
    return result;
}
inline bool pointer(uint32_t address) { return address >= 0x10000 && address <= 0xfff00000 && !(address & 3); }
inline uint32_t add(uint32_t address, uint32_t offset) {
    if (address > UINT32_MAX-offset) throw std::runtime_error("Game address overflow.");
    return address+offset;
}
using Reader = std::function<bool(uint32_t, void*, size_t)>;
inline uint32_t read32(const Reader& read, uint32_t address) {
    uint32_t result = 0;
    if (!read(address, &result, sizeof(result))) throw std::runtime_error("Could not read a complete game value.");
    return result;
}
struct State {
    uint32_t app=0, board=0, logic=0, player=0, phase=0, countAddress=0;
    int32_t charges=0;
};
inline State inspect(const Reader& read, const Layout& layout, uint32_t imageBase) {
    State result;
    result.app = read32(read, layout.appGlobal);
    if (!pointer(result.app)) throw std::runtime_error("The game is still starting.");
    if (read32(read, result.app) != add(imageBase, 0x1d7cbc))
        throw std::runtime_error("Unexpected Peggle application object.");
    result.board = read32(read, add(result.app, layout.boardOffset));
    if (!pointer(result.board)) throw std::runtime_error("Open a level first.");
    if (read32(read, result.board) != add(imageBase, 0x1d76f4) ||
        read32(read, add(result.board, 0xb0)) != result.app)
        throw std::runtime_error("The board changed or does not match this game.");
    result.logic = read32(read, add(result.board, layout.logicOffset));
    if (!pointer(result.logic) || read32(read, result.logic) != add(imageBase, 0x1eaf08) ||
        read32(read, add(result.logic, 0x104)) != result.board)
        throw std::runtime_error("The level state changed or is unsupported.");
    result.player = read32(read, add(result.logic, layout.playerOffset));
    if (result.player > 1) throw std::runtime_error("Invalid current-player index.");
    result.phase = read32(read, add(result.logic, 4));
    result.countAddress = add(result.logic, layout.countOffset + result.player*4);
    result.charges = static_cast<int32_t>(read32(read, result.countAddress));
    if (result.charges < 0 || result.charges > 999)
        throw std::runtime_error("Unexpected Zen count; no write allowed.");
    return result;
}
struct Grant { uint32_t address; int32_t before; int32_t after; };
inline Grant planGrant(const State& state) {
    if (state.phase != 1) throw std::runtime_error("Wait until the next ball is ready to fire, then try again (game state " + std::to_string(state.phase) + ").");
    if (!pointer(state.countAddress) || state.charges < 0 || state.charges >= 999)
        throw std::runtime_error("Zen count is outside the supported range.");
    return {state.countAddress, state.charges, state.charges+1};
}
inline void validateLoadedBall(const Reader& read, const State& state, uint32_t imageBase) {
    const uint32_t gun=read32(read,add(state.board,0xbc));
    if (!pointer(gun) || read32(read,gun)!=add(imageBase,0x1f286c) ||
        read32(read,add(gun,0x148))!=state.board)
        throw std::runtime_error("The loaded gun does not match the current board.");
    const uint32_t ball=read32(read,add(gun,0x1c0));
    if (!pointer(ball) || read32(read,ball)!=add(imageBase,0x1f19b4) || read32(read,add(ball,0x10))!=2)
        throw std::runtime_error("Wait for a ball to finish loading into the gun.");
    uint8_t held=0;
    if (!read(add(ball,0x140),&held,1)) throw std::runtime_error("Could not read the loaded-ball flag.");
    if (held!=1) throw std::runtime_error("The ball has already been fired.");
    uint16_t trigger=0;
    if (!read(add(state.logic,0xec),&trigger,2)) throw std::runtime_error("Could not read the shot-trigger flags.");
    if (trigger || read32(read,add(state.logic,0xf0)))
        throw std::runtime_error("A shot is already queued. Wait for the next ball.");
}
} // namespace zen
