#include "zen_core.h"
#include <iostream>
#include <map>
#include <utility>

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template<class F> void rejects(F&& action, const char* reason) {
    try { action(); }
    catch (const std::runtime_error& error) {
        if (std::string(error.what()).find(reason) != std::string::npos) return;
        throw std::runtime_error(std::string("Wrong refusal: ") + error.what());
    }
    throw std::runtime_error("Expected refusal, but operation succeeded.");
}

zen::Range code(uint32_t address, const char* pattern) {
    zen::Range result{address, {}};
    for (int byte : zen::Pattern(pattern).bytes)
        result.bytes.push_back(byte < 0 ? 0x5a : static_cast<uint8_t>(byte));
    return result;
}
void storeOperand(zen::Range& range, size_t offset, uint32_t value) {
    require(offset <= range.bytes.size() && range.bytes.size()-offset >= 4,
            "Invalid test operand location.");
    std::memcpy(range.bytes.data()+offset, &value, sizeof(value));
}
std::vector<zen::Range> signatures(uint32_t imageBase = 0x400000,
                                   uint32_t appGlobal = 0x600100) {
    std::vector<zen::Range> result{
        code(imageBase+0x1000, zen::kBoardAob),
        code(imageBase+0x2000, zen::kLayoutAob),
        code(imageBase+0x3000, zen::kZenAob)};
    storeOperand(result[0], 1, appGlobal);
    return result;
}

struct Game {
    uint32_t imageBase = 0x400000;
    uint32_t app = 0x1000000, board = 0x1100000, logic = 0x1200000;
    uint32_t gun = 0x1300000, ball = 0x1400000;
    zen::Layout layout = zen::resolve(signatures());
    std::map<uint32_t, uint8_t> memory;
    bool partialRead = false;
    uint32_t failedAddress = 0;

    explicit Game(uint32_t player = 0, int32_t charges = 0, uint32_t phase = 1) {
        put(layout.appGlobal, app);
        put(app, imageBase+0x1d7cbc);
        put(app+layout.boardOffset, board);
        put(board, imageBase+0x1d76f4);
        put(board+0xb0, app);
        put(board+layout.logicOffset, logic);
        put(logic, imageBase+0x1eaf08);
        put(logic+0x104, board);
        put(logic+layout.playerOffset, player);
        put(logic+4, phase);
        put(logic+layout.countOffset, static_cast<uint32_t>(charges));
        put(logic+layout.countOffset+4, static_cast<uint32_t>(charges));
    }
    void put(uint32_t address, uint32_t value) {
        for (uint32_t i = 0; i != 4; ++i)
            memory[address+i] = static_cast<uint8_t>(value >> (i*8));
    }
    void loadBall() {
        put(board+0xbc, gun);
        put(gun, imageBase+0x1f286c);
        put(gun+0x148, board);
        put(gun+0x1c0, ball);
        put(ball, imageBase+0x1f19b4);
        put(ball+0x10, 2);
        put(ball+0x140, 1);
        put(logic+0xec, 0);
        put(logic+0xf0, 0);
    }
    zen::Reader reader() {
        return [this](uint32_t address, void* destination, size_t count) {
            auto* output = static_cast<uint8_t*>(destination);
            if (address == failedAddress) {
                if (partialRead && count != 0) output[0] = 0;
                return false;
            }
            for (size_t i = 0; i < count; ++i) {
                const auto found = memory.find(address+static_cast<uint32_t>(i));
                if (found == memory.end()) return false;
                output[i] = found->second;
            }
            return true;
        };
    }
    zen::State inspect() { return zen::inspect(reader(), layout, imageBase); }
};

using Test = std::pair<const char*, std::function<void()>>;
} // namespace

int main() {
    const std::vector<Test> tests{
        {"unique signatures resolve real operand widths", [] {
            const auto layout = zen::resolve(signatures());
            require(layout.boardSite == 0x401000 && layout.layoutSite == 0x402000 &&
                    layout.zenSite == 0x403000, "Wrong signature sites.");
            require(layout.appGlobal == 0x600100 && layout.boardOffset == 0x7b8 &&
                    layout.logicOffset == 0x154 && layout.playerOffset == 0x128 &&
                    layout.countOffset == 0x20c, "Wrong decoded object layout.");
        }},
        {"every absent signature refuses", [] {
            for (size_t absent = 0; absent < 3; ++absent) {
                auto ranges = signatures();
                ranges.erase(ranges.begin()+absent);
                rejects([&] { zen::resolve(ranges); }, "AOB not found");
            }
        }},
        {"every duplicate signature refuses", [] {
            for (size_t duplicate = 0; duplicate < 3; ++duplicate) {
                auto ranges = signatures();
                auto extra = ranges[duplicate];
                extra.address += 0x10000;
                ranges.push_back(extra);
                rejects([&] { zen::resolve(ranges); }, "ambiguous");
            }
        }},
        {"duplicate matches within one range refuse", [] {
            auto range = code(0x400000, zen::kBoardAob);
            const auto second = range.bytes;
            range.bytes.insert(range.bytes.end(), second.begin(), second.end());
            rejects([&] { zen::unique({range}, zen::Pattern(zen::kBoardAob), "test"); }, "ambiguous");
        }},
        {"relocated app global and code addresses resolve", [] {
            const auto layout = zen::resolve(signatures(0x700000, 0x9234a0));
            require(layout.boardSite == 0x701000 && layout.appGlobal == 0x9234a0,
                    "Relocated wildcard operand was ignored.");
            Game game;
            game.memory.erase(game.layout.appGlobal);
            game.layout = layout;
            game.put(layout.appGlobal, game.app);
            require(game.inspect().board == game.board, "Relocated global was not followed.");
        }},
        {"bad encoded layout offsets refuse", [] {
            for (const auto& entry : std::vector<std::pair<size_t, size_t>>{
                     {0, 7}, {1, 2}, {1, 12}, {2, 2}, {2, 15}}) {
                auto ranges = signatures();
                ranges[entry.first].bytes[entry.second] ^= 1;
                rejects([&] { zen::resolve(ranges); }, "AOB not found");
            }
        }},
        {"truncated instruction signature refuses", [] {
            auto ranges = signatures();
            ranges[0].bytes.resize(4);
            rejects([&] { zen::resolve(ranges); }, "AOB not found");
        }},
        {"partial operand is never completed from adjacent ranges", [] {
            const std::vector<zen::Range> ranges{{0x401000, {0x78, 0x56, 0x34}},
                                                   {0x401003, {0x12}}};
            rejects([&] { zen::operand(ranges, 0x401000); }, "Incomplete");
            rejects([&] { zen::operand(ranges, 0x400fff); }, "Incomplete");
            rejects([&] { zen::operand(ranges, 0x401004); }, "Incomplete");
        }},
        {"both player counts use distinct addresses", [] {
            Game first(0, 2), second(1, 7);
            const auto a = first.inspect(), b = second.inspect();
            require(a.player == 0 && a.countAddress == first.logic+0x20c && a.charges == 2,
                    "Player zero count is wrong.");
            require(b.player == 1 && b.countAddress == second.logic+0x210 && b.charges == 7,
                    "Player one count is wrong.");
        }},
        {"object vtables must all match", [] {
            for (int object = 0; object < 3; ++object) {
                Game game;
                game.put(object == 0 ? game.app : object == 1 ? game.board : game.logic, 0x41414140);
                rejects([&] { game.inspect(); }, object == 0 ? "application object" :
                                                   object == 1 ? "board changed" : "level state changed");
            }
        }},
        {"inconsistent object back links refuse", [] {
            Game boardMismatch;
            boardMismatch.put(boardMismatch.board+0xb0, boardMismatch.app+4);
            rejects([&] { boardMismatch.inspect(); }, "board changed");
            Game logicMismatch;
            logicMismatch.put(logicMismatch.logic+0x104, logicMismatch.board+4);
            rejects([&] { logicMismatch.inspect(); }, "level state changed");
        }},
        {"missing or unaligned object pointers refuse", [] {
            for (const uint32_t bad : {0u, 0x40u, 0x1000001u, 0xfffffffcu}) {
                Game game;
                game.put(game.layout.appGlobal, bad);
                rejects([&] { game.inspect(); }, "still starting");
                Game noBoard;
                noBoard.put(noBoard.app+noBoard.layout.boardOffset, bad);
                rejects([&] { noBoard.inspect(); }, "Open a level");
                Game noLogic;
                noLogic.put(noLogic.board+noLogic.layout.logicOffset, bad);
                rejects([&] { noLogic.inspect(); }, "level state changed");
            }
        }},
        {"failed and partial reads refuse at every state field", [] {
            Game locations;
            const std::vector<uint32_t> addresses{
                locations.layout.appGlobal, locations.app, locations.app+0x7b8,
                locations.board, locations.board+0xb0, locations.board+0x154,
                locations.logic, locations.logic+0x104, locations.logic+0x128,
                locations.logic+4, locations.logic+0x20c};
            for (const auto address : addresses) {
                for (bool partial : {false, true}) {
                    Game game;
                    game.failedAddress = address;
                    game.partialRead = partial;
                    rejects([&] { game.inspect(); }, "complete game value");
                }
            }
        }},
        {"invalid player indices refuse", [] {
            for (uint32_t player : {2u, 0xffffffffu}) {
                Game game(player);
                rejects([&] { game.inspect(); }, "current-player index");
            }
        }},
        {"invalid signed and excessive counts refuse", [] {
            for (int32_t charges : {-1, -2147483647, 1000, 2147483647}) {
                Game game(0, charges);
                rejects([&] { game.inspect(); }, "Unexpected Zen count");
            }
        }},
        {"non-ready game phases cannot produce a grant", [] {
            for (uint32_t phase : {0u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 0xffffffffu}) {
                Game game(0, 0, phase);
                const auto state = game.inspect();
                rejects([&] { zen::planGrant(state); }, "ready to fire");
            }
        }},
        {"one-charge plan targets selected player and does not mutate memory", [] {
            for (uint32_t player : {0u, 1u}) {
                Game game(player, 12);
                const auto before = game.memory;
                const auto plan = zen::planGrant(game.inspect());
                require(plan.address == game.logic+0x20c+4*player && plan.before == 12 && plan.after == 13,
                        "Grant did not add exactly one to the selected count.");
                require(game.memory == before, "Planning a grant mutated memory.");
            }
        }},
        {"count limit and invalid grant addresses refuse", [] {
            Game game(0, 999);
            auto state = game.inspect();
            rejects([&] { zen::planGrant(state); }, "supported range");
            state.charges = 0;
            state.countAddress = 0;
            rejects([&] { zen::planGrant(state); }, "supported range");
            state.countAddress = game.logic+0x20d;
            rejects([&] { zen::planGrant(state); }, "supported range");
        }},
        {"zero and highest supported grants preserve exact counts", [] {
            for (int32_t charges : {0, 998}) {
                Game game(0, charges);
                const auto plan = zen::planGrant(game.inspect());
                require(plan.before == charges && plan.after == charges+1,
                        "Grant changed count by something other than one.");
            }
        }},
        {"loaded gun and held ball validate without mutation", [] {
            for (uint32_t player : {0u, 1u}) {
                Game game(player);
                game.loadBall();
                const auto before = game.memory;
                zen::validateLoadedBall(game.reader(), game.inspect(), game.imageBase);
                require(game.memory == before, "Loaded-ball validation mutated memory.");
            }
        }},
        {"missing gun and incorrect gun identity refuse", [] {
            for (int invalid = 0; invalid < 3; ++invalid) {
                Game game;
                game.loadBall();
                if (invalid == 0) game.put(game.board+0xbc, 0);
                if (invalid == 1) game.put(game.gun, game.imageBase+0x1f2868);
                if (invalid == 2) game.put(game.gun+0x148, game.board+4);
                rejects([&] { zen::validateLoadedBall(game.reader(), game.inspect(), game.imageBase); },
                        "gun does not match");
            }
        }},
        {"missing ball and incorrect ball identity or kind refuse", [] {
            for (int invalid = 0; invalid < 4; ++invalid) {
                Game game;
                game.loadBall();
                if (invalid == 0) game.put(game.gun+0x1c0, 0);
                if (invalid == 1) game.put(game.ball, game.imageBase+0x1f19b0);
                if (invalid == 2) game.put(game.ball+0x10, 1);
                if (invalid == 3) game.put(game.ball+0x10, 0xffffffffu);
                rejects([&] { zen::validateLoadedBall(game.reader(), game.inspect(), game.imageBase); },
                        "finish loading");
            }
        }},
        {"fired or invalid held flag refuses", [] {
            for (uint32_t held : {0u, 2u, 255u}) {
                Game game;
                game.loadBall();
                game.put(game.ball+0x140, held);
                rejects([&] { zen::validateLoadedBall(game.reader(), game.inspect(), game.imageBase); },
                        "already been fired");
            }
        }},
        {"pending trigger bytes or timer refuse", [] {
            for (int pending = 0; pending < 3; ++pending) {
                Game game;
                game.loadBall();
                if (pending == 0) game.put(game.logic+0xec, 1);
                if (pending == 1) game.put(game.logic+0xec, 0x100);
                if (pending == 2) game.put(game.logic+0xf0, 1);
                rejects([&] { zen::validateLoadedBall(game.reader(), game.inspect(), game.imageBase); },
                        "shot is already queued");
            }
        }},
        {"loaded-ball reads reject failure and partial output", [] {
            Game locations;
            const std::vector<std::pair<uint32_t, const char*>> fields{
                {locations.board+0xbc, "complete game value"},
                {locations.gun, "complete game value"},
                {locations.gun+0x148, "complete game value"},
                {locations.gun+0x1c0, "complete game value"},
                {locations.ball, "complete game value"},
                {locations.ball+0x10, "complete game value"},
                {locations.ball+0x140, "loaded-ball flag"},
                {locations.logic+0xec, "shot-trigger flags"},
                {locations.logic+0xf0, "complete game value"}};
            for (const auto& [address, reason] : fields) {
                for (bool partial : {false, true}) {
                    Game game;
                    game.loadBall();
                    const auto state = game.inspect();
                    game.failedAddress = address;
                    game.partialRead = partial;
                    rejects([&] { zen::validateLoadedBall(game.reader(), state, game.imageBase); }, reason);
                }
            }
        }},
        {"address arithmetic rejects overflow", [] {
            rejects([] { zen::add(0xfffffffcu, 4); }, "overflow");
            require(zen::add(0xfffffffbu, 4) == 0xffffffffu, "Valid final address rejected.");
        }}
    };

    size_t failed = 0;
    for (const auto& [name, run] : tests) {
        try { run(); std::cout << "PASS " << name << '\n'; }
        catch (const std::exception& error) {
            ++failed;
            std::cerr << "FAIL " << name << ": " << error.what() << '\n';
        }
    }
    std::cout << tests.size()-failed << '/' << tests.size() << " tests passed.\n";
    return failed == 0 ? 0 : 1;
}
