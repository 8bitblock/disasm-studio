// Read-only probe for the current English Steam Peggle Deluxe 1.01 session.
#include "Core/ProcessMemorySession.h"
#include "Disasm/ZydisDisassembler.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>

int main(int argc, char** argv) {
    if (argc < 3) { std::puts("probe PID state|pegs|disasm|read|balls [hex-address] [byte-count]"); return 2; }
    ds::ProcessMemorySession memory;
    std::string error;
    if (!memory.open(static_cast<uint32_t>(std::strtoul(argv[1], nullptr, 10)), {false, true}, &error)) {
        std::printf("open: %s\n", error.c_str()); return 1;
    }
    const auto snapshot = memory.snapshot();
    std::printf("PID %u creation %llu %s\n", snapshot.identity.pid,
        static_cast<unsigned long long>(snapshot.identity.creationTime100ns), snapshot.path.c_str());
    if (snapshot.name != "popcapgame1.exe" || !snapshot.is32) return 2;
    const auto read = [&](uint64_t address, void* out, size_t size) {
        return memory.read(snapshot.identity, address, out, size, &error);
    };
    if (std::strcmp(argv[2], "pegs") == 0) {
        const auto exact = [&](uint32_t address, auto& value) {
            return read(address, &value, sizeof(value)) == sizeof(value);
        };
        uint32_t app = 0, board = 0, vt = 0, sentinel = 0, count = 0;
        if (!exact(0x6873AC, app) || !exact(app, vt) || vt != 0x5D7CBC ||
            !exact(app + 0x7B8, board) || !exact(board, vt) || vt != 0x5D76F4 ||
            !exact(board + 0x194, sentinel) || !exact(board + 0x198, count) || count > 4096) {
            std::puts("No valid bounded board object list."); return 1;
        }
        struct Node { uint32_t next, previous, object; };
        uint32_t node = 0, previous = sentinel, tail = 0;
        if (!exact(sentinel, node) || !exact(sentinel + 4, tail)) return 1;
        std::vector<uint32_t> visited;
        unsigned pegs = 0, hits = 0;
        for (uint32_t i = 0; i < count; ++i) {
            Node item{};
            if (!node || node == sentinel ||
                std::find(visited.begin(), visited.end(), node) != visited.end() ||
                !exact(node, item) || item.previous != previous) {
                std::puts("Object list changed during observation."); return 1;
            }
            visited.push_back(node);
            uint32_t peg = 0, kind = 0;
            if (!exact(item.object + 0xD0, peg) || !exact(item.object + 0x10, kind)) return 1;
            if (peg) {
                uint8_t hit = 0;
                float bounds[4]{};
                if (!exact(peg + 0x14, hit) || !exact(item.object + 0x14, bounds)) return 1;
                ++pegs; hits += hit != 0;
                std::printf("object=%08X peg=%08X kind=%u hit=%u center=(%.2f,%.2f)\n",
                    item.object, peg, kind, hit, (bounds[0]+bounds[2])*0.5f, (bounds[1]+bounds[3])*0.5f);
            }
            previous = node; node = item.next;
        }
        uint32_t currentCount = 0;
        if (node != sentinel || previous != tail || !exact(board + 0x198, currentCount) || currentCount != count) {
            std::puts("Object list changed during observation."); return 1;
        }
        std::printf("board=%08X objects=%u pegs=%u hit=%u\n", board, count, pegs, hits);
        return 0;
    }
    if (std::strcmp(argv[2], "state") == 0) {
        auto u32 = [&](uint32_t address) { uint32_t value=0; read(address,&value,4); return value; };
        auto u8 = [&](uint32_t address) { uint8_t value=0; read(address,&value,1); return value; };
        auto f32 = [&](uint32_t address) { float value=0; read(address,&value,4); return value; };
        const uint32_t app=u32(0x6873ac), board=u32(app+0x7b8), debug=u32(board+0x140);
        const uint32_t manager=u32(app+0x320), held=u32(debug+8), head=u32(board+0x1a0);
        std::printf("app=%08X board=%08X vtable=%08X debug=%08X vtable=%08X held=%08X drag=%u offsets=(%g,%g)\n",
            app,board,u32(board),debug,u32(debug),held,u8(debug+4),f32(debug+0xc),f32(debug+0x10));
        std::printf("mouse=(%d,%d) boardOrigin=(%u,%u) count=%u\n",static_cast<int32_t>(u32(manager+0xe0)),static_cast<int32_t>(u32(manager+0xe4)),u32(board+0x1a8),u32(board+0x1ac),u32(board+0x1a4));
        uint32_t node=u32(head);
        for(size_t i=0;node && node!=head && i<64;++i) {
            const uint32_t ball=u32(node+8);
            std::printf("node=%08X ball=%08X vtable=%08X ref=%u kind=%u heldFlag=%u inert=%u pos=(%.3f,%.3f) rendered=(%.3f,%.3f) velocity=(%.3f,%.3f)\n",node,ball,u32(ball),u32(ball+4),u32(ball+0x10),u8(ball+0x140),u8(ball+0x18c),f32(ball+0xec),f32(ball+0xf0),f32(ball+0x134),f32(ball+0x138),f32(ball+0xfc),f32(ball+0x100));
            node=u32(node);
        }
        return 0;
    }
    if (std::strcmp(argv[2], "balls") == 0) {
        const auto map = memory.committedRegions(snapshot.identity);
        std::vector<uint8_t> bytes((1u << 20) + 0x200);
        size_t found = 0; uint64_t scanned = 0;
        for (const auto& region : map.regions) {
            if (!region.readable || !region.writable || region.executable || region.type != 0x20000) continue;
            for (uint64_t offset = 0; offset < region.size && scanned < (512ull << 20); offset += 1u << 20) {
                const size_t want = static_cast<size_t>(std::min<uint64_t>(bytes.size(), region.size - offset));
                const size_t got = read(region.base + offset, bytes.data(), want);
                scanned += want;
                for (size_t i = 0; i + 0x190 <= got && i < (1u << 20); i += 4) {
                    uint32_t vt, kind; std::memcpy(&vt, bytes.data()+i,4); std::memcpy(&kind,bytes.data()+i+0x10,4);
                    if (vt != 0x5f19b4 || kind != 2) continue;
                    float values[4];
                    std::memcpy(&values[0],bytes.data()+i+0xec,8); std::memcpy(&values[2],bytes.data()+i+0xfc,8);
                    std::printf("ball %08llX kind=%u stationary=%u inert=%u active=%u pos=(%.3f,%.3f) velocity=(%.3f,%.3f)\n",
                        static_cast<unsigned long long>(region.base+offset+i),kind,bytes[i+0x140],bytes[i+0x18c],bytes[i+0x24],values[0],values[1],values[2],values[3]);
                    if (++found >= 128) return 0;
                }
            }
        }
        std::printf("found=%zu scanned=%llu completeMap=%d\n",found,static_cast<unsigned long long>(scanned),map.complete); return 0;
    }
    if (argc < 4) return 2;
    const uint64_t address = std::strtoull(argv[3],nullptr,16);
    const size_t size = argc > 4 ? std::min<size_t>(std::strtoul(argv[4],nullptr,0),65536) : 256;
    std::vector<uint8_t> bytes(size);
    bytes.resize(read(address,bytes.data(),size));
    if (std::strcmp(argv[2],"disasm") == 0) {
        ds::ZydisDisassembler decoder(ds::Arch::X86);
        for (const auto& insn : decoder.disassemble(bytes.data(),bytes.size(),address,512))
            std::printf("%08llX %-9s %s\n",static_cast<unsigned long long>(insn.address),insn.mnemonic.c_str(),insn.operands.c_str());
    } else {
        for(size_t i=0;i+4<=bytes.size();i+=4) {
            uint32_t value; float real; std::memcpy(&value,bytes.data()+i,4); std::memcpy(&real,bytes.data()+i,4);
            std::printf("%08llX +%03zX %08X %12.5g\n",static_cast<unsigned long long>(address+i),i,value,real);
        }
    }
    return 0;
}
