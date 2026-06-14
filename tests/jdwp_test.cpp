//
// jdwp_test.cpp
// Off-target tests for src/Core/Jdwp.cpp: packet framing round-trip (incl.
// partial/garbage input), big-endian payload reader/writer with non-default
// ID sizes, every reply parser over hand-built buffers, the Event::Composite
// parser, and the request builders' exact wire bytes.
//
// Build & run (Windows, from project root, in a VS dev shell):
//   cl /std:c++20 /EHsc /I src tests\jdwp_test.cpp src\Core\Jdwp.cpp
//   .\jdwp_test.exe
//
#include "Core/Jdwp.h"

#include <cstdio>
#include <cstring>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main() {
    // ---- packet framing ----------------------------------------------------------
    {
        JdwpWriter w;
        w.u4(0xDEADBEEF);
        auto pkt = JdwpEncodeCommand(7, JDWP_SET_VirtualMachine, JDWP_VM_Version, w.bytes());
        CHECK(pkt.size() == 15);                       // 11 header + 4 payload
        CHECK(pkt[0] == 0 && pkt[1] == 0 && pkt[2] == 0 && pkt[3] == 15);   // BE length
        CHECK(pkt[8] == 0 && pkt[9] == 1 && pkt[10] == 1);

        JdwpPacket p; size_t used = 0;
        CHECK(JdwpDecodePacket(pkt.data(), pkt.size(), p, used));
        CHECK(used == 15 && p.id == 7 && !p.isReply());
        CHECK(p.cmdSet == JDWP_SET_VirtualMachine && p.cmd == JDWP_VM_Version);
        CHECK(p.payload.size() == 4 && p.payload[0] == 0xDE);

        // Partial buffer: needs more bytes, consumes nothing.
        CHECK(!JdwpDecodePacket(pkt.data(), 10, p, used) && used == 0);
        CHECK(!JdwpDecodePacket(pkt.data(), 14, p, used) && used == 0);

        // Hostile length: flagged as unrecoverable.
        uint8_t bad[11] = {0, 0, 0, 5, 0, 0, 0, 1, 0, 1, 1};   // length 5 < header
        CHECK(!JdwpDecodePacket(bad, sizeof(bad), p, used) && used == SIZE_MAX);
    }

    // Reply packet decode (flags 0x80, error code field).
    {
        uint8_t rep[13] = {0, 0, 0, 13, 0, 0, 0, 9, 0x80, 0, 21, 0xAB, 0xCD};
        JdwpPacket p; size_t used = 0;
        CHECK(JdwpDecodePacket(rep, sizeof(rep), p, used));
        CHECK(p.isReply() && p.id == 9 && p.errorCode == 21);
        CHECK(p.payload.size() == 2 && p.payload[0] == 0xAB);
    }

    // ---- reader/writer with non-default ID sizes ------------------------------------
    JdwpIdSizes sz4;                                    // a VM with 4-byte IDs
    sz4.fieldID = sz4.methodID = sz4.objectID = sz4.referenceTypeID = sz4.frameID = 4;
    {
        JdwpWriter w;
        w.id(0x11223344, 4);
        w.str("hi");
        w.u8(0x0102030405060708ull);
        JdwpReader r(w.bytes().data(), w.bytes().size());
        CHECK(r.id(4) == 0x11223344);
        CHECK(r.str() == "hi");
        CHECK(r.u8() == 0x0102030405060708ull);
        CHECK(!r.fail() && r.atEnd());
        CHECK(r.u1() == 0 && r.fail());                // past the end: latched fail
    }

    // ---- IDSizes ----------------------------------------------------------------------
    {
        JdwpWriter w;
        for (int i = 0; i < 5; ++i) w.u4(8);
        JdwpIdSizes s;
        CHECK(JdwpParseIdSizes(w.bytes(), s) && s.objectID == 8 && s.frameID == 8);
        JdwpWriter bad;
        for (int i = 0; i < 5; ++i) bad.u4(99);        // implausible width
        CHECK(!JdwpParseIdSizes(bad.bytes(), s));
    }

    // ---- Version ------------------------------------------------------------------------
    {
        JdwpWriter w;
        w.str("desc"); w.u4(1); w.u4(8); w.str("17.0.1"); w.str("OpenJDK 64-Bit Server VM");
        JdwpVersionInfo v;
        CHECK(JdwpParseVersion(w.bytes(), v));
        CHECK(v.jdwpMajor == 1 && v.jdwpMinor == 8);
        CHECK(v.vmName == "OpenJDK 64-Bit Server VM" && v.vmVersion == "17.0.1");
    }

    // ---- AllClasses / AllThreads / Methods (4-byte IDs) -----------------------------------
    {
        JdwpWriter w;
        w.u4(2);
        w.u1(1); w.id(0x1001, 4); w.str("LMain;");            w.u4(7);
        w.u1(2); w.id(0x1002, 4); w.str("Ljava/util/List;");  w.u4(3);
        std::vector<JdwpClassInfo> cs;
        CHECK(JdwpParseAllClasses(w.bytes(), sz4, cs));
        CHECK(cs.size() == 2 && cs[0].typeID == 0x1001 && cs[0].signature == "LMain;");
        CHECK(cs[1].refTypeTag == 2 && cs[1].status == 3);
    }
    {
        JdwpWriter w;
        w.u4(3); w.id(0xA, 4); w.id(0xB, 4); w.id(0xC, 4);
        std::vector<uint64_t> ts;
        CHECK(JdwpParseAllThreads(w.bytes(), sz4, ts));
        CHECK(ts.size() == 3 && ts[2] == 0xC);
    }
    {
        JdwpWriter w;
        w.u4(2);
        w.id(0x21, 4); w.str("main");   w.str("([Ljava/lang/String;)V"); w.u4(9);
        w.id(0x22, 4); w.str("helper"); w.str("()I");                    w.u4(10);
        std::vector<JdwpMethodInfo> ms;
        CHECK(JdwpParseMethods(w.bytes(), sz4, ms));
        CHECK(ms.size() == 2 && ms[0].methodID == 0x21 && ms[0].name == "main");
        CHECK(ms[1].signature == "()I" && ms[1].modBits == 10);
        // Truncated reply fails cleanly.
        auto cut = w.bytes(); cut.resize(cut.size() / 2);
        CHECK(!JdwpParseMethods(cut, sz4, ms));
    }

    // ---- Frames / ThreadStatus / Bytecodes / ConstantPool / LineTable ----------------------
    {
        JdwpWriter w;
        w.u4(1);
        w.id(0x77, 4);                                 // frameID
        w.u1(1); w.id(0x1001, 4); w.id(0x21, 4); w.u8(5);   // location: Main.main bci 5
        std::vector<JdwpFrameInfo> fs;
        CHECK(JdwpParseFrames(w.bytes(), sz4, fs));
        CHECK(fs.size() == 1 && fs[0].frameID == 0x77);
        CHECK(fs[0].loc.classID == 0x1001 && fs[0].loc.methodID == 0x21 && fs[0].loc.index == 5);
    }
    {
        JdwpWriter w; w.u4(JDWP_TS_SLEEPING); w.u4(1);
        int32_t t = 0, s = 0;
        CHECK(JdwpParseThreadStatus(w.bytes(), t, s) && t == JDWP_TS_SLEEPING && s == 1);
    }
    {
        JdwpWriter w; w.u4(3); w.u1(0x10); w.u1(42); w.u1(0xAC);   // bipush 42; ireturn
        std::vector<uint8_t> bc;
        CHECK(JdwpParseBytecodes(w.bytes(), bc));
        CHECK(bc.size() == 3 && bc[0] == 0x10 && bc[2] == 0xAC);
        JdwpWriter lie; lie.u4(100); lie.u1(1);        // count > available
        CHECK(!JdwpParseBytecodes(lie.bytes(), bc));
    }
    {
        JdwpWriter w; w.u4(29); w.u4(3); w.u1(1); w.u1(2); w.u1(3);
        uint32_t cnt = 0; std::vector<uint8_t> cp;
        CHECK(JdwpParseConstantPool(w.bytes(), cnt, cp));
        CHECK(cnt == 29 && cp.size() == 3 && cp[2] == 3);
    }
    {
        JdwpWriter w; w.u8(0); w.u8(40); w.u4(2);
        w.u8(0); w.u4(10); w.u8(5); w.u4(11);
        std::vector<std::pair<uint64_t, uint32_t>> lt;
        CHECK(JdwpParseLineTable(w.bytes(), lt));
        CHECK(lt.size() == 2 && lt[1].first == 5 && lt[1].second == 11);
    }

    // ---- Event::Composite --------------------------------------------------------------------
    {
        JdwpWriter w;
        w.u1(JDWP_SP_ALL);
        w.u4(2);
        w.u1(JDWP_EK_BREAKPOINT); w.u4(31);            // requestID
        w.id(0xB, 4);                                  // thread
        w.u1(1); w.id(0x1001, 4); w.id(0x21, 4); w.u8(17);
        w.u1(JDWP_EK_VM_DEATH); w.u4(0);
        JdwpEventSet es;
        CHECK(JdwpParseEventComposite(w.bytes(), sz4, es));
        CHECK(es.suspendPolicy == JDWP_SP_ALL && es.events.size() == 2);
        if (es.events.size() == 2) {
            CHECK(es.events[0].eventKind == JDWP_EK_BREAKPOINT);
            CHECK(es.events[0].requestID == 31 && es.events[0].threadID == 0xB);
            CHECK(es.events[0].loc.index == 17 && es.events[0].loc.methodID == 0x21);
            CHECK(es.events[1].eventKind == JDWP_EK_VM_DEATH);
        }
    }
    {
        // CLASS_PREPARE + an unknown trailing kind: keeps decoded events, no fail.
        JdwpWriter w;
        w.u1(JDWP_SP_NONE);
        w.u4(2);
        w.u1(JDWP_EK_CLASS_PREPARE); w.u4(5);
        w.id(0xB, 4); w.u1(1); w.id(0x1003, 4); w.str("LFoo;"); w.u4(7);
        w.u1(200); w.u4(1);                            // unknown kind
        JdwpEventSet es;
        CHECK(JdwpParseEventComposite(w.bytes(), sz4, es));
        CHECK(es.events.size() == 2);
        if (es.events.size() == 2) {
            CHECK(es.events[0].signature == "LFoo;" && es.events[0].typeID == 0x1003);
            CHECK(es.events[1].eventKind == 200);
        }
    }

    // ---- request builders -----------------------------------------------------------------------
    {
        JdwpLocation loc{1, 0x1001, 0x21, 17};
        auto b = JdwpBuildBreakpointRequest(loc, sz4);
        // kind, policy, 1 modifier, LocationOnly(7), tag, 4+4 ids, 8 index
        CHECK(b.size() == 1 + 1 + 4 + 1 + 1 + 4 + 4 + 8);
        CHECK(b[0] == JDWP_EK_BREAKPOINT && b[1] == JDWP_SP_ALL && b[6] == 7);
        JdwpReader r(b.data() + 7, b.size() - 7);
        JdwpLocation got = r.location(sz4);
        CHECK(got.classID == 0x1001 && got.methodID == 0x21 && got.index == 17);

        auto s = JdwpBuildStepRequest(0xB, JDWP_STEP_OVER, sz4);
        CHECK(s.size() == 1 + 1 + 4 + 1 + 4 + 4 + 4 + 1 + 4);
        CHECK(s[0] == JDWP_EK_SINGLE_STEP && s[6] == 10);

        auto c = JdwpBuildClearRequest(JDWP_EK_BREAKPOINT, 31);
        CHECK(c.size() == 5 && c[0] == JDWP_EK_BREAKPOINT && c[4] == 31);
    }

    CHECK(JdwpSignatureToClassName("Lcom/foo/Bar;") == "com/foo/Bar");
    CHECK(JdwpSignatureToClassName("[I") == "[I");
    CHECK(std::strlen(JdwpHandshake()) == kJdwpHandshakeLen);

    if (g_fail == 0) std::printf("ALL JDWP TESTS PASSED\n");
    else             std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
