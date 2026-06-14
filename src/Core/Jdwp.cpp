#include "Jdwp.h"

#include <cstring>

namespace ds {

// ---- packet framing -------------------------------------------------------------

std::vector<uint8_t> JdwpEncodeCommand(uint32_t id, uint8_t cmdSet, uint8_t cmd,
                                       const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> out;
    out.reserve(kJdwpHeaderLen + payload.size());
    const uint32_t len = (uint32_t)(kJdwpHeaderLen + payload.size());
    for (int s = 24; s >= 0; s -= 8) out.push_back((uint8_t)(len >> s));
    for (int s = 24; s >= 0; s -= 8) out.push_back((uint8_t)(id >> s));
    out.push_back(0);                  // flags: command
    out.push_back(cmdSet);
    out.push_back(cmd);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

bool JdwpDecodePacket(const uint8_t* data, size_t n, JdwpPacket& out, size_t& consumed) {
    consumed = 0;
    if (!data || n < kJdwpHeaderLen) return false;
    uint32_t len = 0;
    for (int i = 0; i < 4; ++i) len = (len << 8) | data[i];
    if (len < kJdwpHeaderLen || len > (512u << 20)) { consumed = SIZE_MAX; return false; }
    if (n < len) return false;        // need more bytes

    out = JdwpPacket{};
    for (int i = 4; i < 8; ++i) out.id = (out.id << 8) | data[i];
    out.flags = data[8];
    if (out.isReply()) out.errorCode = (uint16_t)((data[9] << 8) | data[10]);
    else { out.cmdSet = data[9]; out.cmd = data[10]; }
    out.payload.assign(data + kJdwpHeaderLen, data + len);
    consumed = len;
    return true;
}

// ---- reply parsers -----------------------------------------------------------------

bool JdwpParseVersion(const std::vector<uint8_t>& payload, JdwpVersionInfo& out) {
    JdwpReader r(payload.data(), payload.size());
    out.description = r.str();
    out.jdwpMajor   = (int32_t)r.u4();
    out.jdwpMinor   = (int32_t)r.u4();
    out.vmVersion   = r.str();
    out.vmName      = r.str();
    return !r.fail();
}

bool JdwpParseIdSizes(const std::vector<uint8_t>& payload, JdwpIdSizes& out) {
    JdwpReader r(payload.data(), payload.size());
    out.fieldID         = (int)r.u4();
    out.methodID        = (int)r.u4();
    out.objectID        = (int)r.u4();
    out.referenceTypeID = (int)r.u4();
    out.frameID         = (int)r.u4();
    if (r.fail()) return false;
    auto sane = [](int v) { return v >= 1 && v <= 8; };
    return sane(out.fieldID) && sane(out.methodID) && sane(out.objectID) &&
           sane(out.referenceTypeID) && sane(out.frameID);
}

bool JdwpParseAllClasses(const std::vector<uint8_t>& payload, const JdwpIdSizes& sz,
                         std::vector<JdwpClassInfo>& out, size_t maxClasses) {
    out.clear();
    JdwpReader r(payload.data(), payload.size());
    const uint32_t count = r.u4();
    for (uint32_t i = 0; i < count && !r.fail() && out.size() < maxClasses; ++i) {
        JdwpClassInfo c;
        c.refTypeTag = r.u1();
        c.typeID     = r.id(sz.referenceTypeID);
        c.signature  = r.str();
        c.status     = (int32_t)r.u4();
        if (r.fail()) break;
        out.push_back(std::move(c));
    }
    return !r.fail();
}

bool JdwpParseAllThreads(const std::vector<uint8_t>& payload, const JdwpIdSizes& sz,
                         std::vector<uint64_t>& out, size_t maxThreads) {
    out.clear();
    JdwpReader r(payload.data(), payload.size());
    const uint32_t count = r.u4();
    for (uint32_t i = 0; i < count && !r.fail() && out.size() < maxThreads; ++i) {
        uint64_t t = r.id(sz.objectID);
        if (r.fail()) break;
        out.push_back(t);
    }
    return !r.fail();
}

bool JdwpParseMethods(const std::vector<uint8_t>& payload, const JdwpIdSizes& sz,
                      std::vector<JdwpMethodInfo>& out, size_t maxMethods) {
    out.clear();
    JdwpReader r(payload.data(), payload.size());
    const uint32_t count = r.u4();
    for (uint32_t i = 0; i < count && !r.fail() && out.size() < maxMethods; ++i) {
        JdwpMethodInfo m;
        m.methodID  = r.id(sz.methodID);
        m.name      = r.str();
        m.signature = r.str();
        m.modBits   = r.u4();
        if (r.fail()) break;
        out.push_back(std::move(m));
    }
    return !r.fail();
}

bool JdwpParseFrames(const std::vector<uint8_t>& payload, const JdwpIdSizes& sz,
                     std::vector<JdwpFrameInfo>& out, size_t maxFrames) {
    out.clear();
    JdwpReader r(payload.data(), payload.size());
    const uint32_t count = r.u4();
    for (uint32_t i = 0; i < count && !r.fail() && out.size() < maxFrames; ++i) {
        JdwpFrameInfo f;
        f.frameID = r.id(sz.frameID);
        f.loc     = r.location(sz);
        if (r.fail()) break;
        out.push_back(f);
    }
    return !r.fail();
}

bool JdwpParseThreadStatus(const std::vector<uint8_t>& payload,
                           int32_t& threadStatus, int32_t& suspendStatus) {
    JdwpReader r(payload.data(), payload.size());
    threadStatus  = (int32_t)r.u4();
    suspendStatus = (int32_t)r.u4();
    return !r.fail();
}

bool JdwpParseBytecodes(const std::vector<uint8_t>& payload, std::vector<uint8_t>& out) {
    out.clear();
    JdwpReader r(payload.data(), payload.size());
    const uint32_t count = r.u4();
    if (r.fail() || (size_t)count > payload.size() - 4) return false;   // fail() guards size >= 4
    out.assign(payload.begin() + 4, payload.begin() + 4 + count);
    return true;
}

bool JdwpParseConstantPool(const std::vector<uint8_t>& payload,
                           uint32_t& cpCount, std::vector<uint8_t>& cpBytes) {
    cpBytes.clear();
    JdwpReader r(payload.data(), payload.size());
    cpCount = r.u4();
    const uint32_t byteCount = r.u4();
    if (r.fail() || (size_t)byteCount > payload.size() - 8) return false;
    cpBytes.assign(payload.begin() + 8, payload.begin() + 8 + byteCount);
    return true;
}

bool JdwpParseLineTable(const std::vector<uint8_t>& payload,
                        std::vector<std::pair<uint64_t, uint32_t>>& out) {
    out.clear();
    JdwpReader r(payload.data(), payload.size());
    r.u8();                            // start
    r.u8();                            // end
    const uint32_t lines = r.u4();
    for (uint32_t i = 0; i < lines && !r.fail() && out.size() < 65536; ++i) {
        uint64_t ci = r.u8();
        uint32_t ln = r.u4();
        if (r.fail()) break;
        out.emplace_back(ci, ln);
    }
    return !r.fail();
}

// ---- events --------------------------------------------------------------------------

bool JdwpParseEventComposite(const std::vector<uint8_t>& payload, const JdwpIdSizes& sz,
                             JdwpEventSet& out) {
    out = JdwpEventSet{};
    JdwpReader r(payload.data(), payload.size());
    out.suspendPolicy = r.u1();
    const uint32_t count = r.u4();
    for (uint32_t i = 0; i < count && !r.fail(); ++i) {
        JdwpEvent e;
        e.eventKind = r.u1();
        e.requestID = (int32_t)r.u4();
        switch (e.eventKind) {
            case JDWP_EK_VM_START:
            case JDWP_EK_THREAD_START:
            case JDWP_EK_THREAD_DEATH:
                e.threadID = r.id(sz.objectID);
                break;
            case JDWP_EK_BREAKPOINT:
            case JDWP_EK_SINGLE_STEP:
                e.threadID = r.id(sz.objectID);
                e.loc      = r.location(sz);
                break;
            case JDWP_EK_CLASS_PREPARE:
                e.threadID  = r.id(sz.objectID);
                e.loc.typeTag = r.u1();                  // refTypeTag
                e.typeID    = r.id(sz.referenceTypeID);
                e.signature = r.str();
                r.u4();                                  // status
                break;
            case JDWP_EK_VM_DEATH:
                break;                                   // no body
            default:
                // Unknown layout: keep what we decoded so far and stop.
                out.events.push_back(e);
                return true;
        }
        if (r.fail()) break;
        out.events.push_back(std::move(e));
    }
    return !r.fail();
}

// ---- request builders -------------------------------------------------------------------

std::vector<uint8_t> JdwpBuildBreakpointRequest(const JdwpLocation& loc, const JdwpIdSizes& sz) {
    JdwpWriter w;
    w.u1(JDWP_EK_BREAKPOINT);
    w.u1(JDWP_SP_ALL);
    w.u4(1);                           // one modifier
    w.u1(7);                           // LocationOnly
    w.location(loc, sz);
    return w.bytes();
}

std::vector<uint8_t> JdwpBuildStepRequest(uint64_t threadID, uint32_t depth,
                                          const JdwpIdSizes& sz, uint32_t stepSize) {
    JdwpWriter w;
    w.u1(JDWP_EK_SINGLE_STEP);
    w.u1(JDWP_SP_ALL);
    w.u4(2);                           // two modifiers
    w.u1(10);                          // Step
    w.id(threadID, sz.objectID);
    w.u4(stepSize);
    w.u4(depth);
    w.u1(1);                           // Count
    w.u4(1);                           // fire once, then auto-expire
    return w.bytes();
}

std::vector<uint8_t> JdwpBuildClearRequest(uint8_t eventKind, int32_t requestID) {
    JdwpWriter w;
    w.u1(eventKind);
    w.u4((uint32_t)requestID);
    return w.bytes();
}

std::string JdwpSignatureToClassName(const std::string& sig) {
    if (sig.size() >= 2 && sig.front() == 'L' && sig.back() == ';')
        return sig.substr(1, sig.size() - 2);
    return sig;
}

} // namespace ds
