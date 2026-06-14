#pragma once
//
// Jdwp.h
// JDWP (Java Debug Wire Protocol) wire-format core: packet framing, the
// big-endian payload reader/writer (ID widths come from VirtualMachine::
// IDSizes, so nothing here hardcodes 8-byte IDs), command constants, request
// builders, and reply/event parsers for the subset DisasmStudio's JVM
// debugger uses. PURE LOGIC — no sockets, no Windows headers — so the whole
// layer is exercised off-target by tests/jdwp_test.cpp over byte buffers.
// The socket lives in JdwpClient, which is a thin pump over this module.
//
// Protocol shape (JDWP spec):
//   handshake: both sides send the 14 ASCII bytes "JDWP-Handshake".
//   packet:    u4 length (incl. 11-byte header), u4 id, u1 flags,
//              command: u1 cmdSet, u1 cmd  |  reply (flags&0x80): u2 errorCode.
//
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

// ---- constants ----------------------------------------------------------------

inline const char* JdwpHandshake() { return "JDWP-Handshake"; }   // 14 bytes, no NUL
constexpr size_t   kJdwpHandshakeLen = 14;
constexpr uint8_t  kJdwpReplyFlag    = 0x80;
constexpr size_t   kJdwpHeaderLen    = 11;

// Command sets / commands (only what the client uses).
enum : uint8_t {
    JDWP_SET_VirtualMachine  = 1,
    JDWP_SET_ReferenceType   = 2,
    JDWP_SET_Method          = 6,
    JDWP_SET_ThreadReference = 11,
    JDWP_SET_EventRequest    = 15,
    JDWP_SET_Event           = 64,
};
enum : uint8_t {                       // VirtualMachine
    JDWP_VM_Version = 1, JDWP_VM_ClassesBySignature = 2, JDWP_VM_AllClasses = 3,
    JDWP_VM_AllThreads = 4, JDWP_VM_Dispose = 6, JDWP_VM_IDSizes = 7,
    JDWP_VM_Suspend = 8, JDWP_VM_Resume = 9,
};
enum : uint8_t {                       // ReferenceType
    JDWP_RT_Signature = 1, JDWP_RT_Methods = 5, JDWP_RT_SourceFile = 7,
    JDWP_RT_ConstantPool = 18,
};
enum : uint8_t {                       // Method
    JDWP_M_LineTable = 1, JDWP_M_Bytecodes = 3,
};
enum : uint8_t {                       // ThreadReference
    JDWP_TR_Name = 1, JDWP_TR_Suspend = 2, JDWP_TR_Resume = 3, JDWP_TR_Status = 4,
    JDWP_TR_Frames = 6,
};
enum : uint8_t {                       // EventRequest
    JDWP_ER_Set = 1, JDWP_ER_Clear = 2,
};
enum : uint8_t {                       // Event
    JDWP_E_Composite = 100,
};

// Event kinds.
enum : uint8_t {
    JDWP_EK_SINGLE_STEP = 1, JDWP_EK_BREAKPOINT = 2, JDWP_EK_EXCEPTION = 4,
    JDWP_EK_THREAD_START = 6, JDWP_EK_THREAD_DEATH = 7, JDWP_EK_CLASS_PREPARE = 8,
    JDWP_EK_VM_START = 90, JDWP_EK_VM_DEATH = 99,
};
// Suspend policies.
enum : uint8_t { JDWP_SP_NONE = 0, JDWP_SP_EVENT_THREAD = 1, JDWP_SP_ALL = 2 };
// Step depths / sizes (EventRequest Step modifier).
enum : uint32_t { JDWP_STEP_INTO = 0, JDWP_STEP_OVER = 1, JDWP_STEP_OUT = 2 };
enum : uint32_t { JDWP_STEPSIZE_MIN = 0, JDWP_STEPSIZE_LINE = 1 };
// Thread statuses (ThreadReference::Status threadStatus).
enum : int32_t {
    JDWP_TS_ZOMBIE = 0, JDWP_TS_RUNNING = 1, JDWP_TS_SLEEPING = 2,
    JDWP_TS_MONITOR = 3, JDWP_TS_WAIT = 4,
};

// ID widths negotiated via VirtualMachine::IDSizes. Defaults match HotSpot (8).
struct JdwpIdSizes {
    int fieldID = 8, methodID = 8, objectID = 8, referenceTypeID = 8, frameID = 8;
};

// An executable code location: class + method + bytecode index.
struct JdwpLocation {
    uint8_t  typeTag = 1;          // 1 = CLASS, 2 = INTERFACE, 3 = ARRAY
    uint64_t classID = 0;
    uint64_t methodID = 0;
    uint64_t index = 0;            // bytecode index (bci)
};

// ---- payload writer / reader ----------------------------------------------------

class JdwpWriter {
public:
    void u1(uint8_t v)  { buf_.push_back(v); }
    void u2(uint16_t v) { buf_.push_back((uint8_t)(v >> 8)); buf_.push_back((uint8_t)v); }
    void u4(uint32_t v) {
        for (int s = 24; s >= 0; s -= 8) buf_.push_back((uint8_t)(v >> s));
    }
    void u8(uint64_t v) {
        for (int s = 56; s >= 0; s -= 8) buf_.push_back((uint8_t)(v >> s));
    }
    void id(uint64_t v, int size) {
        for (int s = (size - 1) * 8; s >= 0; s -= 8) buf_.push_back((uint8_t)(v >> s));
    }
    void str(const std::string& s) {
        u4((uint32_t)s.size());
        buf_.insert(buf_.end(), s.begin(), s.end());
    }
    void location(const JdwpLocation& l, const JdwpIdSizes& sz) {
        u1(l.typeTag);
        id(l.classID, sz.referenceTypeID);
        id(l.methodID, sz.methodID);
        u8(l.index);
    }
    const std::vector<uint8_t>& bytes() const { return buf_; }
private:
    std::vector<uint8_t> buf_;
};

class JdwpReader {
public:
    JdwpReader(const uint8_t* p, size_t n) : p_(p), n_(n) {}
    bool fail() const { return fail_; }
    bool atEnd() const { return off_ >= n_; }

    uint8_t u1() { if (!need(1)) return 0; return p_[off_++]; }
    uint16_t u2() { if (!need(2)) return 0; uint16_t v = ((uint16_t)p_[off_] << 8) | p_[off_ + 1]; off_ += 2; return v; }
    uint32_t u4() {
        if (!need(4)) return 0;
        uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v = (v << 8) | p_[off_ + i];
        off_ += 4; return v;
    }
    uint64_t u8() {
        if (!need(8)) return 0;
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | p_[off_ + i];
        off_ += 8; return v;
    }
    uint64_t id(int size) {
        if (size < 1 || size > 8 || !need((size_t)size)) { fail_ = true; return 0; }
        uint64_t v = 0;
        for (int i = 0; i < size; ++i) v = (v << 8) | p_[off_ + i];
        off_ += (size_t)size; return v;
    }
    std::string str() {
        uint32_t len = u4();
        if (fail_ || !need(len)) { fail_ = true; return std::string(); }
        std::string s((const char*)p_ + off_, len);
        off_ += len;
        return s;
    }
    JdwpLocation location(const JdwpIdSizes& sz) {
        JdwpLocation l;
        l.typeTag  = u1();
        l.classID  = id(sz.referenceTypeID);
        l.methodID = id(sz.methodID);
        l.index    = u8();
        return l;
    }
    void skip(size_t k) { if (need(k)) off_ += k; }
private:
    bool need(size_t k) {
        if (fail_ || off_ > n_ || n_ - off_ < k) { fail_ = true; return false; }
        return true;
    }
    const uint8_t* p_;
    size_t n_, off_ = 0;
    bool fail_ = false;
};

// ---- packet framing --------------------------------------------------------------

struct JdwpPacket {
    uint32_t id = 0;
    uint8_t  flags = 0;
    uint8_t  cmdSet = 0, cmd = 0;      // command packets
    uint16_t errorCode = 0;            // reply packets (flags & kJdwpReplyFlag)
    std::vector<uint8_t> payload;
    bool isReply() const { return (flags & kJdwpReplyFlag) != 0; }
};

// Frame a command packet ready to send.
std::vector<uint8_t> JdwpEncodeCommand(uint32_t id, uint8_t cmdSet, uint8_t cmd,
                                       const std::vector<uint8_t>& payload = {});

// Try to decode one complete packet from the front of [data, data+n).
// Returns true and sets `consumed` when a full packet was present; returns
// false with consumed == 0 when more bytes are needed. A malformed length
// (< header size or > 512 MB) returns false with consumed == SIZE_MAX so the
// caller can drop the connection instead of waiting forever.
bool JdwpDecodePacket(const uint8_t* data, size_t n, JdwpPacket& out, size_t& consumed);

// ---- reply parsers -----------------------------------------------------------------

struct JdwpVersionInfo {
    std::string description, vmVersion, vmName;
    int32_t jdwpMajor = 0, jdwpMinor = 0;
};
bool JdwpParseVersion(const std::vector<uint8_t>& payload, JdwpVersionInfo& out);

bool JdwpParseIdSizes(const std::vector<uint8_t>& payload, JdwpIdSizes& out);

struct JdwpClassInfo {
    uint8_t     refTypeTag = 0;        // 1 class, 2 interface, 3 array
    uint64_t    typeID = 0;
    std::string signature;             // "Lcom/foo/Bar;"
    int32_t     status = 0;
};
bool JdwpParseAllClasses(const std::vector<uint8_t>& payload, const JdwpIdSizes& sz,
                         std::vector<JdwpClassInfo>& out, size_t maxClasses = 100000);

bool JdwpParseAllThreads(const std::vector<uint8_t>& payload, const JdwpIdSizes& sz,
                         std::vector<uint64_t>& out, size_t maxThreads = 100000);

struct JdwpMethodInfo {
    uint64_t    methodID = 0;
    std::string name, signature;
    uint32_t    modBits = 0;
};
bool JdwpParseMethods(const std::vector<uint8_t>& payload, const JdwpIdSizes& sz,
                      std::vector<JdwpMethodInfo>& out, size_t maxMethods = 65536);

// ThreadReference::Frames reply: count x { frameID, location }.
struct JdwpFrameInfo {
    uint64_t     frameID = 0;
    JdwpLocation loc;
};
bool JdwpParseFrames(const std::vector<uint8_t>& payload, const JdwpIdSizes& sz,
                     std::vector<JdwpFrameInfo>& out, size_t maxFrames = 4096);

// ThreadReference::Status reply.
bool JdwpParseThreadStatus(const std::vector<uint8_t>& payload,
                           int32_t& threadStatus, int32_t& suspendStatus);

// Method::Bytecodes reply: u4 count + raw bytecode.
bool JdwpParseBytecodes(const std::vector<uint8_t>& payload, std::vector<uint8_t>& out);

// ReferenceType::ConstantPool reply: u4 count, u4 byteCount, raw cp bytes
// (class-file constant_pool format; feed to ParseConstantPoolOnly).
bool JdwpParseConstantPool(const std::vector<uint8_t>& payload,
                           uint32_t& cpCount, std::vector<uint8_t>& cpBytes);

// Method::LineTable reply: u8 start, u8 end, u4 lines x { u8 codeIndex, u4 line }.
bool JdwpParseLineTable(const std::vector<uint8_t>& payload,
                        std::vector<std::pair<uint64_t, uint32_t>>& out);

// ---- events --------------------------------------------------------------------------

struct JdwpEvent {
    uint8_t  eventKind = 0;
    int32_t  requestID = 0;
    uint64_t threadID = 0;             // VM_START/THREAD_*/BREAKPOINT/STEP/CLASS_PREPARE
    JdwpLocation loc;                  // BREAKPOINT / SINGLE_STEP / EXCEPTION
    uint64_t    typeID = 0;            // CLASS_PREPARE
    std::string signature;             // CLASS_PREPARE
};
struct JdwpEventSet {
    uint8_t suspendPolicy = JDWP_SP_NONE;
    std::vector<JdwpEvent> events;
};
// Parses an Event::Composite payload. Kinds beyond the known set stop the
// parse (their layout is unknown) but events decoded up to that point are
// kept, so an unexpected kind degrades instead of corrupting the stream.
bool JdwpParseEventComposite(const std::vector<uint8_t>& payload, const JdwpIdSizes& sz,
                             JdwpEventSet& out);

// ---- request builders -------------------------------------------------------------------

// EventRequest::Set BREAKPOINT with a LocationOnly modifier. Suspends all.
std::vector<uint8_t> JdwpBuildBreakpointRequest(const JdwpLocation& loc, const JdwpIdSizes& sz);
// EventRequest::Set SINGLE_STEP (depth = JDWP_STEP_*) with a count-1 modifier
// so the request auto-fires once. Suspends all.
std::vector<uint8_t> JdwpBuildStepRequest(uint64_t threadID, uint32_t depth,
                                          const JdwpIdSizes& sz,
                                          uint32_t stepSize = JDWP_STEPSIZE_MIN);
// EventRequest::Clear payload.
std::vector<uint8_t> JdwpBuildClearRequest(uint8_t eventKind, int32_t requestID);

// "Lcom/foo/Bar;" -> "com/foo/Bar" (best-effort; arrays/primitives unchanged).
std::string JdwpSignatureToClassName(const std::string& sig);

} // namespace ds
