//
// jdwp_client_mock_test.cpp
// Loopback transport tests for JdwpClient's single-owner command queue. The
// mock speaks the small bootstrap/RPC subset needed by the client and
// deliberately withholds one reply to exercise detach cancellation/teardown.
//
#include "Core/JdwpClient.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

using namespace ds;
using namespace std::chrono_literals;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

namespace {

static void appendU2(std::vector<uint8_t>& out, uint16_t value) {
    out.push_back((uint8_t)(value >> 8));
    out.push_back((uint8_t)value);
}

static void appendU4(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back((uint8_t)(value >> 24));
    out.push_back((uint8_t)(value >> 16));
    out.push_back((uint8_t)(value >> 8));
    out.push_back((uint8_t)value);
}

static std::vector<uint8_t> makeReply(uint32_t id, const std::vector<uint8_t>& payload,
                                      uint16_t error = 0) {
    std::vector<uint8_t> out;
    appendU4(out, (uint32_t)(kJdwpHeaderLen + payload.size()));
    appendU4(out, id);
    out.push_back(kJdwpReplyFlag);
    appendU2(out, error);
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

class MockVm {
public:
    MockVm() {
        WSADATA data{};
        ok_ = ::WSAStartup(MAKEWORD(2, 2), &data) == 0;
        if (!ok_) return;
        listen_ = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_ == INVALID_SOCKET) { ok_ = false; return; }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        address.sin_port = 0;
        if (::bind(listen_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(listen_, 1) != 0) {
            ok_ = false;
            ::closesocket(listen_);
            listen_ = INVALID_SOCKET;
            return;
        }
        int addressSize = sizeof(address);
        if (::getsockname(listen_, reinterpret_cast<sockaddr*>(&address), &addressSize) != 0) {
            ok_ = false;
            return;
        }
        port_ = ntohs(address.sin_port);
        worker_ = std::thread(&MockVm::run, this);
    }

    ~MockVm() {
        stop_.store(true);
        SOCKET client = client_.load();
        if (client != INVALID_SOCKET) ::shutdown(client, SD_BOTH);
        if (listen_ != INVALID_SOCKET) {
            ::shutdown(listen_, SD_BOTH);
            ::closesocket(listen_);
            listen_ = INVALID_SOCKET;
        }
        if (worker_.joinable()) worker_.join();
        ::WSACleanup();
    }

    bool ok() const { return ok_; }
    uint16_t port() const { return port_; }

    bool waitForWithheldRequest(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lk(signalMtx_);
        return signalCv_.wait_for(lk, timeout, [&] { return withheldSeen_; });
    }

    bool sawDispose() const { return disposeSeen_.load(); }

private:
    bool recvExact(SOCKET socket, uint8_t* out, size_t size) {
        while (size && !stop_.load()) {
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(socket, &readSet);
            timeval timeout{0, 50 * 1000};
            const int selected = ::select(0, &readSet, nullptr, nullptr, &timeout);
            if (selected < 0) return false;
            if (selected == 0) continue;
            const int got = ::recv(socket, reinterpret_cast<char*>(out), (int)size, 0);
            if (got <= 0) return false;
            out += got;
            size -= (size_t)got;
        }
        return size == 0;
    }

    bool sendAll(SOCKET socket, const uint8_t* data, size_t size) {
        while (size && !stop_.load()) {
            const int sent = ::send(socket, reinterpret_cast<const char*>(data), (int)size, 0);
            if (sent <= 0) return false;
            data += sent;
            size -= (size_t)sent;
        }
        return size == 0;
    }

    bool recvPacket(SOCKET socket, JdwpPacket& packet) {
        uint8_t lengthBytes[4];
        if (!recvExact(socket, lengthBytes, sizeof(lengthBytes))) return false;
        const uint32_t length = ((uint32_t)lengthBytes[0] << 24) |
                                ((uint32_t)lengthBytes[1] << 16) |
                                ((uint32_t)lengthBytes[2] << 8) | lengthBytes[3];
        if (length < kJdwpHeaderLen || length > 1024 * 1024) return false;
        std::vector<uint8_t> bytes(length);
        std::memcpy(bytes.data(), lengthBytes, sizeof(lengthBytes));
        if (!recvExact(socket, bytes.data() + 4, bytes.size() - 4)) return false;
        size_t consumed = 0;
        return JdwpDecodePacket(bytes.data(), bytes.size(), packet, consumed) &&
               consumed == bytes.size();
    }

    std::vector<uint8_t> payloadFor(const JdwpPacket& packet) {
        JdwpWriter writer;
        if (packet.cmdSet == JDWP_SET_VirtualMachine && packet.cmd == JDWP_VM_IDSizes) {
            for (int i = 0; i < 5; ++i) writer.u4(8);
        } else if (packet.cmdSet == JDWP_SET_VirtualMachine && packet.cmd == JDWP_VM_Version) {
            writer.str("loopback mock");
            writer.u4(1);
            writer.u4(8);
            writer.str("17-test");
            writer.str("MockVM");
        } else if (packet.cmdSet == JDWP_SET_VirtualMachine && packet.cmd == JDWP_VM_AllClasses) {
            writer.u4(1);
            writer.u1(1);
            writer.id(0x1001, 8);
            writer.str("Lmock/Main;");
            writer.u4(7);
        } else if (packet.cmdSet == JDWP_SET_VirtualMachine && packet.cmd == JDWP_VM_AllThreads) {
            writer.u4(0);
        } else if (packet.cmdSet == JDWP_SET_ReferenceType && packet.cmd == JDWP_RT_Methods) {
            writer.u4(1);
            writer.id(0x21, 8);
            writer.str("main");
            writer.str("()V");
            writer.u4(9);
        } else if (packet.cmdSet == JDWP_SET_EventRequest && packet.cmd == JDWP_ER_Set) {
            writer.u4(31);
        } else if (packet.cmdSet == JDWP_SET_ThreadReference && packet.cmd == JDWP_TR_Frames) {
            writer.u4(1);
            writer.id(0x77, 8);
            writer.u1(1);
            writer.id(0x1001, 8);
            writer.id(0x21, 8);
            writer.u8(5);
        }
        return writer.bytes();
    }

    std::vector<uint8_t> breakpointEvent() {
        JdwpWriter writer;
        writer.u1(JDWP_SP_ALL);
        writer.u4(1);
        writer.u1(JDWP_EK_BREAKPOINT);
        writer.u4(31);
        writer.id(0xB, 8);
        writer.u1(1);
        writer.id(0x1001, 8);
        writer.id(0x21, 8);
        writer.u8(5);
        return JdwpEncodeCommand(0x9000, JDWP_SET_Event, JDWP_E_Composite, writer.bytes());
    }

    void run() {
        sockaddr_storage peer{};
        int peerSize = sizeof(peer);
        const SOCKET socket = ::accept(listen_, reinterpret_cast<sockaddr*>(&peer), &peerSize);
        if (socket == INVALID_SOCKET) return;
        client_.store(socket);

        uint8_t handshake[kJdwpHandshakeLen];
        if (!recvExact(socket, handshake, sizeof(handshake)) ||
            std::memcmp(handshake, JdwpHandshake(), sizeof(handshake)) != 0) {
            ::closesocket(socket);
            client_.store(INVALID_SOCKET);
            return;
        }
        // Split the handshake to exercise incremental receive on the client.
        sendAll(socket, reinterpret_cast<const uint8_t*>(JdwpHandshake()), 5);
        sendAll(socket, reinterpret_cast<const uint8_t*>(JdwpHandshake()) + 5,
                kJdwpHandshakeLen - 5);

        while (!stop_.load()) {
            JdwpPacket packet;
            if (!recvPacket(socket, packet)) break;
            if (packet.cmdSet == JDWP_SET_VirtualMachine && packet.cmd == JDWP_VM_Dispose) {
                disposeSeen_.store(true);
                break;                                      // Dispose has no needed reply here
            }
            if (packet.cmdSet == JDWP_SET_Method && packet.cmd == JDWP_M_Bytecodes) {
                {
                    std::lock_guard<std::mutex> lk(signalMtx_);
                    withheldSeen_ = true;
                }
                signalCv_.notify_all();
                continue;                                   // deliberately park this RPC
            }
            const auto payload = payloadFor(packet);
            const auto reply = makeReply(packet.id, payload);
            if (!sendAll(socket, reply.data(), reply.size())) break;
            if (packet.cmdSet == JDWP_SET_EventRequest && packet.cmd == JDWP_ER_Set &&
                !packet.payload.empty() && packet.payload[0] == JDWP_EK_BREAKPOINT) {
                // Let setBreakpoint publish its row, then deliver a stop that
                // forces the connection thread to issue nested Frames and
                // AllThreads RPCs while it handles the event.
                std::this_thread::sleep_for(20ms);
                const auto event = breakpointEvent();
                if (!sendAll(socket, event.data(), event.size())) break;
            }
        }
        ::shutdown(socket, SD_BOTH);
        ::closesocket(socket);
        client_.store(INVALID_SOCKET);
    }

    bool ok_ = false;
    SOCKET listen_ = INVALID_SOCKET;
    std::atomic<SOCKET> client_{INVALID_SOCKET};
    uint16_t port_ = 0;
    std::atomic<bool> stop_{false};
    std::atomic<bool> disposeSeen_{false};
    std::thread worker_;
    std::mutex signalMtx_;
    std::condition_variable signalCv_;
    bool withheldSeen_ = false;
};

} // namespace

int main() {
    MockVm vm;
    CHECK(vm.ok());
    if (!vm.ok()) return 1;

    JdwpClient client;
    std::string error;
    CHECK(client.attach("127.0.0.1", vm.port(), error));
    if (!error.empty()) std::printf("attach error: %s\n", error.c_str());

    JdwpSnapshot snapshot = client.snapshot();
    CHECK(snapshot.state == JdwpState::Running);
    CHECK(snapshot.vmName == "MockVM");
    CHECK(snapshot.vmVersion == "17-test");
    CHECK(snapshot.classes && snapshot.classes->size() == 1);
    if (snapshot.classes && !snapshot.classes->empty())
        CHECK((*snapshot.classes)[0].name == "mock/Main");

    std::vector<JdwpMethodRow> methods;
    CHECK(client.methodsOf(0x1001, methods));
    CHECK(methods.size() == 1 && methods[0].name == "main");

    client.suspendAll();
    CHECK(client.snapshot().state == JdwpState::Suspended);
    client.resumeAll();
    CHECK(client.snapshot().state == JdwpState::Running);

    JdwpLocation location{1, 0x1001, 0x21, 5};
    CHECK(client.setBreakpoint(location, "mock/Main.main bci=5", error));
    bool handledStop = false;
    for (int i = 0; i < 200 && !handledStop; ++i) {
        const JdwpSnapshot current = client.snapshot();
        for (const auto& event : current.events)
            if (event.find("Breakpoint hit at Main.main bci=5") != std::string::npos)
                handledStop = true;
        if (!handledStop) std::this_thread::sleep_for(10ms);
    }
    snapshot = client.snapshot();
    CHECK(handledStop);                         // nested event RPCs did not self-deadlock
    CHECK(snapshot.state == JdwpState::Suspended);
    CHECK(snapshot.stopThread == 0xB);
    CHECK(snapshot.frames.size() == 1 && snapshot.frames[0].frameID == 0x77);
    CHECK(snapshot.breakpoints.size() == 1 && snapshot.breakpoints[0].hits == 1);
    client.resumeAll();
    CHECK(client.snapshot().state == JdwpState::Running);

    std::atomic<bool> bytecodesReturned{false};
    std::atomic<bool> bytecodesOk{true};
    std::thread caller([&] {
        std::vector<uint8_t> bytes;
        bytecodesOk.store(client.bytecodesOf(0x1001, 0x21, bytes));
        bytecodesReturned.store(true);
    });
    CHECK(vm.waitForWithheldRequest(2s));

    const auto detachStart = std::chrono::steady_clock::now();
    client.detach();
    const auto detachElapsed = std::chrono::steady_clock::now() - detachStart;
    caller.join();
    CHECK(detachElapsed < 1s);
    CHECK(bytecodesReturned.load());
    CHECK(!bytecodesOk.load());
    CHECK(client.snapshot().state == JdwpState::Detached);

    // The owner sends Dispose before closing when the peer remains responsive.
    for (int i = 0; i < 20 && !vm.sawDispose(); ++i) std::this_thread::sleep_for(10ms);
    CHECK(vm.sawDispose());

    // A failure anywhere below the connection-thread entry point must not
    // terminate the process or strand either the in-flight RPC or commands
    // queued behind it. The test hook throws from pumpSocket, i.e. while an
    // active Method::Bytecodes command owns the reader.
    {
        MockVm failureVm;
        CHECK(failureVm.ok());
        if (failureVm.ok()) {
            JdwpClient failingClient;
            std::string failureAttachError;
            CHECK(failingClient.attach("127.0.0.1", failureVm.port(), failureAttachError));

            std::atomic<bool> activeReturned{false};
            std::atomic<bool> activeOk{true};
            std::thread activeCaller([&] {
                std::vector<uint8_t> bytes;
                activeOk.store(failingClient.bytecodesOf(0x1001, 0x21, bytes));
                activeReturned.store(true);
            });
            CHECK(failureVm.waitForWithheldRequest(2s));

            std::atomic<bool> queuedReturned{false};
            std::atomic<bool> queuedOk{true};
            std::thread queuedCaller([&] {
                std::vector<JdwpMethodRow> queuedMethods;
                queuedOk.store(failingClient.methodsOf(0x1001, queuedMethods));
                queuedReturned.store(true);
            });
            std::this_thread::sleep_for(20ms); // let methodsOf enter the command queue

            const auto failureStart = std::chrono::steady_clock::now();
            failingClient.injectReaderFailureForTest();
            activeCaller.join();
            queuedCaller.join();
            const auto failureElapsed = std::chrono::steady_clock::now() - failureStart;

            CHECK(failureElapsed < 1s);
            CHECK(activeReturned.load() && !activeOk.load());
            CHECK(queuedReturned.load() && !queuedOk.load());
            const JdwpSnapshot failed = failingClient.snapshot();
            CHECK(failed.state == JdwpState::Dead);
            CHECK(failed.lastEvent.find("JDWP worker failed: injected reader failure") !=
                  std::string::npos);
            bool loggedFailure = false;
            for (const auto& event : failed.events)
                if (event.find("JDWP worker failed: injected reader failure") != std::string::npos)
                    loggedFailure = true;
            CHECK(loggedFailure);

            // No follow-up request waits for its normal RPC deadline once the
            // worker has published its terminal state.
            const auto rejectedStart = std::chrono::steady_clock::now();
            std::vector<JdwpMethodRow> rejected;
            CHECK(!failingClient.methodsOf(0x1001, rejected));
            CHECK(std::chrono::steady_clock::now() - rejectedStart < 200ms);

            failingClient.detach();
            const JdwpSnapshot detachedAfterFailure = failingClient.snapshot();
            CHECK(detachedAfterFailure.state == JdwpState::Detached);
            CHECK(detachedAfterFailure.lastEvent.find("JDWP worker failed") != std::string::npos);

            // The same client object can establish a clean new session; no
            // socket, nested-pump, command, or failure state leaks across the
            // worker boundary.
            MockVm recoveryVm;
            CHECK(recoveryVm.ok());
            if (recoveryVm.ok()) {
                std::string recoveryError;
                CHECK(failingClient.attach("127.0.0.1", recoveryVm.port(), recoveryError));
                const JdwpSnapshot recovered = failingClient.snapshot();
                CHECK(recovered.state == JdwpState::Running);
                CHECK(recovered.lastEvent.find("attached:") == 0);
                failingClient.detach();
            }
        }
    }

    if (g_fail == 0) std::printf("ALL JDWP CLIENT MOCK TESTS PASSED\n");
    else std::printf("%d CHECK(S) FAILED\n", g_fail);
    return g_fail ? 1 : 0;
}
