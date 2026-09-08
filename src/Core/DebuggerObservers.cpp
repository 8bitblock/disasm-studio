#include "Debugger.h"
#include "DebuggerInternal.h"
#include "NetworkApiCatalog.h"
#include "JvmAware.h"
#include "DbgHelpLock.h"
#include "StepLogic.h"
#include "../Disasm/IDisassembler.h"
#include <windows.h>
#include <dbghelp.h>
#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <limits>

namespace ds {
static void writePrintablePayload(std::FILE* f, const std::vector<uint8_t>& bytes) {
    for (uint8_t b : bytes) {
        if (b == '\r' || b == '\n' || b == '\t') std::fputc((int)b, f);
        else if (b >= 0x20 && b < 0x7F)          std::fputc((int)b, f);
        else                                     std::fputc('.', f);
    }
    if (bytes.empty() || bytes.back() != '\n') std::fputc('\n', f);
}

static void writeHexPayload(std::FILE* f, const std::vector<uint8_t>& bytes) {
    for (size_t off = 0; off < bytes.size(); off += 16) {
        std::fprintf(f, "%08zX  ", off);
        char ascii[17] = {};
        for (size_t i = 0; i < 16; ++i) {
            if (off + i < bytes.size()) {
                uint8_t b = bytes[off + i];
                std::fprintf(f, "%02X ", b);
                ascii[i] = (b >= 0x20 && b < 0x7F) ? (char)b : '.';
            } else {
                std::fputs("   ", f);
                ascii[i] = ' ';
            }
            if (i == 7) std::fputc(' ', f);
        }
        ascii[16] = '\0';
        std::fprintf(f, " %s\n", ascii);
    }
}

// ---- guided network observation (public shell + debug-thread probes) ---------
void Debugger::startNetworkObservation() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        // A terminated snapshot deliberately retains modules/register history,
        // but it has no live debuggee in which probes can be installed. Keep
        // this Core boundary authoritative even if a UI caller has stale state.
        if (cleanupOnly_ || (state_ != DbgState::Running && state_ != DbgState::Paused)) {
            networkObservationWant_.store(false);
            networkCoverage_.requested = false;
            return;
        }
        networkObservationWant_.store(true);
        networkCoverage_.requested = true;
        pendingNetworkSync_ = true;
    }
    requestTraceSyncBreak();
}

void Debugger::stopNetworkObservation() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (cleanupOnly_) return;
        networkObservationWant_.store(false);
        networkCoverage_.requested = false;
        pendingNetworkSync_ = state_ == DbgState::Running || state_ == DbgState::Paused;
    }
    requestTraceSyncBreak();
}

void Debugger::enableNetTap(bool on) {
    if (on) startNetworkObservation();
    else stopNetworkObservation();
}

NetworkObservation Debugger::networkObservationSnapshot() {
    std::lock_guard<std::mutex> lk(mtx_);
    NetworkObservation snapshot;
    snapshot.coverage = networkCoverage_;
    snapshot.events.assign(networkEvents_.begin(), networkEvents_.end());
    return snapshot;
}

NetworkProbeCoverage Debugger::networkProbeCoverage() {
    std::lock_guard<std::mutex> lk(mtx_);
    return networkCoverage_;
}

void Debugger::clearNetworkObservation() {
    std::lock_guard<std::mutex> lk(mtx_);
    networkEvents_.clear();
    networkCoverage_.retainedPayloadBytes = 0;
    networkCoverage_.payloadBytesDropped = 0;
    networkCoverage_.eventsDropped = 0;
}

bool Debugger::setNetCaptureLogFile(const std::string& utf8Path, bool append, std::string* err) {
    if (err) err->clear();
    if (utf8Path.empty() || utf8Path.size() > 32768 || utf8Path.find('\0') != std::string::npos) {
        if (err) *err = "invalid log path";
        return false;
    }
    std::lock_guard lock(netLogMtx_);
    // Reserve an extra control slot for Close, which must always be accepted.
    if (netLogShutdown_ || netLogQueuedControls_ >= kNetLogQueueControls) {
        if (err) *err = "log writer is busy; wait for queued file changes to finish";
        return false;
    }
    NetLogWork work;
    work.kind = NetLogWork::Kind::Open;
    work.path = utf8Path;
    work.append = append;
    work.generation = ++netLogGeneration_;
    netLogQueue_.push_back(std::move(work));
    ++netLogQueuedControls_;
    netLogPath_ = utf8Path;
    netLogStatus_.enabled = true;
    netLogStatus_.opening = true;
    netLogStatus_.draining = false;
    netLogStatus_.error.clear();
    netLogCv_.notify_one();
    return true;
}

void Debugger::closeNetCaptureLogFile() {
    std::lock_guard lock(netLogMtx_);
    if (!netLogStatus_.enabled && !netLogStatus_.opening) return;
    NetLogWork work;
    work.kind = NetLogWork::Kind::Close;
    work.generation = ++netLogGeneration_;
    netLogQueue_.push_back(std::move(work));
    ++netLogQueuedControls_;
    netLogStatus_.enabled = false;
    netLogStatus_.opening = false;
    netLogStatus_.draining = true;
    netLogCv_.notify_one();
}

NetCaptureLogStatus Debugger::netCaptureLogStatus() {
    std::lock_guard lock(netLogMtx_);
    return netLogStatus_;
}

bool Debugger::netCaptureLogEnabled() {
    std::lock_guard lock(netLogMtx_);
    return netLogStatus_.enabled;
}

std::string Debugger::netCaptureLogPath() {
    std::lock_guard lock(netLogMtx_);
    return netLogPath_;
}

static const char* networkApiName(NetworkProbeApi api) {
    const NetworkProbeDescriptor* descriptor = NetworkProbeDescriptorFor(api);
    return descriptor ? descriptor->symbol : "network";
}

static const char* networkStageName(NetworkObservationStage stage) {
    switch (stage) {
        case NetworkObservationStage::NameResolution: return "resolve";
        case NetworkObservationStage::Connect: return "connect";
        case NetworkObservationStage::Request: return "request";
        case NetworkObservationStage::Response: return "response";
        case NetworkObservationStage::Send: return "send";
        case NetworkObservationStage::Receive: return "receive";
        case NetworkObservationStage::HandleClosed: return "close";
        case NetworkObservationStage::Limitation: return "limitation";
        case NetworkObservationStage::ProbeStatus: return "status";
    }
    return "status";
}

static const char* networkDirectionName(NetworkDirection direction) {
    switch (direction) {
        case NetworkDirection::Outbound: return "outbound";
        case NetworkDirection::Inbound: return "inbound";
        case NetworkDirection::None: return "none";
    }
    return "none";
}

void Debugger::pushNetworkEvent(NetworkObservationEvent&& event) {
    event.hostname = BoundNetworkText(std::move(event.hostname));
    event.ip = BoundNetworkText(std::move(event.ip));
    event.endpoint = BoundNetworkText(std::move(event.endpoint));
    event.method = BoundNetworkText(std::move(event.method));
    event.path = BoundNetworkText(std::move(event.path));
    event.object = BoundNetworkText(std::move(event.object));
    event.detail = BoundNetworkText(std::move(event.detail));
    event.runtimeModule = BoundNetworkText(std::move(event.runtimeModule));
    event.mappingEvidence = BoundNetworkText(std::move(event.mappingEvidence));
    if (event.payload.size() > kNetworkObservationPayloadCap) {
        event.payload.resize(kNetworkObservationPayloadCap);
        event.truncated = true;
    }
    std::lock_guard<std::mutex> lk(mtx_);
    if (!event.sessionGeneration) event.sessionGeneration = sessionGeneration_;
    if (!event.pid) event.pid = pid_;
    event.sequence = ++networkEventSequence_;
    auto payloadWouldExceed = [&]() {
        const uint64_t retained = networkPendingPayloadBytes_ +
                                  networkCoverage_.retainedPayloadBytes;
        return retained >= kNetworkObservationRetainedPayloadCap
             ? !event.payload.empty()
             : event.payload.size() > kNetworkObservationRetainedPayloadCap - retained;
    };
    while (!networkEvents_.empty() && payloadWouldExceed()) {
        networkCoverage_.payloadBytesDropped += networkEvents_.front().payload.size();
        networkCoverage_.retainedPayloadBytes -= networkEvents_.front().payload.size();
        networkEvents_.pop_front();
        ++networkCoverage_.eventsDropped;
    }
    if (payloadWouldExceed()) {
        const uint64_t retained = (std::min<uint64_t>)(
            kNetworkObservationRetainedPayloadCap,
            networkPendingPayloadBytes_ + networkCoverage_.retainedPayloadBytes);
        const size_t available = static_cast<size_t>(
            kNetworkObservationRetainedPayloadCap - retained);
        networkCoverage_.payloadBytesDropped += event.payload.size() - available;
        event.payload.resize(available);
        event.truncated = true;
    }
    while (networkEvents_.size() >= kNetworkObservationEventCap) {
        networkCoverage_.retainedPayloadBytes -= networkEvents_.front().payload.size();
        networkCoverage_.payloadBytesDropped += networkEvents_.front().payload.size();
        networkEvents_.pop_front();
        ++networkCoverage_.eventsDropped;
    }
    networkCoverage_.retainedPayloadBytes += event.payload.size();
    networkEvents_.push_back(std::move(event));
}
static void writeNetworkLogRecord(std::FILE* file, const NetworkObservationEvent& event,
                                  uint64_t timestamp) {
    FILETIME utc{static_cast<DWORD>(timestamp), static_cast<DWORD>(timestamp >> 32)}, local{};
    SYSTEMTIME st{};
    FileTimeToLocalFileTime(&utc, &local);
    FileTimeToSystemTime(&local, &st);
    const std::string port = event.portValid ? std::to_string(event.port) : "-";
    const uint32_t eventPid = event.pid;
    std::fprintf(file,
                 "=== %04u-%02u-%02u %02u:%02u:%02u.%03u stage=%s direction=%s api=%s pid=%u tid=%u handle=0x%llX host=%s ip=%s port=%s method=%s path=%s object=%s endpoint=%s detail=%s result=%lld raw_result=0x%llX result_valid=%u pointer_bits=%u requested=%llu requested_valid=%u transferred=%u transferred_valid=%u captured=%zu%s%s%s ===\n",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                 networkStageName(event.stage), networkDirectionName(event.direction),
                 networkApiName(event.api), eventPid, event.tid,
                 (unsigned long long)event.handle, event.hostname.c_str(), event.ip.c_str(),
                 port.c_str(), event.method.c_str(), event.path.c_str(), event.object.c_str(),
                 event.endpoint.c_str(), event.detail.c_str(), (long long)event.result,
                 (unsigned long long)event.rawResult, event.resultValid ? 1u : 0u,
                 static_cast<unsigned>(event.pointerWidthBits),
                 (unsigned long long)event.requestedBytes,
                 event.requestedBytesValid ? 1u : 0u, event.transferred,
                 event.transferredValid ? 1u : 0u,
                 event.payload.size(), event.truncated ? " truncated" : "",
                 event.asyncPartial ? " async-partial" : "",
                 event.payloadOpaque ? " opaque" : "");
    if (!event.payload.empty()) {
        std::fputs("TEXT:\n", file);
        writePrintablePayload(file, event.payload);
        std::fputs("HEX:\n", file);
        writeHexPayload(file, event.payload);
    }
    std::fputc('\n', file);
}

void Debugger::writeNetworkObservationLog(const NetworkObservationEvent& event) {
    std::lock_guard lock(netLogMtx_);
    if (!netLogStatus_.enabled || netLogShutdown_) return;
    if (event.payload.size() > kNetLogQueueBytes - sizeof(NetworkObservationEvent)) {
        ++netLogStatus_.droppedRecords;
        return;
    }
    size_t bytes = sizeof(NetworkObservationEvent) + event.payload.size();
    for (const auto* text : {&event.hostname, &event.ip, &event.endpoint, &event.method,
            &event.path, &event.object, &event.detail, &event.runtimeModule, &event.mappingEvidence}) {
        if (text->size() > kNetLogQueueBytes || bytes > kNetLogQueueBytes - text->size()) {
            ++netLogStatus_.droppedRecords;
            return;
        }
        bytes += text->size();
    }
    if (netLogStatus_.queuedRecords >= kNetLogQueueRecords ||
        bytes > kNetLogQueueBytes - netLogStatus_.queuedBytes) {
        ++netLogStatus_.droppedRecords;
        return;
    }
    NetLogWork work;
    work.event = event;
    work.event.pid = event.pid ? event.pid : pid_; // called only by the debug-event owner
    work.bytes = bytes;
    work.generation = netLogGeneration_;
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    work.timestamp = (uint64_t(now.dwHighDateTime) << 32) | now.dwLowDateTime;
    netLogQueue_.push_back(std::move(work));
    ++netLogStatus_.queuedRecords;
    netLogStatus_.queuedBytes += bytes;
    netLogCv_.notify_one();
}

void Debugger::networkLogWorkerLoop() {
    std::FILE* file = nullptr; // accessed/closed exclusively by this worker
    uint64_t openGeneration = 0;
    auto closeFile = [&] {
        if (!file) return;
        SYSTEMTIME st{};
        GetLocalTime(&st);
        std::fprintf(file, "\n# stopped %04u-%02u-%02u %02u:%02u:%02u.%03u local\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        const bool failed = std::ferror(file) != 0;
        const int closed = std::fclose(file);
        file = nullptr;
        if (failed || closed != 0) {
            std::lock_guard lock(netLogMtx_);
            netLogStatus_.error = "network log could not be completely written to storage";
        }
    };
    for (;;) {
        NetLogWork work;
        {
            std::unique_lock lock(netLogMtx_);
            netLogCv_.wait(lock, [this] { return netLogShutdown_ || !netLogQueue_.empty(); });
            if (netLogQueue_.empty() && netLogShutdown_) break;
            work = std::move(netLogQueue_.front());
            netLogQueue_.pop_front();
            if (work.kind == NetLogWork::Kind::Record) {
                --netLogStatus_.queuedRecords;
                netLogStatus_.queuedBytes -= work.bytes;
            } else --netLogQueuedControls_;
        }
        if (work.kind == NetLogWork::Kind::Close) {
            closeFile();
            std::lock_guard lock(netLogMtx_);
            if (work.generation == netLogGeneration_) netLogStatus_.draining = false;
        } else if (work.kind == NetLogWork::Kind::Open) {
            closeFile();
            const auto path = widenUtf8(work.path);
            const bool opened = !path.empty() &&
                _wfopen_s(&file, path.c_str(), work.append ? L"ab" : L"wb") == 0 && file;
            if (opened) {
                openGeneration = work.generation;
                SYSTEMTIME st{};
                GetLocalTime(&st);
                std::fprintf(file,
                    "# DisasmStudio typed network observation log\n"
                    "# started %04u-%02u-%02u %02u:%02u:%02u.%03u local\n"
                    "# bounded asynchronous writer; queue drops are reported in Server Watch\n\n",
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
            }
            std::lock_guard lock(netLogMtx_);
            if (work.generation == netLogGeneration_) {
                netLogStatus_.opening = false;
                netLogStatus_.enabled = opened;
                if (!opened) netLogStatus_.error = "could not open network log file: " + work.path;
            }
        } else if (file && work.generation == openGeneration) {
            writeNetworkLogRecord(file, work.event, work.timestamp);
            // Flushing is exclusively writer-owned. Even a stalled filesystem
            // cannot hold a debug-event/UI mutex or grow the bounded queue.
            if (std::fflush(file) != 0 || std::ferror(file)) {
                closeFile();
                std::lock_guard lock(netLogMtx_);
                if (work.generation == netLogGeneration_) {
                    netLogStatus_.enabled = false;
                    netLogStatus_.error = "network log write failed; logging stopped";
                }
                ++netLogStatus_.droppedRecords;
            }
        } else {
            std::lock_guard lock(netLogMtx_);
            ++netLogStatus_.droppedRecords;
        }
    }
    closeFile();
}

// Resolve exports from the debuggee's exact mapped modules. Probe metadata lives
// outside bps_, so it never appears in the analyst breakpoint list. A user bp can
// share the physical int3 and remains the owner/visible stop.
void Debugger::armNetTap() {
    if (!hProcess_) return;
    std::vector<DbgModule> modules;
    { std::lock_guard<std::mutex> lk(mtx_); modules = dbgModules_; }
    std::unordered_set<std::string> catalogBackedSpecs;
    std::vector<std::string> rejectedSpecs;
    for (const NetworkProbeDescriptor& spec : kNetworkProbeDescriptors) {
        if (!NetworkProbeDescriptorFor(spec.api)) continue;
        const auto catalog = LookupNetworkApi(spec.dll, spec.symbol);
        if (!catalog) {
            rejectedSpecs.push_back(std::string(spec.dll) + "!" + spec.symbol);
            continue;
        }
        catalogBackedSpecs.insert(catalog->dll + "!" + catalog->normalizedName);
    }
    auto targetExecutableImageAddress = [&](const DbgModule& module, uint64_t va) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (::VirtualQueryEx((HANDLE)hProcess_, reinterpret_cast<LPCVOID>(va), &mbi,
                             sizeof(mbi)) != sizeof(mbi) ||
            mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE ||
            reinterpret_cast<uint64_t>(mbi.AllocationBase) != module.base ||
            va < module.base || (module.size && va - module.base >= module.size) ||
            (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))
            return false;
        switch (mbi.Protect & 0xFFu) {
            case PAGE_EXECUTE:
            case PAGE_EXECUTE_READ:
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY: return true;
            default: return false;
        }
    };
    uint32_t available = 0, skipped = 0;
    for (const NetworkProbeDescriptor& spec : kNetworkProbeDescriptors) {
        if (!NetworkProbeDescriptorFor(spec.api)) continue;
        // Registration is fail-closed: a typo, wrong DLL, or future ad-hoc row
        // cannot become a live target mutation until it is cataloged exactly.
        if (!LookupNetworkApi(spec.dll, spec.symbol)) continue;
        auto module = std::find_if(modules.begin(), modules.end(), [&](const DbgModule& m) {
            return jvmdetail::baseNameLower(m.name) == spec.dll ||
                   jvmdetail::baseNameLower(m.path) == spec.dll;
        });
        if (module == modules.end() || !module->base || !module->size) continue;
        const uint64_t addr = resolveMappedExport(module->base, module->size, spec.symbol);
        if (!addr || !targetExecutableImageAddress(*module, addr)) continue;
        ++available;
        { std::lock_guard<std::mutex> lk(mtx_);
          if (networkProbeBps_.count(addr)) continue; }

        NetworkProbeBp probe;
        probe.api = spec.api;
        probe.moduleBase = module->base;
        bool conflict = false;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (auto user = bps_.find(addr); user != bps_.end() && user->second.armed) {
                probe.orig = user->second.orig;
                probe.ownsByte = false;
            } else if (bps_.count(addr)) {
                conflict = true;
            } else if (traceBps_.count(addr) || dllTargetBps_.count(addr) ||
                       antiTraps_.count(addr) || networkReturnBps_.count(addr) ||
                       authorizationBps_.count(addr) ||
                       authorizationReturnBps_.count(addr) ||
                       (runtimeTempBpAddr_ && *runtimeTempBpAddr_ == addr)) {
                conflict = true;
            }
        }
        if (conflict) { ++skipped; continue; }
        if (probe.ownsByte) {
            if (!readByteRPM((HANDLE)hProcess_, addr, probe.orig) || probe.orig == 0xCC ||
                !replaceByteIfEqual((HANDLE)hProcess_, addr, probe.orig, 0xCC)) {
                ++skipped;
                continue;
            }
        }
        {
            std::lock_guard<std::mutex> lk(mtx_);
            networkProbeBps_[addr] = probe;
            auto at = std::lower_bound(networkProbeBpAddrs_.begin(), networkProbeBpAddrs_.end(), addr);
            networkProbeBpAddrs_.insert(at, addr);
        }
    }
    std::string unsupportedCatalog =
        "Cataloged APIs without a live ABI decoder (not silently observed): ";
    bool hasUnsupportedCatalog = false;
    for (const NetworkApiMatch& api : EnumerateNetworkApis()) {
        if (catalogBackedSpecs.count(api.dll + "!" + api.normalizedName)) continue;
        if (hasUnsupportedCatalog) unsupportedCatalog += ", ";
        unsupportedCatalog += api.dll + "!" + api.canonicalName;
        hasUnsupportedCatalog = true;
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        networkCoverage_.sessionGeneration = sessionGeneration_;
        networkCoverage_.pid = pid_;
        networkCoverage_.requested = networkObservationWant_.load();
        networkCoverage_.active = !networkProbeBps_.empty();
        networkCoverage_.wow64 = isWow64_.load();
        networkCoverage_.probesAvailable = available;
        networkCoverage_.probesArmed = static_cast<uint32_t>(networkProbeBps_.size());
        networkCoverage_.probesSkipped = skipped + static_cast<uint32_t>(rejectedSpecs.size());
        networkCoverage_.probesSharedWithUserBreakpoints = 0;
        networkCoverage_.winsock = networkCoverage_.nameResolution = false;
        networkCoverage_.winHttp = networkCoverage_.winInet = networkCoverage_.urlMon = false;
        for (const auto& [ignored, probe] : networkProbeBps_) {
            (void)ignored;
            if (!probe.ownsByte) ++networkCoverage_.probesSharedWithUserBreakpoints;
            if (probe.api >= NetworkProbeApi::ResolveAddrInfoA &&
                probe.api <= NetworkProbeApi::DnsQueryUtf8)
                networkCoverage_.nameResolution = true;
            if ((probe.api >= NetworkProbeApi::ResolveAddrInfoA &&
                 probe.api <= NetworkProbeApi::GetNameInfoW) ||
                (probe.api >= NetworkProbeApi::Connect &&
                 probe.api <= NetworkProbeApi::CloseSocket))
                networkCoverage_.winsock = true;
            if (probe.api >= NetworkProbeApi::WinHttpOpen && probe.api <= NetworkProbeApi::WinHttpCloseHandle)
                networkCoverage_.winHttp = true;
            if (probe.api >= NetworkProbeApi::InternetOpenA && probe.api <= NetworkProbeApi::InternetCloseHandle)
                networkCoverage_.winInet = true;
            if (probe.api >= NetworkProbeApi::UrlDownloadToFileA &&
                probe.api <= NetworkProbeApi::UrlOpenBlockingStreamW)
                networkCoverage_.urlMon = true;
        }
        networkCoverage_.payloads = networkCoverage_.winsock || networkCoverage_.winHttp || networkCoverage_.winInet;
        networkCoverage_.limitations = {
            "Custom TLS stacks and raw Winsock TLS payloads remain opaque encrypted bytes.",
            "Overlapped/asynchronous receive completion can outlive the API return and is reported as partial.",
            "Direct syscalls, custom/inlined network stacks, kernel traffic, and child processes are not observed.",
            "API entry probes briefly restore one instruction under debugger-controlled peer suspension.",
        };
        if (hasUnsupportedCatalog)
            networkCoverage_.limitations.push_back(std::move(unsupportedCatalog));
        if (networkCoverage_.handleStatesDropped)
            networkCoverage_.limitations.push_back(
                "HTTP/socket handle-lineage state exceeded the 4,096-record cap; some descendant metadata is unavailable.");
        if (!rejectedSpecs.empty()) {
            std::string rejected = "Live probe specs rejected by exact network catalog guard: ";
            for (size_t i = 0; i < rejectedSpecs.size(); ++i) {
                if (i) rejected += ", ";
                rejected += rejectedSpecs[i];
            }
            networkCoverage_.limitations.push_back(std::move(rejected));
        }
        netTapArmed_ = !networkProbeBps_.empty();
    }
}

void Debugger::disarmNetTap() {
    bool retained = false;
    {
        std::lock_guard lock(mtx_);
        const auto retire = [&](auto& sites, auto& addresses) {
            for (auto at = sites.begin(); at != sites.end();) {
                // A read/write failure does not retire physical INT3 ownership.
                // Restored or superseded bytes can release their owner safely.
                if (!hProcess_ || !at->second.ownsByte ||
                    restoreDebuggerOwnedByte((HANDLE)hProcess_, at->first, at->second.orig))
                    at = sites.erase(at);
                else { retained = true; ++at; }
            }
            addresses.clear();
            for (const auto& [address, ignored] : sites) {
                (void)ignored; addresses.push_back(address);
            }
            std::sort(addresses.begin(), addresses.end());
        };
        retire(networkProbeBps_, networkProbeBpAddrs_);
        retire(networkReturnBps_, networkReturnBpAddrs_);
        networkCoverage_.active = retained;
        networkCoverage_.probesArmed = static_cast<uint32_t>(networkProbeBps_.size());
        networkPendingPayloadBytes_ = 0;
        netTapArmed_ = retained;
        if (retained && std::find(networkCoverage_.limitations.begin(), networkCoverage_.limitations.end(),
                "Server Watch stop incomplete: retained breakpoint bytes will be retried.") == networkCoverage_.limitations.end())
            networkCoverage_.limitations.emplace_back(
                "Server Watch stop incomplete: retained breakpoint bytes will be retried.");
    }
    networkPendingReturns_.clear();
    networkHandleLineage_.clear();
    if (retained)
        recordExecutionFailure("Server Watch stop could not restore every breakpoint; ownership retained and target remains paused");
}

void Debugger::retireNetworkModule(uint64_t base, uint64_t size) {
    if (!base) return;
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto it = networkProbeBps_.begin(); it != networkProbeBps_.end(); ) {
        if (it->second.moduleBase == base) it = networkProbeBps_.erase(it);
        else ++it;
    }
    networkProbeBpAddrs_.clear();
    for (const auto& [addr, ignored] : networkProbeBps_) {
        (void)ignored; networkProbeBpAddrs_.push_back(addr);
    }
    std::sort(networkProbeBpAddrs_.begin(), networkProbeBpAddrs_.end());
    if (!size) {
        // With no image extent, address-range retirement would risk deleting
        // unrelated higher mappings. Drop all in-flight returns without writing
        // any possibly reused VA; loaded entry probes will be re-evaluated below.
        networkPendingReturns_.clear();
        networkPendingPayloadBytes_ = 0;
        // Unknown extent cannot prove that any return site's mapping vanished.
        // Keep their physical owners; later hits/Stop safely restore each byte.
    }
    for (auto it = networkReturnBps_.begin(); it != networkReturnBps_.end(); ) {
        if (size && it->first >= base && it->first - base < size) {
            (void)networkPendingReturns_.eraseAddress(it->first,
                [&](const NetworkPendingFrame& frame) {
                    networkPendingPayloadBytes_ -= (std::min<uint64_t>)(
                        networkPendingPayloadBytes_, frame.payload.size());
                });
            it = networkReturnBps_.erase(it);
        } else ++it;
    }
    networkReturnBpAddrs_.clear();
    for (const auto& [addr, ignored] : networkReturnBps_) {
        (void)ignored; networkReturnBpAddrs_.push_back(addr);
    }
    std::sort(networkReturnBpAddrs_.begin(), networkReturnBpAddrs_.end());
    networkCoverage_.probesArmed = static_cast<uint32_t>(networkProbeBps_.size());
    networkCoverage_.active = !networkProbeBps_.empty();
    netTapArmed_ = !networkProbeBps_.empty();
}

bool Debugger::disarmNetworkProbe(uint64_t addr) {
    NetworkProbeBp probe;
    { std::lock_guard<std::mutex> lk(mtx_);
      auto it = networkProbeBps_.find(addr); if (it == networkProbeBps_.end()) return false;
      probe = it->second; it->second.armed = false; }
    return !probe.ownsByte || replaceByteIfEqual((HANDLE)hProcess_, addr, 0xCC, probe.orig);
}

bool Debugger::rearmNetworkProbe(uint64_t addr) {
    NetworkProbeBp probe;
    { std::lock_guard<std::mutex> lk(mtx_);
      auto it = networkProbeBps_.find(addr); if (it == networkProbeBps_.end()) return false;
      probe = it->second; }
    const bool ok = !probe.ownsByte || replaceByteIfEqual((HANDLE)hProcess_, addr, probe.orig, 0xCC);
    if (ok) { std::lock_guard<std::mutex> lk(mtx_); if (auto it = networkProbeBps_.find(addr); it != networkProbeBps_.end()) it->second.armed = true; }
    return ok;
}

bool Debugger::rearmNetworkReturn(uint64_t addr) {
    NetworkReturnBp site;
    { std::lock_guard<std::mutex> lk(mtx_);
      auto it = networkReturnBps_.find(addr); if (it == networkReturnBps_.end()) return false;
      site = it->second; }
    const bool ok = !site.ownsByte || replaceByteIfEqual((HANDLE)hProcess_, addr, site.orig, 0xCC);
    if (ok) {
        std::lock_guard<std::mutex> lk(mtx_);
        if (auto it = networkReturnBps_.find(addr); it != networkReturnBps_.end())
            it->second.armed = true;
    }
    return ok;
}

static std::string readNetworkAnsi(HANDLE process, uint64_t address,
                                   size_t maxChars = kNetworkObservationTextCap,
                                   bool* hitLimit = nullptr) {
    std::string value;
    if (hitLimit) *hitLimit = false;
    if (!address) return value;
    value.reserve(128);
    maxChars = (std::min)(maxChars, kNetworkObservationTextCap);
    bool terminated = false;
    for (size_t i = 0; i < maxChars; ++i) {
        char ch = 0;
        if (!readRemoteExact(process, address + i, &ch, sizeof(ch))) break;
        if (!ch) { terminated = true; break; }
        value.push_back(ch);
    }
    if (hitLimit) *hitLimit = maxChars != 0 && value.size() == maxChars && !terminated;
    return value;
}

static std::string readNetworkWide(HANDLE process, uint64_t address,
                                   size_t maxChars = kNetworkObservationTextCap,
                                   bool* hitLimit = nullptr) {
    std::vector<wchar_t> wide;
    if (hitLimit) *hitLimit = false;
    if (!address) return {};
    wide.reserve(128);
    maxChars = (std::min)(maxChars, kNetworkObservationTextCap);
    bool terminated = false;
    for (size_t i = 0; i < maxChars; ++i) {
        uint16_t unit = 0;
        if (!readRemoteExact(process, address + i * 2u, &unit, sizeof(unit))) break;
        if (!unit) { terminated = true; break; }
        wide.push_back(static_cast<wchar_t>(unit));
    }
    if (hitLimit) *hitLimit = maxChars != 0 && wide.size() == maxChars && !terminated;
    if (wide.empty()) return {};
    const int count = WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                                          nullptr, 0, nullptr, nullptr);
    if (count <= 0) return {};
    std::string value(static_cast<size_t>(count), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()),
                        value.data(), count, nullptr, nullptr);
    return BoundNetworkText(std::move(value));
}

static std::vector<uint8_t> readNetworkPayload(HANDLE process, uint64_t address,
                                                uint64_t length) {
    std::vector<uint8_t> payload;
    const size_t take = static_cast<size_t>((std::min<uint64_t>)(
        length, kNetworkObservationPayloadCap));
    if (!address || !take) return payload;
    payload.resize(take);
    SIZE_T got = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), payload.data(), take, &got) || !got) {
        payload.clear();
        return payload;
    }
    payload.resize(static_cast<size_t>(got));
    return payload;
}

static std::vector<uint8_t> readNetworkWsabufs(HANDLE process, bool wow64,
                                               uint64_t buffers, uint64_t count,
                                               uint64_t byteLimit = UINT64_MAX,
                                               uint64_t* describedBytes = nullptr,
                                               bool* truncated = nullptr,
                                               bool* describedBytesValid = nullptr) {
    std::vector<uint8_t> payload;
    const size_t stride = wow64 ? 8u : 16u;
    const uint64_t originalCount = count;
    count = (std::min<uint64_t>)(count, 16u);
    uint64_t described = 0;
    uint64_t processed = 0;
    bool wasTruncated = originalCount > count;
    for (uint64_t i = 0; i < count; ++i) {
        uint8_t descriptor[16]{};
        if (!readRemoteExact(process, buffers + i * stride, descriptor, stride)) {
            wasTruncated = true;
            break;
        }
        uint32_t length = 0;
        std::memcpy(&length, descriptor, sizeof(length));
        ++processed;
        described = UINT64_MAX - described < length ? UINT64_MAX : described + length;
        uint64_t pointer = 0;
        if (wow64) {
            uint32_t narrow = 0;
            std::memcpy(&narrow, descriptor + 4, sizeof(narrow));
            pointer = narrow;
        } else {
            std::memcpy(&pointer, descriptor + 8, sizeof(pointer));
        }
        const uint64_t available = kNetworkObservationPayloadCap - payload.size();
        const uint64_t take = (std::min<uint64_t>)((std::min<uint64_t>)(length, available), byteLimit);
        if (!take) {
            if (length) wasTruncated = true;
            continue;
        }
        std::vector<uint8_t> part = readNetworkPayload(process, pointer, take);
        payload.insert(payload.end(), part.begin(), part.end());
        if (part.size() < take) { wasTruncated = true; break; }
        if (take < length) wasTruncated = true;
        byteLimit -= take;
    }
    if (processed < count) wasTruncated = true;
    if (payload.size() == kNetworkObservationPayloadCap && described > payload.size())
        wasTruncated = true;
    if (describedBytes) *describedBytes = described;
    if (truncated) *truncated = wasTruncated;
    if (describedBytesValid)
        *describedBytesValid = originalCount <= 16u && processed == originalCount &&
                               described != UINT64_MAX;
    return payload;
}

static bool readInternetBuffer(HANDLE process, bool wow64, uint64_t descriptor,
                               uint64_t& buffer, uint32_t& length,
                               uint64_t* headers = nullptr,
                               uint32_t* headersLength = nullptr) {
    buffer = 0;
    length = 0;
    if (headers) *headers = 0;
    if (headersLength) *headersLength = 0;
    const size_t size = wow64 ? 40u : 56u;
    std::array<uint8_t, 56> bytes{};
    if (!descriptor || !readRemoteExact(process, descriptor, bytes.data(), size)) return false;
    uint32_t structureSize = 0;
    std::memcpy(&structureSize, bytes.data(), sizeof(structureSize));
    if (structureSize < size) return false;
    if (wow64) {
        uint32_t pointer = 0;
        std::memcpy(&pointer, bytes.data() + 20, sizeof(pointer));
        buffer = pointer;
        std::memcpy(&length, bytes.data() + 24, sizeof(length));
        if (headers) {
            std::memcpy(&pointer, bytes.data() + 8, sizeof(pointer));
            *headers = pointer;
        }
        if (headersLength)
            std::memcpy(headersLength, bytes.data() + 12, sizeof(*headersLength));
    } else {
        std::memcpy(&buffer, bytes.data() + 32, sizeof(buffer));
        std::memcpy(&length, bytes.data() + 40, sizeof(length));
        if (headers) std::memcpy(headers, bytes.data() + 16, sizeof(*headers));
        if (headersLength)
            std::memcpy(headersLength, bytes.data() + 24, sizeof(*headersLength));
    }
    return true;
}

static std::string readNetworkHostent(HANDLE process, bool wow64, uint64_t address,
                                      std::string* firstIp = nullptr) {
    if (firstIp) firstIp->clear();
    if (!address) return {};
    const uint64_t typeAt = address + (wow64 ? 8u : 16u);
    const uint64_t lengthAt = typeAt + 2u;
    const uint64_t listAt = address + (wow64 ? 12u : 24u);
    uint16_t family = 0, addressLength = 0;
    if (!readRemoteExact(process, typeAt, &family, sizeof(family)) ||
        !readRemoteExact(process, lengthAt, &addressLength, sizeof(addressLength))) return {};
    const NetworkCallContext pointerContext{wow64, 0, {}};
    const NetworkMemoryReader read = [process](uint64_t at, void* out, size_t size) {
        return readRemoteExact(process, at, out, size);
    };
    uint64_t list = 0;
    if (!ReadNetworkPointer(pointerContext, read, listAt, list)) return {};
    std::string endpoints;
    const uint64_t pointerSize = wow64 ? 4u : 8u;
    for (size_t i = 0; list && i < 8; ++i) {
        uint64_t item = 0;
        if (!ReadNetworkPointer(pointerContext, read, list + i * pointerSize, item) || !item) break;
        std::string one;
        if (family == 2 && addressLength >= 4) {
            uint8_t bytes[4]{};
            if (readRemoteExact(process, item, bytes, sizeof(bytes))) one = FormatIpv4Address(bytes);
        } else if (family == 23 && addressLength >= 16) {
            uint8_t bytes[16]{};
            if (readRemoteExact(process, item, bytes, sizeof(bytes))) one = FormatIpv6Address(bytes);
        }
        if (!one.empty()) {
            if (firstIp && firstIp->empty()) *firstIp = one;
            if (!endpoints.empty()) endpoints += ", ";
            endpoints += one;
        }
    }
    return BoundNetworkText(std::move(endpoints));
}

static std::string readNetworkSockaddr(HANDLE process, uint64_t address, uint64_t length,
                                       std::string* ip = nullptr, uint16_t* port = nullptr,
                                       bool* portValid = nullptr) {
    if (ip) ip->clear();
    if (port) *port = 0;
    if (portValid) *portValid = false;
    const size_t take = static_cast<size_t>((std::min<uint64_t>)(length, 128u));
    if (!address || take < 2) return {};
    std::array<uint8_t, 128> bytes{};
    if (!readRemoteExact(process, address, bytes.data(), take)) return {};
    NetworkEndpointParts parts;
    if (!DecodeNetworkSockaddr(bytes.data(), take, parts)) return {};
    if (ip) *ip = parts.ip;
    if (port) *port = parts.port;
    if (portValid) *portValid = parts.portValid;
    return parts.endpoint;
}

static std::string formatNetworkHostPort(const std::string& host, uint16_t port,
                                         bool portValid) {
    if (host.empty()) return {};
    if (!portValid) return host;
    if (host.find(':') != std::string::npos && host.front() != '[')
        return "[" + host + "]:" + std::to_string(port);
    return host + ":" + std::to_string(port);
}

void Debugger::decorateNetworkEvent(NetworkObservationEvent& event) {
    if (!event.caller || !hProcess_) return;
    DbgModule module;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = std::find_if(dbgModules_.begin(), dbgModules_.end(), [&](const DbgModule& candidate) {
            return candidate.base && candidate.size && event.caller >= candidate.base &&
                   event.caller - candidate.base < candidate.size;
        });
        if (it == dbgModules_.end()) return;
        module = *it;
    }
    event.runtimeModule = module.name.empty() ? module.path : module.name;
    event.runtimeModuleBase = module.base;
    event.runtimeModuleLoadGeneration = module.loadGeneration;

    IMAGE_DOS_HEADER dos{};
    DWORD signature = 0;
    IMAGE_FILE_HEADER file{};
    uint32_t sizeOfHeaders = 0;
    if (!readRemoteExact((HANDLE)hProcess_, module.base, &dos, sizeof(dos)) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 || dos.e_lfanew > 0x100000 ||
        !readRemoteExact((HANDLE)hProcess_, module.base + dos.e_lfanew, &signature, sizeof(signature)) ||
        signature != IMAGE_NT_SIGNATURE ||
        !readRemoteExact((HANDLE)hProcess_, module.base + dos.e_lfanew + 4, &file, sizeof(file)) ||
        !file.NumberOfSections || file.NumberOfSections > 96 || file.SizeOfOptionalHeader < 64 ||
        !readRemoteExact((HANDLE)hProcess_, module.base + dos.e_lfanew + 24 + 60,
                         &sizeOfHeaders, sizeof(sizeOfHeaders)))
        return;

    const uint64_t rva = event.caller - module.base;
    if (rva < sizeOfHeaders) {
        event.fileOffset = rva;
        event.fileOffsetValid = true;
        event.mappingEvidence =
            "observed live PE header projection (backing-file identity/extent not proven)";
        event.evidenceQuality = NetworkEvidenceQuality::Observed;
        return;
    }
    const uint64_t sectionsAt = module.base + dos.e_lfanew + 24 + file.SizeOfOptionalHeader;
    std::vector<IMAGE_SECTION_HEADER> sections(file.NumberOfSections);
    if (!readRemoteExact((HANDLE)hProcess_, sectionsAt, sections.data(),
                         sections.size() * sizeof(IMAGE_SECTION_HEADER)))
        return;
    for (const IMAGE_SECTION_HEADER& section : sections) {
        const uint64_t start = section.VirtualAddress;
        const uint64_t rawSize = section.SizeOfRawData;
        if (!rawSize || rva < start || rva - start >= rawSize) continue;
        const uint64_t delta = rva - start;
        if (section.PointerToRawData > UINT64_MAX - delta) return;
        event.fileOffset = section.PointerToRawData + delta;
        event.fileOffsetValid = true;
        event.mappingEvidence =
            "observed live PE section projection (backing-file identity/extent not proven)";
        event.evidenceQuality = NetworkEvidenceQuality::Observed;
        return;
    }
    event.mappingEvidence = "caller is in a live image range without file-backed raw bytes";
}

// Decode the stopped call in the target ABI, retain nested return state per thread,
// and plant a shared physical return site only when the result/buffer is needed.
void Debugger::netTapCapture(uint64_t /*addr*/, uint32_t tid, NetworkProbeApi api) {
    auto th = threads_.find(tid);
    if (th == threads_.end()) return;
    Registers r;
    if (!ctxReadFull(th->second, r)) return;
    HANDLE hp = (HANDLE)hProcess_;
    const bool wow64 = isWow64_.load();
    const NetworkCallContext context{ wow64, r.rsp, { r.rcx, r.rdx, r.r8, r.r9 } };
    const NetworkMemoryReader read = [hp](uint64_t address, void* out, size_t size) {
        return readRemoteExact(hp, address, out, size);
    };
    NetworkPendingFrame frame;
    frame.api = api;
    frame.wide = api == NetworkProbeApi::ResolveAddrInfoW ||
                 api == NetworkProbeApi::GetAddrInfoExW ||
                 api == NetworkProbeApi::GetNameInfoW ||
                 api == NetworkProbeApi::DnsQueryW ||
                 api == NetworkProbeApi::InternetOpenW ||
                 api == NetworkProbeApi::InternetConnectW ||
                 api == NetworkProbeApi::HttpOpenRequestW ||
                 api == NetworkProbeApi::HttpAddRequestHeadersW ||
                 api == NetworkProbeApi::HttpSendRequestW ||
                 api == NetworkProbeApi::HttpSendRequestExW ||
                 api == NetworkProbeApi::HttpEndRequestW ||
                 api == NetworkProbeApi::InternetOpenUrlW ||
                 api == NetworkProbeApi::InternetReadFileExW ||
                 api == NetworkProbeApi::HttpQueryInfoW ||
                 api == NetworkProbeApi::UrlDownloadToFileW ||
                 api == NetworkProbeApi::UrlDownloadToCacheFileW ||
                 api == NetworkProbeApi::UrlOpenStreamW ||
                 api == NetworkProbeApi::UrlOpenBlockingStreamW;
    (void)ReadNetworkReturnAddress(context, read, frame.returnAddress);
    frame.caller = frame.returnAddress;
    for (size_t i = 0; i < frame.args.size(); ++i)
        (void)ReadNetworkArgument(context, i, read, frame.args[i]);
    // Win64 stack home slots are 64-bit, but the high half is unspecified for
    // DWORD/ULONG/int arguments. Normalize scalar ABI values before any bounds
    // decision; handles, pointers, and callback/context values stay full-width.
    const auto argU32 = [&](size_t index) {
        return static_cast<uint32_t>(frame.args[index]);
    };
    const auto argI32 = [&](size_t index) {
        return static_cast<int32_t>(argU32(index));
    };
    const auto positiveI32Length = [&](size_t index) -> uint32_t {
        const int32_t value = argI32(index);
        return value > 0 ? static_cast<uint32_t>(value) : 0u;
    };
    frame.handle = frame.args[0];
    // Session async mode is inherited by connection/request handles. Capture it
    // at entry so async read/write returns never inspect completion-owned output.
    frame.async = networkHandleLineage_.resolve(frame.handle).async;

    auto queueReturn = [&](NetworkPendingFrame pending) {
        if (!pending.returnAddress) return false;
        const uint64_t returnAddress = pending.returnAddress;
        const bool first = networkPendingReturns_.references(returnAddress) == 0;
        if (first) {
            NetworkReturnBp site;
            bool conflict = false;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                if (auto user = bps_.find(returnAddress);
                    user != bps_.end() && user->second.armed) {
                    site.orig = user->second.orig;
                    site.ownsByte = false;
                } else if (bps_.count(returnAddress)) {
                    conflict = true;
                } else if (networkProbeBps_.count(returnAddress) || traceBps_.count(returnAddress) ||
                           dllTargetBps_.count(returnAddress) || antiTraps_.count(returnAddress) ||
                           authorizationBps_.count(returnAddress) ||
                           authorizationReturnBps_.count(returnAddress) ||
                           (runtimeTempBpAddr_ && *runtimeTempBpAddr_ == returnAddress)) {
                    conflict = true;
                }
            }
            if (conflict || (site.ownsByte &&
                (!readByteRPM(hp, returnAddress, site.orig) || site.orig == 0xCC ||
                 !replaceByteIfEqual(hp, returnAddress, site.orig, 0xCC)))) {
                std::lock_guard<std::mutex> lk(mtx_);
                ++networkCoverage_.pendingReturnsDropped;
                return false;
            }
            {
                std::lock_guard<std::mutex> lk(mtx_);
                networkReturnBps_[returnAddress] = site;
                auto at = std::lower_bound(networkReturnBpAddrs_.begin(), networkReturnBpAddrs_.end(),
                                           returnAddress);
                networkReturnBpAddrs_.insert(at, returnAddress);
            }
        }
        const size_t pendingPayload = pending.payload.size();
        if (pendingPayload) {
            std::lock_guard<std::mutex> lk(mtx_);
            auto wouldExceed = [&]() {
                const uint64_t retained = networkPendingPayloadBytes_ +
                                          networkCoverage_.retainedPayloadBytes;
                return retained >= kNetworkObservationRetainedPayloadCap ||
                       pending.payload.size() >
                           kNetworkObservationRetainedPayloadCap - retained;
            };
            while (!networkEvents_.empty() && wouldExceed()) {
                networkCoverage_.payloadBytesDropped += networkEvents_.front().payload.size();
                networkCoverage_.retainedPayloadBytes -= networkEvents_.front().payload.size();
                networkEvents_.pop_front();
                ++networkCoverage_.eventsDropped;
            }
            const uint64_t retained = (std::min<uint64_t>)(
                kNetworkObservationRetainedPayloadCap,
                networkPendingPayloadBytes_ + networkCoverage_.retainedPayloadBytes);
            const size_t available = static_cast<size_t>(
                kNetworkObservationRetainedPayloadCap - retained);
            if (pending.payload.size() > available) {
                networkCoverage_.payloadBytesDropped += pending.payload.size() - available;
                pending.payload.resize(available);
                pending.payloadTruncated = true;
            }
        }
        const size_t admittedPayload = pending.payload.size();
        if (networkPendingReturns_.push(tid, returnAddress, std::move(pending))) {
            if (admittedPayload) {
                std::lock_guard<std::mutex> lk(mtx_);
                networkPendingPayloadBytes_ += admittedPayload;
            }
            return true;
        }
        if (first) {
            NetworkReturnBp site;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                auto it = networkReturnBps_.find(returnAddress);
                if (it != networkReturnBps_.end()) { site = it->second; networkReturnBps_.erase(it); }
                auto at = std::lower_bound(networkReturnBpAddrs_.begin(), networkReturnBpAddrs_.end(),
                                           returnAddress);
                if (at != networkReturnBpAddrs_.end() && *at == returnAddress)
                    networkReturnBpAddrs_.erase(at);
                ++networkCoverage_.pendingReturnsDropped;
            }
            if (site.ownsByte) (void)replaceByteIfEqual(hp, returnAddress, 0xCC, site.orig);
        } else {
            std::lock_guard<std::mutex> lk(mtx_);
            ++networkCoverage_.pendingReturnsDropped;
        }
        return false;
    };

    switch (api) {
        case NetworkProbeApi::ResolveAddrInfoA:
        case NetworkProbeApi::ResolveAddrInfoW:
            frame.hostname = frame.wide ? readNetworkWide(hp, frame.args[0])
                                        : readNetworkAnsi(hp, frame.args[0]);
            frame.detail = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            frame.buffer = frame.args[3]; // addrinfo**
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::GetAddrInfoExA:
        case NetworkProbeApi::GetAddrInfoExW:
            frame.hostname = frame.wide ? readNetworkWide(hp, frame.args[0])
                                        : readNetworkAnsi(hp, frame.args[0]);
            frame.detail = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            frame.buffer = frame.args[5]; // ADDRINFOEX**
            frame.async = frame.args[7] != 0 || frame.args[8] != 0;
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::GetHostByName:
            frame.hostname = readNetworkAnsi(hp, frame.args[0]);
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::GetNameInfoA:
        case NetworkProbeApi::GetNameInfoW: {
            frame.endpoint = readNetworkSockaddr(hp, frame.args[0], positiveI32Length(1),
                                                 &frame.ip, &frame.port,
                                                 &frame.portValid);
            frame.buffer = frame.args[2];
            frame.countOrLength = argU32(3);
            frame.transferredPtr = frame.args[4]; // service-name buffer
            frame.addressLengthPtr = argU32(5); // service-name character capacity
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::DnsQueryA:
        case NetworkProbeApi::DnsQueryW:
        case NetworkProbeApi::DnsQueryUtf8:
            frame.hostname = frame.wide ? readNetworkWide(hp, frame.args[0])
                                        : readNetworkAnsi(hp, frame.args[0]);
            frame.countOrLength = static_cast<uint16_t>(frame.args[1]); // DNS record type
            frame.buffer = frame.args[4];        // DNS_RECORD**
            frame.detail = "DNS record type " +
                           std::to_string(static_cast<uint16_t>(frame.countOrLength));
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::Connect:
        case NetworkProbeApi::WSAConnect:
            frame.endpoint = readNetworkSockaddr(hp, frame.args[1], positiveI32Length(2),
                                                 &frame.ip, &frame.port,
                                                 &frame.portValid);
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::CloseSocket:
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::Send:
        case NetworkProbeApi::SendTo: {
            const int32_t requested = argI32(2);
            frame.requestedLengthValid = requested >= 0;
            frame.requestedLength = requested >= 0 ? static_cast<uint32_t>(requested) : 0u;
            frame.payload = readNetworkPayload(hp, frame.args[1], frame.requestedLength);
            frame.payloadTruncated = frame.payload.size() < frame.requestedLength;
            if (api == NetworkProbeApi::SendTo)
                frame.endpoint = readNetworkSockaddr(hp, frame.args[4], positiveI32Length(5),
                                                     &frame.ip, &frame.port,
                                                     &frame.portValid);
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::WSASend:
        case NetworkProbeApi::WSASendTo:
            frame.buffers = frame.args[1];
            frame.countOrLength = argU32(2);
            frame.transferredPtr = frame.args[3];
            frame.payload = readNetworkWsabufs(hp, wow64, frame.buffers,
                                               frame.countOrLength, UINT64_MAX,
                                               &frame.requestedLength,
                                               &frame.payloadTruncated,
                                               &frame.requestedLengthValid);
            if (api == NetworkProbeApi::WSASendTo)
                frame.endpoint = readNetworkSockaddr(hp, frame.args[5], positiveI32Length(6),
                                                     &frame.ip, &frame.port,
                                                     &frame.portValid);
            frame.async = frame.args[NetworkOverlappedArgumentIndex(api)] != 0;
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::Recv:
        case NetworkProbeApi::RecvFrom: {
            frame.buffer = frame.args[1];
            const int32_t requested = argI32(2);
            frame.requestedLengthValid = requested >= 0;
            frame.countOrLength = requested >= 0 ? static_cast<uint32_t>(requested) : 0u;
            frame.requestedLength = frame.countOrLength;
            if (api == NetworkProbeApi::RecvFrom) {
                frame.addressPtr = frame.args[4];
                frame.addressLengthPtr = frame.args[5];
            }
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::WSARecv:
        case NetworkProbeApi::WSARecvFrom:
            frame.buffers = frame.args[1];
            frame.countOrLength = argU32(2);
            frame.transferredPtr = frame.args[3];
            (void)readNetworkWsabufs(hp, wow64, frame.buffers,
                                     frame.countOrLength, 0,
                                     &frame.requestedLength, nullptr,
                                     &frame.requestedLengthValid);
            if (api == NetworkProbeApi::WSARecvFrom) {
                frame.addressPtr = frame.args[5];
                frame.addressLengthPtr = frame.args[6];
            }
            frame.async = frame.args[NetworkOverlappedArgumentIndex(api)] != 0;
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpOpen:
            frame.handle = 0;
            frame.detail = readNetworkWide(hp, frame.args[0]);
            frame.async = NetworkHttpSessionIsAsync(argU32(4));
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::InternetOpenA:
        case NetworkProbeApi::InternetOpenW:
            frame.handle = 0;
            frame.detail = frame.wide ? readNetworkWide(hp, frame.args[0])
                                      : readNetworkAnsi(hp, frame.args[0]);
            frame.async = NetworkHttpSessionIsAsync(argU32(4));
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpConnect:
            frame.hostname = readNetworkWide(hp, frame.args[1]);
            frame.port = static_cast<uint16_t>(frame.args[2]);
            frame.portValid = true; // INTERNET_PORT is a 16-bit value, including valid zero.
            if (NetworkLooksLikeIp(frame.hostname)) frame.ip = frame.hostname;
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::InternetConnectA:
        case NetworkProbeApi::InternetConnectW:
            frame.hostname = frame.wide ? readNetworkWide(hp, frame.args[1])
                                        : readNetworkAnsi(hp, frame.args[1]);
            frame.port = static_cast<uint16_t>(frame.args[2]);
            frame.portValid = true; // INTERNET_PORT is a 16-bit value, including valid zero.
            if (NetworkLooksLikeIp(frame.hostname)) frame.ip = frame.hostname;
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpOpenRequest:
        case NetworkProbeApi::HttpOpenRequestA:
        case NetworkProbeApi::HttpOpenRequestW:
            frame.parent = frame.args[0];
            frame.method = api == NetworkProbeApi::WinHttpOpenRequest || frame.wide
                         ? readNetworkWide(hp, frame.args[1]) : readNetworkAnsi(hp, frame.args[1]);
            frame.object = api == NetworkProbeApi::WinHttpOpenRequest || frame.wide
                         ? readNetworkWide(hp, frame.args[2]) : readNetworkAnsi(hp, frame.args[2]);
            frame.path = frame.object;
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpAddRequestHeaders:
        case NetworkProbeApi::HttpAddRequestHeadersA:
        case NetworkProbeApi::HttpAddRequestHeadersW: {
            const uint32_t headerChars = static_cast<uint32_t>(frame.args[2]);
            const size_t headerLimit = headerChars == UINT32_MAX
                                     ? kNetworkObservationTextCap : headerChars;
            bool headerHitLimit = false;
            frame.detail = api == NetworkProbeApi::WinHttpAddRequestHeaders || frame.wide
                         ? readNetworkWide(hp, frame.args[1], headerLimit, &headerHitLimit)
                         : readNetworkAnsi(hp, frame.args[1], headerLimit, &headerHitLimit);
            frame.payloadTruncated = (headerChars != UINT32_MAX &&
                                      headerChars > kNetworkObservationTextCap) ||
                                     (headerChars == UINT32_MAX && headerHitLimit);
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::InternetOpenUrlA:
        case NetworkProbeApi::InternetOpenUrlW:
            frame.parent = frame.args[0];
            frame.object = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            {
                NetworkUrlParts url;
                if (ParseNetworkUrl(frame.object, url)) {
                    frame.hostname = std::move(url.hostname);
                    frame.ip = std::move(url.ip);
                    frame.port = url.port;
                    frame.portValid = url.portValid;
                    frame.path = std::move(url.path);
                }
            }
            {
                const uint32_t headerChars = static_cast<uint32_t>(frame.args[3]);
                const size_t headerLimit = headerChars == UINT32_MAX
                                         ? kNetworkObservationTextCap : headerChars;
                bool headerHitLimit = false;
                frame.detail = frame.wide
                             ? readNetworkWide(hp, frame.args[2], headerLimit, &headerHitLimit)
                             : readNetworkAnsi(hp, frame.args[2], headerLimit, &headerHitLimit);
                frame.payloadTruncated = (headerChars != UINT32_MAX &&
                                          headerChars > kNetworkObservationTextCap) ||
                                         (headerChars == UINT32_MAX && headerHitLimit);
            }
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpSendRequest:
        case NetworkProbeApi::HttpSendRequestA:
        case NetworkProbeApi::HttpSendRequestW: {
            const uint32_t headerChars = static_cast<uint32_t>(frame.args[2]);
            const size_t headerLimit = headerChars == UINT32_MAX
                                     ? kNetworkObservationTextCap : headerChars;
            bool headerHitLimit = false;
            frame.detail = api == NetworkProbeApi::WinHttpSendRequest || frame.wide
                         ? readNetworkWide(hp, frame.args[1], headerLimit, &headerHitLimit)
                         : readNetworkAnsi(hp, frame.args[1], headerLimit, &headerHitLimit);
            // DWORD stack arguments only guarantee their low 32 bits on Win64;
            // do not treat stale upper home-slot bytes as part of the length.
            frame.requestedLength = static_cast<uint32_t>(frame.args[4]);
            frame.requestedLengthValid = true;
            frame.payload = readNetworkPayload(hp, frame.args[3], frame.requestedLength);
            frame.payloadTruncated = frame.payload.size() < frame.requestedLength ||
                                     (headerChars != UINT32_MAX &&
                                      headerChars > kNetworkObservationTextCap) ||
                                     (headerChars == UINT32_MAX && headerHitLimit);
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::HttpSendRequestExA:
        case NetworkProbeApi::HttpSendRequestExW: {
            frame.buffers = frame.args[1];
            uint64_t body = 0, headers = 0;
            uint32_t bodyLength = 0, headersLength = 0;
            if (readInternetBuffer(hp, wow64, frame.buffers, body, bodyLength,
                                   &headers, &headersLength)) {
                frame.payload = readNetworkPayload(hp, body, bodyLength);
                frame.requestedLength = bodyLength;
                frame.requestedLengthValid = true;
                frame.payloadTruncated = frame.payload.size() < bodyLength ||
                                         headersLength > kNetworkObservationTextCap;
                frame.detail = frame.wide
                             ? readNetworkWide(hp, headers, headersLength)
                             : readNetworkAnsi(hp, headers, headersLength);
            }
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::HttpEndRequestA:
        case NetworkProbeApi::HttpEndRequestW:
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpWriteData:
        case NetworkProbeApi::InternetWriteFile:
            frame.requestedLength = argU32(2);
            frame.requestedLengthValid = true;
            frame.payload = readNetworkPayload(hp, frame.args[1], frame.requestedLength);
            frame.payloadTruncated = frame.payload.size() < frame.requestedLength;
            frame.transferredPtr = frame.args[3];
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpReceiveResponse:
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpReadData:
        case NetworkProbeApi::InternetReadFile:
            frame.buffer = frame.args[1];
            frame.countOrLength = argU32(2);
            frame.requestedLength = frame.countOrLength;
            frame.requestedLengthValid = true;
            frame.transferredPtr = frame.args[3];
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::InternetReadFileExA:
        case NetworkProbeApi::InternetReadFileExW: {
            frame.buffers = frame.args[1];
            frame.async = frame.async || (argU32(2) & 0x1u) != 0; // IRF_ASYNC
            uint64_t requestedBuffer = 0;
            uint32_t requestedLength = 0;
            if (readInternetBuffer(hp, wow64, frame.buffers,
                                   requestedBuffer, requestedLength)) {
                frame.requestedLength = requestedLength;
                frame.requestedLengthValid = true;
            }
            (void)queueReturn(std::move(frame));
            return;
        }
        case NetworkProbeApi::WinHttpQueryHeaders:
            frame.buffer = frame.args[3];
            frame.transferredPtr = frame.args[4];
            if (frame.transferredPtr) {
                uint32_t capacity = 0;
                if (readRemoteExact(hp, frame.transferredPtr, &capacity, sizeof(capacity))) {
                    frame.countOrLength = capacity;
                    frame.requestedLength = capacity;
                    frame.requestedLengthValid = true;
                }
            }
            frame.detail = "query level " + std::to_string(static_cast<uint32_t>(frame.args[1]));
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::HttpQueryInfoA:
        case NetworkProbeApi::HttpQueryInfoW:
            frame.buffer = frame.args[2];
            frame.transferredPtr = frame.args[3];
            if (frame.transferredPtr) {
                uint32_t capacity = 0;
                if (readRemoteExact(hp, frame.transferredPtr, &capacity, sizeof(capacity))) {
                    frame.countOrLength = capacity;
                    frame.requestedLength = capacity;
                    frame.requestedLengthValid = true;
                }
            }
            frame.detail = "query level " + std::to_string(static_cast<uint32_t>(frame.args[1]));
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::WinHttpCloseHandle:
        case NetworkProbeApi::InternetCloseHandle:
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::UrlDownloadToFileA:
        case NetworkProbeApi::UrlDownloadToFileW:
            frame.object = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            {
                NetworkUrlParts url;
                if (ParseNetworkUrl(frame.object, url)) {
                    frame.hostname = std::move(url.hostname); frame.ip = std::move(url.ip);
                    frame.port = url.port; frame.portValid = url.portValid;
                    frame.path = std::move(url.path);
                }
            }
            frame.detail = frame.wide ? readNetworkWide(hp, frame.args[2])
                                      : readNetworkAnsi(hp, frame.args[2]);
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::UrlDownloadToCacheFileA:
        case NetworkProbeApi::UrlDownloadToCacheFileW:
            frame.object = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            {
                NetworkUrlParts url;
                if (ParseNetworkUrl(frame.object, url)) {
                    frame.hostname = std::move(url.hostname); frame.ip = std::move(url.ip);
                    frame.port = url.port; frame.portValid = url.portValid;
                    frame.path = std::move(url.path);
                }
            }
            frame.buffer = frame.args[2];
            frame.countOrLength = argU32(3);
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::UrlOpenStreamA:
        case NetworkProbeApi::UrlOpenStreamW:
            frame.object = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            {
                NetworkUrlParts url;
                if (ParseNetworkUrl(frame.object, url)) {
                    frame.hostname = std::move(url.hostname); frame.ip = std::move(url.ip);
                    frame.port = url.port; frame.portValid = url.portValid;
                    frame.path = std::move(url.path);
                }
            }
            (void)queueReturn(std::move(frame));
            return;
        case NetworkProbeApi::UrlOpenBlockingStreamA:
        case NetworkProbeApi::UrlOpenBlockingStreamW:
            frame.object = frame.wide ? readNetworkWide(hp, frame.args[1])
                                      : readNetworkAnsi(hp, frame.args[1]);
            {
                NetworkUrlParts url;
                if (ParseNetworkUrl(frame.object, url)) {
                    frame.hostname = std::move(url.hostname); frame.ip = std::move(url.ip);
                    frame.port = url.port; frame.portValid = url.portValid;
                    frame.path = std::move(url.path);
                }
            }
            frame.buffer = frame.args[2]; // IStream**
            (void)queueReturn(std::move(frame));
            return;
        default:
            return;
    }
}

// Restore one shared return instruction, pop exactly the calling thread's top
// frame, publish its typed result, and tell the event loop whether peers still
// reference this site and therefore require it to be re-armed after one TF step.
bool Debugger::netTapOnReturn(uint64_t addr, uint32_t tid, bool* transitionFailed) {
    if (transitionFailed) *transitionFailed = false;
    HANDLE hp = (HANDLE)hProcess_;
    NetworkReturnBp site;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        auto it = networkReturnBps_.find(addr);
        if (it == networkReturnBps_.end()) return false;
        site = it->second;
    }
    const auto th = threads_.find(tid);
    if (th == threads_.end() || !ctxSetRip(th->second, addr)) {
        if (transitionFailed) *transitionFailed = true;
        if (th == threads_.end()) recordExecutionFailure("network return thread disappeared; target remains paused");
        return false;
    }
    if (site.ownsByte && !replaceByteIfEqual(hp, addr, 0xCC, site.orig)) {
        if (transitionFailed) *transitionFailed = true;
        return false;
    }
    { std::lock_guard lock(mtx_);
      if (auto at = networkReturnBps_.find(addr); at != networkReturnBps_.end()) at->second.armed = false; }
    auto finishSite = [&]() {
        const bool shared = networkPendingReturns_.references(addr) != 0;
        if (!shared) {
            std::lock_guard<std::mutex> lk(mtx_);
            networkReturnBps_.erase(addr);
            auto at = std::lower_bound(networkReturnBpAddrs_.begin(),
                                       networkReturnBpAddrs_.end(), addr);
            if (at != networkReturnBpAddrs_.end() && *at == addr)
                networkReturnBpAddrs_.erase(at);
        }
        return shared;
    };
    NetworkPendingFrame frame;
    if (!networkPendingReturns_.pop(tid, addr, frame)) return finishSite();
    if (!frame.payload.empty()) {
        std::lock_guard<std::mutex> lk(mtx_);
        networkPendingPayloadBytes_ -= (std::min<uint64_t>)(
            networkPendingPayloadBytes_, frame.payload.size());
    }
    Registers r;
    if (!ctxReadFull(th->second, r)) return finishSite();
    const bool wow64 = isWow64_.load();
    const int32_t result32 = static_cast<int32_t>(static_cast<uint32_t>(r.rax));
    const uint64_t rawResult = wow64 ? static_cast<uint32_t>(r.rax) : r.rax;
    NetworkObservationEvent event;
    event.tickMs = GetTickCount(); event.tid = tid; event.api = frame.api;
    event.caller = frame.caller; event.handle = frame.handle;
    event.result = result32;
    SetNetworkObservedRawResult(event, r.rax, wow64);
    event.hostname = frame.hostname; event.ip = frame.ip;
    event.port = frame.port; event.portValid = frame.portValid;
    event.endpoint = frame.endpoint; event.method = frame.method;
    event.path = frame.path; event.object = frame.object; event.detail = frame.detail;
    event.requestedBytes = frame.requestedLength;
    event.requestedBytesValid = frame.requestedLengthValid;
    event.asyncPartial = frame.async;
    event.truncated = frame.payloadTruncated;

    auto applyLineage = [&]() {
        const NetworkHandleRecord lineage = networkHandleLineage_.resolve(frame.handle);
        if (event.hostname.empty()) event.hostname = lineage.hostname;
        if (event.ip.empty()) event.ip = lineage.ip;
        if (!event.portValid && lineage.portValid) {
            event.port = lineage.port;
            event.portValid = true;
        }
        if (event.method.empty()) event.method = lineage.method;
        if (event.path.empty()) event.path = lineage.path;
        if (event.object.empty()) event.object = lineage.object;
        if (event.endpoint.empty()) event.endpoint = lineage.endpoint;
        if (event.endpoint.empty()) {
            const std::string& host = !event.ip.empty() ? event.ip : event.hostname;
            event.endpoint = formatNetworkHostPort(host, event.port, event.portValid);
        }
        event.asyncPartial = event.asyncPartial || lineage.async;
    };
    auto readTransferred = [&](uint32_t& transferred) {
        transferred = 0;
        return frame.transferredPtr &&
               readRemoteExact(hp, frame.transferredPtr, &transferred,
                               sizeof(transferred));
    };
    auto captureTransferred = [&]() {
        uint32_t transferred = 0;
        if (!readTransferred(transferred)) return false;
        event.transferred = transferred;
        event.transferredValid = true;
        return true;
    };
    auto putHandleState = [&](uint64_t handle, NetworkHandleRecord record) {
        if (networkHandleLineage_.put(handle, std::move(record))) return true;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            networkCoverage_.handleStatesDropped =
                NetworkHandleStatesDropped(networkHandleLineage_);
            if (networkCoverage_.handleStatesDropped == 1)
                networkCoverage_.limitations.push_back(
                    "HTTP/socket handle-lineage state exceeded the 4,096-record cap; some descendant metadata is unavailable.");
        }
        if (!event.detail.empty()) event.detail += "; ";
        event.detail += "handle-lineage state dropped at bounded capacity";
        return false;
    };
    switch (frame.api) {
        case NetworkProbeApi::ResolveAddrInfoA:
        case NetworkProbeApi::ResolveAddrInfoW: {
            event.stage = NetworkObservationStage::NameResolution;
            event.result = result32;
            if (result32 == 0 && frame.buffer) {
                const NetworkCallContext pointerContext{ isWow64_.load(), 0, {} };
                const NetworkMemoryReader read = [hp](uint64_t address, void* out, size_t size) {
                    return readRemoteExact(hp, address, out, size);
                };
                uint64_t cursor = 0;
                if (ReadNetworkPointer(pointerContext, read, frame.buffer, cursor)) {
                    std::string endpoints;
                    for (size_t i = 0; cursor && i < 8; ++i) {
                        uint32_t addrLen = 0;
                        uint64_t addrPtr = 0, next = 0;
                        const uint64_t addrLenAt = cursor + 16;
                        (void)readRemoteExact(hp, addrLenAt, &addrLen, sizeof(addrLen));
                        const uint64_t addrPtrAt = cursor + (isWow64_.load() ? 24u : 32u);
                        const uint64_t nextAt = cursor + (isWow64_.load() ? 28u : 40u);
                        if (ReadNetworkPointer(pointerContext, read, addrPtrAt, addrPtr)) {
                            std::string oneIp;
                            uint16_t onePort = 0;
                            bool onePortValid = false;
                            const std::string one = readNetworkSockaddr(
                                hp, addrPtr, addrLen, &oneIp, &onePort, &onePortValid);
                            if (!one.empty()) {
                                if (event.ip.empty()) {
                                    event.ip = std::move(oneIp);
                                    event.port = onePort;
                                    event.portValid = onePortValid;
                                }
                                if (!endpoints.empty()) endpoints += ", ";
                                endpoints += one;
                            }
                        }
                        if (!ReadNetworkPointer(pointerContext, read, nextAt, next) || next == cursor) break;
                        cursor = next;
                    }
                    event.endpoint = BoundNetworkText(std::move(endpoints));
                }
            }
            break;
        }
        case NetworkProbeApi::GetAddrInfoExA:
        case NetworkProbeApi::GetAddrInfoExW: {
            event.stage = NetworkObservationStage::NameResolution;
            event.asyncPartial = frame.async;
            if (result32 == 0 && frame.buffer && !frame.async) {
                const bool narrow = isWow64_.load();
                const NetworkCallContext pointerContext{narrow, 0, {}};
                const NetworkMemoryReader read = [hp](uint64_t address, void* out, size_t size) {
                    return readRemoteExact(hp, address, out, size);
                };
                uint64_t cursor = 0;
                if (ReadNetworkPointer(pointerContext, read, frame.buffer, cursor)) {
                    std::string endpoints;
                    for (size_t i = 0; cursor && i < 8; ++i) {
                        uint32_t addrLen = 0;
                        uint64_t addrPtr = 0, next = 0;
                        (void)readRemoteExact(hp, cursor + 16, &addrLen, sizeof(addrLen));
                        const uint64_t addrAt = cursor + (narrow ? 24u : 32u);
                        const uint64_t nextAt = cursor + (narrow ? 40u : 64u);
                        if (ReadNetworkPointer(pointerContext, read, addrAt, addrPtr)) {
                            std::string oneIp;
                            uint16_t onePort = 0;
                            bool onePortValid = false;
                            const std::string one = readNetworkSockaddr(
                                hp, addrPtr, addrLen, &oneIp, &onePort, &onePortValid);
                            if (!one.empty()) {
                                if (event.ip.empty()) {
                                    event.ip = std::move(oneIp);
                                    event.port = onePort;
                                    event.portValid = onePortValid;
                                }
                                if (!endpoints.empty()) endpoints += ", ";
                                endpoints += one;
                            }
                        }
                        if (!ReadNetworkPointer(pointerContext, read, nextAt, next) || next == cursor)
                            break;
                        cursor = next;
                    }
                    event.endpoint = BoundNetworkText(std::move(endpoints));
                }
            }
            break;
        }
        case NetworkProbeApi::GetHostByName:
            event.stage = NetworkObservationStage::NameResolution;
            event.result = static_cast<int64_t>(rawResult);
            if (rawResult)
                event.endpoint = readNetworkHostent(hp, isWow64_.load(), rawResult,
                                                    &event.ip);
            break;
        case NetworkProbeApi::GetNameInfoA:
        case NetworkProbeApi::GetNameInfoW:
            event.stage = NetworkObservationStage::NameResolution;
            if (result32 == 0) {
                bool hostHitLimit = false, serviceHitLimit = false;
                event.hostname = frame.wide
                    ? readNetworkWide(hp, frame.buffer,
                                      static_cast<size_t>((std::min<uint64_t>)(
                                          frame.countOrLength, kNetworkObservationTextCap)),
                                      &hostHitLimit)
                    : readNetworkAnsi(hp, frame.buffer,
                                      static_cast<size_t>((std::min<uint64_t>)(
                                          frame.countOrLength, kNetworkObservationTextCap)),
                                      &hostHitLimit);
                const std::string service = frame.wide
                    ? readNetworkWide(hp, frame.transferredPtr,
                                      static_cast<size_t>((std::min<uint64_t>)(
                                          frame.addressLengthPtr, kNetworkObservationTextCap)),
                                      &serviceHitLimit)
                    : readNetworkAnsi(hp, frame.transferredPtr,
                                      static_cast<size_t>((std::min<uint64_t>)(
                                          frame.addressLengthPtr, kNetworkObservationTextCap)),
                                      &serviceHitLimit);
                event.truncated = event.truncated || hostHitLimit || serviceHitLimit;
                if (!service.empty()) event.detail = "service " + service;
            }
            break;
        case NetworkProbeApi::DnsQueryA:
        case NetworkProbeApi::DnsQueryW:
        case NetworkProbeApi::DnsQueryUtf8:
            event.stage = NetworkObservationStage::NameResolution;
            break;
        case NetworkProbeApi::Connect:
        case NetworkProbeApi::WSAConnect:
            event.stage = NetworkObservationStage::Connect;
            event.direction = NetworkDirection::Outbound;
            event.result = result32;
            if (result32 == 0 && frame.handle) {
                NetworkHandleRecord socket;
                socket.kind = NetworkHandleKind::Socket;
                socket.endpoint = frame.endpoint; socket.ip = frame.ip;
                socket.port = frame.port; socket.portValid = frame.portValid;
                (void)putHandleState(frame.handle, std::move(socket));
            }
            break;
        case NetworkProbeApi::Send:
        case NetworkProbeApi::SendTo:
            event.stage = NetworkObservationStage::Send;
            event.direction = NetworkDirection::Outbound;
            if (result32 >= 0) {
                event.transferred = static_cast<uint32_t>(result32);
                event.transferredValid = true;
            }
            if (result32 > 0) {
                if (event.transferred < frame.payload.size()) frame.payload.resize(event.transferred);
            }
            event.payload = std::move(frame.payload);
            event.truncated = event.truncated || event.transferred > event.payload.size();
            event.payloadOpaque = true; // raw Winsock may contain TLS ciphertext; bytes remain exact
            applyLineage();
            break;
        case NetworkProbeApi::WSASend:
        case NetworkProbeApi::WSASendTo:
            event.stage = NetworkObservationStage::Send;
            event.direction = NetworkDirection::Outbound;
            if (result32 == 0) (void)captureTransferred();
            event.payload = std::move(frame.payload);
            if (event.transferred && event.transferred < event.payload.size()) event.payload.resize(event.transferred);
            event.truncated = event.truncated || event.transferred > event.payload.size();
            event.payloadOpaque = true;
            applyLineage();
            break;
        case NetworkProbeApi::Recv:
        case NetworkProbeApi::RecvFrom:
            event.stage = NetworkObservationStage::Receive;
            event.direction = NetworkDirection::Inbound;
            if (result32 >= 0) {
                event.transferred = static_cast<uint32_t>(result32);
                event.transferredValid = true;
            }
            if (result32 > 0) {
                event.payload = readNetworkPayload(hp, frame.buffer,
                    (std::min<uint64_t>)(event.transferred, frame.countOrLength));
            }
            if (result32 > 0 && frame.addressPtr && frame.addressLengthPtr) {
                int32_t length = 0;
                if (readRemoteExact(hp, frame.addressLengthPtr, &length, sizeof(length)) && length > 0)
                    event.endpoint = readNetworkSockaddr(
                        hp, frame.addressPtr, static_cast<uint32_t>(length),
                        &event.ip, &event.port, &event.portValid);
            }
            event.truncated = event.truncated || event.transferred > event.payload.size();
            event.payloadOpaque = true;
            applyLineage();
            break;
        case NetworkProbeApi::WSARecv:
        case NetworkProbeApi::WSARecvFrom:
            event.stage = NetworkObservationStage::Receive;
            event.direction = NetworkDirection::Inbound;
            if (result32 == 0) {
                (void)captureTransferred();
                event.payload = readNetworkWsabufs(hp, isWow64_.load(), frame.buffers,
                                                   frame.countOrLength, event.transferred);
            }
            if (result32 == 0 && frame.addressPtr && frame.addressLengthPtr) {
                int32_t length = 0;
                if (readRemoteExact(hp, frame.addressLengthPtr, &length, sizeof(length)) && length > 0)
                    event.endpoint = readNetworkSockaddr(
                        hp, frame.addressPtr, static_cast<uint32_t>(length),
                        &event.ip, &event.port, &event.portValid);
            }
            event.truncated = event.truncated || event.transferred > event.payload.size();
            event.payloadOpaque = true;
            applyLineage();
            break;
        case NetworkProbeApi::CloseSocket:
            event.stage = NetworkObservationStage::HandleClosed;
            applyLineage();
            if (result32 == 0) networkHandleLineage_.erase(frame.handle);
            break;
        case NetworkProbeApi::WinHttpOpen:
        case NetworkProbeApi::InternetOpenA:
        case NetworkProbeApi::InternetOpenW:
            event.stage = NetworkObservationStage::ProbeStatus;
            event.result = static_cast<int64_t>(rawResult);
            event.handle = rawResult;
            event.detail = rawResult ? "HTTP session opened" : "HTTP session open failed";
            event.asyncPartial = frame.async;
            if (rawResult) {
                NetworkHandleRecord record;
                record.kind = NetworkHandleKind::Session;
                record.async = frame.async;
                (void)putHandleState(rawResult, std::move(record));
            }
            break;
        case NetworkProbeApi::WinHttpConnect:
        case NetworkProbeApi::InternetConnectA:
        case NetworkProbeApi::InternetConnectW:
            event.stage = NetworkObservationStage::Connect;
            event.result = static_cast<int64_t>(rawResult);
            event.handle = rawResult;
            event.asyncPartial = networkHandleLineage_.resolve(frame.handle).async;
            if (rawResult) {
                NetworkHandleRecord record;
                record.kind = NetworkHandleKind::Connection; record.parent = frame.handle;
                record.hostname = frame.hostname; record.ip = frame.ip;
                record.port = frame.port; record.portValid = frame.portValid;
                (void)putHandleState(rawResult, std::move(record));
                event.endpoint = formatNetworkHostPort(
                    !event.ip.empty() ? event.ip : event.hostname,
                    event.port, event.portValid);
            }
            break;
        case NetworkProbeApi::WinHttpOpenRequest:
        case NetworkProbeApi::HttpOpenRequestA:
        case NetworkProbeApi::HttpOpenRequestW:
        case NetworkProbeApi::InternetOpenUrlA:
        case NetworkProbeApi::InternetOpenUrlW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.result = static_cast<int64_t>(rawResult);
            event.handle = rawResult;
            if (rawResult) {
                NetworkHandleRecord record;
                record.kind = NetworkHandleKind::Request;
                record.parent = frame.parent ? frame.parent : frame.handle;
                record.hostname = frame.hostname; record.ip = frame.ip;
                record.port = frame.port; record.portValid = frame.portValid;
                record.method = frame.method; record.path = frame.path;
                record.object = frame.object;
                (void)putHandleState(rawResult, std::move(record));
            }
            applyLineage();
            break;
        case NetworkProbeApi::WinHttpAddRequestHeaders:
        case NetworkProbeApi::HttpAddRequestHeadersA:
        case NetworkProbeApi::HttpAddRequestHeadersW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            applyLineage();
            break;
        case NetworkProbeApi::WinHttpSendRequest:
        case NetworkProbeApi::HttpSendRequestA:
        case NetworkProbeApi::HttpSendRequestW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.payload = std::move(frame.payload);
            applyLineage();
            break;
        case NetworkProbeApi::HttpSendRequestExA:
        case NetworkProbeApi::HttpSendRequestExW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.payload = std::move(frame.payload);
            applyLineage();
            break;
        case NetworkProbeApi::HttpEndRequestA:
        case NetworkProbeApi::HttpEndRequestW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.detail = "extended request body ended";
            applyLineage();
            break;
        case NetworkProbeApi::WinHttpWriteData:
        case NetworkProbeApi::InternetWriteFile:
            event.stage = NetworkObservationStage::Send;
            event.direction = NetworkDirection::Outbound;
            applyLineage();
            if (result32 != 0 && !event.asyncPartial)
                (void)captureTransferred();
            event.payload = std::move(frame.payload);
            if (result32 != 0 && event.transferred && event.transferred < event.payload.size())
                event.payload.resize(event.transferred);
            event.truncated = event.truncated || event.transferred > event.payload.size();
            break;
        case NetworkProbeApi::WinHttpReceiveResponse:
            event.stage = NetworkObservationStage::Response;
            event.direction = NetworkDirection::Inbound;
            applyLineage();
            break;
        case NetworkProbeApi::WinHttpReadData:
        case NetworkProbeApi::InternetReadFile:
            event.stage = NetworkObservationStage::Receive;
            event.direction = NetworkDirection::Inbound;
            applyLineage();
            if (result32 != 0 && !event.asyncPartial) {
                (void)captureTransferred();
                event.payload = readNetworkPayload(hp, frame.buffer,
                    (std::min<uint64_t>)(event.transferred, frame.countOrLength));
            }
            event.truncated = event.truncated || event.transferred > event.payload.size();
            break;
        case NetworkProbeApi::InternetReadFileExA:
        case NetworkProbeApi::InternetReadFileExW: {
            event.stage = NetworkObservationStage::Receive;
            event.direction = NetworkDirection::Inbound;
            applyLineage();
            uint64_t body = 0;
            uint32_t bodyLength = 0;
            if (result32 != 0 && !event.asyncPartial &&
                readInternetBuffer(hp, isWow64_.load(), frame.buffers, body, bodyLength)) {
                event.transferred = bodyLength;
                event.transferredValid = true;
                event.payload = readNetworkPayload(hp, body, bodyLength);
                event.truncated = event.truncated || bodyLength > event.payload.size();
            }
            break;
        }
        case NetworkProbeApi::WinHttpQueryHeaders:
        case NetworkProbeApi::HttpQueryInfoA:
        case NetworkProbeApi::HttpQueryInfoW:
            event.stage = NetworkObservationStage::Response;
            event.direction = NetworkDirection::Inbound;
            // On failure the size pointer is an updated required length, not a
            // claim that the caller supplied that capacity. Never read beyond
            // the entry-time buffer size (especially ERROR_INSUFFICIENT_BUFFER).
            if (result32 != 0) {
                (void)captureTransferred();
                const uint64_t readable = (std::min<uint64_t>)(
                    event.transferred, frame.countOrLength);
                event.payload = readNetworkPayload(hp, frame.buffer, readable);
                event.truncated = event.transferred > event.payload.size();
            }
            applyLineage();
            break;
        case NetworkProbeApi::UrlDownloadToFileA:
        case NetworkProbeApi::UrlDownloadToFileW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.object = frame.object;
            event.detail = "destination: " + frame.detail;
            break;
        case NetworkProbeApi::UrlDownloadToCacheFileA:
        case NetworkProbeApi::UrlDownloadToCacheFileW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.object = frame.object;
            if (result32 == 0)
                event.detail = "cache destination: " +
                    (frame.wide ? readNetworkWide(hp, frame.buffer)
                                : readNetworkAnsi(hp, frame.buffer));
            break;
        case NetworkProbeApi::UrlOpenStreamA:
        case NetworkProbeApi::UrlOpenStreamW:
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.object = frame.object;
            event.asyncPartial = true; // callback completion is outside this API return
            break;
        case NetworkProbeApi::UrlOpenBlockingStreamA:
        case NetworkProbeApi::UrlOpenBlockingStreamW: {
            event.stage = NetworkObservationStage::Request;
            event.direction = NetworkDirection::Outbound;
            event.object = frame.object;
            const NetworkCallContext pointerContext{isWow64_.load(), 0, {}};
            const NetworkMemoryReader read = [hp](uint64_t at, void* out, size_t size) {
                return readRemoteExact(hp, at, out, size);
            };
            uint64_t stream = 0;
            if (result32 == 0 && ReadNetworkPointer(pointerContext, read, frame.buffer, stream))
                event.handle = stream;
            break;
        }
        case NetworkProbeApi::WinHttpCloseHandle:
        case NetworkProbeApi::InternetCloseHandle:
            event.stage = NetworkObservationStage::HandleClosed;
            applyLineage();
            if (result32 != 0) networkHandleLineage_.erase(frame.handle);
            break;
        default:
            event.stage = NetworkObservationStage::ProbeStatus;
            break;
    }

    decorateNetworkEvent(event);
    writeNetworkObservationLog(event);
    pushNetworkEvent(std::move(event));

    return finishSite();
}


} // namespace ds
