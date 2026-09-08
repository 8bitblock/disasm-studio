#include "MemoryToolsTab.h"

#include "../Core/AtomicFile.h"
#include "../Core/AttachImagePolicy.h"
#include "../Core/MemCompare.h"
#include "../Ui/Fonts.h"
#include "../Ui/Icons.h"
#include "../Ui/Splitter.h"
#include "../Ui/Widgets.h"

#include "imgui.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commdlg.h>

#include <algorithm>
#include <array>
#include <bit>
#include <charconv>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <limits>
#include <numeric>
#include <set>
#include <sstream>
#include <unordered_set>

namespace ds {
namespace {

constexpr size_t kScanChunkBytes = 64u * 1024u;
constexpr size_t kPointerReadChunkBytes = 1u * 1024u * 1024u;
constexpr uint64_t kMiB = 1024ull * 1024ull;
constexpr uint64_t kInitialScanMemoryReserve = 512ull * kMiB;
constexpr uint64_t kRefineScanMemoryReserve = 256ull * kMiB;
constexpr uint32_t kMemPrivate = 0x00020000u;
constexpr uint32_t kMemMapped  = 0x00040000u;
constexpr uint32_t kMemImage   = 0x01000000u;

const char* const kValueKinds[] = {
    "Byte (1)", "2 Bytes", "4 Bytes", "8 Bytes", "Float", "Double",
    "Array of byte", "UTF-8 text", "UTF-16 text"
};

const char* const kScanModes[] = {
    "Exact value", "Not equal to", "Greater than value", "Less than value",
    "Between values", "Changed", "Unchanged", "Increased", "Decreased",
    "Increased by", "Decreased by", "Unknown initial value"
};

const char* const kMemoryTypeNames[] = {
    "u8", "i8", "u16", "i16", "u32", "i32", "u64", "i64",
    "float", "double", "bytes", "UTF-8", "UTF-16"
};

const char* const kFreezeModes[] = { "None", "Constant", "Minimum", "Maximum" };

uint64_t saturatingAdd(uint64_t left, uint64_t right) {
    return left > UINT64_MAX - right ? UINT64_MAX : left + right;
}

uint64_t saturatingMultiply(uint64_t left, uint64_t right) {
    return left && right > UINT64_MAX / left ? UINT64_MAX : left * right;
}

uint64_t conservativeInitialScanCap(uint64_t requested, bool& limited) {
    limited = false;
    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    uint64_t safe = 256ull * kMiB; // fail-safe when memory telemetry is unavailable
    if (GlobalMemoryStatusEx(&memory)) {
        // A dense snapshot is bytes + bitmap, and atomic refinement clones it.
        // Reserving two additional units plus application headroom avoids
        // committing a scan whose very next operation would predictably thrash.
        safe = memory.ullAvailPhys > kInitialScanMemoryReserve
            ? (memory.ullAvailPhys - kInitialScanMemoryReserve) / 3ull
            : 16ull * kMiB;
    }
    safe = (std::max)(safe, 16ull * kMiB);
    const uint64_t admitted = (std::min)(requested, safe);
    limited = admitted < requested;
    return admitted;
}

uint64_t retainedScanBytes(const MemoryScanSnapshot& snapshot) {
    uint64_t bytes = saturatingMultiply(
        static_cast<uint64_t>(snapshot.chunks().capacity()),
        sizeof(MemoryScanChunk));
    for (const MemoryScanChunk& chunk : snapshot.chunks()) {
        bytes = saturatingAdd(bytes, static_cast<uint64_t>(chunk.bytes.capacity()));
        const uint64_t bitmap = saturatingMultiply(
            static_cast<uint64_t>(chunk.candidateBitmap.capacity()),
            sizeof(uint64_t));
        bytes = saturatingAdd(bytes, bitmap);
    }
    return bytes;
}

bool memoryAdmitsAtomicRefinement(const MemoryScanSnapshot& snapshot,
                                  uint64_t& retained, uint64_t& available) {
    retained = retainedScanBytes(snapshot);
    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    if (!GlobalMemoryStatusEx(&memory)) {
        available = 0;
        return retained <= 256ull * kMiB;
    }
    available = memory.ullAvailPhys;
    const uint64_t copyAllowance = saturatingAdd(retained, retained / 4ull);
    const uint64_t required = saturatingAdd(copyAllowance,
                                            kRefineScanMemoryReserve);
    return available >= required;
}

bool isIntegerKind(int kind) { return kind >= 0 && kind <= 3; }

MemoryValueType valueTypeForKind(int kind, bool signedInteger) {
    switch (kind) {
        case 0: return signedInteger ? MemoryValueType::Int8 : MemoryValueType::UInt8;
        case 1: return signedInteger ? MemoryValueType::Int16 : MemoryValueType::UInt16;
        case 2: return signedInteger ? MemoryValueType::Int32 : MemoryValueType::UInt32;
        case 3: return signedInteger ? MemoryValueType::Int64 : MemoryValueType::UInt64;
        case 4: return MemoryValueType::Float32;
        case 5: return MemoryValueType::Float64;
        case 6: return MemoryValueType::ByteArray;
        case 7: return MemoryValueType::Utf8;
        case 8: return MemoryValueType::Utf16Le;
        default:return MemoryValueType::UInt32;
    }
}

bool controlsForValueType(MemoryValueType type, int& kind,
                          bool& signedInteger) noexcept {
    signedInteger = false;
    switch (type) {
        case MemoryValueType::UInt8:    kind = 0; return true;
        case MemoryValueType::Int8:     kind = 0; signedInteger = true; return true;
        case MemoryValueType::UInt16:   kind = 1; return true;
        case MemoryValueType::Int16:    kind = 1; signedInteger = true; return true;
        case MemoryValueType::UInt32:   kind = 2; return true;
        case MemoryValueType::Int32:    kind = 2; signedInteger = true; return true;
        case MemoryValueType::UInt64:   kind = 3; return true;
        case MemoryValueType::Int64:    kind = 3; signedInteger = true; return true;
        case MemoryValueType::Float32:  kind = 4; return true;
        case MemoryValueType::Float64:  kind = 5; return true;
        case MemoryValueType::ByteArray:kind = 6; return true;
        case MemoryValueType::Utf8:     kind = 7; return true;
        case MemoryValueType::Utf16Le:  kind = 8; return true;
        default: return false;
    }
}

bool scanModeNeedsValue(MemoryScanMode mode) {
    return mode == MemoryScanMode::Exact || mode == MemoryScanMode::NotEqual ||
           mode == MemoryScanMode::GreaterThanValue ||
           mode == MemoryScanMode::LessThanValue ||
           mode == MemoryScanMode::Between ||
           mode == MemoryScanMode::IncreasedBy ||
           mode == MemoryScanMode::DecreasedBy;
}

bool scanModeNeedsSecondValue(MemoryScanMode mode) {
    return mode == MemoryScanMode::Between;
}

bool scanModeUsesPrevious(MemoryScanMode mode) {
    return mode == MemoryScanMode::Changed || mode == MemoryScanMode::Unchanged ||
           mode == MemoryScanMode::Increased || mode == MemoryScanMode::Decreased ||
           mode == MemoryScanMode::IncreasedBy || mode == MemoryScanMode::DecreasedBy;
}

bool parseHexAddress(std::string_view text, uint64_t& value) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())))
        text.remove_prefix(1);
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())))
        text.remove_suffix(1);
    if (text.empty() || text.front() == '-' || text.front() == '+') return false;
    if (text.size() >= 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
        text.remove_prefix(2);
    if (text.empty()) return false;
    uint64_t parsed = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed, 16);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) return false;
    value = parsed;
    return true;
}

std::string hexAddress(uint64_t address) {
    char buffer[32]{};
    std::snprintf(buffer, sizeof(buffer), "0x%llX",
                  static_cast<unsigned long long>(address));
    return buffer;
}

std::string compactCount(uint64_t value) {
    char buffer[64]{};
    if (value >= 1'000'000'000ull)
        std::snprintf(buffer, sizeof(buffer), "%.2fB", value / 1'000'000'000.0);
    else if (value >= 1'000'000ull)
        std::snprintf(buffer, sizeof(buffer), "%.2fM", value / 1'000'000.0);
    else if (value >= 1'000ull)
        std::snprintf(buffer, sizeof(buffer), "%.1fK", value / 1'000.0);
    else
        std::snprintf(buffer, sizeof(buffer), "%llu",
                      static_cast<unsigned long long>(value));
    return buffer;
}

std::string formatMemoryValue(MemoryValueType type,
                              const std::vector<uint8_t>& bytes,
                              bool hexadecimal = false,
                              bool nullTerminated = false) {
    MemoryScanValue value;
    value.type = type;
    value.bytes = bytes;
    value.nullTerminated = nullTerminated;
    return FormatMemoryScanValue(value, { hexadecimal });
}

std::string formatMemoryValue(MemoryValueType type, const uint8_t* bytes,
                              size_t size, bool hexadecimal = false,
                              bool nullTerminated = false) {
    if (!bytes || !size) return {};
    return formatMemoryValue(type, std::vector<uint8_t>(bytes, bytes + size),
                             hexadecimal, nullTerminated);
}

bool caseContains(std::string_view haystack, std::string_view needle) {
    if (needle.empty()) return true;
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
        [](char a, char b) {
            return std::tolower(static_cast<unsigned char>(a)) ==
                   std::tolower(static_cast<unsigned char>(b));
        }) != haystack.end();
}

bool moduleContains(const MemoryTableModuleView& module, uint64_t address) {
    return module.base && module.size && address >= module.base &&
           address - module.base < module.size;
}

const MemoryTableModuleView* containingModule(
    const std::vector<MemoryTableModuleView>& modules, uint64_t address) {
    for (const auto& module : modules)
        if (moduleContains(module, address)) return &module;
    return nullptr;
}

std::string moduleAddressLabel(const std::vector<MemoryTableModuleView>& modules,
                               uint64_t address) {
    if (const auto* module = containingModule(modules, address)) {
        const std::string& name = module->name.empty() ? module->path : module->name;
        char buffer[256]{};
        std::snprintf(buffer, sizeof(buffer), "%s+0x%llX", name.c_str(),
                      static_cast<unsigned long long>(address - module->base));
        return buffer;
    }
    return hexAddress(address);
}

std::string protectionLabel(const MemoryToolsTab::TargetRegion& region) {
    char buffer[16]{};
    std::snprintf(buffer, sizeof(buffer), "%c%c%c%s%s",
                  region.readable ? 'R' : '-', region.writable ? 'W' : '-',
                  region.executable ? 'X' : '-', region.copyOnWrite ? "C" : "-",
                  region.guarded ? "G" : "-");
    return buffer;
}

const char* regionTypeLabel(uint32_t type) {
    if (type == kMemPrivate) return "Private";
    if (type == kMemMapped) return "Mapped";
    if (type == kMemImage) return "Image";
    return "Other";
}

uint64_t hashBytes(uint64_t hash, const void* bytes, size_t size) {
    const auto* p = static_cast<const uint8_t*>(bytes);
    for (size_t i = 0; i < size; ++i) {
        hash ^= p[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

uint64_t hashString(uint64_t hash, const std::string& value) {
    return hashBytes(hash, value.data(), value.size());
}

struct StringInputUserData {
    std::string* value = nullptr;
    ImGuiInputTextCallback chained = nullptr;
    void* chainedData = nullptr;
};

int stringInputCallback(ImGuiInputTextCallbackData* data) {
    auto* user = static_cast<StringInputUserData*>(data->UserData);
    if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
        std::string* value = user->value;
        value->resize(static_cast<size_t>(data->BufTextLen));
        data->Buf = value->data();
    } else if (user->chained) {
        data->UserData = user->chainedData;
        return user->chained(data);
    }
    return 0;
}

bool inputTextString(const char* label, std::string& value,
                     ImGuiInputTextFlags flags = 0) {
    flags |= ImGuiInputTextFlags_CallbackResize;
    StringInputUserData user{ &value, nullptr, nullptr };
    return ImGui::InputText(label, value.data(), value.capacity() + 1, flags,
                            stringInputCallback, &user);
}

std::wstring wideFromUtf8(std::string_view input) {
    if (input.empty()) return {};
    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring output(static_cast<size_t>(needed), L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(),
                            static_cast<int>(input.size()), output.data(), needed) != needed)
        return {};
    return output;
}

bool regionSelected(const MemoryToolsTab::TargetRegion& region,
                    const MemoryToolsTab::ScanScope& scope) {
    if (!region.readable || region.guarded || region.noAccess || !region.size) return false;
    if (region.type == kMemPrivate && !scope.includePrivate) return false;
    if (region.type == kMemImage && !scope.includeImage) return false;
    if (region.type == kMemMapped && !scope.includeMapped) return false;
    if (region.type != kMemPrivate && region.type != kMemImage &&
        region.type != kMemMapped && !scope.includePrivate) return false;
    if (scope.writableOnly && !region.writable) return false;
    if (scope.excludeExecutable && region.executable) return false;
    return true;
}

bool regionIntersection(const MemoryToolsTab::TargetRegion& region,
                        const MemoryToolsTab::ScanScope& scope,
                        uint64_t& begin, uint64_t& endExclusive) {
    if (!regionSelected(region, scope)) return false;
    begin = region.base;
    endExclusive = region.size > UINT64_MAX - region.base
        ? UINT64_MAX : region.base + region.size;
    if (scope.hasStart) begin = (std::max)(begin, scope.start);
    if (scope.hasEnd) {
        const uint64_t requestedEnd = scope.end == UINT64_MAX ? UINT64_MAX : scope.end + 1;
        endExclusive = (std::min)(endExclusive, requestedEnd);
    }
    return begin < endExclusive;
}

bool rangeWritableWithoutProtection(
    const std::vector<MemoryToolsTab::TargetRegion>& regions,
    uint64_t address, size_t size, bool& touchesExecutable) {
    touchesExecutable = false;
    if (!size || address > UINT64_MAX - static_cast<uint64_t>(size)) return false;
    const uint64_t end = address + static_cast<uint64_t>(size);
    uint64_t cursor = address;
    while (cursor < end) {
        const auto found = std::find_if(regions.begin(), regions.end(),
            [cursor](const MemoryToolsTab::TargetRegion& region) {
                return region.size && cursor >= region.base &&
                       cursor - region.base < region.size;
            });
        if (found == regions.end()) return false;
        touchesExecutable = touchesExecutable || found->executable;
        if (!found->readable || !found->writable || found->executable ||
            found->guarded || found->noAccess) return false;
        const uint64_t regionEnd = found->size > UINT64_MAX - found->base
            ? UINT64_MAX : found->base + found->size;
        if (regionEnd <= cursor) return false;
        cursor = (std::min)(regionEnd, end);
    }
    return true;
}

} // namespace

bool MemoryToolsTab::TargetToken::valid() const noexcept {
    return source != TargetSource::None && pid && generation &&
           (source != TargetSource::Passive || creationTime);
}

bool MemoryToolsTab::TargetToken::sameSession(const TargetToken& other) const noexcept {
    return valid() && other.valid() && source == other.source && pid == other.pid &&
           generation == other.generation && creationTime == other.creationTime;
}

MemoryToolsTab::MemoryToolsTab() {
    freezeThread_ = std::thread([this] { freezeWorkerLoop(); });
}

MemoryToolsTab::~MemoryToolsTab() {
    scanCancel_.store(true, std::memory_order_release);
    pointerCancel_.store(true, std::memory_order_release);
    freezeStop_.store(true, std::memory_order_release);
    freezeCv_.notify_all();
    if (scanThread_.joinable()) scanThread_.join();
    if (pointerThread_.joinable()) pointerThread_.join();
    if (freezeThread_.joinable()) freezeThread_.join();
}

MemoryToolsTab::TargetToken MemoryToolsTab::currentTarget(AppContext& ctx) {
    DbgSnapshot fallback;
    const DbgSnapshot* debug = ctx.frameDebugSnapshot;
    if (!debug) { fallback = ctx.debug.snapshot(); debug = &fallback; }
    const bool debugUsable =
        (debug->state == DbgState::Running || debug->state == DbgState::Paused) &&
        debug->pid && debug->sessionGeneration;
    const ProcessMemorySessionSnapshot passive = passive_.snapshot();

    if (targetSource_ == TargetSource::None) {
        if (debugUsable) targetSource_ = TargetSource::Debugger;
        else if (passive.open && passive.alive) targetSource_ = TargetSource::Passive;
    }

    TargetToken result;
    if (targetSource_ == TargetSource::Debugger && debugUsable) {
        result.source = TargetSource::Debugger;
        result.pid = debug->pid;
        result.generation = debug->sessionGeneration;
        result.is32 = debug->is32;
        result.canWrite = true;
        result.paused = debug->state == DbgState::Paused;
        if (!debug->modules.empty()) {
            result.name = debug->modules.front().name;
            result.path = debug->modules.front().path;
        }
        if (result.name.empty()) result.name = "debug target";
    } else if (targetSource_ == TargetSource::Passive &&
               passive.open && passive.alive && passive.identity.valid()) {
        result.source = TargetSource::Passive;
        result.pid = passive.identity.pid;
        result.generation = passive.identity.generation;
        result.creationTime = passive.identity.creationTime100ns;
        result.is32 = passive.is32;
        result.canWrite = passive.canWrite;
        result.name = passive.name;
        result.path = passive.path;
    }
    return result;
}

size_t MemoryToolsTab::readTarget(Debugger* debugger,
                                  ProcessMemorySession* passive,
                                  const TargetToken& target, uint64_t address,
                                  void* output, size_t size, std::string* error) {
    if (error) error->clear();
    if (!target.valid() || !output || !size) {
        if (error) *error = "invalid memory read";
        return 0;
    }
    if (target.source == TargetSource::Debugger && debugger) {
        const size_t got = debugger->readMemoryMaskedForSession(
            target.pid, target.generation, address, output, size);
        if (got != size && error) *error = got ? "partial debugger read" : "debugger read failed";
        return got;
    }
    if (target.source == TargetSource::Passive && passive) {
        return passive->read({ target.pid, target.creationTime, target.generation },
                             address, output, size, error);
    }
    if (error) *error = "memory target is unavailable";
    return 0;
}

bool MemoryToolsTab::writeTarget(Debugger* debugger,
                                 ProcessMemorySession* passive,
                                 const TargetToken& target, uint64_t address,
                                 const std::vector<uint8_t>& bytes,
                                 bool allowProtectionChange, std::string& error) {
    error.clear();
    if (!target.valid() || bytes.empty() ||
        address > UINT64_MAX - static_cast<uint64_t>(bytes.size())) {
        error = "invalid memory write";
        return false;
    }
    if (target.source == TargetSource::Debugger && debugger) {
        if (!allowProtectionChange) {
            std::string mapError;
            const auto regions = collectRegions(debugger, passive, target, mapError);
            bool executable = false;
            if (!rangeWritableWithoutProtection(regions, address, bytes.size(), executable)) {
                error = executable
                    ? "executable-page writes require explicit per-record authority and a debugger pause"
                    : "read-only/unmapped memory requires explicit protection-change authority";
                return false;
            }
        }
        if (allowProtectionChange && !target.paused) {
            const auto regions = debugger->regionsForSession(target.pid, target.generation);
            bool touchesExecutable = false;
            const uint64_t writeEnd = address + static_cast<uint64_t>(bytes.size());
            for (const MemRegion& region : regions) {
                const uint64_t regionEnd = region.size > UINT64_MAX - region.base
                    ? UINT64_MAX : region.base + region.size;
                if (region.exec && address < regionEnd && region.base < writeEnd) {
                    touchesExecutable = true;
                    break;
                }
            }
            if (touchesExecutable) {
                error = "executable-page writes require a visible debugger pause";
                return false;
            }
        }
        const size_t put = debugger->writeMemoryForSession(
            target.pid, target.generation, address, bytes.data(), bytes.size(),
            allowProtectionChange);
        if (put == bytes.size()) return true;
        error = target.paused
            ? "debugger rejected or could not verify the write"
            : "write failed; executable memory requires a debugger pause";
        return false;
    }
    if (target.source == TargetSource::Passive && passive) {
        const ProcessMemoryWriteResult result = passive->write(
            { target.pid, target.creationTime, target.generation }, address,
            bytes.data(), bytes.size(), { allowProtectionChange });
        if (result.ok()) return true;
        error = result.error.empty() ? "passive memory write failed" : result.error;
        return false;
    }
    error = "memory target is unavailable";
    return false;
}

std::vector<MemoryToolsTab::TargetRegion> MemoryToolsTab::collectRegions(
    Debugger* debugger, ProcessMemorySession* passive,
    const TargetToken& target, std::string& error) {
    error.clear();
    std::vector<TargetRegion> output;
    if (!target.valid()) {
        error = "memory target is unavailable";
        return output;
    }
    if (target.source == TargetSource::Debugger && debugger) {
        const auto result = debugger->queryRegionsForSession(target.pid, target.generation);
        output.reserve(result.regions.size());
        for (const MemRegion& region : result.regions) {
            output.push_back({ region.base, region.size, region.allocationBase,
                region.protect, region.state, region.type, region.read,
                region.write, region.exec,
                (region.protect & (PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0,
                (region.protect & PAGE_GUARD) != 0,
                (region.protect & 0xFFu) == PAGE_NOACCESS });
        }
        if (!result.complete) error = "Incomplete scope: " +
            (result.error.empty() ? std::string("debugger memory map is partial") : result.error);
    } else if (target.source == TargetSource::Passive && passive) {
        ProcessMemoryRegionResult result = passive->committedRegions(
            { target.pid, target.creationTime, target.generation });
        output.reserve(result.regions.size());
        for (const ProcessMemoryRegion& region : result.regions) {
            output.push_back({ region.base, region.size, region.allocationBase,
                region.protect, region.state, region.type, region.readable,
                region.writable, region.executable, region.copyOnWrite,
                region.guarded, region.noAccess });
        }
        if (!result.complete) error = "Incomplete scope: " +
            (result.error.empty() ? std::string("memory map is partial") : result.error);
    }
    std::sort(output.begin(), output.end(),
              [](const TargetRegion& a, const TargetRegion& b) {
                  return a.base < b.base;
              });
    return output;
}

std::vector<MemoryTableModuleView> MemoryToolsTab::modulesFor(
    AppContext& ctx, const TargetToken& target) const {
    std::vector<MemoryTableModuleView> modules;
    if (!target.valid()) return modules;
    if (target.source == TargetSource::Debugger) {
        const auto liveModules = ctx.debug.modulesForSession(
            target.pid, target.generation);
        modules.reserve(liveModules.size());
        for (const DbgModule& module : liveModules)
            modules.push_back({ module.name, module.path, module.base, module.size });
    } else {
        modules.reserve(passiveModules_.size());
        for (const ModuleInfo& module : passiveModules_)
            modules.push_back({ module.name, module.path, module.base, module.size });
    }
    return modules;
}

void MemoryToolsTab::handleTargetTransition(const TargetToken& target) {
    const bool unchanged = (!target.valid() && !lastTarget_.valid()) ||
                           target.sameSession(lastTarget_);
    if (unchanged) return;

    scanCancel_.store(true, std::memory_order_release);
    pointerCancel_.store(true, std::memory_order_release);
    ++scanEpoch_;
    ++pointerEpoch_;
    scanSnapshot_.reset();
    scanMapWarning_.clear();
    scanPage_ = {};
    scanLiveRows_.clear();
    scanLiveOwner_ = {};
    firstScanDone_ = false;
    scanPageStart_ = 0;
    scanStatus_ = target.valid() ? "New target: start a fresh scan."
                                 : "Memory target closed; scan invalidated.";
    pointerRows_.clear();
    pointerStatus_.clear();
    passiveModulesLastRefresh_ = 0.0;
    regionCache_.clear();
    regionOwner_ = {};
    viewBytesRead_ = 0;
    viewHavePrevious_ = false;
    viewValid_.fill(0);
    viewPreviousValid_.fill(0);
    viewWildcard_.fill(0);
    viewStatus_.clear();
    viewOwner_ = {};
    viewBase_ = 0;
    viewBaseValid_ = false;
    viewNeedsRefresh_ = true;
    std::snprintf(viewAddress_, sizeof(viewAddress_), "%s", "0");
    viewSelectionBegin_ = viewSelectionEnd_ = -1;
    viewHistory_.clear();
    viewHistoryIndex_ = 0;
    viewEdit_[0] = '\0';
    pointerTarget_[0] = '\0';
    scanStart_[0] = scanEnd_[0] = '\0';
    for (TableRow& row : table_) {
        row.record.enabled = false;
        row.record.freezeActive = false;
        row.resolved = false;
        row.writeOk = false;
        row.status = "Disabled after target change; review before enabling.";
    }
    lastTarget_ = target;
}

void MemoryToolsTab::refreshProcessList() {
    processes_ = processManager_.enumerate();
    std::sort(processes_.begin(), processes_.end(),
              [](const ProcessInfo& a, const ProcessInfo& b) {
                  const int byName = _stricmp(a.name.c_str(), b.name.c_str());
                  return byName == 0 ? a.pid < b.pid : byName < 0;
              });
    selectedProcess_ = -1;
}

void MemoryToolsTab::renderTargetBar(AppContext& ctx, const TargetToken& target) {
    const float scale = theme::UiScale();
    ImGui::BeginChild("##memory_target_bar", ImVec2(0, 0),
                      ImGuiChildFlags_AutoResizeY);
    ImGui::TextUnformatted("Memory Tools");
    ui::SameLineIfFits(240.0f * scale);
    ImGui::TextDisabled("Value scans, memory and address records");
    if (target.valid()) {
        ui::StatePill(target.source == TargetSource::Debugger ? "DEBUGGER" : "PASSIVE",
                      target.source == TargetSource::Debugger
                          ? theme::col::warn() : theme::col::good(), nullptr);
        ui::SameLineIfFits(145.0f * scale);
        if (ImGui::Button("Open Process...")) processPickerOpen_ = true;
        if (target.source == TargetSource::Passive) {
            ui::SameLineIfFits(60.0f * scale);
            if (ImGui::Button("Close")) {
                passive_.close();
                passiveModules_.clear();
                targetSource_ = TargetSource::None;
            }
        } else {
            ui::SameLineIfFits(140.0f * scale);
            if (ImGui::Button("Communications")) ctx.requestedTab = "Communications";
        }
        ImGui::TextWrapped("%s  |  PID %u  |  %s  |  %s",
                           target.name.c_str(), target.pid, target.is32 ? "x86" : "x64",
                           target.canWrite ? "read/write" : "read-only");
    } else {
        ImGui::TextDisabled("No live-memory target");
        ui::SameLineIfFits(150.0f * scale);
        if (ui::AccentButton("Open Process...", theme::col::accent(),
                             "Open a non-invasive query/read/write handle; this does not attach a debugger.",
                             true))
            processPickerOpen_ = true;
        const DbgSnapshot debug = ctx.frameDebugSnapshot
            ? *ctx.frameDebugSnapshot : ctx.debug.snapshot();
        if ((debug.state == DbgState::Running || debug.state == DbgState::Paused) &&
            debug.pid && debug.sessionGeneration) {
            ui::SameLineIfFits(160.0f * scale);
            if (ImGui::SmallButton("Use debugger target"))
                targetSource_ = TargetSource::Debugger;
        }
    }
    if (!targetStatus_.empty()) {
        ImGui::PushTextWrapPos();
        ImGui::TextDisabled("%s", targetStatus_.c_str());
        ImGui::PopTextWrapPos();
    }
    ImGui::EndChild();
    ImGui::Separator();
}

void MemoryToolsTab::renderProcessPicker(AppContext& ctx) {
    if (processPickerOpen_) {
        processPickerOpen_ = false;
        refreshProcessList();
        ImGui::OpenPopup("Open Process Memory");
    }
    ImGui::SetNextWindowSize(ImVec2(720.0f * theme::UiScale(),
                                    580.0f * theme::UiScale()),
                             ImGuiCond_FirstUseEver);
    if (!ImGui::BeginPopupModal("Open Process Memory", nullptr,
                                ImGuiWindowFlags_NoSavedSettings)) return;

    if (ui::ToolbarIconButton(DS_ICON_REFRESH, "Refresh", "Refresh process list"))
        refreshProcessList();
    ImGui::SameLine();
    if (ui::SearchBox("##memory_process_filter", "process name or PID...",
                      processFilter_, sizeof(processFilter_),
                      260.0f * theme::UiScale()))
        selectedProcess_ = -1;
    ImGui::TextDisabled("Opening here is non-invasive: it does not call DebugActiveProcess or suspend the target.");

    if (ImGui::BeginTable("##memory_processes", 4,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
            ImVec2(0, -42.0f * theme::UiScale()))) {
        ImGui::TableSetupColumn("PID", ImGuiTableColumnFlags_WidthFixed, 75.0f);
        ImGui::TableSetupColumn("Process");
        ImGui::TableSetupColumn("Arch", ImGuiTableColumnFlags_WidthFixed, 55.0f);
        ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed, 75.0f);
        ImGui::TableHeadersRow();
        for (int i = 0; i < static_cast<int>(processes_.size()); ++i) {
            const ProcessInfo& process = processes_[i];
            const std::string pidText = std::to_string(process.pid);
            if (processFilter_[0] && !caseContains(process.name, processFilter_) &&
                !caseContains(pidText, processFilter_)) continue;
            ImGui::TableNextRow();
            ImGui::PushID(i);
            ImGui::TableSetColumnIndex(0); ImGui::Text("%u", process.pid);
            ImGui::TableSetColumnIndex(1);
            if (ImGui::Selectable(process.name.c_str(), selectedProcess_ == i,
                                  ImGuiSelectableFlags_SpanAllColumns))
                selectedProcess_ = i;
            ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(process.is64 ? "x64" : "x86");
            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(process.canOpen ? theme::col::good() : theme::col::bad(),
                               "%s", process.canOpen ? "query ok" : "denied");
            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    ImGui::BeginDisabled(selectedProcess_ < 0 ||
                         selectedProcess_ >= static_cast<int>(processes_.size()));
    if (ui::AccentButton("Open memory", theme::col::accent())) {
        const ProcessInfo process = processes_[selectedProcess_];
        const DbgSnapshot debug = ctx.debug.snapshot();
        if ((debug.state == DbgState::Running || debug.state == DbgState::Paused) &&
            debug.pid == process.pid && debug.sessionGeneration) {
            targetSource_ = TargetSource::Debugger;
            targetStatus_ = "Using the existing breakpoint-aware debugger session.";
            ImGui::CloseCurrentPopup();
        } else {
            std::string error;
            if (passive_.open(process.pid, {}, &error)) {
                targetSource_ = TargetSource::Passive;
                passiveModules_ = processManager_.modules(process.pid);
                const auto snapshot = passive_.snapshot();
                targetStatus_ = snapshot.canWrite
                    ? "Passive read/write session opened."
                    : "Passive read-only session opened; writes were denied.";
                ImGui::CloseCurrentPopup();
            } else {
                targetStatus_ = error.empty() ? "Could not open process memory." : error;
                ui::Toast(ui::ToastKind::Error, targetStatus_);
            }
        }
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) ImGui::CloseCurrentPopup();
    ImGui::EndPopup();
}

void MemoryToolsTab::refreshRegionCache(AppContext& ctx, const TargetToken& target) {
    regionCache_ = collectRegions(&ctx.debug, &passive_, target, regionStatus_);
    regionOwner_ = target;
    if (target.source == TargetSource::Passive)
        refreshPassiveModules(target, ImGui::GetTime());
}

bool MemoryToolsTab::refreshPassiveModules(const TargetToken& target,
                                           double refreshedAt) {
    if (target.source != TargetSource::Passive || !target.valid()) return false;
    const ProcessMemoryIdentity expected{
        target.pid, target.creationTime, target.generation
    };
    const ProcessMemorySessionSnapshot before = passive_.snapshot();
    if (!ProcessMemoryIdentityMatches(before.identity, expected) ||
        !before.open || !before.alive)
        return false;
    auto modules = processManager_.modules(target.pid);
    const ProcessMemorySessionSnapshot after = passive_.snapshot();
    if (!ProcessMemoryIdentityMatches(after.identity, expected) ||
        !after.open || !after.alive)
        return false;
    passiveModules_ = std::move(modules);
    passiveModulesLastRefresh_ = refreshedAt;
    return true;
}

bool MemoryToolsTab::buildScanConfig(bool first, MemoryScanConfig& config,
                                     std::string& error) const {
    error.clear();
    if (scanMode_ < 0 || scanMode_ > static_cast<int>(MemoryScanMode::UnknownInitial)) {
        error = "Select a valid scan mode.";
        return false;
    }
    config = {};
    config.type = valueTypeForKind(valueKind_, signedIntegers_);
    config.mode = static_cast<MemoryScanMode>(scanMode_);
    config.alignment = static_cast<uint32_t>((std::max)(1, alignment_));
    if (!first && config.mode == MemoryScanMode::UnknownInitial) {
        error = "Unknown initial value is only valid for the first scan.";
        return false;
    }

    const MemoryValueParseOptions parseOptions{ scanHex_, nullTerminateText_ };
    const bool variable = !MemoryValueTypeFixedSize(config.type);
    if (scanModeNeedsValue(config.mode) || variable) {
        if (!ParseMemoryScanValue(config.type, scanValue_, parseOptions,
                                  config.value, &error))
            return false;
        if (variable) config.elementSize = config.value.size();
    }
    if (scanModeNeedsSecondValue(config.mode) &&
        !ParseMemoryScanValue(config.type, scanValue2_, parseOptions,
                              config.secondValue, &error))
        return false;
    if (MemoryValueTypeIsFloat(config.type) && floatTolerance_) {
        config.tolerance.enabled = true;
        config.tolerance.absolute = (std::max)(0.0, static_cast<double>(absoluteTolerance_));
    }
    if (!ValidateMemoryScanConfig(config, &error)) return false;
    if (!first) {
        const size_t oldWidth = MemoryScanElementSize(scanShape_);
        if (config.type != scanShape_.type ||
            MemoryScanElementSize(config) != oldWidth ||
            config.alignment != scanShape_.alignment) {
            error = "Value type, width, and alignment are locked until New Scan.";
            return false;
        }
    }
    return true;
}

bool MemoryToolsTab::buildScanScope(ScanScope& scope, std::string& error) const {
    error.clear();
    scope = {};
    scope.includePrivate = scanPrivate_;
    scope.includeImage = scanImage_;
    scope.includeMapped = scanMapped_;
    scope.writableOnly = scanWritableOnly_;
    scope.excludeExecutable = scanExcludeExecutable_;
    scope.requestedMaxBytes =
        static_cast<uint64_t>((std::clamp)(scanMaxMiB_, 16, 2048)) << 20;
    scope.maxBytes = conservativeInitialScanCap(
        scope.requestedMaxBytes, scope.memoryAdmissionLimited);
    if (scanStart_[0]) {
        if (!parseHexAddress(scanStart_, scope.start)) {
            error = "Start address must be hexadecimal.";
            return false;
        }
        scope.hasStart = true;
    }
    if (scanEnd_[0]) {
        if (!parseHexAddress(scanEnd_, scope.end)) {
            error = "End address must be hexadecimal.";
            return false;
        }
        scope.hasEnd = true;
    }
    if (scope.hasStart && scope.hasEnd && scope.end < scope.start) {
        error = "Scan range ends before it starts.";
        return false;
    }
    if (!scope.includePrivate && !scope.includeImage && !scope.includeMapped) {
        error = "Select at least one memory region type.";
        return false;
    }
    return true;
}

void MemoryToolsTab::clearScan(const char* status) {
    scanMapWarning_.clear();
    scanCancel_.store(true, std::memory_order_release);
    ++scanEpoch_;
    if (!scanEpoch_) ++scanEpoch_;
    scanSnapshot_.reset();
    scanPage_ = {};
    scanLiveRows_.clear();
    scanLiveOwner_ = {};
    scanPageStart_ = 0;
    scanPageRevision_ = UINT64_MAX;
    firstScanDone_ = false;
    if (status) scanStatus_ = status;
    else scanStatus_.clear();
}

bool MemoryToolsTab::applyScanPreset(const MemoryScanValue& value) {
    int kind = 0;
    bool signedInteger = false;
    if (!value.valid() ||
        !controlsForValueType(value.type, kind, signedInteger)) {
        scanStatus_ = "The incoming scan value was invalid.";
        return false;
    }
    const std::string formatted = FormatMemoryScanValue(value);
    if (formatted.empty() || formatted.size() >= sizeof(scanValue_)) {
        scanStatus_ = "The incoming scan value was too large for the scanner.";
        return false;
    }

    // Replacing scanner inputs is reserved for an explicit preparation request.
    // Preserve the analyst's scope filters/range and never start target reads here.
    clearScan();
    valueKind_ = kind;
    signedIntegers_ = signedInteger;
    scanHex_ = false;
    nullTerminateText_ = value.nullTerminated;
    scanMode_ = static_cast<int>(MemoryScanMode::Exact);
    std::snprintf(scanValue_, sizeof(scanValue_), "%s", formatted.c_str());
    scanValue2_[0] = '\0';
    floatTolerance_ = false;
    alignment_ = 1;
    scanStatus_ = "Typed value prepared for an exact first scan; existing scope retained.";
    return true;
}

void MemoryToolsTab::cancelScan() {
    if (!scanRunning_.load(std::memory_order_acquire)) return;
    scanCancel_.store(true, std::memory_order_release);
    scanStatus_ = "Cancelling scan; the previous snapshot remains available...";
}

void MemoryToolsTab::pumpScanCompletion() {
    if (scanRunning_.load(std::memory_order_acquire)) return;
    if (scanThread_.joinable()) scanThread_.join();
    ScanCompletion completed;
    {
        std::lock_guard lock(scanMutex_);
        if (!scanCompletionReady_) return;
        completed = std::move(scanCompletion_);
        scanCompletionReady_ = false;
    }
    if (completed.epoch != scanEpoch_ || !completed.owner.sameSession(lastTarget_)) return;
    if (completed.adopt && completed.snapshot) {
        scanSnapshot_ = std::move(completed.snapshot);
        scanShape_ = completed.config;
        if (!completed.mapWarning.empty()) scanMapWarning_ = std::move(completed.mapWarning);
        firstScanDone_ = true;
        scanPageStart_ = 0;
        ++scanRevision_;
        scanPageRevision_ = UINT64_MAX;
    }
    scanStatus_ = std::move(completed.status);
}

void MemoryToolsTab::firstScan(AppContext& ctx, const TargetToken& target) {
    pumpScanCompletion();
    if (!target.valid() || scanRunning_.load(std::memory_order_acquire)) return;
    if (scanThread_.joinable()) scanThread_.join();

    MemoryScanConfig config;
    ScanScope scope;
    std::string error;
    if (!buildScanConfig(true, config, error) || !buildScanScope(scope, error)) {
        scanStatus_ = error;
        return;
    }
    clearScan();
    scanCancel_.store(false, std::memory_order_release);
    scanProgress_.store(0, std::memory_order_relaxed);
    scanTotal_.store(0, std::memory_order_relaxed);
    scanMatches_.store(0, std::memory_order_relaxed);
    scanStatus_ = "Mapping readable regions...";

    Debugger* debugger = &ctx.debug;
    ProcessMemorySession* passive = &passive_;
    const uint64_t epoch = scanEpoch_;
    scanRunning_.store(true, std::memory_order_release);
    try {
        scanThread_ = std::thread([this, debugger, passive, target, config, scope, epoch] {
            ScanCompletion done;
            done.owner = target;
            done.config = config;
            done.epoch = epoch;
            try {
                std::string mapError;
                std::vector<TargetRegion> regions = collectRegions(
                    debugger, passive, target, mapError);
                done.mapWarning = mapError;
                uint64_t eligibleBytes = 0;
                for (const TargetRegion& region : regions) {
                    uint64_t begin = 0, end = 0;
                    if (!regionIntersection(region, scope, begin, end)) continue;
                    const uint64_t span = end - begin;
                    eligibleBytes = eligibleBytes > UINT64_MAX - span
                        ? UINT64_MAX : eligibleBytes + span;
                }
                done.coverageTruncated = eligibleBytes > scope.maxBytes;
                const uint64_t planned = (std::min)(eligibleBytes, scope.maxBytes);
                scanTotal_.store(planned, std::memory_order_relaxed);

                auto snapshot = std::make_shared<MemoryScanSnapshot>();
                const size_t width = MemoryScanElementSize(config);
                uint64_t budgetLeft = scope.maxBytes;
                bool failed = false;
                for (const TargetRegion& region : regions) {
                    if (!budgetLeft || scanCancel_.load(std::memory_order_acquire)) break;
                    uint64_t begin = 0, end = 0;
                    if (!regionIntersection(region, scope, begin, end)) continue;
                    for (uint64_t address = begin;
                         address < end && budgetLeft &&
                         !scanCancel_.load(std::memory_order_acquire);) {
                        const uint64_t remaining = end - address;
                        const size_t owned = static_cast<size_t>((std::min<uint64_t>)(
                            (std::min<uint64_t>)(remaining, kScanChunkBytes), budgetLeft));
                        size_t wanted = owned;
                        if (width > 1 && remaining > owned) {
                            const uint64_t lookahead = (std::min<uint64_t>)(
                                width - 1, remaining - owned);
                            wanted += static_cast<size_t>(lookahead);
                        }
                        std::vector<uint8_t> bytes(wanted);
                        std::string readError;
                        const size_t got = readTarget(debugger, passive, target, address,
                                                      bytes.data(), wanted, &readError);
                        bytes.resize(got);
                        done.bytesAttempted += owned;
                        done.bytesRead += (std::min)(got, owned);
                        if (!got) {
                            ++done.unreadableChunks;
                        } else {
                            if (got < wanted) ++done.partialChunks;
                            const size_t candidateSpan = (std::min)(owned, got);
                            std::string appendError;
                            if (!snapshot->appendInitialChunk(config, address, bytes,
                                                              candidateSpan, &appendError)) {
                                failed = true;
                                done.status = "Scan failed: " + appendError;
                                break;
                            }
                        }
                        budgetLeft -= owned;
                        scanProgress_.store(done.bytesAttempted, std::memory_order_relaxed);
                        scanMatches_.store(snapshot->candidateCount(), std::memory_order_relaxed);
                        if (address > UINT64_MAX - owned) break;
                        address += owned;
                    }
                    if (failed) break;
                }

                if (scanCancel_.load(std::memory_order_acquire)) {
                    done.status = "First scan cancelled.";
                } else if (!failed) {
                    done.snapshot = std::move(snapshot);
                    done.adopt = true;
                    char status[256]{};
                    std::snprintf(status, sizeof(status),
                        "First scan: %s results; %.1f MiB read%s%s%s%s.",
                        compactCount(done.snapshot->candidateCount()).c_str(),
                        done.bytesRead / (1024.0 * 1024.0),
                        done.coverageTruncated ? "; coverage limit reached" : "",
                        scope.memoryAdmissionLimited
                            ? "; cap reduced for safe refinement headroom" : "",
                        done.unreadableChunks ? "; unreadable chunks skipped" : "",
                        done.partialChunks ? "; partial chunks kept only through their readable prefix" : "");
                    done.status = status;
                }
            } catch (const std::exception& exception) {
                done.status = std::string("Scan failed: ") + exception.what();
            } catch (...) {
                done.status = "Scan failed: unknown worker error.";
            }
            {
                std::lock_guard lock(scanMutex_);
                scanCompletion_ = std::move(done);
                scanCompletionReady_ = true;
            }
            scanRunning_.store(false, std::memory_order_release);
        });
    } catch (const std::exception& exception) {
        scanRunning_.store(false, std::memory_order_release);
        scanStatus_ = std::string("Unable to start scan: ") + exception.what();
    }
}

void MemoryToolsTab::nextScan(AppContext& ctx, const TargetToken& target) {
    pumpScanCompletion();
    if (!target.valid() || !firstScanDone_ || !scanSnapshot_ ||
        scanRunning_.load(std::memory_order_acquire)) return;
    if (scanThread_.joinable()) scanThread_.join();

    MemoryScanConfig config;
    std::string error;
    if (!buildScanConfig(false, config, error)) {
        scanStatus_ = error;
        return;
    }
    uint64_t retained = 0;
    uint64_t available = 0;
    if (!memoryAdmitsAtomicRefinement(*scanSnapshot_, retained, available)) {
        char message[320]{};
        if (available) {
            std::snprintf(message, sizeof(message),
                "Next scan not started: the %.1f MiB retained snapshot needs conservative copy headroom, but only %.1f MiB of physical memory is available. Narrow the range or start with an exact value.",
                retained / static_cast<double>(kMiB),
                available / static_cast<double>(kMiB));
        } else {
            std::snprintf(message, sizeof(message),
                "Next scan not started: Windows memory telemetry was unavailable and the %.1f MiB snapshot exceeds the fail-safe copy limit. Narrow the range.",
                retained / static_cast<double>(kMiB));
        }
        scanStatus_ = message;
        return;
    }
    scanCancel_.store(false, std::memory_order_release);
    scanProgress_.store(0, std::memory_order_relaxed);
    scanTotal_.store(scanSnapshot_->candidateCount(), std::memory_order_relaxed);
    scanMatches_.store(scanSnapshot_->candidateCount(), std::memory_order_relaxed);
    scanStatus_ = "Refining the previous snapshot in page-sized reads...";

    const std::shared_ptr<const MemoryScanSnapshot> prior = scanSnapshot_;
    Debugger* debugger = &ctx.debug;
    ProcessMemorySession* passive = &passive_;
    const uint64_t epoch = scanEpoch_;
    scanRunning_.store(true, std::memory_order_release);
    try {
        scanThread_ = std::thread([this, debugger, passive, target, config, prior, epoch] {
            ScanCompletion done;
            done.owner = target;
            done.config = config;
            done.epoch = epoch;
            try {
                auto working = std::make_shared<MemoryScanSnapshot>(*prior);
                uint64_t processed = 0;
                bool failed = false;
                for (size_t i = 0; i < prior->chunkCount(); ++i) {
                    if (scanCancel_.load(std::memory_order_acquire)) break;
                    const MemoryScanChunk& chunk = prior->chunks()[i];
                    std::vector<uint8_t> bytes(chunk.bytes.size());
                    std::string readError;
                    const size_t got = readTarget(debugger, passive, target, chunk.base,
                                                  bytes.data(), bytes.size(), &readError);
                    bytes.resize(got);
                    done.bytesAttempted += chunk.candidateSpan;
                    done.bytesRead += (std::min)(got, chunk.candidateSpan);
                    if (!got) ++done.unreadableChunks;
                    else if (got < chunk.bytes.size()) ++done.partialChunks;
                    std::string refineError;
                    if (!working->refineChunk(i, config, bytes, &refineError)) {
                        done.status = "Next scan failed: " + refineError;
                        failed = true;
                        break;
                    }
                    processed += chunk.candidateCount;
                    scanProgress_.store(processed, std::memory_order_relaxed);
                    scanMatches_.store(working->candidateCount(), std::memory_order_relaxed);
                }
                if (scanCancel_.load(std::memory_order_acquire)) {
                    done.status = "Next scan cancelled; previous results preserved.";
                } else if (!failed) {
                    done.snapshot = std::move(working);
                    done.adopt = true;
                    char status[220]{};
                    std::snprintf(status, sizeof(status),
                        "Next scan: %s results; %.1f MiB re-read%s%s.",
                        compactCount(done.snapshot->candidateCount()).c_str(),
                        done.bytesRead / (1024.0 * 1024.0),
                        done.unreadableChunks ? "; unreadable candidates removed" : "",
                        done.partialChunks ? "; partial chunks kept only through their readable prefix" : "");
                    done.status = status;
                }
            } catch (const std::bad_alloc&) {
                done.status = "Next scan needs a temporary snapshot copy; not enough memory. Narrow the range first.";
            } catch (const std::exception& exception) {
                done.status = std::string("Next scan failed; previous results preserved: ") + exception.what();
            } catch (...) {
                done.status = "Next scan failed; previous results preserved.";
            }
            {
                std::lock_guard lock(scanMutex_);
                scanCompletion_ = std::move(done);
                scanCompletionReady_ = true;
            }
            scanRunning_.store(false, std::memory_order_release);
        });
    } catch (const std::exception& exception) {
        scanRunning_.store(false, std::memory_order_release);
        scanStatus_ = std::string("Unable to start next scan: ") + exception.what();
    }
}

void MemoryToolsTab::rebuildScanPage() {
    if (!scanSnapshot_) {
        scanPage_ = {};
        return;
    }
    if (scanPageRevision_ == scanRevision_ &&
        scanPageCachedStart_ == scanPageStart_) return;
    scanPage_ = scanSnapshot_->page(scanPageStart_, scanPageSize_);
    scanPageRevision_ = scanRevision_;
    scanPageCachedStart_ = scanPageStart_;
}

void MemoryToolsTab::renderScanner(AppContext& ctx, const TargetToken& target) {
    const float scale = theme::UiScale();
    pumpScanCompletion();
    rebuildScanPage();

    ImGui::TextUnformatted("Value scanner");
    ImGui::Separator();

    const bool running = scanRunning_.load(std::memory_order_acquire);
    ImGui::BeginDisabled(running || firstScanDone_);
    ImGui::SetNextItemWidth(150.0f * theme::UiScale());
    ImGui::Combo("Type", &valueKind_, kValueKinds,
                 static_cast<int>(std::size(kValueKinds)));
    if (isIntegerKind(valueKind_)) {
        ui::SameLineIfFits(80.0f * scale);
        ImGui::Checkbox("Signed", &signedIntegers_);
        ui::SameLineIfFits(60.0f * scale);
        ImGui::Checkbox("Hex", &scanHex_);
    } else if (valueKind_ == 4 || valueKind_ == 5) {
        ui::SameLineIfFits(100.0f * scale);
        ImGui::Checkbox("Raw bits", &scanHex_);
    } else if (valueKind_ == 7 || valueKind_ == 8) {
        ui::SameLineIfFits(125.0f * scale);
        ImGui::Checkbox("Include NUL", &nullTerminateText_);
    }
    ImGui::EndDisabled();

    ImGui::SetNextItemWidth(180.0f * theme::UiScale());
    ImGui::Combo("Scan", &scanMode_, kScanModes,
                 static_cast<int>(std::size(kScanModes)));
    const auto mode = static_cast<MemoryScanMode>(
        (std::clamp)(scanMode_, 0, static_cast<int>(MemoryScanMode::UnknownInitial)));
    if (scanModeNeedsValue(mode) || !MemoryValueTypeFixedSize(
            valueTypeForKind(valueKind_, signedIntegers_))) {
        ImGui::TextUnformatted(mode == MemoryScanMode::Between ? "Lower value" : "Value");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputText("##memory_scan_value", scanValue_, sizeof(scanValue_));
    }
    if (scanModeNeedsSecondValue(mode)) {
        ImGui::TextUnformatted("Upper value");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputText("##memory_scan_upper", scanValue2_, sizeof(scanValue2_));
    }
    if (valueKind_ == 4 || valueKind_ == 5) {
        ImGui::Checkbox("Float tolerance", &floatTolerance_);
        if (floatTolerance_) {
            ui::SameLineIfFits(220.0f * scale);
            ImGui::SetNextItemWidth(120.0f * theme::UiScale());
            ImGui::InputFloat("Absolute##scan_tolerance", &absoluteTolerance_,
                              0.0f, 0.0f, "%.8g");
        }
    }

    if (ImGui::CollapsingHeader("Scan scope")) {
        ImGui::BeginDisabled(running || firstScanDone_);
        ImGui::Checkbox("Private", &scanPrivate_); ui::SameLineIfFits(75.0f * scale);
        ImGui::Checkbox("Image", &scanImage_); ui::SameLineIfFits(95.0f * scale);
        ImGui::Checkbox("Mapped", &scanMapped_);
        ImGui::Checkbox("Writable only", &scanWritableOnly_); ui::SameLineIfFits(175.0f * scale);
        ImGui::Checkbox("Exclude executable", &scanExcludeExecutable_);
        ImGui::SetNextItemWidth(90.0f * theme::UiScale());
        ImGui::InputInt("Alignment", &alignment_);
        alignment_ = (std::clamp)(alignment_, 1, 4096);
        ImGui::SetNextItemWidth(135.0f * theme::UiScale());
        ImGui::InputText("Start (hex)", scanStart_, sizeof(scanStart_),
                         ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::SetNextItemWidth(135.0f * theme::UiScale());
        ImGui::InputText("End (hex)", scanEnd_, sizeof(scanEnd_),
                         ImGuiInputTextFlags_CharsHexadecimal);
        ImGui::SetNextItemWidth(90.0f * theme::UiScale());
        ImGui::InputInt("Read cap MiB", &scanMaxMiB_);
        scanMaxMiB_ = (std::clamp)(scanMaxMiB_, 16, 2048);
        ImGui::EndDisabled();
        ImGui::PushTextWrapPos();
        ImGui::TextDisabled("The read cap limits scan coverage and may be reduced to keep enough memory for refinement. Results are exact within the reported coverage.");
        ImGui::PopTextWrapPos();
    }

    ImGui::BeginDisabled(!target.valid() || running || firstScanDone_);
    if (ui::AccentButton("First scan", theme::col::accent())) firstScan(ctx, target);
    ImGui::EndDisabled();
    ui::SameLineIfFits(90.0f * scale);
    ImGui::BeginDisabled(!target.valid() || running || !firstScanDone_ ||
                         mode == MemoryScanMode::UnknownInitial);
    if (ImGui::Button("Next scan")) nextScan(ctx, target);
    ImGui::EndDisabled();
    ui::SameLineIfFits(90.0f * scale);
    ImGui::BeginDisabled(running && !firstScanDone_);
    if (ImGui::Button("New scan")) clearScan("Ready for a new first scan.");
    ImGui::EndDisabled();
    if (running) {
        ui::SameLineIfFits(70.0f * scale);
        if (ImGui::Button("Cancel")) cancelScan();
    }

    if (running) {
        const uint64_t total = scanTotal_.load(std::memory_order_relaxed);
        const uint64_t done = scanProgress_.load(std::memory_order_relaxed);
        const float fraction = total ? static_cast<float>((std::min)(done, total)) /
                                           static_cast<float>(total) : 0.0f;
        const std::string overlay = compactCount(done) + " / " + compactCount(total) +
                                    "  (" + compactCount(
                                        scanMatches_.load(std::memory_order_relaxed)) +
                                    " candidates)";
        ImGui::ProgressBar(fraction, ImVec2(-1.0f, 0.0f), overlay.c_str());
    }
    if (!scanStatus_.empty()) {
        ImGui::PushTextWrapPos();
        ImGui::TextDisabled("%s", scanStatus_.c_str());
        ImGui::PopTextWrapPos();
    }
    if (!scanMapWarning_.empty()) {
        ImGui::PushTextWrapPos();
        ImGui::TextColored(theme::col::warn(), "%s", scanMapWarning_.c_str());
        ImGui::PopTextWrapPos();
    }

    if (!firstScanDone_ || !scanSnapshot_) return;

    const uint64_t total = scanSnapshot_->candidateCount();
    const uint64_t firstShown = total ? scanPage_.first + 1 : 0;
    const uint64_t lastShown = scanPage_.first + scanPage_.matches.size();
    ImGui::SeparatorText("Results");
    ImGui::Text("%s matches  |  %s-%s", compactCount(total).c_str(),
                compactCount(firstShown).c_str(), compactCount(lastShown).c_str());
    ui::SameLineIfFits(130.0f * scale);
    ImGui::BeginDisabled(scanPage_.first == 0);
    if (ImGui::SmallButton("|<")) { scanPageStart_ = 0; rebuildScanPage(); }
    ImGui::SameLine();
    if (ImGui::SmallButton("<")) {
        scanPageStart_ = scanPageStart_ > scanPageSize_
            ? scanPageStart_ - scanPageSize_ : 0;
        rebuildScanPage();
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!scanPage_.hasMore);
    if (ImGui::SmallButton(">")) { scanPageStart_ = scanPage_.next; rebuildScanPage(); }
    ImGui::SameLine();
    if (ImGui::SmallButton(">|")) {
        scanPageStart_ = total ? ((total - 1) / scanPageSize_) * scanPageSize_ : 0;
        rebuildScanPage();
    }
    ImGui::EndDisabled();

    const auto modules = modulesFor(ctx, target);
    if (!scanLiveOwner_.sameSession(target) || scanLiveRevision_ != scanRevision_ ||
        scanLivePageStart_ != scanPage_.first ||
        scanLiveRows_.size() != scanPage_.matches.size()) {
        scanLiveRows_.assign(scanPage_.matches.size(), {});
        scanLiveOwner_ = target;
        scanLiveRevision_ = scanRevision_;
        scanLivePageStart_ = scanPage_.first;
    }
    const uint64_t liveTick = static_cast<uint64_t>(ImGui::GetTime() * 4.0);
    if (ImGui::BeginTable("##memory_scan_results", 5,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
            ImVec2(0, 0))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 145.0f);
        ImGui::TableSetupColumn("Module", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Current", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Previous", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("State", ImGuiTableColumnFlags_WidthFixed, 68.0f);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(scanPage_.matches.size()));
        while (clipper.Step()) {
            for (int rowIndex = clipper.DisplayStart; rowIndex < clipper.DisplayEnd;
                 ++rowIndex) {
                const MemoryScanMatch& match = scanPage_.matches[static_cast<size_t>(rowIndex)];
                ScanLiveRow& live = scanLiveRows_[static_cast<size_t>(rowIndex)];
                if (live.tick != liveTick) {
                    live.tick = liveTick;
                    live.bytes.assign(match.bytes.size(), 0);
                    const size_t got = live.bytes.empty() ? 0 : readTarget(
                        &ctx.debug, &passive_, target, match.address,
                        live.bytes.data(), live.bytes.size());
                    live.complete = got == live.bytes.size();
                    live.bytes.resize(got);
                }
                const bool complete = live.complete;
                const std::vector<uint8_t>& current = live.bytes;
                const bool changed = complete && current != match.bytes;

                ImGui::TableNextRow();
                ImGui::PushID(rowIndex);
                ImGui::TableSetColumnIndex(0);
                const std::string address = hexAddress(match.address);
                if (ImGui::Selectable(address.c_str(), false,
                        ImGuiSelectableFlags_SpanAllColumns |
                        ImGuiSelectableFlags_AllowDoubleClick) &&
                    ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    navigateViewer(match.address);
                    inspectorSelectRequest_ = 0;
                }
                if (ImGui::BeginPopupContextItem("##scan_result_menu")) {
                    if (ImGui::MenuItem("Open in memory viewer")) {
                        navigateViewer(match.address);
                        inspectorSelectRequest_ = 0;
                    }
                    if (ImGui::MenuItem("Add to address table"))
                        addAddressRow(ctx, target, match.address, scanShape_.type, &match.bytes,
                                      "scan result");
                    if (ImGui::MenuItem("Use as pointer target")) {
                        std::snprintf(pointerTarget_, sizeof(pointerTarget_), "%llX",
                                      static_cast<unsigned long long>(match.address));
                        inspectorSelectRequest_ = 2;
                    }
                    const bool debuggerOwned =
                        target.source == TargetSource::Debugger && target.valid() &&
                        ctx.frameDebugSnapshot && ctx.frameDebugSnapshot->attached() &&
                        DebugTargetIdentityMatches(
                            { ctx.frameDebugSnapshot->pid,
                              ctx.frameDebugSnapshot->sessionGeneration },
                            { target.pid, target.generation });
                    if (ImGui::MenuItem("Open in Live Assembly", nullptr, false,
                                        debuggerOwned))
                        ctx.gotoAddressLive(
                            match.address, { target.pid, target.generation });
                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                        ImGui::SetTooltip("Decodes the bytes stored at this address. To inspect code that accesses the value, navigate to the accessing instruction's address.");
                    if (ImGui::MenuItem("Copy address"))
                        ImGui::SetClipboardText(address.c_str());
                    ImGui::EndPopup();
                }
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(moduleAddressLabel(modules, match.address).c_str());
                ImGui::TableSetColumnIndex(2);
                if (complete)
                    ImGui::TextUnformatted(formatMemoryValue(scanShape_.type, current,
                        scanHex_, nullTerminateText_).c_str());
                else
                    ImGui::TextDisabled("unreadable");
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(formatMemoryValue(scanShape_.type, match.bytes,
                    scanHex_, nullTerminateText_).c_str());
                ImGui::TableSetColumnIndex(4);
                ImGui::TextColored(!complete ? theme::col::bad() :
                                   (changed ? theme::col::warn() : theme::col::good()),
                                   "%s", !complete ? "gone" : changed ? "changed" : "same");
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
}

void MemoryToolsTab::navigateViewer(uint64_t address, bool recordHistory,
                                    uint32_t selectionBytes) {
    const uint64_t limit = lastTarget_.valid() && lastTarget_.is32 ? UINT32_MAX : UINT64_MAX;
    if (address > limit) {
        viewStatus_ = "Address exceeds this 32-bit target's range.";
        return;
    }
    // Keep all displayed addresses representable, including a jump to UINT64_MAX.
    const uint64_t nextBase = (std::min)(address & ~uint64_t{0xFu},
                                        limit - (viewBytes_.size() - 1));
    const uint32_t available = static_cast<uint32_t>(viewBytes_.size() -
                                                     (address - nextBase));
    const uint32_t selected = (std::min)((std::max)(selectionBytes, 1u), available);
    if (recordHistory) {
        if (viewHistory_.empty()) {
            viewHistory_.push_back({address, selected});
            viewHistoryIndex_ = 0;
        } else if (viewHistory_[viewHistoryIndex_].address != address ||
                   viewHistory_[viewHistoryIndex_].selectionBytes != selected) {
            viewHistory_.erase(viewHistory_.begin() +
                                   static_cast<std::ptrdiff_t>(viewHistoryIndex_ + 1),
                               viewHistory_.end());
            viewHistory_.push_back({address, selected});
            if (viewHistory_.size() > 256) viewHistory_.erase(viewHistory_.begin());
            viewHistoryIndex_ = viewHistory_.size() - 1;
        }
    }
    if (!viewBaseValid_ || nextBase != viewBase_) {
        viewBytesRead_ = 0;
        viewHavePrevious_ = false;
        viewValid_.fill(0);
        viewPreviousValid_.fill(0);
        viewOwner_ = {};
    }
    viewWildcard_.fill(0);
    viewEdit_[0] = '\0';
    viewStatus_.clear();
    viewBase_ = nextBase;
    viewBaseValid_ = true;
    std::snprintf(viewAddress_, sizeof(viewAddress_), "%llX",
                  static_cast<unsigned long long>(address));
    viewSelectionBegin_ = static_cast<int>(address - viewBase_);
    viewSelectionEnd_ = viewSelectionBegin_ + static_cast<int>(selected) - 1;
    viewScrollSelection_ = true;
    viewLastRefresh_ = 0.0;
    viewNeedsRefresh_ = true;
}

bool MemoryToolsTab::viewerRangeReadable(int offset, size_t size) const {
    if (offset < 0 || !size || static_cast<size_t>(offset) >= viewValid_.size() ||
        size > viewValid_.size() - static_cast<size_t>(offset)) return false;
    return std::all_of(viewValid_.begin() + offset,
                       viewValid_.begin() + offset + size,
                       [](uint8_t valid) { return valid != 0; });
}

void MemoryToolsTab::selectViewerByte(int offset, bool extend) {
    offset = (std::clamp)(offset, 0, static_cast<int>(viewBytes_.size()) - 1);
    if (extend && viewSelectionBegin_ >= 0) viewSelectionEnd_ = offset;
    else viewSelectionBegin_ = viewSelectionEnd_ = offset;
    viewEdit_[0] = '\0'; // A draft must never silently move to a different address.
    const int lo = (std::min)(viewSelectionBegin_, viewSelectionEnd_);
    std::snprintf(viewAddress_, sizeof(viewAddress_), "%llX",
                  static_cast<unsigned long long>(viewBase_ + lo));
    if (!viewHistory_.empty())
        viewHistory_[viewHistoryIndex_] = {viewBase_ + lo,
            static_cast<uint32_t>(std::abs(viewSelectionEnd_ - viewSelectionBegin_) + 1)};
}

std::string MemoryToolsTab::viewerSelectionText(bool pattern, bool ascii) const {
    const int lo = (std::min)(viewSelectionBegin_, viewSelectionEnd_);
    const int hi = (std::max)(viewSelectionBegin_, viewSelectionEnd_);
    if (lo < 0 || hi >= static_cast<int>(viewBytes_.size())) return {};
    if (!pattern && !viewerRangeReadable(lo, static_cast<size_t>(hi - lo + 1)))
        return {};
    std::string text;
    for (int i = lo; i <= hi; ++i) {
        if (ascii) {
            const uint8_t ch = viewBytes_[i];
            text.push_back(ch >= 32 && ch < 127 ? static_cast<char>(ch) : '.');
        } else {
            if (!text.empty()) text.push_back(' ');
            if (pattern && (!viewValid_[i] || viewWildcard_[i])) text += "??";
            else {
                char byte[4]{};
                std::snprintf(byte, sizeof(byte), "%02X", viewBytes_[i]);
                text += byte;
            }
        }
    }
    return text;
}

void MemoryToolsTab::refreshViewer(AppContext& ctx, const TargetToken& target,
                                   bool force) {
    if (!target.valid() || !viewBaseValid_) {
        viewBytesRead_ = 0;
        viewValid_.fill(0);
        viewPreviousValid_.fill(0);
        viewHavePrevious_ = false;
        return;
    }
    const double now = ImGui::GetTime();
    if (!force && !viewNeedsRefresh_ &&
        (!viewAutoRefresh_ || now - viewLastRefresh_ < 0.25))
        return;
    viewLastRefresh_ = now;
    viewNeedsRefresh_ = false;

    if (viewOwner_.sameSession(target)) {
        viewPrevious_ = viewBytes_;
        viewPreviousValid_ = viewValid_;
        viewHavePrevious_ = true;
    } else {
        viewHavePrevious_ = false;
        viewPreviousValid_.fill(0);
    }
    viewBytes_.fill(0);
    viewValid_.fill(0);
    viewBytesRead_ = 0;
    viewStatus_.clear();
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    const uint64_t pageSize = info.dwPageSize ? info.dwPageSize : 4096;
    const uint64_t limit = target.is32 ? UINT32_MAX : UINT64_MAX;
    // A failed page must not hide a later readable page. At most two OS-page
    // reads cover this small viewer; each read still checks the exact session.
    for (size_t offset = 0; offset < viewBytes_.size();) {
        const uint64_t address = viewBase_ + offset;
        if (address > limit) break;
        size_t count = (std::min)(viewBytes_.size() - offset,
            static_cast<size_t>(pageSize - address % pageSize));
        if (count - 1 > limit - address)
            count = static_cast<size_t>(limit - address + 1);
        std::string error;
        const size_t got = (std::min)(count, readTarget(&ctx.debug, &passive_,
            target, address, viewBytes_.data() + offset, count, &error));
        std::fill_n(viewValid_.begin() + offset, got, uint8_t{1});
        viewBytesRead_ += got;
        if (got != count && viewStatus_.empty())
            viewStatus_ = error.empty() ? "Some bytes could not be read." : error;
        offset += count;
    }
    viewOwner_ = target;
    if (viewBytesRead_ != viewBytes_.size() && viewStatus_.empty())
        viewStatus_ = "Outside the target address range.";
}

void MemoryToolsTab::renderHexViewer(AppContext& ctx, const TargetToken& target) {
    const float scale = theme::UiScale();
    const uint64_t targetLimit = target.is32 ? UINT32_MAX : UINT64_MAX;
    const bool focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
                         !ImGui::GetIO().WantTextInput;
    auto restoreHistory = [&] {
        const ViewerLocation location = viewHistory_[viewHistoryIndex_];
        navigateViewer(location.address, false, location.selectionBytes);
    };
    if (focused && ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_G))
        viewFocusAddress_ = true;
    if (focused && ImGui::GetIO().KeyAlt && !viewHistory_.empty()) {
        if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow) && viewHistoryIndex_ > 0) {
            --viewHistoryIndex_; restoreHistory();
        }
        if (ImGui::IsKeyPressed(ImGuiKey_RightArrow) &&
            viewHistoryIndex_ + 1 < viewHistory_.size()) {
            ++viewHistoryIndex_; restoreHistory();
        }
    }
    ImGui::BeginDisabled(viewHistory_.empty() || viewHistoryIndex_ == 0);
    if (ImGui::Button("<##mem_back")) {
        --viewHistoryIndex_;
        restoreHistory();
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Back (Alt+Left)");
    ImGui::SameLine();
    ImGui::BeginDisabled(viewHistory_.empty() ||
                         viewHistoryIndex_ + 1 >= viewHistory_.size());
    if (ImGui::Button(">##mem_forward")) {
        ++viewHistoryIndex_;
        restoreHistory();
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
        ImGui::SetTooltip("Forward (Alt+Right)");
    ImGui::SameLine();
    ImGui::SetNextItemWidth((std::max)(100.0f * scale,
        (std::min)(190.0f * scale, ImGui::GetContentRegionAvail().x - 50.0f * scale)));
    if (viewFocusAddress_) { ImGui::SetKeyboardFocusHere(); viewFocusAddress_ = false; }
    const bool enter = ImGui::InputTextWithHint("##memory_view_address", "Hex address (Ctrl+G)",
        viewAddress_, sizeof(viewAddress_), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if (enter || ImGui::Button("Go")) {
        uint64_t address = 0;
        if (parseHexAddress(viewAddress_, address) && address <= targetLimit)
            navigateViewer(address);
        else if (parseHexAddress(viewAddress_, address))
            ui::Toast(ui::ToastKind::Error, "Address exceeds this 32-bit target's range.");
        else ui::Toast(ui::ToastKind::Error, "Memory address must be hexadecimal.");
    }
    ui::SameLineIfFits(275.0f * scale);
    ImGui::BeginDisabled(!viewBaseValid_ || viewBase_ == 0);
    if (ImGui::Button("-0x100"))
        navigateViewer(viewBase_ >= 0x100 ? viewBase_ - 0x100 : 0);
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!viewBaseValid_ || viewBase_ > targetLimit - 0x100);
    if (ImGui::Button("+0x100"))
        navigateViewer(viewBase_ + 0x100);
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (ImGui::Button("Refresh"))
        refreshViewer(ctx, target, true);
    ui::SameLineIfFits(100.0f * scale);
    ImGui::Checkbox("Live refresh", &viewAutoRefresh_);

    refreshViewer(ctx, target, false);
    ImGui::PushTextWrapPos();
    ImGui::TextDisabled("%zu/256 bytes readable | %s", viewBytesRead_,
        viewAutoRefresh_ ? "updates every 250 ms" : "snapshot held");
    if (!viewStatus_.empty()) ImGui::TextColored(theme::col::warn(), "%s", viewStatus_.c_str());
    ImGui::PopTextWrapPos();

    const float gridHeight = (std::clamp)(ImGui::GetContentRegionAvail().y * 0.56f,
                                         100.0f * scale, 350.0f * scale);
    if (ImGui::BeginChild("##memory_hex_grid", ImVec2(0, gridHeight),
                          ImGuiChildFlags_Borders,
                          ImGuiWindowFlags_HorizontalScrollbar)) {
        if (ImGui::IsWindowFocused() && !ImGui::GetIO().WantTextInput &&
            !ImGui::GetIO().KeyAlt) {
            const ImGuiIO& io = ImGui::GetIO();
            int next = (std::max)(viewSelectionEnd_, 0);
            if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow)) --next;
            if (ImGui::IsKeyPressed(ImGuiKey_RightArrow)) ++next;
            if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) next -= 16;
            if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) next += 16;
            if (ImGui::IsKeyPressed(ImGuiKey_Home)) next = io.KeyCtrl ? 0 : next & ~15;
            if (ImGui::IsKeyPressed(ImGuiKey_End)) next = io.KeyCtrl ? 255 : next | 15;
            if (next != viewSelectionEnd_) {
                selectViewerByte(next, io.KeyShift); viewScrollSelection_ = true;
            }
            if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A)) {
                selectViewerByte(0, false); selectViewerByte(255, true);
            }
            if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C)) {
                const std::string text = viewerSelectionText(io.KeyShift);
                if (!text.empty()) ImGui::SetClipboardText(text.c_str());
                else ui::Toast(ui::ToastKind::Warn,
                    "Unreadable selection: use Ctrl+Shift+C to copy an AOB with ??.");
            }
        }
        ui::PushMono();
        const float cell = ImGui::CalcTextSize("00").x + 7.0f * scale;
        const float asciiCell = ImGui::CalcTextSize("M").x + 1.0f * scale;
        const float byteStart = ImGui::CalcTextSize(target.is32 ? "00000000" : "0000000000000000").x +
                                16.0f * scale;
        const float asciiStart = byteStart + 16 * (cell + 1.0f) + 8.0f * scale;
        ImGui::TextUnformatted("Address");
        for (int column = 0; column < 16; ++column) {
            ImGui::SameLine(byteStart + column * (cell + 1.0f));
            ImGui::TextDisabled("%02X", column);
        }
        ImGui::SameLine(asciiStart); ImGui::TextDisabled("ASCII");
        for (size_t line = 0; line < 16; ++line) {
            const size_t first = line * 16;
            ImGui::PushID(static_cast<int>(line));
            ImGui::Text("%0*llX", target.is32 ? 8 : 16,
                         static_cast<unsigned long long>(viewBase_ + first));
            for (size_t column = 0; column < 16; ++column) {
                const size_t offset = first + column;
                ImGui::SameLine(byteStart + column * (cell + 1.0f));
                ImGui::PushID(static_cast<int>(column));
                char byte[4] = "??";
                if (viewValid_[offset])
                    std::snprintf(byte, sizeof(byte), "%02X", viewBytes_[offset]);
                const int lo = (std::min)(viewSelectionBegin_, viewSelectionEnd_);
                const int hi = (std::max)(viewSelectionBegin_, viewSelectionEnd_);
                const bool selected = viewSelectionBegin_ >= 0 &&
                                      static_cast<int>(offset) >= lo &&
                                      static_cast<int>(offset) <= hi;
                const bool changed = viewValid_[offset] && viewHavePrevious_ &&
                                     viewPreviousValid_[offset] &&
                                     viewBytes_[offset] != viewPrevious_[offset];
                ImGui::PushStyleColor(ImGuiCol_Text, !viewValid_[offset] ? theme::col::muted() :
                    changed ? theme::col::warn() : ImGui::GetStyleColorVec4(ImGuiCol_Text));
                const bool activated = ImGui::Selectable(byte, selected, 0, ImVec2(cell, 0.0f));
                if (activated || ImGui::IsItemClicked(ImGuiMouseButton_Left)) {
                    selectViewerByte(static_cast<int>(offset), ImGui::GetIO().KeyShift);
                }
                if (ImGui::IsItemHovered() && ImGui::IsMouseDragging(ImGuiMouseButton_Left))
                    selectViewerByte(static_cast<int>(offset), true);
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s\n%s%s%s",
                    hexAddress(viewBase_ + offset).c_str(),
                    viewValid_[offset] ? "Readable byte" : "Unreadable byte; never treated as zero",
                    changed ? " | changed since previous refresh" : "",
                    viewWildcard_[offset] ? " | copied as ?? in AOB" : "");
                if (viewWildcard_[offset]) {
                    const ImVec2 min = ImGui::GetItemRectMin(), max = ImGui::GetItemRectMax();
                    ImGui::GetWindowDrawList()->AddLine(ImVec2(min.x, max.y - 1),
                        ImVec2(max.x, max.y - 1), ImGui::GetColorU32(theme::col::accent()), 1.0f);
                }
                if (viewScrollSelection_ && static_cast<int>(offset) == viewSelectionEnd_) {
                    ImGui::SetScrollHereY(0.5f); viewScrollSelection_ = false;
                }
                ImGui::PopStyleColor();
                ImGui::PopID();
            }
            for (size_t column = 0; column < 16; ++column) {
                const size_t offset = first + column;
                const uint8_t ch = viewBytes_[offset];
                const char text[2] = {viewValid_[offset] ?
                    (ch >= 32 && ch < 127 ? static_cast<char>(ch) : '.') : '?', '\0'};
                ImGui::SameLine(asciiStart + column * asciiCell);
                ImGui::PushID(static_cast<int>(offset) + 256);
                const bool selected = viewSelectionBegin_ >= 0 &&
                    static_cast<int>(offset) >= (std::min)(viewSelectionBegin_, viewSelectionEnd_) &&
                    static_cast<int>(offset) <= (std::max)(viewSelectionBegin_, viewSelectionEnd_);
                const bool activated = ImGui::Selectable(text, selected, 0, ImVec2(asciiCell, 0));
                if (activated || ImGui::IsItemClicked(ImGuiMouseButton_Left))
                    selectViewerByte(static_cast<int>(offset), ImGui::GetIO().KeyShift);
                if (ImGui::IsItemHovered() && ImGui::IsMouseDragging(ImGuiMouseButton_Left))
                    selectViewerByte(static_cast<int>(offset), true);
                ImGui::PopID();
            }
            ImGui::PopID();
        }
        ui::PopMono();
    }
    ImGui::EndChild();

    const int selectionLo = (std::min)(viewSelectionBegin_, viewSelectionEnd_);
    const int selectionHi = (std::max)(viewSelectionBegin_, viewSelectionEnd_);
    const bool hasSelection = selectionLo >= 0 && selectionHi >= selectionLo &&
                              selectionHi < static_cast<int>(viewBytes_.size());
    const size_t selectionSize = hasSelection ? static_cast<size_t>(selectionHi - selectionLo + 1) : 0;
    const bool validSelection = hasSelection && viewerRangeReadable(selectionLo, selectionSize);
    if (hasSelection) {
        ImGui::PushTextWrapPos();
        ImGui::Text("%s - %s | %zu byte%s", hexAddress(viewBase_ + selectionLo).c_str(),
            hexAddress(viewBase_ + selectionHi).c_str(), selectionSize, selectionSize == 1 ? "" : "s");
        ImGui::PopTextWrapPos();
    }
    ImGui::BeginDisabled(!hasSelection);
    if (ImGui::Button("Copy...")) ImGui::OpenPopup("##memory_copy");
    if (ImGui::BeginPopup("##memory_copy")) {
        if (ImGui::MenuItem("Exact bytes", "Ctrl+C", false, validSelection))
            ImGui::SetClipboardText(viewerSelectionText(false).c_str());
        if (ImGui::MenuItem("AOB with wildcards", "Ctrl+Shift+C"))
            ImGui::SetClipboardText(viewerSelectionText(true).c_str());
        if (ImGui::MenuItem("ASCII display", nullptr, false, validSelection))
            ImGui::SetClipboardText(viewerSelectionText(false, true).c_str());
        if (ImGui::MenuItem("Selected address"))
            ImGui::SetClipboardText(hexAddress(viewBase_ + selectionLo).c_str());
        ImGui::Separator();
        if (ImGui::MenuItem("Use ?? for selected bytes"))
            std::fill(viewWildcard_.begin() + selectionLo,
                      viewWildcard_.begin() + selectionHi + 1, uint8_t{1});
        if (ImGui::MenuItem("Use exact selected bytes"))
            std::fill(viewWildcard_.begin() + selectionLo,
                      viewWildcard_.begin() + selectionHi + 1, uint8_t{0});
        if (ImGui::MenuItem("Clear all wildcard marks")) viewWildcard_.fill(0);
        ImGui::TextDisabled("Underlined bytes and unreadable bytes become ?? in AOB copies.");
        ImGui::TextDisabled("Marks apply to this view until navigation; memory is unchanged.");
        ImGui::EndPopup();
    }
    ImGui::EndDisabled();
    ui::SameLineIfFits(115.0f * scale);
    ImGui::BeginDisabled(!validSelection);
    if (ImGui::Button("Add address")) {
        std::vector<uint8_t> captured(viewBytes_.begin() + selectionLo,
                                      viewBytes_.begin() + selectionHi + 1);
        const MemoryValueType type = captured.size() == 1 ? MemoryValueType::UInt8 :
            captured.size() == 2 ? MemoryValueType::UInt16 :
            captured.size() == 4 ? MemoryValueType::UInt32 :
            captured.size() == 8 ? MemoryValueType::UInt64 : MemoryValueType::ByteArray;
        addAddressRow(ctx, target, viewBase_ + selectionLo, type, &captured, "viewer selection");
    }
    ImGui::EndDisabled();
    const size_t pointerWidth = target.is32 ? 4u : 8u;
    ui::SameLineIfFits(140.0f * scale);
    ImGui::BeginDisabled(!viewerRangeReadable(selectionLo, pointerWidth));
    bool followedPointer = false;
    if (ImGui::Button("Follow pointer")) {
        uint64_t pointer = 0;
        std::memcpy(&pointer, viewBytes_.data() + selectionLo, pointerWidth);
        navigateViewer(pointer);
        followedPointer = true;
    }
    ImGui::EndDisabled();
    if (followedPointer) return;

    // These are interpretations of bytes at the selection start, not inferred
    // variable types. Their read width is independent of the selected span.
    if (ImGui::CollapsingHeader("Value at selection", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::SetNextItemWidth(85.0f * scale);
        ImGui::Combo("##memory_value_type", &viewValueType_, kMemoryTypeNames, 10);
        const MemoryValueType type = static_cast<MemoryValueType>(viewValueType_);
        const size_t width = MemoryValueTypeFixedSize(type);
        const bool readable = viewerRangeReadable(selectionLo, width);
        ui::SameLineIfFits(180.0f * scale);
        const std::string value = readable ? formatMemoryValue(type,
            viewBytes_.data() + selectionLo, width) : "unreadable";
        ImGui::TextUnformatted(value.c_str());
        if (readable && type != MemoryValueType::Float32 && type != MemoryValueType::Float64) {
            ui::SameLineIfFits(110.0f * scale);
            ImGui::TextDisabled("(%s)", formatMemoryValue(type,
                viewBytes_.data() + selectionLo, width, true).c_str());
        }
        ImGui::BeginDisabled(!readable);
        if (ImGui::SmallButton("Copy value")) ImGui::SetClipboardText(value.c_str());
        ui::SameLineIfFits(150.0f * scale);
        if (ImGui::SmallButton("Add typed address")) {
            std::vector<uint8_t> captured(viewBytes_.begin() + selectionLo,
                                          viewBytes_.begin() + selectionLo + width);
            addAddressRow(ctx, target, viewBase_ + selectionLo, type, &captured, "viewer value");
        }
        ImGui::EndDisabled();
        ui::SameLineIfFits(175.0f * scale);
        ImGui::TextDisabled("%zu bytes, little-endian", width);
    }
    if (ImGui::CollapsingHeader("Edit selected bytes")) {
        ImGui::PushTextWrapPos();
        ImGui::BeginDisabled(!validSelection || !target.canWrite);
        if (ImGui::SmallButton("Load selection into editor"))
            std::snprintf(viewEdit_, sizeof(viewEdit_), "%s", viewerSelectionText(false).c_str());
        ImGui::TextDisabled("Exact-length, verified write. Selecting another span clears this draft.");
        ImGui::SetNextItemWidth(-1.0f);
        ImGui::InputTextWithHint("##memory_edit", "bytes: e.g. 90 90 01", viewEdit_,
                                 sizeof(viewEdit_));
        ImGui::EndDisabled();
        ImGui::BeginDisabled(!validSelection || !target.canWrite || !viewEdit_[0]);
        if (ImGui::Button("Write selected bytes")) {
            MemoryScanValue value;
            std::string error;
            if (!ParseMemoryScanValue(MemoryValueType::ByteArray, viewEdit_, value, &error) ||
                (!value.mask.empty() && std::find(value.mask.begin(), value.mask.end(), 0u) !=
                                        value.mask.end())) {
                if (error.empty()) error = "Writes cannot contain ?? wildcards.";
                ui::Toast(ui::ToastKind::Error, error);
            } else if (value.bytes.size() != selectionSize) {
                ui::Toast(ui::ToastKind::Error,
                          "Write length must exactly match the selected byte span.");
            } else if (writeTarget(&ctx.debug, &passive_, target,
                                   viewBase_ + static_cast<uint64_t>(selectionLo),
                                   value.bytes, false, error)) {
                ui::Toast(ui::ToastKind::Success, "Verified memory write applied.");
                refreshViewer(ctx, target, true);
            } else {
                ui::Toast(ui::ToastKind::Error, error);
            }
        }
        ImGui::EndDisabled();
        ImGui::PopTextWrapPos();
    }
    if (ImGui::CollapsingHeader("Viewer controls")) {
        ImGui::PushTextWrapPos();
        ImGui::TextDisabled("Click bytes or ASCII; drag or Shift-click to select. Arrow keys move; Shift+arrows extend. Home/End move within a row; Ctrl+Home/End and Ctrl+A cover this view. Ctrl+C copies bytes; Ctrl+Shift+C copies AOB. Ctrl+G focuses the address; Alt+Left/Right use history. Amber = changed; ?? = unreadable; underline = wildcard mark.");
        ImGui::PopTextWrapPos();
    }
}

void MemoryToolsTab::renderRegionBrowser(AppContext& ctx,
                                         const TargetToken& target) {
    if (!regionOwner_.sameSession(target)) refreshRegionCache(ctx, target);
    if (ImGui::Button(DS_ICON_REFRESH " Refresh map")) refreshRegionCache(ctx, target);
    ImGui::SameLine();
    ui::SearchBox("##memory_region_filter", "module, type, protection...",
                  regionFilter_, sizeof(regionFilter_), 230.0f * theme::UiScale());
    ImGui::SameLine(); ImGui::Checkbox("R", &regionReadableOnly_);
    ImGui::SameLine(); ImGui::Checkbox("W", &regionWritableOnly_);
    ImGui::SameLine(); ImGui::Checkbox("X", &regionExecutableOnly_);
    if (!regionStatus_.empty()) ImGui::TextDisabled("%s", regionStatus_.c_str());

    const auto modules = modulesFor(ctx, target);
    std::vector<size_t> visibleRegions;
    visibleRegions.reserve(regionCache_.size());
    for (size_t index = 0; index < regionCache_.size(); ++index) {
        const TargetRegion& region = regionCache_[index];
        if (regionReadableOnly_ && !region.readable) continue;
        if (regionWritableOnly_ && !region.writable) continue;
        if (regionExecutableOnly_ && !region.executable) continue;
        if (regionFilter_[0]) {
            const std::string module = moduleAddressLabel(modules, region.base);
            const std::string access = protectionLabel(region);
            const std::string type = regionTypeLabel(region.type);
            if (!caseContains(module, regionFilter_) &&
                !caseContains(access, regionFilter_) &&
                !caseContains(type, regionFilter_)) continue;
        }
        visibleRegions.push_back(index);
    }
    if (ImGui::BeginTable("##memory_regions", 7,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("End", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("Size", ImGuiTableColumnFlags_WidthFixed, 80.0f);
        ImGui::TableSetupColumn("Access", ImGuiTableColumnFlags_WidthFixed, 62.0f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 68.0f);
        ImGui::TableSetupColumn("Module");
        ImGui::TableSetupColumn("Allocation", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(visibleRegions.size()));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const TargetRegion& region = regionCache_[visibleRegions[static_cast<size_t>(i)]];
                const std::string module = moduleAddressLabel(modules, region.base);
                const std::string access = protectionLabel(region);
                const std::string type = regionTypeLabel(region.type);
                const uint64_t end = region.size > UINT64_MAX - region.base
                    ? UINT64_MAX : region.base + region.size;
                ImGui::TableNextRow();
                ImGui::PushID(i);
                ImGui::TableSetColumnIndex(0);
                const std::string base = hexAddress(region.base);
                if (ImGui::Selectable(base.c_str(), false,
                                      ImGuiSelectableFlags_SpanAllColumns |
                                      ImGuiSelectableFlags_AllowDoubleClick) &&
                    ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                    navigateViewer(region.base);
                    inspectorSelectRequest_ = 0;
                }
                if (ImGui::BeginPopupContextItem("##region_menu")) {
                    if (ImGui::MenuItem("Open in memory viewer")) {
                        navigateViewer(region.base); inspectorSelectRequest_ = 0;
                    }
                    if (ImGui::MenuItem("Use as scan range")) {
                        std::snprintf(scanStart_, sizeof(scanStart_), "%llX",
                                      static_cast<unsigned long long>(region.base));
                        std::snprintf(scanEnd_, sizeof(scanEnd_), "%llX",
                                      static_cast<unsigned long long>(end ? end - 1 : end));
                        if (firstScanDone_) clearScan("Region selected; start a new scan.");
                    }
                    if (ImGui::MenuItem("Copy base")) ImGui::SetClipboardText(base.c_str());
                    ImGui::EndPopup();
                }
                ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(hexAddress(end).c_str());
                ImGui::TableSetColumnIndex(2); ImGui::Text("%.2f MiB", region.size / 1048576.0);
                ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(access.c_str());
                ImGui::TableSetColumnIndex(4); ImGui::TextUnformatted(type.c_str());
                ImGui::TableSetColumnIndex(5); ImGui::TextUnformatted(module.c_str());
                ImGui::TableSetColumnIndex(6);
                ImGui::TextUnformatted(hexAddress(region.allocationBase).c_str());
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
}

void MemoryToolsTab::cancelPointerScan() {
    if (!pointerRunning_.load(std::memory_order_acquire)) return;
    pointerCancel_.store(true, std::memory_order_release);
    pointerStatus_ = "Cancelling pointer scan...";
}

void MemoryToolsTab::pumpPointerCompletion() {
    if (pointerRunning_.load(std::memory_order_acquire)) return;
    if (pointerThread_.joinable()) pointerThread_.join();
    PointerCompletion completed;
    {
        std::lock_guard lock(pointerMutex_);
        if (!pointerCompletionReady_) return;
        completed = std::move(pointerCompletion_);
        pointerCompletionReady_ = false;
    }
    if (completed.epoch != pointerEpoch_ || !completed.owner.sameSession(lastTarget_)) return;
    pointerRows_ = std::move(completed.rows);
    pointerStatus_ = std::move(completed.status);
}

void MemoryToolsTab::startPointerScan(AppContext& ctx, const TargetToken& target) {
    pumpPointerCompletion();
    if (!target.valid() || pointerRunning_.load(std::memory_order_acquire)) return;
    uint64_t seed = 0;
    if (!parseHexAddress(pointerTarget_, seed)) {
        pointerStatus_ = "Pointer target must be a hexadecimal address.";
        return;
    }
    if (!MemoryPointerAddressCanonical(seed, target.is32 ? 4 : 8)) {
        pointerStatus_ = target.is32
            ? "Pointer target is outside the 32-bit address space."
            : "Pointer target is not a canonical x64 address.";
        return;
    }
    if (pointerThread_.joinable()) pointerThread_.join();
    pointerRows_.clear();
    pointerCancel_.store(false, std::memory_order_release);
    pointerProgress_.store(0, std::memory_order_relaxed);
    pointerTotal_.store(static_cast<uint64_t>((std::clamp)(pointerMaxMiB_, 16, 1024)) << 20,
                        std::memory_order_relaxed);
    pointerStatus_ = "Capturing readable pages for a bounded pointer backlink scan...";
    const int depth = (std::clamp)(pointerDepth_, 1, 16);
    const uint64_t maxOffset = static_cast<uint64_t>((std::clamp)(pointerMaxOffset_, 0, 1 << 20));
    const uint64_t readCap = static_cast<uint64_t>((std::clamp)(pointerMaxMiB_, 16, 1024)) << 20;
    const bool writableOnly = pointerWritableOnly_;
    const bool staticRootsOnly = pointerStaticRootsOnly_;
    Debugger* debugger = &ctx.debug;
    ProcessMemorySession* passive = &passive_;
    const auto modules = modulesFor(ctx, target);
    const uint64_t epoch = pointerEpoch_;
    pointerRunning_.store(true, std::memory_order_release);
    try {
        pointerThread_ = std::thread([this, debugger, passive, target, seed, depth,
                                      maxOffset, readCap, writableOnly,
                                      staticRootsOnly, modules, epoch] {
            PointerCompletion done;
            done.owner = target;
            done.epoch = epoch;
            try {
                std::string mapError;
                const auto regions = collectRegions(debugger, passive, target, mapError);
                std::vector<std::vector<uint8_t>> storage;
                std::vector<uint64_t> bases;
                uint64_t attempted = 0;
                for (const TargetRegion& region : regions) {
                    if (pointerCancel_.load(std::memory_order_acquire)) break;
                    if (!region.readable || region.guarded || region.noAccess || !region.size ||
                        (writableOnly && !region.writable)) continue;
                    uint64_t cursor = region.base;
                    uint64_t remaining = region.size;
                    while (remaining && attempted < readCap) {
                        if (pointerCancel_.load(std::memory_order_acquire)) break;
                        const size_t request = static_cast<size_t>((std::min<uint64_t>)({
                            remaining, kPointerReadChunkBytes, readCap - attempted }));
                        const uint64_t lookahead = remaining > request
                            ? (std::min<uint64_t>)(target.is32 ? 3u : 7u,
                                                   remaining - request)
                            : 0;
                        std::vector<uint8_t> bytes(request +
                                                   static_cast<size_t>(lookahead));
                        const size_t got = readTarget(debugger, passive, target, cursor,
                                                      bytes.data(), bytes.size());
                        attempted += request;
                        pointerProgress_.store(attempted, std::memory_order_relaxed);
                        if (got >= (target.is32 ? 4u : 8u)) {
                            bytes.resize(got);
                            bases.push_back(cursor);
                            storage.push_back(std::move(bytes));
                        }
                        cursor += request;
                        remaining -= request;
                    }
                    if (attempted >= readCap) { done.coverageTruncated = true; break; }
                }
                done.bytesRead = 0;
                for (const auto& bytes : storage) done.bytesRead += bytes.size();

                if (pointerCancel_.load(std::memory_order_acquire)) {
                    done.status = "Pointer scan cancelled.";
                } else {
                    std::vector<MemoryPointerBlock> blocks;
                    blocks.reserve(storage.size());
                    for (size_t i = 0; i < storage.size(); ++i)
                        blocks.push_back({ bases[i], storage[i] });
                    MemoryPointerSearchOptions options;
                    options.pointerWidth = target.is32 ? 4 : 8;
                    options.maxDepth = static_cast<uint32_t>(depth);
                    options.maxOffset = maxOffset;
                    options.maxResults = 50'000;
                    options.maxFrontier = 150'000;
                    options.maxSeedTargets = 250'000;
                    options.maxCandidateReads = 75'000'000;
                    options.maxComparisons = 125'000'000;
                    options.cancelled = [this] {
                        return pointerCancel_.load(std::memory_order_acquire);
                    };
                    const std::array<uint64_t, 1> seeds{ seed };
                    MemoryPointerSearchResult result = FindMemoryPointerChains(
                        blocks, seeds, options);
                    if (result.status == MemoryPointerSearchStatus::Cancelled) {
                        done.status = "Pointer scan cancelled.";
                    } else if (result.status == MemoryPointerSearchStatus::InvalidOptions) {
                        done.status = "Pointer scan rejected invalid or out-of-bounds options.";
                    } else if (result.status == MemoryPointerSearchStatus::ResourceFailure) {
                        done.status = "Pointer scan stopped because bounded working memory could not be allocated.";
                    } else {
                        done.rows.reserve(result.chains.size());
                        for (MemoryPointerChain& chain : result.chains) {
                            const MemoryTableModuleView* module = containingModule(modules,
                                                                                   chain.rootAddress);
                            if (staticRootsOnly && !module) continue;
                            PointerRow row;
                            row.chain = std::move(chain);
                            row.moduleRoot = module != nullptr;
                            if (module) {
                                row.address.kind = MemoryTableBaseKind::ModuleRelative;
                                row.address.moduleName = module->name;
                                row.address.modulePath = module->path;
                                row.address.moduleOffset = row.chain.rootAddress - module->base;
                                row.rootLabel = moduleAddressLabel(modules, row.chain.rootAddress);
                            } else {
                                row.address.kind = MemoryTableBaseKind::Absolute;
                                row.address.absoluteAddress = row.chain.rootAddress;
                                row.rootLabel = hexAddress(row.chain.rootAddress);
                            }
                            row.address.pointerOffsets.reserve(row.chain.offsets.size());
                            for (uint64_t offset : row.chain.offsets)
                                row.address.pointerOffsets.push_back(static_cast<int64_t>(offset));
                            done.rows.push_back(std::move(row));
                        }
                        std::stable_sort(done.rows.begin(), done.rows.end(),
                            [](const PointerRow& a, const PointerRow& b) {
                                if (a.moduleRoot != b.moduleRoot) return a.moduleRoot > b.moduleRoot;
                                if (a.chain.offsets.size() != b.chain.offsets.size())
                                    return a.chain.offsets.size() < b.chain.offsets.size();
                                const uint64_t as = std::accumulate(a.chain.offsets.begin(),
                                                                    a.chain.offsets.end(), uint64_t{});
                                const uint64_t bs = std::accumulate(b.chain.offsets.begin(),
                                                                    b.chain.offsets.end(), uint64_t{});
                                return as == bs ? a.chain.rootAddress < b.chain.rootAddress : as < bs;
                            });
                        char text[300]{};
                        std::snprintf(text, sizeof(text),
                            "%s pointer chains from %.1f MiB%s%s.",
                            compactCount(done.rows.size()).c_str(),
                            done.bytesRead / 1048576.0,
                            done.coverageTruncated ? "; coverage hit the read cap" : "",
                            result.status == MemoryPointerSearchStatus::Truncated
                                ? "; search work/result bounds were reached" : "");
                        done.status = text;
                        if (!mapError.empty()) done.status += " Map: " + mapError;
                    }
                }
            } catch (const std::bad_alloc&) {
                done.status = "Pointer capture exceeded available memory; lower the read cap.";
            } catch (const std::exception& exception) {
                done.status = std::string("Pointer scan failed: ") + exception.what();
            } catch (...) {
                done.status = "Pointer scan failed.";
            }
            {
                std::lock_guard lock(pointerMutex_);
                pointerCompletion_ = std::move(done);
                pointerCompletionReady_ = true;
            }
            pointerRunning_.store(false, std::memory_order_release);
        });
    } catch (const std::exception& exception) {
        pointerRunning_.store(false, std::memory_order_release);
        pointerStatus_ = std::string("Unable to start pointer scan: ") + exception.what();
    }
}

void MemoryToolsTab::renderPointerScanner(AppContext& ctx,
                                          const TargetToken& target) {
    pumpPointerCompletion();
    const float scale = theme::UiScale();
    const bool running = pointerRunning_.load(std::memory_order_acquire);
    ImGui::TextWrapped("Finds bounded pointer paths ending at a live address. Module roots are ASLR-stable and rank first.");
    ImGui::BeginDisabled(running);
    ImGui::SetNextItemWidth(160.0f * scale);
    ImGui::InputText("Target (hex)", pointerTarget_, sizeof(pointerTarget_),
                     ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SetNextItemWidth(90.0f * scale);
    ImGui::InputInt("Max depth", &pointerDepth_);
    pointerDepth_ = (std::clamp)(pointerDepth_, 1, 16);
    ui::SameLineIfFits(100.0f * scale + ImGui::CalcTextSize("Max offset").x + ImGui::GetStyle().ItemInnerSpacing.x);
    ImGui::SetNextItemWidth(100.0f * scale);
    ImGui::InputInt("Max offset", &pointerMaxOffset_);
    pointerMaxOffset_ = (std::clamp)(pointerMaxOffset_, 0, 1 << 20);
    ui::SameLineIfFits(90.0f * scale + ImGui::CalcTextSize("Read MiB").x + ImGui::GetStyle().ItemInnerSpacing.x);
    ImGui::SetNextItemWidth(90.0f * scale);
    ImGui::InputInt("Read MiB", &pointerMaxMiB_);
    pointerMaxMiB_ = (std::clamp)(pointerMaxMiB_, 16, 1024);
    ImGui::Checkbox("Module roots only", &pointerStaticRootsOnly_);
    ui::SameLineIfFits(ImGui::GetFrameHeight() + ImGui::CalcTextSize("Writable storage only").x + ImGui::GetStyle().ItemInnerSpacing.x);
    ImGui::Checkbox("Writable storage only", &pointerWritableOnly_);
    ImGui::EndDisabled();

    ImGui::BeginDisabled(running || !target.valid());
    if (ui::AccentButton("Pointer scan", theme::col::accent())) startPointerScan(ctx, target);
    ImGui::EndDisabled();
    if (running) {
        ui::SameLineIfFits(ImGui::CalcTextSize("Cancel").x + ImGui::GetStyle().FramePadding.x * 2);
        if (ImGui::Button("Cancel")) cancelPointerScan();
        const uint64_t total = pointerTotal_.load(std::memory_order_relaxed);
        const uint64_t done = pointerProgress_.load(std::memory_order_relaxed);
        ImGui::ProgressBar(total ? static_cast<float>((std::min)(done, total)) /
                                      static_cast<float>(total) : 0.0f,
                           ImVec2(-1, 0), nullptr);
    }
    if (!pointerStatus_.empty()) {
        ImGui::PushTextWrapPos();
        ImGui::TextDisabled("%s", pointerStatus_.c_str());
        ImGui::PopTextWrapPos();
    }
    if (pointerRows_.empty()) {
        ImGui::TextWrapped(running ? "Searching for pointer paths..."
            : pointerStatus_.empty()
                ? "Enter a target address and run Pointer scan. Results can be added to the address table with a double-click or the context menu."
                : "No pointer paths to show. Review the scan status above, adjust the target or scan limits, then run Pointer scan again.");
        return;
    }
    ImGui::TextDisabled("%zu pointer path%s", pointerRows_.size(), pointerRows_.size() == 1 ? "" : "s");
    ui::ItemTooltip("Double-click a path to add it to the address table. Right-click for viewer actions.");

    if (ImGui::BeginTable("##pointer_results", 4,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("Root", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Offsets", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Depth", ImGuiTableColumnFlags_WidthFixed, 52.0f * scale);
        ImGui::TableSetupColumn("Root kind", ImGuiTableColumnFlags_WidthFixed, 72.0f * scale);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(pointerRows_.size()));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const PointerRow& row = pointerRows_[static_cast<size_t>(i)];
                std::string offsets;
                for (uint64_t offset : row.chain.offsets) {
                    if (!offsets.empty()) offsets += " -> ";
                    offsets += "+0x";
                    char text[24]{};
                    std::snprintf(text, sizeof(text), "%llX",
                                  static_cast<unsigned long long>(offset));
                    offsets += text;
                }
                ImGui::TableNextRow();
                ImGui::PushID(i);
                ImGui::TableSetColumnIndex(0);
                if (ImGui::Selectable(row.rootLabel.c_str(), false,
                                      ImGuiSelectableFlags_SpanAllColumns |
                                      ImGuiSelectableFlags_AllowDoubleClick) &&
                    ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left))
                    addPointerRow(ctx, target, row);
                if (ImGui::BeginPopupContextItem("##pointer_menu")) {
                    if (ImGui::MenuItem("Add pointer to address table"))
                        addPointerRow(ctx, target, row);
                    if (ImGui::MenuItem("Open root in viewer")) {
                        navigateViewer(row.chain.rootAddress); inspectorSelectRequest_ = 0;
                    }
                    if (ImGui::MenuItem("Open target in viewer")) {
                        navigateViewer(row.chain.targetAddress); inspectorSelectRequest_ = 0;
                    }
                    ImGui::EndPopup();
                }
                ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(offsets.c_str());
                ImGui::TableSetColumnIndex(2); ImGui::Text("%zu", row.chain.offsets.size());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextColored(row.moduleRoot ? theme::col::good() : theme::col::warn(),
                                   "%s", row.moduleRoot ? "module" : "absolute");
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
}

void MemoryToolsTab::renderInspector(AppContext& ctx, const TargetToken& target) {
    const int selectRequest = inspectorSelectRequest_;
    inspectorSelectRequest_ = -1;
    if (ImGui::BeginTabBar("##memory_inspector_tabs")) {
        if (ImGui::BeginTabItem("Hex editor", nullptr,
                selectRequest == 0 ? ImGuiTabItemFlags_SetSelected : 0)) {
            inspectorTab_ = 0;
            renderHexViewer(ctx, target);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Regions", nullptr,
                selectRequest == 1 ? ImGuiTabItemFlags_SetSelected : 0)) {
            inspectorTab_ = 1;
            renderRegionBrowser(ctx, target);
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Pointer scan", nullptr,
                selectRequest == 2 ? ImGuiTabItemFlags_SetSelected : 0)) {
            inspectorTab_ = 2;
            renderPointerScanner(ctx, target);
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
}

void MemoryToolsTab::addAddressRow(AppContext& ctx, const TargetToken& target,
                                   uint64_t address, MemoryValueType type,
                                   const std::vector<uint8_t>* captured,
                                   const char* description) {
    if (!target.valid() || table_.size() >= kMemoryTableMaxRecords) return;
    TableRow row;
    row.id = nextTableId_++;
    row.record.description = description ? description : "address";
    row.record.type = type;
    row.record.nullTerminateText =
        (type == MemoryValueType::Utf8 || type == MemoryValueType::Utf16Le) &&
        nullTerminateText_;
    row.record.enabled = true;
    row.absoluteOwner = target;
    const auto modules = modulesFor(ctx, target);
    if (const auto* module = containingModule(modules, address)) {
        row.record.address.kind = MemoryTableBaseKind::ModuleRelative;
        row.record.address.moduleName = module->name;
        row.record.address.modulePath = module->path;
        row.record.address.moduleOffset = address - module->base;
        row.absoluteOwner = {};
    } else {
        row.record.address.kind = MemoryTableBaseKind::Absolute;
        row.record.address.absoluteAddress = address;
    }

    std::vector<uint8_t> bytes;
    const size_t width = MemoryValueTypeFixedSize(type);
    if (captured && !captured->empty()) {
        bytes = *captured;
        if (width && bytes.size() != width) bytes.resize(width, 0);
    } else if (width) {
        bytes.resize(width);
        bytes.resize(readTarget(&ctx.debug, &passive_, target, address,
                                bytes.data(), bytes.size()));
    }
    if (!bytes.empty())
        row.record.desiredValueText = formatMemoryValue(
            type, bytes, false, row.record.nullTerminateText);
    else
        row.record.desiredValueText = "0";
    row.status = "Ready; freezing is off until explicitly armed.";
    table_.push_back(std::move(row));
}

void MemoryToolsTab::addPointerRow(AppContext& ctx, const TargetToken& target,
                                   const PointerRow& pointer) {
    if (!target.valid() || table_.size() >= kMemoryTableMaxRecords) return;
    TableRow row;
    row.id = nextTableId_++;
    row.record.description = "pointer to " + hexAddress(pointer.chain.targetAddress);
    row.record.type = firstScanDone_ && MemoryValueTypeFixedSize(scanShape_.type)
        ? scanShape_.type : MemoryValueType::UInt32;
    row.record.address = pointer.address;
    row.record.enabled = true;
    if (row.record.address.kind == MemoryTableBaseKind::Absolute)
        row.absoluteOwner = target;

    // Pointer scans are snapshots.  Re-resolve the expression immediately
    // before it acquires live-table authority so a target mutation between the
    // scan and this click cannot silently bind the row to a different object.
    if (target.source == TargetSource::Passive)
        refreshPassiveModules(target, ImGui::GetTime());
    const auto modules = modulesFor(ctx, target);
    const auto resolved = ResolveMemoryTableAddress(
        row.record, modules,
        [&ctx, this, &target](uint64_t at, void* output, size_t size) {
            return readTarget(&ctx.debug, &passive_, target, at, output, size);
        }, target.is32 ? 4 : 8);
    const bool stillMatches = resolved.resolved() &&
                              resolved.address == pointer.chain.targetAddress;
    if (!stillMatches) row.record.enabled = false;

    std::vector<uint8_t> current(MemoryValueTypeFixedSize(row.record.type));
    if (stillMatches && !current.empty()) {
        const size_t got = readTarget(&ctx.debug, &passive_, target,
                                      resolved.address,
                                      current.data(), current.size());
        current.resize(got);
    } else {
        current.clear();
    }
    row.record.desiredValueText = current.empty()
        ? "0" : formatMemoryValue(row.record.type, current, false);
    row.status = stillMatches
        ? "Pointer chain revalidated; freezing is off until explicitly armed."
        : "Pointer changed since the scan; added disabled for review.";
    table_.push_back(std::move(row));
}

bool MemoryToolsTab::resolveRow(AppContext& ctx, const TargetToken& target,
                                TableRow& row, uint64_t& address,
                                std::string& error) {
    error.clear();
    address = 0;
    if (!target.valid()) { error = "no memory target"; return false; }
    if (!row.record.enabled) { error = "disabled"; return false; }
    if (row.record.address.kind == MemoryTableBaseKind::Absolute &&
        !row.absoluteOwner.sameSession(target)) {
        error = "absolute address belongs to another target session";
        return false;
    }
    const auto modules = modulesFor(ctx, target);
    const auto resolved = ResolveMemoryTableAddress(row.record, modules,
        [&ctx, this, &target](uint64_t at, void* output, size_t size) {
            return readTarget(&ctx.debug, &passive_, target, at, output, size);
        }, target.is32 ? 4 : 8);
    if (!resolved.resolved()) {
        switch (resolved.status) {
            case MemoryTableResolveStatus::ModuleNotFound: error = "module not loaded"; break;
            case MemoryTableResolveStatus::AmbiguousModule: error = "module identity is ambiguous"; break;
            case MemoryTableResolveStatus::ReadFailure: error = "pointer read failed"; break;
            case MemoryTableResolveStatus::NullPointer: error = "pointer chain reached null"; break;
            case MemoryTableResolveStatus::ArithmeticOverflow: error = "pointer arithmetic overflow"; break;
            case MemoryTableResolveStatus::NonCanonicalAddress:
            case MemoryTableResolveStatus::NonCanonicalPointer: error = "non-canonical address"; break;
            default: error = "address expression is invalid"; break;
        }
        return false;
    }
    address = resolved.address;
    return true;
}

bool MemoryToolsTab::saveTableDialog(const TargetToken& target) {
    targetStatus_.clear();
    std::vector<wchar_t> file(32768, L'\0');
    const std::wstring suggested = wideFromUtf8(
        (target.name.empty() ? std::string("memory-table") : target.name) + ".dsmem.json");
    if (!suggested.empty())
        wcsncpy_s(file.data(), file.size(), suggested.c_str(), _TRUNCATE);
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = GetActiveWindow();
    dialog.lpstrFilter = L"DisasmStudio memory table\0*.dsmem.json\0JSON files\0*.json\0All files\0*.*\0";
    dialog.lpstrFile = file.data();
    dialog.nMaxFile = static_cast<DWORD>(file.size());
    dialog.lpstrDefExt = L"json";
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&dialog)) return false;

    MemoryTableDocument document;
    document.title = target.name.empty() ? "Memory table" : target.name;
    document.records.reserve(table_.size());
    for (const TableRow& row : table_) document.records.push_back(row.record);
    std::string json;
    std::string error;
    if (!SerializeMemoryTable(document, json, &error)) {
        targetStatus_ = "Table save failed: " + error;
        return false;
    }
    if (!atomic_file::Write(std::filesystem::path(file.data()), json)) {
        targetStatus_ = "Table save failed; the previous file/backup remains available.";
        return false;
    }
    targetStatus_ = "Memory table saved atomically (runtime enable/freeze authority is not persisted).";
    return true;
}

bool MemoryToolsTab::loadTableDialog() {
    targetStatus_.clear();
    std::vector<wchar_t> file(32768, L'\0');
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = GetActiveWindow();
    dialog.lpstrFilter = L"DisasmStudio memory table\0*.dsmem.json\0JSON files\0*.json\0All files\0*.*\0";
    dialog.lpstrFile = file.data();
    dialog.nMaxFile = static_cast<DWORD>(file.size());
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&dialog)) return false;
    const std::filesystem::path path(file.data());
    MemoryTableDocument document;
    std::string json;
    std::string error;
    const atomic_file::ReadSource source = atomic_file::ReadValidated(
        path, json, [&document, &error](std::string_view candidate) {
            MemoryTableDocument parsed;
            std::string candidateError;
            if (!DeserializeMemoryTable(candidate, parsed, &candidateError)) {
                error = std::move(candidateError);
                return false;
            }
            document = std::move(parsed);
            error.clear();
            return true;
        }, kMemoryTableMaxSerializedBytes);
    if (source == atomic_file::ReadSource::None) {
        targetStatus_ = "Table load failed: " +
            (error.empty() ? std::string("no valid primary or backup file") : error);
        return false;
    }
    std::vector<TableRow> replacement;
    replacement.reserve(document.records.size());
    for (MemoryTableRecord& record : document.records) {
        TableRow row;
        row.id = nextTableId_++;
        row.record = std::move(record);
        row.status = "Loaded disabled; review the target and enable explicitly.";
        replacement.push_back(std::move(row));
    }
    table_ = std::move(replacement);
    targetStatus_ = source == atomic_file::ReadSource::Backup
        ? "Recovered the backup table safely; every record is disabled and unfrozen."
        : "Memory table loaded safely: every record is disabled and unfrozen.";
    return true;
}

void MemoryToolsTab::publishFreezePlan(AppContext& ctx,
                                       const TargetToken& target) {
    FreezePlan plan;
    plan.debugger = &ctx.debug;
    plan.passive = &passive_;
    plan.processManager = &processManager_;
    plan.target = target;
    plan.intervalMs = (std::clamp)(freezeIntervalMs_, 25u, 5000u);
    if (target.canWrite) {
        for (const TableRow& row : table_) {
            if (row.record.enabled && row.record.freezeActive &&
                row.record.freezeMode != MemoryFreezeMode::None) {
                plan.rows.push_back({ row.id, row.record, row.absoluteOwner });
            }
        }
    }

    uint64_t fingerprint = 1469598103934665603ull;
    fingerprint = hashBytes(fingerprint, &target.source, sizeof(target.source));
    fingerprint = hashBytes(fingerprint, &target.pid, sizeof(target.pid));
    fingerprint = hashBytes(fingerprint, &target.generation, sizeof(target.generation));
    fingerprint = hashBytes(fingerprint, &target.creationTime, sizeof(target.creationTime));
    fingerprint = hashBytes(fingerprint, &plan.intervalMs, sizeof(plan.intervalMs));
    for (const FreezeRowPlan& row : plan.rows) {
        fingerprint = hashBytes(fingerprint, &row.id, sizeof(row.id));
        fingerprint = hashBytes(fingerprint, &row.record.type, sizeof(row.record.type));
        fingerprint = hashBytes(fingerprint, &row.record.freezeMode,
                                sizeof(row.record.freezeMode));
        fingerprint = hashBytes(fingerprint, &row.record.displayHex,
                                sizeof(row.record.displayHex));
        fingerprint = hashBytes(fingerprint, &row.record.nullTerminateText,
                                sizeof(row.record.nullTerminateText));
        fingerprint = hashBytes(fingerprint, &row.record.allowProtectionChange,
                                sizeof(row.record.allowProtectionChange));
        fingerprint = hashString(fingerprint, row.record.desiredValueText);
        fingerprint = hashBytes(fingerprint, &row.record.address.kind,
                                sizeof(row.record.address.kind));
        fingerprint = hashBytes(fingerprint, &row.record.address.absoluteAddress,
                                sizeof(row.record.address.absoluteAddress));
        fingerprint = hashString(fingerprint, row.record.address.moduleName);
        fingerprint = hashString(fingerprint, row.record.address.modulePath);
        fingerprint = hashBytes(fingerprint, &row.record.address.moduleOffset,
                                sizeof(row.record.address.moduleOffset));
        for (int64_t offset : row.record.address.pointerOffsets)
            fingerprint = hashBytes(fingerprint, &offset, sizeof(offset));
        fingerprint = hashBytes(fingerprint, &row.absoluteOwner.pid,
                                sizeof(row.absoluteOwner.pid));
        fingerprint = hashBytes(fingerprint, &row.absoluteOwner.generation,
                                sizeof(row.absoluteOwner.generation));
    }
    if (fingerprint == freezePlanFingerprint_) return;
    freezePlanFingerprint_ = fingerprint;
    {
        std::lock_guard lock(freezeMutex_);
        plan.revision = ++freezePlanRevision_;
        freezePlan_ = std::move(plan);
    }
    freezeCv_.notify_all();
}

void MemoryToolsTab::freezeWorkerLoop() {
    uint64_t activeRevision = 0;
    for (;;) {
        FreezePlan plan;
        {
            std::unique_lock lock(freezeMutex_);
            freezeCv_.wait(lock, [this, activeRevision] {
                return freezeStop_.load(std::memory_order_acquire) ||
                       freezePlan_.revision != activeRevision;
            });
            if (freezeStop_.load(std::memory_order_acquire)) return;
            plan = freezePlan_;
            activeRevision = plan.revision;
        }

        while (!freezeStop_.load(std::memory_order_acquire)) {
            auto planObsolete = [this, activeRevision] {
                if (freezeStop_.load(std::memory_order_acquire)) return true;
                std::lock_guard lock(freezeMutex_);
                return freezePlan_.revision != activeRevision;
            };
            FreezeCompletion completion;
            completion.revision = plan.revision;
            completion.owner = plan.target;
            completion.rows.reserve(plan.rows.size());
            struct PendingDebuggerWrite {
                size_t resultIndex = 0;
                MemoryWriteSpan span;
            };
            std::vector<PendingDebuggerWrite> pending;

            std::vector<MemoryTableModuleView> liveModules;
            const bool needsModules = std::any_of(plan.rows.begin(), plan.rows.end(),
                [](const FreezeRowPlan& row) {
                    return row.record.address.kind == MemoryTableBaseKind::ModuleRelative;
                });
            if (needsModules && plan.target.source == TargetSource::Debugger &&
                plan.debugger) {
                const auto modules = plan.debugger->modulesForSession(
                    plan.target.pid, plan.target.generation);
                liveModules.reserve(modules.size());
                for (const DbgModule& module : modules)
                    liveModules.push_back({ module.name, module.path,
                                            module.base, module.size });
            } else if (needsModules && plan.target.source == TargetSource::Passive &&
                       plan.passive && plan.processManager) {
                const ProcessMemorySessionSnapshot before = plan.passive->snapshot();
                const ProcessMemoryIdentity expected{
                    plan.target.pid, plan.target.creationTime, plan.target.generation
                };
                if (ProcessMemoryIdentityMatches(before.identity, expected) &&
                    before.open && before.alive) {
                    const auto modules = plan.processManager->modules(plan.target.pid);
                    const ProcessMemorySessionSnapshot after = plan.passive->snapshot();
                    if (ProcessMemoryIdentityMatches(after.identity, expected) &&
                        after.open && after.alive) {
                        liveModules.reserve(modules.size());
                        for (const ModuleInfo& module : modules)
                            liveModules.push_back({ module.name, module.path,
                                                    module.base, module.size });
                    }
                }
            }

            for (const FreezeRowPlan& item : plan.rows) {
                if (planObsolete()) break;
                FreezeRowResult rowResult;
                rowResult.id = item.id;
                if (!plan.target.valid()) {
                    rowResult.status = "target unavailable";
                    completion.rows.push_back(std::move(rowResult));
                    continue;
                }
                if (item.record.address.kind == MemoryTableBaseKind::Absolute &&
                    !item.absoluteOwner.sameSession(plan.target)) {
                    rowResult.status = "absolute address is stale";
                    completion.rows.push_back(std::move(rowResult));
                    continue;
                }
                const auto reader = [&plan](uint64_t at, void* output, size_t size) {
                    return readTarget(plan.debugger, plan.passive, plan.target,
                                      at, output, size);
                };
                const auto resolved = ResolveMemoryTableAddress(
                    item.record, liveModules, reader, plan.target.is32 ? 4 : 8);
                if (!resolved.resolved()) {
                    rowResult.status = "address/pointer resolution failed";
                    completion.rows.push_back(std::move(rowResult));
                    continue;
                }
                rowResult.address = resolved.address;
                rowResult.resolved = true;
                size_t width = MemoryValueTypeFixedSize(item.record.type);
                if (!width) {
                    MemoryScanValue desired;
                    std::string parseError;
                    if (!ParseMemoryScanValue(item.record.type,
                                              item.record.desiredValueText,
                                              { item.record.displayHex,
                                                item.record.nullTerminateText },
                                              desired, &parseError)) {
                        rowResult.status = "invalid desired value: " + parseError;
                        completion.rows.push_back(std::move(rowResult));
                        continue;
                    }
                    width = desired.size();
                }
                std::vector<uint8_t> current(width);
                if (!width || reader(resolved.address, current.data(), width) != width) {
                    rowResult.status = "current value is unreadable";
                    completion.rows.push_back(std::move(rowResult));
                    continue;
                }
                const MemoryFreezeDecision decision = EvaluateMemoryFreeze(
                    item.record, current);
                if (decision.code == MemoryFreezeDecisionCode::AlreadySatisfied) {
                    rowResult.ok = true;
                    rowResult.status = "held";
                    completion.rows.push_back(std::move(rowResult));
                    continue;
                }
                if (!decision.shouldWrite()) {
                    rowResult.status = decision.error.empty()
                        ? "freeze policy rejected the value" : decision.error;
                    completion.rows.push_back(std::move(rowResult));
                    continue;
                }

                if (plan.target.source == TargetSource::Debugger) {
                    const size_t resultIndex = completion.rows.size();
                    rowResult.status = "write queued";
                    completion.rows.push_back(std::move(rowResult));
                    pending.push_back({ resultIndex,
                                        { resolved.address, decision.bytes,
                                          item.record.allowProtectionChange } });
                } else {
                    std::string error;
                    const bool wrote = writeTarget(plan.debugger, plan.passive,
                        plan.target, resolved.address, decision.bytes,
                        item.record.allowProtectionChange, error);
                    rowResult.ok = wrote;
                    rowResult.wrote = wrote;
                    rowResult.status = wrote ? "restored" : error;
                    completion.rows.push_back(std::move(rowResult));
                }
            }

            if (!pending.empty() && plan.debugger && !planObsolete()) {
                // Debugger admission is deliberately bounded to 64 queued
                // transactions. Split a large table into batches so one noisy
                // row set cannot make every freeze silently fail.
                constexpr size_t kFreezeBatchRows = 32;
                for (size_t begin = 0; begin < pending.size(); begin += kFreezeBatchRows) {
                    if (planObsolete()) break;
                    const size_t end = (std::min)(pending.size(), begin + kFreezeBatchRows);
                    std::vector<MemoryWriteSpan> spans;
                    spans.reserve(end - begin);
                    for (size_t i = begin; i < end; ++i) spans.push_back(pending[i].span);
                    const std::vector<size_t> results =
                        plan.debugger->writeMemoryBatchForSession(
                            plan.target.pid, plan.target.generation, spans);
                    for (size_t i = begin; i < end; ++i) {
                        FreezeRowResult& result = completion.rows[pending[i].resultIndex];
                        const size_t local = i - begin;
                        const bool ok = local < results.size() &&
                            results[local] == pending[i].span.bytes.size();
                        result.ok = ok;
                        result.wrote = ok;
                        result.status = ok ? "restored" :
                            "debugger write rejected, timed out, or could not verify";
                    }
                }
            }

            {
                std::lock_guard lock(freezeMutex_);
                if (freezePlan_.revision == plan.revision) {
                    freezeCompletion_ = std::move(completion);
                    freezeCompletionReady_ = true;
                }
            }

            std::unique_lock lock(freezeMutex_);
            const bool replaced = freezeCv_.wait_for(
                lock, std::chrono::milliseconds(plan.intervalMs),
                [this, activeRevision] {
                    return freezeStop_.load(std::memory_order_acquire) ||
                           freezePlan_.revision != activeRevision;
                });
            if (freezeStop_.load(std::memory_order_acquire)) return;
            if (replaced) break;
        }
    }
}

void MemoryToolsTab::pumpFreezeCompletion() {
    FreezeCompletion completion;
    {
        std::lock_guard lock(freezeMutex_);
        if (!freezeCompletionReady_) return;
        completion = std::move(freezeCompletion_);
        freezeCompletionReady_ = false;
    }
    if (completion.revision != freezePlanRevision_ ||
        !completion.owner.sameSession(lastTarget_)) return;
    for (const FreezeRowResult& result : completion.rows) {
        const auto found = std::find_if(table_.begin(), table_.end(),
            [&result](const TableRow& row) { return row.id == result.id; });
        if (found == table_.end()) continue;
        found->resolvedAddress = result.address;
        found->resolved = result.resolved;
        found->writeOk = result.ok;
        found->status = result.status;
    }
}

void MemoryToolsTab::renderAddressTable(AppContext& ctx,
                                        const TargetToken& target) {
    const float scale = theme::UiScale();
    pumpFreezeCompletion();
    ImGui::TextUnformatted("Address table");
    ui::SameLineIfFits(65.0f * scale);
    if (ImGui::SmallButton("Save...")) {
        if (saveTableDialog(target)) ui::Toast(ui::ToastKind::Success, targetStatus_);
        else if (!targetStatus_.empty()) ui::Toast(ui::ToastKind::Error, targetStatus_);
    }
    ui::SameLineIfFits(65.0f * scale);
    if (ImGui::SmallButton("Load...")) {
        if (loadTableDialog()) ui::Toast(ui::ToastKind::Success, targetStatus_);
        else if (!targetStatus_.empty()) ui::Toast(ui::ToastKind::Error, targetStatus_);
    }
    ui::SameLineIfFits(220.0f * scale);
    int interval = static_cast<int>(freezeIntervalMs_);
    ImGui::SetNextItemWidth(120.0f * scale);
    if (ImGui::InputInt("Freeze ms", &interval, 25, 100))
        freezeIntervalMs_ = static_cast<uint32_t>((std::clamp)(interval, 25, 5000));
    ui::SameLineIfFits(245.0f * scale);
    ImGui::SetNextItemWidth(130.0f * theme::UiScale());
    const bool addOnEnter = ImGui::InputTextWithHint("##new_memory_address", "address (hex)", newAddress_, sizeof(newAddress_),
                     ImGuiInputTextFlags_CharsHexadecimal |
                     ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    ImGui::BeginDisabled(!target.valid());
    if ((ImGui::SmallButton("Add address") || addOnEnter) && target.valid()) {
        uint64_t address = 0;
        if (parseHexAddress(newAddress_, address)) {
            addAddressRow(ctx, target, address, MemoryValueType::UInt32,
                          nullptr, "manual address");
            newAddress_[0] = '\0';
        } else {
            ui::Toast(ui::ToastKind::Error, "Address must be hexadecimal.");
        }
    }
    ImGui::EndDisabled();
    ImGui::TextDisabled("%zu records; loaded records never auto-enable", table_.size());
    ImGui::Separator();
    if (table_.empty()) {
        ImGui::TextWrapped("Add an address above, add a scan result or viewer selection, or load a saved memory table.");
        return;
    }

    uint64_t deleteId = 0;
    if (ImGui::BeginTable("##memory_address_table", 11,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable |
            ImGuiTableFlags_Reorderable, ImVec2(0, 0),
            (std::max)(1120.0f * scale, ImGui::GetContentRegionAvail().x))) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, 34.0f * scale);
        ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch, 1.2f);
        ImGui::TableSetupColumn("Group", ImGuiTableColumnFlags_WidthStretch, 0.7f);
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthStretch, 1.1f);
        ImGui::TableSetupColumn("Type", ImGuiTableColumnFlags_WidthFixed, 76.0f * scale);
        ImGui::TableSetupColumn("Current", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Desired", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Mode", ImGuiTableColumnFlags_WidthFixed, 82.0f * scale);
        ImGui::TableSetupColumn("Freeze", ImGuiTableColumnFlags_WidthFixed, 48.0f * scale);
        ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 92.0f * scale);
        ImGui::TableHeadersRow();

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(table_.size()));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                TableRow& row = table_[static_cast<size_t>(i)];
                auto disarmAfterEdit = [&row] {
                    row.writeOk = false;
                    row.lastReadAt = 0.0;
                    if (row.record.freezeActive) {
                        row.record.freezeActive = false;
                        row.status = "freeze disarmed after record edit; review and re-arm";
                    } else {
                        row.status = "edited; value has not been applied";
                    }
                };
                ImGui::PushID(static_cast<int>(row.id));
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                bool enabled = row.record.enabled;
                ImGui::BeginDisabled(!target.valid());
                if (ImGui::Checkbox("##enabled", &enabled)) {
                    row.record.enabled = enabled;
                    if (!enabled) {
                        row.record.freezeActive = false;
                        row.status = "disabled";
                    } else if (row.record.address.kind == MemoryTableBaseKind::Absolute) {
                        row.absoluteOwner = target;
                        row.status = "absolute address bound to this target session";
                    } else {
                        row.status = "enabled; module identity will be resolved live";
                    }
                    row.lastReadAt = 0.0;
                }
                ImGui::EndDisabled();
                ImGui::TableSetColumnIndex(1);
                ImGui::SetNextItemWidth(-1);
                inputTextString("##description", row.record.description);
                ImGui::TableSetColumnIndex(2);
                ImGui::SetNextItemWidth(-1);
                inputTextString("##group", row.record.group);

                std::string expression;
                if (row.record.address.kind == MemoryTableBaseKind::ModuleRelative) {
                    expression = row.record.address.moduleName.empty()
                        ? row.record.address.modulePath : row.record.address.moduleName;
                    expression += "+0x";
                    char offset[32]{};
                    std::snprintf(offset, sizeof(offset), "%llX",
                                  static_cast<unsigned long long>(
                                      row.record.address.moduleOffset));
                    expression += offset;
                } else {
                    expression = hexAddress(row.record.address.absoluteAddress);
                }
                for (int64_t offset : row.record.address.pointerOffsets) {
                    char step[48]{};
                    if (offset >= 0)
                        std::snprintf(step, sizeof(step), " -> +0x%llX",
                                      static_cast<unsigned long long>(offset));
                    else
                        std::snprintf(step, sizeof(step), " -> -0x%llX",
                                      static_cast<unsigned long long>(-(offset + 1)) + 1ull);
                    expression += step;
                }
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(expression.c_str());
                if (ImGui::BeginPopupContextItem("##table_address_menu")) {
                    if (ImGui::MenuItem("Open resolved address in viewer", nullptr,
                                        false, row.resolved)) {
                        navigateViewer(row.resolvedAddress);
                        inspectorSelectRequest_ = 0;
                    }
                    if (row.record.address.kind == MemoryTableBaseKind::Absolute &&
                        ImGui::MenuItem("Rebind absolute address to current target",
                                        nullptr, false, target.valid())) {
                        disarmAfterEdit();
                        row.absoluteOwner = target;
                        row.record.enabled = true;
                        row.status = "rebound to current target session";
                    }
                    if (ImGui::Checkbox("Display/parse numeric value as hex",
                                        &row.record.displayHex))
                        disarmAfterEdit();
                    if ((row.record.type == MemoryValueType::Utf8 ||
                         row.record.type == MemoryValueType::Utf16Le) &&
                        ImGui::Checkbox("Include trailing NUL in text writes",
                                        &row.record.nullTerminateText))
                        disarmAfterEdit();
                    if (ImGui::Checkbox("Allow protected/executable-page write",
                                        &row.record.allowProtectionChange))
                        disarmAfterEdit();
                    ImGui::TextDisabled("Explicit per-record authority; guard/no-access stays denied.");
                    ImGui::EndPopup();
                }

                ImGui::TableSetColumnIndex(4);
                int type = static_cast<int>(row.record.type);
                ImGui::SetNextItemWidth(-1);
                if (ImGui::Combo("##type", &type, kMemoryTypeNames,
                                 static_cast<int>(std::size(kMemoryTypeNames)))) {
                    disarmAfterEdit();
                    row.record.type = static_cast<MemoryValueType>(type);
                    if (row.record.type != MemoryValueType::Utf8 &&
                        row.record.type != MemoryValueType::Utf16Le)
                        row.record.nullTerminateText = false;
                    row.lastReadAt = 0.0;
                }

                uint64_t address = 0;
                std::string resolveError;
                const double now = ImGui::GetTime();
                if (row.record.enabled && target.valid() &&
                    (row.lastReadAt == 0.0 || now - row.lastReadAt >= 0.25)) {
                    row.lastReadAt = now;
                    row.resolved = resolveRow(ctx, target, row, address, resolveError);
                    row.resolvedAddress = row.resolved ? address : 0;
                    if (row.resolved) {
                        size_t width = MemoryValueTypeFixedSize(row.record.type);
                        MemoryScanValue desired;
                        std::string parseError;
                        if (!width && ParseMemoryScanValue(row.record.type,
                                row.record.desiredValueText,
                                { row.record.displayHex,
                                  row.record.nullTerminateText }, desired, &parseError))
                            width = desired.size();
                        std::vector<uint8_t> bytes(width);
                        const size_t got = width ? readTarget(&ctx.debug, &passive_, target,
                            address, bytes.data(), bytes.size()) : 0;
                        bytes.resize(got);
                        row.currentText = got == width && width
                            ? formatMemoryValue(row.record.type, bytes,
                                                row.record.displayHex,
                                                row.record.nullTerminateText)
                            : "unreadable";
                        if (row.status.empty() || row.status == "unreadable" ||
                            row.status.starts_with("resolve:"))
                            row.status = got == width && width ? "ready" : "unreadable";
                    } else {
                        row.currentText = "--";
                        row.status = "resolve: " + resolveError;
                    }
                }

                ImGui::TableSetColumnIndex(5);
                ImGui::TextUnformatted(row.record.enabled ? row.currentText.c_str() : "--");
                ImGui::TableSetColumnIndex(6);
                ImGui::SetNextItemWidth(-1);
                if (inputTextString("##desired", row.record.desiredValueText))
                    disarmAfterEdit();
                ImGui::TableSetColumnIndex(7);
                int freezeMode = static_cast<int>(row.record.freezeMode);
                ImGui::SetNextItemWidth(-1);
                if (ImGui::Combo("##freeze_mode", &freezeMode, kFreezeModes,
                                 static_cast<int>(std::size(kFreezeModes)))) {
                    disarmAfterEdit();
                    row.record.freezeMode = static_cast<MemoryFreezeMode>(freezeMode);
                    if (row.record.freezeMode == MemoryFreezeMode::None)
                        row.record.freezeActive = false;
                }
                ImGui::TableSetColumnIndex(8);
                ImGui::BeginDisabled(!row.record.enabled ||
                                     row.record.freezeMode == MemoryFreezeMode::None ||
                                     !target.valid() || !target.canWrite);
                bool freezeActive = row.record.freezeActive;
                if (ImGui::Checkbox("##freeze", &freezeActive)) {
                    row.record.freezeActive = freezeActive;
                    row.writeOk = false;
                    row.status = freezeActive ? "freeze armed; pending first evaluation"
                                              : "freeze off";
                }
                ImGui::EndDisabled();
                ImGui::TableSetColumnIndex(9);
                ImGui::TextColored(row.writeOk ? theme::col::good() :
                    (row.status.starts_with("resolve:") ? theme::col::bad() :
                                                         ImGui::GetStyleColorVec4(ImGuiCol_TextDisabled)),
                    "%s", row.status.c_str());
                ImGui::TableSetColumnIndex(10);
                ImGui::BeginDisabled(!row.record.enabled ||
                                     !target.valid() || !target.canWrite);
                if (ImGui::SmallButton("Apply")) {
                    MemoryScanValue desired;
                    std::string error;
                    if (!ParseMemoryScanValue(row.record.type,
                            row.record.desiredValueText,
                            { row.record.displayHex,
                              row.record.nullTerminateText }, desired, &error) ||
                        (!desired.mask.empty() &&
                         std::find(desired.mask.begin(), desired.mask.end(), 0u) !=
                             desired.mask.end())) {
                        if (error.empty()) error = "writes cannot contain ?? wildcards";
                        row.status = error;
                        row.writeOk = false;
                    } else {
                        if (target.source == TargetSource::Passive)
                            refreshPassiveModules(target, ImGui::GetTime());
                        uint64_t freshAddress = 0;
                        std::string resolveError;
                        if (!resolveRow(ctx, target, row, freshAddress,
                                        resolveError)) {
                            row.resolved = false;
                            row.resolvedAddress = 0;
                            row.writeOk = false;
                            row.status = "resolve before write: " + resolveError;
                        } else {
                            row.resolved = true;
                            row.resolvedAddress = freshAddress;
                            row.writeOk = writeTarget(&ctx.debug, &passive_, target,
                                freshAddress, desired.bytes,
                                row.record.allowProtectionChange, error);
                            row.status = row.writeOk ? "verified write applied" : error;
                        }
                        row.lastReadAt = 0.0;
                    }
                }
                ImGui::EndDisabled();
                ImGui::SameLine();
                if (ImGui::SmallButton("..."))
                    ImGui::OpenPopup("##table_row_menu");
                if (ImGui::BeginPopup("##table_row_menu")) {
                    if (ImGui::MenuItem("Delete record")) deleteId = row.id;
                    if (ImGui::MenuItem("Copy address expression"))
                        ImGui::SetClipboardText(expression.c_str());
                    const bool debuggerOwned = row.resolved &&
                        target.source == TargetSource::Debugger && target.valid() &&
                        ctx.frameDebugSnapshot && ctx.frameDebugSnapshot->attached() &&
                        DebugTargetIdentityMatches(
                            { ctx.frameDebugSnapshot->pid,
                              ctx.frameDebugSnapshot->sessionGeneration },
                            { target.pid, target.generation });
                    if (ImGui::MenuItem("Open in Live Assembly", nullptr,
                                        false, debuggerOwned))
                        ctx.gotoAddressLive(
                            row.resolvedAddress, { target.pid, target.generation });
                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
                        ImGui::SetTooltip("Decodes the bytes stored at this address. To inspect code that accesses the value, navigate to the accessing instruction's address.");
                    ImGui::EndPopup();
                }
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
    if (deleteId) {
        table_.erase(std::remove_if(table_.begin(), table_.end(),
            [deleteId](const TableRow& row) { return row.id == deleteId; }), table_.end());
    }
}

void MemoryToolsTab::consumeMemoryRequest(AppContext& ctx,
                                          const TargetToken& target) {
    if (!ctx.requestedMemory.pending) return;
    MemoryToolsRequest request = std::move(ctx.requestedMemory);
    ctx.requestedMemory = {};

    const bool ownerRequested = request.target.pid != 0 ||
                                request.target.sessionGeneration != 0;
    const bool identityMatches = target.valid() &&
        (!ownerRequested ||
         (request.target.valid() && target.source == TargetSource::Debugger &&
          DebugTargetIdentityMatches(
              { target.pid, target.generation }, request.target)));
    // A scan preset is never accepted without an exact debugger owner, even if
    // a malformed caller constructs the request fields directly.
    const bool scanOwnerMatches = !request.prepareScan ||
        (request.target.valid() && target.source == TargetSource::Debugger &&
         DebugTargetIdentityMatches(
             { target.pid, target.generation }, request.target));
    if (identityMatches && scanOwnerMatches) {
        navigateViewer(request.address, true, request.selectionBytes);
        inspectorSelectRequest_ = 0;
        if (request.prepareScan) applyScanPreset(request.scanValue);
    } else {
        targetStatus_ = "Memory navigation request expired because the debugger target changed.";
    }
}

void MemoryToolsTab::render(AppContext& ctx) {
    pumpScanCompletion();
    pumpPointerCompletion();
    pumpFreezeCompletion();

    if (ctx.requestedMemory.pending && ctx.requestedMemory.target.pid) {
        DbgSnapshot fallback;
        const DbgSnapshot* debug = ctx.frameDebugSnapshot;
        if (!debug) { fallback = ctx.debug.snapshot(); debug = &fallback; }
        if ((debug->state == DbgState::Running || debug->state == DbgState::Paused) &&
            debug->pid == ctx.requestedMemory.target.pid &&
            debug->sessionGeneration == ctx.requestedMemory.target.sessionGeneration)
            targetSource_ = TargetSource::Debugger;
    }
    TargetToken target = currentTarget(ctx);
    handleTargetTransition(target);
    consumeMemoryRequest(ctx, target);
    renderTargetBar(ctx, target);
    renderProcessPicker(ctx);
    // Target controls can close or replace a session in this frame. Retire its
    // visible results and freeze authority before rendering further actions.
    target = currentTarget(ctx);
    handleTargetTransition(target);

    if (!target.valid()) {
        publishFreezePlan(ctx, target);
        if (ui::EmptyState(DS_ICON_MEMORY, "Open a process to inspect live memory",
            "Scan and edit without debugger attachment, or reuse an existing debugger session.",
            "Open Process..."))
            processPickerOpen_ = true;
        ImGui::SeparatorText("Offline address table");
        ImGui::PushTextWrapPos();
        ImGui::TextDisabled("Load, inspect, and edit records now. Enabling, resolving, applying, and freezing require a live target.");
        ImGui::PopTextWrapPos();
        ImGui::BeginChild("##memory_table_no_target", ImVec2(0, 0),
                          ImGuiChildFlags_Borders);
        renderAddressTable(ctx, target);
        ImGui::EndChild();
        return;
    }

    if (!regionOwner_.sameSession(target)) refreshRegionCache(ctx, target);
    if (target.source == TargetSource::Passive) {
        const double now = ImGui::GetTime();
        if (passiveModulesLastRefresh_ == 0.0 ||
            now - passiveModulesLastRefresh_ >= 1.0)
            refreshPassiveModules(target, now);
    }
    if (!viewBaseValid_ && !regionCache_.empty()) navigateViewer(regionCache_.front().base);
    if (!pointerTarget_[0] && viewBaseValid_)
        std::snprintf(pointerTarget_, sizeof(pointerTarget_), "%llX",
                      static_cast<unsigned long long>(viewBase_));

    const float scale = theme::UiScale();
    const ImVec2 available = ImGui::GetContentRegionAvail();
    const float contentHeight = (std::max)(1.0f, available.y - 6.0f * scale -
                                          ImGui::GetStyle().ItemSpacing.y * 2.0f);
    const float minUpper = (std::min)(220.0f * scale, contentHeight * 0.55f);
    const float maxUpper = (std::max)(minUpper, contentHeight -
        (std::min)(150.0f * scale, contentHeight * 0.4f));
    if (upperHeight_ <= 0.0f) upperHeight_ = available.y * 0.62f;
    upperHeight_ = (std::clamp)(upperHeight_, minUpper, maxUpper);
    if (ImGui::BeginChild("##memory_upper", ImVec2(0, upperHeight_), false)) {
        const float upperWidth = ImGui::GetContentRegionAvail().x;
        const bool compact = upperWidth < 720.0f * scale;
        if (compact != compactUpperLayout_ && inspectorSelectRequest_ < 0)
            inspectorSelectRequest_ = inspectorTab_;
        compactUpperLayout_ = compact;
        if (compact) {
            // Give each tool readable columns at narrow widths; the address
            // table and its live controls retain their own pane below.
            if (inspectorSelectRequest_ >= 0) compactUpperView_ = 1;
            static const char* upperViews[] = { "Value scanner", "Memory inspector" };
            compactUpperView_ = ui::TabStrip("##memory_compact_views", upperViews, 2,
                                             compactUpperView_);
            if (compactUpperView_ != 0 && scanRunning_.load(std::memory_order_acquire)) {
                if (ImGui::SmallButton("Cancel value scan##compact")) cancelScan();
            }
            if (compactUpperView_ == 0 && pointerRunning_.load(std::memory_order_acquire)) {
                if (ImGui::SmallButton("Cancel pointer scan##compact"))
                    cancelPointerScan();
            }
            ImGui::BeginChild("##memory_compact_tool", ImVec2(0, 0), ImGuiChildFlags_Borders);
            if (compactUpperView_ == 0) renderScanner(ctx, target);
            else renderInspector(ctx, target);
            ImGui::EndChild();
        } else {
            if (scannerWidth_ <= 0.0f) scannerWidth_ = upperWidth * 0.37f;
            scannerWidth_ = (std::clamp)(scannerWidth_, 300.0f * scale,
                                         upperWidth - 360.0f * scale - 6.0f * scale);
            ImGui::BeginChild("##memory_scanner", ImVec2(scannerWidth_, 0),
                              ImGuiChildFlags_Borders);
            renderScanner(ctx, target);
            ImGui::EndChild();
            ui::VSplitter("##memory_split", &scannerWidth_, 300.0f * scale,
                          360.0f * scale, 6.0f * scale);
            ImGui::BeginChild("##memory_inspector", ImVec2(0, 0),
                              ImGuiChildFlags_Borders);
            renderInspector(ctx, target);
            ImGui::EndChild();
        }
    }
    ImGui::EndChild();

    ImGui::InvisibleButton("##memory_horizontal_split", ImVec2(-1, 6.0f * scale));
    if (ImGui::IsItemHovered() || ImGui::IsItemActive())
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
    if (ImGui::IsItemActive()) {
        upperHeight_ += ImGui::GetIO().MouseDelta.y;
        upperHeight_ = (std::clamp)(upperHeight_, minUpper, maxUpper);
    }
    ImGui::BeginChild("##memory_table", ImVec2(0, 0), ImGuiChildFlags_Borders);
    renderAddressTable(ctx, target);
    ImGui::EndChild();

    publishFreezePlan(ctx, target);
    const bool freezing = std::any_of(table_.begin(), table_.end(),
        [](const TableRow& row) {
            return row.record.enabled && row.record.freezeActive &&
                   row.record.freezeMode != MemoryFreezeMode::None;
        });
    const bool tableWatching = std::any_of(table_.begin(), table_.end(),
        [](const TableRow& row) { return row.record.enabled; });
    ctx.wantContinuousRedraw = scanRunning_.load(std::memory_order_acquire) ||
        pointerRunning_.load(std::memory_order_acquire) ||
        (viewAutoRefresh_ && inspectorTab_ == 0) || tableWatching || freezing;
}

} // namespace ds
