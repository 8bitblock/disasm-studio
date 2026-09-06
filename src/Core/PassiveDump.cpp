#include "PassiveDump.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <cstring>
#include <cwctype>
#include <iomanip>
#include <map>
#include <sstream>
#include <type_traits>
#include <unordered_map>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#  include <TlHelp32.h>
#endif

namespace ds {
namespace {

constexpr uint64_t kFnvOffset = 1469598103934665603ull;
constexpr uint64_t kFnvPrime = 1099511628211ull;
constexpr size_t kMaxRemoteExportTargets = 262144;
constexpr size_t kMaxRemoteExportName = 256;

double clampRatio(double v, double fallback) {
    if (!std::isfinite(v)) return fallback;
    return std::clamp(v, 0.0, 1.0);
}

uint64_t nowMs() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

const char* decisionName(PassiveSettleDecision d) {
    switch (d) {
        case PassiveSettleDecision::Continue: return "continue";
        case PassiveSettleDecision::Immediate: return "immediate capture";
        case PassiveSettleDecision::Settled: return "entropy/change settled";
        case PassiveSettleDecision::TimedOut: return "watch timeout";
        case PassiveSettleDecision::Manual: return "manual capture";
    }
    return "unknown";
}

const char* oepTrustName(PassiveOepTrust trust) {
    switch (trust) {
        case PassiveOepTrust::NotAssessed: return "not assessed";
        case PassiveOepTrust::HeaderEntryUnverified: return "header entry unverified";
        case PassiveOepTrust::ManualOepRejected: return "manual OEP rejected";
        case PassiveOepTrust::ManualOepValidated: return "manual OEP validated";
    }
    return "unknown";
}

const char* artifactName(PassiveArtifactAssessment assessment) {
    switch (assessment) {
        case PassiveArtifactAssessment::RawCaptureOnly: return "raw capture only";
        case PassiveArtifactAssessment::RebuiltAnalysisOnly: return "rebuilt PE (analysis-only)";
        case PassiveArtifactAssessment::RebuiltRunnable: return "rebuilt PE (runnable OEP trusted)";
    }
    return "unknown";
}

#ifdef _WIN32

template <typename T>
class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(T h) : h_(h) {}
    ~UniqueHandle() { reset(); }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    UniqueHandle(UniqueHandle&& o) noexcept : h_(o.release()) {}
    UniqueHandle& operator=(UniqueHandle&& o) noexcept {
        if (this != &o) reset(o.release());
        return *this;
    }
    void reset(T h = nullptr) {
        if (h_ && h_ != INVALID_HANDLE_VALUE) CloseHandle(h_);
        h_ = h;
    }
    T get() const { return h_; }
    T release() { T h = h_; h_ = nullptr; return h; }
    explicit operator bool() const { return h_ && h_ != INVALID_HANDLE_VALUE; }
private:
    T h_ = nullptr;
};

using Handle = UniqueHandle<HANDLE>;

std::string winError(const char* action, DWORD code = GetLastError()) {
    std::ostringstream os;
    os << action << " failed (Win32 " << code << ").";
    return os.str();
}

std::wstring normalizePath(std::wstring s) {
    if (s.rfind(L"\\\\?\\", 0) == 0) s.erase(0, 4);
    std::replace(s.begin(), s.end(), L'/', L'\\');
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(towlower(c));
    });
    while (s.size() > 3 && s.back() == L'\\') s.pop_back();
    return s;
}

std::wstring fullPath(const std::wstring& p) {
    if (p.empty()) return {};
    DWORD n = GetFullPathNameW(p.c_str(), 0, nullptr, nullptr);
    if (!n || n > 32768) return p;
    std::wstring out(n, L'\0');
    DWORD got = GetFullPathNameW(p.c_str(), n, out.data(), nullptr);
    if (!got || got >= n) return p;
    out.resize(got);
    return out;
}

std::string utf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(),
                                static_cast<int>(s.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, s.data(),
                        static_cast<int>(s.size()), out.data(), n, nullptr, nullptr);
    return out;
}

std::string narrowBaseName(const std::wstring& p) {
    size_t at = p.find_last_of(L"\\/");
    std::wstring w = at == std::wstring::npos ? p : p.substr(at + 1);
    return utf8(w);
}

std::wstring quoteWindowsArg(const std::wstring& arg) {
    if (arg.empty()) return L"\"\"";
    if (arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) return arg;
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') { ++slashes; continue; }
        if (c == L'\"') {
            out.append(slashes * 2 + 1, L'\\');
            out.push_back(L'\"');
        } else {
            out.append(slashes, L'\\');
            out.push_back(c);
        }
        slashes = 0;
    }
    out.append(slashes * 2, L'\\');
    out.push_back(L'\"');
    return out;
}

std::wstring commandLine(const PassiveDumpRequest& r) {
    std::wstring out = quoteWindowsArg(fullPath(r.executable));
    for (const auto& a : r.arguments) {
        out.push_back(L' ');
        out += quoteWindowsArg(a);
    }
    return out;
}

bool queryProcessPath(HANDLE process, std::wstring& out) {
    std::wstring buf(32768, L'\0');
    DWORD n = static_cast<DWORD>(buf.size());
    if (!QueryFullProcessImageNameW(process, 0, buf.data(), &n) || !n) return false;
    buf.resize(n);
    out = std::move(buf);
    return true;
}

std::vector<PassiveModuleInfo> enumerateModules(uint32_t pid, size_t cap,
                                                std::vector<std::string>* warnings = nullptr) {
    std::vector<PassiveModuleInfo> out;
    Handle snap;
    for (unsigned retry = 0; retry < 5; ++retry) {
        snap.reset(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
        if (snap || GetLastError() != ERROR_BAD_LENGTH) break;
    }
    if (!snap) {
        if (warnings) warnings->push_back(winError("Module enumeration"));
        return out;
    }
    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (!Module32FirstW(snap.get(), &me)) {
        if (warnings) warnings->push_back(winError("Module32First"));
        return out;
    }
    do {
        PassiveModuleInfo m;
        m.base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
        m.size = me.modBaseSize;
        m.name = me.szModule;
        m.path = me.szExePath;
        if (m.base && m.size) out.push_back(std::move(m));
    } while (out.size() < cap && Module32NextW(snap.get(), &me));
    if (out.size() == cap && warnings)
        warnings->push_back("Module enumeration reached its safety cap.");
    return out;
}

bool chooseMainModule(const std::vector<PassiveModuleInfo>& modules,
                      const std::wstring& processPath, PassiveModuleInfo& out) {
    if (processPath.empty()) return false;
    const std::wstring wanted = normalizePath(processPath);
    const PassiveModuleInfo* match = nullptr;
    for (const auto& m : modules) {
        if (!m.path.empty() && normalizePath(m.path) == wanted) {
            if (match && match->base != m.base) return false; // ambiguous: refuse
            match = &m;
        }
    }
    if (!match) return false;
    out = *match;
    out.mainModule = true;
    return true;
}

template <typename T>
bool readAt(const std::vector<uint8_t>& b, uint64_t off, T& v) {
    if (off > b.size() || sizeof(T) > b.size() - static_cast<size_t>(off)) return false;
    std::memcpy(&v, b.data() + static_cast<size_t>(off), sizeof(T));
    return true;
}

struct PeView {
    bool is64 = false;
    uint32_t pe = 0;
    uint32_t timestamp = 0;
    uint32_t opt = 0;
    uint32_t sectionTable = 0;
    uint16_t sectionCount = 0;
    uint32_t sizeImage = 0;
    uint32_t sizeHeaders = 0;
    uint32_t entryRva = 0;
    uint32_t numberDirs = 0;
    uint32_t dirOff = 0;
    struct Sec {
        std::string name;
        uint32_t va = 0;
        uint32_t virtualSize = 0;
        uint32_t rawSize = 0;
        uint32_t rawPointer = 0;
        uint32_t characteristics = 0;
    };
    std::vector<Sec> sections;
};

bool parsePeView(const std::vector<uint8_t>& b, PeView& p, bool diskLayout,
                 std::string* error = nullptr) {
    uint16_t mz = 0, magic = 0, optSize = 0;
    uint32_t sig = 0;
    if (!readAt(b, 0, mz) || mz != 0x5a4d || !readAt(b, 0x3c, p.pe) ||
        p.pe > b.size() || 24 > b.size() - p.pe ||
        !readAt(b, p.pe, sig) || sig != 0x4550 ||
        !readAt(b, p.pe + 8, p.timestamp) ||
        !readAt(b, p.pe + 6, p.sectionCount) ||
        !readAt(b, p.pe + 20, optSize)) {
        if (error) *error = "Malformed or truncated PE headers.";
        return false;
    }
    if (!p.sectionCount || p.sectionCount > 96) {
        if (error) *error = "PE section count is outside the safety limit.";
        return false;
    }
    p.opt = p.pe + 24;
    if (p.opt > b.size() || optSize > b.size() - p.opt || !readAt(b, p.opt, magic) ||
        (magic != 0x10b && magic != 0x20b)) {
        if (error) *error = "Unsupported or truncated PE optional header.";
        return false;
    }
    p.is64 = magic == 0x20b;
    const uint32_t minOpt = p.is64 ? 112u : 96u;
    if (optSize < minOpt || !readAt(b, p.opt + 16, p.entryRva) ||
        !readAt(b, p.opt + 56, p.sizeImage) || !readAt(b, p.opt + 60, p.sizeHeaders) ||
        !readAt(b, p.opt + (p.is64 ? 108 : 92), p.numberDirs)) {
        if (error) *error = "PE optional header lacks required fields.";
        return false;
    }
    p.dirOff = p.opt + (p.is64 ? 112 : 96);
    const uint32_t physicalDirs = optSize > p.dirOff - p.opt
        ? (optSize - (p.dirOff - p.opt)) / 8u : 0u;
    p.numberDirs = std::min<uint32_t>({ p.numberDirs, physicalDirs, 16u });
    const uint64_t st = static_cast<uint64_t>(p.opt) + optSize;
    const uint64_t se = st + static_cast<uint64_t>(p.sectionCount) * 40;
    if (!p.sizeImage || p.sizeImage > kPassiveDumpMaxImage || !p.sizeHeaders ||
        p.sizeHeaders > p.sizeImage || st > UINT32_MAX || se > b.size() ||
        se > p.sizeHeaders) {
        if (error) *error = "PE image/header sizes are invalid or exceed the capture cap.";
        return false;
    }
    p.sectionTable = static_cast<uint32_t>(st);
    p.sections.clear();
    p.sections.reserve(p.sectionCount);
    for (uint16_t i = 0; i < p.sectionCount; ++i) {
        const uint32_t at = p.sectionTable + i * 40;
        PeView::Sec s;
        char name[9]{};
        std::memcpy(name, b.data() + at, 8);
        s.name = name;
        if (!readAt(b, at + 8, s.virtualSize) || !readAt(b, at + 12, s.va) ||
            !readAt(b, at + 16, s.rawSize) || !readAt(b, at + 20, s.rawPointer) ||
            !readAt(b, at + 36, s.characteristics)) return false;
        const uint64_t span = std::max<uint32_t>(s.virtualSize, s.rawSize);
        if (s.va > p.sizeImage || span > p.sizeImage - s.va) {
            if (error) *error = "A PE section virtual range is outside SizeOfImage.";
            return false;
        }
        if (diskLayout && s.rawSize &&
            (s.rawPointer > b.size() || s.rawSize > b.size() - s.rawPointer)) {
            if (error) *error = "A PE section raw range is outside the module file.";
            return false;
        }
        p.sections.push_back(std::move(s));
    }
    return true;
}

bool dataDirectory(const std::vector<uint8_t>& b, const PeView& p, uint32_t index,
                   uint32_t& rva, uint32_t& size) {
    rva = size = 0;
    if (index >= p.numberDirs) return false;
    return readAt(b, p.dirOff + index * 8ull, rva) &&
           readAt(b, p.dirOff + index * 8ull + 4, size);
}

bool remoteImageSize(HANDLE process, uint64_t base, uint32_t& size, std::string& error) {
    std::array<uint8_t, 0x1000> first{};
    SIZE_T got = 0;
    if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(base)),
                           first.data(), first.size(), &got) || got < 0x100) {
        error = "The selected main module header is not readable.";
        return false;
    }
    std::vector<uint8_t> hdr(first.begin(), first.begin() + got);
    PeView p;
    if (!parsePeView(hdr, p, false, &error)) {
        // The section table can legitimately extend past the first page. Read a
        // bounded 64 KiB header window and retry.
        hdr.assign(0x10000, 0);
        got = 0;
        if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(base)),
                               hdr.data(), hdr.size(), &got) || got < 0x100) return false;
        hdr.resize(got);
        if (!parsePeView(hdr, p, false, &error)) return false;
    }
    size = p.sizeImage;
    return true;
}

bool readableProtection(DWORD protect) {
    if (!protect || (protect & (PAGE_GUARD | PAGE_NOACCESS))) return false;
    const DWORD basic = protect & 0xffu;
    return basic == PAGE_READONLY || basic == PAGE_READWRITE ||
           basic == PAGE_WRITECOPY || basic == PAGE_EXECUTE_READ ||
           basic == PAGE_EXECUTE_READWRITE || basic == PAGE_EXECUTE_WRITECOPY;
}

PassiveCapture captureImage(HANDLE process, uint64_t base, size_t size,
                            const std::atomic<bool>& cancel) {
    PassiveCapture c;
    c.base = base;
    if (!size || size > kPassiveDumpMaxImage || base > UINT64_MAX - size) return c;
    c.bytes.assign(size, 0);
    const size_t pages = (size + kPassiveDumpPageSize - 1) / kPassiveDumpPageSize;
    c.pageValid.assign(pages, 0);
    c.pageBackfilled.assign(pages, 0);
    c.pageProtection.assign(pages, 0);

    uint64_t cursor = base;
    const uint64_t end = base + size;
    while (cursor < end && !cancel.load(std::memory_order_acquire)) {
        MEMORY_BASIC_INFORMATION mbi{};
        const SIZE_T q = VirtualQueryEx(process,
            reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(cursor)), &mbi, sizeof(mbi));
        if (!q || !mbi.RegionSize) {
            cursor = std::min<uint64_t>(end, (cursor | (kPassiveDumpPageSize - 1)) + 1);
            continue;
        }
        const uint64_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const uint64_t rawEnd = regionBase > UINT64_MAX - mbi.RegionSize
            ? UINT64_MAX : regionBase + mbi.RegionSize;
        const uint64_t regionEnd = std::min<uint64_t>(end, rawEnd);
        const uint64_t from = std::max(cursor, base);
        const bool readable = mbi.State == MEM_COMMIT && readableProtection(mbi.Protect);
        size_t firstPage = static_cast<size_t>((from - base) / kPassiveDumpPageSize);
        size_t lastPage = static_cast<size_t>((regionEnd - base + kPassiveDumpPageSize - 1) /
                                              kPassiveDumpPageSize);
        lastPage = std::min(lastPage, pages);
        for (size_t pg = firstPage; pg < lastPage; ++pg)
            c.pageProtection[pg] = mbi.Protect;
        if (readable) {
            constexpr size_t kBulkPages = (1u << 20) / kPassiveDumpPageSize;
            for (size_t pg = firstPage; pg < lastPage &&
                 !cancel.load(std::memory_order_acquire);) {
                const size_t groupPages = std::min(kBulkPages, lastPage - pg);
                const size_t off = pg * kPassiveDumpPageSize;
                const size_t want = std::min(groupPages * kPassiveDumpPageSize, size - off);
                SIZE_T got = 0;
                const BOOL bulkOk = ReadProcessMemory(process,
                    reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(base + off)),
                    c.bytes.data() + off, want, &got);
                if (bulkOk && got == want) {
                    for (size_t i = 0; i < groupPages; ++i) {
                        if (!c.pageValid[pg + i]) {
                            c.pageValid[pg + i] = 1;
                            ++c.readablePages;
                        }
                    }
                } else {
                    // A guard/race inside a bulk span must not leave partially
                    // copied bytes looking authoritative. Zero it, then recover
                    // every independently readable page with exact-size reads.
                    std::fill_n(c.bytes.data() + off, want, uint8_t{0});
                    for (size_t i = 0; i < groupPages; ++i) {
                        const size_t page = pg + i;
                        const size_t pageOff = page * kPassiveDumpPageSize;
                        const size_t pageWant = std::min(kPassiveDumpPageSize, size - pageOff);
                        SIZE_T pageGot = 0;
                        if (ReadProcessMemory(process,
                                reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(base + pageOff)),
                                c.bytes.data() + pageOff, pageWant, &pageGot) &&
                            pageGot == pageWant) {
                            if (!c.pageValid[page]) {
                                c.pageValid[page] = 1;
                                ++c.readablePages;
                            }
                        } else {
                            std::fill_n(c.bytes.data() + pageOff, pageWant, uint8_t{0});
                        }
                    }
                }
                pg += groupPages;
            }
        }
        if (regionEnd <= cursor) break;
        cursor = regionEnd;
    }
    c.unreadablePages = static_cast<uint32_t>(pages - c.readablePages);
    return c;
}

bool pageSpanRemoteValid(const PassiveCapture& c, uint64_t begin, uint64_t size) {
    if (!size) return true;
    if (begin > c.bytes.size() || size > c.bytes.size() - static_cast<size_t>(begin)) return false;
    const size_t first = static_cast<size_t>(begin / kPassiveDumpPageSize);
    const size_t last = static_cast<size_t>((begin + size - 1) / kPassiveDumpPageSize);
    if (last >= c.pageValid.size()) return false;
    // Import observations must come from exact remote bytes. Disk-backfilled
    // discardable pages are valid only as reconstruction input and must never
    // lend provenance to a zero/stale slot in PassiveCapture::bytes.
    for (size_t p = first; p <= last; ++p) if (!c.pageValid[p]) return false;
    return true;
}

void validateCoverage(PassiveCapture& c) {
    c.completeForDiskRebuild = false;
    c.missingRequiredPageRvas.clear();
    if (c.bytes.empty() || c.pageValid.empty() || !c.pageValid[0]) return;
    PeView p;
    if (!parsePeView(c.bytes, p, false)) return;
    std::vector<uint8_t> required(c.pageValid.size(), 0);
    auto mark = [&](uint64_t rva, uint64_t n) {
        if (!n || rva >= c.bytes.size()) return;
        n = std::min<uint64_t>(n, c.bytes.size() - static_cast<size_t>(rva));
        const size_t first = static_cast<size_t>(rva / kPassiveDumpPageSize);
        const size_t last = static_cast<size_t>((rva + n - 1) / kPassiveDumpPageSize);
        for (size_t pg = first; pg <= last && pg < required.size(); ++pg) required[pg] = 1;
    };
    mark(0, p.sizeHeaders);
    for (const auto& s : p.sections) {
        // PeUnpack materializes max(VirtualSize,SizeOfRawData). Any code or
        // initialized-data tail may contain the unpacked payload even when the
        // original file had no bytes there, so it must come from a valid remote
        // page. Only a pure IMAGE_SCN_CNT_UNINITIALIZED_DATA section is allowed
        // to retain an unreadable zero-fill tail.
        constexpr uint32_t kCode = 0x00000020u;
        constexpr uint32_t kInitialized = 0x00000040u;
        constexpr uint32_t kUninitialized = 0x00000080u;
        const bool pureBss = (s.characteristics & kUninitialized) != 0 &&
                             (s.characteristics & (kCode | kInitialized)) == 0;
        mark(s.va, pureBss ? s.rawSize : std::max(s.virtualSize, s.rawSize));
    }
    for (size_t pg = 0; pg < required.size(); ++pg) {
        const bool available = c.pageValid[pg] ||
            (pg < c.pageBackfilled.size() && c.pageBackfilled[pg]);
        if (required[pg] && !available) {
            if (c.missingRequiredPageRvas.size() < 256)
                c.missingRequiredPageRvas.push_back(static_cast<uint32_t>(pg * kPassiveDumpPageSize));
        }
    }
    c.completeForDiskRebuild = c.missingRequiredPageRvas.empty();
}

bool readFileAt(HANDLE file, uint64_t offset, void* out, size_t size) {
    if (!file || !out || !size || offset > INT64_MAX) return false;
    LARGE_INTEGER where{};
    where.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file, where, nullptr, FILE_BEGIN)) return false;
    size_t done = 0;
    while (done < size) {
        const DWORD want = static_cast<DWORD>(std::min<size_t>(size - done, 8u << 20));
        DWORD got = 0;
        if (!ReadFile(file, static_cast<uint8_t*>(out) + done, want, &got, nullptr) || got != want)
            return false;
        done += got;
    }
    return true;
}

void backfillDiscardablePages(PassiveCapture& capture, const std::wstring& modulePath,
                              std::vector<uint8_t>& reconstruction,
                              std::vector<std::string>& warnings) {
    capture.pageBackfilled.assign(capture.pageValid.size(), 0);
    std::vector<uint8_t>().swap(reconstruction);
    if (capture.bytes.empty() || modulePath.empty()) return;
    PeView live;
    if (!parsePeView(capture.bytes, live, false)) return;

    // 0 = no required bytes, 1 = discardable-only required bytes, 2 = any
    // non-discardable/header byte. A page is backfilled only in state 1.
    std::vector<uint8_t> kind(capture.pageValid.size(), 0);
    auto mark = [&](uint64_t rva, uint64_t n, uint8_t value) {
        if (!n || rva >= capture.bytes.size()) return;
        n = std::min<uint64_t>(n, capture.bytes.size() - static_cast<size_t>(rva));
        const size_t first = static_cast<size_t>(rva / kPassiveDumpPageSize);
        const size_t last = static_cast<size_t>((rva + n - 1) / kPassiveDumpPageSize);
        for (size_t pg = first; pg <= last && pg < kind.size(); ++pg)
            kind[pg] = std::max(kind[pg], value);
    };
    mark(0, live.sizeHeaders, 2);
    constexpr uint32_t kDiscardable = 0x02000000u;
    for (const auto& s : live.sections)
        mark(s.va, s.rawSize, (s.characteristics & kDiscardable) ? 1 : 2);

    bool needed = false;
    for (size_t pg = 0; pg < kind.size(); ++pg)
        if (!capture.pageValid[pg] && kind[pg] == 1) { needed = true; break; }
    if (!needed) return; // the common path retains exactly one mapped image

    Handle file(CreateFileW(modulePath.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    LARGE_INTEGER fileSize{};
    if (!file || !GetFileSizeEx(file.get(), &fileSize) || fileSize.QuadPart <= 0) return;
    const uint64_t diskSize = static_cast<uint64_t>(fileSize.QuadPart);
    const size_t headerSize = static_cast<size_t>(std::min<uint64_t>(diskSize, 1u << 20));
    std::vector<uint8_t> diskHeader(headerSize);
    if (!readFileAt(file.get(), 0, diskHeader.data(), diskHeader.size())) return;
    PeView disk;
    if (!parsePeView(diskHeader, disk, false) || live.is64 != disk.is64 ||
        live.timestamp != disk.timestamp || live.sizeImage != disk.sizeImage ||
        live.sections.size() != disk.sections.size()) {
        warnings.push_back("Unreadable discardable pages were not backfilled because the live and on-disk PE identities differ.");
        return;
    }
    for (size_t i = 0; i < live.sections.size(); ++i) {
        const auto& a = live.sections[i];
        const auto& b = disk.sections[i];
        if (a.name != b.name || a.va != b.va || a.virtualSize != b.virtualSize ||
            a.rawSize != b.rawSize || a.rawPointer != b.rawPointer ||
            a.characteristics != b.characteristics || b.rawPointer > diskSize ||
            b.rawSize > diskSize - b.rawPointer) {
            warnings.push_back("Unreadable discardable pages were not backfilled because section layouts differ from disk.");
            return;
        }
    }
    if (live.sizeHeaders != disk.sizeHeaders || live.sizeHeaders > diskHeader.size() ||
        !pageSpanRemoteValid(capture, 0, live.sizeHeaders) ||
        std::memcmp(capture.bytes.data(), diskHeader.data(), live.sizeHeaders) != 0) {
        warnings.push_back("Unreadable discardable pages were not backfilled because the complete readable PE headers do not match disk byte-for-byte.");
        return;
    }
    reconstruction = capture.bytes;

    uint32_t restored = 0;
    for (size_t pg = 0; pg < kind.size(); ++pg) {
        if (capture.pageValid[pg] || kind[pg] != 1) continue;
        const uint64_t pageBegin = pg * kPassiveDumpPageSize;
        const uint64_t pageEnd = std::min<uint64_t>(reconstruction.size(), pageBegin + kPassiveDumpPageSize);
        bool copied = false;
        bool complete = true;
        for (const auto& s : disk.sections) {
            if (!(s.characteristics & kDiscardable) || !s.rawSize) continue;
            const uint64_t secBegin = s.va;
            const uint64_t secEnd = static_cast<uint64_t>(s.va) + s.rawSize;
            const uint64_t from = std::max(pageBegin, secBegin);
            const uint64_t to = std::min(pageEnd, secEnd);
            if (from >= to) continue;
            const uint64_t diskOff = static_cast<uint64_t>(s.rawPointer) + (from - secBegin);
            if (diskOff > diskSize || to - from > diskSize - diskOff ||
                !readFileAt(file.get(), diskOff,
                            reconstruction.data() + static_cast<size_t>(from),
                            static_cast<size_t>(to - from))) {
                complete = false; break;
            }
            copied = true;
        }
        if (copied && complete) {
            capture.pageBackfilled[pg] = 1;
            ++restored;
        }
    }
    if (restored) {
        std::ostringstream os;
        os << "Best-effort restored " << restored
           << " unreadable discardable page(s) after exact full-header/layout correlation with the current module path. Windows cannot prove that a replaced path is the original mapped file object, so any rebuilt PE is forced analysis-only; remote validity remains separate.";
        warnings.push_back(os.str());
    } else std::vector<uint8_t>().swap(reconstruction);
}

struct ExportTarget {
    uint64_t address = 0;
    std::string dll;
    std::string name;
    uint16_t ordinal = 0;
    bool byOrdinal = false;
};
using ExportMap = std::map<uint64_t, ExportTarget>;

bool remoteModuleRead(HANDLE process, const PassiveModuleInfo& module,
                      uint64_t rva, void* out, size_t size) {
    if (!process || !out || !size || rva > module.size || size > module.size - rva ||
        module.base > UINT64_MAX - rva)
        return false;
    SIZE_T got = 0;
    return ReadProcessMemory(process,
               reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(module.base + rva)),
               out, size, &got) && got == size;
}

struct RemoteExportSnapshot {
    PassiveModuleInfo module;
    uint32_t exportRva = 0;
    uint32_t exportSize = 0;
    IMAGE_EXPORT_DIRECTORY directory{};
    std::vector<uint32_t> functions;
    std::vector<uint32_t> nameRvas;
    std::vector<uint16_t> ordinals;
    std::vector<uint8_t> exportBlob; // contains strings/forwarders; parsed only after resume
};

std::vector<RemoteExportSnapshot> captureRemoteExportSnapshots(
        HANDLE process, const std::vector<PassiveModuleInfo>& modules,
        uint64_t mainBase, bool& truncated, std::vector<std::string>& warnings) {
    constexpr size_t kMaxSnapshots = 256;
    constexpr uint64_t kMaxOneExportBlob = 8ull * 1024 * 1024;
    constexpr uint64_t kMaxExportBlobBytes = 64ull * 1024 * 1024;
    std::vector<RemoteExportSnapshot> out;
    out.reserve(std::min(kMaxSnapshots, modules.size()));
    uint64_t blobBytes = 0;
    size_t functionBudget = kMaxRemoteExportTargets;
    for (const auto& module : modules) {
        if (module.base == mainBase) continue;
        if (out.size() >= kMaxSnapshots) { truncated = true; break; }
        const size_t headerSize = static_cast<size_t>(std::min<uint64_t>(module.size, 64u << 10));
        if (headerSize < 0x100) continue;
        std::vector<uint8_t> header(headerSize);
        if (!remoteModuleRead(process, module, 0, header.data(), header.size())) continue;
        PeView p;
        if (!parsePeView(header, p, false) || p.sizeImage != module.size) continue;
        uint32_t erva = 0, esize = 0;
        if (!dataDirectory(header, p, 0, erva, esize) || !erva || esize < 40 ||
            static_cast<uint64_t>(erva) + esize > module.size) continue;
        if (esize > kMaxOneExportBlob || blobBytes > kMaxExportBlobBytes - esize) {
            truncated = true; continue;
        }
        RemoteExportSnapshot s;
        s.module = module;
        s.exportRva = erva;
        s.exportSize = esize;
        if (!remoteModuleRead(process, module, erva, &s.directory, sizeof(s.directory)) ||
            !s.directory.NumberOfFunctions || s.directory.NumberOfFunctions > 200000 ||
            s.directory.NumberOfNames > 200000 ||
            s.directory.NumberOfNames > s.directory.NumberOfFunctions ||
            s.directory.NumberOfFunctions > functionBudget) {
            if (s.directory.NumberOfFunctions > functionBudget) truncated = true;
            continue;
        }
        s.functions.resize(s.directory.NumberOfFunctions);
        s.nameRvas.resize(s.directory.NumberOfNames);
        s.ordinals.resize(s.directory.NumberOfNames);
        if (!remoteModuleRead(process, module, s.directory.AddressOfFunctions,
                              s.functions.data(), s.functions.size() * sizeof(uint32_t)) ||
            (!s.nameRvas.empty() &&
             (!remoteModuleRead(process, module, s.directory.AddressOfNames,
                                s.nameRvas.data(), s.nameRvas.size() * sizeof(uint32_t)) ||
              !remoteModuleRead(process, module, s.directory.AddressOfNameOrdinals,
                                s.ordinals.data(), s.ordinals.size() * sizeof(uint16_t)))))
            continue;
        s.exportBlob.resize(esize);
        if (!remoteModuleRead(process, module, erva, s.exportBlob.data(), s.exportBlob.size()))
            continue;
        functionBudget -= s.functions.size();
        blobBytes += s.exportBlob.size();
        out.push_back(std::move(s));
    }
    if (truncated)
        warnings.push_back("Remote export metadata reached its bounded module/function/blob capture budget.");
    return out;
}

bool localExportName(const RemoteExportSnapshot& s, uint32_t rva, std::string& out) {
    out.clear();
    if (rva < s.exportRva || static_cast<uint64_t>(rva) >=
        static_cast<uint64_t>(s.exportRva) + s.exportBlob.size()) return false;
    size_t at = static_cast<size_t>(rva - s.exportRva);
    for (size_t n = 0; n <= kMaxRemoteExportName && at < s.exportBlob.size(); ++n, ++at) {
        const uint8_t c = s.exportBlob[at];
        if (!c) return !out.empty();
        if (c < 0x20 || c > 0x7e) return false;
        out.push_back(static_cast<char>(c));
    }
    return false;
}

ExportMap buildExportMap(const std::vector<RemoteExportSnapshot>& snapshots,
                         bool& truncated, std::vector<std::string>& warnings) {
    ExportMap targets;
    for (const auto& s : snapshots) {
        std::unordered_map<uint32_t, std::string> names;
        names.reserve(std::min<size_t>(s.nameRvas.size(), 65536));
        for (size_t i = 0; i < s.nameRvas.size(); ++i) {
            const uint16_t index = s.ordinals[i];
            std::string name;
            if (index >= s.functions.size() || !localExportName(s, s.nameRvas[i], name)) continue;
            auto it = names.find(index);
            if (it == names.end() || name < it->second) names[index] = std::move(name);
        }
        const std::string dll = narrowBaseName(s.module.name.empty() ? s.module.path : s.module.name);
        for (size_t i = 0; i < s.functions.size() && targets.size() < kMaxRemoteExportTargets; ++i) {
            const uint32_t functionRva = s.functions[i];
            if (!functionRva || functionRva >= s.module.size) continue;
            const uint64_t exportEnd = static_cast<uint64_t>(s.exportRva) + s.exportSize;
            if (functionRva >= s.exportRva && functionRva < exportEnd) continue;
            if (s.module.base > UINT64_MAX - functionRva ||
                s.directory.Base + static_cast<uint64_t>(i) > 0xffff) continue;
            ExportTarget target;
            target.address = s.module.base + functionRva;
            target.dll = dll;
            target.ordinal = static_cast<uint16_t>(s.directory.Base + i);
            auto ni = names.find(static_cast<uint32_t>(i));
            if (ni == names.end()) target.byOrdinal = true;
            else target.name = ni->second;
            auto [at, inserted] = targets.emplace(target.address, target);
            if (!inserted) {
                if (at->second.byOrdinal && !target.byOrdinal) at->second = std::move(target);
                else if (!at->second.byOrdinal && !target.byOrdinal && target.name < at->second.name)
                    at->second = std::move(target);
            }
        }
        if (targets.size() >= kMaxRemoteExportTargets) { truncated = true; break; }
    }
    if (targets.size() >= kMaxRemoteExportTargets)
        warnings.push_back("Exact-export map reached its 262,144-entry aggregate-memory safety cap.");
    return targets;
}

struct ScanRange { uint32_t rva = 0; uint32_t size = 0; bool knownIat = false; };

std::vector<PeUnpackImport> observeImports(const PassiveCapture& c,
                                           const ExportMap& exports,
                                           bool& truncated,
                                           std::vector<std::string>& warnings) {
    PeView p;
    if (!parsePeView(c.bytes, p, false)) return {};
    if (exports.empty()) {
        warnings.push_back("No exact loaded-module exports were available for passive IAT observation.");
        return {};
    }

    std::vector<ScanRange> ranges;
    uint32_t iatRva = 0, iatSize = 0;
    if (dataDirectory(c.bytes, p, 12, iatRva, iatSize) && iatRva && iatSize &&
        iatRva < c.bytes.size()) {
        iatSize = static_cast<uint32_t>(std::min<uint64_t>(iatSize, c.bytes.size() - iatRva));
        if (iatSize > (32u << 20)) {
            iatSize = 32u << 20;
            truncated = true;
            warnings.push_back("The declared IAT exceeded 32 MiB and was bounded before exact-export matching.");
        }
        ranges.push_back({ iatRva, iatSize, true });
    }
    uint64_t scanBudget = 64ull * 1024 * 1024;
    for (const auto& s : p.sections) {
        const bool executable = (s.characteristics & 0x20000000u) != 0;
        const bool writable = (s.characteristics & 0x80000000u) != 0;
        const bool importLike = s.name == ".idata" || s.name == ".rdata" || s.name == ".data";
        if (executable || (!writable && !importLike) || !scanBudget || s.va >= c.bytes.size()) continue;
        uint64_t n = std::min<uint64_t>(std::max(s.virtualSize, s.rawSize), c.bytes.size() - s.va);
        n = std::min(n, scanBudget);
        if (n) ranges.push_back({ s.va, static_cast<uint32_t>(n), false });
        scanBudget -= n;
    }
    if (!scanBudget) {
        truncated = true;
        warnings.push_back("Passive import scanning reached its 64 MiB data-section cap.");
    }

    const uint32_t ptrSize = p.is64 ? 8u : 4u;
    std::map<uint32_t, PeUnpackImport> found;
    for (const auto& range : ranges) {
        std::vector<std::pair<uint32_t, ExportTarget>> run;
        auto flush = [&] {
            if (range.knownIat || run.size() >= 2) {
                for (const auto& [rva, t] : run) {
                    PeUnpackImport i;
                    i.slotVA = c.base + rva;
                    i.dll = t.dll;
                    i.name = t.name;
                    i.ordinal = t.ordinal;
                    i.byOrdinal = t.byOrdinal;
                    i.resolvedVA = t.address;
                    found.emplace(rva, std::move(i));
                }
            }
            run.clear();
        };
        const uint64_t end = std::min<uint64_t>(c.bytes.size(),
            static_cast<uint64_t>(range.rva) + range.size);
        uint64_t at = (static_cast<uint64_t>(range.rva) + ptrSize - 1) & ~(ptrSize - 1ull);
        for (; at + ptrSize <= end && found.size() < 16384; at += ptrSize) {
            if (!pageSpanRemoteValid(c, at, ptrSize)) { flush(); continue; }
            uint64_t value = 0;
            if (p.is64) readAt(c.bytes, at, value);
            else { uint32_t v = 0; readAt(c.bytes, at, v); value = v; }
            auto target = exports.find(value);
            if (target == exports.end()) { flush(); continue; }
            if (!run.empty() && run.back().first + ptrSize != at) flush();
            run.emplace_back(static_cast<uint32_t>(at), target->second);
            // A hostile all-export-pointer range must not accumulate millions
            // of string-owning candidates before the first flush.
            if (run.size() >= 4096) flush();
            if (found.size() >= 16384) { truncated = true; break; }
        }
        flush();
        if (found.size() >= 16384) { truncated = true; break; }
    }
    std::vector<PeUnpackImport> out;
    out.reserve(found.size());
    for (auto& [_, i] : found) out.push_back(std::move(i));
    return out;
}

using NtSuspendResume = LONG (NTAPI*)(HANDLE);

class OptionalSuspend {
public:
    bool suspend(HANDLE process) {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        suspend_ = reinterpret_cast<NtSuspendResume>(GetProcAddress(ntdll, "NtSuspendProcess"));
        resume_ = reinterpret_cast<NtSuspendResume>(GetProcAddress(ntdll, "NtResumeProcess"));
        process_ = process;
        if (!suspend_ || !resume_ || suspend_(process_) < 0) return false;
        active_ = true;
        return true;
    }
    ~OptionalSuspend() { resume(); }
    bool resume() {
        if (!active_) return true;
        const bool ok = resume_(process_) >= 0;
        // Retain ownership on failure so the destructor gets one final retry.
        // Clearing this unconditionally could strand every target thread
        // suspended after a transient NtResumeProcess failure.
        if (ok) active_ = false;
        return ok;
    }
private:
    HANDLE process_ = nullptr;
    NtSuspendResume suspend_ = nullptr;
    NtSuspendResume resume_ = nullptr;
    bool active_ = false;
};

void appendPageProvenance(std::ostringstream& os, const PassiveCapture& capture) {
    os << "Page provenance map (RVA half-open ranges):\n";
    if (capture.pageValid.empty()) { os << "  <none>\n"; return; }
    auto state = [&](size_t page) {
        if (page < capture.pageValid.size() && capture.pageValid[page]) return 1u;
        if (page < capture.pageBackfilled.size() && capture.pageBackfilled[page]) return 2u;
        return 0u;
    };
    auto protection = [&](size_t page) -> uint32_t {
        return page < capture.pageProtection.size() ? capture.pageProtection[page] : 0;
    };
    size_t begin = 0;
    while (begin < capture.pageValid.size()) {
        const unsigned provenance = state(begin);
        const uint32_t protect = protection(begin);
        size_t end = begin + 1;
        while (end < capture.pageValid.size() && state(end) == provenance &&
               protection(end) == protect) ++end;
        const uint64_t beginRva = static_cast<uint64_t>(begin) * kPassiveDumpPageSize;
        const uint64_t endRva = std::min<uint64_t>(capture.bytes.size(),
            static_cast<uint64_t>(end) * kPassiveDumpPageSize);
        const char* label = provenance == 1 ? "remote-valid" :
                            provenance == 2 ? "disk-backfill-working-copy" :
                                              "unreadable-zero-in-raw";
        os << "  0x" << std::hex << beginRva << "-0x" << endRva
           << " " << label << " protect=0x" << protect << std::dec << "\n";
        begin = end;
    }
}

std::string buildReport(const PassiveDumpResult& r) {
    std::ostringstream os;
    os << "Passive process snapshot\n"
       << "Access model: query/read only; no DebugActiveProcess, injection, patching, or target writes.\n"
       << "PID: " << r.pid << "\n"
       << "Module: " << utf8(r.module.path) << "\n"
       << "Runtime range: 0x" << std::hex << r.module.base << "-0x"
       << (r.module.base + r.module.size) << std::dec << "\n"
       << "Timing decision: " << decisionName(r.timingDecision) << "\n"
       << "Samples: " << r.sampleHistory.size() << "\n"
       << "Readable pages: " << r.capture.readablePages << "/"
       << r.capture.pageValid.size() << "\n"
       << "Best-effort discardable pages backfilled: "
       << std::count(r.capture.pageBackfilled.begin(), r.capture.pageBackfilled.end(), uint8_t{1}) << "\n"
       << "Disk backfill provenance: "
       << (std::find(r.capture.pageBackfilled.begin(), r.capture.pageBackfilled.end(), uint8_t{1}) !=
           r.capture.pageBackfilled.end()
           ? "best-effort current-path correlation; artifact cannot be labelled runnable"
           : "not used") << "\n"
       << "Required file-backed coverage: "
       << (r.capture.completeForDiskRebuild ? "complete" : "incomplete") << "\n"
       << "Exact-export import slots: " << r.observedImports.size()
       << (r.importObservationTruncated ? " (truncated)" : "") << "\n"
       << "Import observation coherence: "
       << (!r.importObservationRequested ? "not requested"
           : r.importObservationCoherent ? "remote exports captured in the final suspension window"
                                          : "best-effort live remote export snapshot") << "\n"
       << "OEP trust: " << oepTrustName(r.oep.trust) << "\n"
       << "Artifact assessment: " << artifactName(r.artifactAssessment) << "\n"
       << "Estimated aggregate peak / budget: " << r.memory.estimatedPeakBytes
       << " / " << r.memory.budgetBytes << " bytes\n"
       << "Final-capture suspension: "
       << (r.suspendedDuringCapture ? "NtSuspendProcess/NtResumeProcess used"
                                    : "not used; consistency is best-effort") << "\n";
    if (r.launched)
        os << "Launch: normal CreateProcess (no DEBUG flags), one-process kill-on-close Job containment: "
           << (r.launchContained ? "active" : "failed") << "\n";
    if (!r.warnings.empty()) {
        os << "Warnings:\n";
        for (const auto& w : r.warnings) os << "  - " << w << "\n";
    }
    if (!r.error.empty()) os << "Error: " << r.error << "\n";
    appendPageProvenance(os, r.capture);
    if (!r.rebuilt.report.empty())
        os << "PE reconstruction details:\n" << r.rebuilt.report;
    return os.str();
}

#endif // _WIN32

#ifndef _WIN32
std::string buildReport(const PassiveDumpResult& r) {
    std::ostringstream os;
    os << "Passive process snapshot\nPID: " << r.pid << "\n";
    if (!r.error.empty()) os << "Error: " << r.error << "\n";
    return os.str();
}
#endif

} // namespace

PassiveMemoryAssessment EstimatePassiveDumpMemory(uint64_t imageBytes,
                                                   bool rebuildPe,
                                                   bool observeExactExportImports) {
    PassiveMemoryAssessment a;
    a.imageBytes = imageBytes;
    a.imageMultiplier = rebuildPe ? 6u : 2u;
    // A remote export map uses node/string storage rather than one flat image;
    // reserve generously for its hard-capped entries and module scratch data.
    const uint64_t fixedReserve = observeExactExportImports
        ? 384ull * 1024 * 1024 : 64ull * 1024 * 1024;
    if (!imageBytes || imageBytes > kPassiveDumpMaxImage ||
        imageBytes > (UINT64_MAX - fixedReserve) / a.imageMultiplier) {
        a.estimatedPeakBytes = UINT64_MAX;
        return a;
    }
    a.estimatedPeakBytes = fixedReserve + imageBytes * a.imageMultiplier;
    a.accepted = a.estimatedPeakBytes <= a.budgetBytes;
    return a;
}

PassiveOepAssessment AssessPassiveOep(const PassiveCapture& capture,
                                      bool hasManualOep,
                                      uint64_t manualOepVA) {
    PassiveOepAssessment a;
    a.trust = hasManualOep ? PassiveOepTrust::ManualOepRejected
                           : PassiveOepTrust::NotAssessed;
    a.effectiveVA = hasManualOep ? manualOepVA : 0;
    const auto& b = capture.bytes;
    auto get = [&](uint64_t off, void* out, size_t n) {
        if (!out || off > b.size() || n > b.size() - static_cast<size_t>(off)) return false;
        std::memcpy(out, b.data() + static_cast<size_t>(off), n);
        return true;
    };
    uint16_t mz = 0, sectionCount = 0, optionalSize = 0, magic = 0;
    uint32_t pe = 0, signature = 0, sizeImage = 0, headerEntry = 0;
    if (!get(0, &mz, sizeof(mz)) || mz != 0x5a4d ||
        !get(0x3c, &pe, sizeof(pe)) ||
        !get(pe, &signature, sizeof(signature)) || signature != 0x4550 ||
        !get(static_cast<uint64_t>(pe) + 6, &sectionCount, sizeof(sectionCount)) ||
        !get(static_cast<uint64_t>(pe) + 20, &optionalSize, sizeof(optionalSize)) ||
        !sectionCount || sectionCount > 96) return a;
    const uint64_t optional = static_cast<uint64_t>(pe) + 24;
    if (!get(optional, &magic, sizeof(magic)) || (magic != 0x10b && magic != 0x20b) ||
        optionalSize < (magic == 0x20b ? 112u : 96u) ||
        !get(optional + 16, &headerEntry, sizeof(headerEntry)) ||
        !get(optional + 56, &sizeImage, sizeof(sizeImage)) || !sizeImage ||
        sizeImage > b.size()) return a;

    uint64_t candidateVA = manualOepVA;
    uint64_t candidateRva64 = 0;
    if (hasManualOep) {
        if (manualOepVA < capture.base) return a;
        candidateRva64 = manualOepVA - capture.base;
    } else {
        candidateRva64 = headerEntry;
        if (capture.base > UINT64_MAX - headerEntry) return a;
        candidateVA = capture.base + headerEntry;
        a.trust = PassiveOepTrust::HeaderEntryUnverified;
    }
    a.effectiveVA = candidateVA;
    if (candidateRva64 >= sizeImage || candidateRva64 >= b.size() || candidateRva64 > UINT32_MAX)
        return a;
    a.entryRVA = static_cast<uint32_t>(candidateRva64);

    const uint64_t sectionTable = optional + optionalSize;
    if (sectionTable > b.size() || static_cast<uint64_t>(sectionCount) * 40 > b.size() - sectionTable)
        return a;
    bool owner = false;
    for (uint16_t i = 0; i < sectionCount; ++i) {
        const uint64_t at = sectionTable + static_cast<uint64_t>(i) * 40;
        uint32_t virtualSize = 0, rva = 0, rawSize = 0;
        if (!get(at + 8, &virtualSize, sizeof(virtualSize)) ||
            !get(at + 12, &rva, sizeof(rva)) || !get(at + 16, &rawSize, sizeof(rawSize)))
            return a;
        const uint64_t span = std::max<uint32_t>(virtualSize, rawSize);
        if (a.entryRVA >= rva && static_cast<uint64_t>(a.entryRVA) - rva < span) {
            owner = true; break;
        }
    }
    if (!owner) return a;
    const size_t page = static_cast<size_t>(candidateRva64 / kPassiveDumpPageSize);
    a.pageCaptured = page < capture.pageValid.size() && capture.pageValid[page] != 0;
    if (page < capture.pageProtection.size()) {
        const uint32_t basic = capture.pageProtection[page] & 0xffu;
        a.executablePage = basic == 0x10u || basic == 0x20u ||
                           basic == 0x40u || basic == 0x80u;
    }
    a.structurallyValid = owner && a.pageCaptured;
    if (hasManualOep && a.structurallyValid && a.executablePage)
        a.trust = PassiveOepTrust::ManualOepValidated;
    return a;
}

PassiveArtifactAssessment AssessPassiveArtifact(bool rebuildSucceeded,
                                                 PassiveOepTrust oepTrust,
                                                 bool usedDiskBackfill) noexcept {
    if (!rebuildSucceeded) return PassiveArtifactAssessment::RawCaptureOnly;
    if (oepTrust == PassiveOepTrust::ManualOepValidated && !usedDiskBackfill)
        return PassiveArtifactAssessment::RebuiltRunnable;
    return PassiveArtifactAssessment::RebuiltAnalysisOnly;
}

PassivePageFingerprint FingerprintPassivePages(const std::vector<uint8_t>& bytes,
                                                const std::vector<uint8_t>& valid,
                                                size_t pageSize,
                                                size_t entropyByteCap) {
    PassivePageFingerprint f;
    f.pageSize = pageSize;
    f.byteSize = bytes.size();
    if (!pageSize || pageSize > (16u << 20) || bytes.size() > kPassiveDumpMaxImage) return f;
    const size_t pages = (bytes.size() + pageSize - 1) / pageSize;
    f.hashes.assign(pages, 0);
    f.valid.assign(pages, 0);
    uint64_t readableBytes = 0;
    for (size_t pg = 0; pg < pages; ++pg) {
        if (pg >= valid.size() || !valid[pg]) continue;
        const size_t off = pg * pageSize;
        const size_t n = std::min(pageSize, bytes.size() - off);
        f.valid[pg] = 1;
        readableBytes += n;
    }
    if (!readableBytes) return f;
    const uint64_t stride = entropyByteCap
        ? std::max<uint64_t>(1, (readableBytes + entropyByteCap - 1) / entropyByteCap) : 0;
    std::array<uint64_t, 256> counts{};
    uint64_t ordinal = 0;
    for (size_t pg = 0; pg < pages; ++pg) {
        if (!f.valid[pg]) continue;
        const size_t off = pg * pageSize;
        const size_t n = std::min(pageSize, bytes.size() - off);
        uint64_t hash = kFnvOffset;
        for (size_t i = 0; i < n; ++i, ++ordinal) {
            const uint8_t value = bytes[off + i];
            hash ^= value;
            hash *= kFnvPrime;
            if (stride && ordinal % stride == 0 && f.sampledBytes < entropyByteCap) {
                ++counts[value];
                ++f.sampledBytes;
            }
        }
        // A readable page must remain distinguishable from the unreadable hash
        // sentinel even in the astronomically unlikely FNV-zero case.
        f.hashes[pg] = hash ? hash : 1;
    }
    if (f.sampledBytes) {
        for (uint64_t count : counts) {
            if (!count) continue;
            const double probability = static_cast<double>(count) / static_cast<double>(f.sampledBytes);
            f.entropy -= probability * std::log2(probability);
        }
    }
    return f;
}

PassiveSampleMetrics ComparePassiveSamples(const PassivePageFingerprint* previous,
                                            const PassivePageFingerprint& current,
                                            uint64_t timestampMs) {
    PassiveSampleMetrics m;
    m.timestampMs = timestampMs;
    m.totalPages = static_cast<uint32_t>(std::min<size_t>(current.valid.size(), UINT32_MAX));
    m.entropy = current.entropy;
    for (uint8_t v : current.valid) if (v) ++m.readablePages;
    if (!previous || previous->pageSize != current.pageSize ||
        previous->byteSize != current.byteSize) return m;
    const size_t pages = std::max(previous->valid.size(), current.valid.size());
    uint32_t previousReadable = 0;
    for (uint8_t v : previous->valid) if (v) ++previousReadable;
    for (size_t pg = 0; pg < pages; ++pg) {
        const bool a = pg < previous->valid.size() && previous->valid[pg];
        const bool b = pg < current.valid.size() && current.valid[pg];
        if (a != b) { ++m.validityChangedPages; continue; }
        if (!a) continue;
        ++m.comparablePages;
        const uint64_t ah = pg < previous->hashes.size() ? previous->hashes[pg] : 0;
        const uint64_t bh = pg < current.hashes.size() ? current.hashes[pg] : 0;
        if (ah != bh) ++m.changedPages;
    }
    const uint32_t coverageDenom = std::max(previousReadable, m.readablePages);
    m.comparablePageRatio = coverageDenom
        ? static_cast<double>(m.comparablePages) / coverageDenom : 0.0;
    m.changedPageRatio = coverageDenom
        ? static_cast<double>(m.changedPages + m.validityChangedPages) / coverageDenom : 1.0;
    m.entropyDelta = std::abs(current.entropy - previous->entropy);
    return m;
}

PassiveSettleTracker::PassiveSettleTracker(PassiveSettleConfig config)
    : config_(config) {
    config_.stableSamplesRequired = std::clamp<uint32_t>(config_.stableSamplesRequired, 1, 1000);
    config_.minWatchMs = std::min<uint64_t>(config_.minWatchMs, 60ull * 60 * 1000);
    if (!config_.maxWatchMs) config_.maxWatchMs = 60000;
    config_.maxWatchMs = std::min<uint64_t>(config_.maxWatchMs, 24ull * 60 * 60 * 1000);
    config_.maxChangedPageRatio = clampRatio(config_.maxChangedPageRatio, 0.0025);
    config_.maxEntropyDelta = std::isfinite(config_.maxEntropyDelta)
        ? std::clamp(config_.maxEntropyDelta, 0.0, 8.0) : 0.015;
    config_.minComparablePageRatio = clampRatio(config_.minComparablePageRatio, 0.8);
    if (config_.maxWatchMs && config_.maxWatchMs < config_.minWatchMs)
        config_.maxWatchMs = config_.minWatchMs;
}

void PassiveSettleTracker::reset(uint64_t startTimestampMs) {
    startTimestampMs_ = startTimestampMs;
    lastTimestampMs_ = startTimestampMs;
    stableSamples_ = 0;
    haveSample_ = false;
    latest_ = {};
}

PassiveSettleDecision PassiveSettleTracker::observe(const PassiveSampleMetrics& sample,
                                                    bool manualCaptureRequested) {
    if (manualCaptureRequested) {
        latest_ = sample;
        return PassiveSettleDecision::Manual;
    }
    if (!haveSample_ && !startTimestampMs_) startTimestampMs_ = sample.timestampMs;
    const bool monotonic = !haveSample_ || sample.timestampMs >= lastTimestampMs_;
    const uint64_t elapsed = sample.timestampMs >= startTimestampMs_
        ? sample.timestampMs - startTimestampMs_ : 0;
    const bool stable = haveSample_ && monotonic && sample.comparablePages != 0 &&
        sample.comparablePageRatio >= config_.minComparablePageRatio &&
        sample.changedPageRatio <= config_.maxChangedPageRatio &&
        sample.entropyDelta <= config_.maxEntropyDelta;
    stableSamples_ = stable ? std::min<uint32_t>(stableSamples_ + 1, 1000000) : 0;
    latest_ = sample;
    lastTimestampMs_ = std::max(lastTimestampMs_, sample.timestampMs);
    haveSample_ = true;
    if (elapsed >= config_.minWatchMs && stableSamples_ >= config_.stableSamplesRequired)
        return PassiveSettleDecision::Settled;
    if (config_.maxWatchMs && elapsed >= config_.maxWatchMs)
        return PassiveSettleDecision::TimedOut;
    return PassiveSettleDecision::Continue;
}

std::vector<PassiveProcessInfo> EnumeratePassiveProcesses(size_t cap) {
    std::vector<PassiveProcessInfo> out;
#ifdef _WIN32
    cap = std::min<size_t>(cap, 16384);
    Handle snap(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snap) return out;
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (!Process32FirstW(snap.get(), &pe)) return out;
    do {
        if (!pe.th32ProcessID) continue;
        PassiveProcessInfo info;
        info.pid = pe.th32ProcessID;
        info.imageName = pe.szExeFile;
        Handle process(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.pid));
        if (process) queryProcessPath(process.get(), info.imagePath);
        out.push_back(std::move(info));
    } while (out.size() < cap && Process32NextW(snap.get(), &pe));
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        if (a.imageName != b.imageName) return a.imageName < b.imageName;
        return a.pid < b.pid;
    });
#else
    (void)cap;
#endif
    return out;
}

PassiveDumpService::~PassiveDumpService() {
    cancelAndWait();
    terminateContainedLaunch();
}

bool PassiveDumpService::start(PassiveDumpRequest request, std::string* error) {
    if ((request.pid == 0 && request.executable.empty()) ||
        (request.pid != 0 && !request.executable.empty())) {
        if (error) *error = "Choose exactly one source: an existing PID or an executable to launch.";
        return false;
    }
    if (request.executable.size() > 32767 || request.arguments.size() > 256) {
        if (error) *error = "The launch path/argument list exceeds the bounded Windows command-line policy.";
        return false;
    }
    size_t commandChars = request.executable.size() + 1;
    for (const auto& arg : request.arguments) {
        if (arg.size() > 32767 || commandChars > 32767 ||
            arg.size() + 3 > 32767 - commandChars) {
            if (error) *error = "The launch command line exceeds 32,767 characters.";
            return false;
        }
        commandChars += arg.size() + 3;
    }
    request.captureCap = std::clamp<size_t>(request.captureCap, 0x1000, kPassiveDumpMaxImage);
    request.sampleIntervalMs = std::clamp<uint32_t>(request.sampleIntervalMs, 50, 5000);
    bool expected = false;
    if (!busy_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        if (error) *error = "A passive dump is already running.";
        return false;
    }
    std::lock_guard<std::mutex> lifecycle(lifecycleMutex_);
    if (worker_.joinable()) worker_.join();
    terminateContainedLaunch();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        progress_ = {};
        results_.clear();
    }
    emergencyFailure_.store(PassiveWorkerFailure::None, std::memory_order_release);
    cancel_.store(false, std::memory_order_release);
    manualCapture_.store(false, std::memory_order_release);
    try {
        worker_ = std::thread([this, request = std::move(request)]() mutable noexcept {
            const bool launched = request.pid == 0;
            try {
                workerMain(std::move(request));
            } catch (const std::bad_alloc&) {
                failWorkerNoexcept(PassiveWorkerFailure::OutOfMemory, launched);
            } catch (...) {
                failWorkerNoexcept(PassiveWorkerFailure::Unexpected, launched);
            }
        });
    } catch (...) {
        busy_.store(false, std::memory_order_release);
        if (error) *error = "The passive-dump worker thread could not be created.";
        return false;
    }
    return true;
}

void PassiveDumpService::requestCapture() {
    manualCapture_.store(true, std::memory_order_release);
    cv_.notify_all();
}

void PassiveDumpService::cancel() {
    cancel_.store(true, std::memory_order_release);
    cv_.notify_all();
}

void PassiveDumpService::cancelAndWait() {
    std::lock_guard<std::mutex> lifecycle(lifecycleMutex_);
    cancel();
    if (worker_.joinable()) worker_.join();
}

void PassiveDumpService::terminateContainedLaunch() {
#ifdef _WIN32
    uintptr_t job = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        job = ownedLaunchJob_;
        ownedLaunchJob_ = 0;
    }
    if (job) {
        TerminateJobObject(reinterpret_cast<HANDLE>(job), 1);
        CloseHandle(reinterpret_cast<HANDLE>(job));
    }
#else
    std::lock_guard<std::mutex> lock(mutex_);
    ownedLaunchJob_ = 0;
#endif
}

PassiveDumpProgress PassiveDumpService::progress() const {
    std::lock_guard<std::mutex> lock(mutex_);
    PassiveDumpProgress out = progress_;
    const PassiveWorkerFailure failure = emergencyFailure_.load(std::memory_order_acquire);
    if (failure == PassiveWorkerFailure::OutOfMemory)
        out.status = "Passive snapshot stopped at the emergency out-of-memory boundary.";
    else if (failure == PassiveWorkerFailure::Unexpected)
        out.status = "Passive snapshot stopped at the emergency worker boundary.";
    return out;
}

bool PassiveDumpService::tryTakeResult(PassiveDumpResult& out) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!results_.empty()) {
            out = std::move(results_.back());
            results_.clear();
            return true;
        }
    }
    PassiveWorkerFailure failure = emergencyFailure_.load(std::memory_order_acquire);
    if (failure == PassiveWorkerFailure::None) return false;
    // Allocation is deliberately deferred to the polling/caller thread. If it
    // also cannot allocate, the atomic failure remains pending for a later poll.
    static_assert(std::is_nothrow_move_assignable_v<PassiveDumpResult>);
    try {
        PassiveDumpResult fallback;
        fallback.workerFailure = failure;
        fallback.error = failure == PassiveWorkerFailure::OutOfMemory
            ? "Passive snapshot ran out of memory within its aggregate budget."
            : "Passive snapshot stopped after an unexpected worker failure.";
        fallback.report = fallback.error;
        PassiveWorkerFailure expected = failure;
        if (!emergencyFailure_.compare_exchange_strong(expected, PassiveWorkerFailure::None,
                                                        std::memory_order_acq_rel)) return false;
        out = std::move(fallback); // statically guaranteed not to allocate/throw
        return true;
    } catch (...) {
        return false; // emergencyFailure_ was not consumed; a later poll can retry
    }
}

void PassiveDumpService::publish(PassiveDumpPhase phase, const std::string& status) {
    std::lock_guard<std::mutex> lock(mutex_);
    progress_.phase = phase;
    progress_.status = status;
}

void PassiveDumpService::failWorkerNoexcept(PassiveWorkerFailure failure, bool launched) noexcept {
    // Store the diagnostic before touching a mutex or any object that might be
    // in a partially-mutated state. No strings/vectors are constructed here.
    emergencyFailure_.store(failure, std::memory_order_release);
    if (launched) {
        try { terminateContainedLaunch(); } catch (...) {}
    }
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        progress_.phase = PassiveDumpPhase::Failed;
        results_.clear();
    } catch (...) {
        // std::mutex acquisition can theoretically report a system error. The
        // atomic failure/busy state remains sufficient for caller recovery.
    }
    busy_.store(false, std::memory_order_release);
    cv_.notify_all();
}

void PassiveDumpService::workerMain(PassiveDumpRequest request) {
    PassiveDumpResult result;
    result.launched = request.pid == 0;
    result.importObservationRequested = request.observeExactExportImports;
    auto finish = [&](PassiveDumpPhase phase) {
        if (phase == PassiveDumpPhase::Failed && result.launched) terminateContainedLaunch();
        result.report = buildReport(result);
        {
            std::lock_guard<std::mutex> lock(mutex_);
            progress_.phase = phase;
            progress_.status = result.error.empty() ? (result.success ? "Passive snapshot complete." : "Snapshot incomplete.")
                                                    : result.error;
            results_.clear();
            results_.push_back(std::move(result));
        }
        busy_.store(false, std::memory_order_release);
        cv_.notify_all();
    };

#ifndef _WIN32
    result.error = "Passive process dumping is available only on Windows.";
    finish(PassiveDumpPhase::Failed);
    return;
#else
    publish(PassiveDumpPhase::Opening, result.launched ? "Launching without debugger flags..."
                                                       : "Opening process read-only...");
    uint32_t pid = request.pid;
    Handle launchedProcess;
    if (result.launched) {
        const std::wstring executable = fullPath(request.executable);
        std::wstring cmd = commandLine(request);
        if (cmd.empty() || cmd.size() >= 32767) {
            result.error = "The fully quoted Windows command line exceeds 32,767 characters.";
            finish(PassiveDumpPhase::Failed); return;
        }
        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        const wchar_t* cwd = request.workingDirectory.empty() ? nullptr : request.workingDirectory.c_str();
        if (!CreateProcessW(executable.c_str(), cmd.data(), nullptr, nullptr, FALSE,
                            CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP, nullptr, cwd, &si, &pi)) {
            result.error = winError("CreateProcess"); finish(PassiveDumpPhase::Failed); return;
        }
        Handle child(pi.hProcess), initialThread(pi.hThread);
        Handle job(CreateJobObjectW(nullptr, nullptr));
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
                                                  JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        if (!job || !SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation,
                                              &limits, sizeof(limits)) ||
            !AssignProcessToJobObject(job.get(), child.get())) {
            const std::string e = winError("Launch containment setup");
            TerminateProcess(child.get(), 1);
            WaitForSingleObject(child.get(), 5000);
            result.error = e + " The suspended target was terminated before it ran.";
            finish(PassiveDumpPhase::Failed); return;
        }
        if (ResumeThread(initialThread.get()) == static_cast<DWORD>(-1)) {
            const std::string e = winError("ResumeThread");
            TerminateJobObject(job.get(), 1);
            WaitForSingleObject(child.get(), 5000);
            result.error = e; finish(PassiveDumpPhase::Failed); return;
        }
        pid = pi.dwProcessId;
        result.launchContained = true;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ownedLaunchJob_ = reinterpret_cast<uintptr_t>(job.release());
        }
        // Keep the authoritative CreateProcess handle for the entire capture.
        // Closing and reopening by numeric PID creates a fast-exit/PID-reuse
        // window in which an unrelated process could otherwise be captured.
        launchedProcess = std::move(child);
    }

    result.pid = pid;
    DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
                   PROCESS_VM_READ | SYNCHRONIZE;
    constexpr DWORD kSuspendResume = 0x0800;
    bool suspendRight = request.suspendDuringFinalCapture;
    Handle process;
    if (launchedProcess) {
        process = std::move(launchedProcess);
    } else {
        process.reset(OpenProcess(access | (suspendRight ? kSuspendResume : 0), FALSE, pid));
        if (!process && suspendRight) {
            result.warnings.push_back("PROCESS_SUSPEND_RESUME was denied; final capture will remain unsuspended.");
            suspendRight = false;
            process.reset(OpenProcess(access, FALSE, pid));
        }
    }
    if (!process) {
        result.error = winError("OpenProcess"); finish(PassiveDumpPhase::Failed); return;
    }
    if (pid == GetCurrentProcessId() && suspendRight) {
        suspendRight = false;
        result.warnings.push_back("Self-snapshot suspension was disabled to avoid suspending the capture worker itself.");
    }
    std::vector<PassiveModuleInfo> modules;
    bool mainReady = false;
    const uint64_t moduleDeadline = nowMs() + (result.launched ? 5000 : 0);
    do {
        result.processPath.clear();
        if (queryProcessPath(process.get(), result.processPath)) {
            modules = enumerateModules(pid, 512, nullptr);
            mainReady = chooseMainModule(modules, result.processPath, result.module);
        }
        if (mainReady) break;
        if (!result.launched || WaitForSingleObject(process.get(), 0) != WAIT_TIMEOUT ||
            cancel_.load(std::memory_order_acquire) || nowMs() >= moduleDeadline) break;
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(25), [this] {
            return cancel_.load(std::memory_order_acquire);
        });
    } while (true);
    if (!mainReady) {
        // One diagnostic enumeration captures the real error after transient
        // loader-startup races have been exhausted.
        modules = enumerateModules(pid, 512, &result.warnings);
        result.error = result.processPath.empty()
            ? "The target image path could not be queried safely."
            : "The main module could not be matched uniquely to the process image path.";
        finish(PassiveDumpPhase::Failed); return;
    }
    uint32_t headerImageSize = 0;
    std::string headerError;
    if (!remoteImageSize(process.get(), result.module.base, headerImageSize, headerError)) {
        result.error = headerError; finish(PassiveDumpPhase::Failed); return;
    }
    if (headerImageSize > result.module.size) {
        result.error = "PE SizeOfImage exceeds the main module extent reported by the loader.";
        finish(PassiveDumpPhase::Failed); return;
    }
    result.module.size = headerImageSize;
    if (result.module.base > UINT64_MAX - result.module.size) {
        result.error = "The loader-reported main module range overflows the address space.";
        finish(PassiveDumpPhase::Failed); return;
    }
    if (result.module.size > request.captureCap) {
        result.error = "The main module exceeds the configured passive capture cap.";
        finish(PassiveDumpPhase::Failed); return;
    }
    result.memory = EstimatePassiveDumpMemory(result.module.size, request.rebuildPe,
                                              request.observeExactExportImports);
    if (!result.memory.accepted) {
        std::ostringstream message;
        message << "The passive capture was refused before allocation: estimated aggregate peak "
                << result.memory.estimatedPeakBytes << " bytes exceeds the "
                << result.memory.budgetBytes << "-byte safety budget.";
        result.error = message.str();
        finish(PassiveDumpPhase::Failed); return;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        progress_.pid = pid;
        progress_.moduleBase = result.module.base;
        progress_.moduleSize = result.module.size;
        progress_.totalPages = static_cast<uint32_t>((result.module.size + kPassiveDumpPageSize - 1) /
                                                     kPassiveDumpPageSize);
    }

    const uint64_t start = nowMs();
    PassiveSettleTracker tracker(request.settle);
    tracker.reset(start);
    PassivePageFingerprint previous;
    bool havePrevious = false;
    if (request.timing == PassiveTiming::Immediate) {
        result.timingDecision = PassiveSettleDecision::Immediate;
    } else {
        publish(PassiveDumpPhase::Watching,
                request.timing == PassiveTiming::Manual
                    ? "Watching read-only; waiting for manual capture..."
                    : "Watching page changes and entropy settle...");
        for (;;) {
            if (cancel_.load(std::memory_order_acquire)) {
                result.error = "Passive snapshot cancelled.";
                if (request.terminateLaunchedOnCancel && result.launched) terminateContainedLaunch();
                finish(PassiveDumpPhase::Cancelled); return;
            }
            if (WaitForSingleObject(process.get(), 0) != WAIT_TIMEOUT) {
                result.error = "The target exited before the passive capture point.";
                finish(PassiveDumpPhase::Failed); return;
            }
            PassiveCapture sample = captureImage(process.get(), result.module.base,
                                                  static_cast<size_t>(result.module.size), cancel_);
            if (cancel_.load(std::memory_order_acquire)) continue;
            PassivePageFingerprint fp = FingerprintPassivePages(sample.bytes, sample.pageValid);
            const uint64_t stamp = nowMs();
            PassiveSampleMetrics metrics = ComparePassiveSamples(havePrevious ? &previous : nullptr,
                                                                 fp, stamp);
            const bool manual = manualCapture_.exchange(false, std::memory_order_acq_rel);
            PassiveSettleDecision decision = tracker.observe(metrics, manual);
            if (result.sampleHistory.size() == 512) result.sampleHistory.erase(result.sampleHistory.begin());
            result.sampleHistory.push_back(metrics);
            result.finalSample = metrics;
            previous = std::move(fp);
            havePrevious = true;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                progress_.elapsedMs = stamp - start;
                progress_.samples = static_cast<uint32_t>(result.sampleHistory.size());
                progress_.stableSamples = tracker.stableSamples();
                progress_.readablePages = sample.readablePages;
                progress_.changedPageRatio = metrics.changedPageRatio;
                progress_.entropy = metrics.entropy;
            }
            if (request.timing == PassiveTiming::Manual) {
                if (decision == PassiveSettleDecision::Manual) {
                    result.timingDecision = decision; break;
                }
            } else if (decision != PassiveSettleDecision::Continue) {
                result.timingDecision = decision; break;
            }
            std::unique_lock<std::mutex> lock(mutex_);
            cv_.wait_for(lock, std::chrono::milliseconds(request.sampleIntervalMs), [this] {
                return cancel_.load(std::memory_order_acquire) ||
                       manualCapture_.load(std::memory_order_acquire);
            });
        }
    }

    OptionalSuspend suspension;
    std::vector<RemoteExportSnapshot> finalExportSnapshots;
    if (request.suspendDuringFinalCapture && suspendRight) {
        publish(PassiveDumpPhase::Suspending, "Suspending briefly for a consistent final read...");
        if (suspension.suspend(process.get())) result.suspendedDuringCapture = true;
        else result.warnings.push_back("NtSuspendProcess failed; the final page snapshot is best-effort.");
    }
    publish(PassiveDumpPhase::Capturing, "Capturing readable mapped pages...");
    result.capture = captureImage(process.get(), result.module.base,
                                  static_cast<size_t>(result.module.size), cancel_);
    modules = enumerateModules(pid, 512, &result.warnings);
    if (request.observeExactExportImports && !cancel_.load(std::memory_order_acquire)) {
        publish(PassiveDumpPhase::ResolvingImports,
                "Capturing final remote export metadata for local IAT matching...");
        finalExportSnapshots = captureRemoteExportSnapshots(
            process.get(), modules, result.module.base,
            result.importObservationTruncated, result.warnings);
        result.importObservationCoherent = result.suspendedDuringCapture;
    }
    if (result.suspendedDuringCapture && !suspension.resume()) {
        result.warnings.push_back("NtResumeProcess reported a transient failure after final capture; retrying before local reconstruction.");
        if (!suspension.resume()) {
            result.error = "The target could not be resumed promptly; local import scanning/reconstruction was aborted.";
            finish(PassiveDumpPhase::Failed); return;
        }
    }
    if (cancel_.load(std::memory_order_acquire)) {
        result.error = "Passive snapshot cancelled during capture.";
        if (request.terminateLaunchedOnCancel && result.launched) terminateContainedLaunch();
        finish(PassiveDumpPhase::Cancelled); return;
    }
    std::vector<uint8_t> reconstructionBytes;
    backfillDiscardablePages(result.capture, result.module.path, reconstructionBytes, result.warnings);
    validateCoverage(result.capture);
    if (!result.capture.completeForDiskRebuild)
        std::vector<uint8_t>().swap(reconstructionBytes);
    result.oep = AssessPassiveOep(result.capture, request.hasManualOep, request.manualOepVA);
    auto finalFp = FingerprintPassivePages(result.capture.bytes, result.capture.pageValid);
    result.finalSample = ComparePassiveSamples(havePrevious ? &previous : nullptr, finalFp, nowMs());
    if (result.sampleHistory.empty() ||
        result.sampleHistory.back().timestampMs != result.finalSample.timestampMs) {
        if (result.sampleHistory.size() == 512) result.sampleHistory.erase(result.sampleHistory.begin());
        result.sampleHistory.push_back(result.finalSample);
    }

    if (request.observeExactExportImports) {
        publish(PassiveDumpPhase::ResolvingImports,
                "Matching the captured IAT locally against final remote exports...");
        ExportMap finalExports = buildExportMap(finalExportSnapshots,
                                                result.importObservationTruncated,
                                                result.warnings);
        std::vector<RemoteExportSnapshot>().swap(finalExportSnapshots);
        result.observedImports = observeImports(result.capture, finalExports,
                                                result.importObservationTruncated, result.warnings);
        finalExports.clear(); // release the map before PeUnpack's transactional copies
    }

    if (request.rebuildPe) {
        publish(PassiveDumpPhase::Rebuilding, "Reconstructing a disk-layout PE...");
        if (!result.capture.completeForDiskRebuild) {
            result.rebuilt.repairs.failureArtifactOnly = true;
            result.rebuilt.issues.push_back({ PeUnpackSeverity::Error, "partial-passive-capture",
                "One or more required PE pages were unreadable; the exact raw capture remains in PassiveCapture without an image-sized duplicate." });
            result.rebuilt.report = "Passive PE reconstruction refused incomplete required-page coverage; use the retained PassiveCapture bytes as an analysis artifact.";
            result.error = "The mapped image has unreadable file-backed pages; a runnable PE was not emitted.";
        } else {
            PeUnpackOptions options;
            options.runtimeImageBase = result.module.base;
            const bool trustedManualOep =
                result.oep.trust == PassiveOepTrust::ManualOepValidated;
            // Never write an analyst-supplied address into the output unless
            // its exact captured page was executable and section-backed.
            options.hasOep = trustedManualOep;
            options.oepVA = request.manualOepVA;
            options.normalizeRelocations = request.normalizeRelocations;
            options.restoreIntactImports = true;
            options.rebuildObservedImports = request.observeExactExportImports;
            options.observedImports = result.observedImports;
            // PassiveCapture already retains the exact remote bytes and page
            // provenance, so PeUnpack must not duplicate another image-sized raw
            // failure vector inside the same result.
            options.retainRawMappedImage = false;
            const std::vector<uint8_t>& rebuildInput = reconstructionBytes.empty()
                ? result.capture.bytes : reconstructionBytes;
            result.rebuilt = RebuildMappedPe(rebuildInput, options);
            const bool usedDiskBackfill = std::find(result.capture.pageBackfilled.begin(),
                result.capture.pageBackfilled.end(), uint8_t{1}) != result.capture.pageBackfilled.end();
            result.artifactAssessment = AssessPassiveArtifact(
                result.rebuilt.success, result.oep.trust, usedDiskBackfill);
            if (result.rebuilt.success) {
                if (trustedManualOep) {
                    result.rebuilt.issues.push_back({ PeUnpackSeverity::Info, "manual-oep-validated",
                        usedDiskBackfill
                            ? "The analyst OEP is section-backed and its exact captured page was executable; disk-backfilled bytes still make the rebuilt PE analysis-only."
                            : "The analyst OEP is section-backed and its exact captured page was executable; with no disk-backfilled pages, the rebuilt PE may be treated as runnable." });
                    result.rebuilt.report += usedDiskBackfill
                        ? "info [manual-oep-validated]: OEP trust retained, but artifact runnability is independently downgraded by disk backfill.\n"
                        : "info [manual-oep-validated]: exact captured executable page and PE section containment validated; no disk backfill used.\n";
                } else {
                    const char* code = request.hasManualOep ? "manual-oep-rejected" : "oep-unverified";
                    const char* message = request.hasManualOep
                        ? "The supplied OEP was not backed by an exact captured executable page; it was not written and the unchanged header entry remains analysis-only."
                        : "The unchanged PE header entry point is not a validated unpacked OEP; this rebuilt PE is analysis-only.";
                    result.rebuilt.issues.push_back({ PeUnpackSeverity::Warning, code, message });
                    result.rebuilt.report += std::string("warning [") + code + "]: " + message + "\n";
                }
                if (usedDiskBackfill) {
                    constexpr const char* message =
                        "One or more discardable pages came from a best-effort current-path disk correlation rather than the remote capture; the rebuilt PE is analysis-only.";
                    result.rebuilt.issues.push_back({ PeUnpackSeverity::Warning,
                        "disk-backfill-best-effort", message });
                    result.rebuilt.report += std::string("warning [disk-backfill-best-effort]: ") +
                                             message + "\n";
                }
            }
            if (!result.rebuilt.success) result.error = "PE reconstruction failed; the raw mapped artifact was retained.";
        }
        result.success = result.rebuilt.success;
    } else {
        result.success = !result.capture.bytes.empty() && result.capture.readablePages != 0;
    }
    finish(result.success ? PassiveDumpPhase::Complete : PassiveDumpPhase::Failed);
#endif
}

} // namespace ds
