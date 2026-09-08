#include "BinaryDiffTab.h"
#include "../Ui/Fonts.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "../Core/DiffRegions.h"
#include "../Core/Project.h"
#include "../Core/SemanticDiffBinary.h"
#include "../Core/SemanticTransfer.h"
#include "../Disasm/DisassemblerFactory.h"
#include "../Disasm/JvmDisassembler.h"
#include "../Disasm/GmlDisassembler.h"
#include "imgui.h"

#include <algorithm>
#include <cctype>
#include <exception>
#include <limits>
#include <cstdio>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <windows.h>
#include <commdlg.h>

namespace ds {

static DocumentResultIdentity currentDiffTargetIdentity(const AppContext& ctx) {
    const BinaryFile& binary = ctx.staticBinary();
    return MakeDocumentResultIdentity(
        ctx.staticDocumentId(), ctx.staticImageGeneration(), binary.loaded(),
        binary.loaded() ? binary.contentHash() : 0,
        binary.loaded() ? binary.imageRevision() : 0);
}

BinaryDiffTab::BinaryDiffTab() {
    // Start only after every synchronization member has been constructed.
    worker_ = std::jthread([this](std::stop_token stop) { workerLoop(stop); });
}

BinaryDiffTab::~BinaryDiffTab() {
    desiredEpoch_.fetch_add(1, std::memory_order_acq_rel);
    {
        std::lock_guard lock(workerMutex_);
        pendingJob_.reset();
        readyResult_.reset();
    }
    worker_.request_stop();
    workerCv_.notify_all();
    if (worker_.joinable()) worker_.join();
}

static std::string baseName(const std::string& p) {
    size_t s = p.find_last_of("/\\");
    return s == std::string::npos ? p : p.substr(s + 1);
}

static const char* semanticBasisName(SemanticMatchBasis basis) {
    switch (basis) {
        case SemanticMatchBasis::AuthoritativeName: return "symbol";
        case SemanticMatchBasis::SemanticHash:      return "semantic hash";
        case SemanticMatchBasis::CfgStructure:      return "CFG structure";
        case SemanticMatchBasis::CallNeighborhood:  return "call neighborhood";
        default:                                     return "unknown";
    }
}

static const char* semanticEditName(InstructionEditKind kind) {
    switch (kind) {
        case InstructionEditKind::Insert:  return "insert";
        case InstructionEditKind::Delete:  return "delete";
        case InstructionEditKind::Replace: return "replace";
        default:                           return "edit";
    }
}

static const char* semanticTransferName(MetadataTransferKind kind) {
    switch (kind) {
        case MetadataTransferKind::Name:      return "name";
        case MetadataTransferKind::Comment:   return "comment";
        case MetadataTransferKind::Prototype: return "prototype";
        case MetadataTransferKind::Bookmark:  return "bookmark";
        default:                              return "metadata";
    }
}

static std::string semanticFunctionLabel(const SemanticFunction& function) {
    if (!function.name.empty()) return function.name;
    char address[32]{};
    std::snprintf(address, sizeof(address), "sub_%llX",
                  static_cast<unsigned long long>(function.address));
    return address;
}

static bool semanticFilterMatches(std::string_view value, std::string_view query) {
    return query.empty() || std::search(value.begin(), value.end(), query.begin(), query.end(),
        [](unsigned char left, unsigned char right) {
            return std::tolower(left) == std::tolower(right);
        }) != value.end();
}

static bool semanticAddressMatches(uint64_t value, std::string_view query) {
    char address[32]{};
    std::snprintf(address, sizeof(address), "0x%llX", static_cast<unsigned long long>(value));
    return semanticFilterMatches(address, query);
}

// Map a structured image's machine type to a decoder. Raw/Unknown has no
// authoritative ISA in Binary Diff because this surface has no explicit Raw
// architecture picker; flat/section byte comparison remains available.
static bool archOf(const BinaryFile& bf, Arch& out) {
    switch (bf.machine()) {
        case MachineArch::X86:     out = Arch::X86; return true;
        case MachineArch::X64:     out = Arch::X64; return true;
        case MachineArch::ARM:     out = Arch::ARM; return true;
        case MachineArch::THUMB:   out = Arch::THUMB; return true;
        case MachineArch::ARM64:   out = Arch::ARM64; return true;
        case MachineArch::MIPS:    out = Arch::MIPS; return true;
        case MachineArch::MIPS64:  out = Arch::MIPS64; return true;
        case MachineArch::PPC:     out = Arch::PPC; return true;
        case MachineArch::PPC64:   out = Arch::PPC64; return true;
        case MachineArch::RISCV:   out = Arch::RISCV32; return true;
        case MachineArch::RISCV64: out = Arch::RISCV64; return true;
        case MachineArch::JVM:     out = Arch::JVM; return true;
        case MachineArch::GML:     out = Arch::GML; return true;
        case MachineArch::Unknown: return false;
    }
    return false;
}

static DecoderConfig decoderFor(const BinaryFile& binary, Arch arch) {
    DecoderConfig config;
    config.engine = Engine::Zydis;
    config.arch = arch;
    return DecoderConfigForImage(binary, config);
}

// Locate the section of `bf` whose raw file data covers file offset `off`.
// Returns nullptr if the offset is outside every section's raw range.
static const Section* sectionAtOffset(const BinaryFile& bf, uint64_t off) {
    for (const auto& s : bf.sections())
        if (s.rawSize && off >= s.rawOffset && off - s.rawOffset < s.rawSize) return &s;
    return nullptr;
}

bool BinaryDiffTab::queryFileIdentity(const std::string& path, FileIdentity& out) {
    out = {};
    if (path.empty()) return false;

    const int chars = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           path.c_str(), -1, nullptr, 0);
    if (chars <= 0) return false;
    std::vector<wchar_t> wide(static_cast<size_t>(chars));
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.c_str(), -1,
                             wide.data(), chars)) return false;

    HANDLE file = CreateFileW(wide.data(), FILE_READ_ATTRIBUTES,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION info{};
    const BOOL ok = GetFileInformationByHandle(file, &info);
    CloseHandle(file);
    if (!ok) return false;

    out.size = (static_cast<uint64_t>(info.nFileSizeHigh) << 32) | info.nFileSizeLow;
    out.writeTime = (static_cast<uint64_t>(info.ftLastWriteTime.dwHighDateTime) << 32) |
                    info.ftLastWriteTime.dwLowDateTime;
    out.fileIndex = (static_cast<uint64_t>(info.nFileIndexHigh) << 32) | info.nFileIndexLow;
    out.volumeSerial = info.dwVolumeSerialNumber;
    out.valid = true;
    return true;
}

bool BinaryDiffTab::sameIdentity(const FileIdentity& a, const FileIdentity& b) {
    return a.valid && b.valid && a.size == b.size && a.writeTime == b.writeTime &&
           a.fileIndex == b.fileIndex && a.volumeSerial == b.volumeSerial;
}

const char* BinaryDiffTab::phaseName(DiffPhase phase) {
    switch (phase) {
        case DiffPhase::LoadingLeft:       return "Loading left file";
        case DiffPhase::LoadingRight:      return "Loading right file";
        case DiffPhase::ComparingBytes:    return "Comparing bytes";
        case DiffPhase::ComparingSections: return "Comparing sections";
        case DiffPhase::BuildingSemanticLeft:  return "Analyzing left functions";
        case DiffPhase::BuildingSemanticRight: return "Analyzing right functions";
        case DiffPhase::MatchingSemantics:     return "Matching semantic functions";
        case DiffPhase::Complete:          return "Complete";
        case DiffPhase::Cancelled:         return "Cancelled";
        case DiffPhase::Failed:            return "Failed";
        default:                           return "Idle";
    }
}

void BinaryDiffTab::openInto(bool leftSide) {
    std::vector<wchar_t> file(32768, L'\0');
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = ::GetActiveWindow();
    ofn.lpstrFilter = L"Binaries\0*.exe;*.dll;*.sys;*.bin;*.elf;*.so;*.dylib;*.class\0All Files\0*.*\0";
    ofn.lpstrFile   = file.data();
    ofn.nMaxFile    = static_cast<DWORD>(file.size());
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameW(&ofn)) {
        const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
            file.data(), -1, nullptr, 0, nullptr, nullptr);
        if (length <= 1) {
            diffError_ = "The selected file path could not be read as Unicode.";
            return;
        }
        std::string path(static_cast<size_t>(length), '\0');
        if (!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, file.data(), -1,
                                path.data(), length, nullptr, nullptr)) {
            diffError_ = "The selected file path could not be read as Unicode.";
            return;
        }
        path.pop_back();

        // Selection performs metadata-only identity capture. BinaryFile::load,
        // hashing, parsing, and semantic construction all belong to workerLoop.
        FileIdentity identity{};
        if (!queryFileIdentity(path, identity)) {
            diffError_ = "Could not inspect the selected file.";
            diffPhase_.store(DiffPhase::Failed, std::memory_order_release);
        } else {
            cancelDiff();
            invalidateComparison();
            if (leftSide) {
                selectedLeftPath_ = path;
                leftIdentity_ = identity;
            } else {
                selectedRightPath_ = path;
                rightIdentity_ = identity;
            }
            diffError_.clear();
            diffPhase_.store(DiffPhase::Idle, std::memory_order_release);
        }
        // Keep the owned image buffers until their replacement arrives by move,
        // but never present their differences under a newly selected file name.
    }
}

void BinaryDiffTab::computeDiff(const AppContext* ctx) {
    if (selectedLeftPath_.empty() || selectedRightPath_.empty()) return;
    invalidateComparison();

    FileIdentity leftNow{}, rightNow{};
    if (!queryFileIdentity(selectedLeftPath_, leftNow) ||
        !queryFileIdentity(selectedRightPath_, rightNow) ||
        !sameIdentity(leftNow, leftIdentity_) ||
        !sameIdentity(rightNow, rightIdentity_)) {
        cancelDiff();
        diffError_ = "A source file changed on disk. Reload it before computing a diff.";
        diffPhase_.store(DiffPhase::Failed, std::memory_order_release);
        return;
    }

    DiffJob job;
    job.epoch = desiredEpoch_.fetch_add(1, std::memory_order_acq_rel) + 1;
    job.leftPath = selectedLeftPath_;
    job.rightPath = selectedRightPath_;
    job.leftIdentity = leftIdentity_;
    job.rightIdentity = rightIdentity_;
    job.sectionAware = sectionAware_ && !semanticMode_;
    job.semantic = semanticMode_;
    if (ctx && job.semantic && ctx->staticProject().hash) {
        const ProjectState& project = ctx->staticProject();
        job.activeMetadata.hash = project.hash;
        job.activeMetadata.names.reserve(project.names.size());
        for (const auto& [address, name] : project.names)
            job.activeMetadata.names.emplace_back(address, name);
        job.activeMetadata.comments.reserve(project.comments.size());
        for (const auto& [address, comment] : project.comments)
            job.activeMetadata.comments.emplace_back(address, comment);
        for (const PjFunctionOverride& item : project.functionOverrides)
            if (item.action == PjFunctionAction::Define && !item.prototype.empty())
                job.activeMetadata.prototypes.emplace_back(item.address, item.prototype);
        job.activeMetadata.bookmarks.reserve(project.bookmarks.size());
        for (const PjBookmark& bookmark : project.bookmarks)
            job.activeMetadata.bookmarks.push_back(bookmark.address);
        auto byAddress = [](const auto& a, const auto& b) { return a.first < b.first; };
        std::sort(job.activeMetadata.names.begin(), job.activeMetadata.names.end(), byAddress);
        std::sort(job.activeMetadata.comments.begin(), job.activeMetadata.comments.end(), byAddress);
        std::sort(job.activeMetadata.prototypes.begin(), job.activeMetadata.prototypes.end(), byAddress);
        std::sort(job.activeMetadata.bookmarks.begin(), job.activeMetadata.bookmarks.end());
    }
    {
        std::lock_guard lock(workerMutex_);
        pendingJob_ = std::move(job); // latest request wins
        readyResult_.reset();
        diffProgress_.store(0, std::memory_order_release);
        diffProgressTotal_.store(0, std::memory_order_release);
        diffPhase_.store(DiffPhase::LoadingLeft, std::memory_order_release);
        diffRunning_.store(true, std::memory_order_release);
    }
    diffError_.clear();
    semanticWarning_.clear();
    semanticTransferStatus_.clear();
    semanticTransferTarget_ = {};
    workerCv_.notify_one();
}

void BinaryDiffTab::cancelDiff() {
    desiredEpoch_.fetch_add(1, std::memory_order_acq_rel);
    {
        std::lock_guard lock(workerMutex_);
        pendingJob_.reset();
        readyResult_.reset();
        diffRunning_.store(false, std::memory_order_release);
        diffPhase_.store(DiffPhase::Cancelled, std::memory_order_release);
        diffProgress_.store(0, std::memory_order_release);
        diffProgressTotal_.store(0, std::memory_order_release);
    }
}

void BinaryDiffTab::invalidateComparison() {
    computed_ = false;
    semanticComputed_ = false;
    curRegion_ = -1;
    applyScroll_ = false;
    scrollY_ = 0.0f;
    semanticProposalSelected_.clear();
    semanticProposalSelectionCount_ = 0;
    semanticTransferTarget_ = {};
    semanticTransferStatus_.clear();
    semanticFilterDirty_ = true;
}

void BinaryDiffTab::gotoRegion(int idx) {
    if (idx < 0 || idx >= (int)regions_.size()) return;
    curRegion_ = idx;
    // Back up a few rows so the change sits below the top edge with some context.
    float row = (float)(regions_[idx].start / 16) - 3.0f;
    if (row < 0) row = 0;
    scrollY_ = row * ImGui::GetTextLineHeightWithSpacing();
    applyScroll_ = true;   // force both panes to this position next render
}

// (Re)build a decoder for each side whenever that file's architecture changes.
void BinaryDiffTab::ensureDecoders() {
    if (left_.loaded() && (!leftDis_ || leftDisArch_ != left_.machine())) {
        leftDisArch_ = left_.machine();
        leftDisError_.clear();
        Arch arch = Arch::X64;
        if (!archOf(left_, arch)) {
            leftDis_.reset();
            leftDisError_ =
                "Raw/unknown image has no explicit decoder architecture; disassembly is not authoritative.";
        } else {
            leftDis_ = MakeDisassembler(decoderFor(left_, arch));
            if (!leftDis_) leftDisError_ = "decoder factory returned null";
            else if (!leftDis_->ready()) {
                leftDisError_ = leftDis_->errorMessage().empty()
                    ? "decoder initialization failed"
                    : std::string(leftDis_->errorMessage());
            }
        }
    }
    if (right_.loaded() && (!rightDis_ || rightDisArch_ != right_.machine())) {
        rightDisArch_ = right_.machine();
        rightDisError_.clear();
        Arch arch = Arch::X64;
        if (!archOf(right_, arch)) {
            rightDis_.reset();
            rightDisError_ =
                "Raw/unknown image has no explicit decoder architecture; disassembly is not authoritative.";
        } else {
            rightDis_ = MakeDisassembler(decoderFor(right_, arch));
            if (!rightDis_) rightDisError_ = "decoder factory returned null";
            else if (!rightDis_->ready()) {
                rightDisError_ = rightDis_->errorMessage().empty()
                    ? "decoder initialization failed"
                    : std::string(rightDis_->errorMessage());
            }
        }
    }
}

void BinaryDiffTab::workerLoop(std::stop_token stop) {
    for (;;) {
        DiffJob job;
        {
            std::unique_lock lock(workerMutex_);
            workerCv_.wait(lock, [&] { return stop.stop_requested() || pendingJob_.has_value(); });
            if (stop.stop_requested()) return;
            job = std::move(*pendingJob_);
            pendingJob_.reset();
        }

        auto stale = [&] {
            return stop.stop_requested() ||
                   desiredEpoch_.load(std::memory_order_acquire) != job.epoch;
        };
        auto setProgress = [&](DiffPhase phase, uint64_t current, uint64_t total) {
            std::lock_guard lock(workerMutex_);
            if (stale()) return;
            diffPhase_.store(phase, std::memory_order_release);
            diffProgress_.store(current, std::memory_order_release);
            diffProgressTotal_.store(total, std::memory_order_release);
        };
        auto publish = [&](DiffResult&& result) {
            if (stale()) return;
            const bool failed = !result.error.empty();
            {
                std::lock_guard lock(workerMutex_);
                if (stale()) return;
                readyResult_ = std::move(result);
                diffRunning_.store(false, std::memory_order_release);
                diffPhase_.store(failed ? DiffPhase::Failed : DiffPhase::Complete,
                                 std::memory_order_release);
            }
        };

        try {
            DiffResult result;
            result.epoch = job.epoch;
            result.leftIdentity = job.leftIdentity;
            result.rightIdentity = job.rightIdentity;

        FileIdentity before{}, after{};
        BinaryFile left, right;
        BinaryLoadOptions loadOptions;
        loadOptions.cancelled = stale;
        setProgress(DiffPhase::LoadingLeft, 0, 0);
        if (!queryFileIdentity(job.leftPath, before) ||
            !sameIdentity(before, job.leftIdentity) || !left.load(job.leftPath, loadOptions) ||
            !queryFileIdentity(job.leftPath, after) || !sameIdentity(before, after) ||
            left.bytes().size() != after.size) {
            result.error = "The left source changed or could not be reloaded.";
            publish(std::move(result));
            continue;
        }
        if (stale()) continue;

        setProgress(DiffPhase::LoadingRight, 0, 0);
        if (!queryFileIdentity(job.rightPath, before) ||
            !sameIdentity(before, job.rightIdentity) || !right.load(job.rightPath, loadOptions) ||
            !queryFileIdentity(job.rightPath, after) || !sameIdentity(before, after) ||
            right.bytes().size() != after.size) {
            result.error = "The right source changed or could not be reloaded.";
            publish(std::move(result));
            continue;
        }
        if (stale()) continue;

        const auto& a = left.bytes();
        const auto& b = right.bytes();
        if (!job.semantic) {
        ByteDiffScanResult flat;
        setProgress(DiffPhase::ComparingBytes, 0, std::min(a.size(), b.size()));
        const bool complete = ScanByteDifferences(
            a.data(), a.size(), b.data(), b.size(), 16, 5000, 50000, flat,
            stale,
            [&](uint64_t current, uint64_t total) {
                setProgress(DiffPhase::ComparingBytes, current, total);
            });
        if (!complete || stale()) continue;

        result.totalDiff = flat.totalDiff;
        result.diffs.reserve(flat.samples.size());
        for (const auto& d : flat.samples) result.diffs.push_back({ d.offset, d.a, d.b });
        result.regions.reserve(flat.regions.size());
        for (const auto& r : flat.regions) result.regions.push_back({ r.start, r.end });

        if (job.sectionAware) {
            const auto& rsecs = right.sections();
            uint64_t sectionWork = 0;
            for (const auto& ls : left.sections()) {
                const Section* match = nullptr;
                for (const auto& rs : rsecs)
                    if (!rs.name.empty() && rs.name == ls.name) { match = &rs; break; }
                if (!match) for (const auto& rs : rsecs)
                    if (rs.virtualAddress == ls.virtualAddress) { match = &rs; break; }
                if (!match) continue;
                const uint64_t lAvail = ls.rawOffset < a.size() ? a.size() - ls.rawOffset : 0;
                const uint64_t rAvail = match->rawOffset < b.size() ? b.size() - match->rawOffset : 0;
                const uint64_t len = std::min({ ls.rawSize, match->rawSize, lAvail, rAvail });
                sectionWork = len > UINT64_MAX - sectionWork ? UINT64_MAX : sectionWork + len;
            }

            uint64_t progressed = 0;
            setProgress(DiffPhase::ComparingSections, 0, sectionWork);
            for (const auto& ls : left.sections()) {
                if (stale()) break;
                SecDiff sd;
                sd.name = ls.name;
                sd.rva = ls.virtualAddress;
                sd.lOff = ls.rawOffset;

                const Section* match = nullptr;
                for (const auto& rs : rsecs)
                    if (!rs.name.empty() && rs.name == ls.name) { match = &rs; break; }
                if (!match) for (const auto& rs : rsecs)
                    if (rs.virtualAddress == ls.virtualAddress) { match = &rs; break; }
                if (!match) {
                    ++result.sectionUnmatched;
                    result.sections.push_back(std::move(sd));
                    continue;
                }

                sd.matched = true;
                sd.rOff = match->rawOffset;
                const uint64_t lAvail = ls.rawOffset < a.size() ? a.size() - ls.rawOffset : 0;
                const uint64_t rAvail = match->rawOffset < b.size() ? b.size() - match->rawOffset : 0;
                const uint64_t len64 = std::min({ ls.rawSize, match->rawSize, lAvail, rAvail });
                sd.len = static_cast<size_t>(len64);
                for (size_t i = 0; i < sd.len; ++i) {
                    if ((i % (64u * 1024u)) == 0) {
                        if (stale()) break;
                        setProgress(DiffPhase::ComparingSections, progressed + i, sectionWork);
                    }
                    if (a[static_cast<size_t>(ls.rawOffset) + i] !=
                        b[static_cast<size_t>(match->rawOffset) + i]) ++sd.diffBytes;
                }
                if (stale()) break;
                progressed = len64 > UINT64_MAX - progressed ? UINT64_MAX : progressed + len64;
                const uint64_t lraw = std::min(ls.rawSize, lAvail);
                const uint64_t rraw = std::min(match->rawSize, rAvail);
                const uint64_t extra = lraw > rraw ? lraw - rraw : rraw - lraw;
                if (extra > std::numeric_limits<size_t>::max() - sd.diffBytes)
                    sd.diffBytes = std::numeric_limits<size_t>::max();
                else
                    sd.diffBytes += static_cast<size_t>(extra);
                result.sectionTotalDiff = sd.diffBytes > UINT64_MAX - result.sectionTotalDiff
                    ? UINT64_MAX : result.sectionTotalDiff + sd.diffBytes;
                result.sections.push_back(std::move(sd));
            }
            if (stale()) continue;

            // Account for right-only sections using the same name/RVA matching
            // policy as the historical render-thread implementation.
            for (const auto& rs : rsecs) {
                bool inLeft = false;
                for (const auto& ls : left.sections()) {
                    if ((!rs.name.empty() && rs.name == ls.name) ||
                        rs.virtualAddress == ls.virtualAddress) { inLeft = true; break; }
                }
                if (!inLeft) ++result.sectionUnmatched;
            }
        }
        }

        if (job.semantic) {
            result.semanticRequested = true;
            Arch leftArch = Arch::X64, rightArch = Arch::X64;
            const bool leftArchValid = archOf(left, leftArch);
            const bool rightArchValid = archOf(right, rightArch);
            if (!leftArchValid || !rightArchValid) {
                result.semanticError =
                    "Semantic comparison is unavailable for Raw/unknown inputs because Binary Diff has no explicit per-side decoder selection. Flat byte comparison remains available.";
            } else if (leftArch != rightArch) {
                result.semanticError = std::string("Semantic comparison requires matching architectures (left: ") +
                    ArchName(leftArch) + ", right: " + ArchName(rightArch) + ").";
            } else {
                auto makeFactory = [](const BinaryFile& image) {
                    return [javaClass = image.javaClass(), archive = image.gameMakerArchive()](const DecoderConfig& config) {
                        auto decoder = MakeDisassembler(config);
                        if (decoder) AttachJvmClass(*decoder, javaClass);
                        if (decoder && archive) AttachGameMakerArchive(*decoder, archive);
                        return decoder;
                    };
                };
                SemanticDiffLimits semanticLimits;
                setProgress(DiffPhase::BuildingSemanticLeft, 0, a.size());
                SemanticImageBuildResult leftSemantic = BuildSemanticImage(
                    left, decoderFor(left, leftArch), makeFactory(left),
                    semanticLimits, stale);
                if (stale() || leftSemantic.cancelled) continue;
                setProgress(DiffPhase::BuildingSemanticLeft, a.size(), a.size());
                if (!leftSemantic.complete) {
                    result.semanticError = leftSemantic.error.empty()
                        ? "Left semantic analysis did not complete." : std::move(leftSemantic.error);
                } else {
                    setProgress(DiffPhase::BuildingSemanticRight, 0, b.size());
                SemanticImageBuildResult rightSemantic = BuildSemanticImage(
                    right, decoderFor(right, rightArch), makeFactory(right),
                    semanticLimits, stale);
                    if (stale() || rightSemantic.cancelled) continue;
                    setProgress(DiffPhase::BuildingSemanticRight, b.size(), b.size());
                    if (!rightSemantic.complete) {
                        result.semanticError = rightSemantic.error.empty()
                            ? "Right semantic analysis did not complete." : std::move(rightSemantic.error);
                    } else {
                        // Merge persisted analyst metadata only on the worker.
                        // The active in-memory snapshot wins for its exact hash;
                        // other sides use their atomically loaded project sidecar.
                        auto metadataFor = [&](uint64_t hash, const char* side) {
                            DiffJob::MetadataSnapshot snapshot;
                            if (job.activeMetadata.hash && job.activeMetadata.hash == hash) {
                                snapshot = job.activeMetadata;
                                return snapshot;
                            }
                            ProjectState project;
                            const ProjectLoadResult load = LoadProjectDetailed(hash, project);
                            if (load.recoveredFromBackup() ||
                                (!load.loaded &&
                                 (ProjectLoadAttemptRequiresWarning(load.primary) ||
                                  ProjectLoadAttemptRequiresWarning(load.backup)))) {
                                if (!result.semanticWarning.empty()) result.semanticWarning += "\n";
                                result.semanticWarning += side;
                                result.semanticWarning += " metadata: ";
                                result.semanticWarning += load.error.empty()
                                    ? (load.recoveredFromBackup()
                                        ? "recovered project analysis from the backup sidecar"
                                        : "the invalid project sidecar was not applied")
                                    : load.error;
                                result.semanticWarning += ".";
                            }
                            if (!load.loaded || project.hash != hash) return snapshot;
                            snapshot.hash = hash;
                            snapshot.names.reserve(project.names.size());
                            snapshot.comments.reserve(project.comments.size());
                            snapshot.bookmarks.reserve(project.bookmarks.size());
                            for (const auto& [address, name] : project.names)
                                snapshot.names.emplace_back(address, name);
                            for (const auto& [address, comment] : project.comments)
                                snapshot.comments.emplace_back(address, comment);
                            for (const PjFunctionOverride& item : project.functionOverrides)
                                if (item.action == PjFunctionAction::Define && !item.prototype.empty())
                                    snapshot.prototypes.emplace_back(item.address, item.prototype);
                            for (const PjBookmark& bookmark : project.bookmarks)
                                snapshot.bookmarks.push_back(bookmark.address);
                            return snapshot;
                        };
                        auto applyMetadata = [](SemanticImage& image,
                                                const DiffJob::MetadataSnapshot& snapshot) {
                            if (!snapshot.hash || snapshot.hash != image.contentIdentity) return;
                            std::unordered_map<uint64_t, std::string> names(
                                snapshot.names.begin(), snapshot.names.end());
                            std::unordered_map<uint64_t, std::string> comments(
                                snapshot.comments.begin(), snapshot.comments.end());
                            std::unordered_map<uint64_t, std::string> prototypes(
                                snapshot.prototypes.begin(), snapshot.prototypes.end());
                            std::unordered_set<uint64_t> bookmarks(snapshot.bookmarks.begin(),
                                                                   snapshot.bookmarks.end());
                            for (SemanticFunction& function : image.functions) {
                                if (auto name = names.find(function.address); name != names.end()) {
                                    function.name = name->second;
                                    function.authoritativeName = true;
                                    function.nameTransferable = true;
                                }
                                if (auto prototype = prototypes.find(function.address);
                                    prototype != prototypes.end())
                                    function.prototype = prototype->second;
                                for (uint32_t instructionIndex = 0;
                                     instructionIndex < function.instructions.size();
                                     ++instructionIndex) {
                                    const uint64_t address = function.instructions[instructionIndex].address;
                                    if (auto comment = comments.find(address); comment != comments.end())
                                        function.comments.push_back({instructionIndex, comment->second});
                                    if (bookmarks.count(address))
                                        function.bookmarkInstructions.push_back(instructionIndex);
                                }
                            }
                        };
                        applyMetadata(leftSemantic.image,
                                      metadataFor(leftSemantic.image.contentIdentity, "Left"));
                        applyMetadata(rightSemantic.image,
                                      metadataFor(rightSemantic.image.contentIdentity, "Right"));

                        setProgress(DiffPhase::MatchingSemantics, 0,
                                    leftSemantic.image.functions.size() +
                                    rightSemantic.image.functions.size());
                        SemanticDiffResult semantic = ComputeSemanticDiff(
                            leftSemantic.image, rightSemantic.image, semanticLimits, stale,
                            [&](const SemanticDiffProgress& progress) {
                                setProgress(DiffPhase::MatchingSemantics,
                                            progress.completed, progress.total);
                            });
                        if (stale() || semantic.cancelled) continue;
                        if (!semantic.complete) {
                            result.semanticError = semantic.error.empty()
                                ? "Semantic matching did not complete." : semantic.error;
                        }
                        result.semanticLeft = std::move(leftSemantic.image);
                        result.semanticRight = std::move(rightSemantic.image);
                        result.semanticDiff = std::move(semantic);
                    }
                }
            }
        }

        // Detect an atomic replacement or edit that occurred after the reload.
        FileIdentity leftFinal{}, rightFinal{};
        if (!queryFileIdentity(job.leftPath, leftFinal) ||
            !queryFileIdentity(job.rightPath, rightFinal) ||
            !sameIdentity(leftFinal, job.leftIdentity) ||
            !sameIdentity(rightFinal, job.rightIdentity)) {
            result.error = "A source file changed while the diff was running.";
        }
        if (result.error.empty()) {
            result.leftBinary = std::move(left);
            result.rightBinary = std::move(right);
        }
            publish(std::move(result));
        } catch (const std::exception& exception) {
            DiffResult failure;
            failure.epoch = job.epoch;
            failure.leftIdentity = job.leftIdentity;
            failure.rightIdentity = job.rightIdentity;
            failure.error = std::string("Binary Diff worker failed: ") + exception.what();
            publish(std::move(failure));
        } catch (...) {
            DiffResult failure;
            failure.epoch = job.epoch;
            failure.leftIdentity = job.leftIdentity;
            failure.rightIdentity = job.rightIdentity;
            failure.error = "Binary Diff worker failed: unknown exception.";
            publish(std::move(failure));
        }
    }
}

void BinaryDiffTab::pumpDiffResult() {
    std::optional<DiffResult> ready;
    {
        std::lock_guard lock(workerMutex_);
        if (readyResult_) {
            ready = std::move(readyResult_);
            readyResult_.reset();
        }
    }
    if (!ready || ready->epoch != desiredEpoch_.load(std::memory_order_acquire)) return;

    FileIdentity leftNow{}, rightNow{};
    if (!ready->error.empty() ||
        !queryFileIdentity(selectedLeftPath_, leftNow) ||
        !queryFileIdentity(selectedRightPath_, rightNow) ||
        !sameIdentity(leftNow, ready->leftIdentity) ||
        !sameIdentity(rightNow, ready->rightIdentity) ||
        !sameIdentity(leftIdentity_, ready->leftIdentity) ||
        !sameIdentity(rightIdentity_, ready->rightIdentity)) {
        diffError_ = ready->error.empty()
            ? "A source file changed before the diff result could be applied. Reload it."
            : std::move(ready->error);
        diffPhase_.store(DiffPhase::Failed, std::memory_order_release);
        return;
    }

    left_ = std::move(ready->leftBinary);
    right_ = std::move(ready->rightBinary);
    leftDis_.reset();
    rightDis_.reset();
    leftDisError_.clear();
    rightDisError_.clear();
    leftDisArch_ = MachineArch::Unknown;
    rightDisArch_ = MachineArch::Unknown;
    diffs_ = std::move(ready->diffs);
    regions_ = std::move(ready->regions);
    secDiffs_ = std::move(ready->sections);
    totalDiff_ = static_cast<size_t>(std::min<uint64_t>(
        ready->totalDiff, std::numeric_limits<size_t>::max()));
    secTotalDiff_ = static_cast<size_t>(std::min<uint64_t>(
        ready->sectionTotalDiff, std::numeric_limits<size_t>::max()));
    secUnmatched_ = ready->sectionUnmatched;
    semanticLeft_ = std::move(ready->semanticLeft);
    semanticRight_ = std::move(ready->semanticRight);
    semanticDiff_ = std::move(ready->semanticDiff);
    semanticComputed_ = ready->semanticRequested;
    semanticError_ = std::move(ready->semanticError);
    semanticWarning_ = std::move(ready->semanticWarning);
    semanticSelectedMatch_ = semanticDiff_.matched.empty() ? -1 : 0;
    semanticFilterDirty_ = true;
    semanticSelectedHunk_ = -1;
    semanticProposalSelected_.assign(semanticDiff_.transferProposals.size(), false);
    semanticProposalSelectionCount_ = 0;
    semanticTransferTarget_ = {};
    semanticTransferStatus_.clear();
    curRegion_ = -1;
    applyScroll_ = false;
    computed_ = true;
    diffError_.clear();
    diffPhase_.store(DiffPhase::Complete, std::memory_order_release);
}

void BinaryDiffTab::render(AppContext& ctx) {
    pumpDiffResult();

    // Keep source setup in the same full-width work area as the computed diff.
    if (!computed_) {
        renderLoadZone(ctx);
        return;
    }

    // Source names stay within equal columns; long paths remain available in
    // tooltips instead of pushing the comparison controls off the window.
    const float scale = theme::UiScale();
    ui::PanelHeader("Binary Diff", semanticMode_ ? "Semantic function comparison" : "Byte comparison");
    if (ImGui::BeginTable("##diff_toolbar_sources", 2,
                          ImGuiTableFlags_SizingStretchSame | ImGuiTableFlags_NoSavedSettings |
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableNextRow();
        auto source = [&](int column, const char* button, bool left,
                          const std::string& path) {
            ImGui::TableSetColumnIndex(column);
            if (ImGui::Button(button)) openInto(left);
            ImGui::SameLine();
            ImGui::TextDisabled("%s", baseName(path).c_str());
            if (ImGui::IsItemHovered())
                ImGui::SetTooltip("%s\n%llu bytes", path.c_str(),
                    static_cast<unsigned long long>(left ? leftIdentity_.size : rightIdentity_.size));
        };
        source(0, "Baseline...", true, selectedLeftPath_);
        source(1, "Candidate...", false, selectedRightPath_);
        ImGui::EndTable();
    }
    if (!computed_) return;
    const bool running = diffRunning_.load(std::memory_order_acquire);
    if (running) {
        ctx.wantContinuousRedraw = true;
        if (ImGui::Button("Cancel")) cancelDiff();
    } else {
        ImGui::BeginDisabled(selectedLeftPath_.empty() || selectedRightPath_.empty());
        if (ui::AccentButton("Recompute", theme::col::accent())) computeDiff(&ctx);
        ImGui::EndDisabled();
    }
    ui::SameLineIfFits(ImGui::CalcTextSize("Section-aware").x + ImGui::GetFrameHeight() + 12.0f * scale);
    // Section-aware alignment toggle: recompute immediately so the summary +
    // (when on) the per-section breakdown reflect the chosen mode.
    ImGui::BeginDisabled(semanticMode_);
    if (ImGui::Checkbox("Section-aware", &sectionAware_)) computeDiff(&ctx);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Align matching sections (by name, else RVA) before diffing,\n"
                          "instead of comparing by flat file offset.");
    ImGui::EndDisabled();
    ui::SameLineIfFits(ImGui::CalcTextSize("Semantic").x + ImGui::GetFrameHeight() + 12.0f * scale);
    if (ImGui::Checkbox("Semantic", &semanticMode_)) computeDiff(&ctx);
    if (ImGui::IsItemHovered())
        ImGui::SetTooltip("Match functions by symbols, normalized instruction semantics, CFG shape, and calls.\n"
                          "Analysis runs on the Binary Diff worker; metadata is never transferred automatically.");
    // A mode change enqueues a fresh worker result. Hide the old totals and
    // metadata proposals immediately, including the frame that enqueued it.
    if (!computed_) {
        ctx.wantContinuousRedraw = diffRunning_.load(std::memory_order_acquire);
        return;
    }
    ui::SameLineIfFits(100.0f * scale);
    ui::StatePill(running ? "RUNNING" : "COMPLETE",
                  running ? theme::col::accent() : theme::col::good());
    ImGui::Separator();

    if (running) {
        const uint64_t current = diffProgress_.load(std::memory_order_acquire);
        const uint64_t total = diffProgressTotal_.load(std::memory_order_acquire);
        ImGui::TextDisabled("%s", phaseName(diffPhase_.load(std::memory_order_acquire)));
        ui::SameLineIfFits(220.0f * scale);
        if (total) {
            const float fraction = static_cast<float>(std::min(current, total)) /
                                   static_cast<float>(total);
            ImGui::ProgressBar(fraction, ImVec2(std::min(220.0f * scale, ImGui::GetContentRegionAvail().x), 0));
        } else {
            const float t = static_cast<float>(ImGui::GetTime());
            ImGui::ProgressBar(t - static_cast<float>(static_cast<long long>(t)),
                               ImVec2(std::min(220.0f * scale, ImGui::GetContentRegionAvail().x), 0), "");
        }
        ImGui::Separator();
    } else if (!diffError_.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::col::bad());
        ImGui::TextWrapped("%s", diffError_.c_str());
        ImGui::PopStyleColor();
        ImGui::Separator();
    }

    if (semanticMode_) {
        renderSemantic(ctx);
        return;
    }

    // Section-aware breakdown: a compact per-section diff table above the synced
    // hex panes (the hex panes still show the flat byte view for navigation).
    if (sectionAware_) {
        size_t matchedCount = 0;
        for (const auto& sd : secDiffs_) if (sd.matched) ++matchedCount;
        ImGui::Text("Section-aware: %zu differing byte(s) across %zu matched section(s)",
                    secTotalDiff_, matchedCount);
        if (secUnmatched_) {
            ui::SameLineIfFits(340.0f * scale);
            ImGui::TextColored(theme::col::warn(), "  %zu section(s) present on only one side", secUnmatched_);
        }
        float tableH = std::max(1.0f, std::min(ImGui::GetContentRegionAvail().y * 0.35f, 160.0f * scale));
        if (ui::BeginDataTable("secdiff", 5,
                ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_ScrollY,
                ImVec2(0, tableH))) {
            ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 120.0f * theme::UiScale());
            ImGui::TableSetupColumn("RVA",     ImGuiTableColumnFlags_WidthFixed, 110.0f * theme::UiScale());
            ImGui::TableSetupColumn("Compared",ImGuiTableColumnFlags_WidthFixed, 90.0f * theme::UiScale());
            ImGui::TableSetupColumn("Diff",    ImGuiTableColumnFlags_WidthFixed, 90.0f * theme::UiScale());
            ImGui::TableSetupColumn("Status");
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();
            for (const auto& sd : secDiffs_) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(sd.name.c_str());
                ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", (unsigned long long)sd.rva);
                ImGui::TableSetColumnIndex(2); ImGui::Text("%zu B", sd.len);
                ImGui::TableSetColumnIndex(3);
                if (!sd.matched)         ImGui::TextDisabled("-");
                else if (sd.diffBytes)   ImGui::TextColored(theme::col::bad(),  "%zu", sd.diffBytes);
                else                     ImGui::TextColored(theme::col::good(), "0");
                ImGui::TableSetColumnIndex(4);
                if (!sd.matched)         ImGui::TextColored(theme::col::warn(), "no match (left only)");
                else if (sd.diffBytes)   ImGui::TextUnformatted("changed");
                else                     ImGui::TextDisabled("identical");
            }
            ui::EndDataTable();
        }
        ImGui::Separator();
    }

    const size_t maxN = std::max(left_.bytes().size(), right_.bytes().size());
    const uint64_t rowCount = (static_cast<uint64_t>(maxN) + 15) / 16;
    const int rows = static_cast<int>(std::min<uint64_t>(
        rowCount, static_cast<uint64_t>(std::numeric_limits<int>::max())));

    ImGui::Text("Differing bytes: %zu", totalDiff_);
    ui::ItemTooltip("Includes changed bytes in the shared range and bytes present on only one side.");
    ui::SameLineIfFits(ImGui::CalcTextSize("Changed bytes   Selected change").x);
    ImGui::BeginGroup();
    ImGui::TextColored(theme::col::bad(), "Changed bytes");
    ImGui::SameLine();
    ImGui::TextColored(theme::col::warn(), "Selected change");
    ImGui::EndGroup();

    // Difference navigation: jump between coalesced change regions; F3 / Shift+F3
    // step forward / back while the tab is focused. Selecting a region scrolls both
    // panes to it and drives the side-by-side ASM panel below.
    const int nReg = (int)regions_.size();
    bool focused = ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) &&
        !ImGui::GetIO().WantTextInput && !ImGui::IsPopupOpen(nullptr,
            ImGuiPopupFlags_AnyPopupId | ImGuiPopupFlags_AnyPopupLevel);
    ImGui::BeginDisabled(nReg == 0);
    bool prev = ImGui::Button("Prev") ||
                (focused && ImGui::IsKeyPressed(ImGuiKey_F3) && ImGui::GetIO().KeyShift);
    ImGui::SameLine();
    bool next = ImGui::Button("Next") ||
                (focused && ImGui::IsKeyPressed(ImGuiKey_F3) && !ImGui::GetIO().KeyShift);
    ImGui::EndDisabled();
    ui::SameLineIfFits(300.0f * scale);
    if (nReg && curRegion_ < 0) ImGui::TextDisabled("%d changes; select Prev or Next (F3)", nReg);
    else if (nReg) ImGui::Text("Change %d / %d  @ 0x%llX", curRegion_ + 1, nReg,
                          (unsigned long long)(curRegion_ >= 0 ? regions_[curRegion_].start : regions_[0].start));
    else      ui::StatePill("IDENTICAL", theme::col::good());
    if (next && nReg) gotoRegion(curRegion_ + 1 >= nReg ? 0 : curRegion_ + 1);
    if (prev && nReg) gotoRegion(curRegion_ <= 0 ? nReg - 1 : curRegion_ - 1);

    // Two equal, bordered containers side by side (symmetric = visually centered).
    ImVec2 avail = ImGui::GetContentRegionAvail();
    const float asmH = curRegion_ >= 0
        ? std::max(0.0f, std::min(200.0f * scale, avail.y * 0.45f)) : 0.0f;
    const float gap   = 12.0f * scale;
    const bool stacked = avail.x < 920.0f * scale;
    const float paneW = stacked ? std::max(1.0f, avail.x)
                               : std::max(1.0f, (avail.x - gap) * 0.5f);
    const float hexHeight = avail.y - (asmH > 0 ? asmH + ImGui::GetStyle().ItemSpacing.y : 0);
    const float paneH = std::max(1.0f, stacked
        ? (hexHeight - ImGui::GetStyle().ItemSpacing.y) * 0.5f : hexHeight);

    const bool force = applyScroll_;
    float ls = scrollY_, rs = scrollY_;
    bool  lhov = false, rhov = false;

    // LEFT container.
    ImGui::BeginChild("Lcont", ImVec2(paneW, paneH), ImGuiChildFlags_Borders);
    ui::PanelHeader("Baseline", baseName(left_.path()).c_str());
    ui::ItemTooltip(left_.path().c_str());
    renderPane("Lhex", left_, right_, rows, leftMaster_, ls, lhov, force);
    ImGui::EndChild();

    if (!stacked) ImGui::SameLine(0, gap);

    // RIGHT container.
    ImGui::BeginChild("Rcont", ImVec2(paneW, paneH), ImGuiChildFlags_Borders);
    ui::PanelHeader("Candidate", baseName(right_.path()).c_str());
    ui::ItemTooltip(right_.path().c_str());
    renderPane("Rhex", right_, left_, rows, !leftMaster_, rs, rhov, force);
    ImGui::EndChild();

    if (force) {
        applyScroll_ = false;   // scrollY_ stays at the forced target
    } else {
        // The hovered pane drives the shared scroll; the other follows next frame.
        scrollY_ = leftMaster_ ? ls : rs;
        if (lhov)      leftMaster_ = true;
        else if (rhov) leftMaster_ = false;
    }

    // Side-by-side disassembly of the selected change.
    if (curRegion_ >= 0) renderDiffAsm();
}

// Disassemble the bytes around the selected region in both binaries and show them
// side by side, highlighting the instructions that overlap the changed bytes. A
// region that falls in a non-executable section is shown as raw bytes instead.
void BinaryDiffTab::renderDiffAsm() {
    if (curRegion_ < 0 || curRegion_ >= (int)regions_.size()) return;
    ensureDecoders();
    const DiffRegion reg = regions_[curRegion_];

    ImGui::BeginChild("DiffAsm", ImVec2(0, 0), ImGuiChildFlags_Borders);
    char changeRange[80]{};
    std::snprintf(changeRange, sizeof(changeRange), "File offsets 0x%llX - 0x%llX",
                  (unsigned long long)reg.start, (unsigned long long)reg.end);
    ui::PanelHeader("Disassembly at change", changeRange);

    const float gap   = 12.0f * theme::UiScale();
    const float colW  = std::max(1.0f, (ImGui::GetContentRegionAvail().x - gap) * 0.5f);

    auto renderSide = [&](const char* id, const char* label, const BinaryFile& bf,
                          IDisassembler* dis, const std::string& decoderError) {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::col::code());
        ImGui::BeginChild(id, ImVec2(colW, 0), ImGuiChildFlags_Borders,
                          ImGuiWindowFlags_HorizontalScrollbar);
        ImGui::PopStyleColor();
        ImGui::TextColored(theme::col::accent(), "%s", label);
        Arch displayArch = Arch::X64;
        ImGui::SameLine();
        if (archOf(bf, displayArch)) ImGui::TextDisabled("(%s)", ArchName(displayArch));
        else ImGui::TextDisabled("(Raw ISA unspecified)");
        ImGui::Separator();
        ui::PushMono();
        const auto& bytes = bf.bytes();
        const Section* sec = sectionAtOffset(bf, reg.start);
        if (reg.start >= bytes.size()) {
            ImGui::TextDisabled("(offset past end of this file)");
        } else if (sec && sec->executable && !decoderError.empty()) {
            ImGui::TextColored(theme::col::bad(), "Decoder unavailable: %s",
                               decoderError.c_str());
        } else if (!sec || !sec->executable || !dis) {
            // Data (or unknown) region: show the raw changed bytes instead of code.
            ImGui::TextDisabled("data");
            std::string hx;
            const uint64_t dataEnd = std::min<uint64_t>(reg.end, bytes.size());
            const uint64_t shownEnd = reg.start + std::min<uint64_t>(256, dataEnd - reg.start);
            for (uint64_t o = reg.start; o < shownEnd; ++o) {
                char t[4]; std::snprintf(t, sizeof(t), "%02X ", bytes[(size_t)o]); hx += t;
            }
            ImGui::TextWrapped("%s", hx.c_str());
            if (shownEnd < dataEnd)
                ImGui::TextDisabled("First 256 bytes shown; inspect the full region in the hex pane.");
        } else {
            // Start ~32 bytes before the change (clamped to the section start) so
            // the decode self-syncs onto an instruction boundary before the region.
            uint64_t secStart = sec->rawOffset;
            uint64_t winOff = (reg.start > secStart + 32) ? reg.start - 32 : secStart;
            uint64_t secEnd = std::min<uint64_t>(sec->rawOffset + sec->rawSize, bytes.size());
            uint64_t off = winOff;
            int guard = 0;
            while (off < secEnd && off < reg.end + 16 && guard++ < 256) {
                uint64_t va = 0; bf.offsetToVA(off, va);
                Instruction in;
                size_t avail = (size_t)(secEnd - off);
                bool ok = dis->decodeOne(bytes.data() + off, avail, va, in) && in.length;
                uint32_t len = ok ? in.length : 1;
                bool changed = (off < reg.end) && (off + len > reg.start);   // overlaps the change
                if (changed) {
                    ImVec2 p0 = ImGui::GetCursorScreenPos();
                    ImVec4 highlight = theme::col::warn();
                    highlight.w = 0.18f;
                    ImGui::GetWindowDrawList()->AddRectFilled(
                        p0, ImVec2(p0.x + ImGui::GetContentRegionAvail().x, p0.y + ImGui::GetTextLineHeight()),
                        ImGui::GetColorU32(highlight));
                }
                ImVec4 col = changed ? theme::col::warn() : theme::col::muted();
                if (ok) {
                    const std::string text = InstructionText(in);
                    ImGui::TextColored(col, "%08llX  %s",
                                       (unsigned long long)va, text.c_str());
                }
                else    ImGui::TextColored(col, "%08llX  db 0x%02X",
                                           (unsigned long long)va, bytes[(size_t)off]);
                off += len;
            }
        }
        ui::PopMono();
        ImGui::EndChild();
    };

    renderSide("AsmL", "Baseline",  left_,  leftDis_.get(), leftDisError_);
    ImGui::SameLine(0, gap);
    renderSide("AsmR", "Candidate", right_, rightDis_.get(), rightDisError_);

    ImGui::EndChild();
}

void BinaryDiffTab::renderLoadZone(AppContext& ctx) {
    const float scale = theme::UiScale();
    ImGui::BeginChild("DiffLoadBlock", ImVec2(0, 0), ImGuiChildFlags_None);
    ui::PanelHeader("Binary Diff", "Baseline and candidate");
    ImGui::PushStyleColor(ImGuiCol_Text, theme::col::muted());
    ImGui::TextWrapped("Choose the baseline and candidate images, then compute a byte or semantic diff.");
    ImGui::PopStyleColor();
    ImGui::Separator();

    if (ui::BeginDataTable("##diff_sources", 3,
            ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerH |
            ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("Side", ImGuiTableColumnFlags_WidthFixed,
                                90.0f * scale);
        ImGui::TableSetupColumn("Source image");
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed,
                                130.0f * scale);
        ImGui::TableHeadersRow();
        auto sourceRow = [&](const char* side, bool leftSide,
                             const std::string& path) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextUnformatted(side);
            ImGui::TableSetColumnIndex(1);
            if (path.empty()) ImGui::TextDisabled("No file selected");
            else {
                ImGui::TextUnformatted(baseName(path).c_str());
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", path.c_str());
                const FileIdentity& identity = leftSide ? leftIdentity_ : rightIdentity_;
                if (identity.valid)
                    ImGui::TextDisabled("%llu bytes", static_cast<unsigned long long>(identity.size));
            }
            ImGui::TableSetColumnIndex(2);
            if (ImGui::Button(leftSide ? "Choose baseline..." : "Choose candidate...",
                              ImVec2(-FLT_MIN, 0)))
                openInto(leftSide);
        };
        sourceRow("Baseline", true, selectedLeftPath_);
        sourceRow("Candidate", false, selectedRightPath_);
        ui::EndDataTable();
    }

    const bool ready = !selectedLeftPath_.empty() && !selectedRightPath_.empty();
    const bool running = diffRunning_.load(std::memory_order_acquire);
    ui::PanelHeader("Comparison", "Choose how to compare the selected images");
    if (running) {
        ctx.wantContinuousRedraw = true;
        if (ImGui::Button("Cancel comparison")) cancelDiff();
        ui::SameLineIfFits(100.0f * scale);
        ui::StatePill("RUNNING", theme::col::accent());
        ui::SameLineIfFits(200.0f * scale);
        const uint64_t current = diffProgress_.load(std::memory_order_acquire);
        const uint64_t total = diffProgressTotal_.load(std::memory_order_acquire);
        const float fraction = total
            ? static_cast<float>(std::min(current, total)) / static_cast<float>(total)
            : static_cast<float>(ImGui::GetTime()) -
              static_cast<float>(static_cast<long long>(ImGui::GetTime()));
        ImGui::ProgressBar(fraction, ImVec2(-FLT_MIN, 0),
                           total ? phaseName(diffPhase_.load(std::memory_order_acquire)) : "Working...");
    } else {
        if (ImGui::Checkbox("Semantic function comparison", &semanticMode_)) {
            semanticTransferStatus_.clear();
        }
        ui::SameLineIfFits(ImGui::CalcTextSize("Section-aware").x + ImGui::GetFrameHeight() + 12.0f * scale);
        ImGui::BeginDisabled(semanticMode_);
        ImGui::Checkbox("Section-aware", &sectionAware_);
        ImGui::EndDisabled();
        ui::ItemTooltip("Align matching sections before byte comparison. Semantic mode compares functions.");
        ui::SameLineIfFits(ImGui::CalcTextSize("Compute Diff").x + ImGui::GetStyle().FramePadding.x * 2.0f);
        ImGui::BeginDisabled(!ready);
        if (ui::AccentButton("Compute Diff", theme::col::accent())) computeDiff(&ctx);
        ImGui::EndDisabled();
        ui::SameLineIfFits(110.0f * scale);
        // Compute Diff may have queued the worker in this frame.
        const bool started = diffRunning_.load(std::memory_order_acquire);
        ui::StatePill(started ? "RUNNING" : "IDLE", started ? theme::col::accent() : theme::col::muted());
        if (!ready) {
            ImGui::PushStyleColor(ImGuiCol_Text, theme::col::muted());
            ImGui::TextWrapped("Select both source images above to enable comparison.");
            ImGui::PopStyleColor();
        }
        if (!diffError_.empty()) {
            ImGui::PushTextWrapPos();
            ImGui::TextColored(theme::col::bad(), "%s", diffError_.c_str());
            ImGui::PopTextWrapPos();
        } else if (diffPhase_.load(std::memory_order_acquire) == DiffPhase::Cancelled) {
            ImGui::TextDisabled("Comparison cancelled. Compute Diff to try again.");
        }
    }

    ImGui::EndChild();
}

void BinaryDiffTab::applySelectedSemanticTransfers(AppContext& ctx) {
    size_t requested = 0;
    for (bool selected : semanticProposalSelected_) if (selected) ++requested;
    if (!requested) {
        semanticTransferStatus_ = "Select one or more metadata proposals first.";
        return;
    }
    if (!ctx.staticBinary().loaded() || ctx.staticBinary().isMappedImage()) {
        semanticTransferStatus_ = "Metadata can only be transferred into an open static binary project.";
        return;
    }
    const DocumentResultIdentity activeIdentity =
        currentDiffTargetIdentity(ctx);
    if (!SameDocumentResultImage(semanticTransferTarget_, activeIdentity)) {
        semanticTransferStatus_ =
            "The selected transfer belongs to a different document or image revision.";
        return;
    }

    const uint64_t activeHash = ctx.staticBinary().contentHash();
    if (!activeHash || ctx.staticProject().hash != activeHash) {
        semanticTransferStatus_ = "The active project identity does not match its binary.";
        return;
    }

    size_t applied = 0, unchanged = 0, rejected = 0;
    const size_t count = (std::min)(semanticProposalSelected_.size(),
                                    semanticDiff_.transferProposals.size());
    for (size_t index = 0; index < count; ++index) {
        if (!semanticProposalSelected_[index]) continue;
        const MetadataTransferProposal& proposal = semanticDiff_.transferProposals[index];
        const std::optional<SemanticImage>& target =
            proposal.direction == MetadataTransferDirection::LeftToRight
                ? semanticRight_ : semanticLeft_;
        if (!target || target->contentIdentity != activeHash) {
            ++rejected;
            continue;
        }

        SemanticTransferApplyResult result = ApplySemanticTransferProposal(
            ctx.staticProject(), activeHash, *target, proposal,
            [&](uint64_t address) {
                uint64_t fileOffset = 0;
                return ctx.staticBinary().vaToOffset(address, fileOffset);
            });
        if (result.status == SemanticTransferStatus::Applied) {
            ++applied;
            semanticProposalSelected_[index] = false;
        } else if (result.status == SemanticTransferStatus::Unchanged) {
            ++unchanged;
            semanticProposalSelected_[index] = false;
        } else {
            ++rejected;
        }
    }

    if (applied) {
        // Binary View mirrors these channels in tab-local maps. Signal it before
        // marking the shared ProjectState dirty so a later tab switch cannot
        // overwrite this user-approved transfer with stale local annotations.
        ctx.projectAnnotationsExternallyChanged = true;
        ctx.markProjectDirty();
    }
    semanticProposalSelectionCount_ = static_cast<size_t>(std::count(
        semanticProposalSelected_.begin(), semanticProposalSelected_.end(), true));
    if (!semanticProposalSelectionCount_) semanticTransferTarget_ = {};
    semanticTransferStatus_ = std::to_string(applied) + " applied, " +
                              std::to_string(unchanged) + " already present, " +
                              std::to_string(rejected) + " rejected.";
}

void BinaryDiffTab::renderSemantic(AppContext& ctx) {
    if (diffRunning_.load(std::memory_order_acquire)) {
        ImGui::TextDisabled("The previous semantic result is hidden while the worker analyzes the selected files.");
        return;
    }
    if (!semanticError_.empty()) {
        ImGui::PushTextWrapPos();
        ImGui::TextColored(theme::col::bad(), "%s", semanticError_.c_str());
        ImGui::PopTextWrapPos();
        return;
    }
    if (!semanticWarning_.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::col::warn());
        ImGui::TextWrapped("Project metadata warning: %s", semanticWarning_.c_str());
        ImGui::PopStyleColor();
        ImGui::Separator();
    }
    if (!semanticComputed_ || !semanticLeft_ || !semanticRight_) {
        ImGui::TextDisabled("No semantic comparison has completed for these files.");
        return;
    }
    if (!semanticDiff_.complete) {
        ImGui::TextColored(theme::col::bad(), "%s",
                           semanticDiff_.error.empty() ? "Semantic comparison did not complete."
                                                       : semanticDiff_.error.c_str());
        return;
    }
    if (semanticProposalSelected_.size() != semanticDiff_.transferProposals.size()) {
        semanticProposalSelected_.assign(semanticDiff_.transferProposals.size(), false);
        semanticProposalSelectionCount_ = 0;
        semanticTransferTarget_ = {};
    }

    const DocumentResultIdentity activeTransferIdentity =
        currentDiffTargetIdentity(ctx);
    if (semanticProposalSelectionCount_ &&
        !SameDocumentResultImage(semanticTransferTarget_,
                                 activeTransferIdentity)) {
        std::fill(semanticProposalSelected_.begin(),
                  semanticProposalSelected_.end(), false);
        semanticProposalSelectionCount_ = 0;
        semanticTransferTarget_ = {};
        semanticTransferStatus_ =
            "Selection cleared because the active document or image changed.";
    }

    char semanticCounts[128]{};
    std::snprintf(semanticCounts, sizeof(semanticCounts), "Matched: %zu   Added: %zu   Removed: %zu",
                  semanticDiff_.matched.size(), semanticDiff_.added.size(), semanticDiff_.removed.size());
    ui::PanelHeader("Semantic results", semanticCounts);
    if (semanticDiff_.truncated) {
        ui::SameLineIfFits(ImGui::CalcTextSize("Partial result: analysis limits reached").x);
        ImGui::TextColored(theme::col::warn(), "Partial result: analysis limits reached");
    }

    ui::SearchBox("##semantic_filter", "Find a function, address, or match evidence...",
        semanticFilter_, sizeof(semanticFilter_), std::min(380.0f * theme::UiScale(),
        ImGui::GetContentRegionAvail().x));
    ui::SameLineIfFits(ImGui::CalcTextSize("Changed matches only").x + ImGui::GetFrameHeight() +
                      ImGui::GetStyle().ItemInnerSpacing.x);
    if (ImGui::Checkbox("Changed matches only", &semanticChangesOnly_)) semanticFilterDirty_ = true;
    ui::ItemTooltip("Hide matched functions without instruction edits. Added and removed functions remain searchable.");
    if (semanticFilterDirty_ || appliedSemanticFilter_ != semanticFilter_) {
        appliedSemanticFilter_ = semanticFilter_;
        const std::string_view query = appliedSemanticFilter_;
        semanticVisibleMatches_.clear();
        semanticVisibleAdded_.clear();
        semanticVisibleRemoved_.clear();
        for (size_t index = 0; index < semanticDiff_.matched.size(); ++index) {
            const auto& match = semanticDiff_.matched[index];
            if (match.leftIndex >= semanticLeft_->functions.size() ||
                match.rightIndex >= semanticRight_->functions.size() ||
                (semanticChangesOnly_ && match.hunks.empty())) continue;
            if (semanticFilterMatches(semanticLeft_->functions[match.leftIndex].name, query) ||
                semanticFilterMatches(semanticRight_->functions[match.rightIndex].name, query) ||
                semanticAddressMatches(match.leftAddress, query) ||
                semanticAddressMatches(match.rightAddress, query) ||
                semanticFilterMatches(match.evidence, query) ||
                semanticFilterMatches(semanticBasisName(match.basis), query))
                semanticVisibleMatches_.push_back(index);
        }
        const auto filterUnmatched = [&](const auto& functions, auto& visible) {
            for (size_t index = 0; index < functions.size(); ++index)
                if (semanticFilterMatches(functions[index].name, query) ||
                    semanticAddressMatches(functions[index].address, query)) visible.push_back(index);
        };
        filterUnmatched(semanticDiff_.added, semanticVisibleAdded_);
        filterUnmatched(semanticDiff_.removed, semanticVisibleRemoved_);
        if (std::find(semanticVisibleMatches_.begin(), semanticVisibleMatches_.end(),
                      static_cast<size_t>(semanticSelectedMatch_)) == semanticVisibleMatches_.end()) {
            semanticSelectedMatch_ = semanticVisibleMatches_.empty()
                ? -1 : static_cast<int>(semanticVisibleMatches_.front());
            semanticSelectedHunk_ = -1;
        }
        semanticFilterDirty_ = false;
    }

    const float listHeight = std::max(1.0f, std::min(210.0f * theme::UiScale(),
                                        ImGui::GetContentRegionAvail().y * 0.38f));
    bool showMatchedDetail = false;
    if (ImGui::BeginTabBar("SemanticLists")) {
        if (ui::BeginCountTabItem("Matched", semanticDiff_.matched.size())) {
            showMatchedDetail = true;
            ImGui::TextDisabled("%zu of %zu matched functions", semanticVisibleMatches_.size(), semanticDiff_.matched.size());
            if (semanticVisibleMatches_.empty())
                ImGui::TextWrapped(semanticDiff_.matched.empty() ? "No functions could be matched between these files."
                    : "No matches meet these filters. Clear the search or show unchanged matches.");
            else if (ui::BeginDataTable("SemanticMatched", 5,
                    ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_RowBg |
                    ImGuiTableFlags_ScrollY | ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable,
                    ImVec2(0, listHeight), std::max(720.0f * theme::UiScale(), ImGui::GetContentRegionAvail().x))) {
                ImGui::TableSetupColumn("Baseline", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Candidate", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Confidence", ImGuiTableColumnFlags_WidthFixed,
                                        90.0f * theme::UiScale());
                ImGui::TableSetupColumn("Evidence", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Edits", ImGuiTableColumnFlags_WidthFixed,
                                        52.0f * theme::UiScale());
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                ImGuiListClipper matchClipper;
                matchClipper.Begin(static_cast<int>(semanticVisibleMatches_.size()));
                while (matchClipper.Step()) for (int clippedIndex = matchClipper.DisplayStart;
                                                  clippedIndex < matchClipper.DisplayEnd;
                                                  ++clippedIndex) {
                    const size_t index = semanticVisibleMatches_[static_cast<size_t>(clippedIndex)];
                    const SemanticFunctionMatch& match = semanticDiff_.matched[index];
                    if (match.leftIndex >= semanticLeft_->functions.size() ||
                        match.rightIndex >= semanticRight_->functions.size()) continue;
                    const SemanticFunction& leftFunction = semanticLeft_->functions[match.leftIndex];
                    const SemanticFunction& rightFunction = semanticRight_->functions[match.rightIndex];
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::PushID(static_cast<int>(index));
                    const std::string leftLabel = semanticFunctionLabel(leftFunction);
                    if (ImGui::Selectable(leftLabel.c_str(), semanticSelectedMatch_ == static_cast<int>(index),
                                          ImGuiSelectableFlags_SpanAllColumns)) {
                        semanticSelectedMatch_ = static_cast<int>(index);
                        semanticSelectedHunk_ = -1;
                    }
                    ImGui::PopID();
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("%s\nBaseline: 0x%llX", leftLabel.c_str(),
                                          static_cast<unsigned long long>(match.leftAddress));
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(semanticFunctionLabel(rightFunction).c_str());
                    if (ImGui::IsItemHovered())
                        ImGui::SetTooltip("%s\nCandidate: 0x%llX", semanticFunctionLabel(rightFunction).c_str(),
                                          static_cast<unsigned long long>(match.rightAddress));
                    ImGui::TableSetColumnIndex(2);
                    ImGui::Text("%.0f%%", static_cast<double>(match.confidence) * 100.0);
                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextUnformatted(semanticBasisName(match.basis));
                    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", match.evidence.c_str());
                    ImGui::TableSetColumnIndex(4);
                    if (match.hunks.empty()) ImGui::TextColored(theme::col::good(), "0");
                    else ImGui::TextColored(theme::col::warn(), "%zu", match.hunks.size());
                }
                ui::EndDataTable();
            }
            ImGui::EndTabItem();
        }

        if (ui::BeginCountTabItem("Added", semanticDiff_.added.size())) {
            ImGui::TextDisabled("%zu of %zu candidate-only functions", semanticVisibleAdded_.size(), semanticDiff_.added.size());
            if (semanticVisibleAdded_.empty())
                ImGui::TextWrapped(semanticDiff_.added.empty() ? "No added functions were detected."
                    : "No added functions match this search. Clear the search to see all added functions.");
            else if (ui::BeginDataTable("SemanticAdded", 2,
                    ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                    ImVec2(0, std::max(1.0f, ImGui::GetContentRegionAvail().y)))) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed,
                                        130.0f * theme::UiScale());
                ImGui::TableSetupColumn("Function");
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                ImGuiListClipper addedClipper;
                addedClipper.Begin(static_cast<int>(semanticVisibleAdded_.size()));
                while (addedClipper.Step()) for (int clippedIndex = addedClipper.DisplayStart;
                                                  clippedIndex < addedClipper.DisplayEnd;
                                                  ++clippedIndex) {
                    const SemanticUnmatchedFunction& function =
                        semanticDiff_.added[semanticVisibleAdded_[static_cast<size_t>(clippedIndex)]];
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("0x%llX", static_cast<unsigned long long>(function.address));
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(function.name.empty() ? "(unnamed)" : function.name.c_str());
                    ui::ItemTooltip(function.name.c_str());
                }
                ui::EndDataTable();
            }
            ImGui::EndTabItem();
        }

        if (ui::BeginCountTabItem("Removed", semanticDiff_.removed.size())) {
            ImGui::TextDisabled("%zu of %zu baseline-only functions", semanticVisibleRemoved_.size(), semanticDiff_.removed.size());
            if (semanticVisibleRemoved_.empty())
                ImGui::TextWrapped(semanticDiff_.removed.empty() ? "No removed functions were detected."
                    : "No removed functions match this search. Clear the search to see all removed functions.");
            else if (ui::BeginDataTable("SemanticRemoved", 2,
                    ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                    ImVec2(0, std::max(1.0f, ImGui::GetContentRegionAvail().y)))) {
                ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed,
                                        130.0f * theme::UiScale());
                ImGui::TableSetupColumn("Function");
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                ImGuiListClipper removedClipper;
                removedClipper.Begin(static_cast<int>(semanticVisibleRemoved_.size()));
                while (removedClipper.Step()) for (int clippedIndex = removedClipper.DisplayStart;
                                                    clippedIndex < removedClipper.DisplayEnd;
                                                    ++clippedIndex) {
                    const SemanticUnmatchedFunction& function =
                        semanticDiff_.removed[semanticVisibleRemoved_[static_cast<size_t>(clippedIndex)]];
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("0x%llX", static_cast<unsigned long long>(function.address));
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(function.name.empty() ? "(unnamed)" : function.name.c_str());
                    ui::ItemTooltip(function.name.c_str());
                }
                ui::EndDataTable();
            }
            ImGui::EndTabItem();
        }

        const std::string transferTitle = "Transfer metadata (" +
                                          std::to_string(semanticDiff_.transferProposals.size()) + ")";
        if (ImGui::BeginTabItem(transferTitle.c_str())) {
            const uint64_t activeHash = ctx.staticBinary().loaded()
                                      ? ctx.staticBinary().contentHash() : 0;
            const bool activeProjectValid = activeHash &&
                                            ctx.staticProject().hash == activeHash &&
                                            !ctx.staticBinary().isMappedImage();
            ImGui::TextWrapped("Choose the metadata proposals to transfer into the active project, then apply the selection.");
            if (semanticDiff_.transferProposals.empty())
                ImGui::TextDisabled("No metadata transfer proposals are available for these files.");
            ImGui::BeginChild("SemanticTransfers", ImVec2(0, std::max(1.0f,
                                ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeightWithSpacing() * 3)),
                              ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
            ImGuiListClipper transferClipper;
            transferClipper.Begin(static_cast<int>(semanticDiff_.transferProposals.size()));
            while (transferClipper.Step()) for (int clippedIndex = transferClipper.DisplayStart;
                                                 clippedIndex < transferClipper.DisplayEnd;
                                                 ++clippedIndex) {
                const size_t index = static_cast<size_t>(clippedIndex);
                const MetadataTransferProposal& proposal = semanticDiff_.transferProposals[index];
                const std::optional<SemanticImage>& target =
                    proposal.direction == MetadataTransferDirection::LeftToRight
                        ? semanticRight_ : semanticLeft_;
                const bool instructionMapped =
                    (proposal.kind != MetadataTransferKind::Comment &&
                     proposal.kind != MetadataTransferKind::Bookmark) ||
                    proposal.targetInstructionValid;
                const bool eligible = activeProjectValid && target &&
                                      target->contentIdentity == activeHash && instructionMapped;
                ImGui::PushID(static_cast<int>(index));
                bool selected = semanticProposalSelected_[index];
                ImGui::BeginDisabled(!eligible);
                if (ImGui::Checkbox("##selected", &selected)) {
                    semanticProposalSelected_[index] = selected;
                    if (selected) {
                        if (!semanticProposalSelectionCount_)
                            semanticTransferTarget_ = activeTransferIdentity;
                        ++semanticProposalSelectionCount_;
                    } else if (semanticProposalSelectionCount_) {
                        --semanticProposalSelectionCount_;
                        if (!semanticProposalSelectionCount_)
                            semanticTransferTarget_ = {};
                    }
                }
                ImGui::EndDisabled();
                ImGui::SameLine();
                ImGui::Text("%s  %s  -> 0x%llX  %s",
                            proposal.direction == MetadataTransferDirection::LeftToRight ? "L->R" : "R->L",
                            semanticTransferName(proposal.kind),
                            static_cast<unsigned long long>(proposal.targetFunction),
                            proposal.value.empty() ? "" : proposal.value.c_str());
                if (!eligible) {
                    ImGui::SameLine();
                    ImGui::TextColored(theme::col::warn(), "%s",
                        !instructionMapped ? "(no matched target instruction)"
                                           : "(target is not the active project)");
                }
                if (ImGui::IsItemHovered() && !proposal.value.empty())
                    ImGui::SetTooltip("%s", proposal.value.c_str());
                ImGui::PopID();
            }
            ImGui::EndChild();
            ImGui::BeginDisabled(!activeProjectValid || !semanticProposalSelectionCount_);
            if (ui::AccentButton("Apply selected", theme::col::accent())) applySelectedSemanticTransfers(ctx);
            ImGui::EndDisabled();
            ui::SameLineIfFits(ImGui::CalcTextSize("Clear selection").x + ImGui::GetStyle().FramePadding.x * 2);
            if (ImGui::Button("Clear selection")) {
                std::fill(semanticProposalSelected_.begin(), semanticProposalSelected_.end(), false);
                semanticProposalSelectionCount_ = 0;
                semanticTransferTarget_ = {};
            }
            if (!semanticTransferStatus_.empty()) {
                ImGui::PushStyleColor(ImGuiCol_Text, theme::col::muted());
                ImGui::TextWrapped("%s", semanticTransferStatus_.c_str());
                ImGui::PopStyleColor();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }

    if (!showMatchedDetail || semanticSelectedMatch_ < 0 ||
        semanticSelectedMatch_ >= static_cast<int>(semanticDiff_.matched.size())) return;
    const SemanticFunctionMatch& selected = semanticDiff_.matched[semanticSelectedMatch_];
    if (selected.leftIndex >= semanticLeft_->functions.size() ||
        selected.rightIndex >= semanticRight_->functions.size()) return;
    const SemanticFunction& leftFunction = semanticLeft_->functions[selected.leftIndex];
    const SemanticFunction& rightFunction = semanticRight_->functions[selected.rightIndex];

    ImGui::Separator();
    ImGui::TextWrapped("%s  <->  %s", semanticFunctionLabel(leftFunction).c_str(),
                semanticFunctionLabel(rightFunction).c_str());
    ImGui::PushStyleColor(ImGuiCol_Text, theme::col::muted());
    ImGui::TextWrapped("%s; %.0f%% - %s", semanticBasisName(selected.basis),
                        static_cast<double>(selected.confidence) * 100.0,
                        selected.evidence.c_str());
    ImGui::PopStyleColor();

    if (!selected.hunks.empty()) {
        ImGui::TextDisabled("Instruction edit hunks:");
        const float hunkHeight = std::max(1.0f, std::min(110.0f * theme::UiScale(),
                                                       ImGui::GetContentRegionAvail().y * 0.22f));
        ImGui::BeginChild("SemanticHunks", ImVec2(0, hunkHeight), ImGuiChildFlags_Borders);
        ImGuiListClipper hunkClipper;
        hunkClipper.Begin(static_cast<int>(selected.hunks.size()));
        while (hunkClipper.Step()) {
            for (int clippedIndex = hunkClipper.DisplayStart;
                 clippedIndex < hunkClipper.DisplayEnd; ++clippedIndex) {
                const size_t index = static_cast<size_t>(clippedIndex);
                const InstructionEditHunk& hunk = selected.hunks[index];
                ImGui::PushID(clippedIndex);
                char label[160]{};
                std::snprintf(label, sizeof(label), "%s  L[%u +%u]  R[%u +%u]",
                              semanticEditName(hunk.kind), hunk.leftBegin, hunk.leftCount,
                              hunk.rightBegin, hunk.rightCount);
                if (ImGui::Selectable(label, semanticSelectedHunk_ == clippedIndex))
                    semanticSelectedHunk_ = clippedIndex;
                ImGui::PopID();
            }
        }
        ImGui::EndChild();
        if (selected.hunksTruncated) {
            ImGui::TextColored(theme::col::warn(), "additional hunks omitted by bounds");
        }
    } else {
        ImGui::TextColored(theme::col::good(), "No instruction edits in this match.");
    }

    size_t leftFirst = 0, rightFirst = 0;
    size_t leftLast = leftFunction.instructions.size();
    size_t rightLast = rightFunction.instructions.size();
    const InstructionEditHunk* selectedHunk = nullptr;
    if (semanticSelectedHunk_ >= 0 &&
        semanticSelectedHunk_ < static_cast<int>(selected.hunks.size())) {
        selectedHunk = &selected.hunks[semanticSelectedHunk_];
        leftFirst = selectedHunk->leftBegin > 3 ? selectedHunk->leftBegin - 3 : 0;
        rightFirst = selectedHunk->rightBegin > 3 ? selectedHunk->rightBegin - 3 : 0;
        leftLast = (std::min)(leftFunction.instructions.size(),
                              static_cast<size_t>(selectedHunk->leftBegin) +
                              selectedHunk->leftCount + 3);
        rightLast = (std::min)(rightFunction.instructions.size(),
                               static_cast<size_t>(selectedHunk->rightBegin) +
                               selectedHunk->rightCount + 3);
    }
    const size_t displayRows = (std::max)(leftLast - leftFirst, rightLast - rightFirst);
    const float instructionHeight = std::max(1.0f, ImGui::GetContentRegionAvail().y);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::col::code());
    ui::PushMono();
    if (ImGui::BeginTable("SemanticInstructions", 2,
            ImGuiTableFlags_BordersInnerH | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
            ImGuiTableFlags_ScrollX | ImGuiTableFlags_Resizable,
            ImVec2(0, instructionHeight), std::max(920.0f * theme::UiScale(), ImGui::GetContentRegionAvail().x))) {
        ImGui::TableSetupColumn("Baseline instructions", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Candidate instructions", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>((std::min)(displayRows,
                            static_cast<size_t>(std::numeric_limits<int>::max()))));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const size_t leftIndex = leftFirst + static_cast<size_t>(row);
                const size_t rightIndex = rightFirst + static_cast<size_t>(row);
                ImGui::TableNextRow();
                auto renderInstruction = [&](int column, const SemanticFunction& function,
                                             size_t index, size_t end, uint32_t editBegin,
                                             uint32_t editCount) {
                    ImGui::TableSetColumnIndex(column);
                    if (index >= end || index >= function.instructions.size()) {
                        ImGui::TextDisabled("-");
                        return;
                    }
                    const SemanticInstruction& instruction = function.instructions[index];
                    const bool edited = selectedHunk && index >= editBegin &&
                                        index < static_cast<size_t>(editBegin) + editCount;
                    const ImVec4 color = edited ? theme::col::warn()
                                                : ImGui::GetStyleColorVec4(ImGuiCol_Text);
                    ImGui::TextColored(color, "%08llX  %s",
                                       static_cast<unsigned long long>(instruction.address),
                                       instruction.display.empty() ? instruction.mnemonic.c_str()
                                                                   : instruction.display.c_str());
                    ui::ItemTooltip(instruction.display.empty() ? instruction.mnemonic.c_str()
                                                               : instruction.display.c_str());
                };
                renderInstruction(0, leftFunction, leftIndex, leftLast,
                                  selectedHunk ? selectedHunk->leftBegin : 0,
                                  selectedHunk ? selectedHunk->leftCount : 0);
                renderInstruction(1, rightFunction, rightIndex, rightLast,
                                  selectedHunk ? selectedHunk->rightBegin : 0,
                                  selectedHunk ? selectedHunk->rightCount : 0);
            }
        }
        ImGui::EndTable();
    }
    ui::PopMono();
    ImGui::PopStyleColor();
}

void BinaryDiffTab::renderPane(const char* id, const BinaryFile& self, const BinaryFile& other,
                               int rows, bool master, float& scrollOut, bool& hoveredOut, bool forceScroll) {
    const std::vector<uint8_t>& A = self.bytes();
    const std::vector<uint8_t>& B = other.bytes();
    const ImVec4 cDiff = theme::col::bad();
    const ImVec4 cSame = ImGui::GetStyleColorVec4(ImGuiCol_Text);
    const ImVec4 cSameA = theme::col::muted();
    const ImVec4 cCur = theme::col::warn(); // the currently selected change

    uint64_t curS = 0, curE = 0;
    if (curRegion_ >= 0 && curRegion_ < (int)regions_.size()) { curS = regions_[curRegion_].start; curE = regions_[curRegion_].end; }

    // Both panes retain horizontal access to complete hex/ASCII rows. Equal
    // scrollbar space also keeps their columns aligned; the follower's vertical
    // position is synchronized with the hovered master.
    // A forced scroll (Prev/Next) drives both panes to the selected region.
    ImGuiWindowFlags wf = ImGuiWindowFlags_HorizontalScrollbar;
    ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::col::code());
    ImGui::BeginChild(id, ImVec2(0, 0), ImGuiChildFlags_None, wf);
    ImGui::PopStyleColor();
    if (!master || forceScroll) ImGui::SetScrollY(scrollY_);

    ui::PushMono();
    ImGuiListClipper clip;
    clip.Begin(rows);
    while (clip.Step()) {
        for (int r = clip.DisplayStart; r < clip.DisplayEnd; ++r) {
            size_t base = (size_t)r * 16;
            if (curS < curE && base < curE && base + 16 > curS) {
                const ImVec2 row = ImGui::GetCursorScreenPos();
                ImVec4 highlight = theme::col::selection();
                highlight.w = 0.16f;
                const float rowWidth = std::max(ImGui::GetContentRegionAvail().x,
                    ImGui::CalcTextSize("00000000  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................").x);
                ImGui::GetWindowDrawList()->AddRectFilled(row,
                    ImVec2(row.x + rowWidth, row.y + ImGui::GetTextLineHeight()),
                    ImGui::GetColorU32(highlight));
            }
            ImGui::TextDisabled("%08llX", (unsigned long long)base);
            ImGui::SameLine(0, 10);
            for (int c = 0; c < 16; ++c) {
                size_t idx = base + c;
                if (c) ImGui::SameLine(0, 0);
                if (idx >= A.size()) { ImGui::TextDisabled("   "); continue; }
                bool diff = (idx >= B.size()) || A[idx] != B[idx];
                bool cur  = diff && idx >= curS && idx < curE;
                ImGui::TextColored(cur ? cCur : diff ? cDiff : cSame, "%02X ", A[idx]);
            }
            ImGui::SameLine(0, 10);
            for (int c = 0; c < 16; ++c) {
                size_t idx = base + c;
                if (c) ImGui::SameLine(0, 0);
                if (idx >= A.size()) { ImGui::TextDisabled(" "); continue; }
                bool diff = (idx >= B.size()) || A[idx] != B[idx];
                bool cur  = diff && idx >= curS && idx < curE;
                char ch = (A[idx] >= 32 && A[idx] < 127) ? (char)A[idx] : '.';
                ImGui::TextColored(cur ? cCur : diff ? cDiff : cSameA, "%c", ch);
            }
        }
    }
    ui::PopMono();

    if (master && !forceScroll) scrollOut = ImGui::GetScrollY();
    hoveredOut = ImGui::IsWindowHovered();
    ImGui::EndChild();
}

} // namespace ds
