#include "CortexTab.h"
#include "../Core/ApiDatabase.h"
#include "../Core/Demangle.h"
#include "../Core/BinaryFile.h"
#include "../Core/CFG.h"
#include "../Core/FuncAnnotate.h"
#include "../Core/JumpTableResolver.h"
#include "../Core/PatchSet.h"
#include "../Disasm/DisassemblerFactory.h"
#include "../Disasm/IDisassembler.h"
#include "../Disasm/JvmDisassembler.h"
#include "../Disasm/GmlDisassembler.h"
#include "../Ui/Fonts.h"
#include "../Ui/Icons.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <exception>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace ds {

struct CortexTab::AsyncState {
    enum class Phase : int {
        Idle,
        Snapshot,
        Loading,
        Strings,
        Functions,
        Xrefs,
        Capabilities,
        Algorithms,
        Annotations,
        Triage,
        Report,
    };

    struct Key {
        DocumentResultIdentity image;
        uint64_t knowledge = 0;
        DecoderConfig decoder;
    };

    struct Request {
        Key key;
        std::string path;
        std::string displayName;
        uint64_t expectedSize = 0;
        bool mapped = false;
        bool raw = false;
        uint64_t imageBase = 0;
        bool rawEntryExplicit = false;
        uint64_t rawEntry = 0;
        std::vector<AnalysisLandmark> landmarks;
        std::vector<PjPatch> patches;
        std::vector<size_t> patchSourceIndices;
        uint64_t patchSourceProjectRevision = 0;
        std::vector<PjFunctionOverride> functionOverrides;
        std::vector<PjDataOverride> dataOverrides;
        std::unordered_map<uint64_t, std::string> names;
        std::unordered_map<uint64_t, std::string> algorithmLabels;
        std::vector<uint8_t> mappedBytes;
        std::shared_ptr<const CrackmeTriageReport> crackmeTriage;
    };

    struct Completion {
        Key key;
        bool success = false;
        bool cancelled = false;
        std::string error;
        std::vector<Capability> caps;
        std::vector<AlgoMatch> algos;
        std::vector<FuncResult> funcs;
        std::vector<StrResult> strings;
        std::vector<CortexFuncInfo> funcInfo;
        XrefIndex xref;
        CrackmeTriageReport crackmeTriage;
        CortexReport report;
    };

    std::thread worker;
    std::atomic<bool> running{false};
    std::atomic<bool> cancel{false};
    std::atomic<int> phase{static_cast<int>(Phase::Idle)};
    std::atomic<uint32_t> progress{0};
    std::atomic<uint32_t> total{0};
    Key activeKey;
    std::mutex completionMutex;
    Completion completion;
    bool completionReady = false;

    // A mapped image has no stable path to reload. Its snapshot is therefore
    // staged in small render-frame slices before the worker starts; no worker
    // ever borrows active static-document storage.
    bool staging = false;
    Request stagedRequest;
    size_t stagedOffset = 0;
    size_t stagedPatchIndex = 0;
    size_t stagedPatchOffset = 0;
    std::string notice;
    std::string error;

    static uint32_t boundedProgressTotal(uint64_t n) {
        return static_cast<uint32_t>(std::min<uint64_t>(
            n, std::numeric_limits<uint32_t>::max()));
    }

    void setPhase(Phase p, uint64_t phaseTotal = 0) {
        progress.store(0, std::memory_order_relaxed);
        total.store(boundedProgressTotal(phaseTotal), std::memory_order_relaxed);
        phase.store(static_cast<int>(p), std::memory_order_release);
    }

    bool cancelled() const { return cancel.load(std::memory_order_acquire); }

    void publish(Completion&& out) {
        {
            std::lock_guard<std::mutex> lk(completionMutex);
            completion = std::move(out);
            completionReady = true;
        }
        phase.store(static_cast<int>(Phase::Idle), std::memory_order_release);
        running.store(false, std::memory_order_release);
    }

    void start(Request&& request);
    void run(Request request);
};

namespace {

DocumentResultIdentity currentCortexIdentity(const AppContext& ctx) {
    const BinaryFile& binary = ctx.staticBinary();
    return MakeDocumentResultIdentity(
        ctx.staticDocumentId(), ctx.staticImageGeneration(), binary.loaded(),
        binary.loaded() ? binary.contentHash() : 0,
        binary.loaded() ? binary.imageRevision() : 0);
}

// Project maps do not expose a mutation generation. Build an order-independent
// fingerprint so a rename/confirmed label invalidates Cortex without allocating
// and sorting a copy of every annotation on each rendered frame.
uint64_t projectKnowledgeSignature(const ProjectState& project) {
    uint64_t xorAcc = 0, sumAcc = 0;
    auto commit = [&](uint64_t item) {
        item ^= item >> 33; item *= 0xff51afd7ed558ccdull;
        item ^= item >> 33; item *= 0xc4ceb9fe1a85ec53ull;
        item ^= item >> 33;
        xorAcc ^= item;
        sumAcc += item * 0x9E3779B97F4A7C15ull;
    };
    auto begin = [](uint8_t kind, uint64_t va) {
        uint64_t item = 1469598103934665603ull;
        auto mixByte = [&item](uint8_t b) { item = (item ^ b) * 1099511628211ull; };
        mixByte(kind);
        for (unsigned shift = 0; shift != 64; shift += 8) mixByte((uint8_t)(va >> shift));
        return item;
    };
    auto mixByte = [](uint64_t& item, uint8_t b) {
        item = (item ^ b) * 1099511628211ull;
    };
    auto mixU64 = [&](uint64_t& item, uint64_t value) {
        for (unsigned shift = 0; shift != 64; shift += 8)
            mixByte(item, static_cast<uint8_t>(value >> shift));
    };
    auto mixString = [&](uint64_t& item, const std::string& value) {
        mixU64(item, value.size());
        for (unsigned char c : value) mixByte(item, c);
    };
    auto add = [&](uint8_t kind, uint64_t va, const std::string& value) {
        uint64_t item = begin(kind, va);
        mixString(item, value);
        commit(item);
    };
    for (const auto& [va, name] : project.names) add(0, va, name);
    for (const auto& [va, label] : project.algorithmLabels) add(1, va, label);
    for (const PjFunctionOverride& function : project.functionOverrides) {
        uint64_t item = begin(2, function.address);
        mixByte(item, static_cast<uint8_t>(function.action));
        mixByte(item, function.exactExtentValid ? 1 : 0);
        mixU64(item, function.exactSize);
        mixByte(item, static_cast<uint8_t>(function.noreturn));
        mixByte(item, static_cast<uint8_t>(function.mode));
        mixString(item, function.callingConvention);
        mixString(item, function.prototype);
        commit(item);
    }
    for (size_t index = 0; index < project.dataOverrides.size(); ++index) {
        const PjDataOverride& span = project.dataOverrides[index];
        uint64_t item = begin(3, span.address);
        mixU64(item, index); // overlapping decisions retain their application order
        mixU64(item, span.size);
        mixByte(item, static_cast<uint8_t>(span.kind));
        mixString(item, span.type);
        commit(item);
    }
    uint64_t h = xorAcc ^ (sumAcc + (project.names.size() * 0xD6E8FEB86659FD93ull)
                         + (project.algorithmLabels.size() * 0xA0761D6478BD642Full)
                         + (project.functionOverrides.size() * 0xE7037ED1A0B428DBull));
    h ^= h >> 29; h *= 0x165667919E3779F9ull; h ^= h >> 32;
    return h;
}

bool mappedSpan(const BinaryFile& bin, uint64_t address, uint64_t size) {
    if (!size || address > UINT64_MAX - size) return false;
    size_t available = 0;
    return bin.ptrFromVA(address, available) && size <= static_cast<uint64_t>(available);
}

std::vector<uint64_t> analystSeeds(const BinaryFile& bin,
                                   const std::vector<PjFunctionOverride>& overrides) {
    std::vector<uint64_t> seeds;
    seeds.reserve(overrides.size());
    for (const PjFunctionOverride& item : overrides) {
        size_t available = 0;
        if (item.action == PjFunctionAction::Define &&
            bin.ptrFromVA(item.address, available))
            seeds.push_back(item.address);
    }
    std::sort(seeds.begin(), seeds.end());
    seeds.erase(std::unique(seeds.begin(), seeds.end()), seeds.end());
    return seeds;
}

FunctionNoreturnDecisionResolver analystNoreturnDecisions(
    const std::vector<PjFunctionOverride>& overrides) {
    auto decisions = std::make_shared<std::vector<std::pair<uint64_t, bool>>>();
    decisions->reserve(overrides.size());
    for (const PjFunctionOverride& item : overrides) {
        if (item.action != PjFunctionAction::Define ||
            item.noreturn == PjOverrideBool::Unspecified)
            continue;
        decisions->push_back({item.address, item.noreturn == PjOverrideBool::True});
    }
    std::stable_sort(decisions->begin(), decisions->end(),
                     [](const auto& a, const auto& b) { return a.first < b.first; });
    decisions->erase(std::unique(decisions->begin(), decisions->end(),
                                 [](const auto& a, const auto& b) {
                                     return a.first == b.first;
                                 }), decisions->end());
    if (decisions->empty()) return {};
    return [decisions = std::move(decisions)](uint64_t address) -> std::optional<bool> {
        auto it = std::lower_bound(decisions->begin(), decisions->end(), address,
                                   [](const auto& item, uint64_t value) {
                                       return item.first < value;
                                   });
        return it == decisions->end() || it->first != address
             ? std::nullopt : std::optional<bool>(it->second);
    };
}

void applyFunctionOverrides(const BinaryFile& bin,
                            const std::vector<PjFunctionOverride>& overrides,
                            std::vector<FuncResult>& functions) {
    for (const PjFunctionOverride& decision : overrides) {
        auto it = std::find_if(functions.begin(), functions.end(), [&](const FuncResult& fn) {
            return fn.address == decision.address;
        });
        if (decision.action == PjFunctionAction::Undefine) {
            if (it != functions.end()) functions.erase(it);
            continue;
        }
        size_t available = 0;
        if (!bin.ptrFromVA(decision.address, available)) continue;
        if (it == functions.end()) {
            char name[32];
            std::snprintf(name, sizeof(name), "sub_%llX",
                          static_cast<unsigned long long>(decision.address));
            functions.push_back({decision.address, 0, name, false,
                                 "authoritative analyst definition", false});
            it = std::prev(functions.end());
        }
        it->guessed = false;
        it->reason = "authoritative analyst definition";
        it->analystDefined = true;
        it->seedKind = FunctionSeedKind::Analyst;
        it->boundaryConfidence = FunctionBoundaryConfidence::Authoritative;
        it->noreturnValid = decision.noreturn != PjOverrideBool::Unspecified;
        it->noreturn = decision.noreturn == PjOverrideBool::True;
        it->analystMode = decision.mode == PjFunctionMode::ARM ? 1
                          : decision.mode == PjFunctionMode::Thumb ? 2 : 0;
        it->callingConvention = decision.callingConvention;
        it->prototype = decision.prototype;
        if (decision.exactExtentValid &&
            decision.exactSize <= UINT32_MAX &&
            mappedSpan(bin, decision.address, decision.exactSize)) {
            it->size = static_cast<uint32_t>(decision.exactSize);
            it->chunks = {{decision.address, it->size}};
        }
    }
    std::sort(functions.begin(), functions.end(), [](const FuncResult& a, const FuncResult& b) {
        return a.address < b.address;
    });
}

NoreturnCallResolver makeNoreturnResolver(
    const BinaryFile& bin, const std::vector<PjFunctionOverride>& overrides,
    const std::vector<FuncResult>& functions) {
    auto targets = std::make_shared<std::vector<uint64_t>>();
    auto forcedReturning = std::make_shared<std::vector<uint64_t>>();
    for (const FuncResult& function : functions)
        if (function.noreturnValid && function.noreturn)
            targets->push_back(function.address);
    for (const BinaryFile::Import& item : bin.imports())
        if (item.addressKnown && IsKnownNoreturnApi(item.name))
            targets->push_back(item.iatVA);
    for (const PjFunctionOverride& item : overrides) {
        if (item.action != PjFunctionAction::Define) continue;
        if (item.noreturn == PjOverrideBool::True) targets->push_back(item.address);
        else if (item.noreturn == PjOverrideBool::False)
            forcedReturning->push_back(item.address);
    }
    auto normalize = [](std::vector<uint64_t>& values) {
        std::sort(values.begin(), values.end());
        values.erase(std::unique(values.begin(), values.end()), values.end());
    };
    normalize(*targets);
    normalize(*forcedReturning);
    if (targets->empty()) return {};
    return [targets = std::move(targets),
            forcedReturning = std::move(forcedReturning)](uint64_t target) {
        if (std::binary_search(forcedReturning->begin(), forcedReturning->end(), target))
            return false;
        return std::binary_search(targets->begin(), targets->end(), target);
    };
}

void drawVerticalSplitter(const char* id, const ImVec2& localPos,
                          float height, float thickness, float contentWidth,
                          float& ratio, float minRatio, float maxRatio) {
    ImGui::SetCursorPos(localPos);
    const ImVec2 screenPos = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton(id, ImVec2(thickness, std::max(1.0f, height)));
    const bool hot = ImGui::IsItemHovered() || ImGui::IsItemActive();
    if (hot) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeEW);
    if (ImGui::IsItemActive() && contentWidth > 1.0f)
        ratio += ImGui::GetIO().MouseDelta.x / contentWidth;
    ratio = std::clamp(ratio, minRatio, maxRatio);
    const float x = screenPos.x + thickness * 0.5f;
    ImGui::GetWindowDrawList()->AddLine(
        ImVec2(x, screenPos.y), ImVec2(x, screenPos.y + height),
        ImGui::GetColorU32(hot ? theme::col::accent() : theme::col::lineSoft()),
        hot ? 2.0f : 1.0f);
}

void drawHorizontalSplitter(const char* id, const ImVec2& localPos,
                            float width, float thickness, float contentHeight,
                            float& lowerRatio, float minRatio, float maxRatio) {
    ImGui::SetCursorPos(localPos);
    const ImVec2 screenPos = ImGui::GetCursorScreenPos();
    ImGui::InvisibleButton(id, ImVec2(std::max(1.0f, width), thickness));
    const bool hot = ImGui::IsItemHovered() || ImGui::IsItemActive();
    if (hot) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
    if (ImGui::IsItemActive() && contentHeight > 1.0f)
        lowerRatio -= ImGui::GetIO().MouseDelta.y / contentHeight;
    lowerRatio = std::clamp(lowerRatio, minRatio, maxRatio);
    const float y = screenPos.y + thickness * 0.5f;
    ImGui::GetWindowDrawList()->AddLine(
        ImVec2(screenPos.x, y), ImVec2(screenPos.x + width, y),
        ImGui::GetColorU32(hot ? theme::col::accent() : theme::col::lineSoft()),
        hot ? 2.0f : 1.0f);
}

} // namespace

CortexTab::CortexTab() : async_(std::make_unique<AsyncState>()) {}

CortexTab::~CortexTab() {
    async_->cancel.store(true, std::memory_order_release);
    async_->staging = false;
    if (async_->worker.joinable()) async_->worker.join();
}

void CortexTab::AsyncState::start(Request&& request) {
    cancel.store(false, std::memory_order_release);
    error.clear();
    notice.clear();
    activeKey = request.key;
    setPhase(Phase::Loading);
    running.store(true, std::memory_order_release);
    try {
        worker = std::thread([this, request = std::move(request)]() mutable {
            run(std::move(request));
        });
    } catch (const std::exception& e) {
        running.store(false, std::memory_order_release);
        phase.store(static_cast<int>(Phase::Idle), std::memory_order_release);
        error = std::string("Unable to start Cortex analysis: ") + e.what();
    } catch (...) {
        running.store(false, std::memory_order_release);
        phase.store(static_cast<int>(Phase::Idle), std::memory_order_release);
        error = "Unable to start Cortex analysis.";
    }
}

void CortexTab::AsyncState::run(Request request) {
    Completion out;
    out.key = request.key;
    auto stopIfCancelled = [&]() {
        if (!cancelled()) return false;
        out.cancelled = true;
        publish(std::move(out));
        return true;
    };

    try {
        BinaryFile bin;
        bool loaded = false;
        BinaryLoadOptions loadOptions;
        loadOptions.cancelled = [this] { return cancelled(); };
        if (request.mapped) {
            if (request.mappedBytes.size() != request.expectedSize)
                throw std::runtime_error("the live-image snapshot was incomplete");
            loaded = bin.loadFromMemory(std::move(request.mappedBytes), request.imageBase,
                                        request.displayName);
        } else if (request.raw) {
            loaded = bin.loadRaw(request.path, request.imageBase, loadOptions);
            if (loaded && request.rawEntryExplicit)
                loaded = bin.setRawEntryPointVA(request.rawEntry);
            if (loaded) loaded = bin.setAnalysisLandmarks(std::move(request.landmarks));
        } else {
            loaded = bin.load(request.path, loadOptions);
        }
        if (!loaded && bin.loadError() == BinaryLoadError::Cancelled) {
            if (!stopIfCancelled()) {
                out.cancelled = true;
                publish(std::move(out));
            }
            return;
        }
        if (!loaded) throw std::runtime_error("the analysis image could not be loaded");
        if (!request.mapped &&
            (bin.bytes().size() != request.expectedSize ||
             bin.contentHash() != request.key.image.contentHash))
            throw std::runtime_error("the source file changed after it was opened");
        if (stopIfCancelled()) return;

        // Recreate the exact in-memory patch state over the pristine disk image.
        // Application order is load-bearing: later overlapping patches win.
        if (!request.mapped) {
            for (const PjPatch& patch : request.patches) {
                if (stopIfCancelled()) return;
                if (patch.bytes.empty()) continue;
                if (bin.writeImage(patch.address, patch.bytes.data(), patch.bytes.size()) !=
                    patch.bytes.size())
                    throw std::runtime_error("a saved patch no longer maps into the source image");
            }
        }

        request.key.decoder = DecoderConfigForImage(bin, request.key.decoder);
        out.key = request.key;

        std::unique_ptr<IDisassembler> dis = MakeDisassembler(request.key.decoder);
        if (!dis || !dis->ready())
            throw std::runtime_error(dis && !dis->errorMessage().empty()
                ? std::string(dis->errorMessage()) : "the selected decoder is unavailable");
        if (request.key.decoder.arch == Arch::JVM && bin.javaClass())
            AttachJvmClass(*dis, bin.javaClass());
        if (request.key.decoder.arch == Arch::GML && bin.gameMakerArchive())
            AttachGameMakerArchive(*dis, bin.gameMakerArchive());

        setPhase(Phase::Strings, bin.bytes().size());
        out.strings = ScanStringsImage(bin, kDefaultStringScanCap, &progress);
        if (stopIfCancelled()) return;

        setPhase(Phase::Functions);
        const std::vector<uint64_t> functionSeeds =
            analystSeeds(bin, request.functionOverrides);
        const FunctionNoreturnDecisionResolver noreturnDecisions =
            analystNoreturnDecisions(request.functionOverrides);
        AnalyzeOut functionAnalysis = AnalyzeFunctionsNamed(
            bin, *dis, out.strings, true, request.key.decoder,
            [this] { return cancelled(); }, functionSeeds,
            noreturnDecisions);
        out.funcs = std::move(functionAnalysis.functions);
        std::shared_ptr<const CodeDataMap> codeData;
        if (functionAnalysis.codeDataValid)
            codeData = ApplyCodeDataOverrides(bin, request.dataOverrides,
                std::make_shared<CodeDataMap>(std::move(functionAnalysis.codeData)));
        if (stopIfCancelled()) return;
        applyFunctionOverrides(bin, request.functionOverrides, out.funcs);

        for (FuncResult& function : out.funcs) {
            auto it = request.names.find(function.address);
            if (it == request.names.end() || it->second.empty()) continue;
            function.name = it->second;
            function.guessed = false;
            function.reason.clear();
        }

        const XrefRangePlan xrefPlan = PlanXrefRanges(bin, codeData.get(),
            [this] { return cancelled(); });
        if (xrefPlan.cancelled || stopIfCancelled()) return;
        setPhase(Phase::Xrefs, xrefPlan.decodeBytes);
        out.xref.classificationApplied = xrefPlan.classificationApplied;
        out.xref.classificationScopeDigest = xrefPlan.scopeDigest;
        out.xref.classificationDataBytes = xrefPlan.classifiedDataBytes;
        out.xref.classificationTruncated = xrefPlan.classificationTruncated;
        XrefBuildLimits xrefLimits;
        xrefLimits.cancelled = [this] { return cancelled(); };
        xrefLimits.immediateTargetMapped = [&bin](uint64_t target) {
            size_t available = 0;
            return bin.ptrFromVA(target, available) != nullptr && available != 0;
        };
        for (const XrefCodeRange& range : xrefPlan.ranges) {
            if (stopIfCancelled()) return;
            size_t available = 0;
            const uint8_t* bytes = bin.ptrFromVA(range.address, available);
            if (!bytes) continue;
            if (!BuildXrefInto(out.xref, bytes, static_cast<size_t>(
                                  std::min<uint64_t>(available, range.size)),
                              range.address, *dis, &progress,
                              [&bin](const Instruction& instruction, uint64_t& target) {
                                  return bin.resolveInstructionTarget(instruction, target);
                              }, xrefLimits)) break;
        }
        FinalizeXrefIndex(out.xref);
        if (stopIfCancelled()) return;

        setPhase(Phase::Capabilities);
        out.caps = ScanCapabilities(bin);
        if (stopIfCancelled()) return;

        setPhase(Phase::Algorithms);
        out.algos = ScanAlgorithms(bin, &out.xref, &out.funcs);
        if (stopIfCancelled()) return;

        std::unordered_map<uint64_t, std::string> functionNames;
        functionNames.reserve(out.funcs.size());
        for (const FuncResult& function : out.funcs)
            functionNames[function.address] = function.name;
        for (AlgoMatch& algorithm : out.algos) {
            auto label = algorithm.addressValid
                ? request.algorithmLabels.find(algorithm.address)
                : request.algorithmLabels.end();
            if (label == request.algorithmLabels.end()) {
                for (uint64_t va : algorithm.dataVAs) {
                    label = request.algorithmLabels.find(va);
                    if (label != request.algorithmLabels.end()) break;
                }
            }
            if (label != request.algorithmLabels.end() && !label->second.empty())
                algorithm.name = label->second;
            for (AlgoXref& ref : algorithm.referencedBy) {
                if (!ref.funcAddressValid) continue;
                auto name = functionNames.find(ref.funcAddress);
                if (name != functionNames.end()) ref.funcName = name->second;
            }
        }

        const NoreturnCallResolver noreturnCalls =
            makeNoreturnResolver(bin, request.functionOverrides, out.funcs);
        const std::vector<CallEdgeR> triageCallEdges = BuildCallEdges(
            bin, *dis, out.funcs, JumpTableResolver{}, noreturnCalls,
            [&bin](const Instruction& instruction, uint64_t& target) {
                return bin.resolveInstructionTarget(instruction, target);
            });
        if (stopIfCancelled()) return;

        CrackmeTriageInput triageInput;
        triageInput.bytes = bin.bytes().data();
        triageInput.size = bin.bytes().size();
        triageInput.offsetToVA = [&bin](uint64_t fileOffset, uint64_t& va) {
            return bin.offsetToVA(fileOffset, va);
        };
        triageInput.overlayOffset = bin.overlayOffset();
        triageInput.overlaySize = bin.overlaySize();
        triageInput.imports.reserve(bin.imports().size());
        for (const BinaryFile::Import& source : bin.imports()) {
            triageInput.imports.push_back({ source.dll, source.name, source.iatVA,
                                            source.addressKnown });
        }
        triageInput.functions.reserve(out.funcs.size());
        for (const FuncResult& source : out.funcs) {
            CrackmeTriageFunctionInput function;
            function.address = source.address;
            function.name = source.name;
            function.size = source.size;
            function.ranges.reserve(source.chunks.size());
            for (const FunctionChunk& chunk : source.chunks)
                if (chunk.size) function.ranges.push_back({ chunk.address, chunk.size });
            triageInput.functions.push_back(std::move(function));
        }
        triageInput.callEdges.reserve(triageCallEdges.size());
        for (const CallEdgeR& edge : triageCallEdges)
            triageInput.callEdges.push_back({ edge.from, edge.to });
        triageInput.algorithms.reserve(out.algos.size());
        for (const AlgoMatch& source : out.algos) {
            CrackmeTriageAlgorithmInput algorithm;
            algorithm.address = source.address;
            algorithm.addressValid = source.addressValid;
            algorithm.name = source.name;
            algorithm.category = source.category;
            algorithm.evidence = source.detail;
            if (!source.referencedBy.empty() && source.referencedBy.front().funcAddressValid) {
                algorithm.functionAddress = source.referencedBy.front().funcAddress;
                algorithm.functionAddressValid = true;
            }
            triageInput.algorithms.push_back(std::move(algorithm));
        }
        triageInput.xrefs = &out.xref;
        triageInput.cancelled = [this] { return cancelled(); };

        setPhase(Phase::Triage, bin.bytes().size());
        if (request.crackmeTriage)
            out.crackmeTriage = *request.crackmeTriage;
        else
            out.crackmeTriage = RunCrackmeTriage(triageInput);
        if (stopIfCancelled()) return;

        // Limit expensive CFG annotations to the exact network import/string
        // owners identified above, then expand their direct call neighborhood by
        // two levels. Input order remains the stable tie-break and the cap is the
        // same public bound used by CrackmeTriage.
        const size_t maxCandidates = CrackmeTriageLimits{}.maxFunctions;
        std::unordered_set<uint64_t> annotationCandidates;
        auto addCandidate = [&](uint64_t address) {
            if (annotationCandidates.size() < maxCandidates)
                annotationCandidates.insert(address);
        };
        auto ownerFor = [&](uint64_t address, uint64_t& owner) {
            for (const FuncResult& function : out.funcs) {
                if (!function.chunks.empty()) {
                    for (const FunctionChunk& chunk : function.chunks) {
                        if (chunk.size && address >= chunk.address &&
                            address - chunk.address < chunk.size) {
                            owner = function.address;
                            return true;
                        }
                    }
                } else if (function.size && address >= function.address &&
                           address - function.address < function.size) {
                    owner = function.address;
                    return true;
                }
            }
            return false;
        };
        auto addReferenceOwners = [&](uint64_t target, bool valid) {
            if (!valid) return;
            const std::vector<uint64_t>* sources = out.xref.sources(target);
            if (!sources) return;
            for (uint64_t source : *sources) {
                uint64_t owner = 0;
                if (ownerFor(source, owner)) addCandidate(owner);
            }
        };
        for (const CrackmeTriageCorrelation& correlation : out.crackmeTriage.correlations)
            if (correlation.functionAddressValid) addCandidate(correlation.functionAddress);
        for (const CrackmeTriageEndpoint& endpoint : out.crackmeTriage.endpoints)
            for (const CrackmeTriageLiteralSource& source : endpoint.sources) {
                if (source.literalAddressValid) addReferenceOwners(source.literalAddress, true);
                else addReferenceOwners(source.address, source.addressValid);
            }
        for (const BinaryFile::Import& imported : bin.imports())
            if (imported.addressKnown && LookupNetworkApi(imported.dll, imported.name))
                addReferenceOwners(imported.iatVA, true);

        std::unordered_set<uint64_t> frontier = annotationCandidates;
        for (unsigned depth = 0; depth < 2 && !frontier.empty() &&
                                 annotationCandidates.size() < maxCandidates; ++depth) {
            std::unordered_set<uint64_t> next;
            for (const CallEdgeR& edge : triageCallEdges) {
                if (frontier.count(edge.from) && !annotationCandidates.count(edge.to)) {
                    addCandidate(edge.to);
                    next.insert(edge.to);
                }
                if (frontier.count(edge.to) && !annotationCandidates.count(edge.from)) {
                    addCandidate(edge.from);
                    next.insert(edge.from);
                }
                if (annotationCandidates.size() >= maxCandidates) break;
            }
            frontier = std::move(next);
        }
        if (annotationCandidates.empty()) {
            for (const FuncResult& function : out.funcs) {
                addCandidate(function.address);
                if (annotationCandidates.size() >= std::min<size_t>(64, maxCandidates)) break;
            }
        }

        std::vector<CrackmeTriageApiCallInput> triageApiCalls;
        if (request.key.decoder.arch == Arch::X86 || request.key.decoder.arch == Arch::X64) {
            AnnotateOptions options;
            options.x64 = request.key.decoder.arch == Arch::X64;
            const JumpTableResolver jumpTables =
                [&bin, &dis, decoder = request.key.decoder](const Instruction& instruction) {
                    JumpTableResolution table = ResolveJumpTable(
                        bin, *dis, decoder.arch, decoder.byteOrder, instruction);
                    ResolvedJumpTable resolved;
                    if (table.valid) resolved.targets = std::move(table.targets);
                    resolved.truncated = table.truncated;
                    resolved.evidence = std::move(table.evidence);
                    return resolved;
                };
            std::unordered_map<uint64_t, std::string> namesByVA;
            namesByVA.reserve(out.funcs.size() + bin.imports().size());
            for (const FuncResult& function : out.funcs)
                namesByVA[function.address] = function.name;
            for (const auto& import : bin.imports()) {
                if (!import.addressKnown) continue;
                namesByVA[import.iatVA] = import.dll.empty()
                    ? DemangleForLabel(import.name)
                    : import.dll + "." + DemangleForLabel(import.name);
            }
            std::unordered_map<uint64_t, std::string> stringsByVA;
            stringsByVA.reserve(out.strings.size());
            for (const StrResult& string : out.strings)
                stringsByVA[string.address] = string.text;
            options.nameFor = [&namesByVA](uint64_t va) -> std::string {
                auto it = namesByVA.find(va);
                return it == namesByVA.end() ? std::string() : it->second;
            };
            options.stringFor = [&stringsByVA](uint64_t va) -> std::string {
                auto it = stringsByVA.find(va);
                return it == stringsByVA.end() ? std::string() : it->second;
            };
            options.looksLikeVtable = [](uint64_t) { return false; };

            setPhase(Phase::Annotations, annotationCandidates.size());
            uint32_t annotated = 0;
            for (const FuncResult& function : out.funcs) {
                if (!annotationCandidates.count(function.address)) continue;
                if (annotated >= maxCandidates) break;
                if (stopIfCancelled()) return;
                if (function.size && function.size < 12) continue;
                std::vector<FunctionChunk> owned = function.chunks;
                if (owned.empty()) owned.push_back({function.address,
                    function.size ? function.size : 4096u});
                std::stable_sort(owned.begin(), owned.end(),
                    [entry = function.address](const FunctionChunk& a, const FunctionChunk& b) {
                        const bool ae = a.size && entry >= a.address && entry - a.address < a.size;
                        const bool be = b.size && entry >= b.address && entry - b.address < b.size;
                        return ae != be ? ae : a.address < b.address;
                    });
                std::vector<CFGCodeChunk> chunks;
                chunks.reserve(owned.size());
                for (const FunctionChunk& chunk : owned) {
                    size_t available = 0;
                    const uint8_t* bytes = bin.ptrFromVA(chunk.address, available);
                    if (bytes && chunk.size)
                        chunks.push_back({bytes, std::min<size_t>(available, chunk.size),
                                          chunk.address});
                }
                options.chunks = function.chunks;
                options.ownershipTruncated = function.ownershipTruncated;
                options.seedKind = function.seedKind;
                options.boundaryConfidence = function.boundaryConfidence;
                ControlFlowGraph graph = BuildCFG(
                    chunks, *dis, 2000, jumpTables, noreturnCalls,
                    [&bin](const Instruction& instruction, uint64_t& target) {
                        return bin.resolveInstructionTarget(instruction, target);
                    });
                FuncAnnotations annotations = AnnotateFunction(graph, options);
                CortexFuncInfo info;
                info.address = function.address;
                info.summary = annotations.summary;
                info.convention = annotations.convention;
                for (const FnNote& note : annotations.notes)
                    if (note.kind == NoteKind::Pattern && !note.text.empty())
                        info.patterns.push_back(note.text);
                if (!info.summary.empty() || !info.patterns.empty() ||
                    !info.convention.empty())
                    out.funcInfo.push_back(std::move(info));
                for (const ApiCallObservation& observed : annotations.apiCalls) {
                    if (triageApiCalls.size() >= CrackmeTriageLimits{}.maxTypedCalls) break;
                    CrackmeTriageApiCallInput call;
                    const size_t separator = observed.resolvedName.find_last_of(".!");
                    if (separator != std::string::npos && separator + 1 < observed.resolvedName.size()) {
                        call.dll = observed.resolvedName.substr(0, separator);
                        call.name = observed.resolvedName.substr(separator + 1);
                    } else {
                        call.name = observed.resolvedName;
                    }
                    call.callsite = observed.callVA;
                    call.callsiteValid = observed.callVAValid;
                    call.functionAddress = function.address;
                    call.functionAddressValid = true;
                    call.functionName = function.name;
                    call.returnValueUsed = observed.returnValueUsed;
                    call.returnValueUseKnown = observed.returnValueUseKnown;
                    switch (observed.returnUseKind) {
                    case ApiReturnUseKind::Ignored:    call.returnUseKind = NetworkReturnUseKind::Ignored; break;
                    case ApiReturnUseKind::Compared:   call.returnUseKind = NetworkReturnUseKind::Compared; break;
                    case ApiReturnUseKind::Branched:   call.returnUseKind = NetworkReturnUseKind::Branched; break;
                    case ApiReturnUseKind::Stored:     call.returnUseKind = NetworkReturnUseKind::Stored; break;
                    case ApiReturnUseKind::Propagated: call.returnUseKind = NetworkReturnUseKind::Propagated; break;
                    case ApiReturnUseKind::Consumed:   call.returnUseKind = NetworkReturnUseKind::Consumed; break;
                    case ApiReturnUseKind::Returned:   call.returnUseKind = NetworkReturnUseKind::Returned; break;
                    case ApiReturnUseKind::Unknown:    call.returnUseKind = NetworkReturnUseKind::Unknown; break;
                    }
                    call.returnUseAddress = observed.returnUseVA;
                    call.returnUseAddressValid = observed.returnUseVAValid;
                    call.returnUseInstruction = observed.returnUseInstruction;
                    call.returnUseSummary = observed.returnUseSummary;
                    call.resultInfluencesDecision = observed.resultInfluencesDecision;
                    call.decisionAddress = observed.decisionVA;
                    call.decisionAddressValid = observed.decisionVAValid;
                    call.decisionTarget = observed.decisionTarget;
                    call.decisionTargetValid = observed.decisionTargetValid;
                    call.decisionInstruction = observed.decisionInstruction;
                    call.returnUseEvidence = observed.returnUseEvidence;
                    call.returnUseConfidence = observed.returnUseConfidence;
                    call.replyDecisionAnalysisAttempted =
                        observed.replyDecisionAnalysisAttempted;
                    call.replyDecisionsComplete = observed.replyDecisionsComplete;
                    call.replyDecisionIncompleteReason =
                        observed.replyDecisionIncompleteReason;
                    for (const ApiReplyDecisionObservation& reply :
                         observed.replyDecisions) {
                        CrackmeTriageReplyDecisionInput converted;
                        converted.kind = reply.kind == ApiReplyDecisionKind::ComparisonCall
                            ? NetworkReplyDecisionKind::ComparisonCall
                            : NetworkReplyDecisionKind::DirectComparison;
                        converted.outputArgumentIndex = reply.outputArgumentIndex;
                        converted.outputRole = reply.outputRole;
                        converted.outputExpression = reply.outputExpression;
                        converted.comparisonAddress = reply.comparisonVA;
                        converted.comparisonAddressValid = reply.comparisonVAValid;
                        converted.comparisonInstruction = reply.comparisonInstruction;
                        converted.comparisonSummary = reply.comparisonSummary;
                        converted.expectedValue = reply.expectedValue;
                        converted.decisionAddress = reply.decisionVA;
                        converted.decisionAddressValid = reply.decisionVAValid;
                        converted.decisionTarget = reply.decisionTarget;
                        converted.decisionTargetValid = reply.decisionTargetValid;
                        converted.fallthroughAddress = reply.fallthroughVA;
                        converted.fallthroughAddressValid = reply.fallthroughVAValid;
                        converted.decisionInstruction = reply.decisionInstruction;
                        converted.takenPathSummary = reply.takenPathSummary;
                        converted.fallthroughPathSummary = reply.fallthroughPathSummary;
                        converted.matchAddress = reply.matchVA;
                        converted.matchAddressValid = reply.matchVAValid;
                        converted.mismatchAddress = reply.mismatchVA;
                        converted.mismatchAddressValid = reply.mismatchVAValid;
                        converted.evidence = reply.evidence;
                        converted.confidence = reply.confidence;
                        call.replyDecisions.push_back(std::move(converted));
                    }
                    for (const ApiArgumentObservation& source : observed.arguments) {
                        CrackmeTriageApiArgumentInput argument;
                        argument.ordinal = source.index;
                        argument.name = source.parameter.empty() ? source.abiLocation
                                                                 : source.parameter;
                        argument.literal = source.stringLiteral;
                        argument.address = source.referencedAddress;
                        argument.addressValid = source.referencedAddressValid;
                        call.arguments.push_back(std::move(argument));
                    }
                    triageApiCalls.push_back(std::move(call));
                }
                ++annotated;
                progress.store(annotated, std::memory_order_relaxed);
            }
        }
        if (stopIfCancelled()) return;

        if (!request.crackmeTriage) {
            setPhase(Phase::Triage, bin.bytes().size());
            triageInput.apiCalls = std::move(triageApiCalls);
            out.crackmeTriage = RunCrackmeTriage(triageInput);
        }
        if (stopIfCancelled()) return;

        setPhase(Phase::Report);
        CortexInput input;
        input.bin = &bin;
        input.effectiveArchitecture = ArchName(request.key.decoder.arch);
        input.capabilities = &out.caps;
        input.algorithms = &out.algos;
        input.functions = &out.funcs;
        input.strings = &out.strings;
        input.funcInfo = &out.funcInfo;
        input.crackmeTriage = &out.crackmeTriage;
        out.report = BuildCortexReport(input);
        if (stopIfCancelled()) return;
        out.success = true;
    } catch (const std::exception& e) {
        out.error = std::string("Cortex analysis failed: ") + e.what();
    } catch (...) {
        out.error = "Cortex analysis failed at an unexpected worker boundary.";
    }
    publish(std::move(out));
}

CortexInput CortexTab::inputFor(AppContext& ctx) {
    CortexInput in;
    in.bin          = &ctx.staticBinary();
    in.effectiveArchitecture = ArchName(ctx.staticArch());
    in.capabilities = &caps_;
    in.algorithms   = &algos_;
    in.functions    = &funcs_;
    in.strings      = &strings_;
    in.funcInfo     = &funcInfo_;
    in.crackmeTriage = &crackmeTriage_;
    return in;
}


void CortexTab::analyze(AppContext& ctx) {
    if (!ctx.staticBinary().loaded() ||
        async_->running.load(std::memory_order_acquire) ||
        async_->staging)
        return;

    // Adopt and join any completion before assigning a replacement std::thread.
    pumpAnalysis(ctx);
    if (async_->running.load(std::memory_order_acquire) || async_->staging) return;
    pumpAnalysis(ctx); // closes the narrow running->finished race before assignment

    async_->error.clear();
    async_->notice.clear();

    AsyncState::Request request;
    request.key.image = currentCortexIdentity(ctx);
    request.key.knowledge = projectKnowledgeSignature(ctx.staticProject());
    request.key.decoder = ctx.staticDecoderConfig();
    request.path = ctx.staticBinary().path();
    request.displayName = ctx.staticProject().name.empty()
                        ? ctx.staticBinary().path() : ctx.staticProject().name;
    request.expectedSize = ctx.staticBinary().bytes().size();
    request.mapped = ctx.staticBinary().isMappedImage();
    request.raw = ctx.staticBinary().format() == BinFormat::Raw;
    request.imageBase = ctx.staticBinary().imageBase();
    request.rawEntryExplicit = ctx.staticBinary().rawEntryExplicit();
    request.rawEntry = request.rawEntryExplicit
                     ? ctx.staticBinary().entryPointVA() : 0;
    request.landmarks = ctx.staticBinary().analysisLandmarks();
    request.names = ctx.staticProject().names;
    request.algorithmLabels = ctx.staticProject().algorithmLabels;
    request.functionOverrides = ctx.staticProject().functionOverrides;
    request.dataOverrides = ctx.staticProject().dataOverrides;
    const DocumentAnalysisCache& documentCache = ctx.staticAnalysisCache();
    if (documentCache.matches(ctx.staticBinary(), ctx.staticAnalysis().epoch()))
        request.crackmeTriage = documentCache.crackmeTriage;
    uint64_t patchSnapshotBytes = 0;
    if (!request.mapped) {
        PjPatchSetPlan patchPlan = BuildPatchSetPlan(
            ctx.staticProject().patches, ctx.staticProject().patchSets);
        if (!patchPlan.success) {
            async_->error = std::string(
                "Cortex refused the invalid active patch selection: ") +
                PjPatchSetPlanErrorText(patchPlan.error) + ".";
            return;
        }
        request.patchSourceIndices = std::move(patchPlan.activePatchIndices);
        request.patchSourceProjectRevision = ctx.projectRevision;
        try {
            request.patches.reserve(request.patchSourceIndices.size());
            for (size_t sourceIndex : request.patchSourceIndices) {
                const PjPatch& source = ctx.staticProject().patches[sourceIndex];
                if (source.bytes.size() > UINT64_MAX - patchSnapshotBytes) {
                    async_->error =
                        "The active patch selection is too large to snapshot safely.";
                    return;
                }
                patchSnapshotBytes += source.bytes.size();
                PjPatch patch;
                patch.address = source.address;
                patch.patchSetId = source.patchSetId;
                patch.bytes.reserve(source.bytes.size());
                request.patches.push_back(std::move(patch));
            }
        } catch (const std::exception& e) {
            async_->error = std::string(
                "Unable to stage the active patch selection: ") + e.what();
            return;
        }
    }

    if (request.mapped) {
        // reserve() allocates capacity but copies no input bytes. The actual
        // snapshot advances in bounded slices from pumpAnalysis().
        try {
            request.mappedBytes.reserve(ctx.staticBinary().bytes().size());
        } catch (const std::exception& e) {
            async_->error = std::string("Unable to stage the live image: ") + e.what();
            return;
        }
        async_->stagedRequest = std::move(request);
        async_->stagedOffset = 0;
        async_->stagedPatchIndex = async_->stagedPatchOffset = 0;
        async_->staging = true;
        async_->cancel.store(false, std::memory_order_release);
        async_->setPhase(AsyncState::Phase::Snapshot,
                         async_->stagedRequest.expectedSize);
        async_->notice = "Taking an immutable live-image snapshot...";
        return;
    }

    if (patchSnapshotBytes) {
        async_->stagedRequest = std::move(request);
        async_->stagedOffset = 0;
        async_->stagedPatchIndex = async_->stagedPatchOffset = 0;
        async_->staging = true;
        async_->cancel.store(false, std::memory_order_release);
        async_->setPhase(AsyncState::Phase::Snapshot, patchSnapshotBytes);
        async_->notice = "Taking an immutable patch-state snapshot...";
        return;
    }

    if (request.path.empty()) {
        async_->error =
            "Cortex cannot reload this target safely because it has no source path.";
        return;
    }
    async_->start(std::move(request));
}

void CortexTab::cancelAnalysis() {
    if (async_->staging) {
        async_->staging = false;
        async_->stagedRequest = AsyncState::Request{};
        async_->stagedOffset = 0;
        async_->stagedPatchIndex = async_->stagedPatchOffset = 0;
        async_->phase.store(static_cast<int>(AsyncState::Phase::Idle),
                            std::memory_order_release);
        async_->notice = "Cortex analysis cancelled.";
        return;
    }
    if (async_->running.load(std::memory_order_acquire)) {
        async_->cancel.store(true, std::memory_order_release);
        async_->notice = "Cancelling Cortex analysis...";
    }
}

void CortexTab::pumpAnalysis(AppContext& ctx) {
    auto keyMatches = [&](const AsyncState::Key& key) {
        return SameDocumentResultImage(key.image, currentCortexIdentity(ctx)) &&
               projectKnowledgeSignature(ctx.staticProject()) == key.knowledge &&
               ctx.staticDecoderConfig() == key.decoder;
    };

    if (async_->staging) {
        ctx.wantContinuousRedraw = true;
        AsyncState::Request& request = async_->stagedRequest;
        if (!keyMatches(request.key) ||
            ctx.staticBinary().isMappedImage() != request.mapped ||
            ctx.staticBinary().bytes().size() != request.expectedSize) {
            async_->staging = false;
            async_->stagedRequest = AsyncState::Request{};
            async_->stagedOffset = 0;
            async_->stagedPatchIndex = async_->stagedPatchOffset = 0;
            async_->phase.store(static_cast<int>(AsyncState::Phase::Idle),
                                std::memory_order_release);
            async_->error = "Cortex snapshot stopped because the active target changed.";
        } else if (request.mapped) {
            constexpr size_t kSnapshotBytesPerFrame = 4u * 1024u * 1024u;
            const size_t remaining =
                ctx.staticBinary().bytes().size() - async_->stagedOffset;
            const size_t take = std::min(remaining, kSnapshotBytesPerFrame);
            const uint8_t* begin =
                ctx.staticBinary().bytes().data() + async_->stagedOffset;
            request.mappedBytes.insert(request.mappedBytes.end(), begin, begin + take);
            async_->stagedOffset += take;
            async_->progress.store(AsyncState::boundedProgressTotal(async_->stagedOffset),
                                   std::memory_order_relaxed);
            if (async_->stagedOffset == ctx.staticBinary().bytes().size()) {
                async_->staging = false;
                async_->stagedOffset = 0;
                async_->stagedPatchIndex = async_->stagedPatchOffset = 0;
                AsyncState::Request complete = std::move(async_->stagedRequest);
                async_->start(std::move(complete));
            }
        } else {
            constexpr size_t kSnapshotBytesPerFrame = 4u * 1024u * 1024u;
            size_t budget = kSnapshotBytesPerFrame;
            bool valid =
                request.patchSourceProjectRevision == ctx.projectRevision &&
                request.patchSourceIndices.size() == request.patches.size();
            while (valid && budget &&
                   async_->stagedPatchIndex < request.patches.size()) {
                const size_t destinationIndex = async_->stagedPatchIndex;
                const size_t sourceIndex =
                    request.patchSourceIndices[destinationIndex];
                if (sourceIndex >= ctx.staticProject().patches.size()) {
                    valid = false;
                    break;
                }
                const PjPatch& source = ctx.staticProject().patches[sourceIndex];
                PjPatch& destination = request.patches[destinationIndex];
                valid = source.address == destination.address &&
                        source.patchSetId == destination.patchSetId &&
                        destination.bytes.capacity() >= source.bytes.size() &&
                        async_->stagedPatchOffset <= source.bytes.size();
                if (!valid) break;
                const size_t remaining = source.bytes.size() - async_->stagedPatchOffset;
                if (!remaining) {
                    ++async_->stagedPatchIndex;
                    async_->stagedPatchOffset = 0;
                    continue;
                }
                const size_t take = std::min(remaining, budget);
                const uint8_t* begin = source.bytes.data() + async_->stagedPatchOffset;
                destination.bytes.insert(destination.bytes.end(), begin, begin + take);
                async_->stagedPatchOffset += take;
                async_->stagedOffset += take;
                budget -= take;
                if (async_->stagedPatchOffset == source.bytes.size()) {
                    ++async_->stagedPatchIndex;
                    async_->stagedPatchOffset = 0;
                }
            }
            if (!valid) {
                async_->staging = false;
                async_->stagedRequest = AsyncState::Request{};
                async_->stagedOffset = 0;
                async_->stagedPatchIndex = async_->stagedPatchOffset = 0;
                async_->phase.store(static_cast<int>(AsyncState::Phase::Idle),
                                    std::memory_order_release);
                async_->error =
                    "Cortex patch snapshot stopped because the patch set changed.";
            } else {
                async_->progress.store(
                    AsyncState::boundedProgressTotal(async_->stagedOffset),
                    std::memory_order_relaxed);
                if (async_->stagedPatchIndex == request.patches.size()) {
                    async_->staging = false;
                    async_->stagedOffset = 0;
                    async_->stagedPatchIndex = async_->stagedPatchOffset = 0;
                    AsyncState::Request complete = std::move(async_->stagedRequest);
                    async_->start(std::move(complete));
                }
            }
        }
    }

    if (async_->running.load(std::memory_order_acquire)) {
        // A target/patch/knowledge change cannot invalidate worker memory (the
        // worker owns a clone), but it should stop work whose result is stale.
        // The request key itself is held by the eventual completion; cancellation
        // is also rechecked when that completion is adopted.
        if (!keyMatches(async_->activeKey)) {
            async_->cancel.store(true, std::memory_order_release);
            async_->notice = "Cancelling stale Cortex analysis...";
        }
        ctx.wantContinuousRedraw = true;
        return;
    }

    if (async_->worker.joinable()) async_->worker.join();

    AsyncState::Completion completion;
    {
        std::lock_guard<std::mutex> lk(async_->completionMutex);
        if (!async_->completionReady) return;
        completion = std::move(async_->completion);
        async_->completionReady = false;
    }

    // Cancellation and failure are results too. Reject them against the full
    // document identity before mutating the active document's status surface.
    if (!keyMatches(completion.key)) {
        async_->notice = "Discarded a stale Cortex result after the target changed.";
        async_->error.clear();
        return;
    }
    if (completion.cancelled) {
        async_->notice = "Cortex analysis cancelled.";
        async_->error.clear();
        return;
    }
    if (!completion.success) {
        async_->error = completion.error.empty()
            ? "Cortex analysis did not produce a result."
            : std::move(completion.error);
        async_->notice.clear();
        return;
    }
    caps_ = std::move(completion.caps);
    algos_ = std::move(completion.algos);
    funcs_ = std::move(completion.funcs);
    strings_ = std::move(completion.strings);
    funcInfo_ = std::move(completion.funcInfo);
    xref_ = std::move(completion.xref);
    crackmeTriage_ = std::move(completion.crackmeTriage);
    rep_ = std::move(completion.report);
    analyzed_ = true;
    analyzedIdentity_ = completion.key.image;
    analyzedKnowledge_ = completion.key.knowledge;
    analyzedEngine_ = completion.key.decoder.engine;
    analyzedArch_ = completion.key.decoder.arch;
    behSel_ = rep_.behaviors.empty() ? -1 : 0;
    chat_.clear();
    async_->notice = "Cortex analysis complete.";
    async_->error.clear();
}

void CortexTab::ask(AppContext& ctx, const std::string& q) {
    if (q.empty() || !analyzed_) return;
    std::string a = AskCortex(rep_, inputFor(ctx), q);
    chat_.emplace_back(q, a);
    scrollChat_ = true;
}

void CortexTab::render(AppContext& ctx) {
    const float scale = theme::UiScale();
    ImGui::TextUnformatted("Cortex");
    ui::SameLineIfFits(260.0f * scale);
    ImGui::TextDisabled("Static findings and questions");
    const DocumentResultIdentity currentIdentity = currentCortexIdentity(ctx);
    if (observedIdentity_ != currentIdentity) {
        // Cortex is an app-wide tab today, so explicitly retire every cached
        // per-document view when the active image changes. The worker owns its
        // snapshot and pumpAnalysis() below will cancel/discard it by key.
        caps_.clear();
        algos_.clear();
        funcs_.clear();
        strings_.clear();
        funcInfo_.clear();
        xref_.clear();
        crackmeTriage_ = {};
        rep_ = {};
        analyzed_ = false;
        analyzedIdentity_ = {};
        behSel_ = -1;
        chat_.clear();
        async_->notice.clear();
        async_->error.clear();
        observedIdentity_ = currentIdentity;
    }
    pumpAnalysis(ctx);
    if (!ctx.staticBinary().loaded()) {
        if (ui::EmptyState(DS_ICON_CODE, "No binary loaded",
                           "Open a binary and Cortex will read it: what it does, its behaviours, and a per-function brief you can chat with.",
                           "Open Binary..."))
            ctx.openBinaryDialog();
        return;
    }
    // The report is keyed to the binary's content — invalidate it if the binary changed.
    if (analyzed_ &&
        (!SameDocumentResultImage(analyzedIdentity_, currentIdentity) ||
         analyzedKnowledge_ != projectKnowledgeSignature(ctx.staticProject()) ||
         analyzedEngine_ != ctx.staticEngine() ||
         analyzedArch_ != ctx.staticArch()))
        analyzed_ = false;

    bool busy = async_->staging || async_->running.load(std::memory_order_acquire);
    if (busy) {
        if (ui::ToolbarIconButton(DS_ICON_STOP, "Cancel", "Cancel Cortex analysis"))
            cancelAnalysis();
    } else if (ui::ToolbarIconButton(
                   DS_ICON_LIGHTNING, analyzed_ ? "Re-analyze" : "Analyze",
                   "Read the binary on a background worker and reason over it")) {
        analyze(ctx);
        busy = async_->staging || async_->running.load(std::memory_order_acquire);
    }
    if (analyzed_) {
        ui::SameLineIfFits(100.0f * scale);
        if (ui::ToolbarIconButton(DS_ICON_SAVE, "Export", "Save this Cortex report as Markdown / HTML")) {
            std::string md = RenderCortexMarkdown(rep_);
            std::string html = RenderCortexHtml(rep_);
            std::string msg;
            if (ctx.exportAnalysisFile("cortex-report", md, html, msg))
                ui::Toast(ui::ToastKind::Success, msg);
            else if (!msg.empty())
                ui::Toast(ui::ToastKind::Warn, msg);
        }
    }
    ui::SameLineIfFits(240.0f * scale);
    if (busy) {
        const auto phase = static_cast<AsyncState::Phase>(
            async_->phase.load(std::memory_order_acquire));
        const char* phaseText = "working";
        switch (phase) {
            case AsyncState::Phase::Snapshot:     phaseText = "snapshotting image"; break;
            case AsyncState::Phase::Loading:      phaseText = "loading private image"; break;
            case AsyncState::Phase::Strings:      phaseText = "scanning strings"; break;
            case AsyncState::Phase::Functions:    phaseText = "discovering functions"; break;
            case AsyncState::Phase::Xrefs:        phaseText = "building xrefs"; break;
            case AsyncState::Phase::Capabilities: phaseText = "detecting capabilities"; break;
            case AsyncState::Phase::Algorithms:   phaseText = "matching algorithms"; break;
            case AsyncState::Phase::Annotations:  phaseText = "annotating functions"; break;
            case AsyncState::Phase::Triage:       phaseText = "ranking static endpoint trails"; break;
            case AsyncState::Phase::Report:       phaseText = "building report"; break;
            case AsyncState::Phase::Idle:         break;
        }
        ImGui::TextDisabled("%s", phaseText);
    } else if (analyzed_) ImGui::TextDisabled("%d behaviour%s · %zu functions",
                                       (int)rep_.behaviors.size(), rep_.behaviors.size() == 1 ? "" : "s",
                                       rep_.functions.size());
    else           ImGui::TextDisabled("not analyzed");
    ImGui::Separator();

    if (busy) {
        const uint32_t current = async_->progress.load(std::memory_order_relaxed);
        const uint32_t total = async_->total.load(std::memory_order_relaxed);
        if (total) {
            const float fraction = std::min(1.0f, (float)current / (float)total);
            ImGui::ProgressBar(fraction, ImVec2(-1.0f, 0.0f));
        } else {
            const float time = (float)ImGui::GetTime();
            ImGui::ProgressBar(time - (float)(long long)time,
                               ImVec2(-1.0f, 0.0f), "");
        }
        ImGui::TextDisabled("Analysis owns a private image and may be cancelled safely.");
        return;
    }
    if (!async_->error.empty()) {
        ImGui::PushTextWrapPos(0.0f);
        ImGui::TextColored(theme::col::bad(), "%s", async_->error.c_str());
        ImGui::PopTextWrapPos();
        ImGui::Separator();
    } else if (!async_->notice.empty() && !analyzed_) {
        ImGui::TextDisabled("%s", async_->notice.c_str());
        ImGui::Separator();
    }

    if (!analyzed_) {
        if (ui::EmptyState(DS_ICON_CODE, "Ready to analyze",
                           "Cortex aggregates capabilities, crypto/algorithm matches, and heuristic function names into a plain-English read of this binary.",
                           "Analyze"))
            analyze(ctx);
        return;
    }

    // ---- Verdict header ----
    ImGui::PushTextWrapPos(0.0f);
    ImGui::PushStyleColor(ImGuiCol_Text, theme::col::accent());
    ImGui::TextUnformatted(rep_.headline.c_str());
    ImGui::PopStyleColor();
    ImGui::TextWrapped("%s", rep_.verdict.c_str());
    ImGui::PopTextWrapPos();
    if (!rep_.facts.empty()) {
        std::string facts;
        for (size_t i = 0; i < rep_.facts.size(); ++i) { if (i) facts += "    ·    "; facts += rep_.facts[i]; }
        ImGui::PushTextWrapPos();
        ImGui::TextColored(theme::col::muted(), "%s", facts.c_str());
        ImGui::PopTextWrapPos();
    }
    ImGui::Separator();

    // ---- Retained IDE panes: behaviours | functions, over Ask Cortex ----
    ImVec2 avail = ImGui::GetContentRegionAvail();
    avail.y = std::max(280.0f * scale, avail.y);
    const ImVec2 layoutStart = ImGui::GetCursorPos();
    const float split = 6.0f * scale;
    const float contentH = std::max(1.0f, avail.y - split);
    const float minUpper = std::min(120.0f * scale, contentH * 0.48f);
    const float minChat = std::min(92.0f * scale, contentH * 0.38f);
    const float minChatRatio = minChat / contentH;
    const float maxChatRatio = std::max(minChatRatio, 1.0f - minUpper / contentH);
    chatPaneRatio_ = std::clamp(chatPaneRatio_, minChatRatio, maxChatRatio);
    const float upperH = contentH * (1.0f - chatPaneRatio_);
    const float chatH = contentH - upperH;

    const float contentW = std::max(1.0f, avail.x - split);
    const float minColumn = std::min(180.0f * scale, contentW * 0.44f);
    const float minColumnRatio = minColumn / contentW;
    behaviorPaneRatio_ = std::clamp(
        behaviorPaneRatio_, minColumnRatio,
        std::max(minColumnRatio, 1.0f - minColumnRatio));
    const float behaviorW = contentW * behaviorPaneRatio_;

    ImGui::SetCursorPos(layoutStart);
    ImGui::BeginChild("cx_beh", ImVec2(behaviorW, upperH), ImGuiChildFlags_None);
    ImGui::SeparatorText("Behaviours");
    if (ImGui::BeginTable("cx_behtbl", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                                        ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Behaviour");
        ImGui::TableSetupColumn("%", ImGuiTableColumnFlags_WidthFixed, 40.0f * scale);
        ImGui::TableSetupColumn("Evidence");
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        for (int i = 0; i < (int)rep_.behaviors.size(); ++i) {
            const CortexBehavior& b = rep_.behaviors[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(b.title.c_str(), behSel_ == i, ImGuiSelectableFlags_SpanAllColumns))
                behSel_ = i;
            if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left) && !b.addresses.empty())
                ctx.gotoAddress(b.addresses.front());
            if (ImGui::IsItemHovered() && !b.explanation.empty()) ImGui::SetTooltip("%s", b.explanation.c_str());
            ImGui::TableSetColumnIndex(1);
            ImVec4 col = b.confidence > 0.80f ? theme::col::good()
                       : b.confidence > 0.60f ? theme::col::warn() : theme::col::bad();
            ImGui::TextColored(col, "%.0f", b.confidence * 100.0f);
            ImGui::TableSetColumnIndex(2);
            if (!b.specifics.empty()) {
                std::string sp;
                for (size_t k = 0; k < b.specifics.size() && k < 4; ++k) { if (k) sp += ", "; sp += b.specifics[k]; }
                ImGui::TextColored(theme::col::warn(), "%s", sp.c_str());
                if (ImGui::IsItemHovered() && !b.evidence.empty()) ImGui::SetTooltip("%s", b.evidence.c_str());
            } else {
                ImGui::TextDisabled("%s", b.evidence.c_str());
            }
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    drawVerticalSplitter("##cx_report_split",
                         ImVec2(layoutStart.x + behaviorW, layoutStart.y),
                         upperH, split, contentW, behaviorPaneRatio_,
                         minColumnRatio,
                         std::max(minColumnRatio, 1.0f - minColumnRatio));
    ImGui::SetCursorPos(ImVec2(layoutStart.x + behaviorW + split, layoutStart.y));
    ImGui::BeginChild("cx_hi", ImVec2(contentW - behaviorW, upperH), ImGuiChildFlags_None);
    ImGui::SeparatorText("Notable functions");
    if (ImGui::BeginTable("cx_hitbl", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                                       ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Function", ImGuiTableColumnFlags_WidthFixed, 150.0f * scale);
        ImGui::TableSetupColumn("What it looks like");
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        for (const CortexFuncBrief& f : rep_.highlights) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushStyleColor(ImGuiCol_Text, f.guessed ? theme::col::warn() : ImGui::GetStyleColorVec4(ImGuiCol_Text));
            ImGui::PushID((void*)(uintptr_t)f.address);
            bool clicked = ImGui::Selectable(f.name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns);
            ImGui::PopID();
            ImGui::PopStyleColor();
            if (clicked) ctx.gotoAddress(f.address); // VA 0 is valid for raw/ELF images
            if (ImGui::IsItemHovered() && !f.basis.empty()) ImGui::SetTooltip("%s", f.basis.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextDisabled("%s", f.brief.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    drawHorizontalSplitter("##cx_chat_split",
                           ImVec2(layoutStart.x, layoutStart.y + upperH),
                           avail.x, split, contentH, chatPaneRatio_,
                           minChatRatio, maxChatRatio);

    // ---- Ask Cortex: flat lower pane with a two-row compact composer ----
    ImGui::SetCursorPos(ImVec2(layoutStart.x, layoutStart.y + upperH + split));
    ImGui::BeginChild("cx_chat", ImVec2(avail.x, chatH), ImGuiChildFlags_None);
    ImGui::SeparatorText("Ask Cortex");

    const float composerH = ImGui::GetFrameHeightWithSpacing() * 2.0f;
    ImGui::BeginChild("cx_chatlog", ImVec2(0, -composerH), ImGuiChildFlags_None);
    ImGui::PushTextWrapPos(0.0f);
    for (const auto& qa : chat_) {
        ImGui::TextColored(theme::col::accent(), "you: %s", qa.first.c_str());
        ImGui::TextWrapped("%s", qa.second.c_str());
        ImGui::Spacing();
    }
    if (scrollChat_) { ImGui::SetScrollHereY(1.0f); scrollChat_ = false; }
    ImGui::PopTextWrapPos();
    ImGui::EndChild();

    // Quick-ask chips.
    struct Chip { const char* label; const char* q; };
    static const Chip chips[] = {
        { "Summary",  "what does it do?" },
        { "Crypto?",  "does it use crypto?" },
        { "Network?", "what network apis does it use?" },
        { "Packed?",  "is it packed?" },
        { "Strings",  "show notable strings" },
    };
    for (int i = 0; i < (int)(sizeof(chips) / sizeof(chips[0])); ++i) {
        if (i) ImGui::SameLine();
        if (ImGui::SmallButton(chips[i].label)) ask(ctx, chips[i].q);
    }

    ImGui::SetNextItemWidth(-70.0f * scale);
    bool enter = ImGui::InputTextWithHint("##cx_ask", "ask about this binary...", input_, sizeof(input_),
                                          ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    bool send = ImGui::Button("Ask", ImVec2(60.0f * scale, 0));
    if (enter || send) {
        ask(ctx, input_);
        input_[0] = '\0';
        ImGui::SetKeyboardFocusHere(-1);
    }
    ImGui::EndChild();
}

} // namespace ds
