#include "Core/DocumentContext.h"
#include "Core/PatchedImage.h"

#include <atomic>
#include <cassert>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace ds;
using namespace std::chrono_literals;

namespace {

struct DecodeGate {
    std::mutex mutex;
    std::condition_variable changed;
    bool block = false;
    bool entered = false;
    bool release = false;
};

class TestDecoder final : public IDisassembler {
public:
    TestDecoder(Engine engine, std::shared_ptr<DecodeGate> gate)
        : engine_(engine), gate_(std::move(gate)) {}

    Engine engine() const override { return engine_; }
    const char* engineName() const override { return "document-test"; }

    std::vector<Instruction> disassemble(const uint8_t* data, size_t size,
                                         uint64_t va,
                                         size_t maxInstructions = 0) override {
        std::vector<Instruction> result;
        for (size_t offset = 0; offset < size &&
             (!maxInstructions || result.size() < maxInstructions);) {
            Instruction instruction;
            if (!decodeOne(data + offset, size - offset, va + offset, instruction)) break;
            offset += instruction.length;
            result.push_back(std::move(instruction));
        }
        return result;
    }

    bool decodeOne(const uint8_t* data, size_t size, uint64_t va,
                   Instruction& out) override {
        if (!data || !size) return false;
        if (gate_) {
            std::unique_lock<std::mutex> lock(gate_->mutex);
            if (gate_->block && !gate_->release) {
                gate_->entered = true;
                gate_->changed.notify_all();
                gate_->changed.wait(lock, [&] { return gate_->release; });
            }
        }
        out = {};
        out.address = va;
        out.length = 1;
        out.bytes = "90";
        out.mnemonic = "nop";
        return true;
    }

private:
    Engine engine_;
    std::shared_ptr<DecodeGate> gate_;
};

std::filesystem::path makeRawFixture(uint8_t fill = 0x90) {
    const auto serial = std::chrono::high_resolution_clock::now()
                            .time_since_epoch().count();
    const auto path = std::filesystem::temp_directory_path() /
                      ("disasmstudio_document_context_" +
                       std::to_string(serial) + ".bin");
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    const std::vector<uint8_t> bytes(256, fill);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    out.close();
    assert(out.good());
    return path;
}

template <typename T>
void putOrder(std::vector<uint8_t>& bytes, size_t offset, T value,
              bool bigEndian = false) {
    for (size_t i = 0; i < sizeof(T); ++i) {
        const size_t destination = bigEndian ? sizeof(T) - 1 - i : i;
        bytes[offset + destination] = static_cast<uint8_t>(
            (static_cast<uint64_t>(value) >> (i * 8)) & 0xffu);
    }
}

std::filesystem::path makeElf32Fixture(uint16_t machine, uint32_t flags,
                                       bool bigEndian = false) {
    std::vector<uint8_t> bytes(0x100, 0);
    std::memcpy(bytes.data(), "\x7f" "ELF", 4);
    bytes[4] = 1; bytes[5] = bigEndian ? 2 : 1; bytes[6] = 1;
    putOrder<uint16_t>(bytes, 16, 2, bigEndian);
    putOrder<uint16_t>(bytes, 18, machine, bigEndian);
    putOrder<uint32_t>(bytes, 20, 1, bigEndian);
    putOrder<uint32_t>(bytes, 24, 0x10080, bigEndian);
    putOrder<uint32_t>(bytes, 28, 52, bigEndian);
    putOrder<uint32_t>(bytes, 36, flags, bigEndian);
    putOrder<uint16_t>(bytes, 40, 52, bigEndian);
    putOrder<uint16_t>(bytes, 42, 32, bigEndian);
    putOrder<uint16_t>(bytes, 44, 1, bigEndian);
    putOrder<uint32_t>(bytes, 52, 1, bigEndian); // PT_LOAD
    putOrder<uint32_t>(bytes, 60, 0x10000, bigEndian);
    putOrder<uint32_t>(bytes, 64, 0x10000, bigEndian);
    putOrder<uint32_t>(bytes, 68, static_cast<uint32_t>(bytes.size()), bigEndian);
    putOrder<uint32_t>(bytes, 72, static_cast<uint32_t>(bytes.size()), bigEndian);
    putOrder<uint32_t>(bytes, 76, 5, bigEndian);
    putOrder<uint32_t>(bytes, 80, 0x1000, bigEndian);
    bytes[0x80] = 0x90;

    const auto serial = std::chrono::high_resolution_clock::now()
                            .time_since_epoch().count();
    const auto path = std::filesystem::temp_directory_path() /
        ("disasmstudio_document_elf_" + std::to_string(serial) + ".bin");
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    out.close();
    assert(out.good());
    return path;
}

} // namespace

int main() {
    auto gate = std::make_shared<DecodeGate>();
    auto rejectDecoder = std::make_shared<std::atomic<bool>>(false);
    auto factory = [gate, rejectDecoder](Engine engine, Arch) {
        if (rejectDecoder->load())
            throw std::runtime_error("injected decoder failure");
        return std::make_unique<TestDecoder>(engine, gate);
    };
    auto acceptingStore = [](const BinaryFile&, const ProjectState&,
                             std::string&) { return true; };

    // The historical default remains bounded and explicit requests are clamped.
    {
        AnalysisService automatic(factory);
        assert(automatic.workerCount() >= 1);
        assert(automatic.workerCount() <= AnalysisService::kMaxWorkerCount);
        AnalysisService clamped(factory, 999);
        assert(clamped.workerCount() == AnalysisService::kMaxWorkerCount);
    }

    // Stable monotone identities, an explicit limit, and deterministic selection.
    DocumentManager manager(factory, acceptingStore);
    std::vector<DocumentId> ids;
    for (size_t i = 0; i < DocumentManager::kMaxDocuments; ++i) {
        auto id = manager.create("doc-" + std::to_string(i));
        assert(id);
        ids.push_back(*id);
        assert(manager.activeId() == id);
    }
    assert(!manager.create("ninth"));
    for (size_t i = 0; i < ids.size(); ++i)
        assert(ids[i].value == i + 1);

    assert(manager.activate(ids[2]));
    assert(manager.close(ids[4]));             // inactive removal preserves selection
    assert(manager.activeId() == ids[2]);
    assert(manager.close(ids[2]));             // successor slides into active slot
    assert(manager.activeId() == ids[3]);
    assert(!manager.activate(ids[2]));
    assert(manager.activate(ids.back()));
    assert(manager.close(ids.back()));          // final slot deterministically selects predecessor
    assert(manager.activeId() == ids[6]);

    DocumentContext* first = manager.find(ids[0]);
    DocumentContext* second = manager.find(ids[1]);
    assert(first && second);
    assert(first->analysis().workerCount() == 1);
    assert(second->analysis().workerCount() == 1);

    // VA zero remains a first-class current/back/forward location.
    first->navigation().navigateTo(0, DocumentView::Hex);
    assert(first->navigation().current().valid);
    assert(first->navigation().current().va == 0);
    first->navigation().navigateTo(0x20, DocumentView::Assembly);
    assert(first->navigation().goBack());
    assert(first->navigation().current().valid);
    assert(first->navigation().current().va == 0);
    assert(first->navigation().current().view == DocumentView::Hex);
    assert(first->navigation().goForward());
    assert(first->navigation().current().va == 0x20);
    assert(!second->navigation().current().valid); // per-document isolation

    // FILE/LIVE identity is explicit and independent of address validity. A
    // live address at zero therefore cannot alias a file-space location.
    first->navigation().navigateTo(0, DocumentView::LiveAssembly,
                                   DocumentAddressSpace::Live);
    assert(first->navigation().current().valid);
    assert(first->navigation().current().va == 0);
    assert(first->navigation().current().view == DocumentView::LiveAssembly);
    assert(first->navigation().current().addressSpace == DocumentAddressSpace::Live);
    {
        DocumentNavigation navigation;
        // Selection updates the source anchor without inventing a history jump.
        navigation.replaceCurrent({0, true, DocumentView::Assembly, DocumentAddressSpace::File});
        navigation.replaceCurrent({8, true, DocumentView::Graph, DocumentAddressSpace::File});
        assert(navigation.backStack().empty());
        navigation.navigateTo(16, DocumentView::Pseudocode);
        assert(navigation.goBack());
        assert(navigation.current().va == 8 && navigation.current().view == DocumentView::Graph);
        assert(navigation.goForward());
        assert(navigation.current().va == 16 && navigation.current().view == DocumentView::Pseudocode);
        assert(navigation.goBack());
        navigation.navigateTo(0, DocumentView::Hex, DocumentAddressSpace::FileOffset);
        assert(navigation.forwardStack().empty());
        assert(navigation.current().valid && navigation.current().va == 0);
        assert(navigation.current().addressSpace == DocumentAddressSpace::FileOffset);
        navigation.navigateTo(0, DocumentView::Assembly);
        assert(navigation.goBack());
        assert(navigation.current().addressSpace == DocumentAddressSpace::FileOffset);
        assert(navigation.goForward());

        const DebugTargetIdentity oldTarget{55, 2}, newTarget{55, 3};
        navigation.navigateTo(0, DocumentView::LiveAssembly, DocumentAddressSpace::Live, oldTarget);
        navigation.navigateTo(24, DocumentView::Assembly);
        navigation.navigateTo(32, DocumentView::LiveAssembly, DocumentAddressSpace::Live, newTarget);
        navigation.retireLiveLocations(newTarget);
        assert(navigation.current().va == 32);
        for (const auto& entry : navigation.backStack())
            assert(entry.addressSpace != DocumentAddressSpace::Live ||
                   DebugTargetIdentityMatches(entry.target, newTarget));
        navigation.retireLiveLocations();
        assert(navigation.current().va == 24 && navigation.current().addressSpace == DocumentAddressSpace::File);
        assert(navigation.goBack());
        assert(navigation.current().va == 0 && navigation.current().addressSpace == DocumentAddressSpace::File);

        navigation.clear();
        for (uint64_t i = 0; i < 2000; ++i) navigation.navigateTo(i);
        assert(navigation.backStack().size() == DocumentNavigation::kHistoryLimit);
        size_t steps = 0;
        while (navigation.goBack()) ++steps;
        assert(steps == DocumentNavigation::kHistoryLimit);
        assert(navigation.forwardStack().size() == DocumentNavigation::kHistoryLimit);
        assert(navigation.current().va == 1999 - DocumentNavigation::kHistoryLimit);
        const auto unchanged = navigation.current();
        navigation.navigateTo(DocumentLocation{});
        assert(navigation.current() == unchanged);
    }
    second->navigation().navigateTo(0, DocumentView::Assembly,
                                    DocumentAddressSpace::File);
    assert(manager.activate(ids[0]));
    assert(manager.active() == first);
    assert(manager.active()->navigation().current().valid);
    assert(manager.active()->navigation().current().va == 0);
    assert(manager.active()->navigation().current().addressSpace ==
           DocumentAddressSpace::Live);
    assert(manager.activate(ids[1]));
    assert(manager.active() == second);
    assert(manager.active()->navigation().current().valid);
    assert(manager.active()->navigation().current().va == 0);
    assert(manager.active()->navigation().current().addressSpace ==
           DocumentAddressSpace::File);

    first->editProject().notes = "owned by document one";
    first->cache().imageRevision = 99;
    assert(second->project().notes.empty());
    assert(second->cache().imageRevision == 0);
    assert(manager.clear());
    assert(manager.empty() && !manager.activeId());

    const auto fixture = makeRawFixture();

    // Configuration-aware factories receive byte order and feature bits, and
    // the exact Raw choices survive the durable project snapshot.
    {
        auto lastConfig = std::make_shared<DecoderConfig>();
        ProjectState savedConfig;
        DocumentContext configured(
            DocumentId{99}, "configured raw",
            DocumentContext::DecoderFactory(
                [gate, lastConfig](const DecoderConfig& config) {
                    *lastConfig = config;
                    return std::make_unique<TestDecoder>(config.engine, gate);
                }),
            Engine::Zydis, Arch::X64,
            [&](const BinaryFile&, const ProjectState& snapshot, std::string&) {
                savedConfig = snapshot;
                return true;
            });
        DecoderConfig selected;
        selected.engine = Engine::Capstone;
        selected.arch = Arch::MIPS64;
        selected.byteOrder = ByteOrder::Big;
        selected.features.riscvCompressed = false;
        selected.features.armV8 = true;
        selected.features.armMClass = true;
        selected.features.mipsMicro = true;
        assert(configured.loadRaw(fixture.string(), 0, selected, 0, true));
        assert(*lastConfig == selected);
        assert(configured.decoderConfig() == selected);
        assert(configured.flush());
        assert(savedConfig.rawMappingSaved);
        assert(savedConfig.rawBigEndian);
        assert(!savedConfig.rawRiscvCompressed);
        assert(savedConfig.rawDecoderFeatureBits ==
               DecoderFeatureBits(selected.features));
        DecoderFeatures restoredFeatures;
        assert(DecoderFeaturesFromBits(savedConfig.rawDecoderFeatureBits,
                                       restoredFeatures));
        assert(restoredFeatures == selected.features);
    }

    // Structured ELF metadata overrides contrary caller defaults, while the
    // Raw case above retains every analyst-selected feature bit unchanged.
    {
        auto observed = std::make_shared<DecoderConfig>();
        DocumentContext configured(
            DocumentId{100}, "configured ELF",
            DocumentContext::DecoderFactory(
                [gate, observed](const DecoderConfig& config) {
                    *observed = config;
                    return std::make_unique<TestDecoder>(config.engine, gate);
                }),
            Engine::Capstone, Arch::RISCV32, acceptingStore);

        auto install = [&](uint16_t machine, uint32_t flags, bool bigEndian,
                           DecoderConfig requested) {
            const auto path = makeElf32Fixture(machine, flags, bigEndian);
            BinaryFile image;
            assert(image.load(path.string()));
            std::error_code ec;
            std::filesystem::remove(path, ec);
            ProjectState project;
            assert(configured.replaceImage(
                std::move(image), std::move(project), requested,
                DocumentInstallPersistence::RequiresInitialSave));
        };

        DecoderConfig rvc;
        rvc.engine = Engine::Capstone;
        rvc.arch = Arch::X64; // structured e_machine is authoritative
        rvc.features.riscvCompressed = false; // contradict EF_RISCV_RVC
        install(0xF3, 0x1, false, rvc);
        assert(observed->arch == Arch::RISCV32);
        assert(configured.decoderConfig().arch == Arch::RISCV32);
        assert(observed->features.riscvCompressed);
        assert(configured.decoderConfig().features.riscvCompressed);

        DecoderConfig baseRv = rvc;
        baseRv.features.riscvCompressed = true; // contradict a clear e_flags bit
        install(0xF3, 0, false, baseRv);
        assert(!observed->features.riscvCompressed);
        assert(!configured.decoderConfig().features.riscvCompressed);

        DecoderConfig microMips;
        microMips.engine = Engine::Capstone;
        microMips.arch = Arch::X64; // contradict ELF EM_MIPS
        microMips.features.mipsMicro = false; // contradict EF_MIPS_MICROMIPS
        install(0x08, 0x02000000u, false, microMips);
        assert(observed->arch == Arch::MIPS);
        assert(configured.decoderConfig().arch == Arch::MIPS);
        assert(observed->features.mipsMicro);
        assert(configured.decoderConfig().features.mipsMicro);

        DecoderConfig ppc;
        ppc.engine = Engine::Capstone;
        ppc.arch = Arch::X86; // contradict ELF EM_PPC
        ppc.byteOrder = ByteOrder::Little; // contradict EI_DATA=MSB
        install(0x14, 0, true, ppc);
        assert(observed->arch == Arch::PPC);
        assert(configured.decoderConfig().arch == Arch::PPC);
        assert(observed->byteOrder == ByteOrder::Big);
        assert(configured.decoderConfig().byteOrder == ByteOrder::Big);
    }

    // A fresh raw installation is dirty by construction: its exact mapping is
    // durably committed on the next transition even when the analyst makes no
    // annotation edit. A ticket from that image cannot acknowledge a later
    // installation in the same document.
    size_t initialSaveCalls = 0;
    ProjectState initialSnapshot;
    DocumentManager initialSaveManager(factory,
        [&](const BinaryFile&, const ProjectState& snapshot,
            std::string&) {
            ++initialSaveCalls;
            initialSnapshot = snapshot;
            return true;
        });
    const auto initialId = initialSaveManager.create("fresh raw");
    const auto transitionId = initialSaveManager.create("transition target");
    assert(initialId && transitionId);
    assert(initialSaveManager.activate(*initialId));
    DocumentContext* initialDocument = initialSaveManager.find(*initialId);
    assert(initialDocument);
    std::vector<AnalysisLandmark> initialLandmarks = {
        {0x8010, "firmware_entry", "test evidence"}
    };
    assert(initialDocument->loadRaw(
        fixture.string(), 0x8000, Engine::Zydis, Arch::X64, 0x8000, true,
        std::move(initialLandmarks)));
    assert(initialDocument->persistence() ==
           DocumentInstallPersistence::RequiresInitialSave);
    assert(initialDocument->dirty());
    assert(initialDocument->saveState() == DocumentSaveState::Dirty);
    assert(initialSaveCalls == 0);
    const DocumentSaveTicket firstImageTicket =
        initialDocument->externalSaveTicket();
    assert(initialSaveManager.activate(*transitionId));
    assert(initialSaveCalls == 1);
    assert(!initialDocument->dirty());
    assert(initialSnapshot.rawMappingSaved);
    assert(initialSnapshot.rawImageBase == 0x8000);
    assert(initialSnapshot.rawEntryExplicit);
    assert(initialSnapshot.rawEntry == 0x8000);
    assert(initialSnapshot.rawLandmarks.size() == 1);
    assert(initialSnapshot.rawLandmarks[0].address == 0x8010);
    assert(initialSaveManager.activate(*initialId));
    initialDocument->editProject().notes = "older async snapshot";
    const DocumentSaveTicket olderTicket =
        initialDocument->externalSaveTicket();
    initialDocument->editProject().notes = "newer async snapshot";
    const DocumentSaveTicket newerTicket =
        initialDocument->externalSaveTicket();
    assert(initialDocument->acknowledgeExternalSave(newerTicket));
    const uint64_t newerSavedRevision = initialDocument->savedRevision();
    assert(initialDocument->acknowledgeExternalSave(olderTicket));
    assert(initialDocument->savedRevision() == newerSavedRevision);
    assert(!initialDocument->dirty());
    assert(initialDocument->loadRaw(fixture.string(), 0x9000,
                                    Engine::Zydis, Arch::X64,
                                    0x9000, true));
    assert(!initialDocument->acknowledgeExternalSave(firstImageTicket));
    assert(initialDocument->dirty());

    BinaryFile ephemeralImage;
    assert(ephemeralImage.loadRaw(fixture.string(), 0xA000));
    ProjectState ephemeralProject;
    assert(initialDocument->replaceImage(
        std::move(ephemeralImage), std::move(ephemeralProject),
        Engine::Zydis, Arch::X64,
        DocumentInstallPersistence::Ephemeral));
    assert(initialDocument->persistence() ==
           DocumentInstallPersistence::Ephemeral);
    assert(!initialDocument->dirty());
    assert(initialDocument->saveState() == DocumentSaveState::Clean);
    initialDocument->editProject().notes = "session only";
    assert(initialDocument->dirty());
    const size_t beforeEphemeralTransition = initialSaveCalls;
    assert(initialSaveManager.activate(*transitionId));
    assert(initialSaveCalls == beforeEphemeralTransition);
    assert(!initialDocument->dirty());
    assert(initialDocument->saveState() == DocumentSaveState::Clean);
    assert(initialSaveManager.clear());

    // A real analysis worker holds a borrowed BinaryFile pointer. Removing the
    // document must wait for that worker before clearing and destroying storage.
    DocumentManager lifecycleManager(factory, acceptingStore);
    const auto lifecycleId = lifecycleManager.create("lifecycle");
    assert(lifecycleId);
    DocumentContext* document = lifecycleManager.find(*lifecycleId);
    assert(document);
    assert(document->loadRaw(fixture.string(), 0, Engine::Zydis, Arch::X64,
                             0, true));
    assert(document->binary().loaded());
    assert(document->binary().hasEntryPoint());
    assert(document->binary().entryPointVA() == 0);
    assert(document->analysis().workerCount() == 1);
    {
        const uint64_t cacheEpoch = document->analysis().epoch();
        auto triage = std::make_shared<CrackmeTriageReport>();
        triage->endpoints.push_back({});
        document->cache().imageRevision = document->binary().imageRevision();
        document->cache().analysisEpoch = cacheEpoch;
        document->cache().crackmeTriage = triage;
        document->cache().strings = std::make_shared<const std::vector<StrResult>>();
        document->cache().stringsTruncated = true;
        assert(document->cache().matches(document->binary(), cacheEpoch));
        assert(document->cache().crackmeTriage &&
               document->cache().crackmeTriage->endpoints.size() == 1);
        const uint64_t nextEpoch = document->analysis().bumpEpoch();
        assert(!document->cache().matches(document->binary(), nextEpoch));
        document->cache().clear();
        assert(!document->cache().crackmeTriage);
        assert(!document->cache().strings && !document->cache().stringsTruncated);
    }
    document->editProject().notes = "must survive a rejected staged replacement";
    const uint64_t loadedRevision = document->binary().imageRevision();
    assert(!document->loadRaw(fixture.string(), 0, Engine::Zydis, Arch::X64,
                              0x1000, true));
    assert(document->binary().loaded());
    assert(document->binary().imageRevision() == loadedRevision);
    assert(document->project().notes ==
           "must survive a rejected staged replacement");

    BinaryFile mismatchedImage;
    assert(mismatchedImage.loadRaw(fixture.string(), 0));
    ProjectState mismatchedProject;
    mismatchedProject.hash = mismatchedImage.contentHash() ^ 0xA5A5u;
    assert(!document->replaceImage(std::move(mismatchedImage),
                                   std::move(mismatchedProject),
                                   Engine::Zydis, Arch::X64,
                                   DocumentInstallPersistence::DurableSnapshot));
    assert(document->binary().imageRevision() == loadedRevision);
    assert(document->project().notes ==
           "must survive a rejected staged replacement");

    // All decoder-building mutations are transactional even when a factory
    // throws: no worker barrier or state swap has happened yet.
    IDisassembler* const originalDecoder = document->decoder();
    const Engine originalEngine = document->engine();
    const Arch originalArch = document->arch();
    rejectDecoder->store(true);
    assert(!document->setDecoderConfiguration(Engine::Capstone, Arch::X86));
    assert(!document->loadFile(fixture.string(), Engine::Capstone, Arch::X86));
    assert(!document->loadRaw(fixture.string(), 0, Engine::Capstone, Arch::X86,
                              0, true));
    rejectDecoder->store(false);
    assert(document->decoder() == originalDecoder);
    assert(document->engine() == originalEngine);
    assert(document->arch() == originalArch);
    assert(document->binary().imageRevision() == loadedRevision);
    assert(document->project().notes ==
           "must survive a rejected staged replacement");

    // A caller-staged replacement preserves exact persisted analyst state and
    // all per-document wrapper/runtime/firmware metadata.
    BinaryFile stagedMetadataImage;
    assert(stagedMetadataImage.loadRaw(fixture.string(), 0));
    assert(stagedMetadataImage.setRawEntryPointVA(0));
    ProjectState stagedProject;
    stagedProject.hash = stagedMetadataImage.contentHash();
    stagedProject.notes = "persisted analyst state";
    DocumentRuntimeMetadata stagedMetadata;
    stagedMetadata.liveImage.valid = true;
    stagedMetadata.liveImage.pid = 4242;
    stagedMetadata.liveImage.sessionGeneration = 9;
    stagedMetadata.liveImage.moduleBase = 0x140000000ull;
    stagedMetadata.liveImage.moduleSize = 0x9000;
    stagedMetadata.liveImage.moduleName = "crackme.exe";
    stagedMetadata.liveImage.modulePath = "C:\\Lab\\crackme.exe";
    stagedMetadata.liveImage.moduleLoadGeneration = 3;
    stagedMetadata.java.detail = "java evidence";
    stagedMetadata.runtime.wrapperRuntime = "test runtime";
    stagedMetadata.firmware.kinds = FirmwareKind::LegacyBios;
    assert(document->replaceImage(std::move(stagedMetadataImage),
                                  std::move(stagedProject),
                                  Engine::Zydis, Arch::X64,
                                  DocumentInstallPersistence::DurableSnapshot,
                                  std::move(stagedMetadata)));
    assert(document->project().notes == "persisted analyst state");
    assert(document->javaInfo().detail == "java evidence");
    assert(document->runtimeInfo().wrapperRuntime == "test runtime");
    assert(document->firmwareInfo().kinds == FirmwareKind::LegacyBios);
    assert(document->runtimeMetadata().liveImage.valid);
    assert(document->runtimeMetadata().liveImage.pid == 4242);
    assert(document->runtimeMetadata().liveImage.sessionGeneration == 9);
    assert(document->runtimeMetadata().liveImage.moduleBase == 0x140000000ull);
    assert(document->runtimeMetadata().liveImage.moduleSize == 0x9000);
    assert(document->runtimeMetadata().liveImage.moduleName == "crackme.exe");
    assert(document->runtimeMetadata().liveImage.modulePath ==
           "C:\\Lab\\crackme.exe");
    assert(document->runtimeMetadata().liveImage.moduleLoadGeneration == 3);

    document->cache().imageRevision = loadedRevision;
    const uint8_t patched = 0xCC;
    assert(document->writeImage(0, &patched, 1) == 1); // VA zero mutation
    assert(document->binary().imageRevision() != loadedRevision);
    assert(document->cache().imageRevision == 0);
    assert(!document->runtimeMetadata().liveImage.valid);

    {
        std::lock_guard<std::mutex> lock(gate->mutex);
        gate->block = true;
        gate->entered = false;
        gate->release = false;
    }
    const uint64_t epoch = document->analysis().epoch();
    document->analysis().requestBulk(&document->binary(), document->engine(),
                                     document->arch(), K_Xref, false, epoch);
    {
        std::unique_lock<std::mutex> lock(gate->mutex);
        assert(gate->changed.wait_for(lock, 5s, [&] { return gate->entered; }));
    }

    auto removal = std::async(std::launch::async, [&] {
        return lifecycleManager.close(*lifecycleId);
    });
    assert(removal.wait_for(75ms) == std::future_status::timeout);
    // close() is still at its worker barrier, so borrowed image storage remains.
    assert(document->binary().loaded());
    {
        std::lock_guard<std::mutex> lock(gate->mutex);
        gate->release = true;
    }
    gate->changed.notify_all();
    assert(removal.wait_for(5s) == std::future_status::ready);
    assert(removal.get());
    assert(lifecycleManager.empty());
    assert(!lifecycleManager.activeId());
    assert(lifecycleManager.active() == nullptr);
    assert(lifecycleManager.at(0) == nullptr);
    assert(lifecycleManager.find(*lifecycleId) == nullptr);
    const auto afterOnlyCloseId = lifecycleManager.create("after-only-close");
    assert(afterOnlyCloseId && afterOnlyCloseId->value > lifecycleId->value);
    assert(lifecycleManager.size() == 1);
    assert(lifecycleManager.activeId() == afterOnlyCloseId);
    assert(lifecycleManager.active() == lifecycleManager.find(*afterOnlyCloseId));
    assert(lifecycleManager.close(*afterOnlyCloseId));
    assert(lifecycleManager.empty() && !lifecycleManager.activeId());

    // A dirty document cannot be replaced, deactivated, closed, or erased when
    // its injected durable store fails. Success retries the exact stamped
    // snapshot, including an explicit raw entry at VA zero.
    bool allowSave = false;
    size_t saveCalls = 0;
    std::string savedNotes;
    DocumentManager saveManager(factory,
        [&](const BinaryFile& image, const ProjectState& snapshot,
            std::string& error) {
            ++saveCalls;
            assert(image.loaded());
            assert(snapshot.hash == image.contentHash());
            assert(snapshot.binaryPath == image.path());
            if (!allowSave) {
                error = "injected save failure";
                return false;
            }
            assert(snapshot.rawMappingSaved);
            assert(snapshot.rawEntryExplicit);
            assert(snapshot.rawEntry == 0);
            savedNotes = snapshot.notes;
            return true;
        });
    const auto saveFirstId = saveManager.create("save-first");
    const auto saveSecondId = saveManager.create("save-second");
    assert(saveFirstId && saveSecondId);
    DocumentContext* saveFirst = saveManager.find(*saveFirstId);
    assert(saveFirst);
    assert(saveFirst->loadRaw(fixture.string(), 0, Engine::Zydis, Arch::X64,
                              0, true));
    assert(saveManager.activate(*saveFirstId));
    saveFirst->editProject().notes = "must reach durable storage";
    const uint64_t saveRevision = saveFirst->binary().imageRevision();

    BinaryFile rejectedReplacement;
    assert(rejectedReplacement.loadRaw(fixture.string(), 0x1000));
    ProjectState rejectedProject;
    rejectedProject.notes = "must not replace dirty state";
    assert(!saveFirst->replaceImage(std::move(rejectedReplacement),
                                    std::move(rejectedProject),
                                    Engine::Zydis, Arch::X64,
                                    DocumentInstallPersistence::RequiresInitialSave));
    assert(saveFirst->open());
    assert(saveFirst->binary().imageRevision() == saveRevision);
    assert(saveFirst->project().notes == "must reach durable storage");
    assert(saveFirst->saveState() == DocumentSaveState::Failed);

    std::string transitionError;
    assert(!saveManager.activate(*saveSecondId, {}, &transitionError));
    assert(transitionError == "injected save failure");
    assert(saveManager.activeId() == saveFirstId);
    assert(!saveManager.close(*saveFirstId, {}, &transitionError));
    assert(saveManager.size() == 2);
    assert(saveFirst->open() && saveFirst->binary().loaded());

    allowSave = true;
    assert(saveManager.activate(*saveSecondId, {}, &transitionError));
    assert(saveManager.activeId() == saveSecondId);
    assert(savedNotes == "must reach durable storage");
    assert(saveFirst->saveState() == DocumentSaveState::Clean);
    assert(saveCalls >= 3); // replacement + activation + close retry attempts

    // The controller's first transition phase can mirror UI state or reject a
    // switch before activeId changes.
    assert(saveManager.activate(*saveFirstId));
    bool prepareCalled = false;
    assert(!saveManager.activate(*saveSecondId,
        [&](DocumentContext& outgoing, std::string& error) {
            prepareCalled = true;
            assert(outgoing.id() == *saveFirstId);
            error = "UI mirror rejected transition";
            return false;
        }, &transitionError));
    assert(prepareCalled);
    assert(saveManager.activeId() == saveFirstId);
    assert(transitionError == "UI mirror rejected transition");
    size_t clearPrepareCalls = 0;
    assert(saveManager.clear(
        [&](DocumentContext& outgoing, std::string&) {
            ++clearPrepareCalls;
            assert(outgoing.id() == *saveFirstId);
            return true;
        }));
    assert(clearPrepareCalls == 1); // inactive documents are flushed, not UI-mirrored

    // A fully staged RequiresInitialSave candidate is still unpublished while
    // the outgoing transition callback runs. Rejecting that transition must
    // destroy it without ever enabling the manager's durable-store callback;
    // otherwise a sidecar could appear for a document the user never opened.
    const auto unpublishedSidecar = fixture.parent_path() /
        (fixture.filename().string() + ".unpublished-sidecar");
    std::error_code ignored;
    std::filesystem::remove(unpublishedSidecar, ignored);
    size_t unpublishedSaveCalls = 0;
    DocumentManager stagedFailureManager(factory,
        [&](const BinaryFile&, const ProjectState&, std::string&) {
            ++unpublishedSaveCalls;
            std::ofstream marker(unpublishedSidecar,
                                 std::ios::binary | std::ios::trunc);
            marker << "should never be published";
            return true;
        });
    const auto outgoingId = stagedFailureManager.create("outgoing");
    assert(outgoingId);
    BinaryFile unpublishedImage;
    assert(unpublishedImage.loadRaw(fixture.string(), 0));
    ProjectState unpublishedProject;
    unpublishedProject.hash = unpublishedImage.contentHash();
    const auto rejectedOpen = stagedFailureManager.openStaged(
        "unpublished", std::move(unpublishedImage),
        std::move(unpublishedProject), Engine::Zydis, Arch::X64,
        DocumentInstallPersistence::RequiresInitialSave, {},
        [&](DocumentContext& outgoing, std::string& error) {
            assert(outgoing.id() == *outgoingId);
            error = "injected pre-publication rejection";
            return false;
        });
    assert(!rejectedOpen);
    assert(rejectedOpen.status == DocumentManager::OpenStatus::TransitionBlocked);
    assert(rejectedOpen.error == "injected pre-publication rejection");
    assert(!rejectedOpen.id);
    assert(stagedFailureManager.size() == 1);
    assert(stagedFailureManager.activeId() == outgoingId);
    assert(unpublishedSaveCalls == 0);
    assert(!std::filesystem::exists(unpublishedSidecar));
    const auto postFailureId = stagedFailureManager.create("post-failure");
    assert(postFailureId && postFailureId->value == outgoingId->value + 1);
    assert(stagedFailureManager.size() == 2);
    assert(stagedFailureManager.clear());
    assert(unpublishedSaveCalls == 0);
    assert(!std::filesystem::exists(unpublishedSidecar));

    // The manager's staged-open path never admits a second loaded document with
    // the same pristine content hash; it activates the existing owner instead,
    // even when all eight slots are occupied. A unique staged ninth still fails.
    DocumentManager duplicateManager(factory);
    BinaryFile firstImage;
    assert(firstImage.loadRaw(fixture.string(), 0));
    ProjectState firstProject;
    firstProject.hash = firstImage.contentHash();
    firstProject.notes = "canonical document";
    auto firstOpen = duplicateManager.openStaged(
        "canonical", std::move(firstImage), std::move(firstProject),
        Engine::Zydis, Arch::X64,
        DocumentInstallPersistence::DurableSnapshot);
    assert(firstOpen);
    assert(firstOpen.status == DocumentManager::OpenStatus::Created);
    const auto unrelatedId = duplicateManager.create("unrelated scratch");
    assert(unrelatedId && duplicateManager.activeId() == unrelatedId);
    while (duplicateManager.size() < DocumentManager::kMaxDocuments) {
        const auto filler = duplicateManager.create(
            "cap filler " + std::to_string(duplicateManager.size()));
        assert(filler);
    }
    assert(duplicateManager.size() == DocumentManager::kMaxDocuments);
    const auto activeAtCap = duplicateManager.activeId();
    assert(activeAtCap && activeAtCap != firstOpen.id);

    const auto uniqueFixture = makeRawFixture(0x91);
    BinaryFile ninthImage;
    assert(ninthImage.loadRaw(uniqueFixture.string(), 0));
    ProjectState ninthProject;
    ninthProject.hash = ninthImage.contentHash();
    const auto ninthOpen = duplicateManager.openStaged(
        "unique ninth", std::move(ninthImage), std::move(ninthProject),
        Engine::Zydis, Arch::X64,
        DocumentInstallPersistence::DurableSnapshot);
    assert(!ninthOpen);
    assert(ninthOpen.status == DocumentManager::OpenStatus::LimitReached);
    assert(!ninthOpen.id);
    assert(duplicateManager.size() == DocumentManager::kMaxDocuments);
    assert(duplicateManager.activeId() == activeAtCap);

    BinaryFile duplicateImage;
    assert(duplicateImage.loadRaw(fixture.string(), 0x4000));
    ProjectState duplicateProject;
    duplicateProject.hash = duplicateImage.contentHash();
    duplicateProject.notes = "must be discarded";
    auto duplicateOpen = duplicateManager.openStaged(
        "duplicate", std::move(duplicateImage), std::move(duplicateProject),
        Engine::Capstone, Arch::X86,
        DocumentInstallPersistence::DurableSnapshot);
    assert(duplicateOpen);
    assert(duplicateOpen.status == DocumentManager::OpenStatus::ActivatedExisting);
    assert(duplicateOpen.id == firstOpen.id);
    assert(duplicateManager.activeId() == firstOpen.id);
    assert(duplicateManager.size() == DocumentManager::kMaxDocuments);
    assert(duplicateManager.find(firstOpen.id)->project().notes ==
           "canonical document");
    assert(duplicateManager.clear());

    // Live captures are exact-session artifacts. They must bypass content-hash
    // canonicalization so a same-byte reattach receives a new owner/generation.
    DocumentManager liveCaptureManager(factory);
    BinaryFile oldCapture;
    assert(oldCapture.loadRaw(fixture.string(), 0x5000));
    ProjectState oldCaptureProject;
    oldCaptureProject.hash = oldCapture.contentHash();
    const auto oldCaptureOpen = liveCaptureManager.openStaged(
        "old live capture", std::move(oldCapture), std::move(oldCaptureProject),
        Engine::Zydis, Arch::X64, DocumentInstallPersistence::Ephemeral,
        {}, {}, DocumentOpenReuse::AlwaysCreate);
    assert(oldCaptureOpen && oldCaptureOpen.status == DocumentManager::OpenStatus::Created);

    BinaryFile freshCapture;
    assert(freshCapture.loadRaw(fixture.string(), 0x5000));
    ProjectState freshCaptureProject;
    freshCaptureProject.hash = freshCapture.contentHash();
    const auto freshCaptureOpen = liveCaptureManager.openStaged(
        "fresh live capture", std::move(freshCapture), std::move(freshCaptureProject),
        Engine::Zydis, Arch::X64, DocumentInstallPersistence::Ephemeral,
        {}, {}, DocumentOpenReuse::AlwaysCreate);
    assert(freshCaptureOpen &&
           freshCaptureOpen.status == DocumentManager::OpenStatus::Created);
    assert(freshCaptureOpen.id != oldCaptureOpen.id);
    assert(liveCaptureManager.size() == 2);
    assert(liveCaptureManager.clear());

    // A mapped patch-set toggle is a static-only byte transition unless the UI
    // completes an exact-session live mirror. The commit policy atomically
    // revokes the whole PID/session/module stamp; an explicitly exact mirror
    // preserves it, and the shared invalidation edge remains independently
    // callable for a deferred write which later fails.
    {
        constexpr uint64_t mappedBase = 0x180000000ull;
        BinaryFile mappedImage;
        std::vector<uint8_t> mappedBytes(0x80, 0x90);
        assert(mappedImage.loadFromMemory(
            std::move(mappedBytes), mappedBase, "mapped-patch-toggle"));
        assert(mappedImage.isMappedImage());

        ProjectState mappedProject;
        mappedProject.hash = mappedImage.contentHash();
        mappedProject.patchSets.push_back({ 1, "toggle", false });
        mappedProject.patches.push_back(
            { mappedBase + 4, { 0x90 }, { 0xCC }, 1 });

        DocumentRuntimeMetadata mappedMetadata;
        mappedMetadata.liveImage.valid = true;
        mappedMetadata.liveImage.pid = 7331;
        mappedMetadata.liveImage.sessionGeneration = 17;
        mappedMetadata.liveImage.moduleBase = mappedBase;
        mappedMetadata.liveImage.moduleSize = 0x80;
        mappedMetadata.liveImage.moduleName = "mapped-patch-toggle";
        mappedMetadata.liveImage.moduleLoadGeneration = 5;

        DocumentContext mappedDocument(
            DocumentId{ 9001 }, "mapped patch transition", factory,
            Engine::Zydis, Arch::X64, acceptingStore);
        assert(mappedDocument.replaceImage(
            std::move(mappedImage), std::move(mappedProject),
            Engine::Zydis, Arch::X64,
            DocumentInstallPersistence::Ephemeral,
            std::move(mappedMetadata)));
        const auto verifiedIdentity =
            mappedDocument.runtimeMetadata().liveImage;

        std::vector<PjPatchSet> enabledSets =
            mappedDocument.project().patchSets;
        enabledSets[0].enabled = true;
        PatchSetImageResult toggled = BuildPatchSetImageForSelection(
            mappedDocument.binary(), mappedDocument.project().patches,
            enabledSets, {}, PatchSetImageSource::Pristine);
        assert(toggled.success && toggled.image[4] == 0xCC);
        assert(mappedDocument.commitPatchedImage(
            std::move(toggled.image),
            DocumentLiveImageCommit::InvalidateMappedIdentity));
        assert(mappedDocument.binary().bytes()[4] == 0xCC);
        assert(!mappedDocument.runtimeMetadata().liveImage.valid);

        mappedDocument.setDebugImageIdentity(verifiedIdentity);
        std::vector<uint8_t> exactlyMirrored = mappedDocument.binary().bytes();
        exactlyMirrored[5] = 0xCC;
        assert(mappedDocument.commitPatchedImage(
            std::move(exactlyMirrored),
            DocumentLiveImageCommit::PreserveVerifiedIdentity));
        assert(mappedDocument.runtimeMetadata().liveImage.valid);
        assert(mappedDocument.runtimeMetadata().liveImage.pid == 7331);
        assert(mappedDocument.runtimeMetadata().liveImage.moduleBase ==
               mappedBase);

        mappedDocument.invalidateDebugImageIdentity();
        assert(!mappedDocument.runtimeMetadata().liveImage.valid);
        std::vector<uint8_t> cannotRevalidate = mappedDocument.binary().bytes();
        cannotRevalidate[6] = 0xCC;
        assert(mappedDocument.commitPatchedImage(
            std::move(cannotRevalidate),
            DocumentLiveImageCommit::PreserveVerifiedIdentity));
        assert(!mappedDocument.runtimeMetadata().liveImage.valid);
    }

    std::filesystem::remove(fixture, ignored);
    std::filesystem::remove(uniqueFixture, ignored);
    std::filesystem::remove(unpublishedSidecar, ignored);
    return 0;
}
