// Exercises the ordinary Patch command and its modal against the actual listing
// objects. Selected rows determine the writable span; changed or missing bytes
// must never become implicit permission to overwrite adjacent instructions.
#include "Disasm/Assembler.h"

static void closeMultiRowPatch(Fixture& f) {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    f.tab->openPatchPopup_ = false;
    f.tab->closePatchPopup_ = false;
}

static void multiRowPatchButton(Fixture& f, const char* label) {
    auto body = [&] { f.tab->renderPatchPopup(f.ctx); };
    frame(body);
    ImGuiWindow* popup = ImGui::FindWindowByName("Patch");
    CHECK(popup != nullptr);
    if (popup) {
        ImGui::FocusWindow(popup);
        ImGui::ActivateItemByID(popup->GetID(label));
    }
    frame(body);
}

static bool multiRowPatchTextPoint(Fixture& f, uint64_t address, int column,
                                  ImVec2& point) {
    for (int i = 0; i < 4; ++i) f.assemblyFrame();
    ImGuiWindow* window = ImGui::FindWindowByName("Listing integration");
    ImGuiTable* table = window ? ImGui::GetCurrentContext()->Tables.GetByKey(
        window->GetID(f.tab->asmFullProgram_ ? "asm_full" : "asm")) : nullptr;
    CHECK(table != nullptr);
    if (!table) return false;
    for (const auto& row : f.tab->asmFlow_) if (row.addr == address) {
        point = ImVec2(table->Columns[column].WorkMinX + 4.0f, row.y);
        return true;
    }
    CHECK(false && "Patch selection row must be visible");
    return false;
}

static void checkMultiRowPatchDrag(const std::string& path, bool full, int firstColumn = 3) {
    Fixture f(path, full);
    ImVec2 first, last;
    if (!multiRowPatchTextPoint(f, kTarget, firstColumn, first) ||
        !multiRowPatchTextPoint(f, kTarget + 4, 4, last)) return;
    ImGuiIO& io = ImGui::GetIO();
    io.AddMousePosEvent(first.x, first.y); // address or bytes starts the drag
    f.assemblyFrame();
    io.AddMouseButtonEvent(ImGuiMouseButton_Left, true);
    f.assemblyFrame();
    io.AddMousePosEvent(last.x, last.y); // instruction column extends it
    f.assemblyFrame();
    io.AddMouseButtonEvent(ImGuiMouseButton_Left, false);
    f.assemblyFrame();
    CHECK(f.tab->selVAs_.size() == 3);
    CHECK(f.tab->selVAs_.count(kTarget) && f.tab->selVAs_.count(kTarget + 2) &&
          f.tab->selVAs_.count(kTarget + 4));

    // A right-click on selected instruction text must keep the selected range.
    if (!multiRowPatchTextPoint(f, kTarget + 2, 4, last)) return;
    io.AddMousePosEvent(last.x, last.y);
    f.assemblyFrame();
    io.AddMouseButtonEvent(ImGuiMouseButton_Right, true);
    f.assemblyFrame();
    io.AddMouseButtonEvent(ImGuiMouseButton_Right, false);
    f.assemblyFrame();
    CHECK(f.tab->selVAs_.size() == 3);
    CHECK(!GImGui->OpenPopupStack.empty());
    closeMultiRowPatch(f);
    f.key(ImGuiKey_P);
    CHECK(f.tab->patchVA_ == kTarget && f.tab->patchLen_ == 6);
    CHECK(f.tab->patchInstructionRecords_.size() == 3);
    closeMultiRowPatch(f);
}

static void checkMultiRowPatchInput(const std::string& path, bool full) {
    Fixture f(path, full);
    CHECK(f.clickRow(kTarget, false));
    ImGuiIO& io = ImGui::GetIO();
    io.AddKeyEvent(ImGuiMod_Ctrl, true);
    CHECK(f.clickRow(kTarget + 2, false));
    io.AddKeyEvent(ImGuiMod_Ctrl, false);
    f.assemblyFrame();
    CHECK(f.tab->selVAs_.size() == 2);
    CHECK(f.tab->selVAs_.count(kTarget) && f.tab->selVAs_.count(kTarget + 2));

    // Establish a fresh anchor and use native Shift-click to select every row
    // through the end of the intended six-byte replacement region.
    CHECK(f.clickRow(kTarget, false));
    io.AddKeyEvent(ImGuiMod_Shift, true);
    CHECK(f.clickRow(kTarget + 4, false));
    io.AddKeyEvent(ImGuiMod_Shift, false);
    f.assemblyFrame();
    CHECK(f.tab->selVAs_.size() == 3);
    CHECK(f.tab->selVAs_.count(kTarget) && f.tab->selVAs_.count(kTarget + 2) &&
          f.tab->selVAs_.count(kTarget + 4));
    CHECK(f.tab->cursorVA_ == kTarget + 4);

    f.key(ImGuiKey_P); // normal keyboard dispatch, with cursor on the last row
    CHECK(f.tab->patchVA_ == kTarget);
    CHECK(f.tab->patchLen_ == 6 && f.tab->patchInstructionRecords_.size() == 3);
    f.tab->patchMode_ = 1;
    f.tab->patchAsmText_ = "mov eax, 1; ret";
    multiRowPatchButton(f, "Apply");
    CHECK(f.ctx.staticProject().patches.size() == 1);
    const std::vector<uint8_t> expected{0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};
    if (!f.ctx.staticProject().patches.empty()) {
        const auto& patch = f.ctx.staticProject().patches.front();
        CHECK(patch.address == kTarget && patch.bytes == expected && patch.orig.size() == 6);
    }
    size_t available = 0;
    const uint8_t* bytes = f.ctx.staticBinary().ptrFromVA(kTarget, available);
    CHECK(bytes && available >= 8);
    if (bytes && available >= 8) {
        CHECK(std::equal(expected.begin(), expected.end(), bytes));
        CHECK(bytes[6] == 0xFF && bytes[7] == 0xC0);
    }
    closeMultiRowPatch(f);
}

static void checkMultiRowPatchBounds(const std::string& path) {
    {
        Fixture f(path);
        f.select({kTarget, kTarget + 2});
        CHECK(f.tab->beginStaticInstructionPatch(f.ctx, kTarget + 2));
        CHECK(f.tab->patchVA_ == kTarget && f.tab->patchLen_ == 4);
        f.tab->patchMode_ = 1;
        f.tab->patchAsmText_ = "mov eax, 1; ret"; // six bytes still exceed four
        const uint64_t revision = f.ctx.staticBinary().imageRevision();
        multiRowPatchButton(f, "Apply");
        CHECK(f.ctx.staticProject().patches.empty());
        CHECK(f.ctx.staticBinary().imageRevision() == revision);
        closeMultiRowPatch(f);
    }
    {
        Fixture f(path);
        f.select({kTarget, kTarget + 4});
        CHECK(!f.tab->beginStaticInstructionPatch(f.ctx, kTarget + 4));
        CHECK(!f.tab->openPatchPopup_ && f.tab->patchInstructionRecords_.empty());
        CHECK(!f.tab->patchStatus_.empty());
        CHECK(f.ctx.staticProject().patches.empty());
        // An explicit action on a different row retains its single-row scope.
        CHECK(f.tab->beginStaticInstructionPatch(f.ctx, kTarget + 8));
        CHECK(f.tab->patchVA_ == kTarget + 8 && f.tab->patchLen_ == 2);
        closeMultiRowPatch(f);
    }
    {
        Fixture f(path);
        f.select({kTarget, kTarget + 2, kTarget + 4});
        const uint8_t changed = 0x90;
        CHECK(f.ctx.writeStaticImage(kTarget + 4, &changed, 1) == 1);
        CHECK(!f.tab->beginStaticInstructionPatch(f.ctx, kTarget));
        CHECK(!f.tab->openPatchPopup_ && f.ctx.staticProject().patches.empty());
    }
    {
        Fixture f(path);
        f.select({kTarget, kTarget + 2, kTarget + 4});
        f.tab->selView_ = 4; // a retained LIVE selection grants no FILE region
        CHECK(f.tab->beginStaticInstructionPatch(f.ctx, kTarget));
        CHECK(f.tab->patchVA_ == kTarget && f.tab->patchLen_ == 2);
        CHECK(f.tab->patchInstructionRecords_.size() == 1);
        closeMultiRowPatch(f);
    }
}

static void checkMultiRowPatchRetained(const std::string& path, bool changeBytes) {
    Fixture f(path);
    f.select({kTarget, kTarget + 2, kTarget + 4});
    CHECK(f.tab->beginStaticInstructionPatch(f.ctx, kTarget + 2));
    frame([&] { f.tab->renderPatchPopup(f.ctx); });
    CHECK(f.tab->patchInstructionRecords_.size() == 3);
    // The modal owns snapshots independently of the listing selection and LRU.
    f.tab->selVAs_.clear();
    f.tab->listingSelectedInstructions_.clear();
    f.tab->listingSelectedBytes_ = 0;
    f.tab->listingCursorInstruction_ = {};
    for (size_t page = 21; page < 118; ++page)
        CHECK(f.tab->ensureListingCodePage(f.ctx, page) != nullptr);
    CHECK(f.tab->codePageCache_.count(20) == 0);
    if (changeBytes) {
        const uint8_t changed = 0x90;
        CHECK(f.ctx.writeStaticImage(kTarget + 4, &changed, 1) == 1);
    }
    f.tab->patchMode_ = 0;
    f.tab->patchHex_ = "B8 01 00 00 00 C3";
    const uint64_t revision = f.ctx.staticBinary().imageRevision();
    multiRowPatchButton(f, "Apply");
    CHECK(f.ctx.staticProject().patches.size() == (changeBytes ? 0u : 1u));
    if (changeBytes) {
        CHECK(!f.tab->patchStatus_.empty());
        CHECK(f.ctx.staticBinary().imageRevision() == revision);
        size_t available = 0;
        const uint8_t* bytes = f.ctx.staticBinary().ptrFromVA(kTarget, available);
        CHECK(bytes && available >= 6);
        if (bytes && available >= 6)
            CHECK(bytes[0] == 0xFF && bytes[2] == 0xFF && bytes[4] == 0x90);
    }
    closeMultiRowPatch(f);
}

static void checkMultiRowPatchLongDraft(const std::string& path) {
    Fixture f(path);
    constexpr size_t count = 80;
    f.tab->selVAs_.clear();
    f.tab->selView_ = 0;
    for (size_t i = 0; i < count; ++i) f.tab->selVAs_.insert(kTarget + 2 * i);
    f.tab->rememberListingSelection(f.ctx);
    CHECK(f.tab->beginStaticInstructionPatch(f.ctx, kTarget + 2 * (count - 1)));
    CHECK(f.tab->patchLen_ == 2 * count && f.tab->patchInstructionRecords_.size() == count);
    CHECK(f.tab->patchHex_.size() > 128 && f.tab->patchAsmText_.size() > 256);
    const auto assembled = Assemble(f.ctx.staticDecoderConfig(), f.tab->patchAsmText_, kTarget);
    CHECK(assembled.ok && assembled.bytes.size() == 2 * count);
    std::istringstream hex(f.tab->patchHex_);
    std::vector<unsigned> parsed;
    unsigned byte = 0;
    while (hex >> std::hex >> byte) parsed.push_back(byte);
    CHECK(parsed.size() == 2 * count);
    for (size_t i = 0; i < parsed.size(); ++i) CHECK(parsed[i] == (i % 2 ? 0xC0u : 0xFFu));

    f.tab->patchMode_ = 0;
    multiRowPatchButton(f, "NOP fill");
    CHECK(f.tab->patchHex_.size() > 128);
    multiRowPatchButton(f, "Apply");
    CHECK(f.ctx.staticProject().patches.size() == 1);
    if (!f.ctx.staticProject().patches.empty()) {
        const auto& patch = f.ctx.staticProject().patches.front();
        CHECK(patch.bytes.size() == 2 * count && patch.orig.size() == 2 * count);
        CHECK(std::all_of(patch.bytes.begin(), patch.bytes.end(), [](uint8_t value) { return value == 0x90; }));
    }
    closeMultiRowPatch(f);
}

static void checkMultiRowPatchHexFallback(const std::string& path) {
    Fixture f(path);
    CHECK(f.ctx.setStaticDecoderConfiguration(Engine::Zydis, Arch::X86_16));
    f.tab->synchronizeDocumentImage(f.ctx);
    f.ctx.staticAnalysis().cancelAndWaitIdle();
    f.layout();
    f.tab->setStaticCursor(kTarget);
    CHECK(f.tab->ensureListingCodePage(f.ctx, 20) != nullptr);
    f.select({kTarget, kTarget + 2});
    CHECK(f.tab->beginStaticInstructionPatch(f.ctx, kTarget + 2));
    CHECK(f.tab->patchMode_ == 0 && f.tab->patchLen_ == 4);
    f.tab->patchPadNop_ = false;
    f.tab->patchHex_ = "90 90 90 90";
    multiRowPatchButton(f, "Apply");
    CHECK(f.ctx.staticProject().patches.size() == 1);
    closeMultiRowPatch(f);
}

static void checkMultiRowPatch(const std::string& path) {
    const int before = failures;
    checkMultiRowPatchInput(path, true);
    checkMultiRowPatchInput(path, false);
    checkMultiRowPatchDrag(path, true);
    checkMultiRowPatchDrag(path, false);
    checkMultiRowPatchDrag(path, true, 2);
    checkMultiRowPatchDrag(path, false, 2);
    checkMultiRowPatchBounds(path);
    checkMultiRowPatchRetained(path, false);
    checkMultiRowPatchRetained(path, true);
    checkMultiRowPatchLongDraft(path);
    checkMultiRowPatchHexFallback(path);
    std::printf("Multi-row patch workflow: %s (%d new failure(s))\n",
                failures == before ? "PASS" : "FAIL", failures - before);
}

// Called only by the existing opt-in contained-child fixture after it allocates
// and maps scratch memory. This region is separate from its restoration cases.
static void checkLiveMultiRowPatch(Fixture& f, uint64_t scratch) {
    const int before = failures;
    constexpr uint64_t fileAddress = kTarget + 128;
    const uint64_t liveAddress = scratch + fileAddress;
    const DebugTargetIdentity owner{f.detached.pid, f.detached.sessionGeneration};
    const std::vector<uint8_t> original{0xFF, 0xC0, 0xFF, 0xC0, 0xFF, 0xC0};
    CHECK(f.ctx.debug.writeMemoryForSession(owner.pid, owner.sessionGeneration,
        liveAddress, original.data(), original.size()) == original.size());
    f.tab->liveInsns_ = f.ctx.staticDisassembler()->disassemble(
        original.data(), original.size(), liveAddress, 3);
    CHECK(f.tab->liveInsns_.size() == 3);
    f.tab->liveIdxOf_.clear();
    for (size_t i = 0; i < f.tab->liveInsns_.size(); ++i)
        f.tab->liveIdxOf_[f.tab->liveInsns_[i].address] = static_cast<int>(i);
    f.tab->liveSessionIdentityValid_ = true;
    f.tab->liveSessionPidSeen_ = owner.pid;
    f.tab->liveSessionGenerationSeen_ = owner.sessionGeneration;
    f.tab->mainView_ = 4;
    f.tab->selView_ = 4;

    f.tab->selVAs_ = {liveAddress, liveAddress + 4};
    CHECK(!f.tab->beginLiveInstructionPatch(f.ctx, f.detached, liveAddress));
    CHECK(!f.tab->openPatchPopup_);
    f.tab->selVAs_ = {liveAddress, liveAddress + 2, liveAddress + 4};
    DbgSnapshot stale = f.detached;
    ++stale.sessionGeneration;
    CHECK(!f.tab->beginLiveInstructionPatch(f.ctx, stale, liveAddress));
    CHECK(!f.tab->openPatchPopup_);
    CHECK(f.tab->beginLiveInstructionPatch(f.ctx, f.detached, liveAddress + 4));
    CHECK(f.tab->patchVA_ == liveAddress && f.tab->patchLen_ == 6);
    CHECK(f.tab->patchPopupLive_ && f.tab->patchLiveOriginal_ == original);

    f.tab->patchMode_ = 0;
    f.tab->patchHex_ = "B8 01 00 00 00 C3 90";
    multiRowPatchButton(f, "Apply");
    CHECK(f.ctx.staticProject().patches.empty());
    std::vector<uint8_t> observed(original.size());
    CHECK(f.ctx.debug.readMemoryMaskedForSession(owner.pid, owner.sessionGeneration,
        liveAddress, observed.data(), observed.size()) == observed.size());
    CHECK(observed == original);

    // A byte changed in the final selected row invalidates the whole live draft.
    const uint8_t changed = 0x90;
    CHECK(f.ctx.debug.writeMemoryForSession(owner.pid, owner.sessionGeneration,
        liveAddress + 4, &changed, 1) == 1);
    f.tab->patchHex_ = "B8 01 00 00 00 C3";
    multiRowPatchButton(f, "Apply");
    CHECK(f.ctx.staticProject().patches.empty());
    CHECK(!f.tab->patchStatus_.empty());
    closeMultiRowPatch(f);
    CHECK(f.ctx.debug.writeMemoryForSession(owner.pid, owner.sessionGeneration,
        liveAddress, original.data(), original.size()) == original.size());

    CHECK(f.tab->beginLiveInstructionPatch(f.ctx, f.detached, liveAddress + 2));
    f.tab->patchMode_ = 1;
    f.tab->patchAsmText_ = "mov eax, 1; ret";
    multiRowPatchButton(f, "Apply");
    CHECK(f.ctx.staticProject().patches.size() == 1);
    CHECK(f.tab->patchPopupOutcome_.staticCommitted &&
          f.tab->patchPopupOutcome_.liveRequested && f.tab->patchPopupOutcome_.liveComplete);
    if (!f.tab->patchPopupOutcome_.liveComplete)
        std::printf("Live multi-row patch status: %s\n", f.tab->patchStatus_.c_str());
    CHECK(f.ctx.debug.readMemoryMaskedForSession(owner.pid, owner.sessionGeneration,
        liveAddress, observed.data(), observed.size()) == observed.size());
    CHECK(observed == std::vector<uint8_t>({0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3}));
    closeMultiRowPatch(f);
    f.tab->revertPatchAt(f.ctx, fileAddress);
    CHECK(f.ctx.staticProject().patches.empty() && f.tab->livePatchOriginals_.empty());
    CHECK(f.ctx.debug.readMemoryMaskedForSession(owner.pid, owner.sessionGeneration,
        liveAddress, observed.data(), observed.size()) == observed.size());
    CHECK(observed == original);
    f.tab->mainView_ = 0;
    f.tab->selView_ = 0;
    f.tab->selVAs_.clear();
    f.tab->liveInsns_.clear();
    f.tab->liveIdxOf_.clear();
    f.tab->liveSessionIdentityValid_ = false;
    f.tab->liveSessionPidSeen_ = 0;
    f.tab->liveSessionGenerationSeen_ = 0;
    f.tab->setStaticCursor(kTarget);
    std::printf("Live multi-row patch workflow: %s (%d new failure(s))\n",
                failures == before ? "PASS" : "FAIL", failures - before);
}
