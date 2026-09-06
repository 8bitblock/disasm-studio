// Included by static_listing_actions_test.cpp after Fixture. Uses production UI
// objects and an isolated raw image; never attaches to or changes a process.
static void checkContextActionDispatcher(const std::string& path) {
    Fixture f(path);
    using Action = BinaryViewTab::ContextAction;
    f.tab->mainView_ = 3;
    f.tab->setStaticCursor(0);
    auto target = f.tab->cursorActionTarget(f.ctx);
    std::string reason;
    CHECK(target.valid && target.address == 0 && !target.live);
    CHECK(f.tab->contextualActionAvailable(f.ctx, Action::Rename, target, reason));
    CHECK(f.tab->dispatchContextAction(f.ctx, Action::Rename, target));
    CHECK(f.tab->openRenamePopup_ && f.tab->annPopupVA_ == 0);
    f.tab->openRenamePopup_ = false;
    CHECK(f.tab->dispatchContextAction(f.ctx, Action::Comment, target));
    CHECK(f.tab->openCommentPopup_ && f.tab->annPopupVA_ == 0);
    f.tab->openCommentPopup_ = false;
    CHECK(f.tab->dispatchContextAction(f.ctx, Action::Bookmark, target));
    CHECK(f.tab->dispatchContextAction(f.ctx, Action::Bookmark, target));
    CHECK(f.tab->bookmarks_.size() == 1 && f.tab->bookmarks_[0].address == 0);
    CHECK(f.tab->projectDirty_);
    CHECK(!f.tab->contextualActionAvailable(f.ctx, Action::ShowLive, target, reason));
    CHECK(!reason.empty());
    CHECK(!f.tab->contextualActionAvailable(f.ctx, Action::RunToCursor, target, reason));

    // Invalid synthetic origin and stale owners never open an editor or create
    // another bookmark, even if the numeric address still names valid bytes.
    auto stale = target;
    stale.valid = false;
    CHECK(!f.tab->dispatchContextAction(f.ctx, Action::Comment, stale));
    stale = target; ++stale.document.value;
    CHECK(!f.tab->dispatchContextAction(f.ctx, Action::Rename, stale));
    stale = target; ++stale.imageGeneration;
    CHECK(!f.tab->dispatchContextAction(f.ctx, Action::Bookmark, stale));
    stale = target; ++stale.imageRevision;
    CHECK(!f.tab->dispatchContextAction(f.ctx, Action::Rename, stale));
    stale = target; stale.decoder.arch = Arch::X86;
    CHECK(!f.tab->dispatchContextAction(f.ctx, Action::Comment, stale));
    stale = target; stale.live = true; stale.liveOwner = {77, 123};
    CHECK(!f.tab->dispatchContextAction(f.ctx, Action::Comment, stale));
    CHECK(!f.tab->openCommentPopup_ && !f.tab->openRenamePopup_);
    CHECK(f.tab->bookmarks_.size() == 1);

    f.tab->mainView_ = 0;
    f.tab->setStaticCursor(kTarget);
    CHECK(!f.tab->cursorActionTarget(f.ctx).valid); // provisional listing source
    CHECK(f.tab->acceptListingInstructionBoundary(f.ctx, kTarget));
    CHECK(f.tab->cursorActionTarget(f.ctx).valid);
    f.tab->mainView_ = 2;
    CHECK(!f.tab->cursorActionTarget(f.ctx).instruction); // byte caret is not code authority
    for (int derivedView : {1, 3, 5}) {
        f.tab->mainView_ = derivedView;
        CHECK(f.tab->cursorActionTarget(f.ctx).valid);
        CHECK(!f.tab->cursorActionTarget(f.ctx).instruction);
    }
    const auto blockOrigin = f.tab->contextActionTarget(f.ctx, kTarget, false, true, false);
    CHECK(blockOrigin.valid && !blockOrigin.instruction);
    f.tab->mainView_ = 4; f.tab->liveMode_ = 1;
    f.tab->setLiveCursor(kTarget);
    CHECK(!f.tab->cursorActionTarget(f.ctx).instruction);
}

static void checkLivePatchMappingAndSkippedOutcome(const std::string& path) {
    Fixture f(path);
    // A frame snapshot can become stale before the checked debugger read. The
    // real Debugger remains detached, so this cannot access a real process.
    f.detached.state = DbgState::Paused;
    f.detached.pid = 77; f.detached.sessionGeneration = 123;
    DbgModule module;
    module.base = 0x10000; module.size = 128 * 4096;
    module.name = "fixture"; module.path = f.path; module.loadGeneration = 4;
    f.detached.modules.push_back(module);
    DocumentRuntimeMetadata::LiveImageIdentity identity;
    identity.valid = true;
    identity.pid = f.detached.pid;
    identity.sessionGeneration = f.detached.sessionGeneration;
    identity.moduleBase = module.base; identity.moduleSize = module.size;
    identity.moduleName = module.name; identity.modulePath = module.path;
    identity.moduleLoadGeneration = module.loadGeneration;
    f.ctx.setStaticDebugImageIdentity(identity);
    uint64_t base = 0, size = 0;
    CHECK(f.ctx.debuggerRuntimeImage(f.detached, base, size));
    f.tab->mainView_ = 4;
    BinaryViewTab::PatchApplyOutcome outcome;
    CHECK(f.tab->applyPatchBytes(f.ctx, module.base + kTarget, {0xC3, 0x90}, 2,
                                 false, nullptr, &outcome));
    CHECK(outcome.staticCommitted && outcome.liveRequested && !outcome.liveComplete);
    CHECK(outcome.liveBytesWritten == 0);
    CHECK(f.tab->patchStatus_.find("rollback capture failed") != std::string::npos);
    CHECK(f.ctx.staticProject().patches.size() == 1);
    if (!f.ctx.staticProject().patches.empty())
        CHECK(f.ctx.staticProject().patches[0].address == kTarget);
    CHECK(f.tab->livePatchOriginals_.empty());
    // A same-number FILE address in an unproven LIVE module cannot receive a
    // fallback patch record in the active document.
    f.ctx.invalidateStaticDebugImageIdentity();
    CHECK(!f.tab->applyPatchBytes(f.ctx, kTarget + 8, {0x90, 0x90}, 2,
                                  false, nullptr, &outcome));
    CHECK(!outcome.staticCommitted && f.ctx.staticProject().patches.size() == 1);
}

static void checkEffectivePatchPreview(const std::string& path, bool disabledSet) {
    Fixture f(path);
    if (disabledSet) {
        PjPatchSet set; set.id = 1; set.name = "Inactive test"; set.enabled = false;
        f.ctx.staticProject().patchSets.push_back(set);
        f.tab->patchDestinationSetId_ = 1;
    }
    CHECK(f.tab->beginStaticInstructionPatch(f.ctx, kTarget));
    f.tab->patchMode_ = 0;
    f.tab->patchPadNop_ = true;
    std::snprintf(f.tab->patchHex_, sizeof(f.tab->patchHex_), "C3");
    auto body = [&] { f.tab->renderPatchPopup(f.ctx); };
    frame(body);
    CHECK(f.tab->patchPreviewOriginal_.size() == 2);
    const auto original = f.tab->patchPreviewOriginal_;
    ImGuiWindow* popup = ImGui::FindWindowByName("Patch");
    CHECK(popup != nullptr);
    if (popup) {
        ImGui::FocusWindow(popup);
        ImGui::ActivateItemByID(popup->GetID("Copy bytes"));
        frame(body);
        CHECK(std::string(ImGui::GetClipboardText()) == "C3 90 ");
        ImGui::ActivateItemByID(popup->GetID("Apply"));
        frame(body);
    }
    CHECK(f.ctx.staticProject().patches.size() == 1);
    if (!f.ctx.staticProject().patches.empty())
        CHECK((f.ctx.staticProject().patches[0].bytes == std::vector<uint8_t>{0xC3, 0x90}));
    CHECK(f.tab->patchPopupOutcome_.staticCommitted);
    CHECK(!f.tab->patchPopupOutcome_.liveRequested);
    CHECK(!GImGui->OpenPopupStack.empty()); // outcomes remain reviewable
    CHECK(f.tab->patchPreviewOriginal_ == original); // before image retained after apply
    size_t available = 0;
    const auto* bytes = f.ctx.staticBinary().ptrFromVA(kTarget, available);
    CHECK(bytes && available >= 2);
    if (bytes && available >= 2) {
        if (disabledSet) {
            CHECK(bytes[0] == original[0] && bytes[1] == original[1]);
            CHECK(f.tab->patchStatus_.find("disabled") != std::string::npos);
        } else CHECK(bytes[0] == 0xC3 && bytes[1] == 0x90);
    }
    ImGui::ClosePopupsOverWindow(nullptr, false);
}
