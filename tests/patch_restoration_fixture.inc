// Opt-in integration through the production Binary View patch/revert methods
// and the real debugger. Only a contained copy of this harness is launched;
// no existing process, executable code in the child, or user file is modified.
static bool waitPatchRestorationPause(Debugger& debugger) {
    const ULONGLONG deadline = GetTickCount64() + 8000;
    do {
        const DbgSnapshot current = debugger.snapshot();
        if (current.state == DbgState::Paused) return true;
        if (current.state == DbgState::Terminated) return false;
        Sleep(5);
    } while (GetTickCount64() < deadline);
    return false;
}

static bool waitPatchRestorationBreakpoint(Debugger& debugger,
                                           DebugTargetIdentity owner,
                                           uint64_t address, bool armed) {
    const ULONGLONG deadline = GetTickCount64() + 4000;
    do {
        const DbgSnapshot current = debugger.snapshot();
        if (current.state != DbgState::Paused ||
            !DebugTargetIdentityMatches(
                {current.pid, current.sessionGeneration}, owner))
            return false;
        const auto found = std::find_if(current.breakpoints.begin(),
            current.breakpoints.end(), [&](const auto& bp) {
                return bp.address == address;
            });
        if (armed ? found != current.breakpoints.end() && found->armed &&
                        found->error.empty()
                  : found == current.breakpoints.end())
            return true;
        Sleep(5);
    } while (GetTickCount64() < deadline);
    return false;
}

static void checkLivePatchByteRestoration(const std::string& path) {
    char enabled[8]{};
    if (!GetEnvironmentVariableA("DS_PATCH_RESTORATION_LIVE_TEST", enabled,
                                 static_cast<DWORD>(sizeof(enabled))) ||
        enabled[0] != '1') {
        std::printf("SKIP live patch restoration (set DS_PATCH_RESTORATION_LIVE_TEST=1)\n");
        return;
    }
    const int failuresBefore = failures;
    Fixture f(path);
    char executable[MAX_PATH]{};
    const DWORD executableLength = GetModuleFileNameA(nullptr, executable, MAX_PATH);
    CHECK(executableLength != 0 && executableLength < MAX_PATH);
    if (!executableLength || executableLength >= MAX_PATH) return;

    // The child takes its bounded sleep branch before creating ImGui/AppContext.
    // The inherited marker cannot recur into another copy of the test suite.
    const DWORD oldLength = GetEnvironmentVariableA(
        "DS_PATCH_RESTORATION_CHILD", nullptr, 0);
    std::vector<char> oldMarker(oldLength ? oldLength : 1, '\0');
    if (oldLength)
        GetEnvironmentVariableA("DS_PATCH_RESTORATION_CHILD", oldMarker.data(),
                                static_cast<DWORD>(oldMarker.size()));
    CHECK(SetEnvironmentVariableA("DS_PATCH_RESTORATION_CHILD", "1") != FALSE);
    std::string error;
    const bool launched = f.ctx.debug.launchAndAttach(
        executable, error, true, /*containedJob=*/true);
    CHECK(SetEnvironmentVariableA("DS_PATCH_RESTORATION_CHILD",
                                 oldLength ? oldMarker.data() : nullptr) != FALSE);
    CHECK(launched);
    if (!launched) {
        std::printf("Live patch restoration launch failed: %s\n", error.c_str());
        return;
    }
    CHECK(waitPatchRestorationPause(f.ctx.debug));
    f.detached = f.ctx.debug.snapshot();
    if (f.detached.state != DbgState::Paused) return;
    const DebugTargetIdentity owner{
        f.detached.pid, f.detached.sessionGeneration
    };
    CHECK(owner.valid() && !f.detached.is32 && f.detached.containedJob);
    const uint64_t originalRip = f.detached.regs.rip;
    const uint32_t originalTid = f.detached.activeTid;

    constexpr size_t imageSize = 128 * 4096;
    const uint64_t scratch = f.ctx.debug.allocRemote(imageSize);
    CHECK(scratch != 0);
    if (!scratch) return;
    const uint64_t target = scratch + kTarget;
    size_t available = 0;
    const uint8_t* original = f.ctx.staticBinary().ptrFromVA(kTarget, available);
    CHECK(original && available >= 4);
    if (!original || available < 4) return;
    const std::vector<uint8_t> pristine(original, original + 4);
    const std::vector<uint8_t> patched{0x90, 0x90, 0x90, 0x90};
    CHECK(f.ctx.debug.writeMemoryForSession(owner.pid, owner.sessionGeneration,
        target, pristine.data(), pristine.size()) == pristine.size());

    // A synthetic module in the retained frame maps only this newly allocated
    // scratch image. The actual reads/writes still require the real PID/session.
    DbgModule module;
    module.base = scratch;
    module.size = imageSize;
    module.name = "patch-restoration-scratch";
    module.path = path;
    module.loadGeneration = 1;
    f.detached.modules.push_back(module);
    DocumentRuntimeMetadata::LiveImageIdentity identity;
    identity.valid = true;
    identity.pid = owner.pid;
    identity.sessionGeneration = owner.sessionGeneration;
    identity.moduleBase = module.base;
    identity.moduleSize = module.size;
    identity.moduleName = module.name;
    identity.modulePath = module.path;
    identity.moduleLoadGeneration = module.loadGeneration;
    f.ctx.setStaticDebugImageIdentity(identity);
    f.tab->mainView_ = 0;
    f.tab->frameSnap_ = &f.detached;

    auto logicalBytes = [&] {
        std::vector<uint8_t> bytes(pristine.size());
        CHECK(f.ctx.debug.readMemoryMaskedForSession(
            owner.pid, owner.sessionGeneration, target,
            bytes.data(), bytes.size()) == bytes.size());
        return bytes;
    };
    auto rawByte = [&] {
        uint8_t byte = 0;
        CHECK(f.ctx.debug.readMemoryForSession(owner.pid,
            owner.sessionGeneration, target + 1, &byte, 1) == 1);
        return byte;
    };
    auto addBreakpoint = [&] {
        CHECK(f.ctx.debug.addBreakpointForSession(owner, target + 1));
        CHECK(waitPatchRestorationBreakpoint(f.ctx.debug, owner, target + 1, true));
        CHECK(rawByte() == 0xCC);
    };
    auto removeBreakpoint = [&] {
        CHECK(f.ctx.debug.removeBreakpointForSession(owner, target + 1));
        CHECK(waitPatchRestorationBreakpoint(f.ctx.debug, owner, target + 1, false));
    };
    auto applyPatch = [&] {
        // A real FILE edit retires its backing-file stamp even after a verified
        // live mirror. Each independent scratch scenario starts pristine again,
        // so reestablish only this synthetic mapping after checking that state.
        CHECK(f.ctx.staticProject().patches.empty());
        CHECK(f.tab->livePatchOriginals_.empty());
        CHECK(logicalBytes() == pristine);
        f.ctx.setStaticDebugImageIdentity(identity);
        BinaryViewTab::PatchApplyOutcome outcome;
        CHECK(f.tab->applyPatchBytes(f.ctx, kTarget, patched,
            static_cast<uint32_t>(patched.size()), false, nullptr, &outcome, true));
        if (!outcome.staticCommitted || !outcome.liveRequested || !outcome.liveComplete)
            std::printf("Live patch apply outcome: static=%d requested=%d complete=%d status=%s\n",
                outcome.staticCommitted, outcome.liveRequested, outcome.liveComplete,
                f.tab->patchStatus_.c_str());
        CHECK(outcome.staticCommitted && outcome.liveRequested && outcome.liveComplete);
        CHECK(f.ctx.staticProject().patches.size() == 1);
        const auto saved = f.tab->livePatchOriginals_.find(kTarget);
        CHECK(saved != f.tab->livePatchOriginals_.end());
        if (saved != f.tab->livePatchOriginals_.end())
            CHECK(saved->second.bytes == pristine);
        CHECK(logicalBytes() == patched);
    };
    auto checkRestored = [&] {
        CHECK(f.ctx.staticProject().patches.empty());
        CHECK(f.tab->livePatchOriginals_.empty());
        CHECK(f.tab->livePatchSetOwners_.empty());
        CHECK(f.tab->livePatchOriginalBytes_ == 0);
        CHECK(logicalBytes() == pristine);
        size_t currentAvailable = 0;
        const uint8_t* current = f.ctx.staticBinary().ptrFromVA(kTarget, currentAvailable);
        CHECK(current && currentAvailable >= pristine.size());
        if (current && currentAvailable >= pristine.size())
            CHECK(std::equal(pristine.begin(), pristine.end(), current));
    };

    // An armed INT3 inside the span must remain physical debugger ownership,
    // while the retained patch original and final restored bytes remain logical.
    addBreakpoint();
    applyPatch();
    f.tab->revertPatchAt(f.ctx, kTarget);
    checkRestored();
    CHECK(rawByte() == 0xCC);
    removeBreakpoint();
    CHECK(rawByte() == pristine[1]);

    // Removing the breakpoint first must not turn a captured trap into a new,
    // unowned INT3 when the patch is reverted later.
    addBreakpoint();
    applyPatch();
    removeBreakpoint();
    CHECK(rawByte() == patched[1]);
    f.tab->revertPatchAt(f.ctx, kTarget);
    checkRestored();
    CHECK(rawByte() == pristine[1]);

    // A rejected static commit happens after live restoration. Rollback must
    // put the patched logical bytes back underneath the still-armed breakpoint.
    addBreakpoint();
    applyPatch();
    PjPatch invalid;
    invalid.address = UINT64_MAX;
    invalid.orig = {0x11};
    invalid.bytes = {0x22};
    f.ctx.staticProject().patches.push_back(std::move(invalid));
    f.tab->revertPatchAt(f.ctx, kTarget);
    CHECK(f.ctx.staticProject().patches.size() == 2);
    CHECK(f.tab->patchStatus_.find("rolled back") != std::string::npos);
    CHECK(f.tab->livePatchOriginals_.size() == 1);
    CHECK(logicalBytes() == patched);
    CHECK(rawByte() == 0xCC);
    if (f.ctx.staticProject().patches.size() == 2)
        f.ctx.staticProject().patches.pop_back();
    f.tab->revertPatchAt(f.ctx, kTarget);
    checkRestored();
    removeBreakpoint();
    CHECK(rawByte() == pristine[1]);

    const DbgSnapshot after = f.ctx.debug.snapshot();
    CHECK(after.state == DbgState::Paused && after.pid == owner.pid &&
          after.sessionGeneration == owner.sessionGeneration &&
          after.regs.rip == originalRip && after.activeTid == originalTid);
    f.ctx.debug.detach(); // closes the kill-on-close job containing only our child
    std::printf("Live patch restoration: %s (%d new failure(s))\n",
        failures == failuresBefore ? "passed" : "FAILED", failures - failuresBefore);
}
