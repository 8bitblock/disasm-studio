// Production LIVE listing and xref navigation against memory allocated only in
// a contained copy of this harness. The child never executes the scratch bytes.
#include "Core/XrefIndex.h"

static ImGuiTable* liveScrollTable() {
    for (int index = 0; index < GImGui->Tables.GetMapSize(); ++index) {
        ImGuiTable* table = GImGui->Tables.TryGetMapData(index);
        if (table && table->LastFrameActive == ImGui::GetFrameCount() &&
            table->InnerWindow && std::strstr(table->InnerWindow->Name, "/live_asm_"))
            return table;
    }
    return nullptr;
}

static void checkLiveAssemblyScrolling(const std::string& path) {
    char enabled[8]{};
    char focused[8]{};
    const bool explicitlyEnabled =
        GetEnvironmentVariableA("DS_LIVE_SCROLL_TEST", enabled, sizeof(enabled)) && enabled[0] == '1';
    const bool focusedRun =
        GetEnvironmentVariableA("DS_LIVE_SCROLL_ONLY", focused, sizeof(focused)) && focused[0] == '1';
    if (!explicitlyEnabled && !focusedRun) {
        std::printf("SKIP live assembly scrolling (set DS_LIVE_SCROLL_TEST=1)\n");
        return;
    }
    const int failuresBefore = failures;
    Fixture f(path);
    char executable[MAX_PATH]{};
    const DWORD executableLength = GetModuleFileNameA(nullptr, executable, MAX_PATH);
    CHECK(executableLength && executableLength < MAX_PATH);
    if (!executableLength || executableLength >= MAX_PATH) return;

    // Reuse the bounded child branch, restoring the parent's environment before
    // doing any UI work. The debugger's kill-on-close job owns only this child.
    const DWORD oldLength = GetEnvironmentVariableA("DS_PATCH_RESTORATION_CHILD", nullptr, 0);
    std::vector<char> oldMarker(oldLength ? oldLength : 1, '\0');
    if (oldLength)
        GetEnvironmentVariableA("DS_PATCH_RESTORATION_CHILD", oldMarker.data(),
                                static_cast<DWORD>(oldMarker.size()));
    CHECK(SetEnvironmentVariableA("DS_PATCH_RESTORATION_CHILD", "1") != FALSE);
    std::string error;
    const bool launched = f.ctx.debug.launchAndAttach(executable, error, true, true);
    CHECK(SetEnvironmentVariableA("DS_PATCH_RESTORATION_CHILD",
                                 oldLength ? oldMarker.data() : nullptr) != FALSE);
    CHECK(launched);
    if (!launched) {
        std::printf("Live scroll child launch failed: %s\n", error.c_str());
        return;
    }
    CHECK(waitPatchRestorationPause(f.ctx.debug));
    f.detached = f.ctx.debug.snapshot();
    if (f.detached.state != DbgState::Paused) return;
    const DebugTargetIdentity owner{f.detached.pid, f.detached.sessionGeneration};
    CHECK(owner.valid() && f.detached.containedJob && !f.detached.is32);
    const uint64_t originalRip = f.detached.regs.rip;
    const uint32_t originalTid = f.detached.activeTid;
    constexpr size_t imageSize = 128 * 4096;
    const uint64_t scratch = f.ctx.debug.allocRemote(imageSize);
    CHECK(scratch != 0);
    if (!scratch) return;
    const uint64_t source = scratch + kTarget + 16;
    const uint64_t stringAddress = scratch + 0x70000;
    std::vector<uint8_t> image(imageSize);
    for (size_t offset = 0; offset < image.size(); offset += 2) {
        image[offset] = 0xFF; image[offset + 1] = 0xC0; // inc eax
    }
    const size_t sourceOffset = static_cast<size_t>(source - scratch);
    image[sourceOffset] = 0x48; image[sourceOffset + 1] = 0x8D;
    image[sourceOffset + 2] = 0x0D; // lea rcx, [rip + string]
    const int32_t displacement = static_cast<int32_t>(stringAddress - (source + 7));
    std::memcpy(image.data() + sourceOffset + 3, &displacement, sizeof(displacement));
    image[sourceOffset + 7] = 0x90;
    const char text[] = "Live scrolling string reference";
    std::memcpy(image.data() + (stringAddress - scratch), text, sizeof(text));
    CHECK(f.ctx.debug.writeMemoryForSession(owner.pid, owner.sessionGeneration,
        scratch, image.data(), image.size()) == image.size());

    DbgModule module;
    module.base = scratch; module.size = imageSize;
    module.name = "live-scroll-scratch"; module.path = path; module.loadGeneration = 1;
    f.detached.modules.push_back(module);
    DocumentRuntimeMetadata::LiveImageIdentity identity;
    identity.valid = true; identity.pid = owner.pid;
    identity.sessionGeneration = owner.sessionGeneration;
    identity.moduleBase = scratch; identity.moduleSize = imageSize;
    identity.moduleName = module.name; identity.modulePath = path;
    identity.moduleLoadGeneration = module.loadGeneration;
    f.ctx.setStaticDebugImageIdentity(identity);
    f.tab->frameSnap_ = &f.detached;
    f.tab->showRegBox_ = false;
    f.tab->showMemoryValues_ = false;
    f.tab->showStringComments_ = false;
    f.tab->showHints_ = false;

    // Run the actual targeted-xref decoder over checked child memory, then use
    // the production retained-result handoff that the Strings panel invokes.
    std::vector<uint8_t> referenceBytes(96);
    CHECK(f.ctx.debug.readMemoryMaskedForSession(owner.pid, owner.sessionGeneration,
        source - 32, referenceBytes.data(), referenceBytes.size()) == referenceBytes.size());
    f.tab->xrefHits_.clear();
    CHECK(FindRefsInBuffer(referenceBytes.data(), referenceBytes.size(), source - 32,
        stringAddress, *f.tab->liveDecoder(f.ctx, false), f.tab->xrefHits_));
    CHECK(f.tab->xrefHits_ == std::vector<uint64_t>{source});
    f.tab->xrefTarget_ = stringAddress;
    f.tab->xrefTargetValid_ = f.tab->xrefPinned_ = f.tab->xrefHitsLive_ = true;
    f.tab->xrefLiveOwner_ = owner;
    f.tab->xrefLiveModules_ = f.tab->contextActionTarget(f.ctx, source, true).liveModules;
    frame([&] { CHECK(f.tab->followXrefSource(f.ctx, 0)); });
    CHECK(f.tab->mainView_ == 4 && f.tab->cursorLive_ && f.tab->cursorVA_ == source);
    CHECK(!f.tab->followLiveRip_);
    f.tab->selView_ = 4;
    f.tab->selVAs_ = {source, source + 7};
    f.tab->selAnchorVA_ = source;
    f.tab->selAnchorValid_ = true;
    const auto selection = f.tab->selVAs_;
    const auto location = f.tab->navigation_->current();
    const auto back = f.tab->navigation_->backStack();
    const auto forward = f.tab->navigation_->forwardStack();
    auto render = [&] {
        frame([&] { f.tab->renderLiveAssembly(f.ctx); }, "Live scrolling integration",
              ImVec2(1180, 720));
    };
    auto retained = [&] {
        CHECK(f.tab->cursorVA_ == source && f.tab->cursorValid_ && f.tab->cursorLive_);
        CHECK(f.tab->selVAs_ == selection && f.tab->selAnchorVA_ == source &&
              f.tab->selAnchorValid_ && f.tab->selView_ == 4);
        CHECK(f.tab->navigation_->current() == location);
        CHECK(f.tab->navigation_->backStack() == back);
        CHECK(f.tab->navigation_->forwardStack() == forward);
        CHECK(!f.tab->followLiveRip_);
    };
    for (int i = 0; i < 4; ++i) render();
    CHECK(!f.tab->liveInsns_.empty());
    ImGuiTable* table = liveScrollTable();
    CHECK(table && table->InnerWindow);
    if (!table || !table->InnerWindow || f.tab->liveInsns_.empty()) return;
    ImGui::GetIO().AddMousePosEvent(table->InnerWindow->InnerClipRect.Min.x + 220,
                                  table->InnerWindow->InnerClipRect.Min.y + 180);
    ImGui::FocusWindow(table->InnerWindow);
    render(); render();

    // Locate the address's actual rendered glyphs in the address column. Table
    // row heights can differ when cells are clipped; extrapolating from the last
    // row produces a false movement even when the same visible text is stable.
    // This uses normal draw output and does not depend on the private pan state.
    auto rowY = [&](uint64_t address) {
        const ImGuiTable* current = liveScrollTable();
        if (!current || !f.tab->liveIdxOf_.count(address)) return -1000000.0f;
        char needle[40];
        std::snprintf(needle, sizeof(needle), "0x%llX", address);
        const size_t length = std::strlen(needle);
        ImFont* font = ui::gMonoFont ? ui::gMonoFont : ImGui::GetFont();
        const auto& vertices = current->InnerWindow->DrawList->VtxBuffer;
        const float left = current->Columns[2].WorkMinX;
        const float right = current->Columns[2].WorkMaxX;
        const ImFontGlyph* zero = font->FindGlyph('0');
        if (!zero) return -1000000.0f;
        for (int i = 0; i + static_cast<int>(length * 4) <= vertices.Size; ++i) {
            const auto& first = vertices[i];
            if (first.pos.x < left || first.pos.x > std::min(right, left + 32.0f) ||
                std::fabs(first.uv.x - zero->U0) > 0.000001f ||
                std::fabs(first.uv.y - zero->V0) > 0.000001f) continue;
            bool matches = true;
            for (size_t c = 0; c < length && matches; ++c) {
                const ImFontGlyph* glyph = font->FindGlyph(static_cast<ImWchar>(needle[c]));
                const auto& top = vertices[i + static_cast<int>(c * 4)];
                const auto& bottom = vertices[i + static_cast<int>(c * 4) + 2];
                matches = glyph && std::fabs(top.uv.x - glyph->U0) < 0.000001f &&
                    std::fabs(top.uv.y - glyph->V0) < 0.000001f &&
                    std::fabs(bottom.uv.x - glyph->U1) < 0.000001f &&
                    std::fabs(bottom.uv.y - glyph->V1) < 0.000001f;
            }
            if (matches) return first.pos.y;
        }
        return -1000000.0f;
    };
    int stableRefills = 0;
    int refillDiagnostics = 0;
    auto finishInput = [&] {
        uint64_t anchor = 0;
        float beforeY = 0;
        const uint64_t beforeStart = f.tab->liveCacheStart_;
        const float beforeScroll = liveScrollTable()->InnerWindow->Scroll.y;
        if (f.tab->liveBrowseRefillDirection_ && f.tab->functions_.empty()) {
            const ImGuiTable* current = liveScrollTable();
            for (const Instruction& instruction : f.tab->liveInsns_) {
                const float y = rowY(instruction.address);
                if (y >= current->InnerWindow->InnerClipRect.Min.y +
                         current->InstanceDataFirst.LastTopHeadersRowHeight &&
                    y < current->InnerWindow->InnerClipRect.Max.y - 24) {
                    anchor = instruction.address; beforeY = y; break;
                }
            }
        }
        // ImGui applies scroll targets on the next frame, and freezing the
        // header can reflow visible cells. Allow the bounded correction to
        // settle, then require the same actual glyph position and retired pan.
        for (int i = 0; i < 4; ++i) render();
        if (anchor) {
            CHECK(f.tab->liveIdxOf_.count(anchor) != 0);
            if (std::fabs(rowY(anchor) - beforeY) > 2.0f && refillDiagnostics++ < 2) {
                const auto* current = liveScrollTable();
                std::printf("[live scroll] anchor=%llX y %.2f -> %.2f, scroll %.2f -> %.2f, start=%llX -> %llX\n",
                    anchor, beforeY, rowY(anchor), beforeScroll,
                    current->InnerWindow->Scroll.y, beforeStart, f.tab->liveCacheStart_);
            }
            CHECK(std::fabs(rowY(anchor) - beforeY) <= 2.0f);
            CHECK(!f.tab->liveWindowPanScrollValid_);
            ++stableRefills;
        }
        retained();
    };
    auto wheel = [&](float amount) {
        ImGui::GetIO().AddMouseWheelEvent(0, amount);
        render(); finishInput();
    };
    // A short scroll leaves the source decoded in the very same window. The
    // repeat xref handoff must still center it, not treat the old focus as done.
    const float originalSourceY = rowY(source);
    const uint64_t sameWindowStart = f.tab->liveCacheStart_;
    wheel(-3);
    CHECK(f.tab->liveCacheStart_ == sameWindowStart);
    CHECK(std::fabs(rowY(source) - originalSourceY) > 20.0f);
    frame([&] { CHECK(f.tab->followXrefSource(f.ctx, 0)); });
    for (int i = 0; i < 4; ++i) render();
    if (std::fabs(rowY(source) - originalSourceY) > 2.0f)
        std::printf("[live scroll] repeat xref Y %.2f -> %.2f, rowheight=%.2f, scroll=%.2f\n",
            originalSourceY, rowY(source), liveScrollTable()->RowPosY2 - liveScrollTable()->RowPosY1,
            liveScrollTable()->InnerWindow->Scroll.y);
    CHECK(std::fabs(rowY(source) - originalSourceY) <= 2.0f);

    const uint64_t initialStart = f.tab->liveCacheStart_;
    for (int i = 0; i < 100 && initialStart - f.tab->liveCacheStart_ < 2048; ++i)
        wheel(8);
    CHECK(f.tab->liveCacheStart_ + 2048 <= initialStart);
    const uint64_t upperStart = f.tab->liveCacheStart_;
    for (int i = 0; i < 100 && f.tab->liveCacheStart_ < upperStart + 4096; ++i)
        wheel(-8);
    CHECK(f.tab->liveCacheStart_ >= upperStart + 4096);
    CHECK(stableRefills >= 8);

    auto page = [&](ImGuiKey key) {
        ImGui::FocusWindow(liveScrollTable()->InnerWindow);
        ImGui::GetIO().AddKeyEvent(key, true);
        render();
        ImGui::GetIO().AddKeyEvent(key, false);
        finishInput();
    };
    const uint64_t pageDownStart = f.tab->liveCacheStart_;
    for (int i = 0; i < 60 && f.tab->liveCacheStart_ < pageDownStart + 1024; ++i)
        page(ImGuiKey_PageDown);
    CHECK(f.tab->liveCacheStart_ >= pageDownStart + 1024);
    const uint64_t pageUpStart = f.tab->liveCacheStart_;
    for (int i = 0; i < 80 && f.tab->liveCacheStart_ + 1024 > pageUpStart; ++i)
        page(ImGuiKey_PageUp);
    CHECK(f.tab->liveCacheStart_ + 1024 <= pageUpStart);

    // Explicitly navigating to the same selected xref must reveal it again,
    // even though ordinary scrolling deliberately keeps that cursor selected.
    frame([&] { f.tab->liveNavigate(source); });
    for (int i = 0; i < 4; ++i) render();
    CHECK(f.tab->liveIdxOf_.count(source) != 0);
    table = liveScrollTable();
    CHECK(rowY(source) >= table->InnerWindow->InnerClipRect.Min.y);
    CHECK(rowY(source) < table->InnerWindow->InnerClipRect.Max.y);

    // The first earlier refill must cross the known function start, and quiet
    // frames must keep that committed start instead of reapplying the function
    // alignment hint and moving the view back down into the function.
    BinaryViewTab::Func function{};
    function.address = kTarget; function.name = "live_scroll_function"; function.size = 4096;
    f.tab->functions_ = {function};
    f.tab->funcIndex_.clear();
    f.tab->funcIndexDirty_ = true;
    ++f.tab->functionsGen_;
    frame([&] { f.tab->liveNavigate(source); });
    for (int i = 0; i < 4; ++i) render();
    CHECK(f.tab->liveCacheStart_ == scratch + kTarget);
    for (int i = 0; i < 20 && f.tab->liveCacheStart_ >= scratch + kTarget; ++i) wheel(8);
    CHECK(f.tab->liveCacheStart_ < scratch + kTarget);
    const uint64_t committedStart = f.tab->liveCacheStart_;
    const float committedScroll = liveScrollTable()->InnerWindow->Scroll.y;
    for (int i = 0; i < 8; ++i) {
        render();
        CHECK(f.tab->liveCacheStart_ == committedStart);
        CHECK(std::fabs(liveScrollTable()->InnerWindow->Scroll.y - committedScroll) <= 0.5f);
    }

    // Following the real paused RIP should stop as soon as the analyst wheels
    // within the current window. A later refresh must preserve that viewport.
    f.tab->functions_.clear(); f.tab->funcIndex_.clear();
    f.tab->funcIndexDirty_ = true; ++f.tab->functionsGen_;
    f.tab->followLiveRip_ = true;
    f.tab->liveBrowseValid_ = false;
    f.tab->lastScrolledRipValid_ = false;
    for (int i = 0; i < 4; ++i) render();
    const uint64_t ripWindowStart = f.tab->liveCacheStart_;
    const float ripScroll = liveScrollTable()->InnerWindow->Scroll.y;
    ImGui::GetIO().AddMouseWheelEvent(0, -1);
    render(); render(); render();
    CHECK(!f.tab->followLiveRip_);
    CHECK(f.tab->liveCacheStart_ == ripWindowStart);
    const float manualRipScroll = liveScrollTable()->InnerWindow->Scroll.y;
    CHECK(manualRipScroll > ripScroll + 1.0f);
    ++f.tab->liveGen_;
    for (int i = 0; i < 4; ++i) render();
    CHECK(f.tab->liveCacheStart_ == ripWindowStart);
    CHECK(std::fabs(liveScrollTable()->InnerWindow->Scroll.y - manualRipScroll) <= 0.5f);

    // Give the child an explicit unreadable page, so downward refill cannot
    // advance. Retain the useful preceding rows on repeated attempts and quiet
    // frames, then restore the allocation's original protection.
    HANDLE childProcess = static_cast<HANDLE>(f.ctx.debug.duplicateProcessHandleForSession(owner));
    CHECK(childProcess != nullptr);
    if (childProcess) {
        const uint64_t guard = scratch + 0x40000;
        DWORD oldProtection = 0;
        const BOOL protectedPage = VirtualProtectEx(childProcess,
            reinterpret_cast<void*>(guard), 4096, PAGE_NOACCESS, &oldProtection);
        CHECK(protectedPage != FALSE);
        if (protectedPage) {
            frame([&] { f.tab->liveNavigate(guard - 32); });
            for (int i = 0; i < 4; ++i) render();
            CHECK(!f.tab->liveInsns_.empty());
            const uint64_t boundaryStart = f.tab->liveCacheStart_;
            const uint64_t boundaryLast = f.tab->liveInsns_.back().address;
            const size_t boundaryCount = f.tab->liveInsns_.size();
            int blockedRefills = 0;
            for (int i = 0; i < 8; ++i) {
                ImGui::GetIO().AddMouseWheelEvent(0, -20);
                render();
                if (f.tab->liveBrowseRefillDirection_) ++blockedRefills;
                render(); render();
                CHECK(liveScrollTable() != nullptr);
                CHECK(f.tab->liveCacheStart_ == boundaryStart);
                CHECK(f.tab->liveInsns_.size() == boundaryCount);
                CHECK(f.tab->liveInsns_.back().address == boundaryLast);
            }
            CHECK(blockedRefills >= 2);
            DWORD ignored = 0;
            CHECK(VirtualProtectEx(childProcess, reinterpret_cast<void*>(guard),
                                  4096, oldProtection, &ignored) != FALSE);
        }
        CloseHandle(childProcess);
    }
    const DbgSnapshot after = f.ctx.debug.snapshot();
    CHECK(after.state == DbgState::Paused && after.pid == owner.pid &&
          after.sessionGeneration == owner.sessionGeneration &&
          after.regs.rip == originalRip && after.activeTid == originalTid);
    CHECK(after.breakpoints.empty() && after.hwBreakpoints.empty());
    CHECK(f.ctx.staticProject().patches.empty());
    std::vector<uint8_t> afterBytes(image.size());
    CHECK(f.ctx.debug.readMemoryMaskedForSession(owner.pid, owner.sessionGeneration,
        scratch, afterBytes.data(), afterBytes.size()) == afterBytes.size());
    CHECK(afterBytes == image);
    f.ctx.debug.detach();
    CHECK(!f.ctx.debug.memorySessionMatches(owner));
    std::printf("Live assembly scrolling: %s (%d new failure(s), %d stable refills)\n",
        failures == failuresBefore ? "passed" : "FAILED", failures - failuresBefore, stableRefills);
}
