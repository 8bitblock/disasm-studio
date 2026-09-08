// Links the actual listing copy/signature actions against the isolated clipboard
// configured by main. A read failure must leave the prior clipboard untouched.
static void checkInstructionCopy(const std::string& path) {
    Fixture f(path);
    CHECK(f.clickRow(kTarget, false));
    auto copyChord = [&](bool wildcard) {
        ImGuiIO& io = ImGui::GetIO();
        io.AddKeyEvent(ImGuiMod_Ctrl, true);
        if (wildcard) io.AddKeyEvent(ImGuiMod_Shift, true);
        io.AddKeyEvent(ImGuiKey_C, true);
        f.assemblyFrame();
        io.AddKeyEvent(ImGuiKey_C, false);
        io.AddKeyEvent(ImGuiMod_Ctrl, false);
        if (wildcard) io.AddKeyEvent(ImGuiMod_Shift, false);
        f.assemblyFrame();
    };
    ImGui::SetClipboardText("before shortcut");
    copyChord(false);
    CHECK(std::string(ImGui::GetClipboardText()) == "FF C0");
    ImGui::SetClipboardText("before wildcard shortcut");
    copyChord(true);
    CHECK(std::string(ImGui::GetClipboardText()) == "FF C0");

    f.select({kTarget, kTarget + 2});
    f.selectionMenu("Copy bytes (without wildcards)##sel");
    CHECK(std::string(ImGui::GetClipboardText()) == "FF C0 FF C0");
    f.selectionMenu("Copy bytes (with wildcards)##sel");
    CHECK(std::string(ImGui::GetClipboardText()) == "FF C0 FF C0");
    frame([&] { f.tab->copyAssemblyBytes(f.ctx, f.detached, false, false, true); });
    CHECK(std::string(ImGui::GetClipboardText()) == "{ 0xFF, 0xC0, 0xFF, 0xC0 }");

    f.select({kTarget, kTarget + 4});
    frame([&] { f.tab->copyAssemblyBytes(f.ctx, f.detached, false, false); });
    CHECK(std::string(ImGui::GetClipboardText()) == "FF C0\nFF C0");
    f.select({kTarget, UINT64_MAX});
    ImGui::SetClipboardText("preserve on failed copy");
    frame([&] { f.tab->copyAssemblyBytes(f.ctx, f.detached, false, false); });
    CHECK(std::string(ImGui::GetClipboardText()) == "preserve on failed copy");
    // A detached/stale LIVE selection never copies from the FILE image.
    frame([&] { f.tab->copyAssemblyBytes(f.ctx, f.detached, true, false); });
    CHECK(std::string(ImGui::GetClipboardText()) == "preserve on failed copy");

    f.tab->selVAs_.clear();
    const uint8_t code[] = {0x48, 0xE8, 0x12, 0x34, 0x56, 0x78,
        0xC7, 0x05, 0x56, 0x34, 0x12, 0x00, 0x0A, 0x00, 0x00, 0x00};
    CHECK(f.ctx.writeStaticImage(kTarget, code, sizeof(code)) == sizeof(code));
    CHECK(f.tab->buildSignature(f.ctx, kTarget, kTarget, false, false) == "48 E8 12 34 56 78");
    CHECK(f.tab->buildSignature(f.ctx, kTarget, kTarget, false, true) == "48 E8 ?? ?? ?? ??");
    CHECK(f.tab->buildSignature(f.ctx, kTarget, kTarget + 6, false, true) ==
          "48 E8 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? 0A 00 00 00");
    CHECK(f.tab->buildSignature(f.ctx, kTarget, kTarget + 2, false, false).empty());
    CHECK(f.tab->buildSignature(f.ctx, kTarget + 1024, kTarget, false, false).empty());
    CHECK(f.tab->buildSignature(f.ctx, kTarget + 1024, kTarget + 2048, false, false).empty());
    CHECK(f.tab->buildSignature(f.ctx, UINT64_MAX, UINT64_MAX, false, false).empty());
    CHECK(f.tab->buildSignature(f.ctx, kTarget, kTarget, true, false, &f.detached).empty());
}
