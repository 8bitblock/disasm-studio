// Production Hex view input keeps cursor, visible selection and copied bytes
// aligned. No target process is attached and no byte-edit command is exercised.
static void checkHexRefinement(const std::string& path) {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    ImGuiIO& io = ImGui::GetIO();
    io.ClearInputKeys(); io.ClearInputMouse();
    Fixture f(path);
    f.tab->navigateToFileOffset(f.ctx, 48);
    ImVec2 size(420, 600);
    auto paint = [&] {
        frame([&] { f.tab->renderHex(f.ctx); }, "Hex refinement QA", size);
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    auto settle = [&] { paint(); paint(); paint(); };
    settle();
    ImGuiWindow* hex = releaseWindow("/hex_");
    CHECK(hex != nullptr);
    if (!hex) return;
    ImGui::FocusWindow(hex);
    paint();
    auto key = [&](ImGuiKey value, bool shift = false, bool ctrl = false) {
        io.AddKeyEvent(ImGuiMod_Shift, shift);
        io.AddKeyEvent(ImGuiMod_Ctrl, ctrl);
        io.AddKeyEvent(value, true);
        paint();
        io.AddKeyEvent(value, false);
        io.AddKeyEvent(ImGuiMod_Shift, false);
        io.AddKeyEvent(ImGuiMod_Ctrl, false);
        paint();
    };
    CHECK(f.tab->hexCursorOff_ == 48 && f.tab->hexSelA_ == 48 && f.tab->hexSelB_ == 48);
    key(ImGuiKey_RightArrow, true);
    CHECK(f.tab->hexCursorOff_ == 49 && f.tab->hexSelA_ == 48 && f.tab->hexSelB_ == 49);
    key(ImGuiKey_DownArrow, true);
    CHECK(f.tab->hexCursorOff_ == 65 && f.tab->hexSelA_ == 48 && f.tab->hexSelB_ == 65);
    key(ImGuiKey_LeftArrow);
    CHECK(f.tab->hexCursorOff_ == 64 && f.tab->hexSelA_ == 64 && f.tab->hexSelB_ == 64);
    key(ImGuiKey_RightArrow);
    CHECK(f.tab->hexCursorOff_ == 65 && f.tab->hexSelA_ == 65 && f.tab->hexSelB_ == 65);
    key(ImGuiKey_Home);
    CHECK(f.tab->hexCursorOff_ == 64 && f.tab->hexSelA_ == 64 && f.tab->hexSelB_ == 64);
    key(ImGuiKey_End, true);
    CHECK(f.tab->hexCursorOff_ == 79 && f.tab->hexSelA_ == 64 && f.tab->hexSelB_ == 79);
    key(ImGuiKey_C, false, true);
    std::string expected;
    char byte[4];
    for (size_t offset = 64; offset <= 79; ++offset) {
        std::snprintf(byte, sizeof(byte), "%02X", f.ctx.staticBinary().bytes()[offset]);
        if (!expected.empty()) expected += ' ';
        expected += byte;
    }
    CHECK(std::string(ImGui::GetClipboardText()) == expected);
    key(ImGuiKey_Home, false, true);
    CHECK(f.tab->hexCursorOff_ == 0 && f.tab->hexSelA_ == 0 && f.tab->hexSelB_ == 0);
    key(ImGuiKey_End, false, true);
    const uint64_t last = f.ctx.staticBinary().bytes().size() - 1;
    CHECK(f.tab->hexCursorOff_ == last && f.tab->hexSelA_ == last && f.tab->hexSelB_ == last);
    key(ImGuiKey_RightArrow);
    CHECK(f.tab->hexCursorOff_ == last && f.tab->hexSelB_ == last);
    key(ImGuiKey_Tab);
    CHECK(f.tab->hexAsciiCol_);
    key(ImGuiKey_Tab);
    CHECK(!f.tab->hexAsciiCol_);
    f.tab->navigateToFileOffset(f.ctx, 128);
    settle();
    CHECK(f.tab->hexCursorOff_ == 128 && f.tab->hexSelA_ == 128 && f.tab->hexSelB_ == 128);
    f.tab->restoreNavigationLocation({32, true, DocumentView::Hex, DocumentAddressSpace::FileOffset});
    settle();
    CHECK(f.tab->hexCursorOff_ == 32 && f.tab->hexSelA_ == 32 && f.tab->hexSelB_ == 32);
    f.tab->hexSelA_ = last + 1; f.tab->hexSelB_ = last + 2;
    settle();
    CHECK(f.tab->hexSelA_ == ~0ull && f.tab->hexSelB_ == ~0ull);
    CHECK(f.ctx.staticProject().patches.empty());

    const float oldScale = theme::UiScale();
    const float oldFontScale = io.FontGlobalScale;
    const auto oldTheme = theme::CurrentTheme();
    ImGui::FocusWindow(nullptr);
    // This fixture runs last: rebuilding the production atlas replaces the
    // default test font and global icon/mono handles. Do not change the font
    // geometry of earlier fixtures that intentionally use AddFontDefault().
    for (float scale : {1.0f, 1.5f, 2.0f}) {
        io.FontGlobalScale = 1.0f;
        ui::LoadFonts(scale);
        unsigned char* pixels = nullptr; int atlasWidth = 0, atlasHeight = 0;
        io.Fonts->GetTexDataAsRGBA32(&pixels, &atlasWidth, &atlasHeight);
        CHECK(pixels && atlasWidth > 0 && atlasHeight > 0);
        theme::SetUiScale(scale);
        for (auto palette : {theme::ThemeId::Midnight, theme::ThemeId::Light}) {
            theme::ApplyTheme(palette);
            for (float width : {340.0f, 540.0f, 980.0f}) {
                size = ImVec2(width * scale, 600.0f * scale);
                settle();
                ImGuiWindow* outer = ImGui::FindWindowByName("Hex refinement QA");
                hex = releaseWindow("/hex_");
                CHECK(outer && hex);
                if (outer && hex) {
                    // Only the byte grid scrolls horizontally. Help and actions
                    // fit above it at compact widths and independent DPI/zoom.
                    CHECK(outer->ScrollMax.x <= 1.0f);
                    CHECK(outer->ScrollMax.y <= 1.0f);
                    CHECK(hex->InnerRect.GetHeight() >= 150.0f * scale);
                    CHECK(hex->Pos.x >= outer->InnerRect.Min.x - 1.0f);
                    CHECK(hex->Pos.x + hex->Size.x <= outer->InnerRect.Max.x + 1.0f);
                }
            }
        }
    }
    theme::SetUiScale(oldScale);
    theme::ApplyTheme(oldTheme);
    ui::LoadFonts(oldScale);
    unsigned char* pixels = nullptr; int atlasWidth = 0, atlasHeight = 0;
    io.Fonts->GetTexDataAsRGBA32(&pixels, &atlasWidth, &atlasHeight);
    CHECK(pixels && atlasWidth > 0 && atlasHeight > 0);
    io.FontGlobalScale = oldFontScale;
    io.ClearInputKeys(); io.ClearInputMouse();
    ImGui::ClearActiveID();
}
