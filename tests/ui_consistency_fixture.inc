// Independent integration review: every shipped palette and density must keep
// the same destinations, shell bounds, and usable palette at both zoom sizes.
static void checkUiConsistencyMatrix() {
    ImGuiIO& io = ImGui::GetIO();
    const auto priorTheme = theme::CurrentTheme();
    const auto priorDensity = theme::CurrentDensity();
    const float priorScale = theme::UiScale();
    const int priorZoom = theme::UiZoomPercent();
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    io.ClearInputKeys(); io.ClearInputMouse();
    App app;
    const char* destinations[] = {"Projects", "Communications", "Sig Scanner", "Binary View",
        "Memory Tools", "Binary Diff", "Binary Tech", "Cortex", "Prism"};
    struct ScaleCase { int zoom; float dpi; };
    for (const ScaleCase scaling : {ScaleCase{90, 1.0f}, ScaleCase{150, 1.0f},
                                   ScaleCase{75, 2.0f}, ScaleCase{90, 1.5f}}) {
        const float scale = scaling.dpi * scaling.zoom / 100.0f;
        const float previouslyApplied = theme::UiScale();
        theme::SetUiZoomPercent(scaling.zoom);
        CHECK(theme::UiScale() == previouslyApplied); // host applies between frames
        ui::LoadFonts(scale);
        unsigned char* pixels = nullptr; int width = 0, height = 0;
        io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
        CHECK(pixels && width > 0 && height > 0);
        theme::SetUiScale(scale);
        for (auto density : {theme::Density::Compact, theme::Density::Comfortable, theme::Density::Spacious}) {
            theme::SetDensity(density);
            for (int palette = 0; palette < static_cast<int>(theme::ThemeId::Count); ++palette) {
                const auto selectedTheme = static_cast<theme::ThemeId>(palette);
                theme::ApplyTheme(selectedTheme);
                CHECK(theme::UiZoomPercent() == scaling.zoom);
                CHECK(theme::UiScale() == scale);
                for (const ImVec2 size : {ImVec2(820, 560), ImVec2(1440, 900), ImVec2(1600, 960)}) {
                    std::printf("[consistency] %s / %s / zoom %d%% / DPI %.2fx / %.0fx%.0f\n",
                        theme::ThemeName(selectedTheme), theme::DensityName(density),
                        scaling.zoom, scaling.dpi, size.x, size.y);
                    for (int settle = 0; settle < 3; ++settle) workbenchFrame(app, size);
                    for (int tab = 0; tab < 9; ++tab) {
                        workbenchChord(app, size, static_cast<ImGuiKey>(ImGuiKey_1 + tab));
                        checkWorkbenchDestination(destinations[tab]);
                        checkWorkbenchBounds(size);
                        CHECK(GImGui->ErrorCountCurrentFrame == 0);
                    }
                    workbenchChord(app, size, ImGuiKey_K);
                    for (int settle = 0; settle < 3; ++settle) workbenchFrame(app, size);
                    ImGuiWindow* paletteWindow = ImGui::FindWindowByName("##cmdpalette");
                    CHECK(paletteWindow && paletteWindow->LastFrameActive == ImGui::GetFrameCount());
                    if (paletteWindow) {
                        CHECK(paletteWindow->Pos.x >= 0 && paletteWindow->Pos.y >= 0);
                        CHECK(paletteWindow->Pos.x + paletteWindow->Size.x <= size.x + 1);
                        CHECK(paletteWindow->Pos.y + paletteWindow->Size.y <= size.y + 1);
                        CHECK(paletteWindow->ScrollMax.x <= 1 && paletteWindow->ScrollMax.y <= 1);
                    }
                    CHECK(GImGui->ErrorCountCurrentFrame == 0);
                    workbenchChord(app, size, ImGuiKey_K);
                    CHECK(!app.wantsExit());
                }
            }
        }
    }
    // Mouse-route every full workspace label in the actual shell. Keyboard
    // shortcuts and compact overflow inventory are covered by the matrix above.
    const ImVec2 mouseSize(1920, 1200);
    theme::SetUiScale(0.9f);
    theme::SetDensity(theme::Density::Compact);
    theme::ApplyTheme(theme::ThemeId::Axiom);
    ui::LoadFonts(0.9f);
    unsigned char* mousePixels = nullptr; int mouseWidth = 0, mouseHeight = 0;
    io.Fonts->GetTexDataAsRGBA32(&mousePixels, &mouseWidth, &mouseHeight);
    for (int settle = 0; settle < 3; ++settle) workbenchFrame(app, mouseSize);
    ImGuiWindow* strip = ImGui::FindWindowByName("##tabstrip");
    CHECK(strip);
    if (strip) {
        float x = strip->Pos.x + 8.0f * theme::UiScale();
        const float y = strip->Pos.y + strip->Size.y * 0.5f;
        for (int tab = 0; tab < 9; ++tab) {
            const bool badge = tab == 1 || tab == 3;
            const float width = std::max(62.0f * theme::UiScale(),
                ImGui::CalcTextSize(destinations[tab]).x + (badge ? 38.0f : 24.0f) * theme::UiScale());
            io.AddMousePosEvent(x + width * 0.5f, y);
            workbenchFrame(app, mouseSize);
            io.AddMouseButtonEvent(ImGuiMouseButton_Left, true);
            workbenchFrame(app, mouseSize);
            io.AddMouseButtonEvent(ImGuiMouseButton_Left, false);
            workbenchFrame(app, mouseSize);
            workbenchFrame(app, mouseSize);
            checkWorkbenchDestination(destinations[tab]);
            x += width;
        }
    }
    io.AddMousePosEvent(-FLT_MAX, -FLT_MAX);
    theme::SetUiZoomPercent(priorZoom);
    theme::SetUiScale(priorScale); theme::SetDensity(priorDensity); theme::ApplyTheme(priorTheme);
    ui::LoadFonts(priorScale);
    unsigned char* pixels = nullptr; int width = 0, height = 0;
    io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
    io.ClearInputKeys(); io.ClearInputMouse();
}
