#include "Ui/Widgets.h"
#include "Ui/Theme.h"
#include "Ui/Fonts.h"
#include "imgui.h"
#include "imgui_internal.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>

static void frame(float width, const std::function<void()>& body) {
    ImGui::GetIO().DisplaySize = ImVec2(width, 700);
    ImGui::NewFrame();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImVec2(width, 700));
    ImGui::Begin("test", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoSavedSettings);
    body();
    ImGui::End();
    ImGui::Render();
}

int main() {
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.DeltaTime = 1.0f / 60.0f;
    io.Fonts->AddFontDefault();
    unsigned char* pixels; int width, height;
    io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
    ds::theme::ApplyTheme();

    // Long source names and counters must wrap inside a section header without
    // covering its following actions or treating literal ## as an ImGui ID.
    for (int theme = 0; theme < static_cast<int>(ds::theme::ThemeId::Count); ++theme) {
        ds::theme::ApplyTheme(static_cast<ds::theme::ThemeId>(theme));
        for (float paneWidth : {240.0f, 700.0f}) {
            frame(paneWidth, [&] {
                const float right = ImGui::GetCursorScreenPos().x + ImGui::GetContentRegionAvail().x;
                ImGui::LogToBuffer();
                ds::ui::PanelHeader("Selected target ## analyst name",
                    "A long file name with spaces and explicit FILE ownership");
                const ImVec2 headerEnd = ImGui::GetItemRectMax();
                assert(headerEnd.x <= right + 1.0f);
                assert(std::strstr(GImGui->LogBuffer.c_str(), "## analyst name"));
                ImGui::LogFinish();
                ImGui::Button("Open target");
                assert(ImGui::GetItemRectMin().y >= headerEnd.y);
                assert(GImGui->ErrorCountCurrentFrame == 0);
            });
        }
    }
    ds::theme::ApplyTheme(ds::theme::ThemeId::Midnight);

    // A toolbar wraps only when the next complete control would be clipped.
    frame(280, [] {
        ImGui::Button("First", ImVec2(150, 30));
        const float row = ImGui::GetItemRectMin().y;
        ds::ui::SameLineIfFits(150);
        ImGui::Button("Second", ImVec2(150, 30));
        assert(ImGui::GetItemRectMin().y > row);
    });
    frame(640, [] {
        ImGui::Button("First", ImVec2(150, 30));
        const float row = ImGui::GetItemRectMin().y;
        ds::ui::SameLineIfFits(150);
        ImGui::Button("Second", ImVec2(150, 30));
        assert(ImGui::GetItemRectMin().y == row);
    });

    // The former fixed-height onboarding panel hid its action once its copy
    // wrapped. Inspect the real ImGui child after layout settles at narrow width.
    for (int i = 0; i < 3; ++i) frame(300, [] {
        ds::ui::EmptyState(nullptr, "No binary loaded",
            "Open a binary to detect capabilities from imports, section names, and byte patterns. "
            "Choose a file to start investigating its functions and references.", "Open Binary...");
    });
    bool foundEmpty = false;
    for (ImGuiWindow* window : GImGui->Windows) {
        if (std::strstr(window->Name, "empty_state")) {
            foundEmpty = true;
            assert(window->ScrollMax.y == 0.0f);
            assert(window->ScrollMax.x == 0.0f);
        }
    }
    assert(foundEmpty);

    // Details must retain long paths at narrow widths, including inside an
    // indented group. Values stay within the content bounds at every scale.
    for (float scale : {1.0f, 1.5f, 2.0f}) {
        ds::theme::SetUiScale(scale);
        ds::theme::ApplyTheme();
        for (float paneWidth : {240.0f, 520.0f}) {
            frame(paneWidth * scale, [&] {
                ImGui::Indent(24.0f * scale);
                const ImVec2 origin = ImGui::GetCursorScreenPos();
                const float right = origin.x + ImGui::GetContentRegionAvail().x;
                ds::ui::KeyValueRow("Project path", "%s",
                    "C:\\Analyses\\firmware-and-library-investigation\\release\\reference-image-with-a-long-name.bin");
                assert(ImGui::GetItemRectMin().x >= origin.x - 1.0f);
                assert(ImGui::GetItemRectMax().x <= right + 1.0f);
                if (paneWidth < 300.0f) {
                    assert(ImGui::GetItemRectSize().y > ImGui::GetTextLineHeight());
                    assert(ImGui::GetItemRectMin().y > origin.y);
                } else
                    assert(ImGui::GetItemRectMin().y >= origin.y - 1.0f &&
                           ImGui::GetItemRectMin().y <= origin.y + 1.0f);
                ImGui::Unindent(24.0f * scale);
            });
        }
    }
    ds::theme::SetUiScale(1.0f);
    ds::theme::ApplyTheme();

    const char* labels[] = {"Assembly", "Pseudocode", "Hex", "Graph", "Call Graph", "Overview", "Live Assembly"};
    const bool enabled[] = {true, true, true, true, true, true, false};
    int selected = 0;
    auto tabs = [&] { selected = ds::ui::TabStrip("views", labels, 7, selected, enabled); };
    for (int i = 0; i < 4; ++i) frame(320, tabs);
    selected = 5; // external navigation to a destination beyond the visible strip
    for (int i = 0; i < 30; ++i) frame(320, tabs);
    assert(selected == 5);
    ImGuiTabBar* bar = GImGui->TabBars.GetByIndex(0);
    assert(bar->WidthAllTabs > bar->BarRect.GetWidth());
    assert(bar->ScrollingAnim > 0);
    ImGuiTabItem* selectedTab = ImGui::TabBarFindTabByID(bar, bar->SelectedTabId);
    assert(selectedTab && std::strcmp(ImGui::TabBarGetTabName(bar, selectedTab), "Overview") == 0);

    // Resize and click an ordinary destination; the caller-owned selection must
    // follow the native tab bar instead of resetting to the old external value.
    for (int i = 0; i < 30; ++i) frame(1000, tabs);
    bar = GImGui->TabBars.GetByIndex(0);
    ImGuiTabItem& hex = bar->Tabs[2];
    const ImVec2 target(bar->BarRect.Min.x + hex.Offset - bar->ScrollingAnim + hex.Width * 0.5f,
                        bar->BarRect.GetCenter().y);
    io.AddMousePosEvent(target.x, target.y);
    frame(1000, tabs);
    io.AddMouseButtonEvent(ImGuiMouseButton_Left, true);
    frame(1000, tabs);
    io.AddMouseButtonEvent(ImGuiMouseButton_Left, false);
    for (int i = 0; i < 3; ++i) frame(1000, tabs);
    assert(selected == 2);
    selected = 6;
    for (int i = 0; i < 3; ++i) frame(1000, tabs);
    assert(selected == 0); // disabled external destinations never become active

    // The first count tab performs native tab-bar layout, including its overflow
    // controls and open tab-list popup. Hiding Text around BeginTabItem used to
    // hide the popup's actual glyphs as well. Exercise the native menu, not just
    // its item IDs or the custom count drawing.
    io.ClearInputKeys();
    io.ClearInputMouse();
    io.AddMousePosEvent(-FLT_MAX, -FLT_MAX);
    const char* countLabels[] = {"Breakpoints###count-breakpoints", "Threads", "Modules"};
    ImGuiID nativeTabIds[3]{};
    ImGuiID nativeNestedId = 0;
    ImGuiTabBar* countBar = nullptr;
    ImVec2 countBarOrigin;
    auto countTabs = [&](bool counted) {
        countBarOrigin = ImGui::GetCursorScreenPos();
        if (ImGui::BeginTabBar("count-overflow", ImGuiTabBarFlags_TabListPopupButton |
                              ImGuiTabBarFlags_FittingPolicyScroll)) {
            countBar = GImGui->CurrentTabBar;
            for (int index = 0; index < 3; ++index) {
                const bool open = counted
                    ? ds::ui::BeginCountTabItem(countLabels[index], 12 + index)
                    : ImGui::BeginTabItem(countLabels[index]);
                if (counted) assert(GImGui->LastItemData.ID == nativeTabIds[index]);
                else nativeTabIds[index] = GImGui->LastItemData.ID;
                if (open) {
                    if (index == 0) {
                        if (counted) assert(ImGui::GetID("nested-table") == nativeNestedId);
                        else nativeNestedId = ImGui::GetID("nested-table");
                    }
                    ImGui::EndTabItem();
                }
            }
            ImGui::EndTabBar();
        }
        assert(GImGui->ErrorCountCurrentFrame == 0);
    };
    for (int index = 0; index < 3; ++index) frame(210, [&] { countTabs(false); });
    assert(nativeNestedId != 0);
    for (int index = 0; index < 4; ++index) frame(210, [&] { countTabs(true); });
    assert(countBar && countBar->WidthAllTabsIdeal > countBar->BarRect.GetWidth());
    // The list button sits immediately before the native tab labels.
    const ImVec2 countMenu(countBarOrigin.x + ImGui::GetFontSize() * 0.5f,
                          countBar->BarRect.GetCenter().y);
    io.AddMousePosEvent(countMenu.x, countMenu.y);
    frame(210, [&] { countTabs(true); });
    io.AddMouseButtonEvent(ImGuiMouseButton_Left, true);
    frame(210, [&] { countTabs(true); });
    io.AddMouseButtonEvent(ImGuiMouseButton_Left, false);
    for (int index = 0; index < 3; ++index) frame(210, [&] { countTabs(true); });
    bool visibleMenuGlyphs = false;
    const ImFontGlyph* menuGlyph = ImGui::GetFont()->FindGlyph('B');
    assert(menuGlyph); // the first menu item is Breakpoints
    for (ImGuiWindow* window : GImGui->Windows) {
        if (window->LastFrameActive != ImGui::GetFrameCount() ||
            !(window->Flags & ImGuiWindowFlags_Popup) ||
            std::strncmp(window->Name, "##Combo_", 8) != 0) continue;
        for (const ImDrawVert& vertex : window->DrawList->VtxBuffer) {
            // Check an actual menu-letter UV, excluding textured anti-aliased
            // borders as well as ordinary backgrounds and arrow triangles.
            if ((vertex.col & IM_COL32_A_MASK) != 0 &&
                vertex.uv.x == menuGlyph->U0 && vertex.uv.y == menuGlyph->V0) {
                visibleMenuGlyphs = true;
                break;
            }
        }
    }
    assert(visibleMenuGlyphs);
    io.AddKeyEvent(ImGuiKey_Escape, true);
    frame(210, [&] { countTabs(true); });
    io.AddKeyEvent(ImGuiKey_Escape, false);
    frame(210, [&] { countTabs(true); });
    io.ClearInputKeys();
    io.ClearInputMouse();
    io.AddMousePosEvent(-FLT_MAX, -FLT_MAX);

    // Custom pills participate in keyboard navigation and activate with Space.
    bool pressed = false;
    bool requestFocus = true;
    auto pill = [&] {
        if (requestFocus) ImGui::SetKeyboardFocusHere();
        pressed |= ds::ui::Pill("pill", "Architecture");
    };
    frame(500, pill);
    requestFocus = false;
    frame(500, pill);
    io.AddKeyEvent(ImGuiKey_Tab, true);
    frame(500, pill);
    io.AddKeyEvent(ImGuiKey_Tab, false);
    frame(500, pill);
    io.AddKeyEvent(ImGuiKey_Space, true);
    frame(500, pill);
    io.AddKeyEvent(ImGuiKey_Space, false);
    frame(500, pill);
    assert(pressed);
    ImGui::DestroyContext();
    std::puts("ui_widgets_test: passed");
}
