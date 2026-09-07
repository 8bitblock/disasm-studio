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
