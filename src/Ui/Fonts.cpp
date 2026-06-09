#include "Fonts.h"
#include "imgui.h"

namespace ds::ui {

ImFont* gUiFont   = nullptr;
ImFont* gMonoFont = nullptr;

void PushMono() {
    ImGui::PushFont(gMonoFont ? gMonoFont : ImGui::GetFont());
}
void PopMono() {
    ImGui::PopFont();
}

} // namespace ds::ui
