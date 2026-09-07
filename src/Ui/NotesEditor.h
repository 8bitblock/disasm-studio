#pragma once

#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_stdlib.h"
#include "../Core/Project.h"
#include <algorithm>
#include <cstring>
#include <string>

namespace ds::ui {

struct NotesEditResult { bool changed = false; bool rejected = false; };

// CallbackEdit runs on ImGui's internal buffer before imgui_stdlib resizes or
// copies into the supplied string. The prior value therefore stays available
// without taking a full-text snapshot on every frame. Rejected edits restore
// that complete prior value, including text after a middle insertion.
inline NotesEditResult InputProjectNotes(const char* label, std::string& notes,
                                        ImVec2 size, bool reload = false) {
    if (reload)
        if (auto* state = ImGui::GetInputTextState(ImGui::GetID(label)))
            state->ReloadUserBufAndKeepSelection();
    struct EditContext {
        const std::string* previous;
        bool rejected = false;
    } context{&notes};
    const bool changed = ImGui::InputTextMultiline(label, &notes, size,
        ImGuiInputTextFlags_CallbackEdit, [](ImGuiInputTextCallbackData* data) {
            auto& edit = *static_cast<EditContext*>(data->UserData);
            if (data->EventFlag != ImGuiInputTextFlags_CallbackEdit ||
                ProjectNotesFitPersistenceBudget(std::string_view(data->Buf, data->BufTextLen))) return 0;
            const auto& previous = *edit.previous;
            // Existing project notes are bounded by the project JSON reader.
            // The oversized edited buffer has room for the full prior value.
            IM_ASSERT(previous.size() < static_cast<size_t>(data->BufSize));
            std::memcpy(data->Buf, previous.c_str(), previous.size() + 1);
            data->BufTextLen = static_cast<int>(previous.size());
            int cursor = std::clamp(data->CursorPos, 0, data->BufTextLen);
            while (cursor > 0 && cursor < data->BufTextLen &&
                   (static_cast<unsigned char>(data->Buf[cursor]) & 0xC0) == 0x80) --cursor;
            data->CursorPos = data->SelectionStart = data->SelectionEnd = cursor;
            data->BufDirty = true;
            edit.rejected = true;
            return 0;
        }, &context);
    return {changed && !context.rejected, context.rejected};
}

} // namespace ds::ui
