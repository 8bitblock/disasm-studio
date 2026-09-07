// Drive the actual ImGui/std::string editor so callback ordering, clipboard
// insertion and its retained input buffer are covered at the persistence cap.
static void checkNotesEditorBoundaries() {
    ImGui::ClosePopupsOverWindow(nullptr, false);
    ImGui::ClearActiveID();
    std::string notes = std::string(20000, 'n') + "\nUTF-8: \xCE\xA9 \xF0\x9F\x94\x8D\n";
    ds::ui::NotesEditResult edit;
    ImGuiID id = 0;
    bool focus = true, reload = false;
    auto paint = [&] {
        frame([&] {
            if (focus) ImGui::SetKeyboardFocusHere();
            id = ImGui::GetID("##notes-boundary");
            edit = ds::ui::InputProjectNotes("##notes-boundary", notes, ImVec2(600, 300), reload);
        }, "Notes boundaries", ImVec2(700, 420));
        focus = reload = false;
        CHECK(GImGui->ErrorCountCurrentFrame == 0);
    };
    paint(); paint();
    CHECK(!edit.changed && !edit.rejected);
    auto* state = ImGui::GetInputTextState(id);
    CHECK(state != nullptr);
    if (!state) return;
    auto position = [&](int cursor) {
        state->ReloadUserBufAndKeepSelection();
        state->ReloadSelectionStart = state->ReloadSelectionEnd = cursor;
        paint();
        CHECK(state->GetCursorPos() == cursor && !state->HasSelection());
    };
    position(20000);
    ImGui::GetIO().AddInputCharactersUTF8("edited");
    paint();
    CHECK(edit.changed && !edit.rejected);
    CHECK(notes.substr(20000, 6) == "edited");

    // External note updates become visible even while the input owns focus.
    notes = "external \xCE\xA9 replacement";
    reload = true;
    paint();
    CHECK(std::string(state->TextA.Data) == notes);
    CHECK(!edit.changed && !edit.rejected);

    // 126 ordinary bytes plus a newline occupy 128 encoded JSON bytes.
    const size_t lines = ds::kProjectJsonStringTokenBytes / 128;
    notes.assign(lines * 127, 'n');
    for (size_t i = 126; i < notes.size(); i += 127) notes[i] = '\n';
    notes.replace(notes.size() - 7, 7, "\xCE\xA9\xF0\x9F\x94\x8D\n");
    const std::string full = notes;
    CHECK(ds::ProjectNotesFitPersistenceBudget(full));
    position(0);
    ImGui::GetIO().AddInputCharactersUTF8("x");
    paint();
    CHECK(edit.rejected && !edit.changed);
    CHECK(notes == full && state->TextLen == static_cast<int>(full.size()));
    CHECK(std::string(state->TextA.Data) == full);
    paint();
    CHECK(!edit.changed && !edit.rejected);

    position(static_cast<int>(notes.size() / 2));
    ImGui::SetClipboardText("\xCE\xA9\xF0\x9F\x94\x8D");
    ImGui::GetIO().AddKeyEvent(ImGuiMod_Ctrl, true);
    ImGui::GetIO().AddKeyEvent(ImGuiKey_V, true);
    paint();
    CHECK(edit.rejected && !edit.changed);
    CHECK(notes == full && std::string(state->TextA.Data) == full);
    ImGui::GetIO().AddKeyEvent(ImGuiKey_V, false);
    ImGui::GetIO().AddKeyEvent(ImGuiMod_Ctrl, false);
    paint();
    CHECK(!edit.changed && !edit.rejected);
    // Undo following a rejected paste must also keep the complete old value.
    ImGui::GetIO().AddKeyEvent(ImGuiMod_Ctrl, true);
    ImGui::GetIO().AddKeyEvent(ImGuiKey_Z, true);
    paint();
    CHECK(notes == full);
    ImGui::GetIO().AddKeyEvent(ImGuiKey_Z, false);
    ImGui::GetIO().AddKeyEvent(ImGuiMod_Ctrl, false);
    paint();
    ImGui::ClearActiveID();
}
