// Keep the shared full-suite source untouched while another task may compile it.
// /Gy + /OPT:REF discards its unused entrypoint and unrelated App/tab fixtures.
#define main staticListingFullSuiteMain
#include "static_listing_actions_test.cpp"
#undef main

int main() {
    char temporary[MAX_PATH]{};
    if (!GetEnvironmentVariableA("DS_STATIC_LISTING_TEST_ROOT", temporary, MAX_PATH)) return 2;
    const std::string path = std::string(temporary) + "\\listing.raw";
    {
        std::ofstream output(path, std::ios::binary);
        for (size_t i = 0; i < 128 * 4096 / 2; ++i) { output.put('\xFF'); output.put('\xC0'); }
    }
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.DeltaTime = 1.0f / 60.0f;
    io.Fonts->AddFontDefault();
    unsigned char* pixels = nullptr;
    int width = 0, height = 0;
    io.Fonts->GetTexDataAsRGBA32(&pixels, &width, &height);
    static std::string testClipboard;
    ImGui::GetPlatformIO().Platform_SetClipboardTextFn = [](ImGuiContext*, const char* value) {
        testClipboard = value ? value : "";
    };
    ImGui::GetPlatformIO().Platform_GetClipboardTextFn = [](ImGuiContext*) -> const char* {
        return testClipboard.c_str();
    };
    theme::ApplyTheme();
    try {
        checkReleaseWorkbench(path);
        checkRegisterEditorPresentation(path);
        checkInspectorObservationValidity(path);
    } catch (const std::exception& error) {
        std::printf("EXCEPTION: %s\n", error.what());
        ++failures;
    }
    ImGui::DestroyContext();
    std::printf("release_workbench_test: %s (%d failure(s))\n", failures ? "FAILED" : "passed", failures);
    return failures ? 1 : 0;
}
