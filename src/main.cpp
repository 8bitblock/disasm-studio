//
// main.cpp
// Win32 + DirectX 11 host for the ImGui-based disassembler workbench.
// Based on the canonical Dear ImGui example_win32_directx11 backend, with
// docking + 3D-accelerated (hardware) rendering enabled.
//
#include "App.h"
#include "Ui/Fonts.h"
#include "resource.h"

#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"

#include <d3d11.h>
#include <windows.h>
#include <shellapi.h>
#include <fstream>
#include <string>
#include <tchar.h>
#include <utility>

// --- Direct3D 11 globals -----------------------------------------------------
static ID3D11Device*           g_pd3dDevice          = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext   = nullptr;
static IDXGISwapChain*         g_pSwapChain          = nullptr;
static bool                    g_SwapChainOccluded   = false;
static UINT                    g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
// WndProc and the render loop run on the same UI thread. WM_DPICHANGED stores
// only the newest requested DPI here; ImGui/font/DX11 work happens later,
// between frames, after the message queue has drained.
static constexpr UINT          kDefaultDpi = 96;
static UINT                    g_AppliedDpi = kDefaultDpi;
static UINT                    g_PendingDpi = 0;
// Separate from g_AppliedDpi: a failed B-scale rebuild has already destroyed
// the prior A-scale texture even though A remains the last successfully applied
// DPI. Equality is only a safe fast path while these resources are valid.
static bool                    g_DpiResourcesValid = true;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
bool ApplyPendingDpiChange();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ImGui's Win32 backend message handler.
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

// CommandLineToArgvW preserves quoted paths and non-ASCII characters. The rest
// of the application uses UTF-8 paths, matching the Win32 file-dialog bridge in
// App.cpp, so convert exactly once at the process boundary.
static std::string Utf8FromWide(const wchar_t* text) {
    if (!text || !*text) return {};
    int n = ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1,
                                  nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out((size_t)n, '\0');
    if (!::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text, -1,
                               out.data(), n, nullptr, nullptr))
        return {};
    out.pop_back();   // drop the converted NUL terminator
    return out;
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
    std::string startupPath;
    int argc = 0;
    if (wchar_t** argv = ::CommandLineToArgvW(::GetCommandLineW(), &argc)) {
        if (argc >= 2) startupPath = Utf8FromWide(argv[1]);
        ::LocalFree(argv);
    }

    // Per-monitor DPI awareness BEFORE any window exists, so Windows hands us
    // real pixels (no blurry bitmap upscaling) on HiDPI/4K displays. We then
    // scale fonts + style by the window's DPI ourselves for a crisp UI.
    ImGui_ImplWin32_EnableDpiAwareness();

    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0L, 0L,
                       hInstance, nullptr, nullptr, nullptr, nullptr,
                       L"DisasmStudioWnd", nullptr };
    // Application icon (embedded via app.rc): large for alt-tab/taskbar, small
    // for the window caption. Loaded from the multi-resolution app.ico.
    wc.hIcon   = (HICON)::LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_APPICON), IMAGE_ICON,
                                     0, 0, LR_DEFAULTSIZE | LR_SHARED);
    wc.hIconSm = (HICON)::LoadImageW(hInstance, MAKEINTRESOURCEW(IDI_APPICON), IMAGE_ICON,
                                     ::GetSystemMetrics(SM_CXSMICON),
                                     ::GetSystemMetrics(SM_CYSMICON), LR_SHARED);
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(wc.lpszClassName, L"DisasmStudio",
                                WS_OVERLAPPEDWINDOW, 100, 100, 1600, 960,
                                nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWMAXIMIZED);
    ::UpdateWindow(hwnd);

    // --- ImGui setup ---
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    // Browser-style single main window, BUT individual panels (side panel, debug
    // panels, the CFG and pseudocode views) can be "popped out" into their own OS
    // windows — so enable multi-viewport. The platform-window pump at the bottom of
    // the render loop is gated on this same flag.
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
    // Let ImGui preserve logical window/layout sizes when viewport DPI changes.
    // Fonts are deliberately not bitmap-scaled by ImGui: the host rebuilds a
    // crisp atlas at the destination monitor's native DPI instead.
    io.ConfigFlags |= ImGuiConfigFlags_DpiEnableScaleViewports;
    // Docking for the panels INSIDE Binary View (a per-page DockSpace): drag-resize,
    // re-dock, float as an OS window, or stack as tabs. Combined with ViewportsEnable,
    // a panel dragged out of the window becomes its own OS viewport for free.
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigViewportsNoTaskBarIcon = true;   // popped panels are tools, not separate apps

    // Persist the panel layout across sessions in %APPDATA%\DisasmStudio\imgui.ini.
    // ImGui stores the pointer (not a copy), so the path must outlive the context —
    // a function-local static is fine for the program's lifetime.
    static std::string iniPath;
    {
        char appdata[MAX_PATH] = {0};
        if (GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata))) {
            std::string dir = std::string(appdata) + "\\DisasmStudio";
            CreateDirectoryA(dir.c_str(), nullptr);
            iniPath = dir + "\\imgui.ini";
            io.IniFilename = iniPath.c_str();
        } else {
            io.IniFilename = nullptr;   // no APPDATA: don't persist
        }
    }

    ImGui::StyleColorsDark();
    ImGuiStyle& style = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
        style.WindowRounding = 0.0f;
        style.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // DPI scale for the display this window opened on. Fonts are loaded at the
    // scaled pixel size (so glyphs are crisp, not stretched) and the style metrics
    // are scaled to match via theme::SetUiScale (consumed when the theme applies).
    const float dpi = ImGui_ImplWin32_GetDpiScaleForHwnd(hwnd);
    ds::theme::SetUiScale(dpi);
    g_AppliedDpi = static_cast<UINT>(ds::theme::UiScale() * kDefaultDpi + 0.5f);
    g_PendingDpi = 0; // a pre-init notification is already reflected by the HWND

    // UI + mono faces, with the Segoe MDL2 icon font merged in (see Fonts.cpp).
    ds::ui::LoadFonts(ds::theme::UiScale());

    // The constructor applies the saved theme and, when supplied, opens the
    // command-line file through AppContext::loadBinaryPath.
    ds::App app(std::move(startupPath));

    bool running = true;
    // Idle throttle: when nothing is animating, block waiting for input instead of
    // spinning the GPU at vsync. `framesToRender` keeps a short burst of frames going
    // after any activity so ImGui animations (fades, scrolls) settle, and the finite
    // wait timeout is a backstop so any missed wake (e.g. a late analysis result)
    // self-corrects within a quarter second.
    int framesToRender = 4;
    while (running) {
        // Sleep until an input message arrives (or the fallback elapses) only when
        // fully idle: no queued frames and nothing the app wants animated.
        if (framesToRender <= 0 && !app.wantsContinuousRedraw())
            ::MsgWaitForMultipleObjects(0, nullptr, FALSE, 250, QS_ALLINPUT);

        MSG msg;
        bool gotMsg = false;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) running = false;
            gotMsg = true;
        }
        if (!running) break;
        if (gotMsg) framesToRender = 4;   // keep rendering briefly after any input

        // WM_DPICHANGED may arrive in a burst while the window crosses monitor
        // boundaries. Consume only the latest value, outside any ImGui frame,
        // and rebuild the atlas + its DX11 texture as one operation.
        if (ApplyPendingDpiChange()) framesToRender = 4;
        if (!g_DpiResourcesValid) {
            // Device-object creation failed. Rendering with the atlas texture
            // absent is unsafe, so keep pumping messages and retry at a bounded
            // rate. A newer WM_DPICHANGED replaces the queued DPI naturally.
            ::MsgWaitForMultipleObjects(0, nullptr, FALSE, 250, QS_ALLINPUT);
            continue;
        }

        // Skip rendering when minimized/occluded to save GPU.
        if (g_SwapChainOccluded && g_pSwapChain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED) {
            ::Sleep(10);
            continue;
        }
        g_SwapChainOccluded = false;

        if (g_ResizeWidth != 0 && g_ResizeHeight != 0) {
            CleanupRenderTarget();
            HRESULT hr = g_pSwapChain->ResizeBuffers(0, g_ResizeWidth, g_ResizeHeight, DXGI_FORMAT_UNKNOWN, 0);
            g_ResizeWidth = g_ResizeHeight = 0;
            // On device-removed/reset ResizeBuffers fails; don't (re)create an RTV from a
            // dead swapchain — leave it null and let the render guard below skip the frame.
            if (SUCCEEDED(hr)) CreateRenderTarget();
        }

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        app.render();
        if (app.wantsExit()) running = false;

        ImGui::Render();
        // Skip the main target when it is unavailable (e.g. a failed ResizeBuffers on
        // device-removed) so we never bind/clear a null render-target view.
        if (g_mainRenderTargetView) {
            const ImVec4 clear = ds::theme::col::windowBg();   // match the active theme (incl. Light)
            const float c[4] = { clear.x * clear.w, clear.y * clear.w, clear.z * clear.w, clear.w };
            g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
            g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, c);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        }

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        HRESULT hr = g_pSwapChain->Present(1, 0); // vsync on
        g_SwapChainOccluded = (hr == DXGI_STATUS_OCCLUDED);

        // Decide whether to keep rendering: stay at full rate while the app wants
        // animation (background work / debugging) or the user is mid-interaction
        // (an active widget, text input, or a held mouse button — these can animate
        // without generating new window messages); otherwise spend down the burst.
        if (app.wantsContinuousRedraw() || ImGui::IsAnyItemActive() || io.WantTextInput ||
            ImGui::IsMouseDown(ImGuiMouseButton_Left))
            framesToRender = 4;
        else if (framesToRender > 0)
            --framesToRender;
    }

    // Flush the panel layout now: ImGui's ~5 s autosave timer may not have fired for a
    // change made just before exit, and DestroyContext() does not save.
    if (io.IniFilename) ImGui::SaveIniSettingsToDisk(io.IniFilename);

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

// --- D3D helpers -------------------------------------------------------------
bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount        = 2;
    sd.BufferDesc.Width   = 0;
    sd.BufferDesc.Height  = 0;
    sd.BufferDesc.Format  = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator   = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags              = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage        = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow       = hWnd;
    sd.SampleDesc.Count   = 1;
    sd.Windowed           = TRUE;
    sd.SwapEffect         = DXGI_SWAP_EFFECT_DISCARD;

    UINT flags = 0;
#ifdef _DEBUG
    flags |= D3D11_CREATE_DEVICE_DEBUG;
#endif
    D3D_FEATURE_LEVEL fl;
    const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };

    // Prefer a hardware (GPU) device for 3D acceleration; fall back to WARP.
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags, levels, 2,
        D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &fl, &g_pd3dDeviceContext);
    if (hr == DXGI_ERROR_UNSUPPORTED) {
        hr = D3D11CreateDeviceAndSwapChain(
            nullptr, D3D_DRIVER_TYPE_WARP, nullptr, flags, levels, 2,
            D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &fl, &g_pd3dDeviceContext);
    }
    if (hr != S_OK) return false;
    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain)        { g_pSwapChain->Release();        g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice)        { g_pd3dDevice->Release();        g_pd3dDevice = nullptr; }
}

void CreateRenderTarget() {
    ID3D11Texture2D* back = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&back));
    if (back) {
        g_pd3dDevice->CreateRenderTargetView(back, nullptr, &g_mainRenderTargetView);
        back->Release();
    }
}

void CleanupRenderTarget() {
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
}

bool ApplyPendingDpiChange() {
    const UINT nextDpi = g_PendingDpi;
    if (nextDpi == 0) return false;
    if (nextDpi == g_AppliedDpi && g_DpiResourcesValid) {
        g_PendingDpi = 0;
        return false;
    }

    const float requestedScale = static_cast<float>(nextDpi) /
                                 static_cast<float>(kDefaultDpi);

    // The font atlas owns the ImFont pointers used throughout the UI. Invalidate
    // the old GPU texture before clearing/loading the atlas.
    g_DpiResourcesValid = false;
    ImGui_ImplDX11_InvalidateDeviceObjects();
    ds::ui::LoadFonts(requestedScale);

    // ApplyTheme derives every metric from an unscaled baseline and retains the
    // active palette + density. Repeated A->B->A monitor moves therefore return
    // to exactly the original style instead of multiplying previous metrics.
    ds::theme::SetUiScale(requestedScale);
    ds::theme::ApplyTheme();

    // Explicitly create the replacement texture before the next DX11 NewFrame.
    // On failure, clean up any partially-created backend objects and retain the
    // queued DPI. The render loop suppresses drawing and retries after 250 ms.
    if (!ImGui_ImplDX11_CreateDeviceObjects()) {
        ImGui_ImplDX11_InvalidateDeviceObjects();
        return false;
    }

    g_AppliedDpi = nextDpi;
    g_PendingDpi = 0;
    g_DpiResourcesValid = true;
    return true;
}

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // Always give the backend the notification (it updates viewport/monitor
    // bookkeeping), but do not let an early return swallow our main-window DPI
    // handling. No ImGui or DX11 objects are mutated in this callback.
    const LRESULT imguiResult = ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam);
    if (msg == WM_DPICHANGED) {
        const UINT dpiX = LOWORD(wParam);
        const UINT dpiY = HIWORD(wParam);
        const UINT nextDpi = dpiY ? dpiY : dpiX;
        if (nextDpi) g_PendingDpi = nextDpi; // last notification wins

        // Windows computes this rectangle so the window keeps the same logical
        // size on the destination monitor. Applying it in WndProc is the
        // documented WM_DPICHANGED contract; expensive resource work is queued.
        const RECT* suggested = reinterpret_cast<const RECT*>(lParam);
        if (suggested && suggested->right > suggested->left &&
            suggested->bottom > suggested->top) {
            ::SetWindowPos(hWnd, nullptr, suggested->left, suggested->top,
                           suggested->right - suggested->left,
                           suggested->bottom - suggested->top,
                           SWP_NOZORDER | SWP_NOACTIVATE);
        }
        return 0;
    }
    if (imguiResult)
        return true;
    switch (msg) {
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED) return 0;
            g_ResizeWidth  = (UINT)LOWORD(lParam);
            g_ResizeHeight = (UINT)HIWORD(lParam);
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0; // disable ALT app menu
            break;
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
    }
    return ::DefWindowProcW(hWnd, msg, wParam, lParam);
}
