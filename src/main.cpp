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
#include <fstream>
#include <tchar.h>
#include <windows.h>

// --- Direct3D 11 globals -----------------------------------------------------
static ID3D11Device*           g_pd3dDevice          = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext   = nullptr;
static IDXGISwapChain*         g_pSwapChain          = nullptr;
static bool                    g_SwapChainOccluded   = false;
static UINT                    g_ResizeWidth = 0, g_ResizeHeight = 0;
static ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

// ImGui's Win32 backend message handler.
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int) {
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
    io.ConfigViewportsNoTaskBarIcon = true;   // popped panels are tools, not separate apps
    io.IniFilename = nullptr; // don't persist/restore window layout

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

    // Prefer crisp Windows system fonts; fall back to the built-in font.
    // A proportional face for the UI and a monospace face for code/hex views.
    {
        auto fileExists = [](const char* p) { std::ifstream f(p); return f.good(); };
        const float uiPx   = 17.0f * dpi;
        const float monoPx = 16.0f * dpi;
        ImFont* uiFont = nullptr;
        if (fileExists("C:\\Windows\\Fonts\\segoeui.ttf"))
            uiFont = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", uiPx);
        if (!uiFont) uiFont = io.Fonts->AddFontDefault();
        ds::ui::gUiFont = uiFont;

        ImFont* mono = nullptr;
        if (fileExists("C:\\Windows\\Fonts\\consola.ttf"))
            mono = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\consola.ttf", monoPx);
        else if (fileExists("C:\\Windows\\Fonts\\cour.ttf"))
            mono = io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\cour.ttf", monoPx);
        ds::ui::gMonoFont = mono; // null -> PushMono() uses the default font
    }

    ds::App app;   // ctor applies the saved theme (which now picks up the UI scale)

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

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
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
