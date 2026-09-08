#pragma once
// Test-only offscreen capture of the current, already rendered ImGui frame.
// Uses the production DX11 backend and actual ImDrawData; creates no native
// window or swap chain and performs no interaction with the operating system UI.
// Link the installed imgui backend library plus d3d11/dxgi/d3dcompiler.
#include "imgui.h"
#include "imgui_impl_dx11.h"
#include <d3d11.h>
#include <wrl/client.h>
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace ds::test {

// Call immediately after ImGui::Render(), between frames. The caller chooses
// an explicit output directory; a capture failure is returned with its reason.
// Font-only test frames are supported. Foreign textures/callbacks and an
// existing renderer are rejected rather than reusing unrelated device state.
inline bool captureUiFrame(const std::filesystem::path& path, std::string* error = nullptr) {
    if (error) error->clear();
    const auto fail = [&](const std::string& reason) {
        if (error) *error = reason;
        return false;
    };
    const auto deviceFailure = [&](const char* operation, HRESULT result) {
        char reason[192]{};
        std::snprintf(reason, sizeof(reason), "%s failed (HRESULT 0x%08lX)",
                      operation, static_cast<unsigned long>(result));
        return fail(reason);
    };
    if (!ImGui::GetCurrentContext()) return fail("No current ImGui context.");
    ImDrawData* source = ImGui::GetDrawData();
    if (!source || !source->Valid) return fail("Capture requires a completed ImGui::Render frame.");
    ImGuiIO& io = ImGui::GetIO();
    if (io.BackendRendererUserData) return fail("The test context already owns a renderer.");
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        return fail("Offscreen capture supports the single test viewport only.");
    if (source->FramebufferScale.x != 1.0f || source->FramebufferScale.y != 1.0f)
        return fail("Capture requires framebuffer scale 1; set UI scale and rebuild fonts for DPI cases.");
    if (!std::isfinite(source->DisplaySize.x) || !std::isfinite(source->DisplaySize.y) ||
        source->DisplaySize.x < 1 || source->DisplaySize.y < 1 ||
        source->DisplaySize.x > 8192 || source->DisplaySize.y > 8192)
        return fail("Capture dimensions must be finite and between 1 and 8192 pixels.");
    const UINT width = static_cast<UINT>(std::ceil(source->DisplaySize.x));
    const UINT height = static_cast<UINT>(std::ceil(source->DisplaySize.y));
    const ImTextureID originalFontTexture = io.Fonts->TexID;
    for (const ImDrawList* list : source->CmdLists)
        for (const ImDrawCmd& command : list->CmdBuffer) {
            if (command.UserCallback && command.UserCallback != ImDrawCallback_ResetRenderState)
                return fail("The frame contains a custom renderer callback.");
            if (command.ElemCount && command.GetTexID() != originalFontTexture)
                return fail("The frame contains a non-font texture without a capture-device owner.");
        }

    using Microsoft::WRL::ComPtr;
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1,
                                       D3D_FEATURE_LEVEL_10_0};
    D3D_FEATURE_LEVEL level{};
    HRESULT result = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT, levels, static_cast<UINT>(std::size(levels)),
        D3D11_SDK_VERSION, &device, &level, &context);
    if (FAILED(result)) return deviceFailure("Hardware D3D11 device creation", result);

    // Each invocation uploads the current atlas. Tests may clear/rebuild fonts
    // between captures; no renderer state or GPU font pointer survives this call.
    struct RendererScope {
        ImGuiIO& io;
        ImTextureID fontTexture;
        ImGuiBackendFlags flags;
        const char* name;
        bool initialized = false;
        ~RendererScope() {
            if (initialized) ImGui_ImplDX11_Shutdown();
            io.Fonts->SetTexID(fontTexture);
            io.BackendFlags = flags;
            io.BackendRendererName = name;
        }
    } renderer{io, originalFontTexture, io.BackendFlags, io.BackendRendererName};
    if (!ImGui_ImplDX11_Init(device.Get(), context.Get())) return fail("DX11 backend initialization failed.");
    renderer.initialized = true;
    if (!ImGui_ImplDX11_CreateDeviceObjects()) return fail("DX11 font/shader device objects could not be created.");

    D3D11_TEXTURE2D_DESC description{};
    description.Width = width;
    description.Height = height;
    description.MipLevels = 1;
    description.ArraySize = 1;
    description.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    description.SampleDesc.Count = 1;
    description.Usage = D3D11_USAGE_DEFAULT;
    description.BindFlags = D3D11_BIND_RENDER_TARGET;
    ComPtr<ID3D11Texture2D> target;
    result = device->CreateTexture2D(&description, nullptr, &target);
    if (FAILED(result)) return deviceFailure("Capture render target creation", result);
    ComPtr<ID3D11RenderTargetView> targetView;
    result = device->CreateRenderTargetView(target.Get(), nullptr, &targetView);
    if (FAILED(result)) return deviceFailure("Capture target view creation", result);
    description.Usage = D3D11_USAGE_STAGING;
    description.BindFlags = 0;
    description.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    ComPtr<ID3D11Texture2D> staging;
    result = device->CreateTexture2D(&description, nullptr, &staging);
    if (FAILED(result)) return deviceFailure("Capture staging texture creation", result);

    struct DrawListDelete { void operator()(ImDrawList* list) const { IM_DELETE(list); } };
    std::vector<std::unique_ptr<ImDrawList, DrawListDelete>> lists;
    lists.reserve(static_cast<size_t>(source->CmdListsCount));
    ImDrawData capture;
    capture.Valid = true;
    capture.DisplayPos = source->DisplayPos;
    capture.DisplaySize = source->DisplaySize;
    capture.FramebufferScale = source->FramebufferScale;
    capture.OwnerViewport = source->OwnerViewport;
    for (const ImDrawList* list : source->CmdLists) {
        lists.emplace_back(list->CloneOutput());
        for (ImDrawCmd& command : lists.back()->CmdBuffer)
            if (command.GetTexID() == originalFontTexture) command.TextureId = io.Fonts->TexID;
        capture.AddDrawList(lists.back().get());
    }
    ID3D11RenderTargetView* outputView = targetView.Get();
    context->OMSetRenderTargets(1, &outputView, nullptr);
    const ImVec4 background = ImGui::GetStyleColorVec4(ImGuiCol_WindowBg);
    const float clear[] = {background.x, background.y, background.z, 1.0f};
    context->ClearRenderTargetView(targetView.Get(), clear);
    ImGui_ImplDX11_RenderDrawData(&capture);
    context->CopyResource(staging.Get(), target.Get());
    D3D11_MAPPED_SUBRESOURCE mapped{};
    result = context->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(result)) return deviceFailure("Capture readback", result);
    struct MapScope {
        ID3D11DeviceContext* context;
        ID3D11Texture2D* texture;
        ~MapScope() { context->Unmap(texture, 0); }
    } mapping{context.Get(), staging.Get()};

    std::error_code filesystemError;
    if (!path.parent_path().empty()) std::filesystem::create_directories(path.parent_path(), filesystemError);
    if (filesystemError) return fail("Could not create capture directory: " + filesystemError.message());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) return fail("Could not open the capture BMP for writing.");
    BITMAPFILEHEADER file{};
    BITMAPINFOHEADER info{};
    file.bfType = 0x4D42;
    file.bfOffBits = sizeof(file) + sizeof(info);
    file.bfSize = file.bfOffBits + width * height * 4;
    info.biSize = sizeof(info);
    info.biWidth = static_cast<LONG>(width);
    info.biHeight = -static_cast<LONG>(height); // top-down, matching D3D rows
    info.biPlanes = 1;
    info.biBitCount = 32;
    info.biCompression = BI_RGB;
    info.biSizeImage = width * height * 4;
    output.write(reinterpret_cast<const char*>(&file), sizeof(file));
    output.write(reinterpret_cast<const char*>(&info), sizeof(info));
    std::vector<uint8_t> row(static_cast<size_t>(width) * 4);
    for (UINT y = 0; y < height; ++y) {
        const auto* rgba = static_cast<const uint8_t*>(mapped.pData) + static_cast<size_t>(y) * mapped.RowPitch;
        for (UINT x = 0; x < width; ++x) {
            row[x * 4] = rgba[x * 4 + 2];
            row[x * 4 + 1] = rgba[x * 4 + 1];
            row[x * 4 + 2] = rgba[x * 4];
            row[x * 4 + 3] = 255;
        }
        output.write(reinterpret_cast<const char*>(row.data()), static_cast<std::streamsize>(row.size()));
    }
    output.close();
    if (!output) return fail("Capture BMP write or close failed.");
    return true;
}

} // namespace ds::test
