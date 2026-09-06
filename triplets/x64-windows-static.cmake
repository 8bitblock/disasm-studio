# Keep vcpkg-built C++ dependencies ABI-aligned with DisasmStudio's VS 2022
# project even when a newer Visual Studio is installed side by side. MSBuild
# supplies both environment variables below from its active VS instance. A
# direct `vcpkg install` retains a portable VS2022-only discovery fallback.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE static)
set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_PLATFORM_TOOLSET v143)

set(_ds_vs_path "$ENV{VCPKG_VISUAL_STUDIO_PATH}")
if(_ds_vs_path STREQUAL "")
    find_program(_ds_vswhere
        NAMES vswhere.exe
        HINTS "$ENV{ProgramFiles\(x86\)}/Microsoft Visual Studio/Installer"
        NO_DEFAULT_PATH)
    if(NOT _ds_vswhere)
        message(FATAL_ERROR
            "DisasmStudio requires VS2022: vswhere.exe was not found. "
            "Set VCPKG_VISUAL_STUDIO_PATH to the active VS2022 installation.")
    endif()
    execute_process(
        COMMAND "${_ds_vswhere}"
            -latest
            -version "[17.0,18.0)"
            -products *
            -requires Microsoft.Component.MSBuild Microsoft.VisualStudio.Component.VC.Tools.x86.x64
            -property installationPath
        RESULT_VARIABLE _ds_vswhere_result
        OUTPUT_VARIABLE _ds_vs_path
        OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT _ds_vswhere_result EQUAL 0 OR _ds_vs_path STREQUAL "")
        message(FATAL_ERROR
            "A complete VS2022 C++ installation was not found. "
            "Install the Desktop development with C++ workload or set "
            "VCPKG_VISUAL_STUDIO_PATH explicitly.")
    endif()
endif()
string(REGEX REPLACE "[/\\\\]+$" "" _ds_vs_path "${_ds_vs_path}")
set(VCPKG_VISUAL_STUDIO_PATH "${_ds_vs_path}")

set(_ds_toolset_version "$ENV{DS_VCPKG_PLATFORM_TOOLSET_VERSION}")
if(_ds_toolset_version STREQUAL "")
    set(_ds_toolset_version_file
        "${VCPKG_VISUAL_STUDIO_PATH}/VC/Auxiliary/Build/Microsoft.VCToolsVersion.v143.default.txt")
    if(NOT EXISTS "${_ds_toolset_version_file}")
        message(FATAL_ERROR
            "The selected Visual Studio instance has no v143 default-toolset marker: "
            "${_ds_toolset_version_file}")
    endif()
    file(STRINGS "${_ds_toolset_version_file}" _ds_toolset_version LIMIT_COUNT 1)
    string(STRIP "${_ds_toolset_version}" _ds_toolset_version)
endif()
if(NOT _ds_toolset_version MATCHES "^14\\.[0-9]+(\\.[0-9]+)?$")
    message(FATAL_ERROR
        "Invalid VS2022 v143 toolset version '${_ds_toolset_version}'.")
endif()
if(NOT EXISTS
   "${VCPKG_VISUAL_STUDIO_PATH}/VC/Tools/MSVC/${_ds_toolset_version}/bin/Hostx64/x64/cl.exe")
    message(FATAL_ERROR
        "The selected VS instance does not contain v143 ${_ds_toolset_version}: "
        "${VCPKG_VISUAL_STUDIO_PATH}")
endif()
set(VCPKG_PLATFORM_TOOLSET_VERSION "${_ds_toolset_version}")

# These values affect dependency ABI selection. Tracking them prevents a binary
# cache hit from crossing Visual Studio instances/toolset minors.
set(VCPKG_ENV_PASSTHROUGH
    VCPKG_VISUAL_STUDIO_PATH
    DS_VCPKG_PLATFORM_TOOLSET_VERSION)
