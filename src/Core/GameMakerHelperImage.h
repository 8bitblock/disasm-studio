#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace ds {

// The resource is compiled into DisasmStudio.exe; it is never downloaded or
// resolved from a game directory, plugin directory, or a caller-selected DLL.
inline constexpr uint16_t GameMakerHelperResourceId = 30101;
inline constexpr size_t GameMakerHelperMaximumBytes = 32u * 1024u * 1024u;

std::string GameMakerHelperSha256(std::span<const uint8_t> bytes);
bool ValidateGameMakerHelperImage(std::span<const uint8_t> bytes, std::string& error);

// Intended for an owned background worker. Produces an absolute UTF-8 filename
// in the OS-known per-user Local AppData cache, verified against the embedded
// bytes. Existing corrupt cache files are replaced atomically.
bool ExtractEmbeddedGameMakerHelper(std::string& outputPath, std::string& error);

// Testable extraction engine. cacheDirectory must name a dedicated, absolute
// local directory whose parent exists. The directory is created privately or,
// if already owned by the current user, its DACL is restricted to user+SYSTEM.
// Reparse points, hardlinked helper files, remote/device paths, and a directory
// owned by another user are rejected. No caller-selected image file is read.
bool ExtractGameMakerHelperBytes(std::span<const uint8_t> bytes,
                                const std::string& cacheDirectory,
                                std::string& outputPath, std::string& error);

} // namespace ds
