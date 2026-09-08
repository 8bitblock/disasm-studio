#include "Core/ArtifactWrite.h"
#include "Core/BinaryFile.h"
#include <windows.h>
#include <cassert>
#include <fstream>
#include <iostream>
#include <iterator>
#include <thread>

using namespace ds;
namespace fs = std::filesystem;
std::vector<uint8_t> read(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), {}};
}
int main() {
    const auto root = fs::temp_directory_path() /
        (L"ds-artifact-fixture-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    assert(fs::create_directory(root));
    const auto destination = root / L"saved-λ.bin";
    const std::vector<uint8_t> original{1,2,3,4}, changed{9,8,7};
    assert(WriteArtifactBytes(destination, original).success);
    auto failed = WriteArtifact(destination, [&](ArtifactOutput& output, std::string& error) {
        assert(output.write(changed)); error = "injected generation failure"; return false;
    });
    assert(!failed.success && failed.error == "injected generation failure");
    assert(read(destination) == original);
    failed = WriteArtifact(destination, [&](ArtifactOutput& output, std::string&) -> bool {
        assert(output.write(changed)); throw std::runtime_error("generation threw");
    });
    assert(!failed.success && read(destination) == original);
    assert(!WriteArtifactBytes(destination, changed, false).success);
    assert(read(destination) == original);
    HANDLE locked = CreateFileW(destination.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    assert(locked != INVALID_HANDLE_VALUE);
    failed = WriteArtifactBytes(destination, changed);
    assert(!failed.success && read(destination) == original);
    CloseHandle(locked);
    assert(WriteArtifactBytes(destination, changed).success && read(destination) == changed);
    assert(WriteArtifactBytes(destination, {}).success && read(destination).empty());
    assert(!WriteArtifactBytes(root, original).success);
    assert(!WriteArtifactBytes(root / L"saved.bin:stream", original).success);
    assert(!WriteArtifactBytes(root / L"missing" / L"file.bin", original).success);
    for (const auto& entry : fs::directory_iterator(root)) assert(entry.path() == destination);

    // Cheap image capture retains exact bytes across checked writes, image
    // commits, moves, and document clear. Self-sourced writes stay transactional.
    BinaryFile image;
    const auto input = root / L"snapshot.raw";
    assert(WriteArtifactBytes(input, original).success);
    const auto inputUtf8 = input.u8string();
    assert(image.loadRaw(std::string(inputUtf8.begin(), inputUtf8.end()), 0x1000));
    BinaryFile copied = image;
    auto owned = image.ownedBytes();
    assert(copied.bytes().data() == image.bytes().data());
    const uint8_t replacement = 42;
    assert(image.writeImage(0x1001, &replacement, 1) == 1);
    assert(copied.bytes() == original && *owned == original);
    assert(image.bytes()[1] == replacement);
    auto before = image.ownedBytes();
    assert(image.writeImage(0x1001, image.bytes().data(), 3) == 3);
    assert((*before)[1] == replacement);
    auto committed = original;
    assert(image.commitPatchedImage(std::move(committed)));
    assert((*before)[1] == replacement);
    image.clear(); copied.clear();
    assert(*owned == original);

    ArtifactWriteService service;
    std::promise<void> release;
    auto gate = release.get_future().share();
    std::string error;
    const auto caller = std::this_thread::get_id();
    assert(service.start([owned, destination, gate, caller] {
        assert(std::this_thread::get_id() != caller);
        gate.wait(); return WriteArtifactBytes(destination, *owned);
    }, error));
    ArtifactWriteResult result;
    assert(service.pending() && !service.take(result));
    assert(!service.start([] { return ArtifactWriteResult{}; }, error));
    release.set_value();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!service.take(result) && std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    assert(result.success && result.bytes == original.size() && read(destination) == original);
    assert(!service.pending());
    assert(service.start([]() -> ArtifactWriteResult { throw std::runtime_error("worker failed"); }, error));
    while (!service.take(result) && std::chrono::steady_clock::now() < deadline)
        std::this_thread::yield();
    assert(!result.success && result.error == "worker failed");
    // Cleanup only this fixture's exact private directory.
    fs::remove_all(root);
    std::cout << "artifact_write_test: all checks passed\n";
}
