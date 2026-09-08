#include "BinaryFile.h"
#include "../Disasm/IDisassembler.h"
#include "AddressSpan.h"
#include "JvmClass.h"
#include "GameMakerArchive.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <fstream>
#include <limits>
#include <new>
#include <stdexcept>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>

namespace ds {

namespace {
// C++20's filesystem::path has a native char8_t constructor. Build a u8string
// explicitly instead of using the deprecated filesystem::u8path compatibility
// shim, while keeping this Core module portable and free of Win32 APIs.
std::filesystem::path PathFromUtf8(const std::string& path) {
    std::u8string u8(path.size(), u8'\0');
    if (!path.empty()) std::memcpy(u8.data(), path.data(), path.size());
    return std::filesystem::path(u8);
}

std::string Utf8FromPath(const std::filesystem::path& path) {
    const std::u8string u8 = path.u8string();
    std::string out(u8.size(), '\0');
    if (!u8.empty()) std::memcpy(out.data(), u8.data(), u8.size());
    return out;
}

// Store a durable spelling after a successful open. In particular, a binary
// supplied as a relative startup argument must still reopen after the process
// working directory changes or the path is written to the recents index.
std::string DurableUtf8Path(const std::filesystem::path& openedPath) {
    std::error_code ec;
    std::filesystem::path absolute = std::filesystem::absolute(openedPath, ec);
    if (ec) absolute = openedPath;
    std::error_code canonicalEc;
    std::filesystem::path canonical = std::filesystem::weakly_canonical(absolute, canonicalEc);
    if (!canonicalEc) absolute = std::move(canonical);
    else absolute = absolute.lexically_normal();
    return Utf8FromPath(absolute);
}

// A zero PE VirtualSize is seen in real toolchains and means that the raw
// section still owns a file-backed mapping. When VirtualSize is non-zero, raw
// alignment bytes beyond it are file padding rather than mapped VAs. Keeping
// this policy in one helper makes offsetToVA and vaToOffset true inverses.
uint64_t SectionVirtualExtent(const Section& section) {
    return section.virtualSize ? section.virtualSize : section.rawSize;
}

uint64_t SectionFileBackedExtent(const Section& section) {
    return std::min(section.rawSize, SectionVirtualExtent(section));
}
} // namespace

DecoderConfig DecoderConfigForImage(const BinaryFile& image,
                                    DecoderConfig config) {
    if (!image.loaded() || image.format() == BinFormat::Raw) return config;

    switch (image.machine()) {
        case MachineArch::X86:     config.arch = Arch::X86; break;
        case MachineArch::X64:     config.arch = Arch::X64; break;
        case MachineArch::ARM:     config.arch = Arch::ARM; break;
        case MachineArch::THUMB:   config.arch = Arch::THUMB; break;
        case MachineArch::ARM64:   config.arch = Arch::ARM64; break;
        case MachineArch::MIPS:    config.arch = Arch::MIPS; break;
        case MachineArch::MIPS64:  config.arch = Arch::MIPS64; break;
        case MachineArch::PPC:     config.arch = Arch::PPC; break;
        case MachineArch::PPC64:   config.arch = Arch::PPC64; break;
        case MachineArch::RISCV:   config.arch = Arch::RISCV32; break;
        case MachineArch::RISCV64: config.arch = Arch::RISCV64; break;
        case MachineArch::JVM:     config.arch = Arch::JVM; break;
        case MachineArch::GML:     config.arch = Arch::GML; break;
        case MachineArch::Unknown: break; // retain an explicit caller choice
    }

    config.byteOrder = image.bigEndian() ? ByteOrder::Big : ByteOrder::Little;
    config.features = DecoderFeatures{};
    if (image.format() == BinFormat::ELF) {
        const BinaryFile::ElfDecoderMetadata& metadata = image.elfDecoderMetadata();
        if (metadata.present &&
            (image.machine() == MachineArch::RISCV ||
             image.machine() == MachineArch::RISCV64))
            config.features.riscvCompressed = metadata.riscvCompressed;
        if (metadata.present &&
            (image.machine() == MachineArch::MIPS ||
             image.machine() == MachineArch::MIPS64))
            config.features.mipsMicro = metadata.mipsMicro;
    }
    return config;
}

void BinaryFile::clear() {
    ++imageRevision_;
    path_.clear();
    loadError_ = BinaryLoadError::None;
    loadErrorText_.clear();
    data_.clear();
    sections_.clear();
    hash_ = 0; hashValid_ = false;   // recompute the sidecar key for the next file
    format_    = BinFormat::Unknown;
    machine_   = MachineArch::Unknown;
    is64_      = true;
    bigEndian_ = false;
    elfDecoderMetadata_ = {};
    fileCharacteristics_ = 0;
    mappedImage_ = false;
    mappedBase_  = 0;
    imageBase_ = 0;
    entryRVA_  = 0;
    entryPointPresent_ = false;
    rawEntryExplicit_ = false;
    analysisLandmarks_.clear();
    exportRVA_ = 0;
    exportSize_= 0;
    importRVA_ = 0;
    importSize_= 0;
    relocRVA_  = 0;
    relocSize_ = 0;
    exceptRVA_ = 0;
    exceptSize_= 0;
    resourceRVA_  = 0;
    resourceSize_ = 0;
    debugRVA_ = 0; debugSize_ = 0;
    tlsRVA_ = 0; tlsSize_ = 0;
    loadConfigRVA_ = 0; loadConfigSize_ = 0;
    delayImportRVA_ = 0; delayImportSize_ = 0;
    overlayOffset_ = 0;
    overlaySize_   = 0;
    securityOff_   = 0;
    securitySize_  = 0;
    clrRva_        = 0;
    clrSize_       = 0;
    sizeOfHeaders_ = 0;
    exports_.clear();
    imports_.clear();
    relocs_.clear();
    elfRelocationTables_.clear();
    elfRelocationsTruncated_ = false;
    elfLinkageSections_.clear();
    elfLinkageTruncated_ = false;
    elfDynamic_ = {};
    elfVersions_ = {};
    elfInitializers_ = {};
    machO_ = {};
    resources_.clear();
    peTls_ = {};
    delayImports_.clear();
    peDebugEntries_.clear();
    peLoadConfig_ = {};
    runtimeFunctions_.clear();
    javaClass_.reset();
    gameMakerArchive_.reset();
}

bool BinaryFile::rejectLoad(BinaryLoadError code, const char* message) noexcept {
    clear();
    loadError_ = code;
    try {
        loadErrorText_ = message ? message : "";
    } catch (...) {
        loadErrorText_.clear();
    }
    return false;
}

const char* BinaryFile::formatName() const {
    switch (format_) {
        case BinFormat::PE32:     return "PE32";
        case BinFormat::PE32Plus: return "PE32+";
        case BinFormat::ELF:      return "ELF";
        case BinFormat::MachO:    return machO_.universal ? "Mach-O Universal" : "Mach-O";
        case BinFormat::JavaClass: return "Java class";
        case BinFormat::GameMakerArchive: return "GameMaker archive";
        case BinFormat::Raw:      return "Raw";
        default:                  return "Unknown";
    }
}

bool BinaryFile::load(const std::string& path) {
    return load(path, BinaryLoadOptions{});
}

bool BinaryFile::load(const std::string& path, const BinaryLoadOptions& options) {
    clear();
    try {
    // All public paths are UTF-8 (Win32 dialogs and command-line startup both
    // convert at the boundary). A char8_t filesystem path preserves non-ASCII
    // file names on Windows instead of sending UTF-8 bytes through the active
    // ANSI codepage.
    const std::filesystem::path fsPath = PathFromUtf8(path);
    std::ifstream f(fsPath, std::ios::binary | std::ios::ate);
    if (!f) return rejectLoad(BinaryLoadError::OpenFailed, "could not open file");
    const std::streampos end = f.tellg();
    if (end <= std::streampos(0))
        return rejectLoad(BinaryLoadError::EmptyFile, "file is empty or its size is unavailable");
    const uintmax_t fileSize = static_cast<uintmax_t>(static_cast<std::streamoff>(end));
    if ((options.maxBytes && fileSize > options.maxBytes) ||
        fileSize > static_cast<uintmax_t>((std::numeric_limits<size_t>::max)()) ||
        fileSize > static_cast<uintmax_t>(data_.max_size()) ||
        fileSize > static_cast<uintmax_t>((std::numeric_limits<std::streamsize>::max)()))
        return rejectLoad(BinaryLoadError::FileTooLarge,
                          "file exceeds the configured in-memory load admission limit");
    if (options.cancelled && options.cancelled())
        return rejectLoad(BinaryLoadError::Cancelled, "binary load cancelled");
    const size_t byteCount = static_cast<size_t>(fileSize);
    try {
        data_.resize(byteCount);
    } catch (const std::bad_alloc&) {
        return rejectLoad(BinaryLoadError::AllocationFailed,
                          "not enough memory to load file");
    } catch (const std::length_error&) {
        return rejectLoad(BinaryLoadError::FileTooLarge,
                          "file size exceeds the in-memory image limit");
    }
    f.seekg(0);
    if (!f) return rejectLoad(BinaryLoadError::ReadFailed, "could not seek to file start");
    const size_t chunkBytes = std::clamp<size_t>(
        options.readChunkBytes ? options.readChunkBytes : 1,
        64ull * 1024ull, 64ull * 1024ull * 1024ull);
    size_t offset = 0;
    while (offset < byteCount) {
        if (options.cancelled && options.cancelled())
            return rejectLoad(BinaryLoadError::Cancelled, "binary load cancelled");
        const size_t chunk = std::min(chunkBytes, byteCount - offset);
        if (!f.read(reinterpret_cast<char*>(data_.mutableData() + offset),
                    static_cast<std::streamsize>(chunk)))
            return rejectLoad(BinaryLoadError::ReadFailed, "could not read complete file");
        offset += chunk;
    }
    if (options.cancelled && options.cancelled())
        return rejectLoad(BinaryLoadError::Cancelled, "binary load cancelled");
    path_ = DurableUtf8Path(fsPath);

    uint32_t magic = 0;
    if (data_.size() >= 4) std::memcpy(&magic, data_.data(), 4);
    const bool machMagic = magic == 0xFEEDFACEu || magic == 0xFEEDFACFu ||
                           magic == 0xCEFAEDFEu || magic == 0xCFFAEDFEu ||
                           magic == 0xBEBAFECAu || magic == 0xBFBAFECAu ||
                           magic == 0xCAFEBABEu || magic == 0xCAFEBABFu;

    if (data_.size() >= 2 && data_[0] == 'M' && data_[1] == 'Z') {
        // MZ is an authoritative structured-format claim. A malformed PE/DOS
        // image must not silently inherit Raw's unspecified architecture and
        // then be decoded as the caller's x86/x64 default. Intentional DOS,
        // firmware, and damaged-image work remains available through loadRaw().
        if (!parsePE()) {
            const bool unsupported = loadError_ == BinaryLoadError::UnsupportedMachine;
            return rejectLoad(unsupported ? BinaryLoadError::UnsupportedMachine
                                          : BinaryLoadError::MalformedPE,
                              unsupported ? "unsupported PE machine type"
                                          : "malformed MZ/PE image");
        }
    } else if (data_.size() >= 4 && std::memcmp(data_.data(), "\x7F""ELF", 4) == 0) {
        // A recognized but invalid ELF is not an analyst-authorized Raw image.
        // Normal Open must report the structural failure; Open as Raw remains
        // the explicit route for intentionally treating those bytes as a blob.
        if (!parseELF()) {
            const bool unsupported = loadError_ == BinaryLoadError::UnsupportedMachine;
            return rejectLoad(unsupported ? BinaryLoadError::UnsupportedMachine
                                          : BinaryLoadError::MalformedELF,
                              unsupported ? "unsupported ELF machine type"
                                          : "malformed ELF image");
        }
    } else if (IsJavaClassImage(data_.data(), data_.size())) {   // 0xCAFEBABE
        // IsJavaClassImage also validates the class-file version, which
        // disambiguates ordinary fat Mach-O headers sharing CAFEBABE. Once that
        // structured claim is present, a malformed constant pool/method table
        // is an error rather than analyst-authorized Raw input.
        if (!parseJavaClass())
            return rejectLoad(BinaryLoadError::MalformedJavaClass,
                              "malformed Java class file");
    } else if (IsGameMakerArchiveImage(data_.data(), data_.size())) {
        if (!parseGameMakerArchive(options.cancelled)) {
            const std::string reason = loadErrorText_.empty()
                ? "malformed GameMaker archive" : loadErrorText_;
            return rejectLoad(options.cancelled && options.cancelled()
                ? BinaryLoadError::Cancelled : BinaryLoadError::MalformedGameMakerArchive,
                reason.c_str());
        }
    } else if (machMagic) {
        // A recognized Mach-O container with an unsupported or malformed CPU
        // is not a Raw blob. Normal Open must fail instead of granting a
        // default x86/x64 decoder authority; Open as Raw remains explicit.
        if (!parseMachO()) {
            const bool unsupported = loadError_ == BinaryLoadError::UnsupportedMachine;
            return rejectLoad(unsupported ? BinaryLoadError::UnsupportedMachine
                                          : BinaryLoadError::MalformedMachO,
                              unsupported ? "unsupported Mach-O machine type"
                                          : "malformed Mach-O image");
        }
    } else {
        if (!initializeRawLayout(0))
            return rejectLoad(BinaryLoadError::InvalidRawMapping,
                              "raw mapping exceeds the address space");
    }
    return true;
    } catch (const std::bad_alloc&) {
        return rejectLoad(BinaryLoadError::AllocationFailed,
                          "not enough memory to finish loading image");
    } catch (const std::length_error&) {
        return rejectLoad(BinaryLoadError::AllocationFailed,
                          "loader metadata exceeds an allocation limit");
    } catch (const std::exception& error) {
        return rejectLoad(BinaryLoadError::ReadFailed, error.what());
    } catch (...) {
        return rejectLoad(BinaryLoadError::ReadFailed,
                          "binary loader failed with an unknown error");
    }
}

bool BinaryFile::initializeRawLayout(uint64_t base, bool mappedImage) {
    if (data_.empty()) return false;
    const uint64_t lastOffset = static_cast<uint64_t>(data_.size() - 1);
    if (lastOffset > std::numeric_limits<uint64_t>::max() - base) return false;

    // A structured parser may have populated part of its model before rejecting
    // the image. A Raw fallback must not expose those stale sections/directories.
    format_       = BinFormat::Raw;
    machine_      = MachineArch::Unknown; // the Open-as-Raw dialog owns arch selection
    is64_         = true;
    bigEndian_    = false;
    elfDecoderMetadata_ = {};
    fileCharacteristics_ = 0;
    mappedImage_  = mappedImage;
    mappedBase_   = mappedImage ? base : 0;
    imageBase_    = base;
    entryRVA_     = 0;                    // no fabricated header entry point
    entryPointPresent_ = false;
    rawEntryExplicit_ = false;
    analysisLandmarks_.clear();
    exportRVA_    = 0; exportSize_ = 0;
    importRVA_    = 0; importSize_ = 0;
    relocRVA_     = 0; relocSize_  = 0;
    exceptRVA_    = 0; exceptSize_ = 0;
    resourceRVA_  = 0; resourceSize_ = 0;
    debugRVA_     = 0; debugSize_ = 0;
    tlsRVA_       = 0; tlsSize_ = 0;
    loadConfigRVA_= 0; loadConfigSize_ = 0;
    delayImportRVA_= 0; delayImportSize_ = 0;
    overlayOffset_= 0; overlaySize_= 0;
    securityOff_  = 0; securitySize_ = 0;
    clrRva_       = 0; clrSize_ = 0;
    sizeOfHeaders_= 0;
    sections_.clear();
    exports_.clear();
    imports_.clear();
    relocs_.clear();
    elfRelocationTables_.clear();
    elfRelocationsTruncated_ = false;
    elfLinkageSections_.clear();
    elfLinkageTruncated_ = false;
    elfDynamic_ = {};
    elfVersions_ = {};
    elfInitializers_ = {};
    machO_ = {};
    resources_.clear();
    peTls_ = {};
    delayImports_.clear();
    peDebugEntries_.clear();
    peLoadConfig_ = {};
    runtimeFunctions_.clear();
    javaClass_.reset();
    gameMakerArchive_.reset();

    Section raw;
    raw.name            = ".raw";
    raw.virtualAddress  = 0;
    raw.virtualSize     = static_cast<uint64_t>(data_.size());
    raw.rawOffset       = 0;
    raw.rawSize         = static_cast<uint64_t>(data_.size());
    raw.characteristics = 0x60000020u; // code | execute | read (synthetic)
    raw.executable      = true;
    sections_.push_back(std::move(raw));
    return true;
}

bool BinaryFile::loadRaw(const std::string& path, uint64_t base) {
    return loadRaw(path, base, BinaryLoadOptions{});
}

bool BinaryFile::loadRaw(const std::string& path, uint64_t base,
                         const BinaryLoadOptions& options) {
    clear();
    try {
    const std::filesystem::path fsPath = PathFromUtf8(path);
    std::ifstream f(fsPath, std::ios::binary | std::ios::ate);
    if (!f) return rejectLoad(BinaryLoadError::OpenFailed, "could not open raw file");
    const std::streampos end = f.tellg();
    if (end <= std::streampos(0))
        return rejectLoad(BinaryLoadError::EmptyFile,
                          "raw file is empty or its size is unavailable");
    const uintmax_t fileSize = static_cast<uintmax_t>(static_cast<std::streamoff>(end));
    if ((options.maxBytes && fileSize > options.maxBytes) ||
        fileSize > static_cast<uintmax_t>((std::numeric_limits<size_t>::max)()) ||
        fileSize > static_cast<uintmax_t>(data_.max_size()) ||
        fileSize > static_cast<uintmax_t>((std::numeric_limits<std::streamsize>::max)()))
        return rejectLoad(BinaryLoadError::FileTooLarge,
                          "raw file exceeds the configured in-memory load admission limit");
    if (options.cancelled && options.cancelled())
        return rejectLoad(BinaryLoadError::Cancelled, "raw binary load cancelled");
    const size_t byteCount = static_cast<size_t>(fileSize);
    try {
        data_.resize(byteCount);
    } catch (const std::bad_alloc&) {
        return rejectLoad(BinaryLoadError::AllocationFailed,
                          "not enough memory to load raw file");
    } catch (const std::length_error&) {
        return rejectLoad(BinaryLoadError::FileTooLarge,
                          "raw file size exceeds the in-memory image limit");
    }
    f.seekg(0);
    if (!f) return rejectLoad(BinaryLoadError::ReadFailed,
                              "could not seek to raw file start");
    const size_t chunkBytes = std::clamp<size_t>(
        options.readChunkBytes ? options.readChunkBytes : 1,
        64ull * 1024ull, 64ull * 1024ull * 1024ull);
    size_t offset = 0;
    while (offset < byteCount) {
        if (options.cancelled && options.cancelled())
            return rejectLoad(BinaryLoadError::Cancelled, "raw binary load cancelled");
        const size_t chunk = std::min(chunkBytes, byteCount - offset);
        if (!f.read(reinterpret_cast<char*>(data_.mutableData() + offset),
                    static_cast<std::streamsize>(chunk)))
            return rejectLoad(BinaryLoadError::ReadFailed,
                              "could not read complete raw file");
        offset += chunk;
    }
    if (options.cancelled && options.cancelled())
        return rejectLoad(BinaryLoadError::Cancelled, "raw binary load cancelled");
    if (!initializeRawLayout(base))
        return rejectLoad(BinaryLoadError::InvalidRawMapping,
                          "raw mapping exceeds the address space");
    path_ = DurableUtf8Path(fsPath);
    return true;
    } catch (const std::bad_alloc&) {
        return rejectLoad(BinaryLoadError::AllocationFailed,
                          "not enough memory to finish loading raw image");
    } catch (const std::length_error&) {
        return rejectLoad(BinaryLoadError::AllocationFailed,
                          "raw image metadata exceeds an allocation limit");
    } catch (const std::exception& error) {
        return rejectLoad(BinaryLoadError::ReadFailed, error.what());
    } catch (...) {
        return rejectLoad(BinaryLoadError::ReadFailed,
                          "raw binary loader failed with an unknown error");
    }
}

bool BinaryFile::remapRaw(uint64_t base, uint64_t entryVA, bool entryExplicit,
                          std::vector<AnalysisLandmark> landmarks) {
    if (format_ != BinFormat::Raw || mappedImage_ || data_.empty() ||
        static_cast<uint64_t>(data_.size() - 1) >
            std::numeric_limits<uint64_t>::max() - base ||
        landmarks.size() > kMaxAnalysisLandmarks)
        return false;
    const auto mapped = [&](uint64_t va) {
        return va >= base && va - base < data_.size();
    };
    if (entryExplicit && !mapped(entryVA)) return false;
    for (const AnalysisLandmark& landmark : landmarks)
        if (landmark.name.empty() || !mapped(landmark.address)) return false;

    // Normalize the caller-owned temporary before committing any metadata.
    // This uses the same ordering/deduplication contract as setAnalysisLandmarks.
    std::sort(landmarks.begin(), landmarks.end(), [](const AnalysisLandmark& a,
                                                    const AnalysisLandmark& b) {
        if (a.address != b.address) return a.address < b.address;
        return a.name < b.name;
    });
    landmarks.erase(std::unique(landmarks.begin(), landmarks.end(),
                                [](const AnalysisLandmark& a, const AnalysisLandmark& b) {
        return a.address == b.address && a.name == b.name;
    }), landmarks.end());

    imageBase_ = base;
    entryRVA_ = entryExplicit ? entryVA - base : 0;
    entryPointPresent_ = rawEntryExplicit_ = entryExplicit;
    analysisLandmarks_ = std::move(landmarks);
    ++imageRevision_;
    return true;
}

bool BinaryFile::setRawEntryPointVA(uint64_t va) {
    if (format_ != BinFormat::Raw) return false;
    size_t avail = 0;
    if (!ptrFromVA(va, avail) || avail == 0 || va < imageBase_) return false;
    const uint64_t rva = va - imageBase_;
    // The synthetic raw section spans exactly data_.size(), so this also guards
    // the cast-free RVA representation and a one-past-the-image entry.
    if (rva >= data_.size()) return false;
    entryRVA_ = rva;
    entryPointPresent_ = true;
    rawEntryExplicit_ = true;
    return true;
}

bool BinaryFile::setAnalysisLandmarks(std::vector<AnalysisLandmark> landmarks) {
    if (format_ != BinFormat::Raw) return false;
    if (landmarks.size() > kMaxAnalysisLandmarks) return false;
    for (const AnalysisLandmark& lm : landmarks) {
        size_t avail = 0;
        if (lm.name.empty() || !ptrFromVA(lm.address, avail) || avail == 0) return false;
    }
    std::sort(landmarks.begin(), landmarks.end(), [](const AnalysisLandmark& a,
                                                     const AnalysisLandmark& b) {
        if (a.address != b.address) return a.address < b.address;
        return a.name < b.name;
    });
    landmarks.erase(std::unique(landmarks.begin(), landmarks.end(),
                                [](const AnalysisLandmark& a, const AnalysisLandmark& b) {
        return a.address == b.address && a.name == b.name;
    }), landmarks.end());
    analysisLandmarks_ = std::move(landmarks);
    return true;
}

bool BinaryFile::loadFromMemory(std::vector<uint8_t> bytes, uint64_t base, const std::string& name) {
    clear();
    if (bytes.size() < 0x40)
        return rejectLoad(BinaryLoadError::EmptyFile, "memory image is too small to map");
    try {
    data_ = std::move(bytes);
        path_ = name;
        // A live PE mapping: parse the headers but locate section data by RVA and force
        // the runtime base. Only a buffer without an MZ claim is treated as a flat blob.
        if (data_[0] == 'M' && data_[1] == 'Z') {
            mappedImage_ = true;
            mappedBase_  = base;
            if (parsePE()) return true; // honours mappedImage_/mappedBase_
            const bool unsupported = loadError_ == BinaryLoadError::UnsupportedMachine;
            return rejectLoad(unsupported ? BinaryLoadError::UnsupportedMachine
                                          : BinaryLoadError::MalformedPE,
                              unsupported ? "unsupported mapped PE machine type"
                                          : "malformed mapped MZ/PE image");
        }
        if (!initializeRawLayout(base, true))
            return rejectLoad(BinaryLoadError::InvalidRawMapping,
                              "memory mapping exceeds the address space");
        return true;
    } catch (const std::bad_alloc&) {
        return rejectLoad(BinaryLoadError::AllocationFailed,
                          "not enough memory to finish mapping image");
    } catch (const std::length_error&) {
        return rejectLoad(BinaryLoadError::AllocationFailed,
                          "mapped-image metadata exceeds an allocation limit");
    }
}

uint64_t BinaryFile::contentHash() const {
    if (hashValid_) return hash_;   // pristine value, cached before any writeImage() patch
    // FNV-1a, 64-bit. Mixes the length in so two blobs that differ only by
    // trailing zero padding still hash differently.
    uint64_t h = 1469598103934665603ull;
    for (uint8_t b : data_) { h ^= b; h *= 1099511628211ull; }
    h ^= data_.size(); h *= 1099511628211ull;
    hash_ = h; hashValid_ = true;
    return h;
}

// Transactionally overwrite exactly n mapped bytes of the in-memory image so
// the disassembly reflects an applied or reverted patch. Validate every mapped
// span before changing data_: a patch crossing virtual padding or an unmapped
// gap must leave the whole image pristine. contentHash() intentionally remains
// keyed to the original file.
bool BinaryFile::canWriteImage(uint64_t va, size_t n) const {
    // The GML document's code identities and reference chains describe the
    // pristine archive. Archive rewriting is not a supported patch operation;
    // live scalar edits go through the separately validated runtime session.
    if (format_ == BinFormat::GameMakerArchive) return false;
    if (!n) return false;
    uint64_t currentVA = va;
    size_t consumed = 0;
    uint64_t expectedFileOffset = 0;
    bool firstSpan = true;
    while (consumed < n) {
        uint64_t fileOffset = 0;
        size_t available = 0;
        if (!vaToOffset(currentVA, fileOffset) ||
            !ptrFromVA(currentVA, available) || !available ||
            fileOffset >= data_.size())
            return false;
        const size_t chunk = std::min(available, n - consumed);
        if (!chunk || chunk > data_.size() - static_cast<size_t>(fileOffset)) return false;
        if (!firstSpan && fileOffset != expectedFileOffset) return false;
        firstSpan = false;
        if (chunk > std::numeric_limits<uint64_t>::max() - fileOffset) return false;
        expectedFileOffset = fileOffset + chunk;
        consumed += chunk;
        if (consumed < n) {
            if (chunk > std::numeric_limits<uint64_t>::max() - currentVA) return false;
            currentVA += chunk;
        }
    }
    return true;
}

size_t BinaryFile::writeImage(uint64_t va, const uint8_t* in, size_t n) {
    if (!in || !canWriteImage(va, n)) return 0;

    struct WriteSpan { size_t fileOffset = 0, inputOffset = 0, size = 0; };
    try {
        std::vector<WriteSpan> spans;
        spans.reserve(std::min<size_t>(sections_.size() + 1, n));
        uint64_t currentVA = va;
        size_t consumed = 0;
        while (consumed < n) {
            uint64_t fileOffset = 0;
            size_t available = 0;
            if (!vaToOffset(currentVA, fileOffset) ||
                !ptrFromVA(currentVA, available) || !available ||
                fileOffset >= data_.size())
                return 0;
            const size_t chunk = std::min(available, n - consumed);
            if (!chunk || chunk > data_.size() - static_cast<size_t>(fileOffset)) return 0;
            spans.push_back({ static_cast<size_t>(fileOffset), consumed, chunk });
            consumed += chunk;
            if (consumed < n) {
                if (chunk > std::numeric_limits<uint64_t>::max() - currentVA) return 0;
                currentVA += chunk;
            }
        }

        // Stabilize overlapping/self-sourced writes before the first mutation.
        std::vector<uint8_t> replacement(n);
        std::memcpy(replacement.data(), in, n);
        // Freeze the project identity before the first mutation even for a
        // caller that has not queried contentHash() yet.
        (void)contentHash();
        uint8_t* writable = data_.mutableData();
        for (const WriteSpan& span : spans)
            std::memcpy(writable + span.fileOffset,
                        replacement.data() + span.inputOffset, span.size);
        ++imageRevision_;
        return n;
    } catch (const std::bad_alloc&) {
        return 0;
    } catch (const std::length_error&) {
        return 0;
    }
}

bool BinaryFile::commitPatchedImage(std::vector<uint8_t>&& replacement) {
    if (!loaded() || replacement.size() != data_.size()) return false;
    // Preserve the pristine sidecar identity and existing snapshot allocations.
    // Allocate the new owner before publishing; failure leaves this image intact.
    (void)contentHash();
    try { data_ = std::move(replacement); }
    catch (const std::bad_alloc&) { return false; }
    ++imageRevision_;
    return true;
}

template <typename T>
static T rd(const std::vector<uint8_t>& d, size_t off) {
    T v{};
    // No-overflow bound: `off + sizeof(T)` can wrap when off is near SIZE_MAX (a
    // hostile e_shoff/e_lfanew), letting a wild memcpy slip past the guard. Test the
    // two halves separately so the add never happens.
    if (off <= d.size() && sizeof(T) <= d.size() - off) std::memcpy(&v, d.data() + off, sizeof(T));
    return v;
}

// Structured formats must never borrow the host byte order. Keep the ordinary
// little-endian `rd` path unchanged for PE and pass byte order explicitly for
// ELF so concurrent loads cannot affect one another through mutable global
// state.
template <typename T>
static T rdOrder(const std::vector<uint8_t>& d, size_t off, bool bigEndian) {
    static_assert(std::is_integral_v<T> && std::is_unsigned_v<T>);
    if (!bigEndian) return rd<T>(d, off);
    if (off > d.size() || sizeof(T) > d.size() - off) return T{};
    T value{};
    for (size_t i = 0; i < sizeof(T); ++i)
        value = static_cast<T>((value << 8) | static_cast<T>(d[off + i]));
    return value;
}

bool BinaryFile::parsePE() {
    const uint32_t e_lfanew = rd<uint32_t>(data_, 0x3C);
    // Widen before the add so a hostile e_lfanew near UINT32_MAX cannot wrap the
    // bound check and let the memcmp below read far past the buffer.
    if (static_cast<uint64_t>(e_lfanew) + 4 > data_.size()) return false;
    if (std::memcmp(data_.data() + e_lfanew, "PE\0\0", 4) != 0) return false;

    const size_t coff = static_cast<size_t>(e_lfanew) + 4;
    switch (rd<uint16_t>(data_, coff + 0)) {     // COFF Machine field
        case 0x014C: machine_ = MachineArch::X86;   break;
        case 0x8664: machine_ = MachineArch::X64;   break;
        case 0x01C0: machine_ = MachineArch::ARM; break;
        case 0x01C2: case 0x01C4: machine_ = MachineArch::THUMB; break; // Thumb / ARMNT (Thumb-2)
        case 0xAA64: machine_ = MachineArch::ARM64; break;
        case 0x0166: case 0x0266: case 0x0366: case 0x0466: machine_ = MachineArch::MIPS; break; // R4000/MIPS variants
        case 0x01F0: case 0x01F1: machine_ = MachineArch::PPC; break;   // PowerPC / PowerPCFP
        case 0x5032: machine_ = MachineArch::RISCV;   break;            // RISC-V 32
        case 0x5064: machine_ = MachineArch::RISCV64; break;            // RISC-V 64
        default:     machine_ = MachineArch::Unknown; break;
    }
    // A structured image may only grant a decoder architecture represented by
    // this build. The explicit Raw workflow remains the escape hatch for an
    // unsupported machine value.
    if (machine_ == MachineArch::Unknown) {
        loadError_ = BinaryLoadError::UnsupportedMachine;
        return false;
    }
    const uint16_t numSections = rd<uint16_t>(data_, coff + 2);
    const uint16_t optSize     = rd<uint16_t>(data_, coff + 16);
    fileCharacteristics_       = rd<uint16_t>(data_, coff + 18);
    const size_t opt = coff + 20;
    if (opt > data_.size() || optSize > data_.size() - opt || optSize < 64) return false;
    const uint16_t magic = rd<uint16_t>(data_, opt);
    size_t dataDirRel = 0; // optional-header-relative data-directory array offset

    if (magic == 0x20B) {        // PE32+
        format_   = BinFormat::PE32Plus;
        is64_     = true;
        entryRVA_ = rd<uint32_t>(data_, opt + 16);
        imageBase_= rd<uint64_t>(data_, opt + 24);
        dataDirRel= 112;
    } else if (magic == 0x10B) { // PE32
        format_   = BinFormat::PE32;
        is64_     = false;
        entryRVA_ = rd<uint32_t>(data_, opt + 16);
        imageBase_= rd<uint32_t>(data_, opt + 28);
        dataDirRel= 96;
    } else {
        return false;
    }
    const bool machineRequires64 = machine_ == MachineArch::X64 ||
                                   machine_ == MachineArch::ARM64 ||
                                   machine_ == MachineArch::RISCV64;
    const bool machineRequires32 = machine_ == MachineArch::X86 ||
                                   machine_ == MachineArch::ARM ||
                                   machine_ == MachineArch::THUMB ||
                                   machine_ == MachineArch::MIPS ||
                                   machine_ == MachineArch::PPC ||
                                   machine_ == MachineArch::RISCV;
    if ((machineRequires64 && !is64_) || (machineRequires32 && is64_))
        return false; // contradictory COFF machine / optional-header width
    // PE defines AddressOfEntryPoint == 0 as "no entry point".
    entryPointPresent_ = entryRVA_ != 0;

    // For a live process mapping the header's preferred ImageBase is irrelevant under
    // ASLR — the module is actually at mappedBase_. Override before parseImports/Relocs
    // so every resolved VA (IAT slots, reloc targets) is a real runtime address.
    if (mappedImage_) imageBase_ = mappedBase_;

    // SizeOfHeaders is at the same offset in PE32 and PE32+. The optional
    // header bound above makes this a declared, file-backed field rather than
    // bytes borrowed from the section table of a truncated header.
    sizeOfHeaders_ = rd<uint32_t>(data_, opt + 60);

    // Data directory: [0] export, [1] import, [5] base relocations. Only read a
    // directory slot the header actually declares (NumberOfRvaAndSizes sits in
    // the 4 bytes immediately before the array); out-of-range slots stay 0 so
    // parseImports/parseRelocs no-op rather than aliasing the section table.
    const uint32_t numDirs = dataDirRel <= optSize
                           ? rd<uint32_t>(data_, opt + dataDirRel - 4) : 0u;
    auto dir = [&](uint32_t i, uint32_t fieldOffset) -> uint32_t {
        const uint64_t rel = static_cast<uint64_t>(dataDirRel) +
                             static_cast<uint64_t>(i) * 8 + fieldOffset;
        if (i >= numDirs || rel + sizeof(uint32_t) > optSize) return 0u;
        return rd<uint32_t>(data_, opt + static_cast<size_t>(rel));
    };
    exportRVA_  = dir(0, 0);  exportSize_ = dir(0, 4);
    importRVA_  = dir(1, 0);  importSize_ = dir(1, 4);
    resourceRVA_= dir(2, 0);  resourceSize_ = dir(2, 4); // [2] resource directory (.rsrc)
    exceptRVA_  = dir(3, 0);  exceptSize_ = dir(3, 4);  // [3] exception (.pdata RUNTIME_FUNCTIONs)
    securityOff_= dir(4, 0);  securitySize_ = dir(4, 4); // [4] security: FILE OFFSET, not RVA
    relocRVA_   = dir(5, 0);  relocSize_  = dir(5, 4);
    debugRVA_   = dir(6, 0);  debugSize_  = dir(6, 4);  // [6] IMAGE_DEBUG_DIRECTORY array
    tlsRVA_     = dir(9, 0);  tlsSize_    = dir(9, 4);  // [9] IMAGE_TLS_DIRECTORY32/64
    loadConfigRVA_ = dir(10, 0); loadConfigSize_ = dir(10, 4); // [10] load configuration
    delayImportRVA_ = dir(13, 0); delayImportSize_ = dir(13, 4); // [13] delay-load imports
    clrRva_     = dir(14, 0); clrSize_ = dir(14, 4);  // [14] CLR/COM descriptor (.NET)

    size_t sec = opt + optSize;
    // The declared table is atomic format authority. Accepting only the prefix
    // would publish incomplete mappings and let all downstream analyses reason
    // about a different image from the PE header's claim.
    if (numSections > (data_.size() - sec) / 40u) return false;
    for (uint16_t i = 0; i < numSections; ++i, sec += 40) {
        Section s;
        char name[9] = {0};
        std::memcpy(name, data_.data() + sec, 8);
        s.name            = name;
        s.virtualSize     = rd<uint32_t>(data_, sec + 8);
        s.virtualAddress  = rd<uint32_t>(data_, sec + 12);
        if (mappedImage_) {
            // In a process mapping the raw data lives at the section's RVA (and the
            // whole virtual extent is present, zero-filled), so address it by RVA.
            s.rawOffset = s.virtualAddress;
            s.rawSize   = s.virtualSize ? s.virtualSize : rd<uint32_t>(data_, sec + 16);
        } else {
            s.rawSize   = rd<uint32_t>(data_, sec + 16);
            s.rawOffset = rd<uint32_t>(data_, sec + 20);
        }
        s.characteristics = rd<uint32_t>(data_, sec + 36);
        s.executable      = (s.characteristics & 0x20000000u) != 0; // IMAGE_SCN_MEM_EXECUTE
        sections_.push_back(s);
    }

    // A malformed SizeOfHeaders may extend over the first section's file bytes.
    // Header RVA mapping must remain one-to-one, so stop it at the earliest
    // file-backed section offset as well as at EOF. Offset zero is included:
    // the mapping routines treat a section with rawSize > 0 / rawOffset == 0
    // as owning those bytes, so retaining a simultaneous header mapping would
    // break VA<->offset inversion. For mapped images
    // rawOffset is the section RVA, giving the equivalent in-memory boundary.
    uint64_t effectiveHeaders = std::min<uint64_t>(sizeOfHeaders_, data_.size());
    for (const Section& s : sections_) {
        if (!s.rawSize) continue;
        effectiveHeaders = std::min(effectiveHeaders, s.rawOffset);
    }
    sizeOfHeaders_ = static_cast<uint32_t>(effectiveHeaders);

    // PE overlay: anything in the file past the end of all section raw data (and
    // past the headers, so a sectionless PE doesn't claim the whole file). Only
    // meaningful for an on-disk load — a live mapping repurposes rawOffset as the
    // RVA above, so end-of-raw-data math would be nonsense there. Each section's
    // end is clamped to the file size so a hostile rawOffset/rawSize can't wrap
    // 64-bit math or push `end` past EOF and invent a negative-sized overlay.
    if (!mappedImage_) {
        uint64_t end = static_cast<uint64_t>(sec);   // end of the section table
        if (end > data_.size()) end = data_.size();
        for (const Section& s : sections_) {
            uint64_t e = (s.rawOffset <= data_.size() && s.rawSize <= data_.size() - s.rawOffset)
                             ? s.rawOffset + s.rawSize
                             : static_cast<uint64_t>(data_.size());
            if (e > end) end = e;
        }
        if (data_.size() > end) {
            overlayOffset_ = end;
            overlaySize_   = data_.size() - end;
        }
    }

    parseExports();   // needs sections_ for RVA translation / code classification
    parseImports();
    parseDelayImports();
    parseResources(); // needs sections_ + imageBase_ for RVA/offset translation
    parseRelocs();
    parseDebugDirectory();
    parseTlsDirectory();
    parseLoadConfig();
    parseRuntimeFunctions();
    return true;
}

// IMAGE_EXPORT_DIRECTORY + EAT/name/ordinal tables. The export model retains
// ordinal-only entries, multiple names for one ordinal (aliases), forwarded
// exports, and non-code/data exports. Every table and string walk is bounded by
// mapped bytes plus a hard row cap so hostile counts cannot allocate or spin
// without limit. Name bytes remain views into data_ until the final bounded
// rows are materialized, so repeated pointers cannot multiply 4 KiB strings
// into gigabytes of temporary and result storage.
void BinaryFile::parseExports() {
    exports_.clear();
    if (!exportRVA_) return;

    size_t dirAvail = 0;
    const uint8_t* dir = ptrFromRVA(exportRVA_, dirAvail);
    if (!dir || dirAvail < 40) return;

    uint32_t ordinalBase = 0, numberOfFunctions = 0, numberOfNames = 0;
    uint32_t functionsRVA = 0, namesRVA = 0, ordinalsRVA = 0;
    std::memcpy(&ordinalBase,       dir + 16, 4);
    std::memcpy(&numberOfFunctions, dir + 20, 4);
    std::memcpy(&numberOfNames,     dir + 24, 4);
    std::memcpy(&functionsRVA,      dir + 28, 4);
    std::memcpy(&namesRVA,          dir + 32, 4);
    std::memcpy(&ordinalsRVA,       dir + 36, 4);
    if (!numberOfFunctions || !functionsRVA) return;

    constexpr size_t kMaxExportRows       = 200000;
    constexpr size_t kMaxString           = 4096;
    constexpr size_t kMaxStoredStringBytes= 8 * 1024 * 1024;
    constexpr size_t kMaxStringScanBytes  = 16 * 1024 * 1024;

    size_t eatAvail = 0;
    const uint8_t* eatBytes = ptrFromRVA(functionsRVA, eatAvail);
    if (!eatBytes) return;
    const size_t functionCount = std::min<size_t>(
        static_cast<size_t>(std::min<uint64_t>(numberOfFunctions, kMaxExportRows)),
        eatAvail / sizeof(uint32_t));
    if (!functionCount) return;

    std::vector<uint32_t> eat(functionCount);
    std::memcpy(eat.data(), eatBytes, functionCount * sizeof(uint32_t));
    std::vector<std::vector<std::string_view>> aliases(functionCount);

    // Require a terminator within mapped data and the cap. Malformed names are
    // ignored instead of leaking an arbitrary section tail into the UI.
    size_t scannedStringBytes = 0;
    auto stringAt = [&](uint32_t rva, size_t extraLimit) -> std::string_view {
        size_t avail = 0;
        const uint8_t* p = ptrFromRVA(rva, avail);
        if (!p) return {};
        if (scannedStringBytes >= kMaxStringScanBytes) return {};
        const size_t remainingWork = kMaxStringScanBytes - scannedStringBytes;
        const size_t limit = std::min({avail, extraLimit, remainingWork});
        size_t n = 0;
        while (n < limit) {
            ++scannedStringBytes; // charge every inspected byte, including NUL
            if (!p[n]) return std::string_view(reinterpret_cast<const char*>(p), n);
            ++n;
        }
        return {};
    };

    // A hostile table often repeats one long name RVA for every row. Cache the
    // bounded scan, then dedupe aliases by (ordinal, text), including identical
    // strings stored at different RVAs. string_views are safe because data_ is
    // immutable for the duration of this parse.
    std::unordered_map<uint32_t, std::string_view> nameCache;
    nameCache.reserve(std::min<size_t>(numberOfNames, kMaxExportRows));
    auto cachedNameAt = [&](uint32_t rva) -> std::string_view {
        auto [it, inserted] = nameCache.try_emplace(rva);
        if (inserted) it->second = stringAt(rva, kMaxString);
        return it->second;
    };
    struct AliasKey {
        uint32_t ordinalIndex;
        std::string_view name;
        bool operator==(const AliasKey&) const = default;
    };
    struct AliasKeyHash {
        size_t operator()(const AliasKey& key) const noexcept {
            const size_t h1 = std::hash<uint32_t>{}(key.ordinalIndex);
            const size_t h2 = std::hash<std::string_view>{}(key.name);
            return h1 ^ (h2 + static_cast<size_t>(0x9e3779b9u) + (h1 << 6) + (h1 >> 2));
        }
    };
    std::unordered_set<AliasKey, AliasKeyHash> seenAliases;
    seenAliases.reserve(std::min<size_t>(numberOfNames, kMaxExportRows));
    std::unordered_set<uint64_t> seenAliasPointers;
    seenAliasPointers.reserve(std::min<size_t>(numberOfNames, kMaxExportRows));

    size_t namesAvail = 0, ordinalsAvail = 0;
    const uint8_t* nameTable = namesRVA ? ptrFromRVA(namesRVA, namesAvail) : nullptr;
    const uint8_t* ordinalTable = ordinalsRVA ? ptrFromRVA(ordinalsRVA, ordinalsAvail) : nullptr;
    if (nameTable && ordinalTable) {
        const size_t nameCount = std::min<size_t>({
            static_cast<size_t>(std::min<uint64_t>(numberOfNames, kMaxExportRows)),
            namesAvail / sizeof(uint32_t), ordinalsAvail / sizeof(uint16_t)
        });
        for (size_t i = 0; i < nameCount; ++i) {
            uint32_t nameRVA = 0;
            uint16_t ordinalIndex = 0;
            std::memcpy(&nameRVA, nameTable + i * 4, 4);
            std::memcpy(&ordinalIndex, ordinalTable + i * 2, 2);
            if (ordinalIndex >= functionCount || !eat[ordinalIndex]) continue;
            const uint64_t pointerKey = (static_cast<uint64_t>(ordinalIndex) << 32) | nameRVA;
            if (!seenAliasPointers.insert(pointerKey).second) continue;
            const std::string_view name = cachedNameAt(nameRVA);
            if (!name.empty() && seenAliases.insert({ordinalIndex, name}).second)
                aliases[ordinalIndex].push_back(name);
        }
    }

    const uint64_t exportEnd = static_cast<uint64_t>(exportRVA_) + exportSize_;
    auto targetIsCode = [&](uint32_t rva) {
        for (const Section& section : sections_) {
            if (!section.executable || rva < section.virtualAddress) continue;
            const uint64_t span = std::max(section.virtualSize, section.rawSize);
            if (static_cast<uint64_t>(rva) - section.virtualAddress < span) return true;
        }
        return false;
    };

    exports_.reserve(std::min(kMaxExportRows, functionCount + seenAliases.size()));
    size_t storedStringBytes = 0;
    for (size_t i = 0; i < functionCount; ++i) {
        if (exports_.size() >= kMaxExportRows) break;
        const uint32_t rva = eat[i];
        if (!rva) continue;                         // an unassigned ordinal gap

        const bool forwarded = exportSize_ && rva >= exportRVA_ &&
                               static_cast<uint64_t>(rva) < exportEnd;
        std::string_view forwarder;
        if (forwarded) {
            const size_t inDirectory = static_cast<size_t>(exportEnd - rva);
            forwarder = stringAt(rva, std::min(kMaxString, inDirectory));
        }
        const uint64_t va = imageBase_ <= std::numeric_limits<uint64_t>::max() - rva
                          ? imageBase_ + rva : 0;
        size_t targetAvail = 0;
        const bool mapped = !forwarded && va != 0 && ptrFromRVA(rva, targetAvail) != nullptr;
        const bool isCode = mapped && targetIsCode(rva);
        auto append = [&](std::string_view name, bool includeForwarder = true) -> bool {
            if (exports_.size() >= kMaxExportRows) return false;
            const std::string_view storedForwarder = includeForwarder ? forwarder : std::string_view{};
            const size_t rowStringBytes = name.size() + storedForwarder.size();
            if (rowStringBytes > kMaxStoredStringBytes - storedStringBytes) return false;
            Export ex;
            ex.ordinal   = static_cast<uint64_t>(ordinalBase) + i;
            ex.rva       = rva;
            ex.va        = va;
            if (!name.empty()) ex.name.assign(name.data(), name.size());
            if (!storedForwarder.empty())
                ex.forwarder.assign(storedForwarder.data(), storedForwarder.size());
            ex.forwarded = forwarded;
            ex.mapped    = mapped;
            ex.isCode    = isCode;
            exports_.push_back(std::move(ex));
            storedStringBytes += rowStringBytes;
            return true;
        };
        if (aliases[i].empty()) {
            if (!append({})) append({}, false); // metadata-only row after string-budget exhaustion
        }
        else {
            bool emittedAlias = false;
            for (const std::string_view alias : aliases[i]) {
                if (!append(alias)) break;
                emittedAlias = true;
            }
            // Preserve the exported ordinal/target even when a hostile alias
            // set exhausts the aggregate string budget.
            if (!emittedAlias && !append({})) append({}, false);
        }
    }
}

// IMAGE_RESOURCE_DIRECTORY walk (data directory [2]). The resource directory is
// a three-level tree Type -> Name/ID -> Language whose internal offsets are all
// relative to the directory's own base RVA; only the leaf IMAGE_RESOURCE_DATA_
// ENTRY carries an absolute RVA. Every directory/string/data read is bounded by
// mapped bytes, and a visited-entry cap plus a depth cap keep a hostile tree
// (self-referential subdirectory offsets, absurd entry counts) from spinning or
// allocating without limit. Name/ID strings decode from UTF-16LE to UTF-8.
void BinaryFile::parseResources() {
    resources_.clear();
    if (!resourceRVA_) return;
    const uint32_t base = resourceRVA_;

    constexpr size_t kMaxResources = 100000;   // leaf rows retained
    constexpr size_t kMaxVisited   = 500000;   // directory entries inspected
    constexpr size_t kMaxNameChars = 260;      // UTF-16 code units per directory string
    constexpr int    kMaxDepth     = 8;        // legitimate trees are 3 deep

    auto rd16 = [](const uint8_t* p) -> uint16_t {
        return static_cast<uint16_t>(p[0] | (p[1] << 8));
    };
    auto rd32 = [](const uint8_t* p) -> uint32_t {
        return static_cast<uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) |
                                     (static_cast<uint32_t>(p[3]) << 24));
    };
    auto appendUtf8 = [](std::string& out, uint32_t cp) {
        if (cp <= 0x7F) out.push_back(static_cast<char>(cp));
        else if (cp <= 0x7FF) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp <= 0xFFFF) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    };
    // IMAGE_RESOURCE_DIR_STRING_U: a 2-byte length (in UTF-16 code units) then
    // that many UTF-16LE units, at `o` relative to the resource base.
    auto readDirString = [&](uint32_t o) -> std::string {
        std::string s;
        size_t avail = 0;
        const uint8_t* p = ptrFromRVA(static_cast<uint64_t>(base) + o, avail);
        if (!p || avail < 2) return s;
        size_t units = std::min<size_t>(rd16(p), kMaxNameChars);
        units = std::min(units, (avail - 2) / 2);
        for (size_t i = 0; i < units;) {
            const uint16_t w = rd16(p + 2 + i * 2);
            if (w >= 0xD800 && w <= 0xDBFF && i + 1 < units) {
                const uint16_t lo = rd16(p + 2 + (i + 1) * 2);
                if (lo >= 0xDC00 && lo <= 0xDFFF) {
                    appendUtf8(s, 0x10000u + ((w - 0xD800u) << 10) + (lo - 0xDC00u));
                    i += 2;
                    continue;
                }
            }
            appendUtf8(s, w);
            ++i;
        }
        return s;
    };

    size_t visited = 0;
    std::function<void(uint32_t, int, const Resource&)> walk =
        [&](uint32_t dirOffset, int level, const Resource& acc) {
        if (level > kMaxDepth) return;
        if (resources_.size() >= kMaxResources || visited >= kMaxVisited) return;
        size_t avail = 0;
        const uint8_t* d = ptrFromRVA(static_cast<uint64_t>(base) + dirOffset, avail);
        if (!d || avail < 16) return;
        size_t total = static_cast<size_t>(rd16(d + 12)) + rd16(d + 14); // named + id
        total = std::min(total, (avail - 16) / 8);
        for (size_t i = 0; i < total; ++i) {
            if (resources_.size() >= kMaxResources || visited >= kMaxVisited) break;
            ++visited;
            const uint8_t* e = d + 16 + i * 8;
            const uint32_t nameField = rd32(e);
            const uint32_t offField  = rd32(e + 4);
            const bool     isNamed   = (nameField & 0x80000000u) != 0;
            const uint32_t nameVal   = nameField & 0x7FFFFFFFu;

            Resource child = acc;
            if (level == 0) {
                child.typeNamed = isNamed;
                if (isNamed) child.typeName = readDirString(nameVal);
                else         child.typeId   = nameVal;
            } else if (level == 1) {
                child.nameNamed = isNamed;
                if (isNamed) child.name   = readDirString(nameVal);
                else         child.nameId = nameVal;
            } else {
                child.langId = nameVal; // language ids are numeric in practice
            }

            if (offField & 0x80000000u) {          // subdirectory
                walk(offField & 0x7FFFFFFFu, level + 1, child);
            } else {                                // IMAGE_RESOURCE_DATA_ENTRY
                size_t dav = 0;
                const uint8_t* de = ptrFromRVA(static_cast<uint64_t>(base) + offField, dav);
                if (!de || dav < 16) continue;
                child.dataRVA  = rd32(de);
                child.dataSize = rd32(de + 4);
                child.codePage = rd32(de + 8);
                child.va = (imageBase_ <= std::numeric_limits<uint64_t>::max() - child.dataRVA)
                               ? imageBase_ + child.dataRVA : 0;
                size_t tav = 0;
                child.mapped = child.dataSize && ptrFromRVA(child.dataRVA, tav) != nullptr && tav > 0;
                uint64_t off = 0;
                child.fileOffset = (child.mapped && child.va && vaToOffset(child.va, off)) ? off : 0;
                resources_.push_back(std::move(child));
            }
        }
    };
    walk(0, 0, Resource{});
}

// IMAGE_IMPORT_DESCRIPTOR walk: resolve each IAT slot to "DLL.function".
void BinaryFile::parseImports() {
    if (!importRVA_) return;
    const bool pe64    = (format_ == BinFormat::PE32Plus);
    const uint32_t pSz = pe64 ? 8u : 4u;
    const uint64_t ord = pe64 ? 0x8000000000000000ull : 0x80000000ull;

    for (uint32_t desc = 0; desc < 0x10000; desc += 20) {
        size_t av = 0;
        const uint8_t* d = ptrFromRVA((uint64_t)importRVA_ + desc, av);
        if (!d || av < 20) break;
        uint32_t oft, nameRVA, iatRVA;
        std::memcpy(&oft, d + 0, 4); std::memcpy(&nameRVA, d + 12, 4); std::memcpy(&iatRVA, d + 16, 4);
        if (!oft && !nameRVA && !iatRVA) break;   // null terminator descriptor

        std::string dll;
        if (size_t na = 0; const uint8_t* np = ptrFromRVA(nameRVA, na))
            for (size_t k = 0; k < na && k < 128 && np[k]; ++k) dll.push_back((char)np[k]);

        uint32_t ilt = oft ? oft : iatRVA;        // bound imports: OFT may be 0
        for (uint32_t k = 0; k < 50000; ++k) {
            const uint64_t slotDelta = static_cast<uint64_t>(k) * pSz;
            uint64_t iltSlot = 0;
            if (!CheckedAddressAdd(ilt, slotDelta, iltSlot)) break;
            size_t ta = 0;
            const uint8_t* tp = ptrFromRVA(iltSlot, ta);
            if (!tp || ta < pSz) break;
            uint64_t thunk = 0; std::memcpy(&thunk, tp, pSz);
            if (!thunk) break;                    // end of this DLL's thunk array
            uint64_t iatSlot = 0, iatVA = 0;
            if (!CheckedAddressAdd(iatRVA, slotDelta, iatSlot) ||
                !CheckedAddressAdd(imageBase_, iatSlot, iatVA))
                break;                            // malformed range crosses UINT64_MAX
            std::string fn;
            if (thunk & ord) { char b[24]; std::snprintf(b, sizeof(b), "#%u", (unsigned)(thunk & 0xFFFF)); fn = b; }
            else {
                uint32_t hn = (uint32_t)(thunk & 0x7FFFFFFF);
                if (size_t ha = 0; const uint8_t* hp = ptrFromRVA(hn, ha))
                    for (size_t z = 2; z < ha && z < 130 && hp[z]; ++z) fn.push_back((char)hp[z]);
            }
            if (!fn.empty()) imports_.push_back({ iatVA, dll, fn });
            if (imports_.size() > 100000) return;
        }
    }
}

// IMAGE_DELAYLOAD_DESCRIPTOR walk. Descriptor fields are RVAs when dlattrRva
// (bit zero) is set and legacy VAs otherwise. Both representations are resolved
// without narrowing, every string is explicitly bounded, and descriptor/thunk/
// aggregate-row caps prevent hostile tables from monopolising load time.
void BinaryFile::parseDelayImports() {
    delayImports_.clear();
    if (!delayImportRVA_ || delayImportSize_ < 32) return;

    constexpr size_t kMaxDescriptors = 4096;
    constexpr size_t kMaxSymbolsPerDescriptor = 50000;
    constexpr size_t kMaxSymbolsTotal = 100000;
    constexpr size_t kMaxNameBytes = 512;

    size_t directoryAvail = 0;
    const uint8_t* directory = ptrFromRVA(delayImportRVA_, directoryAvail);
    if (!directory) return;
    const size_t descriptorCount = std::min<size_t>({
        static_cast<size_t>(delayImportSize_ / 32), directoryAvail / 32,
        kMaxDescriptors
    });
    const uint32_t pointerSize = is64_ ? 8u : 4u;
    const uint64_t ordinalMask = is64_ ? 0x8000000000000000ull : 0x80000000ull;
    size_t totalSymbols = 0;

    auto read32 = [](const uint8_t* p) {
        uint32_t v = 0;
        std::memcpy(&v, p, sizeof(v));
        return v;
    };
    auto readPointer = [&](const uint8_t* p) {
        uint64_t v = 0;
        std::memcpy(&v, p, pointerSize);
        return v;
    };
    auto fieldToVA = [&](uint32_t field, bool isRva, uint64_t& out) {
        if (!field) { out = 0; return true; }
        if (!isRva) { out = field; return true; }
        return CheckedAddressAdd(imageBase_, field, out);
    };
    auto readCStringVA = [&](uint64_t va, size_t skip, std::string& out,
                             bool& terminated) {
        out.clear();
        terminated = false;
        size_t avail = 0;
        const uint8_t* p = ptrFromVA(va, avail);
        if (!p || skip > avail) return false;
        p += skip;
        avail -= skip;
        const size_t bounded = std::min(avail, kMaxNameBytes);
        size_t count = 0;
        while (count < bounded && p[count] != 0) ++count;
        terminated = count < bounded;
        if (!terminated) return false;
        out.assign(reinterpret_cast<const char*>(p), count);
        return !out.empty();
    };

    for (size_t index = 0; index < descriptorCount; ++index) {
        const uint8_t* raw = directory + index * 32;
        uint32_t fields[8]{};
        for (size_t i = 0; i < 8; ++i) fields[i] = read32(raw + i * 4);
        bool allZero = true;
        for (uint32_t field : fields) allZero &= field == 0;
        if (allZero) break;

        PeDelayImportDescriptor descriptor;
        const uint64_t descriptorOffset = static_cast<uint64_t>(index) * 32;
        const bool descriptorRvaValid =
            descriptorOffset <= std::numeric_limits<uint32_t>::max() - delayImportRVA_;
        if (descriptorRvaValid)
            descriptor.descriptorRVA = delayImportRVA_ + static_cast<uint32_t>(descriptorOffset);
        descriptor.attributes = fields[0];
        descriptor.fieldsAreRVA = (fields[0] & 1u) != 0;
        descriptor.timestamp = fields[7];

        uint64_t dllNameVA = 0;
        const bool addressesRepresentable =
            fieldToVA(fields[1], descriptor.fieldsAreRVA, dllNameVA) &&
            fieldToVA(fields[2], descriptor.fieldsAreRVA, descriptor.moduleHandleVA) &&
            fieldToVA(fields[3], descriptor.fieldsAreRVA, descriptor.iatVA) &&
            fieldToVA(fields[4], descriptor.fieldsAreRVA, descriptor.importNameTableVA) &&
            fieldToVA(fields[5], descriptor.fieldsAreRVA, descriptor.boundIatVA) &&
            fieldToVA(fields[6], descriptor.fieldsAreRVA, descriptor.unloadIatVA);

        const bool dllValid = dllNameVA &&
            readCStringVA(dllNameVA, 0, descriptor.dll, descriptor.dllNameTerminated);
        size_t intAvail = 0, iatAvail = 0;
        const uint8_t* intTable = descriptor.importNameTableVA
                                ? ptrFromVA(descriptor.importNameTableVA, intAvail) : nullptr;
        const uint8_t* iatTable = descriptor.iatVA
                                ? ptrFromVA(descriptor.iatVA, iatAvail) : nullptr;
        descriptor.descriptorValid = descriptorRvaValid && addressesRepresentable &&
                                     dllValid && intTable && iatTable &&
                                     intAvail >= pointerSize && iatAvail >= pointerSize;

        if (descriptor.descriptorValid) {
            const size_t availableSlots = std::min(intAvail, iatAvail) / pointerSize;
            const size_t boundedSlots = std::min<size_t>({
                availableSlots, kMaxSymbolsPerDescriptor,
                kMaxSymbolsTotal - totalSymbols
            });
            descriptor.symbols.reserve(std::min<size_t>(boundedSlots, 1024));
            for (size_t slot = 0; slot < boundedSlots; ++slot) {
                const uint64_t thunk = readPointer(intTable + slot * pointerSize);
                if (!thunk) {
                    descriptor.symbolsTerminated = true;
                    break;
                }
                uint64_t slotDelta = static_cast<uint64_t>(slot) * pointerSize;
                uint64_t iatSlotVA = 0;
                if (!CheckedAddressAdd(descriptor.iatVA, slotDelta, iatSlotVA)) {
                    descriptor.symbolsTruncated = true;
                    break;
                }

                PeDelayImportSymbol symbol;
                symbol.iatVA = iatSlotVA;
                if (thunk & ordinalMask) {
                    symbol.byOrdinal = true;
                    symbol.ordinal = static_cast<uint16_t>(thunk & 0xFFFFu);
                    char ordinalName[24]{};
                    std::snprintf(ordinalName, sizeof(ordinalName), "#%u",
                                  static_cast<unsigned>(symbol.ordinal));
                    symbol.name = ordinalName;
                } else {
                    uint64_t importByNameVA = thunk;
                    if (descriptor.fieldsAreRVA &&
                        !CheckedAddressAdd(imageBase_, thunk, importByNameVA)) {
                        descriptor.symbolsTruncated = true;
                        break;
                    }
                    bool nameTerminated = false;
                    if (!readCStringVA(importByNameVA, 2, symbol.name, nameTerminated)) {
                        descriptor.symbolsTruncated = true;
                        break;
                    }
                }

                Import normalized;
                normalized.iatVA = symbol.iatVA;
                normalized.dll = descriptor.dll;
                normalized.name = symbol.name;
                normalized.delayed = true;
                imports_.push_back(std::move(normalized));
                descriptor.symbols.push_back(std::move(symbol));
                ++totalSymbols;
            }
            if (!descriptor.symbolsTerminated &&
                (boundedSlots == availableSlots || boundedSlots == kMaxSymbolsPerDescriptor ||
                 totalSymbols == kMaxSymbolsTotal))
                descriptor.symbolsTruncated = true;
        }
        delayImports_.push_back(std::move(descriptor));
        if (totalSymbols == kMaxSymbolsTotal) break;
    }
}

// IMAGE_DEBUG_DIRECTORY array with bounded CodeView/RSDS decoding. Some linkers
// leave only PointerToRawData usable in an on-disk file, so the payload resolver
// accepts either an exactly-backed RVA or an exactly-backed raw file span. A
// mapped process image deliberately uses the RVA representation only.
void BinaryFile::parseDebugDirectory() {
    peDebugEntries_.clear();
    if (!debugRVA_ || debugSize_ < 28) return;

    constexpr size_t kMaxEntries = 4096;
    constexpr size_t kMaxPdbPathBytes = 4096;
    size_t directoryAvail = 0;
    const uint8_t* directory = ptrFromRVA(debugRVA_, directoryAvail);
    if (!directory) return;
    const size_t count = std::min<size_t>({
        static_cast<size_t>(debugSize_ / 28), directoryAvail / 28, kMaxEntries
    });

    auto read16 = [](const uint8_t* p) {
        uint16_t v = 0; std::memcpy(&v, p, sizeof(v)); return v;
    };
    auto read32 = [](const uint8_t* p) {
        uint32_t v = 0; std::memcpy(&v, p, sizeof(v)); return v;
    };
    auto formatGuid = [](const std::array<uint8_t, 16>& g) {
        const uint32_t d1 = static_cast<uint32_t>(g[0]) |
                            (static_cast<uint32_t>(g[1]) << 8) |
                            (static_cast<uint32_t>(g[2]) << 16) |
                            (static_cast<uint32_t>(g[3]) << 24);
        const uint16_t d2 = static_cast<uint16_t>(g[4] | (g[5] << 8));
        const uint16_t d3 = static_cast<uint16_t>(g[6] | (g[7] << 8));
        char text[37]{};
        std::snprintf(text, sizeof(text),
                      "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                      static_cast<unsigned>(d1), static_cast<unsigned>(d2),
                      static_cast<unsigned>(d3), static_cast<unsigned>(g[8]),
                      static_cast<unsigned>(g[9]), static_cast<unsigned>(g[10]),
                      static_cast<unsigned>(g[11]), static_cast<unsigned>(g[12]),
                      static_cast<unsigned>(g[13]), static_cast<unsigned>(g[14]),
                      static_cast<unsigned>(g[15]));
        return std::string(text);
    };

    peDebugEntries_.reserve(count);
    for (size_t index = 0; index < count; ++index) {
        const uint8_t* raw = directory + index * 28;
        PeDebugEntry entry;
        entry.characteristics = read32(raw + 0);
        entry.timestamp = read32(raw + 4);
        entry.majorVersion = read16(raw + 8);
        entry.minorVersion = read16(raw + 10);
        entry.type = read32(raw + 12);
        entry.dataSize = read32(raw + 16);
        entry.dataRVA = read32(raw + 20);
        entry.dataFileOffset = read32(raw + 24);

        if (entry.dataSize != 0 && entry.dataFileOffset != 0 &&
            entry.dataFileOffset <= data_.size() &&
            entry.dataSize <= data_.size() - entry.dataFileOffset)
            entry.payloadFileOffsetValid = true;

        const uint8_t* payload = nullptr;
        size_t payloadAvail = 0;
        if (entry.dataRVA) {
            const uint8_t* mapped = ptrFromRVA(entry.dataRVA, payloadAvail);
            if (mapped && entry.dataSize <= payloadAvail) payload = mapped;
        }
        if (!payload && !mappedImage_ && entry.payloadFileOffsetValid) {
            payload = data_.data() + entry.dataFileOffset;
            payloadAvail = entry.dataSize;
        }
        entry.payloadAvailable = payload != nullptr;

        if (entry.type == 2 && payload && entry.dataSize >= 24 &&
            std::memcmp(payload, "RSDS", 4) == 0) {
            entry.codeViewRsds = true;
            std::memcpy(entry.codeViewGuidBytes.data(), payload + 4, 16);
            entry.codeViewGuid = formatGuid(entry.codeViewGuidBytes);
            entry.codeViewAge = read32(payload + 20);

            const size_t declaredPathBytes = static_cast<size_t>(entry.dataSize) - 24;
            const size_t scanned = std::min(declaredPathBytes, kMaxPdbPathBytes);
            const uint8_t* path = payload + 24;
            size_t length = 0;
            while (length < scanned && path[length] != 0) ++length;
            entry.pdbPathTerminated = length < scanned;
            // When a hostile oversized path has no terminator inside the cap,
            // expose no misleading partial pathname. A completely bounded
            // unterminated record is retained verbatim and flagged as such.
            if (entry.pdbPathTerminated || declaredPathBytes <= kMaxPdbPathBytes)
                entry.pdbPath.assign(reinterpret_cast<const char*>(path), length);
        }
        peDebugEntries_.push_back(std::move(entry));
    }
}

// IMAGE_TLS_DIRECTORY32/64. Pointer members are image VAs in both formats.
void BinaryFile::parseTlsDirectory() {
    peTls_ = {};
    if (!tlsRVA_) return;
    peTls_.present = true;
    peTls_.directoryRVA = tlsRVA_;
    peTls_.directorySize = tlsSize_;

    const size_t required = is64_ ? 40u : 24u;
    size_t avail = 0;
    const uint8_t* raw = ptrFromRVA(tlsRVA_, avail);
    if (!raw || tlsSize_ < required || avail < required) return;
    peTls_.directoryValid = true;

    auto readPointer = [&](size_t offset) {
        uint64_t value = 0;
        std::memcpy(&value, raw + offset, is64_ ? 8u : 4u);
        return value;
    };
    const size_t pointerSize = is64_ ? 8u : 4u;
    peTls_.rawDataStartVA = readPointer(0);
    peTls_.rawDataEndVA = readPointer(pointerSize);
    peTls_.indexVA = readPointer(pointerSize * 2);
    peTls_.callbackTableVA = readPointer(pointerSize * 3);
    std::memcpy(&peTls_.zeroFillSize, raw + pointerSize * 4, 4);
    std::memcpy(&peTls_.characteristics, raw + pointerSize * 4 + 4, 4);
    peTls_.rawDataRangeValid = peTls_.rawDataEndVA >= peTls_.rawDataStartVA &&
                              (peTls_.rawDataStartVA != 0 || peTls_.rawDataEndVA == 0);

    if (!peTls_.callbackTableVA) return;
    constexpr size_t kMaxCallbacks = 4096;
    size_t tableAvail = 0;
    const uint8_t* table = ptrFromVA(peTls_.callbackTableVA, tableAvail);
    if (!table || tableAvail < pointerSize) return;
    peTls_.callbackTableMapped = true;
    const size_t availableSlots = tableAvail / pointerSize;
    const size_t boundedSlots = std::min(availableSlots, kMaxCallbacks);
    peTls_.callbacks.reserve(std::min<size_t>(boundedSlots, 64));
    for (size_t index = 0; index < boundedSlots; ++index) {
        uint64_t callback = 0;
        std::memcpy(&callback, table + index * pointerSize, pointerSize);
        if (!callback) {
            peTls_.callbacksTerminated = true;
            break;
        }
        size_t callbackAvail = 0;
        if (!ptrFromVA(callback, callbackAvail) || callbackAvail == 0) {
            peTls_.callbacksTruncated = true;
            break;
        }
        peTls_.callbacks.push_back(callback);
    }
    if (!peTls_.callbacksTerminated && boundedSlots == availableSlots)
        peTls_.callbacksTruncated = true;
    if (!peTls_.callbacksTerminated && boundedSlots == kMaxCallbacks)
        peTls_.callbacksTruncated = true;
}

// Parse only the security-relevant, stable prefix of the 32/64-bit load-config
// structure. `Size` is authoritative: bytes beyond the smaller of Size,
// directory size, and the actual mapped span are never borrowed from a section.
void BinaryFile::parseLoadConfig() {
    peLoadConfig_ = {};
    if (!loadConfigRVA_) return;
    peLoadConfig_.present = true;
    peLoadConfig_.directoryRVA = loadConfigRVA_;
    peLoadConfig_.directorySize = loadConfigSize_;

    size_t avail = 0;
    const uint8_t* raw = ptrFromRVA(loadConfigRVA_, avail);
    if (!raw || loadConfigSize_ < 4 || avail < 4) return;
    std::memcpy(&peLoadConfig_.declaredSize, raw, 4);
    const size_t effective = std::min<size_t>({
        peLoadConfig_.declaredSize, loadConfigSize_, avail
    });
    if (effective < 12) return;
    peLoadConfig_.headerValid = true;
    std::memcpy(&peLoadConfig_.timestamp, raw + 4, 4);
    std::memcpy(&peLoadConfig_.majorVersion, raw + 8, 2);
    std::memcpy(&peLoadConfig_.minorVersion, raw + 10, 2);

    auto has = [&](size_t offset, size_t size) {
        return offset <= effective && size <= effective - offset;
    };
    auto read16 = [&](size_t offset) {
        uint16_t value = 0; if (has(offset, 2)) std::memcpy(&value, raw + offset, 2); return value;
    };
    auto read32 = [&](size_t offset) {
        uint32_t value = 0; if (has(offset, 4)) std::memcpy(&value, raw + offset, 4); return value;
    };
    auto readPointer = [&](size_t offset) {
        uint64_t value = 0;
        const size_t pointerSize = is64_ ? 8u : 4u;
        if (has(offset, pointerSize)) std::memcpy(&value, raw + offset, pointerSize);
        return value;
    };
    auto isMappedVA = [&](uint64_t va) {
        size_t mappedAvail = 0;
        return va != 0 && ptrFromVA(va, mappedAvail) != nullptr && mappedAvail != 0;
    };

    const size_t dependentFlagsOffset = is64_ ? 78u : 54u;
    if (has(dependentFlagsOffset, 2)) {
        peLoadConfig_.dependentLoadFlagsPresent = true;
        peLoadConfig_.dependentLoadFlags = read16(dependentFlagsOffset);
    }

    const size_t securityCookieOffset = is64_ ? 88u : 60u;
    const size_t seHandlerTableOffset = is64_ ? 96u : 64u;
    const size_t seHandlerCountOffset = is64_ ? 104u : 68u;
    const size_t guardCheckOffset = is64_ ? 112u : 72u;
    const size_t guardDispatchOffset = is64_ ? 120u : 76u;
    const size_t guardTableOffset = is64_ ? 128u : 80u;
    const size_t guardCountOffset = is64_ ? 136u : 84u;
    const size_t guardFlagsOffset = is64_ ? 144u : 88u;
    const size_t pointerSize = is64_ ? 8u : 4u;

    if (has(securityCookieOffset, pointerSize)) {
        peLoadConfig_.securityCookiePresent = true;
        peLoadConfig_.securityCookieVA = readPointer(securityCookieOffset);
        peLoadConfig_.securityCookieMapped = isMappedVA(peLoadConfig_.securityCookieVA);
    }
    if (has(seHandlerTableOffset, pointerSize) && has(seHandlerCountOffset, pointerSize)) {
        peLoadConfig_.seHandlerTablePresent = true;
        peLoadConfig_.seHandlerTableVA = readPointer(seHandlerTableOffset);
        peLoadConfig_.seHandlerCount = readPointer(seHandlerCountOffset);
        peLoadConfig_.seHandlerTableMapped = isMappedVA(peLoadConfig_.seHandlerTableVA);
    }
    if (has(guardCheckOffset, pointerSize)) {
        peLoadConfig_.guardCfCheckPresent = true;
        peLoadConfig_.guardCfCheckFunctionVA = readPointer(guardCheckOffset);
        peLoadConfig_.guardCfCheckMapped = isMappedVA(peLoadConfig_.guardCfCheckFunctionVA);
    }
    if (has(guardDispatchOffset, pointerSize)) {
        peLoadConfig_.guardCfDispatchPresent = true;
        peLoadConfig_.guardCfDispatchFunctionVA = readPointer(guardDispatchOffset);
        peLoadConfig_.guardCfDispatchMapped = isMappedVA(peLoadConfig_.guardCfDispatchFunctionVA);
    }
    if (has(guardTableOffset, pointerSize) && has(guardCountOffset, pointerSize)) {
        peLoadConfig_.guardCfTablePresent = true;
        peLoadConfig_.guardCfFunctionTableVA = readPointer(guardTableOffset);
        peLoadConfig_.guardCfFunctionCount = readPointer(guardCountOffset);
        peLoadConfig_.guardCfTableMapped = isMappedVA(peLoadConfig_.guardCfFunctionTableVA);
    }
    if (has(guardFlagsOffset, 4)) {
        peLoadConfig_.guardFlagsPresent = true;
        peLoadConfig_.guardFlags = read32(guardFlagsOffset);
    }
}

// x64 IMAGE_RUNTIME_FUNCTION_ENTRY + UNWIND_INFO. The exception directory and
// every secondary unwind/handler/chain read are independently mapped and
// bounded. A global raw-code-slot budget prevents a maximal hostile .pdata
// table from turning 255-byte declarations into unbounded retained vectors.
void BinaryFile::parseRuntimeFunctions() {
    runtimeFunctions_.clear();
    if (!exceptRVA_ || exceptSize_ < 12 || format_ != BinFormat::PE32Plus ||
        machine_ != MachineArch::X64)
        return;

    constexpr size_t kMaxRuntimeFunctions = 200000;
    constexpr size_t kMaxRetainedCodeSlots = 1000000;
    size_t directoryAvail = 0;
    const uint8_t* directory = ptrFromRVA(exceptRVA_, directoryAvail);
    if (!directory) return;
    const size_t count = std::min<size_t>({
        static_cast<size_t>(exceptSize_ / 12), directoryAvail / 12,
        kMaxRuntimeFunctions
    });
    runtimeFunctions_.reserve(std::min<size_t>(count, 4096));
    size_t retainedSlots = 0;

    auto read32 = [](const uint8_t* p) {
        uint32_t value = 0; std::memcpy(&value, p, 4); return value;
    };
    auto setChain = [&](PeRuntimeFunction& function, const uint8_t* raw) {
        function.chainedInfoPresent = true;
        function.chainedBeginRVA = read32(raw);
        function.chainedEndRVA = read32(raw + 4);
        function.chainedUnwindDataRVA = read32(raw + 8);
        function.chainedInfoValid = function.chainedBeginRVA != 0 &&
                                    function.chainedEndRVA > function.chainedBeginRVA;
    };

    for (size_t index = 0; index < count; ++index) {
        const uint8_t* raw = directory + index * 12;
        PeRuntimeFunction function;
        function.beginRVA = read32(raw);
        function.endRVA = read32(raw + 4);
        function.unwindDataRVA = read32(raw + 8);
        function.rangeValid = function.beginRVA != 0 && function.endRVA > function.beginRVA &&
            CheckedAddressAdd(imageBase_, function.beginRVA, function.beginVA) &&
            CheckedAddressAdd(imageBase_, function.endRVA, function.endVA);
        function.indirectEntry = (function.unwindDataRVA & 1u) != 0;

        if (function.indirectEntry) {
            function.chainedInfoPresent = true;
            size_t chainAvail = 0;
            if (const uint8_t* chain = ptrFromRVA(function.unwindDataRVA & ~1u, chainAvail);
                chain && chainAvail >= 12)
                setChain(function, chain);
            runtimeFunctions_.push_back(std::move(function));
            continue;
        }

        size_t unwindAvail = 0;
        const uint8_t* unwind = function.unwindDataRVA
                              ? ptrFromRVA(function.unwindDataRVA, unwindAvail) : nullptr;
        if (!unwind || unwindAvail < 4) {
            runtimeFunctions_.push_back(std::move(function));
            continue;
        }
        function.unwindVersion = unwind[0] & 0x7u;
        function.unwindFlags = unwind[0] >> 3;
        function.prologSize = unwind[1];
        function.unwindCodeCount = unwind[2];
        function.frameRegister = unwind[3] & 0x0Fu;
        function.frameOffset = unwind[3] >> 4;

        const size_t codeBytes = static_cast<size_t>(function.unwindCodeCount) * 2;
        const bool codeSpanValid = codeBytes <= unwindAvail - 4;
        function.unwindInfoValid = codeSpanValid;
        if (codeSpanValid) {
            const size_t retain = std::min<size_t>(function.unwindCodeCount,
                                                   kMaxRetainedCodeSlots - retainedSlots);
            function.unwindCodeSlots.resize(retain);
            if (retain)
                std::memcpy(function.unwindCodeSlots.data(), unwind + 4, retain * 2);
            retainedSlots += retain;
            function.unwindCodesComplete = retain == function.unwindCodeCount;

            const size_t paddedSlots = (static_cast<size_t>(function.unwindCodeCount) + 1u) & ~size_t{1};
            const size_t tailOffset = 4 + paddedSlots * 2;
            if ((function.unwindFlags & 0x4u) != 0) {
                function.chainedInfoPresent = true;
                if (tailOffset <= unwindAvail && 12 <= unwindAvail - tailOffset)
                    setChain(function, unwind + tailOffset);
            } else if ((function.unwindFlags & 0x3u) != 0) {
                function.exceptionHandlerPresent = true;
                if (tailOffset <= unwindAvail && 4 <= unwindAvail - tailOffset) {
                    function.exceptionHandlerRVA = read32(unwind + tailOffset);
                    if (CheckedAddressAdd(imageBase_, function.exceptionHandlerRVA,
                                          function.exceptionHandlerVA)) {
                        size_t handlerAvail = 0;
                        function.exceptionHandlerMapped = function.exceptionHandlerRVA != 0 &&
                            ptrFromRVA(function.exceptionHandlerRVA, handlerAvail) != nullptr &&
                            handlerAvail != 0;
                    }
                }
            }
        }
        runtimeFunctions_.push_back(std::move(function));
    }
}

// IMAGE_BASE_RELOCATION blocks -> (VA, type) pairs.
void BinaryFile::parseRelocs() {
    if (!relocRVA_) return;
    for (uint32_t off = 0;
         off <= relocSize_ && relocSize_ - off >= 8 && relocs_.size() < 200000; ) {
        size_t av = 0;
        const uint8_t* b = ptrFromRVA((uint64_t)relocRVA_ + off, av);
        if (!b || av < 8) break;
        uint32_t pageRVA, blockSize;
        std::memcpy(&pageRVA, b, 4); std::memcpy(&blockSize, b + 4, 4);
        const uint32_t remaining = relocSize_ - off;
        if (blockSize < 8 || blockSize > remaining || blockSize > av) break;
        uint32_t entries = (blockSize - 8) / 2;
        for (uint32_t e = 0; e < entries; ++e) {
            uint16_t v; std::memcpy(&v, b + 8 + e * 2, 2);
            int type = v >> 12;
            // A dangling HIGHADJ row is malformed and must not publish a mask
            // without its required adjustment slot.
            if (type == 4 && e + 1 >= entries) break;
            if (type != 0) {                       // skip ABSOLUTE padding
                uint64_t relocRVA = 0, relocVA = 0;
                if (CheckedAddressAdd(pageRVA, v & 0xFFFu, relocRVA) &&
                    CheckedAddressAdd(imageBase_, relocRVA, relocVA))
                    relocs_.emplace_back(relocVA, type);
            }
            // IMAGE_REL_BASED_HIGHADJ occupies two 16-bit slots. The second
            // slot is a signed adjustment value, not another relocation row.
            if (type == 4) ++e;
        }
        off += blockSize;
    }
}

// x64 .pdata: an array of 12-byte RUNTIME_FUNCTION { BeginAddress, EndAddress,
// UnwindData } RVAs. Two kinds of entry describe a CONTINUATION of an earlier
// function rather than a new one and are skipped:
//   - UnwindData with bit 0 set points at a parent RUNTIME_FUNCTION directly;
//   - an UNWIND_INFO whose flags carry UNW_FLAG_CHAININFO (0x4).
// Bounded + clamped like every other table walk (a hostile size/RVA must not
// spin or read wild).
std::vector<std::pair<uint64_t, uint64_t>> BinaryFile::pdataRanges() const {
    std::vector<std::pair<uint64_t, uint64_t>> out;
    if (!exceptRVA_ || exceptSize_ < 12) return out;
    if (format_ != BinFormat::PE32Plus || machine_ != MachineArch::X64) return out;
    const uint32_t count = std::min<uint32_t>(exceptSize_ / 12, 200000);
    out.reserve(std::min<uint32_t>(count, 4096));
    for (uint32_t i = 0; i < count; ++i) {
        size_t av = 0;
        const uint8_t* p = ptrFromRVA(static_cast<uint64_t>(exceptRVA_) +
                                      static_cast<uint64_t>(i) * 12, av);
        if (!p || av < 12) break;
        uint32_t begin = 0, end = 0, unwind = 0;
        std::memcpy(&begin, p, 4);
        std::memcpy(&end, p + 4, 4);
        std::memcpy(&unwind, p + 8, 4);
        if (!begin || end <= begin) continue;
        if (unwind & 1u) continue;
        size_t unwindAvail = 0;
        if (const uint8_t* info = ptrFromRVA(unwind, unwindAvail);
            info && unwindAvail >= 1 && ((info[0] >> 3) & 0x4u) != 0)
            continue;
        uint64_t beginVA = 0, endVA = 0;
        if (!CheckedAddressAdd(imageBase_, begin, beginVA) ||
            !CheckedAddressAdd(imageBase_, end, endVA))
            continue;
        out.emplace_back(beginVA, endVA);
    }
    return out;
}

// ------------------------------------------------------------- Java class --
// imageBase_ stays 0 and every section maps identity (virtualAddress ==
// rawOffset == file offset), so VA == file offset throughout: ptrFromVA /
// vaToOffset / offsetToVA line up, and JvmDisassembler's bci math
// (va - method code start) is exact. Each method body becomes its own
// executable section (the listing walks executable sections, so dividers and
// function discovery land on real method starts); one whole-file data section
// at the end backs hex / string-scan / byte-search views for the rest.
bool BinaryFile::parseJavaClass() {
    auto cf = std::make_shared<JvmClassFile>(ParseJavaClass(data_.data(), data_.size()));
    if (!cf->ok) return false;
    format_    = BinFormat::JavaClass;
    machine_   = MachineArch::JVM;
    is64_      = false;
    imageBase_ = 0;
    javaClass_ = cf;

    const std::string cls = JvmShortClassName(cf->thisClass);
    for (const auto& m : cf->methods) {
        if (!m.codeLength) continue;                      // abstract / native: no body
        if ((uint64_t)m.codeOffset + m.codeLength > data_.size()) continue;
        Section s;
        s.name           = cls + "." + m.name;
        s.virtualAddress = m.codeOffset;
        s.virtualSize    = m.codeLength;
        s.rawOffset      = m.codeOffset;
        s.rawSize        = m.codeLength;
        s.executable     = true;
        sections_.push_back(std::move(s));
    }
    // A class file has method bodies and optional conventional launcher roots,
    // but no loader-declared process entry point. FunctionAnalyzer consumes the
    // authoritative method table directly; do not relabel main/<clinit>/the first
    // method as a structured-format entry.
    entryRVA_ = 0;
    entryPointPresent_ = false;

    Section all;
    all.name           = "classfile";
    all.virtualAddress = 0;
    all.virtualSize    = data_.size();
    all.rawOffset      = 0;
    all.rawSize        = data_.size();
    all.executable     = false;
    sections_.push_back(std::move(all));                  // last: method sections win per-VA lookups
    return true;
}

bool BinaryFile::parseGameMakerArchive(const std::function<bool()>& cancelled) {
    auto archive = std::make_shared<GameMakerArchive>(
        ParseGameMakerArchive(data_.data(), data_.size(), cancelled));
    if (!archive->ok) {
        loadErrorText_ = archive->error;
        return false;
    }
    format_ = BinFormat::GameMakerArchive;
    machine_ = MachineArch::GML;
    imageBase_ = 0;
    is64_ = false; // archive offsets are not native runner pointers
    entryRVA_ = 0;
    entryPointPresent_ = false;
    gameMakerArchive_ = archive;
    // Child functions share the parent's physical bytecode. Map each body only
    // once; code-entry identity and aliases remain in the immutable archive.
    for (const auto& code : archive->code) {
        if (code.parentIndex != UINT32_MAX || !code.bytecodeLength) continue;
        Section section;
        section.name = code.name;
        section.virtualAddress = section.rawOffset = code.bytecodeOffset;
        section.virtualSize = section.rawSize = code.bytecodeLength;
        section.executable = archive->bytecodeSupported;
        sections_.push_back(std::move(section));
    }
    Section all;
    all.name = "GameMaker archive";
    all.virtualSize = all.rawSize = data_.size();
    sections_.push_back(std::move(all));
    return true;
}

const Section* BinaryFile::firstCodeSection() const {
    for (const auto& s : sections_) if (s.executable) return &s;
    return nullptr;
}

const uint8_t* BinaryFile::ptrFromRVA(uint64_t rva, size_t& availOut) const {
    // rva is 64-bit so callers walking import/reloc tables (rva + k*stride) can't
    // wrap a 32-bit add and alias an earlier in-bounds slot; ptrFromVA bounds-checks.
    if (rva > std::numeric_limits<uint64_t>::max() - imageBase_) {
        availOut = 0;
        return nullptr;
    }
    return ptrFromVA(imageBase_ + rva, availOut);
}

const uint8_t* BinaryFile::ptrFromVA(uint64_t va, size_t& availOut) const {
    availOut = 0;
    if (format_ == BinFormat::Raw) {
        if (va < imageBase_) return nullptr;
        const uint64_t off = va - imageBase_;
        if (off < data_.size()) {
            availOut = ClampAddressableBytes(va, data_.size() - static_cast<size_t>(off));
            return data_.data() + static_cast<size_t>(off);
        }
        return nullptr;
    }
    if (va < imageBase_) return nullptr;   // below the image base -> not mapped
    const uint64_t rva = va - imageBase_;
    for (const auto& s : sections_) {
        // No-wrap containment: `base + size` overflows on 64-bit ELF/Mach-O fields.
        const uint64_t mappedExtent = SectionVirtualExtent(s);
        if (rva >= s.virtualAddress && rva - s.virtualAddress < mappedExtent) {
            const uint64_t delta = rva - s.virtualAddress;
            const uint64_t fileBackedExtent = SectionFileBackedExtent(s);
            if (delta >= fileBackedExtent) return nullptr; // in virtual padding
            // A malformed image can claim a rawOffset/rawSize past EOF; clamp the
            // returned base and the reported span to the bytes actually present.
            if (delta > std::numeric_limits<uint64_t>::max() - s.rawOffset) return nullptr;
            const uint64_t fileOff = s.rawOffset + delta;
            if (fileOff >= data_.size()) return nullptr;
            const size_t backed = static_cast<size_t>(std::min<uint64_t>(
                fileBackedExtent - delta, data_.size() - fileOff));
            availOut = ClampAddressableBytes(va, backed);
            return data_.data() + static_cast<size_t>(fileOff);
        }
    }
    // PE headers are mapped 1:1 (RVA == file offset), but only for the span
    // explicitly declared by SizeOfHeaders and actually present in the image.
    // This lets legitimate header-resident directories resolve without turning
    // the virtual gap before the first section into file-backed memory.
    if ((format_ == BinFormat::PE32 || format_ == BinFormat::PE32Plus) &&
        rva < sizeOfHeaders_ && rva < data_.size()) {
        const size_t backed = static_cast<size_t>(std::min<uint64_t>(
            static_cast<uint64_t>(sizeOfHeaders_) - rva, data_.size() - rva));
        availOut = ClampAddressableBytes(va, backed);
        return data_.data() + static_cast<size_t>(rva);
    }
    return nullptr;
}

bool BinaryFile::offsetToVA(uint64_t off, uint64_t& vaOut) const {
    // An offset is file-backed only when the byte actually exists. Section
    // headers may declare raw extents past EOF; ptrFromVA/vaToOffset already
    // reject those bytes, so the inverse must do the same before consulting
    // section metadata.
    if (off >= data_.size()) return false;
    if (format_ == BinFormat::Raw) {
        if (off > std::numeric_limits<uint64_t>::max() - imageBase_) return false;
        vaOut = imageBase_ + off;   // Raw: VA space == file space
        return true;
    }
    // Find the section whose raw data contains this offset and remap to its RVA.
    for (const auto& s : sections_) {
        const uint64_t fileBackedExtent = SectionFileBackedExtent(s);
        if (!fileBackedExtent) continue;
        if (off >= s.rawOffset && off - s.rawOffset < fileBackedExtent) { // no-wrap containment
            const uint64_t delta = off - s.rawOffset;
            if (delta > std::numeric_limits<uint64_t>::max() - s.virtualAddress) return false;
            const uint64_t rva = s.virtualAddress + delta;
            if (rva > std::numeric_limits<uint64_t>::max() - imageBase_) return false;
            vaOut = imageBase_ + rva;
            return true;
        }
    }
    // Only the PE header bytes declared by SizeOfHeaders map 1:1. Using the
    // first section's raw offset here would accidentally bless padding or a
    // malformed section-table gap as header data.
    if ((format_ == BinFormat::PE32 || format_ == BinFormat::PE32Plus) &&
        off < sizeOfHeaders_ && off < data_.size()) {
        return CheckedAddressAdd(imageBase_, off, vaOut);
    }
    return false;
}

bool BinaryFile::vaToOffset(uint64_t va, uint64_t& offOut) const {
    if (format_ == BinFormat::Raw) {
        if (va < imageBase_) return false;
        uint64_t off = va - imageBase_;
        if (off >= data_.size()) return false;
        offOut = off; return true;
    }
    if (va < imageBase_) return false;     // below the image base -> not mapped
    const uint64_t rva = va - imageBase_;
    for (const auto& s : sections_) {
        const uint64_t fileBackedExtent = SectionFileBackedExtent(s);
        if (!fileBackedExtent) continue;
        if (rva >= s.virtualAddress && rva - s.virtualAddress < fileBackedExtent) { // no-wrap containment
            uint64_t delta = rva - s.virtualAddress;
            if (delta > std::numeric_limits<uint64_t>::max() - s.rawOffset) return false;
            uint64_t off = s.rawOffset + delta;
            if (off >= data_.size()) return false;
            offOut = off; return true;
        }
    }
    // Header bytes explicitly declared by SizeOfHeaders map 1:1 (RVA == file
    // offset) for PE only. The gap up to the first section RVA remains unmapped.
    if ((format_ == BinFormat::PE32 || format_ == BinFormat::PE32Plus) &&
        rva < sizeOfHeaders_ && rva < data_.size()) {
        offOut = rva;
        return true;
    }
    return false;
}

bool BinaryFile::resolveRealModeAlias(uint16_t segment, uint32_t offset,
                                      uint64_t& vaOut) const {
    const uint64_t linear = (static_cast<uint64_t>(segment) << 4) +
                            static_cast<uint64_t>(offset);
    uint64_t fileOffset = 0;
    if (vaToOffset(linear, fileOffset)) {
        vaOut = linear;
        return true;
    }

    // Only explicit flat firmware mappings receive the legacy BIOS tail
    // alias. Structured binaries must not acquire an invented second mapping.
    constexpr uint64_t kOneMiB = 1u << 20;
    if (format_ != BinFormat::Raw || data_.empty() || linear >= kOneMiB)
        return false;
    const uint64_t tailSpan = std::min<uint64_t>(data_.size(), kOneMiB);
    const uint64_t lowBase = kOneMiB - tailSpan;
    if (linear < lowBase) return false;
    fileOffset = static_cast<uint64_t>(data_.size()) - tailSpan + (linear - lowBase);
    return offsetToVA(fileOffset, vaOut);
}

bool BinaryFile::resolveInstructionTarget(const Instruction& instruction,
                                          uint64_t& vaOut) const {
    if (TryGetDirectTarget(instruction, vaOut)) return true;
    return instruction.farTarget.valid &&
           resolveRealModeAlias(instruction.farTarget.segment,
                                instruction.farTarget.offset, vaOut);
}

// --------------------------------------------------------------------- ELF --
// ELF32/ELF64 in either declared byte order. imageBase_ stays zero and allocated sections carry
// absolute sh_addr values. Non-allocated symbol/string sections are deliberately
// retained in a private header model long enough to parse .dynsym/.symtab, but
// never added to the mapped Section list.
bool BinaryFile::parseELF() {
    constexpr uint32_t SHT_SYMTAB       = 2;
    constexpr uint32_t SHT_STRTAB       = 3;
    constexpr uint32_t SHT_RELA         = 4;
    constexpr uint32_t SHT_DYNAMIC      = 6;
    constexpr uint32_t SHT_NOBITS       = 8;
    constexpr uint32_t SHT_REL          = 9;
    constexpr uint32_t SHT_DYNSYM       = 11;
    constexpr uint32_t SHT_INIT_ARRAY   = 14;
    constexpr uint32_t SHT_FINI_ARRAY   = 15;
    constexpr uint32_t SHT_PREINIT_ARRAY= 16;
    constexpr uint32_t SHT_SYMTAB_SHNDX = 18;
    constexpr uint32_t SHT_GNU_VERDEF   = 0x6ffffffdu;
    constexpr uint32_t SHT_GNU_VERNEED  = 0x6ffffffeu;
    constexpr uint32_t SHT_GNU_VERSYM   = 0x6fffffffu;
    constexpr uint16_t SHN_UNDEF        = 0;
    constexpr uint16_t SHN_XINDEX       = 0xFFFF;
    constexpr uint16_t SHN_LORESERVE    = 0xFF00;
    constexpr uint64_t SHF_ALLOC        = 0x2;
    constexpr uint64_t SHF_EXECINSTR    = 0x4;

    if (data_.size() < 16 || std::memcmp(data_.data(), "\x7F" "ELF", 4) != 0)
        return false;
    const uint8_t eiClass = data_[4]; // ELFCLASS32 / ELFCLASS64
    const uint8_t eiData  = data_[5]; // ELFDATA2LSB / ELFDATA2MSB
    if ((eiClass != 1 && eiClass != 2) || (eiData != 1 && eiData != 2)) return false;
    const bool elf64 = eiClass == 2;
    const size_t headerSize = elf64 ? 64u : 52u;
    if (data_.size() < headerSize) return false;

    is64_      = elf64;
    bigEndian_ = eiData == 2;
    format_    = BinFormat::ELF;
    imageBase_ = 0;
    const uint16_t elfType = rdOrder<uint16_t>(data_, 16, bigEndian_);
    const uint16_t elfMachine = rdOrder<uint16_t>(data_, 18, bigEndian_);
    const uint32_t elfFlags = rdOrder<uint32_t>(data_, elf64 ? 48u : 36u,
                                                bigEndian_);
    constexpr uint32_t EF_RISCV_RVC = 0x00000001u;
    constexpr uint32_t EF_MIPS_MICROMIPS = 0x02000000u;
    elfDecoderMetadata_.present = true;
    elfDecoderMetadata_.flags = elfFlags;
    elfDecoderMetadata_.riscvCompressed = elfMachine == 0xF3 &&
                                          (elfFlags & EF_RISCV_RVC) != 0;
    elfDecoderMetadata_.mipsMicro = elfMachine == 0x08 &&
                                    (elfFlags & EF_MIPS_MICROMIPS) != 0;
    switch (elfMachine) { // e_machine
        case 0x03: machine_ = MachineArch::X86;   break;
        case 0x3E: machine_ = MachineArch::X64;   break;
        case 0x28: machine_ = MachineArch::ARM;   break;
        case 0xB7: machine_ = MachineArch::ARM64; break;
        case 0x08: machine_ = elf64 ? MachineArch::MIPS64 : MachineArch::MIPS; break;
        case 0x14: machine_ = MachineArch::PPC;   break;
        case 0x15: machine_ = MachineArch::PPC64; break;
        case 0xF3: machine_ = elf64 ? MachineArch::RISCV64 : MachineArch::RISCV; break;
        default:   machine_ = MachineArch::Unknown; break;
    }
    // Normal structured loading must never retain an arbitrary caller decoder
    // for an unsupported ELF machine. Users can still opt into loadRaw() and
    // choose the architecture/mapping explicitly.
    if (machine_ == MachineArch::Unknown) {
        loadError_ = BinaryLoadError::UnsupportedMachine;
        return false;
    }
    const bool elfMachineRequires64 = machine_ == MachineArch::X64 ||
                                      machine_ == MachineArch::ARM64 ||
                                      machine_ == MachineArch::PPC64 ||
                                      machine_ == MachineArch::MIPS64 ||
                                      machine_ == MachineArch::RISCV64;
    const bool elfMachineRequires32 = machine_ == MachineArch::X86 ||
                                      machine_ == MachineArch::ARM ||
                                      machine_ == MachineArch::PPC ||
                                      machine_ == MachineArch::MIPS ||
                                      machine_ == MachineArch::RISCV;
    if ((elfMachineRequires64 && !elf64) || (elfMachineRequires32 && elf64))
        return false; // contradictory EI_CLASS / e_machine

    uint64_t ePhOff = 0, eShOff = 0;
    uint16_t ePhEntSize = 0, ePhNum = 0, eShEntSize = 0, declaredShNum = 0;
    uint16_t declaredShStrNdx = 0;
    if (elf64) {
        entryRVA_       = rdOrder<uint64_t>(data_, 24, bigEndian_);
        ePhOff          = rdOrder<uint64_t>(data_, 32, bigEndian_);
        eShOff          = rdOrder<uint64_t>(data_, 40, bigEndian_);
        ePhEntSize      = rdOrder<uint16_t>(data_, 54, bigEndian_);
        ePhNum          = rdOrder<uint16_t>(data_, 56, bigEndian_);
        eShEntSize      = rdOrder<uint16_t>(data_, 58, bigEndian_);
        declaredShNum   = rdOrder<uint16_t>(data_, 60, bigEndian_);
        declaredShStrNdx= rdOrder<uint16_t>(data_, 62, bigEndian_);
    } else {
        entryRVA_       = rdOrder<uint32_t>(data_, 24, bigEndian_);
        ePhOff          = rdOrder<uint32_t>(data_, 28, bigEndian_);
        eShOff          = rdOrder<uint32_t>(data_, 32, bigEndian_);
        ePhEntSize      = rdOrder<uint16_t>(data_, 42, bigEndian_);
        ePhNum          = rdOrder<uint16_t>(data_, 44, bigEndian_);
        eShEntSize      = rdOrder<uint16_t>(data_, 46, bigEndian_);
        declaredShNum   = rdOrder<uint16_t>(data_, 48, bigEndian_);
        declaredShStrNdx= rdOrder<uint16_t>(data_, 50, bigEndian_);
    }
    entryPointPresent_ = elfType != 1 /*ET_REL*/ && entryRVA_ != 0;
    if (elfType == 1 /*ET_REL*/) entryRVA_ = 0; // relocatable objects have no process entry point
    // The 32-bit ARM ELF ABI uses bit zero of e_entry as Thumb-state metadata,
    // not as part of the mapped address. Select the Thumb decoder up front and
    // publish the canonical even entry so every address consumer sees the same
    // executable VA. Symbol values remain byte-for-byte linker metadata and are
    // canonicalized by the analysis layer according to its selected mode.
    if (elfType != 1 /*ET_REL*/ && elfMachine == 0x28 /*EM_ARM*/ && (entryRVA_ & 1u)) {
        machine_ = MachineArch::THUMB;
        entryRVA_ &= ~uint64_t{1};
    }

    // A declared program-header table is authoritative. Reject it as a whole
    // when even one declared entry lies outside the file; accepting only the
    // prefix would silently omit load mappings and analyze a different image.
    const size_t programHeaderNeed = elf64 ? 56u : 32u;
    bool programHeaderTableValid = true;
    if (ePhNum != 0) {
        if (!ePhOff || ePhNum > 4096 || ePhEntSize < programHeaderNeed ||
            ePhOff > data_.size()) {
            programHeaderTableValid = false;
        } else {
            const uint64_t fit = (data_.size() - ePhOff) / ePhEntSize;
            programHeaderTableValid = static_cast<uint64_t>(ePhNum) <= fit;
        }
    }

    // Parse every declared PT_LOAD before looking at section mappings. For
    // executable/shared images the program headers describe the runtime image
    // and are therefore authoritative even when a section table is present.
    // Section headers remain available below for symbols/linkage metadata; ET_REL
    // keeps its synthetic SHF_ALLOC mapping because it has no process image.
    std::vector<Section> loadSegments;
    bool loadSegmentsValid = programHeaderTableValid;
    if (loadSegmentsValid && ePhNum != 0) {
        const size_t count = static_cast<size_t>(ePhNum);
        for (size_t i = 0; i < count; ++i) {
            const size_t base = static_cast<size_t>(ePhOff + i * ePhEntSize);
            if (rdOrder<uint32_t>(data_, base, bigEndian_) != 1 /*PT_LOAD*/) continue;
            uint64_t pOffset = 0, pVaddr = 0, pFileSize = 0, pMemSize = 0;
            uint32_t pFlags = 0;
            if (elf64) {
                pFlags    = rdOrder<uint32_t>(data_, base + 4, bigEndian_);
                pOffset   = rdOrder<uint64_t>(data_, base + 8, bigEndian_);
                pVaddr    = rdOrder<uint64_t>(data_, base + 16, bigEndian_);
                pFileSize = rdOrder<uint64_t>(data_, base + 32, bigEndian_);
                pMemSize  = rdOrder<uint64_t>(data_, base + 40, bigEndian_);
            } else {
                pOffset   = rdOrder<uint32_t>(data_, base + 4, bigEndian_);
                pVaddr    = rdOrder<uint32_t>(data_, base + 8, bigEndian_);
                pFileSize = rdOrder<uint32_t>(data_, base + 16, bigEndian_);
                pMemSize  = rdOrder<uint32_t>(data_, base + 20, bigEndian_);
                pFlags    = rdOrder<uint32_t>(data_, base + 24, bigEndian_);
            }
            // ELF requires p_filesz <= p_memsz. A file-backed prefix must be
            // wholly inside the input, and the virtual half-open range must not
            // wrap. A malformed declared load segment invalidates the complete
            // runtime mapping: silently omitting just that segment would analyze
            // a different image from the one described by the ELF header.
            if (pFileSize > pMemSize) {
                loadSegmentsValid = false;
                break;
            }
            // A zero-sized PT_LOAD contributes no runtime mapping and is legal
            // to ignore. It cannot by itself satisfy the real-mapping gate below.
            if (!pMemSize) continue;
            if (pVaddr > std::numeric_limits<uint64_t>::max() - pMemSize ||
                (!elf64 && pMemSize - 1 >
                    std::numeric_limits<uint32_t>::max() - pVaddr) ||
                (pFileSize && (pOffset > data_.size() ||
                               pFileSize > data_.size() - pOffset)))
            {
                loadSegmentsValid = false;
                break;
            }
            Section section;
            section.name            = "PT_LOAD" + std::to_string(i);
            section.virtualAddress = pVaddr;
            section.virtualSize    = pMemSize;
            section.rawOffset      = pOffset;
            section.rawSize        = pFileSize;
            section.executable     = (pFlags & 1u) != 0;
            section.characteristics = pFlags;
            loadSegments.push_back(std::move(section));
        }
    }
    if (!loadSegmentsValid) return false;

    const bool programMappingsAuthoritative = elfType != 1 /*ET_REL*/ && ePhNum != 0;
    if (programMappingsAuthoritative) {
        // A declared process mapping with no usable PT_LOAD is not a loadable
        // image, even if decorative SHF_ALLOC section headers exist.
        if (loadSegments.empty()) return false;
        sections_ = std::move(loadSegments);
    }

    auto acceptMappedElf = [&]() {
        if (!programHeaderTableValid || sections_.empty()) return false;
        bool hasFileMapping = false;
        for (const Section& section : sections_) {
            if (!SectionFileBackedExtent(section)) continue;
            size_t available = 0;
            if (ptrFromVA(section.virtualAddress, available) && available) {
                hasFileMapping = true;
                break;
            }
        }
        if (!hasFileMapping) return false;
        // A zero entry is normal for shared objects and ET_REL. A declared
        // non-zero process entry must point at an executable, file-backed byte;
        // otherwise a header-only or BSS-only claim must not masquerade as a
        // loadable program image.
        if (!entryPointPresent_) return true;
        for (const Section& section : sections_) {
            if (!section.executable) continue;
            const uint64_t backed = SectionFileBackedExtent(section);
            if (entryRVA_ >= section.virtualAddress &&
                entryRVA_ - section.virtualAddress < backed) {
                size_t available = 0;
                if (ptrFromVA(entryRVA_, available) != nullptr && available != 0)
                    return true;
            }
        }
        return false;
    };

    struct ElfSectionHeader {
        uint32_t name = 0;
        uint32_t type = 0;
        uint64_t flags = 0;
        uint64_t address = 0;
        uint64_t offset = 0;
        uint64_t size = 0;
        uint32_t link = 0;
        uint32_t info = 0;
        uint64_t alignment = 1;
        uint64_t entrySize = 0;
    };

    const size_t expectedShEntSize = elf64 ? 64u : 40u;
    if (!eShOff || eShEntSize < expectedShEntSize || eShOff > data_.size()) {
        return acceptMappedElf();
    }

    // ELF extended numbering stores e_shnum and/or e_shstrndx in section zero.
    // Read only one already-bounded entry before trusting those values.
    if (eShEntSize > data_.size() - eShOff) {
        return acceptMappedElf();
    }
    const size_t sh0 = static_cast<size_t>(eShOff);
    const uint64_t extendedCount = elf64
        ? rdOrder<uint64_t>(data_, sh0 + 32, bigEndian_)
        : rdOrder<uint32_t>(data_, sh0 + 20, bigEndian_);
    const uint32_t extendedStrNdx = elf64
        ? rdOrder<uint32_t>(data_, sh0 + 40, bigEndian_)
        : rdOrder<uint32_t>(data_, sh0 + 24, bigEndian_);
    uint64_t sectionCount = declaredShNum ? declaredShNum : extendedCount;
    uint64_t sectionNameIndex = declaredShStrNdx == SHN_XINDEX
                              ? extendedStrNdx : declaredShStrNdx;
    constexpr uint64_t kMaxElfSections = 4096;
    if (!sectionCount || sectionCount > kMaxElfSections) {
        return acceptMappedElf();
    }
    const uint64_t fitSections = (data_.size() - eShOff) / eShEntSize;
    if (sectionCount > fitSections) {
        return acceptMappedElf();
    }

    std::vector<ElfSectionHeader> headers(static_cast<size_t>(sectionCount));
    for (size_t i = 0; i < headers.size(); ++i) {
        const size_t base = static_cast<size_t>(eShOff + i * eShEntSize);
        ElfSectionHeader& sh = headers[i];
        sh.name = rdOrder<uint32_t>(data_, base, bigEndian_);
        sh.type = rdOrder<uint32_t>(data_, base + 4, bigEndian_);
        if (elf64) {
            sh.flags     = rdOrder<uint64_t>(data_, base + 8, bigEndian_);
            sh.address   = rdOrder<uint64_t>(data_, base + 16, bigEndian_);
            sh.offset    = rdOrder<uint64_t>(data_, base + 24, bigEndian_);
            sh.size      = rdOrder<uint64_t>(data_, base + 32, bigEndian_);
            sh.link      = rdOrder<uint32_t>(data_, base + 40, bigEndian_);
            sh.info      = rdOrder<uint32_t>(data_, base + 44, bigEndian_);
            sh.alignment = rdOrder<uint64_t>(data_, base + 48, bigEndian_);
            sh.entrySize = rdOrder<uint64_t>(data_, base + 56, bigEndian_);
        } else {
            sh.flags     = rdOrder<uint32_t>(data_, base + 8, bigEndian_);
            sh.address   = rdOrder<uint32_t>(data_, base + 12, bigEndian_);
            sh.offset    = rdOrder<uint32_t>(data_, base + 16, bigEndian_);
            sh.size      = rdOrder<uint32_t>(data_, base + 20, bigEndian_);
            sh.link      = rdOrder<uint32_t>(data_, base + 24, bigEndian_);
            sh.info      = rdOrder<uint32_t>(data_, base + 28, bigEndian_);
            sh.alignment = rdOrder<uint32_t>(data_, base + 32, bigEndian_);
            sh.entrySize = rdOrder<uint32_t>(data_, base + 36, bigEndian_);
        }
    }

    auto fileBacked = [&](const ElfSectionHeader& sh) {
        return sh.offset <= data_.size() && sh.size <= data_.size() - sh.offset;
    };
    auto tableString = [&](const ElfSectionHeader& strings, uint32_t offset,
                           size_t maxLength) -> std::string_view {
        if (strings.type != SHT_STRTAB || !fileBacked(strings) || offset >= strings.size)
            return {};
        const size_t start = static_cast<size_t>(strings.offset + offset);
        const size_t remain = static_cast<size_t>(strings.size - offset);
        const size_t limit = std::min(remain, maxLength);
        const char* text = reinterpret_cast<const char*>(data_.data() + start);
        const void* end = std::memchr(text, 0, limit);
        if (!end) return {};
        return std::string_view(text, static_cast<const char*>(end) - text);
    };

    const ElfSectionHeader* sectionNames = sectionNameIndex < headers.size()
                                        ? &headers[static_cast<size_t>(sectionNameIndex)] : nullptr;
    auto sectionName = [&](size_t index) -> std::string_view {
        if (!sectionNames || index >= headers.size()) return {};
        return tableString(*sectionNames, headers[index].name, 256);
    };

    // Relocatable objects normally give every allocated section sh_addr == 0
    // and define st_value relative to its owning section. Assign a stable,
    // disjoint synthetic analysis range to each SHF_ALLOC section so two COMDAT
    // / .text.* sections with the same st_value do not alias. The allocator is
    // deliberately checked: malformed alignment/extent values cause that one
    // section (and its symbols) to be skipped rather than wrapped.
    std::vector<uint64_t> analysisAddress(headers.size(), 0);
    std::vector<uint8_t> analysisAddressValid(headers.size(), 0);
    if (elfType == 1 /*ET_REL*/) {
        constexpr uint64_t kRelocatableAnalysisBase = 0x10000000ull;
        uint64_t cursor = kRelocatableAnalysisBase;
        for (size_t i = 0; i < headers.size(); ++i) {
            const ElfSectionHeader& sh = headers[i];
            if (!(sh.flags & SHF_ALLOC)) continue;
            const uint64_t alignment = sh.alignment ? sh.alignment : 1;
            if ((alignment & (alignment - 1)) != 0) continue; // ELF requires a power of two
            const uint64_t mask = alignment - 1;
            if (cursor > std::numeric_limits<uint64_t>::max() - mask) continue;
            const uint64_t aligned = (cursor + mask) & ~mask;
            const uint64_t span = sh.size ? sh.size : 1; // keep zero-sized allocated sections distinct
            if (span > std::numeric_limits<uint64_t>::max() - aligned) continue;
            analysisAddress[i] = aligned;
            analysisAddressValid[i] = 1;
            cursor = aligned + span;
        }
    } else {
        for (size_t i = 0; i < headers.size(); ++i) {
            analysisAddress[i] = headers[i].address;
            analysisAddressValid[i] = 1;
        }
    }

    for (size_t i = 0; i < headers.size(); ++i) {
        const ElfSectionHeader& sh = headers[i];
        if (!(sh.flags & SHF_ALLOC) || !analysisAddressValid[i]) continue;
        if (!sh.size || analysisAddress[i] > std::numeric_limits<uint64_t>::max() - sh.size)
            continue;
        if (sh.type != SHT_NOBITS && !fileBacked(sh)) continue;
        Section section;
        if (sectionNames) {
            const std::string_view name = tableString(*sectionNames, sh.name, 256);
            if (!name.empty()) section.name.assign(name.data(), name.size());
        }
        section.virtualAddress  = analysisAddress[i];
        section.virtualSize     = sh.size;
        section.rawOffset       = sh.offset;
        section.rawSize         = sh.type == SHT_NOBITS ? 0 : sh.size;
        section.executable      = (sh.flags & SHF_EXECINSTR) != 0;
        section.characteristics = static_cast<uint32_t>(sh.flags);
        if (!programMappingsAuthoritative)
            sections_.push_back(std::move(section));
    }

    // SHT_SYMTAB_SHNDX supplies the real section index for symbols whose
    // 16-bit st_shndx is SHN_XINDEX. Associate each companion with its symtab.
    std::vector<int32_t> extendedIndexSection(headers.size(), -1);
    for (size_t i = 0; i < headers.size(); ++i)
        if (headers[i].type == SHT_SYMTAB_SHNDX && headers[i].link < headers.size())
            extendedIndexSection[headers[i].link] = static_cast<int32_t>(i);

    constexpr size_t kMaxSymbolEntries      = 500000;
    constexpr size_t kMaxSymbolRows         = 300000;
    constexpr size_t kMaxSymbolName         = 4096;
    constexpr size_t kMaxStoredSymbolBytes  = 32 * 1024 * 1024;
    constexpr size_t kMaxNameScanBytes      = 64 * 1024 * 1024;
    size_t parsedEntries = 0, storedBytes = 0, scannedNameBytes = 0;

    struct CachedNameKey {
        uint32_t table = 0;
        uint32_t offset = 0;
        bool operator==(const CachedNameKey&) const = default;
    };
    struct CachedNameHash {
        size_t operator()(const CachedNameKey& key) const noexcept {
            return (static_cast<size_t>(key.table) << 32) ^ key.offset;
        }
    };
    std::unordered_map<CachedNameKey, std::string_view, CachedNameHash> nameCache;
    auto symbolName = [&](uint32_t stringTable, uint32_t offset) -> std::string_view {
        const CachedNameKey key{stringTable, offset};
        if (auto it = nameCache.find(key); it != nameCache.end()) return it->second;
        std::string_view value;
        if (stringTable < headers.size() && scannedNameBytes < kMaxNameScanBytes) {
            const ElfSectionHeader& strings = headers[stringTable];
            if (strings.type == SHT_STRTAB && fileBacked(strings) && offset < strings.size) {
                const size_t remain = static_cast<size_t>(strings.size - offset);
                const size_t work = std::min({remain, kMaxSymbolName,
                                              kMaxNameScanBytes - scannedNameBytes});
                const char* text = reinterpret_cast<const char*>(
                    data_.data() + static_cast<size_t>(strings.offset + offset));
                size_t n = 0;
                while (n < work) {
                    ++scannedNameBytes;
                    if (!text[n]) { value = std::string_view(text, n); break; }
                    ++n;
                }
            }
        }
        nameCache.emplace(key, value);
        return value;
    };

    auto toKind = [](uint8_t type) {
        switch (type) {
            case 1:  return SymbolKind::Object;           // STT_OBJECT
            case 2:  return SymbolKind::Function;         // STT_FUNC
            case 6:  return SymbolKind::ThreadLocal;      // STT_TLS
            case 10: return SymbolKind::IndirectFunction; // STT_GNU_IFUNC
            default: return SymbolKind::Unknown;
        }
    };
    auto toBinding = [](uint8_t binding) {
        switch (binding) {
            case 0:  return SymbolBinding::Local;
            case 1:  return SymbolBinding::Global;
            case 2:  return SymbolBinding::Weak;
            case 10: return SymbolBinding::Unique;
            default: return SymbolBinding::Unknown;
        }
    };
    auto toVisibility = [](uint8_t visibility) {
        switch (visibility & 3u) {
            case 0: return SymbolVisibility::Default;
            case 1: return SymbolVisibility::Internal;
            case 2: return SymbolVisibility::Hidden;
            case 3: return SymbolVisibility::Protected;
        }
        return SymbolVisibility::Unknown;
    };

    // Section-relative reads are checked against both the declared section
    // extent and the bytes actually present in the file. They intentionally
    // permit a valid offset/value of zero.
    auto sectionData = [&](const ElfSectionHeader& sh, uint64_t relative,
                           size_t need) -> const uint8_t* {
        if (relative > sh.size || need > sh.size - relative) return nullptr;
        if (sh.offset > data_.size() || relative > data_.size() - sh.offset)
            return nullptr;
        const uint64_t absolute = sh.offset + relative;
        if (absolute > data_.size() || need > data_.size() - absolute) return nullptr;
        return data_.data() + static_cast<size_t>(absolute);
    };

    struct DynamicArraySpec {
        ElfInitializerKind kind = ElfInitializerKind::InitArray;
        uint64_t address = 0;
        uint64_t size = 0;
        bool addressPresent = false;
        bool sizePresent = false;
    };
    DynamicArraySpec dynamicPreinit{ElfInitializerKind::PreinitArray};
    DynamicArraySpec dynamicInit{ElfInitializerKind::InitArray};
    DynamicArraySpec dynamicFini{ElfInitializerKind::FiniArray};

    // SHT_DYNAMIC: retain DT_NEEDED in declaration order and the initialization
    // tags needed below. Multiple dynamic sections are legal; aggregate status
    // becomes invalid/truncated if any declared table is structurally unsafe.
    constexpr uint64_t kMaxDynamicEntries = 100000;
    constexpr size_t kMaxDependencies = 16384;
    constexpr size_t kMaxDynamicStringBytes = 4 * 1024 * 1024;
    uint64_t dynamicEntriesSeen = 0;
    size_t dynamicStringBytes = 0;
    for (size_t tableIndex = 0; tableIndex < headers.size(); ++tableIndex) {
        const ElfSectionHeader& table = headers[tableIndex];
        if (table.type != SHT_DYNAMIC) continue;
        elfDynamic_.present = true;
        bool tableValid = table.link < headers.size() &&
                          headers[table.link].type == SHT_STRTAB &&
                          fileBacked(headers[table.link]);
        const uint64_t exactEntrySize = elf64 ? 16u : 8u;
        tableValid = tableValid && table.entrySize >= exactEntrySize &&
                     table.offset <= data_.size();
        if (!tableValid) {
            elfDynamic_.valid = false;
            elfDynamic_.terminated = false;
            elfDynamic_.truncated = true;
            continue;
        }
        const uint64_t declared = table.size / table.entrySize;
        const uint64_t fileFit = (data_.size() - table.offset) / table.entrySize;
        const uint64_t budget = dynamicEntriesSeen < kMaxDynamicEntries
                              ? kMaxDynamicEntries - dynamicEntriesSeen : 0;
        const uint64_t count = std::min({declared, fileFit, budget});
        bool terminated = false;
        for (uint64_t i = 0; i < count; ++i) {
            ++dynamicEntriesSeen;
            const uint8_t* raw = sectionData(table, i * table.entrySize,
                                             static_cast<size_t>(exactEntrySize));
            if (!raw) break;
            const size_t rawOffset = static_cast<size_t>(raw - data_.data());
            const int64_t tag = elf64
                ? static_cast<int64_t>(rdOrder<uint64_t>(data_, rawOffset, bigEndian_))
                : static_cast<int32_t>(rdOrder<uint32_t>(data_, rawOffset, bigEndian_));
            const uint64_t value = elf64
                ? rdOrder<uint64_t>(data_, rawOffset + 8, bigEndian_)
                : rdOrder<uint32_t>(data_, rawOffset + 4, bigEndian_);
            if (tag == 0 /*DT_NULL*/) { terminated = true; break; }
            if (tag == 1 /*DT_NEEDED*/) {
                if (elfDynamic_.dependencies.size() >= kMaxDependencies) {
                    elfDynamic_.truncated = true;
                    continue;
                }
                ElfDynamicDependency dependency;
                dependency.dynamicSectionIndex = static_cast<uint32_t>(tableIndex);
                dependency.stringOffset = value;
                std::string_view name;
                if (value <= std::numeric_limits<uint32_t>::max())
                    name = symbolName(table.link, static_cast<uint32_t>(value));
                if (!name.empty() && name.size() <= kMaxDynamicStringBytes - dynamicStringBytes) {
                    dependency.name.assign(name.data(), name.size());
                    dependency.stringValid = true;
                    dynamicStringBytes += name.size();
                } else if (!name.empty()) {
                    elfDynamic_.truncated = true;
                }
                if (!dependency.stringValid) elfDynamic_.valid = false;
                elfDynamic_.dependencies.push_back(std::move(dependency));
            } else if (tag == 12 /*DT_INIT*/ || tag == 13 /*DT_FINI*/) {
                if (elfInitializers_.entries.size() >= 65536) {
                    elfInitializers_.truncated = true;
                    continue;
                }
                ElfInitializer initializer;
                initializer.kind = tag == 12 ? ElfInitializerKind::Init
                                              : ElfInitializerKind::Fini;
                initializer.address = value;
                initializer.addressValid = true; // zero is a representable ELF VA
                size_t avail = 0;
                initializer.addressMapped = ptrFromVA(value, avail) != nullptr && avail != 0;
                initializer.fromDynamic = true;
                elfInitializers_.entries.push_back(std::move(initializer));
            } else {
                DynamicArraySpec* spec = nullptr;
                bool isSize = false;
                switch (tag) {
                    case 32: spec = &dynamicPreinit; break; // DT_PREINIT_ARRAY
                    case 33: spec = &dynamicPreinit; isSize = true; break;
                    case 25: spec = &dynamicInit; break;    // DT_INIT_ARRAY
                    case 27: spec = &dynamicInit; isSize = true; break;
                    case 26: spec = &dynamicFini; break;    // DT_FINI_ARRAY
                    case 28: spec = &dynamicFini; isSize = true; break;
                    default: break;
                }
                if (spec) {
                    if (isSize) { spec->size = value; spec->sizePresent = true; }
                    else { spec->address = value; spec->addressPresent = true; }
                }
            }
        }
        const bool completeBytes = table.size % table.entrySize == 0 && declared <= fileFit;
        if (!terminated || !completeBytes || count < declared) elfDynamic_.truncated = true;
        elfDynamic_.terminated = elfDynamic_.terminated && terminated;
    }

    // GNU symbol-version definition/requirement chains use section-relative
    // next/aux offsets. Track visited offsets and cap both records and retained
    // strings so malformed self-loops cannot spin or allocate without bound.
    constexpr size_t kMaxVersionRows = 65536;
    constexpr size_t kMaxVersionAssociations = 500000;
    constexpr size_t kMaxVersionStringBytes = 8 * 1024 * 1024;
    size_t versionStringBytes = 0;
    size_t versionNeedHeaders = 0;
    auto retainVersionString = [&](uint32_t stringTable, uint32_t offset,
                                   std::string& destination) {
        const std::string_view value = symbolName(stringTable, offset);
        if (value.empty() || value.size() > kMaxVersionStringBytes - versionStringBytes)
            return false;
        destination.assign(value.data(), value.size());
        versionStringBytes += value.size();
        return true;
    };

    for (size_t sectionIndex = 0; sectionIndex < headers.size(); ++sectionIndex) {
        const ElfSectionHeader& table = headers[sectionIndex];
        if (table.type != SHT_GNU_VERDEF) continue;
        if (table.link >= headers.size() || headers[table.link].type != SHT_STRTAB) {
            elfVersions_.definitionsTruncated = true;
            continue;
        }
        std::unordered_set<uint64_t> visited;
        uint64_t offset = 0;
        for (;;) {
            if (elfVersions_.definitions.size() >= kMaxVersionRows ||
                !visited.insert(offset).second) {
                elfVersions_.definitionsTruncated = true;
                break;
            }
            const uint8_t* raw = sectionData(table, offset, 20);
            if (!raw) { elfVersions_.definitionsTruncated = true; break; }
            const size_t base = static_cast<size_t>(raw - data_.data());
            ElfVersionDefinition definition;
            definition.flags = rdOrder<uint16_t>(data_, base + 2, bigEndian_);
            definition.index = rdOrder<uint16_t>(data_, base + 4, bigEndian_) & 0x7fffu;
            const uint16_t count = rdOrder<uint16_t>(data_, base + 6, bigEndian_);
            definition.hash = rdOrder<uint32_t>(data_, base + 8, bigEndian_);
            const uint32_t auxDelta = rdOrder<uint32_t>(data_, base + 12, bigEndian_);
            const uint32_t nextDelta = rdOrder<uint32_t>(data_, base + 16, bigEndian_);
            definition.sectionIndex = static_cast<uint32_t>(sectionIndex);
            uint64_t auxOffset = 0;
            if (auxDelta <= std::numeric_limits<uint64_t>::max() - offset)
                auxOffset = offset + auxDelta;
            const uint8_t* aux = auxDelta ? sectionData(table, auxOffset, 8) : nullptr;
            definition.valid = rdOrder<uint16_t>(data_, base, bigEndian_) == 1 && count != 0 &&
                               definition.index != 0 && aux != nullptr;
            if (aux) {
                const uint32_t nameOffset = rdOrder<uint32_t>(data_,
                    static_cast<size_t>(aux - data_.data()), bigEndian_);
                definition.valid = retainVersionString(table.link, nameOffset,
                                                       definition.name) && definition.valid;
            }
            elfVersions_.definitions.push_back(std::move(definition));
            if (!nextDelta) break;
            if (nextDelta > table.size - std::min(offset, table.size)) {
                elfVersions_.definitionsTruncated = true;
                break;
            }
            offset += nextDelta;
        }
    }

    for (size_t sectionIndex = 0; sectionIndex < headers.size(); ++sectionIndex) {
        const ElfSectionHeader& table = headers[sectionIndex];
        if (table.type != SHT_GNU_VERNEED) continue;
        if (table.link >= headers.size() || headers[table.link].type != SHT_STRTAB) {
            elfVersions_.requirementsTruncated = true;
            continue;
        }
        std::unordered_set<uint64_t> visited;
        uint64_t offset = 0;
        for (;;) {
            if (versionNeedHeaders >= kMaxVersionRows || !visited.insert(offset).second) {
                elfVersions_.requirementsTruncated = true;
                break;
            }
            ++versionNeedHeaders;
            const uint8_t* raw = sectionData(table, offset, 16);
            if (!raw) { elfVersions_.requirementsTruncated = true; break; }
            const size_t base = static_cast<size_t>(raw - data_.data());
            const bool headerValid = rdOrder<uint16_t>(data_, base, bigEndian_) == 1;
            const uint16_t auxCount = rdOrder<uint16_t>(data_, base + 2, bigEndian_);
            const uint32_t fileOffset = rdOrder<uint32_t>(data_, base + 4, bigEndian_);
            const uint32_t auxDelta = rdOrder<uint32_t>(data_, base + 8, bigEndian_);
            const uint32_t nextDelta = rdOrder<uint32_t>(data_, base + 12, bigEndian_);
            std::string file;
            const bool fileValid = retainVersionString(table.link, fileOffset, file);
            if (!headerValid || auxCount == 0) elfVersions_.requirementsTruncated = true;
            uint64_t auxOffset = 0;
            bool auxChainValid = auxDelta != 0 && auxDelta <=
                                 std::numeric_limits<uint64_t>::max() - offset;
            if (auxChainValid) auxOffset = offset + auxDelta;
            for (uint16_t auxIndex = 0; auxIndex < auxCount; ++auxIndex) {
                if (elfVersions_.requirements.size() >= kMaxVersionRows) {
                    elfVersions_.requirementsTruncated = true;
                    auxChainValid = false;
                    break;
                }
                const uint8_t* aux = auxChainValid ? sectionData(table, auxOffset, 16) : nullptr;
                if (!aux) {
                    elfVersions_.requirementsTruncated = true;
                    auxChainValid = false;
                    break;
                }
                const size_t auxBase = static_cast<size_t>(aux - data_.data());
                ElfVersionRequirement requirement;
                requirement.hash = rdOrder<uint32_t>(data_, auxBase, bigEndian_);
                requirement.flags = rdOrder<uint16_t>(data_, auxBase + 4, bigEndian_);
                requirement.index = rdOrder<uint16_t>(data_, auxBase + 6, bigEndian_) & 0x7fffu;
                requirement.sectionIndex = static_cast<uint32_t>(sectionIndex);
                const uint32_t nameOffset = rdOrder<uint32_t>(data_, auxBase + 8, bigEndian_);
                const bool fileCopyValid = file.size() <=
                                           kMaxVersionStringBytes - versionStringBytes;
                if (fileCopyValid) {
                    requirement.file = file;
                    versionStringBytes += file.size();
                } else {
                    elfVersions_.requirementsTruncated = true;
                }
                requirement.valid = headerValid && fileValid && fileCopyValid &&
                                    requirement.index > 1 &&
                                    retainVersionString(table.link, nameOffset, requirement.name);
                elfVersions_.requirements.push_back(std::move(requirement));
                const uint32_t auxNext = rdOrder<uint32_t>(data_, auxBase + 12, bigEndian_);
                if (auxIndex + 1 < auxCount) {
                    if (!auxNext || auxNext > table.size - std::min(auxOffset, table.size)) {
                        elfVersions_.requirementsTruncated = true;
                        auxChainValid = false;
                        break;
                    }
                    auxOffset += auxNext;
                }
            }
            if (!nextDelta) break;
            if (nextDelta > table.size - std::min(offset, table.size)) {
                elfVersions_.requirementsTruncated = true;
                break;
            }
            offset += nextDelta;
        }
    }

    std::unordered_map<uint16_t, const ElfVersionDefinition*> versionDefinitions;
    std::unordered_map<uint16_t, const ElfVersionRequirement*> versionRequirements;
    for (const auto& definition : elfVersions_.definitions)
        if (definition.valid) versionDefinitions.try_emplace(definition.index, &definition);
    for (const auto& requirement : elfVersions_.requirements)
        if (requirement.valid) versionRequirements.try_emplace(requirement.index, &requirement);

    std::unordered_map<uint64_t, size_t> versionAssociation;
    for (size_t sectionIndex = 0; sectionIndex < headers.size(); ++sectionIndex) {
        const ElfSectionHeader& table = headers[sectionIndex];
        if (table.type != SHT_GNU_VERSYM) continue;
        if (table.link >= headers.size() || headers[table.link].type != SHT_DYNSYM ||
            table.offset > data_.size()) {
            elfVersions_.symbolsTruncated = true;
            continue;
        }
        const uint64_t stride = table.entrySize >= 2 ? table.entrySize : 2;
        const uint64_t declared = table.size / stride;
        const uint64_t fileFit = (data_.size() - table.offset) / stride;
        const uint64_t budget = elfVersions_.symbols.size() < kMaxVersionAssociations
                              ? kMaxVersionAssociations - elfVersions_.symbols.size() : 0;
        const uint64_t count = std::min({declared, fileFit, budget});
        for (uint64_t symbolIndex = 0; symbolIndex < count; ++symbolIndex) {
            const uint8_t* raw = sectionData(table, symbolIndex * stride, 2);
            if (!raw) break;
            const uint16_t encoded = rdOrder<uint16_t>(data_,
                static_cast<size_t>(raw - data_.data()), bigEndian_);
            ElfSymbolVersion association;
            association.symbolTableSectionIndex = table.link;
            association.symbolIndex = static_cast<uint32_t>(symbolIndex);
            association.index = encoded & 0x7fffu;
            association.hidden = (encoded & 0x8000u) != 0;
            if (auto it = versionDefinitions.find(association.index);
                it != versionDefinitions.end()) {
                association.definition = true;
                association.valid = true;
                if (it->second->name.size() <= kMaxVersionStringBytes - versionStringBytes) {
                    association.name = it->second->name;
                    versionStringBytes += association.name.size();
                } else {
                    elfVersions_.symbolsTruncated = true;
                }
            } else if (auto it = versionRequirements.find(association.index);
                       it != versionRequirements.end()) {
                association.requirement = true;
                association.valid = true;
                const size_t required = it->second->name.size() + it->second->file.size();
                if (required <= kMaxVersionStringBytes - versionStringBytes) {
                    association.name = it->second->name;
                    association.file = it->second->file;
                    versionStringBytes += required;
                } else {
                    elfVersions_.symbolsTruncated = true;
                }
            } else {
                association.valid = association.index <= 1;
            }
            const uint64_t key = (static_cast<uint64_t>(table.link) << 32) |
                                 static_cast<uint32_t>(symbolIndex);
            versionAssociation.try_emplace(key, elfVersions_.symbols.size());
            elfVersions_.symbols.push_back(std::move(association));
        }
        if (table.size % stride != 0 || count < declared)
            elfVersions_.symbolsTruncated = true;
    }

    struct DefinedKey {
        uint64_t va = 0;
        uint32_t section = 0;
        std::string_view name;
        bool operator==(const DefinedKey&) const = default;
    };
    struct DefinedKeyHash {
        size_t operator()(const DefinedKey& key) const noexcept {
            size_t h = std::hash<uint64_t>{}(key.va);
            h ^= std::hash<uint32_t>{}(key.section) + static_cast<size_t>(0x9e3779b9u) + (h << 6) + (h >> 2);
            h ^= std::hash<std::string_view>{}(key.name) + static_cast<size_t>(0x9e3779b9u) + (h << 6) + (h >> 2);
            return h;
        }
    };
    std::unordered_map<DefinedKey, size_t, DefinedKeyHash> definedRows;
    std::unordered_map<std::string_view, size_t> undefinedRows;

    // Dynamic symbols are parsed first so their public spelling/metadata wins
    // when .symtab repeats the same symbol. True aliases (different names at the
    // same address) remain separate rows.
    for (uint32_t wantedType : {SHT_DYNSYM, SHT_SYMTAB}) {
        for (size_t tableIndex = 0; tableIndex < headers.size(); ++tableIndex) {
            const ElfSectionHeader& table = headers[tableIndex];
            if (table.type != wantedType || table.link >= headers.size()) continue;
            const ElfSectionHeader& strings = headers[table.link];
            const size_t exactEntrySize = elf64 ? 24u : 16u;
            if (table.entrySize < exactEntrySize || !fileBacked(table) ||
                strings.type != SHT_STRTAB || !fileBacked(strings)) continue;
            const uint64_t fileFit = (data_.size() - table.offset) / table.entrySize;
            uint64_t count = std::min(table.size / table.entrySize, fileFit);
            count = std::min<uint64_t>(count, kMaxSymbolEntries - parsedEntries);
            const bool dynamic = wantedType == SHT_DYNSYM;

            for (uint64_t symbolIndex = 0; symbolIndex < count; ++symbolIndex) {
                ++parsedEntries;
                const size_t base = static_cast<size_t>(table.offset + symbolIndex * table.entrySize);
                const uint32_t nameOffset = rdOrder<uint32_t>(data_, base, bigEndian_);
                uint64_t value = 0, symbolSize = 0;
                uint8_t info = 0, other = 0;
                uint16_t section16 = 0;
                if (elf64) {
                    info      = rdOrder<uint8_t>(data_, base + 4, bigEndian_);
                    other     = rdOrder<uint8_t>(data_, base + 5, bigEndian_);
                    section16 = rdOrder<uint16_t>(data_, base + 6, bigEndian_);
                    value     = rdOrder<uint64_t>(data_, base + 8, bigEndian_);
                    symbolSize= rdOrder<uint64_t>(data_, base + 16, bigEndian_);
                } else {
                    value     = rdOrder<uint32_t>(data_, base + 4, bigEndian_);
                    symbolSize= rdOrder<uint32_t>(data_, base + 8, bigEndian_);
                    info      = rdOrder<uint8_t>(data_, base + 12, bigEndian_);
                    other     = rdOrder<uint8_t>(data_, base + 13, bigEndian_);
                    section16 = rdOrder<uint16_t>(data_, base + 14, bigEndian_);
                }
                uint32_t sectionIndex = section16;
                if (section16 == SHN_XINDEX && extendedIndexSection[tableIndex] < 0)
                    continue; // malformed extended-index symbol
                if (section16 == SHN_XINDEX) {
                    const ElfSectionHeader& ext = headers[static_cast<size_t>(extendedIndexSection[tableIndex])];
                    const uint64_t extOffset = symbolIndex * sizeof(uint32_t);
                    if (!fileBacked(ext) || extOffset > ext.size || sizeof(uint32_t) > ext.size - extOffset)
                        continue;
                    sectionIndex = rdOrder<uint32_t>(data_,
                        static_cast<size_t>(ext.offset + extOffset), bigEndian_);
                }

                const std::string_view name = symbolName(table.link, nameOffset);
                if (name.empty()) continue;
                const uint8_t rawType = info & 0x0Fu;
                const uint8_t rawBinding = info >> 4;
                const SymbolKind kind = toKind(rawType);
                const SymbolBinding binding = toBinding(rawBinding);
                const SymbolVisibility visibility = toVisibility(other);
                const bool local = binding == SymbolBinding::Local;
                const ElfSymbolVersion* symbolVersion = nullptr;
                const uint64_t versionKey = (static_cast<uint64_t>(tableIndex) << 32) |
                                            static_cast<uint32_t>(symbolIndex);
                if (auto versionIt = versionAssociation.find(versionKey);
                    versionIt != versionAssociation.end())
                    symbolVersion = &elfVersions_.symbols[versionIt->second];

                if (sectionIndex == SHN_UNDEF) {
                    // DYNSYM undefined rows describe runtime imports; ET_REL
                    // objects commonly carry their externals only in SYMTAB.
                    // Keep non-local global/weak/unique rows from either table,
                    // while file/section bookkeeping is never an API. DYNSYM is
                    // visited first, so its metadata/provider label wins dedup.
                    const bool externallyBound = binding == SymbolBinding::Global ||
                                                 binding == SymbolBinding::Weak ||
                                                 binding == SymbolBinding::Unique;
                    if (local || !externallyBound || rawType == 3 || rawType == 4) continue;
                    auto [it, inserted] = undefinedRows.try_emplace(name, imports_.size());
                    if (!inserted) continue;
                    if (imports_.size() >= kMaxSymbolRows ||
                        name.size() > kMaxStoredSymbolBytes - storedBytes) continue;
                    Import import;
                    import.dll = dynamic ? "(dynamic)" : "(undefined)";
                    import.name.assign(name.data(), name.size());
                    import.addressKnown = false;
                    import.kind = kind;
                    import.binding = binding;
                    import.visibility = visibility;
                    import.dynamicSymbol = dynamic;
                    if (symbolVersion) {
                        import.elfVersionIndex = symbolVersion->index;
                        import.elfVersionHidden = symbolVersion->hidden;
                        if (symbolVersion->name.size() <=
                            kMaxStoredSymbolBytes - storedBytes - name.size()) {
                            import.elfVersion = symbolVersion->name;
                            storedBytes += import.elfVersion.size();
                        }
                    }
                    imports_.push_back(std::move(import));
                    storedBytes += name.size();
                    continue;
                }
                if (sectionIndex < SHN_LORESERVE && sectionIndex >= headers.size())
                    continue; // ordinary section indices must name a real header

                // Ignore table bookkeeping. Keep typed local symbols, and keep
                // untyped symbols only when externally visible/dynamic.
                if (rawType == 3 || rawType == 4) continue; // STT_SECTION / STT_FILE
                if (kind == SymbolKind::Unknown && local && !dynamic) continue;

                const bool regularSection = sectionIndex < headers.size() && sectionIndex < SHN_LORESERVE;
                const ElfSectionHeader* owner = regularSection ? &headers[sectionIndex] : nullptr;
                const bool ownerAddressValid = regularSection && analysisAddressValid[sectionIndex] &&
                                               (headers[sectionIndex].flags & SHF_ALLOC) != 0;
                const uint64_t ownerAddress = ownerAddressValid ? analysisAddress[sectionIndex] : 0;
                uint64_t va = value;
                // ET_REL st_value is section-relative; ET_EXEC/ET_DYN values are
                // already virtual addresses. A regular ET_REL section whose
                // synthetic range was rejected cannot safely contribute symbols.
                if (elfType == 1 /*ET_REL*/ && owner) {
                    if (!ownerAddressValid || ownerAddress > std::numeric_limits<uint64_t>::max() - value)
                        continue;
                    va = ownerAddress + value;
                }
                bool mapped = false, code = false;
                if (owner && ownerAddressValid && va >= ownerAddress) {
                    const uint64_t delta = va - ownerAddress;
                    const bool inSection = delta < owner->size || (owner->size == 0 && delta == 0);
                    if (inSection && owner->type != SHT_NOBITS && fileBacked(*owner) && delta < owner->size)
                        mapped = delta < owner->size && delta < data_.size() - owner->offset;
                    const bool executableStorage = mapped && (owner->flags & SHF_EXECINSTR) != 0;
                    code = executableStorage && kind != SymbolKind::Object &&
                           kind != SymbolKind::ThreadLocal;
                }

                const DefinedKey key{va, sectionIndex, name};
                auto existingIt = definedRows.find(key);
                if (existingIt != definedRows.end()) {
                    Export& existing = exports_[existingIt->second];
                    existing.dynamicSymbol = existing.dynamicSymbol || dynamic;
                    existing.size = std::max(existing.size, symbolSize);
                    existing.mapped = existing.mapped || mapped;
                    existing.isCode = existing.isCode || code;
                    if (existing.kind == SymbolKind::Unknown) existing.kind = kind;
                    if (existing.binding == SymbolBinding::Local && binding != SymbolBinding::Local)
                        existing.binding = binding;
                    if (symbolVersion && existing.elfVersion.empty()) {
                        existing.elfVersionIndex = symbolVersion->index;
                        existing.elfVersionHidden = symbolVersion->hidden;
                        existing.elfVersionDefined = symbolVersion->definition;
                        if (symbolVersion->name.size() <= kMaxStoredSymbolBytes - storedBytes) {
                            existing.elfVersion = symbolVersion->name;
                            storedBytes += existing.elfVersion.size();
                        }
                    }
                    continue;
                }
                if (exports_.size() >= kMaxSymbolRows ||
                    name.size() > kMaxStoredSymbolBytes - storedBytes) continue;
                Export symbol;
                symbol.ordinal = symbolIndex;
                symbol.rva = va;
                symbol.va = va;
                symbol.size = symbolSize;
                symbol.name.assign(name.data(), name.size());
                symbol.mapped = mapped;
                symbol.isCode = code;
                symbol.kind = kind;
                symbol.binding = binding;
                symbol.visibility = visibility;
                symbol.elfSymbol = true;
                symbol.dynamicSymbol = dynamic;
                if (symbolVersion) {
                    symbol.elfVersionIndex = symbolVersion->index;
                    symbol.elfVersionHidden = symbolVersion->hidden;
                    symbol.elfVersionDefined = symbolVersion->definition;
                    if (symbolVersion->name.size() <=
                        kMaxStoredSymbolBytes - storedBytes - name.size()) {
                        symbol.elfVersion = symbolVersion->name;
                        storedBytes += symbol.elfVersion.size();
                    }
                }
                exports_.push_back(std::move(symbol));
                definedRows.emplace(key, exports_.size() - 1);
                storedBytes += name.size();
            }
            if (parsedEntries >= kMaxSymbolEntries) break;
        }
        if (parsedEntries >= kMaxSymbolEntries) break;
    }

    struct RelocationSymbolInfo {
        uint64_t value = 0;
        std::string_view name;
        bool defined = false;
    };
    auto relocationSymbol = [&](uint32_t tableIndex, uint32_t symbolIndex,
                                RelocationSymbolInfo& out) {
        if (tableIndex >= headers.size()) return false;
        const ElfSectionHeader& table = headers[tableIndex];
        if ((table.type != SHT_SYMTAB && table.type != SHT_DYNSYM) ||
            table.link >= headers.size()) return false;
        const uint64_t exactEntrySize = elf64 ? 24u : 16u;
        if (table.entrySize < exactEntrySize || table.offset > data_.size()) return false;
        const uint64_t count = std::min(table.size / table.entrySize,
                                        (data_.size() - table.offset) / table.entrySize);
        if (symbolIndex >= count) return false;
        const uint8_t* raw = sectionData(table,
            static_cast<uint64_t>(symbolIndex) * table.entrySize,
            static_cast<size_t>(exactEntrySize));
        if (!raw) return false;
        const size_t base = static_cast<size_t>(raw - data_.data());
        const uint32_t nameOffset = rdOrder<uint32_t>(data_, base, bigEndian_);
        uint64_t value = 0;
        uint16_t section16 = 0;
        if (elf64) {
            section16 = rdOrder<uint16_t>(data_, base + 6, bigEndian_);
            value = rdOrder<uint64_t>(data_, base + 8, bigEndian_);
        } else {
            value = rdOrder<uint32_t>(data_, base + 4, bigEndian_);
            section16 = rdOrder<uint16_t>(data_, base + 14, bigEndian_);
        }
        uint32_t ownerIndex = section16;
        if (section16 == SHN_XINDEX) {
            if (extendedIndexSection[tableIndex] < 0) return false;
            const ElfSectionHeader& ext = headers[static_cast<size_t>(extendedIndexSection[tableIndex])];
            const uint64_t extOffset = static_cast<uint64_t>(symbolIndex) * sizeof(uint32_t);
            const uint8_t* extRaw = sectionData(ext, extOffset, sizeof(uint32_t));
            if (!extRaw) return false;
            ownerIndex = rdOrder<uint32_t>(data_,
                static_cast<size_t>(extRaw - data_.data()), bigEndian_);
        }
        out.name = symbolName(table.link, nameOffset);
        out.defined = ownerIndex != SHN_UNDEF;
        out.value = value;
        if (out.defined && elfType == 1 /*ET_REL*/ && ownerIndex < headers.size()) {
            if (!analysisAddressValid[ownerIndex] ||
                value > std::numeric_limits<uint64_t>::max() - analysisAddress[ownerIndex])
                return false;
            out.value = analysisAddress[ownerIndex] + value;
        }
        return true;
    };

    auto classifyTargetVA = [&](uint64_t va, bool& mapped) {
        mapped = false;
        for (size_t i = 0; i < headers.size(); ++i) {
            const ElfSectionHeader& owner = headers[i];
            if (!(owner.flags & SHF_ALLOC) || !analysisAddressValid[i] ||
                va < analysisAddress[i]) continue;
            const uint64_t delta = va - analysisAddress[i];
            if (delta >= owner.size) continue;
            mapped = owner.type != SHT_NOBITS && fileBacked(owner) &&
                     delta < data_.size() - owner.offset;
            return true;
        }
        return false;
    };

    constexpr size_t kMaxRelocationTables = 4096;
    constexpr size_t kMaxRelocationEntries = 500000;
    constexpr size_t kMaxRelocationNameBytes = 16 * 1024 * 1024;
    size_t relocationEntries = 0;
    size_t relocationNameBytes = 0;
    for (size_t sectionIndex = 0; sectionIndex < headers.size(); ++sectionIndex) {
        const ElfSectionHeader& table = headers[sectionIndex];
        if (table.type != SHT_REL && table.type != SHT_RELA) continue;
        if (elfRelocationTables_.size() >= kMaxRelocationTables) {
            elfRelocationsTruncated_ = true;
            break;
        }
        ElfRelocationTable result;
        result.sectionIndex = static_cast<uint32_t>(sectionIndex);
        result.targetSectionIndex = table.info;
        result.symbolTableSectionIndex = table.link;
        result.hasAddends = table.type == SHT_RELA;
        const std::string_view tableName = sectionName(sectionIndex);
        result.name.assign(tableName.data(), tableName.size());
        const uint64_t exactEntrySize = elf64
            ? (result.hasAddends ? 24u : 16u)
            : (result.hasAddends ? 12u : 8u);
        const bool symbolTableValid = table.link < headers.size() &&
            (headers[table.link].type == SHT_SYMTAB || headers[table.link].type == SHT_DYNSYM);
        const bool targetSectionValid = elfType != 1 /*ET_REL*/ ||
            (table.info < headers.size() && analysisAddressValid[table.info] &&
             (headers[table.info].flags & SHF_ALLOC) != 0);
        result.valid = symbolTableValid && targetSectionValid &&
                       table.entrySize >= exactEntrySize && table.offset <= data_.size();
        if (!result.valid) {
            result.truncated = true;
            result.complete = false;
            elfRelocationsTruncated_ = true;
            elfRelocationTables_.push_back(std::move(result));
            continue;
        }
        result.declaredEntries = table.size / table.entrySize;
        const uint64_t fileFit = (data_.size() - table.offset) / table.entrySize;
        const uint64_t budget = relocationEntries < kMaxRelocationEntries
                              ? kMaxRelocationEntries - relocationEntries : 0;
        const uint64_t count = std::min({result.declaredEntries, fileFit, budget});
        result.entries.reserve(static_cast<size_t>(std::min<uint64_t>(count, 65536)));
        for (uint64_t index = 0; index < count; ++index) {
            const uint8_t* raw = sectionData(table, index * table.entrySize,
                                             static_cast<size_t>(exactEntrySize));
            if (!raw) break;
            ++relocationEntries;
            const size_t base = static_cast<size_t>(raw - data_.data());
            ElfRelocation relocation;
            uint64_t info = 0;
            if (elf64) {
                relocation.offset = rdOrder<uint64_t>(data_, base, bigEndian_);
                info = rdOrder<uint64_t>(data_, base + 8, bigEndian_);
                if (result.hasAddends)
                    relocation.addend = static_cast<int64_t>(
                        rdOrder<uint64_t>(data_, base + 16, bigEndian_));
                relocation.symbolIndex = static_cast<uint32_t>(info >> 32);
                relocation.type = static_cast<uint32_t>(info);
            } else {
                relocation.offset = rdOrder<uint32_t>(data_, base, bigEndian_);
                info = rdOrder<uint32_t>(data_, base + 4, bigEndian_);
                if (result.hasAddends)
                    relocation.addend = static_cast<int32_t>(
                        rdOrder<uint32_t>(data_, base + 8, bigEndian_));
                relocation.symbolIndex = static_cast<uint32_t>(info >> 8);
                relocation.type = static_cast<uint32_t>(info & 0xffu);
            }
            relocation.hasAddend = result.hasAddends;
            if (elfType == 1 /*ET_REL*/) {
                const ElfSectionHeader& owner = headers[table.info];
                if (relocation.offset < owner.size && relocation.offset <=
                    std::numeric_limits<uint64_t>::max() - analysisAddress[table.info]) {
                    relocation.targetVA = analysisAddress[table.info] + relocation.offset;
                    relocation.targetValid = true;
                    relocation.targetMapped = owner.type != SHT_NOBITS && fileBacked(owner) &&
                                              relocation.offset < data_.size() - owner.offset;
                }
            } else {
                relocation.targetVA = relocation.offset;
                relocation.targetValid = classifyTargetVA(relocation.targetVA,
                                                          relocation.targetMapped);
            }
            RelocationSymbolInfo symbol;
            if (relocationSymbol(table.link, relocation.symbolIndex, symbol)) {
                relocation.symbolValid = true;
                relocation.symbolDefined = symbol.defined;
                relocation.symbolValue = symbol.value;
                if (!symbol.name.empty() &&
                    symbol.name.size() <= kMaxRelocationNameBytes - relocationNameBytes) {
                    relocation.symbolName.assign(symbol.name.data(), symbol.name.size());
                    relocationNameBytes += symbol.name.size();
                } else if (!symbol.name.empty()) {
                    elfRelocationsTruncated_ = true;
                }
            }
            relocation.pltRelated = result.name.find(".plt") != std::string::npos;
            result.entries.push_back(std::move(relocation));
        }
        result.parsedEntries = result.entries.size();
        result.complete = table.size % table.entrySize == 0 &&
                          result.parsedEntries == result.declaredEntries &&
                          result.declaredEntries <= fileFit;
        result.truncated = !result.complete;
        elfRelocationsTruncated_ = elfRelocationsTruncated_ || result.truncated;
        elfRelocationTables_.push_back(std::move(result));
    }

    // Identify conventional PLT/GOT sections by their ABI names. GOT slot size
    // is inferable from ELF class when sh_entsize is absent; a PLT with no
    // sh_entsize is retained as a section but not guessed into arbitrary slots.
    constexpr size_t kMaxLinkageSections = 128;
    constexpr size_t kMaxLinkageSlots = 200000;
    size_t linkageSlotCount = 0;
    for (size_t sectionIndex = 0; sectionIndex < headers.size(); ++sectionIndex) {
        const std::string_view name = sectionName(sectionIndex);
        bool recognized = false;
        ElfLinkageKind kind = ElfLinkageKind::Plt;
        if (name == ".got.plt") { recognized = true; kind = ElfLinkageKind::GotPlt; }
        else if (name == ".got") { recognized = true; kind = ElfLinkageKind::Got; }
        else if (name == ".plt" || name == ".plt.sec" || name == ".plt.got" ||
                 name == ".iplt") { recognized = true; kind = ElfLinkageKind::Plt; }
        if (!recognized) continue;
        if (elfLinkageSections_.size() >= kMaxLinkageSections) {
            elfLinkageTruncated_ = true;
            break;
        }
        const ElfSectionHeader& sh = headers[sectionIndex];
        ElfLinkageSection linkage;
        linkage.sectionIndex = static_cast<uint32_t>(sectionIndex);
        linkage.name.assign(name.data(), name.size());
        linkage.kind = kind;
        linkage.size = sh.size;
        linkage.addressValid = analysisAddressValid[sectionIndex] && (sh.flags & SHF_ALLOC) != 0;
        if (linkage.addressValid) linkage.address = analysisAddress[sectionIndex];
        linkage.mapped = sh.type != SHT_NOBITS && fileBacked(sh);
        linkage.entrySize = sh.entrySize;
        if (!linkage.entrySize && kind != ElfLinkageKind::Plt)
            linkage.entrySize = elf64 ? 8u : 4u;
        if (linkage.entrySize) {
            const uint64_t declared = sh.size / linkage.entrySize;
            const uint64_t budget = linkageSlotCount < kMaxLinkageSlots
                                  ? kMaxLinkageSlots - linkageSlotCount : 0;
            const uint64_t count = std::min(declared, budget);
            for (uint64_t index = 0; index < count; ++index) {
                ElfLinkageSlot slot;
                const uint64_t delta = index * linkage.entrySize;
                slot.addressValid = linkage.addressValid &&
                    delta <= std::numeric_limits<uint64_t>::max() - linkage.address;
                if (slot.addressValid) slot.address = linkage.address + delta;
                slot.mapped = slot.addressValid && linkage.mapped && delta < sh.size &&
                              delta < data_.size() - sh.offset;
                linkage.slots.push_back(std::move(slot));
                ++linkageSlotCount;
            }
            linkage.complete = sh.size % linkage.entrySize == 0 && count == declared;
            linkage.truncated = !linkage.complete;
            elfLinkageTruncated_ = elfLinkageTruncated_ || linkage.truncated;
        }
        elfLinkageSections_.push_back(std::move(linkage));
    }

    // Exact relocation targets associate naturally with GOT slots. PLT slots do
    // not contain the relocation target, but a .rel[a].plt table has a stable
    // one-to-one ABI order when the slot counts match (optionally after one
    // reserved PLT entry), which is the only ordinal inference made here.
    std::unordered_map<uint64_t, std::pair<uint32_t, uint32_t>> relocationAt;
    for (uint32_t tableIndex = 0; tableIndex < elfRelocationTables_.size(); ++tableIndex) {
        auto& table = elfRelocationTables_[tableIndex];
        for (uint32_t entryIndex = 0; entryIndex < table.entries.size(); ++entryIndex) {
            auto& relocation = table.entries[entryIndex];
            if (relocation.targetValid)
                relocationAt.try_emplace(relocation.targetVA,
                                         std::make_pair(tableIndex, entryIndex));
        }
    }
    for (auto& linkage : elfLinkageSections_) {
        for (auto& slot : linkage.slots) {
            if (!slot.addressValid) continue;
            if (auto it = relocationAt.find(slot.address); it != relocationAt.end()) {
                slot.relocationValid = true;
                slot.relocationTableIndex = it->second.first;
                slot.relocationEntryIndex = it->second.second;
                if (linkage.kind != ElfLinkageKind::Plt)
                    elfRelocationTables_[it->second.first].entries[it->second.second].gotRelated = true;
            }
        }
        if (linkage.kind != ElfLinkageKind::Plt || linkage.slots.empty()) continue;
        for (uint32_t tableIndex = 0; tableIndex < elfRelocationTables_.size(); ++tableIndex) {
            auto& table = elfRelocationTables_[tableIndex];
            if (!table.valid || !table.complete ||
                table.name.find(".plt") == std::string::npos || table.entries.empty()) continue;
            size_t firstSlot = 0;
            if (linkage.slots.size() == table.entries.size() + 1) firstSlot = 1;
            else if (linkage.slots.size() != table.entries.size()) continue;
            for (size_t i = 0; i < table.entries.size(); ++i) {
                auto& slot = linkage.slots[firstSlot + i];
                if (!slot.relocationValid) {
                    slot.relocationValid = true;
                    slot.relocationTableIndex = tableIndex;
                    slot.relocationEntryIndex = static_cast<uint32_t>(i);
                }
                table.entries[i].pltRelated = true;
            }
            break;
        }
    }

    constexpr size_t kMaxInitializerEntries = 65536;
    const uint64_t pointerSize = elf64 ? 8u : 4u;
    struct InitializerSlotKey {
        ElfInitializerKind kind = ElfInitializerKind::Init;
        uint64_t slot = 0;
        bool operator==(const InitializerSlotKey&) const = default;
    };
    struct InitializerSlotHash {
        size_t operator()(const InitializerSlotKey& key) const noexcept {
            size_t hash = std::hash<uint64_t>{}(key.slot);
            hash ^= static_cast<size_t>(key.kind) + static_cast<size_t>(0x9e3779b9u) +
                    (hash << 6) + (hash >> 2);
            return hash;
        }
    };
    std::unordered_set<InitializerSlotKey, InitializerSlotHash> initializerSlots;
    std::unordered_set<InitializerSlotKey, InitializerSlotHash> initializerTargets;
    for (const auto& initializer : elfInitializers_.entries)
        if (initializer.addressValid)
            initializerTargets.insert(InitializerSlotKey{initializer.kind, initializer.address});
    for (size_t sectionIndex = 0; sectionIndex < headers.size(); ++sectionIndex) {
        const std::string_view name = sectionName(sectionIndex);
        ElfInitializerKind kind{};
        if (name == ".init") kind = ElfInitializerKind::Init;
        else if (name == ".fini") kind = ElfInitializerKind::Fini;
        else continue;
        const ElfSectionHeader& section = headers[sectionIndex];
        const bool addressValid = analysisAddressValid[sectionIndex] &&
                                  (section.flags & SHF_ALLOC) != 0;
        const uint64_t address = addressValid ? analysisAddress[sectionIndex] : 0;
        if (addressValid && initializerTargets.contains(InitializerSlotKey{kind, address}))
            continue;
        if (elfInitializers_.entries.size() >= kMaxInitializerEntries) {
            elfInitializers_.truncated = true;
            break;
        }
        ElfInitializer initializer;
        initializer.kind = kind;
        initializer.address = address;
        initializer.addressValid = addressValid;
        initializer.addressMapped = addressValid && section.type != SHT_NOBITS &&
                                    fileBacked(section) && section.size != 0;
        initializer.sectionIndex = static_cast<uint32_t>(sectionIndex);
        initializer.requiresRelocation = false;
        elfInitializers_.entries.push_back(std::move(initializer));
    }
    for (size_t sectionIndex = 0; sectionIndex < headers.size(); ++sectionIndex) {
        const ElfSectionHeader& table = headers[sectionIndex];
        ElfInitializerKind kind{};
        if (table.type == SHT_PREINIT_ARRAY) kind = ElfInitializerKind::PreinitArray;
        else if (table.type == SHT_INIT_ARRAY) kind = ElfInitializerKind::InitArray;
        else if (table.type == SHT_FINI_ARRAY) kind = ElfInitializerKind::FiniArray;
        else continue;
        const uint64_t stride = table.entrySize ? table.entrySize : pointerSize;
        if (stride < pointerSize || table.offset > data_.size()) {
            elfInitializers_.truncated = true;
            continue;
        }
        const uint64_t declared = table.size / stride;
        const uint64_t fileFit = (data_.size() - table.offset) / stride;
        const uint64_t budget = elfInitializers_.entries.size() < kMaxInitializerEntries
                              ? kMaxInitializerEntries - elfInitializers_.entries.size() : 0;
        const uint64_t count = std::min({declared, fileFit, budget});
        for (uint64_t index = 0; index < count; ++index) {
            const uint8_t* raw = sectionData(table, index * stride,
                                             static_cast<size_t>(pointerSize));
            if (!raw) break;
            const size_t base = static_cast<size_t>(raw - data_.data());
            const uint64_t address = elf64
                ? rdOrder<uint64_t>(data_, base, bigEndian_)
                : rdOrder<uint32_t>(data_, base, bigEndian_);
            ElfInitializer initializer;
            initializer.kind = kind;
            initializer.address = address;
            initializer.addressValid = true;
            size_t addressAvail = 0;
            initializer.addressMapped = initializer.addressValid &&
                ptrFromVA(address, addressAvail) != nullptr && addressAvail != 0;
            initializer.sectionIndex = static_cast<uint32_t>(sectionIndex);
            initializer.requiresRelocation = elfType == 1 /*ET_REL*/;
            const uint64_t delta = index * stride;
            initializer.slotValid = analysisAddressValid[sectionIndex] &&
                delta <= std::numeric_limits<uint64_t>::max() - analysisAddress[sectionIndex];
            if (initializer.slotValid) initializer.slotVA = analysisAddress[sectionIndex] + delta;
            initializer.slotMapped = initializer.slotValid && fileBacked(table) &&
                                     delta < data_.size() - table.offset;
            if (initializer.slotValid)
                initializerSlots.insert(InitializerSlotKey{kind, initializer.slotVA});
            elfInitializers_.entries.push_back(std::move(initializer));
        }
        if (table.size % stride != 0 || count < declared)
            elfInitializers_.truncated = true;
    }

    auto parseDynamicArray = [&](const DynamicArraySpec& spec) {
        if (!spec.addressPresent) return;
        if (!spec.sizePresent || spec.size % pointerSize != 0) {
            elfInitializers_.truncated = true;
            return;
        }
        size_t available = 0;
        const uint8_t* bytes = ptrFromVA(spec.address, available);
        if (!bytes && spec.size) {
            elfInitializers_.truncated = true;
            return;
        }
        const uint64_t declared = spec.size / pointerSize;
        const uint64_t fileFit = std::min<uint64_t>(declared, available / pointerSize);
        const uint64_t budget = elfInitializers_.entries.size() < kMaxInitializerEntries
                              ? kMaxInitializerEntries - elfInitializers_.entries.size() : 0;
        const uint64_t count = std::min(fileFit, budget);
        for (uint64_t index = 0; index < count; ++index) {
            uint64_t slotVA = 0;
            const uint64_t delta = index * pointerSize;
            if (delta > std::numeric_limits<uint64_t>::max() - spec.address) {
                elfInitializers_.truncated = true;
                break;
            }
            slotVA = spec.address + delta;
            if (initializerSlots.contains(InitializerSlotKey{spec.kind, slotVA})) continue;
            const size_t fileOffset = static_cast<size_t>(bytes - data_.data()) +
                                      static_cast<size_t>(delta);
            const uint64_t address = elf64
                ? rdOrder<uint64_t>(data_, fileOffset, bigEndian_)
                : rdOrder<uint32_t>(data_, fileOffset, bigEndian_);
            ElfInitializer initializer;
            initializer.kind = spec.kind;
            initializer.address = address;
            initializer.addressValid = true;
            size_t addressAvail = 0;
            initializer.addressMapped = initializer.addressValid &&
                ptrFromVA(address, addressAvail) != nullptr && addressAvail != 0;
            initializer.slotVA = slotVA;
            initializer.slotValid = true;
            initializer.slotMapped = true;
            initializer.fromDynamic = true;
            elfInitializers_.entries.push_back(std::move(initializer));
        }
        if (count < declared) elfInitializers_.truncated = true;
    };
    parseDynamicArray(dynamicPreinit);
    parseDynamicArray(dynamicInit);
    parseDynamicArray(dynamicFini);

    return acceptMappedElf();
}

// ------------------------------------------------------------------ Mach-O --
// Thin and universal Mach-O (32/64, either byte order). Like ELF, imageBase_
// stays zero and sections carry absolute VM addresses. All link-edit walks are
// capped and remain inside the selected slice; section raw offsets are rebased
// to the outer file so the existing VA<->offset helpers also work for fat files.
bool BinaryFile::parseMachO() {
    constexpr size_t   kMaxFatSlices = 256;
    constexpr uint32_t kMaxLoadCommands = 4096;
    constexpr size_t   kMaxSections = 65536;
    constexpr uint64_t kMaxSymbolEntries = 262144;
    constexpr size_t   kMaxStoredSymbols = 65536;
    constexpr size_t   kMaxString = 4096;
    constexpr size_t   kMaxStoredStringBytes = 8u * 1024u * 1024u;
    constexpr size_t   kMaxBindings = 65536;
    constexpr uint64_t kMaxBindOperations = 1u << 20;
    constexpr size_t   kMaxTrieNodes = 65536;
    constexpr size_t   kMaxTrieDepth = 256;
    constexpr size_t   kMaxTrieExports = 65536;
    constexpr size_t   kMaxFunctionStarts = 1u << 20;
    constexpr size_t   kMaxInitializers = 65536;

    constexpr uint32_t LC_SEGMENT = 0x01;
    constexpr uint32_t LC_SYMTAB = 0x02;
    constexpr uint32_t LC_LOAD_DYLIB = 0x0c;
    constexpr uint32_t LC_ROUTINES = 0x11;
    constexpr uint32_t LC_SEGMENT_64 = 0x19;
    constexpr uint32_t LC_ROUTINES_64 = 0x1a;
    constexpr uint32_t LC_LAZY_LOAD_DYLIB = 0x20;
    constexpr uint32_t LC_LOAD_WEAK_DYLIB = 0x80000018u;
    constexpr uint32_t LC_REEXPORT_DYLIB = 0x8000001fu;
    constexpr uint32_t LC_DYLD_INFO = 0x22;
    constexpr uint32_t LC_DYLD_INFO_ONLY = 0x80000022u;
    constexpr uint32_t LC_LOAD_UPWARD_DYLIB = 0x80000023u;
    constexpr uint32_t LC_FUNCTION_STARTS = 0x26;
    constexpr uint32_t LC_MAIN = 0x80000028u;
    constexpr uint32_t LC_DYLD_EXPORTS_TRIE = 0x80000033u;

    if (data_.size() < 8) return false;
    machO_ = {};

    auto inFile = [&](uint64_t off, uint64_t size) {
        return off <= data_.size() && size <= static_cast<uint64_t>(data_.size()) - off;
    };
    auto u16 = [&](uint64_t off, bool big) -> uint16_t {
        if (!inFile(off, 2)) return 0;
        const uint8_t* p = data_.data() + static_cast<size_t>(off);
        return big ? static_cast<uint16_t>((uint16_t(p[0]) << 8) | p[1])
                   : static_cast<uint16_t>((uint16_t(p[1]) << 8) | p[0]);
    };
    auto u32 = [&](uint64_t off, bool big) -> uint32_t {
        if (!inFile(off, 4)) return 0;
        const uint8_t* p = data_.data() + static_cast<size_t>(off);
        if (big) return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
                        (uint32_t(p[2]) << 8) | uint32_t(p[3]);
        return (uint32_t(p[3]) << 24) | (uint32_t(p[2]) << 16) |
               (uint32_t(p[1]) << 8) | uint32_t(p[0]);
    };
    auto u64 = [&](uint64_t off, bool big) -> uint64_t {
        if (!inFile(off, 8)) return 0;
        if (big) return (uint64_t(u32(off, true)) << 32) | u32(off + 4, true);
        return (uint64_t(u32(off + 4, false)) << 32) | u32(off, false);
    };
    auto thinMagic = [&](uint32_t raw, bool& out64, bool& outBig) {
        switch (raw) {
            case 0xFEEDFACEu: out64 = false; outBig = false; return true;
            case 0xFEEDFACFu: out64 = true;  outBig = false; return true;
            case 0xCEFAEDFEu: out64 = false; outBig = true;  return true;
            case 0xCFFAEDFEu: out64 = true;  outBig = true;  return true;
            default: return false;
        }
    };
    auto machineForCpu = [](uint32_t cpu) {
        switch (cpu) {
            case 0x00000007u: return MachineArch::X86;
            case 0x01000007u: return MachineArch::X64;
            case 0x0000000cu: return MachineArch::ARM;
            case 0x0100000cu: return MachineArch::ARM64;
            case 0x00000012u: return MachineArch::PPC;
            case 0x01000012u: return MachineArch::PPC64;
            default: return MachineArch::Unknown;
        }
    };
    auto cpuRank = [](uint32_t cpu) {
        switch (cpu) {
            case 0x01000007u: return 0; // fixed, host-independent preference
            case 0x0100000cu: return 1;
            case 0x00000007u: return 2;
            case 0x0000000cu: return 3;
            case 0x01000012u: return 4;
            case 0x00000012u: return 5;
            default: return 100;
        }
    };
    auto cpuWidthMatches = [](uint32_t cpu, bool is64) {
        const bool cpu64 = (cpu & 0x01000000u) != 0;
        return cpu64 == is64;
    };

    const uint32_t outerMagic = rd<uint32_t>(data_, 0);
    bool selected64 = false, selectedBig = false;
    uint64_t sliceBase = 0, sliceSize = data_.size();
    uint32_t selectedCpu = 0, selectedSubtype = 0;
    const bool fat = outerMagic == 0xBEBAFECAu || outerMagic == 0xBFBAFECAu ||
                     outerMagic == 0xCAFEBABEu || outerMagic == 0xCAFEBABFu;

    if (fat) {
        const bool fatBig = outerMagic == 0xBEBAFECAu || outerMagic == 0xBFBAFECAu;
        const bool fat64 = outerMagic == 0xBFBAFECAu || outerMagic == 0xCAFEBABFu;
        machO_.universal = true;
        machO_.fat64 = fat64;
        machO_.containerBigEndian = fatBig;
        const uint32_t declared = u32(4, fatBig);
        if (!declared) return false;
        const uint64_t stride = fat64 ? 32u : 20u;
        const uint32_t inspect = static_cast<uint32_t>(std::min<size_t>(declared, kMaxFatSlices));
        if (declared > kMaxFatSlices) machO_.slicesTruncated = true;
        int bestRank = 100;
        int32_t best = -1;
        for (uint32_t i = 0; i < inspect; ++i) {
            const uint64_t row = 8u + uint64_t(i) * stride;
            if (!inFile(row, stride)) { machO_.slicesTruncated = true; break; }
            MachOSlice slice;
            slice.cpuType = u32(row, fatBig);
            slice.cpuSubtype = u32(row + 4, fatBig);
            slice.fileOffset = fat64 ? u64(row + 8, fatBig) : u32(row + 8, fatBig);
            slice.fileSize = fat64 ? u64(row + 16, fatBig) : u32(row + 12, fatBig);
            slice.alignExponent = fat64 ? u32(row + 24, fatBig) : u32(row + 16, fatBig);
            bool inner64 = false, innerBig = false;
            const bool aligned = slice.alignExponent < 64 &&
                ((slice.fileOffset & ((uint64_t{1} << slice.alignExponent) - 1u)) == 0);
            const uint32_t innerMagic = inFile(slice.fileOffset, 4)
                                      ? rd<uint32_t>(data_, static_cast<size_t>(slice.fileOffset)) : 0;
            const bool magicOk = thinMagic(innerMagic, inner64, innerBig);
            const uint64_t minHeader = inner64 ? 32u : 28u;
            slice.structurallyValid = aligned && magicOk && slice.fileSize >= minHeader &&
                                      inFile(slice.fileOffset, slice.fileSize) &&
                                      u32(slice.fileOffset + 4, innerBig) == slice.cpuType &&
                                      cpuWidthMatches(slice.cpuType, inner64);
            slice.is64Bit = inner64;
            slice.bigEndian = innerBig;
            slice.supported = slice.structurallyValid && cpuRank(slice.cpuType) < 100;
            const int rank = cpuRank(slice.cpuType);
            machO_.slices.push_back(slice);
            if (slice.supported && rank < bestRank) {
                bestRank = rank;
                best = static_cast<int32_t>(machO_.slices.size() - 1);
            }
        }
        if (best < 0) return false;
        machO_.selectedSlice = best;
        MachOSlice& selected = machO_.slices[static_cast<size_t>(best)];
        selected.selected = true;
        sliceBase = selected.fileOffset;
        sliceSize = selected.fileSize;
        selected64 = selected.is64Bit;
        selectedBig = selected.bigEndian;
        selectedCpu = selected.cpuType;
        selectedSubtype = selected.cpuSubtype;
    } else {
        if (!thinMagic(outerMagic, selected64, selectedBig)) return false;
        const uint64_t minHeader = selected64 ? 32u : 28u;
        if (data_.size() < minHeader) return false;
        selectedCpu = u32(4, selectedBig);
        selectedSubtype = u32(8, selectedBig);
        MachOSlice slice;
        slice.cpuType = selectedCpu;
        slice.cpuSubtype = selectedSubtype;
        slice.fileSize = data_.size();
        slice.is64Bit = selected64;
        slice.bigEndian = selectedBig;
        slice.structurallyValid = cpuWidthMatches(selectedCpu, selected64);
        slice.supported = slice.structurallyValid && cpuRank(selectedCpu) < 100;
        // Fat images already select only supported slices. Apply the same rule
        // to thin files instead of silently treating any unknown 32/64-bit CPU
        // as x86/x64 and producing authoritative-looking wrong disassembly.
        if (!slice.supported) return false;
        slice.selected = true;
        machO_.slices.push_back(slice);
        machO_.selectedSlice = 0;
    }

    if (!inFile(sliceBase, sliceSize)) return false;
    const uint64_t sliceEnd = sliceBase + sliceSize;
    const uint64_t headerSize = selected64 ? 32u : 28u;
    if (sliceSize < headerSize) return false;

    is64_ = selected64;
    bigEndian_ = selectedBig;
    format_ = BinFormat::MachO;
    imageBase_ = 0;
    machine_ = machineForCpu(selectedCpu);
    if (machine_ == MachineArch::Unknown) {
        loadError_ = BinaryLoadError::UnsupportedMachine;
        return false;
    }
    sections_.clear();
    exports_.clear();
    imports_.clear();

    auto inSlice = [&](uint64_t off, uint64_t size) {
        return off >= sliceBase && off <= sliceEnd && size <= sliceEnd - off;
    };
    auto relativeRange = [&](uint64_t rel, uint64_t size, uint64_t& absolute) {
        if (rel > sliceSize || size > sliceSize - rel) return false;
        absolute = sliceBase + rel;
        return true;
    };
    auto readCString = [&](uint64_t at, uint64_t end, std::string& out) {
        out.clear();
        if (at >= end || !inFile(at, 1)) return false;
        const uint64_t available = end - at;
        const size_t inspect = static_cast<size_t>(std::min<uint64_t>(available, kMaxString + 1u));
        size_t len = 0;
        while (len < inspect && data_[static_cast<size_t>(at) + len] != 0) ++len;
        if (len == inspect || len > kMaxString) return false;
        out.assign(reinterpret_cast<const char*>(data_.data() + static_cast<size_t>(at)), len);
        return true;
    };
    auto readULEB = [&](uint64_t& pos, uint64_t end, uint64_t& value) {
        value = 0;
        for (unsigned i = 0, shift = 0; i < 10; ++i, shift += 7) {
            if (pos >= end) return false;
            const uint8_t byte = data_[static_cast<size_t>(pos++)];
            const uint64_t payload = byte & 0x7fu;
            if (i == 9 && payload > 1) return false;
            value |= payload << shift;
            if ((byte & 0x80u) == 0) return true;
        }
        return false;
    };
    auto readSLEB = [&](uint64_t& pos, uint64_t end, int64_t& value) {
        uint64_t result = 0;
        unsigned shift = 0;
        for (unsigned i = 0; i < 10; ++i, shift += 7) {
            if (pos >= end) return false;
            const uint8_t byte = data_[static_cast<size_t>(pos++)];
            const uint64_t payload = byte & 0x7fu;
            if (i == 9 && payload != 0 && payload != 0x7f) return false;
            result |= payload << shift;
            if ((byte & 0x80u) == 0) {
                const unsigned used = shift + 7;
                if (used < 64 && (byte & 0x40u)) result |= (~uint64_t{0}) << used;
                value = static_cast<int64_t>(result);
                return true;
            }
        }
        return false;
    };

    struct SegmentMeta {
        std::string name;
        uint64_t vmaddr = 0, vmsize = 0, fileoff = 0, filesize = 0;
        uint32_t initprot = 0;
    };
    struct SectionMeta {
        std::string name;
        uint64_t addr = 0, size = 0, rawOffset = 0, rawBacked = 0;
        uint32_t flags = 0;
        bool executable = false;
    };
    struct BlobRange { uint64_t offset = 0, size = 0; bool valid = false; bool weak = false; bool lazy = false; };
    struct ModInitRange { SectionMeta section; };
    struct RoutineInit { uint64_t address = 0; bool valid = false; };
    std::vector<SegmentMeta> segments;
    std::vector<SectionMeta> sectionOrdinals;
    std::vector<ModInitRange> modInitRanges;
    std::vector<RoutineInit> routineInits;
    std::vector<std::string> dylibs;
    std::vector<BlobRange> bindRanges;
    BlobRange symbolTable, stringTable, exportTrie, functionStarts;
    uint64_t symbolCount = 0;
    bool sawSymtab = false, sawDyldInfo = false, sawExportTrie = false, sawFunctionStarts = false;
    uint64_t textVmaddr = 0, textFileoff = 0;
    bool haveText = false;
    uint64_t preferredBase = 0;
    bool havePreferredBase = false;
    uint64_t entryFileoff = 0;
    bool haveMain = false;

    const uint32_t ncmds = u32(sliceBase + 16, selectedBig);
    const uint32_t sizeofcmds = u32(sliceBase + 20, selectedBig);
    uint64_t lc = sliceBase + headerSize;
    uint64_t commandEnd = sliceEnd;
    bool commandsValid = true;
    bool mappingCommandsValid = true;
    if (sizeofcmds > sliceEnd - lc) {
        commandsValid = false;
        mappingCommandsValid = false;
        machO_.loadCommandsTruncated = true;
    } else {
        commandEnd = lc + sizeofcmds;
    }
    const uint32_t commandLimit = std::min<uint32_t>(ncmds, kMaxLoadCommands);
    if (ncmds > kMaxLoadCommands) {
        commandsValid = false;
        mappingCommandsValid = false;
        machO_.loadCommandsTruncated = true;
    }

    uint32_t parsedCommands = 0;
    for (; parsedCommands < commandLimit; ++parsedCommands) {
        if (!inSlice(lc, 8) || lc + 8 > commandEnd) {
            commandsValid = false;
            mappingCommandsValid = false;
            machO_.loadCommandsTruncated = true;
            break;
        }
        const uint32_t cmd = u32(lc, selectedBig);
        const uint32_t cmdsize = u32(lc + 4, selectedBig);
        if (cmdsize < 8 || (cmdsize & 3u) != 0 || cmdsize > commandEnd - lc) {
            commandsValid = false;
            mappingCommandsValid = false;
            machO_.loadCommandsTruncated = true;
            break;
        }
        const uint64_t lcEnd = lc + cmdsize;

        if (cmd == LC_SEGMENT || cmd == LC_SEGMENT_64) {
            const bool seg64 = cmd == LC_SEGMENT_64;
            const uint64_t segHeader = seg64 ? 72u : 56u;
            if (cmdsize < segHeader) {
                commandsValid = false;
                mappingCommandsValid = false;
            } else {
                char segName[17]{};
                std::memcpy(segName, data_.data() + static_cast<size_t>(lc + 8), 16);
                SegmentMeta segment;
                segment.name = segName;
                segment.vmaddr = seg64 ? u64(lc + 24, selectedBig) : u32(lc + 24, selectedBig);
                segment.vmsize = seg64 ? u64(lc + 32, selectedBig) : u32(lc + 28, selectedBig);
                segment.fileoff = seg64 ? u64(lc + 40, selectedBig) : u32(lc + 32, selectedBig);
                segment.filesize = seg64 ? u64(lc + 48, selectedBig) : u32(lc + 36, selectedBig);
                segment.initprot = seg64 ? u32(lc + 60, selectedBig) : u32(lc + 44, selectedBig);
                const uint32_t nsects = seg64 ? u32(lc + 64, selectedBig) : u32(lc + 48, selectedBig);
                if (segment.fileoff > sliceSize ||
                    segment.filesize > sliceSize - segment.fileoff)
                    mappingCommandsValid = false;
                if (!havePreferredBase && segment.fileoff == 0) {
                    preferredBase = segment.vmaddr;
                    havePreferredBase = true;
                }
                if (!haveText && segment.name == "__TEXT") {
                    textVmaddr = segment.vmaddr;
                    textFileoff = segment.fileoff;
                    haveText = true;
                    preferredBase = segment.vmaddr;
                    havePreferredBase = true;
                }
                segments.push_back(segment);

                const uint64_t stride = seg64 ? 80u : 68u;
                uint64_t sectionAt = lc + segHeader;
                const uint64_t availableRows = sectionAt <= lcEnd ? (lcEnd - sectionAt) / stride : 0;
                uint64_t rows = std::min<uint64_t>(nsects, availableRows);
                if (rows != nsects) {
                    commandsValid = false;
                    mappingCommandsValid = false;
                    machO_.loadCommandsTruncated = true;
                }
                if (sectionOrdinals.size() + rows > kMaxSections) {
                    rows = kMaxSections - sectionOrdinals.size();
                    commandsValid = false;
                    mappingCommandsValid = false;
                    machO_.loadCommandsTruncated = true;
                }
                for (uint64_t i = 0; i < rows; ++i, sectionAt += stride) {
                    char sectName[17]{};
                    char ownerName[17]{};
                    std::memcpy(sectName, data_.data() + static_cast<size_t>(sectionAt), 16);
                    std::memcpy(ownerName, data_.data() + static_cast<size_t>(sectionAt + 16), 16);
                    SectionMeta meta;
                    meta.name = sectName;
                    meta.addr = seg64 ? u64(sectionAt + 32, selectedBig) : u32(sectionAt + 32, selectedBig);
                    meta.size = seg64 ? u64(sectionAt + 40, selectedBig) : u32(sectionAt + 36, selectedBig);
                    const uint64_t fileoff = seg64 ? u32(sectionAt + 48, selectedBig) : u32(sectionAt + 40, selectedBig);
                    meta.flags = seg64 ? u32(sectionAt + 64, selectedBig) : u32(sectionAt + 56, selectedBig);
                    const uint32_t sectionType = meta.flags & 0xffu;
                    const bool zeroFill = sectionType == 1 || sectionType == 0x0c || sectionType == 0x12;
                    const bool virtualInSegment = meta.addr >= segment.vmaddr &&
                        meta.addr - segment.vmaddr <= segment.vmsize &&
                        meta.size <= segment.vmsize - (meta.addr - segment.vmaddr);
                    if (!virtualInSegment) mappingCommandsValid = false;
                    meta.executable = (segment.initprot & 0x4u) != 0 ||
                                      (meta.flags & 0x80000000u) != 0 ||
                                      (meta.flags & 0x400u) != 0 || meta.name == "__text";
                    if (!zeroFill && !(fileoff == 0 && std::strcmp(ownerName, "__TEXT") != 0) && fileoff <= sliceSize) {
                        meta.rawOffset = sliceBase + fileoff;
                        meta.rawBacked = std::min<uint64_t>(meta.size, sliceSize - fileoff);
                        if (meta.rawBacked != meta.size) {
                            mappingCommandsValid = false;
                            machO_.loadCommandsTruncated = true;
                        }
                    } else if (!zeroFill) {
                        mappingCommandsValid = false;
                    }
                    Section section;
                    section.name = meta.name;
                    section.virtualAddress = meta.addr;
                    section.virtualSize = meta.size;
                    section.rawOffset = meta.rawOffset;
                    section.rawSize = meta.rawBacked;
                    section.characteristics = meta.flags;
                    section.executable = meta.executable;
                    sections_.push_back(std::move(section));
                    sectionOrdinals.push_back(meta);
                    if (sectionType == 0x09) modInitRanges.push_back({meta});
                }
            }
        } else if (cmd == LC_MAIN) {
            if (cmdsize < 24) commandsValid = false;
            else { entryFileoff = u64(lc + 8, selectedBig); haveMain = true; }
        } else if (cmd == LC_SYMTAB) {
            if (cmdsize < 24 || sawSymtab) {
                commandsValid = false;
            } else {
                sawSymtab = true;
                symbolCount = u32(lc + 12, selectedBig);
                symbolTable.valid = relativeRange(u32(lc + 8, selectedBig), 0, symbolTable.offset);
                stringTable.size = u32(lc + 20, selectedBig);
                stringTable.valid = relativeRange(u32(lc + 16, selectedBig), stringTable.size, stringTable.offset);
            }
        } else if (cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY) {
            sawDyldInfo = true;
            if (cmdsize < 48) {
                commandsValid = false;
            } else {
                auto addBindRange = [&](uint32_t offRel, uint32_t size, bool weak, bool lazy) {
                    BlobRange b;
                    b.size = size; b.weak = weak; b.lazy = lazy;
                    b.valid = relativeRange(offRel, size, b.offset);
                    if (size) bindRanges.push_back(b);
                };
                addBindRange(u32(lc + 16, selectedBig), u32(lc + 20, selectedBig), false, false);
                addBindRange(u32(lc + 24, selectedBig), u32(lc + 28, selectedBig), true, false);
                addBindRange(u32(lc + 32, selectedBig), u32(lc + 36, selectedBig), false, true);
                if (!sawExportTrie) {
                    exportTrie.size = u32(lc + 44, selectedBig);
                    exportTrie.valid = relativeRange(u32(lc + 40, selectedBig), exportTrie.size, exportTrie.offset);
                    if (exportTrie.size) sawExportTrie = true;
                }
            }
        } else if (cmd == LC_DYLD_EXPORTS_TRIE || cmd == LC_FUNCTION_STARTS) {
            if (cmdsize < 16) {
                commandsValid = false;
            } else {
                BlobRange b;
                b.size = u32(lc + 12, selectedBig);
                b.valid = relativeRange(u32(lc + 8, selectedBig), b.size, b.offset);
                if (cmd == LC_DYLD_EXPORTS_TRIE) {
                    exportTrie = b;
                    sawExportTrie = true;
                } else {
                    functionStarts = b;
                    sawFunctionStarts = true;
                }
            }
        } else if (cmd == LC_ROUTINES || cmd == LC_ROUTINES_64) {
            const bool r64 = cmd == LC_ROUTINES_64;
            const uint64_t need = r64 ? 72u : 40u;
            if (cmdsize < need) commandsValid = false;
            else routineInits.push_back({r64 ? u64(lc + 8, selectedBig) : u32(lc + 8, selectedBig), true});
        } else if (cmd == LC_LOAD_DYLIB || cmd == LC_LOAD_WEAK_DYLIB ||
                   cmd == LC_LAZY_LOAD_DYLIB ||
                   cmd == LC_REEXPORT_DYLIB || cmd == LC_LOAD_UPWARD_DYLIB) {
            std::string name;
            const uint32_t nameOffset = cmdsize >= 24 ? u32(lc + 8, selectedBig) : cmdsize;
            if (nameOffset >= cmdsize || !readCString(lc + nameOffset, lcEnd, name)) commandsValid = false;
            dylibs.push_back(std::move(name)); // retain ordinal even when its spelling is malformed
        }
        lc = lcEnd;
    }
    if (parsedCommands != ncmds || lc != commandEnd) {
        commandsValid = false;
        mappingCommandsValid = false;
        machO_.loadCommandsTruncated = true;
    }
    machO_.loadCommandsValid = commandsValid && mappingCommandsValid;
    // Segment/section declarations are the VA mapping authority for every
    // downstream disassembly and patch operation. An incomplete command frame
    // or section table cannot be accepted as a useful prefix.
    if (!mappingCommandsValid) return false;

    entryRVA_ = 0;
    bool entryValid = false;
    if (haveMain && haveText && entryFileoff >= textFileoff) {
        const uint64_t delta = entryFileoff - textFileoff;
        if (delta <= std::numeric_limits<uint64_t>::max() - textVmaddr) {
            const uint64_t candidate = textVmaddr + delta;
            uint64_t expectedOffset = 0, mappedOffset = 0;
            size_t available = 0;
            bool executable = false;
            for (const Section& section : sections_) {
                if (section.executable && candidate >= section.virtualAddress &&
                    candidate - section.virtualAddress < section.virtualSize) {
                    executable = true;
                    break;
                }
            }
            // LC_MAIN entryoff is a slice-relative file offset. Require it to
            // round-trip to a real, file-backed executable byte; a merely
            // arithmetic __TEXT projection is not loader entry authority.
            if (executable && relativeRange(entryFileoff, 1, expectedOffset) &&
                ptrFromVA(candidate, available) && available &&
                vaToOffset(candidate, mappedOffset) && mappedOffset == expectedOffset) {
                entryRVA_ = candidate;
                entryValid = true;
            }
        }
    }
    entryPointPresent_ = entryValid;

    auto classifyAddress = [&](uint64_t va, bool& mapped, bool& code) {
        mapped = false; code = false;
        size_t available = 0;
        mapped = ptrFromVA(va, available) != nullptr && available != 0;
        for (const Section& section : sections_) {
            if (va >= section.virtualAddress && va - section.virtualAddress < section.virtualSize) {
                code = section.executable;
                break;
            }
        }
    };
    auto libraryName = [&](int32_t ordinal) -> std::string {
        if (ordinal > 0 && static_cast<size_t>(ordinal) <= dylibs.size())
            return dylibs[static_cast<size_t>(ordinal - 1)];
        switch (ordinal) {
            case 0: return "(self)";
            case -1: return "(main executable)";
            case -2: return "(flat lookup)";
            case -3: return "(weak lookup)";
            default: return "(ordinal " + std::to_string(ordinal) + ")";
        }
    };
    std::unordered_set<std::string> normalizedImportKeys;
    std::unordered_set<std::string> normalizedExportKeys;
    auto appendKeyPart = [](std::string& key, const std::string& part) {
        const uint64_t length = part.size();
        key.append(reinterpret_cast<const char*>(&length), sizeof(length));
        key.append(part);
    };
    auto appendImport = [&](uint64_t address, bool addressKnown, const std::string& dll,
                            const std::string& name) {
        if (name.empty()) return;
        std::string key(reinterpret_cast<const char*>(&address), sizeof(address));
        key.push_back(addressKnown ? '\1' : '\0');
        appendKeyPart(key, dll);
        appendKeyPart(key, name);
        if (!normalizedImportKeys.insert(std::move(key)).second) return;
        Import value;
        value.iatVA = address;
        value.addressKnown = addressKnown;
        value.dll = dll;
        value.name = name;
        value.dynamicSymbol = true;
        value.machoSymbol = true;
        imports_.push_back(std::move(value));
    };
    auto appendExport = [&](const std::string& name, uint64_t va, bool mapped, bool code) {
        if (name.empty()) return;
        std::string key(reinterpret_cast<const char*>(&va), sizeof(va));
        appendKeyPart(key, name);
        if (!normalizedExportKeys.insert(std::move(key)).second) return;
        Export value;
        value.ordinal = exports_.size();
        value.rva = va;
        value.va = va;
        value.name = name;
        value.mapped = mapped;
        value.isCode = code;
        value.kind = code ? SymbolKind::Function : SymbolKind::Object;
        value.machoSymbol = true;
        exports_.push_back(std::move(value));
    };

    // LC_SYMTAB / nlist(_64) plus its bounded string table.
    machO_.symbolTablePresent = sawSymtab;
    if (sawSymtab) {
        const uint64_t stride = selected64 ? 16u : 12u;
        uint64_t bytesNeeded = 0;
        const bool countFits = symbolCount <= std::numeric_limits<uint64_t>::max() / stride;
        if (countFits) bytesNeeded = symbolCount * stride;
        symbolTable.size = bytesNeeded;
        symbolTable.valid = symbolTable.valid && countFits && inSlice(symbolTable.offset, bytesNeeded);
        machO_.symbolTableValid = symbolTable.valid && stringTable.valid;
        uint64_t inspect = std::min<uint64_t>(symbolCount, kMaxSymbolEntries);
        if (inspect != symbolCount) machO_.symbolsTruncated = true;
        size_t storedBytes = 0;
        for (uint64_t i = 0; i < inspect && symbolTable.valid && stringTable.valid; ++i) {
            const uint64_t at = symbolTable.offset + i * stride;
            if (!inSlice(at, stride)) {
                machO_.symbolTableValid = false;
                machO_.symbolsTruncated = true;
                break;
            }
            const uint32_t strx = u32(at, selectedBig);
            const uint8_t type = data_[static_cast<size_t>(at + 4)];
            const uint8_t sect = data_[static_cast<size_t>(at + 5)];
            const uint16_t desc = u16(at + 6, selectedBig);
            const uint64_t value = selected64 ? u64(at + 8, selectedBig) : u32(at + 8, selectedBig);
            std::string name;
            if (strx >= stringTable.size ||
                !readCString(stringTable.offset + strx, stringTable.offset + stringTable.size, name)) {
                machO_.symbolTableValid = false;
                continue;
            }
            if (machO_.symbols.size() >= kMaxStoredSymbols ||
                name.size() > kMaxStoredStringBytes - std::min(storedBytes, kMaxStoredStringBytes)) {
                machO_.symbolsTruncated = true;
                continue;
            }
            MachOSymbol symbol;
            symbol.tableIndex = static_cast<uint32_t>(i);
            symbol.value = value;
            symbol.name = name;
            symbol.type = type;
            symbol.sectionIndex = sect;
            symbol.description = desc;
            symbol.external = (type & 0x01u) != 0;
            symbol.debug = (type & 0xe0u) != 0;
            symbol.undefined = !symbol.debug && (type & 0x0eu) == 0;
            if (!symbol.debug && (type & 0x0eu) == 0x0eu &&
                (sect == 0 || sect > sectionOrdinals.size()))
                machO_.symbolTableValid = false;
            classifyAddress(value, symbol.mapped, symbol.isCode);
            machO_.symbols.push_back(symbol);
            storedBytes += name.size();
            if (symbol.debug || name.empty()) continue;
            if (symbol.undefined) {
                const uint8_t ordinal = static_cast<uint8_t>(desc >> 8);
                const int32_t signedOrdinal = ordinal >= 0xfeu
                                            ? static_cast<int8_t>(ordinal)
                                            : static_cast<int32_t>(ordinal);
                appendImport(0, false, libraryName(signedOrdinal), name);
            } else if ((type & 0x0eu) == 0x0eu) {
                appendExport(name, value, symbol.mapped, symbol.isCode);
            }
        }
        if (!symbolTable.valid || !stringTable.valid) {
            machO_.symbolTableValid = false;
            machO_.symbolsTruncated = symbolCount != 0;
        }
    }

    // Classic dyld bind bytecode. Chained fixups use a different load command;
    // an unsupported threaded opcode is surfaced as invalid instead of guessed.
    machO_.bindingsPresent = sawDyldInfo;
    machO_.bindingsValid = sawDyldInfo;
    size_t bindingStoredBytes = 0;
    for (const BlobRange& stream : bindRanges) {
        if (!stream.valid || !inSlice(stream.offset, stream.size)) {
            machO_.bindingsValid = false;
            machO_.bindingsTruncated = true;
            continue;
        }
        uint64_t pos = stream.offset, end = stream.offset + stream.size;
        uint64_t segmentOffset = 0;
        uint32_t segmentIndex = 0;
        int32_t ordinal = 0;
        int64_t addend = 0;
        uint8_t bindType = 1, symbolFlags = 0;
        std::string symbol;
        uint64_t operations = 0;
        bool stopped = false;
        bool cleanStop = false;
        auto advance = [&](uint64_t amount) {
            if (amount > std::numeric_limits<uint64_t>::max() - segmentOffset) return false;
            segmentOffset += amount;
            return true;
        };
        auto emit = [&]() {
            if (machO_.bindings.size() >= kMaxBindings) {
                machO_.bindingsTruncated = true;
                return false;
            }
            MachOBinding binding;
            binding.segmentIndex = segmentIndex;
            binding.segmentOffset = segmentOffset;
            binding.libraryOrdinal = ordinal;
            binding.addend = addend;
            binding.type = bindType;
            binding.symbolFlags = symbolFlags;
            binding.library = libraryName(ordinal);
            binding.symbol = symbol;
            const size_t stringBytes = binding.library.size() + binding.symbol.size();
            if (stringBytes > kMaxStoredStringBytes -
                              std::min(bindingStoredBytes, kMaxStoredStringBytes)) {
                machO_.bindingsTruncated = true;
                return false;
            }
            binding.weak = stream.weak;
            binding.lazy = stream.lazy;
            if (segmentIndex < segments.size() && segmentOffset < segments[segmentIndex].vmsize &&
                segmentOffset <= std::numeric_limits<uint64_t>::max() - segments[segmentIndex].vmaddr) {
                binding.address = segments[segmentIndex].vmaddr + segmentOffset;
                binding.addressValid = true;
                bool code = false;
                classifyAddress(binding.address, binding.mapped, code);
            }
            machO_.bindings.push_back(binding);
            bindingStoredBytes += stringBytes;
            appendImport(binding.address, binding.addressValid, binding.library, binding.symbol);
            return true;
        };
        while (pos < end && operations++ < kMaxBindOperations && !stopped) {
            const uint8_t byte = data_[static_cast<size_t>(pos++)];
            const uint8_t opcode = byte & 0xf0u;
            const uint8_t imm = byte & 0x0fu;
            uint64_t value = 0;
            switch (opcode) {
                case 0x00: // DONE; lazy streams contain multiple DONE-delimited records
                    if (!stream.lazy) { stopped = true; cleanStop = true; }
                    else { symbol.clear(); symbolFlags = 0; addend = 0; ordinal = 0; bindType = 1; }
                    break;
                case 0x10: ordinal = imm; break;
                case 0x20:
                    if (!readULEB(pos, end, value) || value > INT32_MAX) stopped = true;
                    else ordinal = static_cast<int32_t>(value);
                    break;
                case 0x30:
                    ordinal = imm == 0 ? 0 : static_cast<int32_t>(imm | 0xfffffff0u);
                    break;
                case 0x40: {
                    symbolFlags = imm;
                    const uint64_t start = pos;
                    if (!readCString(start, end, symbol)) { stopped = true; break; }
                    pos = start + symbol.size() + 1;
                    break;
                }
                case 0x50: bindType = imm; break;
                case 0x60:
                    if (!readSLEB(pos, end, addend)) stopped = true;
                    break;
                case 0x70:
                    segmentIndex = imm;
                    if (!readULEB(pos, end, segmentOffset)) stopped = true;
                    break;
                case 0x80:
                    if (!readULEB(pos, end, value) || !advance(value)) stopped = true;
                    break;
                case 0x90:
                    if (!emit() || !advance(selected64 ? 8u : 4u)) stopped = true;
                    break;
                case 0xa0:
                    if (!emit() || !readULEB(pos, end, value) ||
                        value > std::numeric_limits<uint64_t>::max() - (selected64 ? 8u : 4u) ||
                        !advance(value + (selected64 ? 8u : 4u))) stopped = true;
                    break;
                case 0xb0: {
                    const uint64_t pointerSize = selected64 ? 8u : 4u;
                    const uint64_t delta = pointerSize * (uint64_t(imm) + 1u);
                    if (!emit() || !advance(delta)) stopped = true;
                    break;
                }
                case 0xc0: {
                    uint64_t count = 0, skip = 0;
                    if (!readULEB(pos, end, count) || !readULEB(pos, end, skip) ||
                        count > kMaxBindOperations - std::min<uint64_t>(operations, kMaxBindOperations)) {
                        stopped = true;
                        break;
                    }
                    const uint64_t pointerSize = selected64 ? 8u : 4u;
                    for (uint64_t i = 0; i < count; ++i) {
                        ++operations;
                        if (!emit() || skip > std::numeric_limits<uint64_t>::max() - pointerSize ||
                            !advance(skip + pointerSize)) { stopped = true; break; }
                    }
                    break;
                }
                default: // includes BIND_OPCODE_THREADED, intentionally not guessed
                    stopped = true;
                    break;
            }
        }
        if ((stopped && (!cleanStop || pos < end)) || operations >= kMaxBindOperations) {
            machO_.bindingsValid = false;
            machO_.bindingsTruncated = true;
        }
    }

    // Export trie (LC_DYLD_EXPORTS_TRIE or the older LC_DYLD_INFO range).
    machO_.exportTriePresent = sawExportTrie;
    machO_.exportTrieValid = sawExportTrie;
    if (sawExportTrie && exportTrie.size) {
        if (!exportTrie.valid || !inSlice(exportTrie.offset, exportTrie.size)) {
            machO_.exportTrieValid = false;
            machO_.exportTrieTruncated = true;
        } else {
            const uint64_t trieBegin = exportTrie.offset;
            const uint64_t trieEnd = exportTrie.offset + exportTrie.size;
            std::unordered_set<uint64_t> visited;
            size_t storedNames = 0;
            std::function<void(uint64_t, const std::string&, size_t)> walk;
            walk = [&](uint64_t nodeOffset, const std::string& prefix, size_t depth) {
                if (!machO_.exportTrieValid || depth > kMaxTrieDepth ||
                    visited.size() >= kMaxTrieNodes || nodeOffset >= exportTrie.size ||
                    !visited.insert(nodeOffset).second) {
                    machO_.exportTrieValid = false;
                    machO_.exportTrieTruncated = true;
                    return;
                }
                uint64_t pos = trieBegin + nodeOffset;
                uint64_t terminalSize = 0;
                if (!readULEB(pos, trieEnd, terminalSize) || terminalSize > trieEnd - pos) {
                    machO_.exportTrieValid = false;
                    machO_.exportTrieTruncated = true;
                    return;
                }
                const uint64_t terminalEnd = pos + terminalSize;
                if (terminalSize) {
                    MachOTrieExport value;
                    value.name = prefix;
                    uint64_t flags = 0;
                    if (!readULEB(pos, terminalEnd, flags)) {
                        machO_.exportTrieValid = false;
                    } else {
                        value.flags = flags;
                        value.reexport = (flags & 0x08u) != 0;
                        value.stubAndResolver = (flags & 0x10u) != 0;
                        if (value.reexport) {
                            uint64_t ordinalValue = 0;
                            if (!readULEB(pos, terminalEnd, ordinalValue) || ordinalValue > INT32_MAX ||
                                !readCString(pos, terminalEnd, value.importName)) {
                                machO_.exportTrieValid = false;
                            } else {
                                value.libraryOrdinal = static_cast<int32_t>(ordinalValue);
                            }
                        } else {
                            uint64_t addressOffset = 0;
                            if (!readULEB(pos, terminalEnd, addressOffset)) {
                                machO_.exportTrieValid = false;
                            } else if (havePreferredBase &&
                                       addressOffset <= std::numeric_limits<uint64_t>::max() - preferredBase) {
                                value.address = preferredBase + addressOffset;
                                value.addressValid = true;
                                bool code = false;
                                classifyAddress(value.address, value.mapped, code);
                                if (value.stubAndResolver && !readULEB(pos, terminalEnd, value.other))
                                    machO_.exportTrieValid = false;
                            } else {
                                machO_.exportTrieValid = false;
                            }
                        }
                    }
                    const size_t outputBytes = prefix.size() + value.importName.size();
                    if (machO_.trieExports.size() >= kMaxTrieExports ||
                        outputBytes > kMaxStoredStringBytes -
                                      std::min(storedNames, kMaxStoredStringBytes)) {
                        machO_.exportTrieTruncated = true;
                    } else {
                        storedNames += outputBytes;
                        machO_.trieExports.push_back(value);
                        if (!value.reexport && value.addressValid) {
                            bool mapped = false, code = false;
                            classifyAddress(value.address, mapped, code);
                            appendExport(value.name, value.address, mapped, code);
                        }
                    }
                }
                pos = terminalEnd;
                if (pos >= trieEnd) {
                    machO_.exportTrieValid = false;
                    machO_.exportTrieTruncated = true;
                    return;
                }
                const uint8_t childCount = data_[static_cast<size_t>(pos++)];
                for (uint8_t child = 0; child < childCount; ++child) {
                    std::string edge;
                    const uint64_t edgeAt = pos;
                    if (!readCString(edgeAt, trieEnd, edge)) {
                        machO_.exportTrieValid = false;
                        machO_.exportTrieTruncated = true;
                        return;
                    }
                    pos = edgeAt + edge.size() + 1;
                    uint64_t childOffset = 0;
                    if (!readULEB(pos, trieEnd, childOffset) || prefix.size() + edge.size() > kMaxString) {
                        machO_.exportTrieValid = false;
                        machO_.exportTrieTruncated = true;
                        return;
                    }
                    walk(childOffset, prefix + edge, depth + 1);
                    if (!machO_.exportTrieValid) return;
                }
            };
            walk(0, {}, 0);
        }
    }

    // LC_FUNCTION_STARTS is a ULEB delta stream relative to the image base.
    machO_.functionStartsPresent = sawFunctionStarts;
    machO_.functionStartsValid = sawFunctionStarts;
    if (sawFunctionStarts && functionStarts.size) {
        if (!functionStarts.valid || !inSlice(functionStarts.offset, functionStarts.size) || !havePreferredBase) {
            machO_.functionStartsValid = false;
            machO_.functionStartsTruncated = true;
        } else {
            uint64_t pos = functionStarts.offset;
            const uint64_t end = pos + functionStarts.size;
            uint64_t address = preferredBase;
            bool terminated = false;
            while (pos < end) {
                uint64_t delta = 0;
                if (!readULEB(pos, end, delta)) {
                    machO_.functionStartsValid = false;
                    machO_.functionStartsTruncated = true;
                    break;
                }
                if (!delta) { terminated = true; break; }
                if (delta > std::numeric_limits<uint64_t>::max() - address) {
                    machO_.functionStartsValid = false;
                    break;
                }
                address += delta;
                if (machO_.functionStarts.size() >= kMaxFunctionStarts) {
                    machO_.functionStartsTruncated = true;
                    break;
                }
                machO_.functionStarts.push_back(address);
            }
            if (!terminated && !machO_.functionStartsTruncated) {
                machO_.functionStartsValid = false;
                machO_.functionStartsTruncated = true;
            }
        }
    }

    // Initializer entry points from LC_ROUTINES(_64) and pointer arrays in
    // S_MOD_INIT_FUNC_POINTERS sections. Pointer value zero remains explicit.
    machO_.initializersPresent = !routineInits.empty() || !modInitRanges.empty();
    machO_.initializersValid = machO_.initializersPresent;
    for (const RoutineInit& routine : routineInits) {
        if (machO_.initializers.size() >= kMaxInitializers) {
            machO_.initializersTruncated = true;
            break;
        }
        MachOInitializer init;
        init.kind = MachOInitializerKind::RoutinesCommand;
        init.targetVA = routine.address;
        init.targetValid = routine.valid;
        classifyAddress(init.targetVA, init.targetMapped, init.targetIsCode);
        machO_.initializers.push_back(std::move(init));
    }
    const uint64_t pointerSize = selected64 ? 8u : 4u;
    for (const ModInitRange& range : modInitRanges) {
        const SectionMeta& section = range.section;
        if ((section.size % pointerSize) != 0) machO_.initializersValid = false;
        const uint64_t declaredCount = section.size / pointerSize;
        uint64_t count = declaredCount;
        if (count > kMaxInitializers - std::min(machO_.initializers.size(), kMaxInitializers)) {
            count = kMaxInitializers - machO_.initializers.size();
            machO_.initializersTruncated = true;
        }
        for (uint64_t i = 0; i < count; ++i) {
            if (i > (std::numeric_limits<uint64_t>::max() - section.rawOffset) / pointerSize ||
                (i + 1) * pointerSize > section.rawBacked) {
                machO_.initializersValid = false;
                machO_.initializersTruncated = true;
                break;
            }
            const uint64_t fileAt = section.rawOffset + i * pointerSize;
            MachOInitializer init;
            init.kind = MachOInitializerKind::ModInitSection;
            init.sectionName = section.name;
            init.targetVA = selected64 ? u64(fileAt, selectedBig) : u32(fileAt, selectedBig);
            init.targetValid = true;
            if (i <= (std::numeric_limits<uint64_t>::max() - section.addr) / pointerSize) {
                init.slotVA = section.addr + i * pointerSize;
                init.slotValid = true;
            }
            classifyAddress(init.targetVA, init.targetMapped, init.targetIsCode);
            machO_.initializers.push_back(std::move(init));
        }
        if (declaredCount > count) machO_.initializersTruncated = true;
    }

    return !sections_.empty() || entryValid || !machO_.symbols.empty() ||
           !machO_.trieExports.empty() || !machO_.functionStarts.empty();
}

} // namespace ds
