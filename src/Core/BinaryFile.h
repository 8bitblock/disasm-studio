#pragma once
//
// BinaryFile.h
// Loads a file into memory and performs lightweight PE parsing so the
// disassembler and views have section/entry-point context to work with.
//
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

struct Section {
    std::string name;
    uint64_t    virtualAddress = 0; // RVA
    uint64_t    virtualSize    = 0;
    uint64_t    rawOffset      = 0; // file offset of raw data
    uint64_t    rawSize        = 0;
    uint32_t    characteristics = 0;
    bool        executable      = false;
};

enum class BinFormat { Unknown, PE32, PE32Plus, ELF, MachO, Raw };

// The CPU the image targets, recovered from the format header so the UI can
// auto-pick the right disassembler arch (and so ELF/Mach-O ARM images route to
// Capstone rather than defaulting to x86/x64 off the 32/64-bit class alone).
enum class MachineArch { Unknown, X86, X64, ARM, ARM64, MIPS, MIPS64, PPC, PPC64, RISCV, RISCV64 };

class BinaryFile {
public:
    bool        load(const std::string& path);
    // Load `path` as a flat code blob (shellcode / firmware) mapped at `base`,
    // with no header parsing. The caller selects the disassembler arch.
    bool        loadRaw(const std::string& path, uint64_t base);
    // Load a PE image already MAPPED in a live process: `bytes` is a copy of the
    // module's in-memory image starting at runtime base `base` (section data sits at
    // its RVA, not its file PointerToRawData), `name` labels it. Sets imageBase_ to
    // the real runtime base (so addresses are runtime VAs, no ASLR delta) and parses
    // the PE headers/sections/imports. Falls back to Raw@base if it isn't a PE.
    // contentHash() reflects the memory image, which deliberately differs from an
    // on-disk load — live-module analysis is in-session only (not sidecar-persisted).
    bool        loadFromMemory(std::vector<uint8_t> bytes, uint64_t base, const std::string& name);
    bool        loaded() const { return !data_.empty(); }
    // True when the current image came from loadFromMemory (a live process mapping).
    bool        isMappedImage() const { return mappedImage_; }
    void        clear();

    const std::string&          path()       const { return path_; }
    BinFormat                   format()      const { return format_; }
    const char*                 formatName()  const;
    MachineArch                 machine()     const { return machine_; }
    bool                        is64Bit()     const { return is64_; }
    uint64_t                    imageBase()   const { return imageBase_; }
    uint64_t                    entryPoint()  const { return entryRVA_; }
    const std::vector<uint8_t>& bytes()       const { return data_; }
    const std::vector<Section>& sections()    const { return sections_; }

    // Stable 64-bit content hash (FNV-1a) used as the persistence sidecar key.
    // Cached on first use (at load, before any patch) so writeImage() patches do
    // not change the key and split a binary's saved analysis across two sidecars.
    uint64_t                    contentHash() const;

    // Translate a virtual address to a pointer into the loaded image, or null.
    const uint8_t* ptrFromVA(uint64_t va, size_t& availOut) const;
    // Same but addressed by RVA (relative to image base). 64-bit so table walks
    // (rva + k*stride) can't wrap a 32-bit add into an aliased in-bounds slot.
    const uint8_t* ptrFromRVA(uint64_t rva, size_t& availOut) const;

    // Translate a raw file offset (an index into bytes()) to its mapped virtual
    // address. Returns false if the offset isn't backed by mapped data. Use this
    // when scanning bytes() directly (strings, byte search) so reported addresses
    // line up with the disassembly instead of being treated as RVAs.
    bool offsetToVA(uint64_t fileOffset, uint64_t& vaOut) const;

    // Inverse of offsetToVA: translate a virtual address to its backing file
    // offset (an index into bytes()). Returns false when the VA is in virtual
    // padding or otherwise has no on-disk bytes. Needed to write patches back to
    // a copy of the file.
    bool vaToOffset(uint64_t va, uint64_t& offOut) const;

    // Overwrite up to n bytes of the in-memory image at VA `va`, so the
    // disassembly reflects an applied (or reverted) patch. Returns the number of
    // bytes written; 0 if `va` is not backed by on-disk data. Deliberately does
    // NOT change contentHash() (keyed to the original file) or the file on disk.
    size_t writeImage(uint64_t va, const uint8_t* data, size_t n);

    // The first executable section, if any (used as the default disasm target).
    const Section* firstCodeSection() const;

    // PE export directory (RVA + size), zero if none / not a PE.
    uint32_t exportDirRVA()  const { return exportRVA_; }
    uint32_t exportDirSize() const { return exportSize_; }

    // Resolved PE imports: each IAT slot's VA + the DLL and function it binds to.
    struct Import { uint64_t iatVA = 0; std::string dll, name; };
    const std::vector<Import>& imports() const { return imports_; }
    // PE base relocations as (VA, type) pairs (type = IMAGE_REL_BASED_*).
    const std::vector<std::pair<uint64_t, int>>& relocations() const { return relocs_; }

private:
    bool parsePE();
    bool parseELF();
    bool parseMachO();
    void parseImports();   // PE data directory [1]
    void parseRelocs();    // PE data directory [5]

    std::string          path_;
    std::vector<uint8_t> data_;
    std::vector<Section> sections_;
    mutable uint64_t     hash_      = 0;       // cached contentHash of the pristine file
    mutable bool         hashValid_ = false;   // false until first contentHash() / reset by clear()
    BinFormat            format_     = BinFormat::Unknown;
    MachineArch          machine_    = MachineArch::Unknown;
    bool                 is64_       = true;
    bool                 mappedImage_ = false;   // image came from a live process mapping
    uint64_t             mappedBase_  = 0;        // runtime base override for a mapped image
    uint64_t             imageBase_  = 0;
    uint64_t             entryRVA_   = 0;
    uint32_t             exportRVA_  = 0;
    uint32_t             exportSize_ = 0;
    uint32_t             importRVA_  = 0;
    uint32_t             importSize_ = 0;
    uint32_t             relocRVA_   = 0;
    uint32_t             relocSize_  = 0;
    std::vector<Import>                    imports_;
    std::vector<std::pair<uint64_t, int>>  relocs_;
};

} // namespace ds
