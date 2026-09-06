#pragma once
//
// BinaryFile.h
// Loads a file into memory and performs lightweight PE parsing so the
// disassembler and views have section/entry-point context to work with.
//
#include "AddressSpan.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ds {

struct JvmClassFile;
struct GameMakerArchive;
struct Instruction;
struct DecoderConfig;

struct Section {
    std::string name;
    uint64_t    virtualAddress = 0; // RVA
    uint64_t    virtualSize    = 0;
    uint64_t    rawOffset      = 0; // file offset of raw data
    uint64_t    rawSize        = 0;
    uint32_t    characteristics = 0;
    bool        executable      = false;
};

// An authoritative analysis root recovered outside the normal executable
// headers (for example a firmware reset vector, SEC/PEI entry, or option-ROM
// initialization entry).  The loader keeps these with the mapped image so the
// background FunctionAnalyzer can seed and name them without borrowing UI state.
struct AnalysisLandmark {
    uint64_t    address = 0;       // mapped VA, including valid VA 0
    std::string name;              // stable symbol spelling
    std::string evidence;          // concise detector evidence for UI/tooltips
};

enum class BinFormat { Unknown, PE32, PE32Plus, ELF, MachO, Raw, JavaClass, GameMakerArchive };

// Stable failure categories let the shell distinguish an unreadable path from
// a recognized-but-invalid format and offer Open as Raw only when that is an
// informed analyst decision. `loadErrorText()` carries a concise diagnostic.
enum class BinaryLoadError : uint8_t {
    None = 0,
    OpenFailed,
    EmptyFile,
    FileTooLarge,
    ReadFailed,
    AllocationFailed,
    Cancelled,
    UnsupportedMachine,
    MalformedPE,
    MalformedELF,
    MalformedMachO,
    MalformedJavaClass,
    InvalidRawMapping,
    MalformedGameMakerArchive,
};

// Normal structured loading intentionally admits a finite in-memory image.
// DisasmStudio currently owns the complete file plus derived analysis state, so
// accepting an arbitrarily large allocation would make a hostile header a
// process-wide availability bug. The shell can also provide a cancellation
// predicate; the reader checks it between bounded chunks.
struct BinaryLoadOptions {
    static constexpr uint64_t kDefaultMaxBytes = 1ull * 1024ull * 1024ull * 1024ull;
    uint64_t maxBytes = kDefaultMaxBytes;
    size_t readChunkBytes = 4ull * 1024ull * 1024ull;
    std::function<bool()> cancelled;
};

// The CPU the image targets, recovered from the format header so the UI can
// auto-pick the right disassembler arch (and so ELF/Mach-O ARM images route to
// Capstone rather than defaulting to x86/x64 off the 32/64-bit class alone).
enum class MachineArch { Unknown, X86, X64, ARM, THUMB, ARM64, MIPS, MIPS64, PPC, PPC64, RISCV, RISCV64, JVM, GML };

class BinaryFile {
public:
    // Keep the in-memory Raw root set within the same bound accepted by the
    // project schema. The bound applies before deduplication so callers cannot
    // install state that this build would serialize but reject on reopen.
    static constexpr size_t kMaxAnalysisLandmarks = 4096;

    // Normalized symbol metadata shared by PE exports and ELF symbol tables.
    // PE does not encode these distinctions, so its rows retain Unknown while
    // `isCode` continues to describe the mapped target section. ELF rows carry
    // the exact st_info/st_other classification recovered from the file.
    enum class SymbolKind : uint8_t {
        Unknown,
        Function,
        Object,
        ThreadLocal,
        IndirectFunction,
    };
    enum class SymbolBinding : uint8_t { Unknown, Local, Global, Weak, Unique };
    enum class SymbolVisibility : uint8_t { Default, Internal, Hidden, Protected, Unknown };

    bool        load(const std::string& path);
    bool        load(const std::string& path, const BinaryLoadOptions& options);
    // Load `path` as a flat code blob (shellcode / firmware) mapped at `base`,
    // with no header parsing. The caller selects the disassembler arch.
    bool        loadRaw(const std::string& path, uint64_t base);
    bool        loadRaw(const std::string& path, uint64_t base,
                        const BinaryLoadOptions& options);
    // Load a PE image already MAPPED in a live process: `bytes` is a copy of the
    // module's in-memory image starting at runtime base `base` (section data sits at
    // its RVA, not its file PointerToRawData), `name` labels it. Sets imageBase_ to
    // the real runtime base (so addresses are runtime VAs, no ASLR delta) and parses
    // the PE headers/sections/imports. A non-MZ buffer falls back to Raw@base;
    // recognized but malformed/unsupported MZ input is rejected.
    // contentHash() reflects the memory image, which deliberately differs from an
    // on-disk load — live-module analysis is in-session only (not sidecar-persisted).
    bool        loadFromMemory(std::vector<uint8_t> bytes, uint64_t base, const std::string& name);
    bool        loaded() const { return !data_.empty(); }
    BinaryLoadError             loadError() const { return loadError_; }
    const std::string&          loadErrorText() const { return loadErrorText_; }
    // True when the current image came from loadFromMemory (a live process mapping).
    bool        isMappedImage() const { return mappedImage_; }
    void        clear();

    const std::string&          path()       const { return path_; }
    BinFormat                   format()      const { return format_; }
    const char*                 formatName()  const;
    MachineArch                 machine()     const { return machine_; }
    bool                        is64Bit()     const { return is64_; }
    // Authoritative byte order of the selected structured image/slice. Current
    // ELF and Mach-O both preserve the selected image/slice byte order.
    // PE, JVM class executable payloads, and explicit Raw mappings report false.
    bool                        bigEndian()   const { return bigEndian_; }
    // Decoder-relevant ELF header metadata. e_flags is authoritative for an
    // ELF image even when every optional ISA bit is clear; `present` keeps
    // that state distinct from non-ELF formats and Raw analyst settings.
    struct ElfDecoderMetadata {
        bool     present = false;
        uint32_t flags = 0;
        bool     riscvCompressed = false; // EF_RISCV_RVC
        bool     mipsMicro = false;        // EF_MIPS_MICROMIPS
    };
    const ElfDecoderMetadata& elfDecoderMetadata() const { return elfDecoderMetadata_; }
    uint16_t                    fileCharacteristics() const { return fileCharacteristics_; }
    bool                        isDll() const {
        return (format_ == BinFormat::PE32 || format_ == BinFormat::PE32Plus) &&
               (fileCharacteristics_ & 0x2000u) != 0; // IMAGE_FILE_DLL
    }
    uint64_t                    imageBase()   const { return imageBase_; }
    uint64_t                    entryPoint()  const { return entryRVA_; }
    // entryPoint() retains its historical RVA return contract.  These helpers
    // distinguish a real entry at RVA/VA zero from "no entry" and are therefore
    // the preferred interface for raw firmware.
    bool                        hasEntryPoint() const {
        if (!entryPointPresent_) return false;
        uint64_t va = 0;
        return CheckedAddressAdd(imageBase_, entryRVA_, va);
    }
    bool                        rawEntryExplicit() const { return format_ == BinFormat::Raw && rawEntryExplicit_; }
    uint64_t                    entryPointVA() const {
        uint64_t va = 0;
        return CheckedAddressAdd(imageBase_, entryRVA_, va) ? va : 0;
    }
    const std::vector<uint8_t>& bytes()       const { return data_; }
    const std::vector<Section>& sections()    const { return sections_; }

    // Configure the analyst/detector-selected entry and additional named roots
    // for a Raw image.  Every accepted address must be backed by the mapping;
    // invalid input leaves the prior metadata unchanged.
    bool setRawEntryPointVA(uint64_t va);
    bool setAnalysisLandmarks(std::vector<AnalysisLandmark> landmarks);
    // Replace a disk-backed Raw image's complete mapping without rereading or
    // copying its bytes. Entry/landmarks are absolute addresses in the new
    // mapping. Validation is atomic; success preserves the pristine hash/path
    // and advances imageRevision so existing analysis cannot reuse old VAs.
    bool remapRaw(uint64_t base, uint64_t entryVA, bool entryExplicit,
                  std::vector<AnalysisLandmark> landmarks);
    const std::vector<AnalysisLandmark>& analysisLandmarks() const { return analysisLandmarks_; }

    // Stable 64-bit content hash (FNV-1a) used as the persistence sidecar key.
    // Cached on first use (at load, before any patch) so writeImage() patches do
    // not change the key and split a binary's saved analysis across two sidecars.
    uint64_t                    contentHash() const;
    // Monotone in-memory image generation. Unlike contentHash(), this changes on
    // load/clear and every successful writeImage(), so derived views can invalidate
    // analysis after a patch without changing the persistence key.
    uint64_t                    imageRevision() const { return imageRevision_; }

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

    // Resolve an x86 real-mode segment:offset target to a VA backed by this
    // image. Direct conventional mappings win; Raw firmware mapped at the top
    // of the address space may also alias its final (at most) 1 MiB through the
    // conventional real-mode window. Numeric VA zero remains a valid result.
    bool resolveRealModeAlias(uint16_t segment, uint32_t offset,
                              uint64_t& vaOut) const;
    // Resolve either an ordinary decoder-supplied direct target or an x86-16
    // segment:offset transfer through this image's explicit firmware mapping.
    // The validity result is separate from the numeric VA, so mapped VA zero is
    // representable.
    bool resolveInstructionTarget(const Instruction& instruction,
                                  uint64_t& vaOut) const;

    // Transactionally overwrite exactly n bytes of the in-memory image at VA
    // `va`, so the disassembly reflects an applied (or reverted) patch. Returns
    // n on success and 0 without modifying any byte if the complete VA range is
    // not file-backed. Deliberately does NOT change contentHash() or the file.
    bool   canWriteImage(uint64_t va, size_t n) const;
    size_t writeImage(uint64_t va, const uint8_t* data, size_t n);

    // Atomically install a complete same-sized image produced by a private
    // patch-list transaction. The replacement is validated before the no-throw
    // vector swap, so allocation or validation failure while constructing the
    // candidate cannot leave a valid prefix of persisted patches applied.
    bool commitPatchedImage(std::vector<uint8_t>&& replacement);

    // The first executable section, if any (used as the default disasm target).
    const Section* firstCodeSection() const;

    // PE export directory (RVA + size), zero if none / not a PE.
    uint32_t exportDirRVA()  const { return exportRVA_; }
    uint32_t exportDirSize() const { return exportSize_; }

    // Complete PE export-address table. There is one row per exported alias;
    // an ordinal-only slot has an empty name. Forwarders retain their textual
    // target (for example "KERNEL32.Sleep"), while local targets expose their
    // VA and whether the containing section is executable. Parsed once with
    // the image so consumers do not each grow a partial PE parser.
    struct Export {
        uint64_t    ordinal  = 0;
        uint64_t    rva      = 0; // PE RVA; ELF/Mach-O absolute value (image base is zero)
        uint64_t    va       = 0;
        uint64_t    size     = 0; // exact ELF st_size when present
        std::string name;
        std::string forwarder;
        bool        forwarded = false;
        bool        mapped    = false;
        bool        isCode    = false;
        SymbolKind       kind       = SymbolKind::Unknown;
        SymbolBinding    binding    = SymbolBinding::Unknown;
        SymbolVisibility visibility = SymbolVisibility::Unknown;
        bool        elfSymbol      = false;
        bool        machoSymbol    = false;
        bool        dynamicSymbol  = false; // originated in SHT_DYNSYM
        uint16_t    elfVersionIndex = 0;
        std::string elfVersion;
        bool        elfVersionHidden = false;
        bool        elfVersionDefined = false;
    };
    const std::vector<Export>& exports() const { return exports_; }

    // One leaf of the PE resource directory (data directory [2]). The directory
    // is a three-level tree Type -> Name/ID -> Language; a leaf carries a data
    // RVA + size + code page. `typeId`/`nameId` hold the numeric id at each
    // level unless that level used a string entry, in which case the decoded
    // UTF-8 text is in `typeName`/`name` and the corresponding *Named flag is
    // set. `va` is imageBase + dataRVA (for cross-view navigation); `fileOffset`
    // is the backing offset into bytes() when `mapped`. Parsed once with the
    // image, bounded like the export table so a hostile tree cannot spin/allocate.
    struct Resource {
        uint32_t    typeId    = 0;   // RT_* when < 0x1000 and not typeNamed
        uint32_t    nameId    = 0;
        uint32_t    langId    = 0;   // LANGID
        std::string typeName;        // decoded string type (when typeNamed)
        std::string name;            // decoded string name (when nameNamed)
        uint32_t    dataRVA   = 0;
        uint32_t    dataSize  = 0;
        uint32_t    codePage  = 0;
        uint64_t    va        = 0;   // imageBase + dataRVA (0 if it would overflow)
        uint64_t    fileOffset= 0;   // index into bytes() when mapped
        bool        mapped    = false;
        bool        typeNamed = false;
        bool        nameNamed = false;
    };
    const std::vector<Resource>& resources() const { return resources_; }
    // PE resource directory (RVA + size), zero if none / not a PE.
    uint32_t resourceDirRVA()  const { return resourceRVA_; }
    uint32_t resourceDirSize() const { return resourceSize_; }

    // PE TLS directory (data directory [9]). The directory stores VAs rather
    // than RVAs, including the callback-table pointer. A present-but-malformed
    // directory remains visible through `present`, while `directoryValid` and
    // the table flags make partial/hostile input explicit. Callback order is
    // preserved and capped; no consumer needs to walk target-controlled memory.
    struct PeTlsInfo {
        bool        present = false;
        bool        directoryValid = false;
        uint32_t    directoryRVA = 0;
        uint32_t    directorySize = 0;
        uint64_t    rawDataStartVA = 0;
        uint64_t    rawDataEndVA = 0;
        uint64_t    indexVA = 0;
        uint64_t    callbackTableVA = 0;
        uint32_t    zeroFillSize = 0;
        uint32_t    characteristics = 0;
        bool        rawDataRangeValid = false;
        bool        callbackTableMapped = false;
        bool        callbacksTerminated = false;
        bool        callbacksTruncated = false;
        std::vector<uint64_t> callbacks;
    };
    const PeTlsInfo& peTls() const { return peTls_; }

    // One symbol in an IMAGE_DELAYLOAD_DESCRIPTOR (data directory [13]).
    // Descriptor metadata is retained alongside its bounded symbol list so
    // tooling can distinguish delay-loading from the normal import table.
    struct PeDelayImportSymbol {
        uint64_t    iatVA = 0;
        std::string name;
        uint16_t    ordinal = 0;
        bool        byOrdinal = false;
    };
    struct PeDelayImportDescriptor {
        uint32_t    descriptorRVA = 0;
        uint32_t    attributes = 0;
        uint32_t    timestamp = 0;
        std::string dll;
        uint64_t    moduleHandleVA = 0;
        uint64_t    iatVA = 0;
        uint64_t    importNameTableVA = 0;
        uint64_t    boundIatVA = 0;
        uint64_t    unloadIatVA = 0;
        bool        fieldsAreRVA = false;
        bool        dllNameTerminated = false;
        bool        descriptorValid = false;
        bool        symbolsTerminated = false;
        bool        symbolsTruncated = false;
        std::vector<PeDelayImportSymbol> symbols;
    };
    const std::vector<PeDelayImportDescriptor>& delayImports() const { return delayImports_; }

    // IMAGE_DEBUG_DIRECTORY records (data directory [6]). CodeView RSDS data
    // is decoded without depending on Win32 GUID types. The GUID bytes remain
    // authoritative; `codeViewGuid` is the conventional printable spelling.
    struct PeDebugEntry {
        uint32_t characteristics = 0;
        uint32_t timestamp = 0;
        uint16_t majorVersion = 0;
        uint16_t minorVersion = 0;
        uint32_t type = 0;
        uint32_t dataSize = 0;
        uint32_t dataRVA = 0;
        uint32_t dataFileOffset = 0;
        bool     payloadAvailable = false;
        bool     payloadFileOffsetValid = false;
        bool     codeViewRsds = false;
        std::array<uint8_t, 16> codeViewGuidBytes{};
        std::string codeViewGuid;
        uint32_t codeViewAge = 0;
        std::string pdbPath;
        bool     pdbPathTerminated = false;
    };
    const std::vector<PeDebugEntry>& peDebugEntries() const { return peDebugEntries_; }

    // Security-relevant prefix fields from IMAGE_LOAD_CONFIG_DIRECTORY32/64
    // (data directory [10]). Presence bits distinguish an absent field in an
    // older/smaller structure from a present field whose value is zero.
    struct PeLoadConfig {
        bool     present = false;
        bool     headerValid = false;
        uint32_t directoryRVA = 0;
        uint32_t directorySize = 0;
        uint32_t declaredSize = 0;
        uint32_t timestamp = 0;
        uint16_t majorVersion = 0;
        uint16_t minorVersion = 0;
        uint16_t dependentLoadFlags = 0;
        bool     dependentLoadFlagsPresent = false;
        uint64_t securityCookieVA = 0;
        bool     securityCookiePresent = false;
        bool     securityCookieMapped = false;
        uint64_t seHandlerTableVA = 0;
        uint64_t seHandlerCount = 0;
        bool     seHandlerTablePresent = false;
        bool     seHandlerTableMapped = false;
        uint64_t guardCfCheckFunctionVA = 0;
        uint64_t guardCfDispatchFunctionVA = 0;
        uint64_t guardCfFunctionTableVA = 0;
        uint64_t guardCfFunctionCount = 0;
        uint32_t guardFlags = 0;
        bool     guardCfCheckPresent = false;
        bool     guardCfDispatchPresent = false;
        bool     guardCfTablePresent = false;
        bool     guardFlagsPresent = false;
        bool     guardCfCheckMapped = false;
        bool     guardCfDispatchMapped = false;
        bool     guardCfTableMapped = false;
    };
    const PeLoadConfig& peLoadConfig() const { return peLoadConfig_; }

    // Parsed x64 IMAGE_RUNTIME_FUNCTION_ENTRY plus its UNWIND_INFO prefix.
    // Raw 16-bit unwind-code slots are retained exactly (bounded globally),
    // allowing later UI/analysis decoders to interpret operation-specific
    // operand slots without reparsing untrusted image bytes.
    struct PeRuntimeFunction {
        uint32_t beginRVA = 0;
        uint32_t endRVA = 0;
        uint32_t unwindDataRVA = 0;
        uint64_t beginVA = 0;
        uint64_t endVA = 0;
        bool     rangeValid = false;
        bool     indirectEntry = false;
        bool     unwindInfoValid = false;
        uint8_t  unwindVersion = 0;
        uint8_t  unwindFlags = 0;
        uint8_t  prologSize = 0;
        uint8_t  unwindCodeCount = 0;
        uint8_t  frameRegister = 0;
        uint8_t  frameOffset = 0;
        std::vector<uint16_t> unwindCodeSlots;
        bool     unwindCodesComplete = false;
        uint32_t exceptionHandlerRVA = 0;
        uint64_t exceptionHandlerVA = 0;
        bool     exceptionHandlerPresent = false;
        bool     exceptionHandlerMapped = false;
        bool     chainedInfoPresent = false;
        bool     chainedInfoValid = false;
        uint32_t chainedBeginRVA = 0;
        uint32_t chainedEndRVA = 0;
        uint32_t chainedUnwindDataRVA = 0;
    };
    const std::vector<PeRuntimeFunction>& runtimeFunctions() const { return runtimeFunctions_; }

    // x64 PE exception directory (.pdata): the linker-emitted RUNTIME_FUNCTION
    // table, one [begin, end) VA range per function (chained-unwind continuation
    // entries are folded away). Authoritative function boundaries for function
    // discovery. Empty for non-x64 / non-PE images (ARM64 .pdata differs).
    std::vector<std::pair<uint64_t, uint64_t>> pdataRanges() const;

    // PE overlay: file bytes appended past the end of every section's raw data
    // (installers, self-extractors, and Java launchers like launch4j/jpackage
    // stash payloads there — it has no VA, so vaToOffset never reaches it).
    // Zero for ELF/Mach-O/raw and for live mappings (rawOffset is an RVA there).
    uint64_t overlayOffset() const { return overlayOffset_; }
    uint64_t overlaySize()   const { return overlaySize_; }
    bool     hasOverlay()    const { return overlaySize_ != 0; }

    // PE security directory (data directory [4], the Authenticode certificate
    // table). Uniquely among directories its first field is a FILE OFFSET, not
    // an RVA — needed to carve a trailing cert off an appended-payload scan.
    uint32_t securityDirOffset() const { return securityOff_; }
    uint32_t securityDirSize()   const { return securitySize_; }

    // PE data directory [14] (CLR/COM descriptor). Nonzero RVA => .NET assembly.
    uint32_t clrDirRVA() const { return clrRva_; }
    uint32_t clrDirSize() const { return clrSize_; }

    // Resolved PE imports and undefined ELF symbols. PE rows have a
    // concrete IAT slot. An ELF undefined symbol has no one-to-one address until
    // relocation/loader resolution, so addressKnown is false and iatVA remains 0.
    struct Import {
        uint64_t iatVA = 0;
        std::string dll, name;
        bool addressKnown = true;
        SymbolKind       kind       = SymbolKind::Unknown;
        SymbolBinding    binding    = SymbolBinding::Unknown;
        SymbolVisibility visibility = SymbolVisibility::Unknown;
        bool dynamicSymbol = false;
        bool delayed = false;
        bool machoSymbol = false;
        uint16_t elfVersionIndex = 0;
        std::string elfVersion;
        bool elfVersionHidden = false;
    };
    const std::vector<Import>& imports() const { return imports_; }
    // PE base relocations as (VA, type) pairs (type = IMAGE_REL_BASED_*).
    const std::vector<std::pair<uint64_t, int>>& relocations() const { return relocs_; }

    // Bounded ELF metadata. REL/RELA rows retain the encoded offset and an
    // explicit target-valid bit so a legitimate VA zero is never confused with
    // an unresolved target. ET_REL offsets are resolved through the same
    // synthetic per-section analysis addresses used by symbols and sections.
    struct ElfRelocation {
        uint64_t offset = 0;
        uint64_t targetVA = 0;
        uint64_t symbolValue = 0;
        int64_t  addend = 0;
        uint32_t type = 0;
        uint32_t symbolIndex = 0;
        std::string symbolName;
        bool hasAddend = false;
        bool targetValid = false;
        bool targetMapped = false;
        bool symbolValid = false;
        bool symbolDefined = false;
        bool pltRelated = false;
        bool gotRelated = false;
    };
    struct ElfRelocationTable {
        uint32_t sectionIndex = 0;
        uint32_t targetSectionIndex = 0;
        uint32_t symbolTableSectionIndex = 0;
        std::string name;
        uint64_t declaredEntries = 0;
        uint64_t parsedEntries = 0;
        bool hasAddends = false;
        bool valid = false;
        bool complete = false;
        bool truncated = false;
        std::vector<ElfRelocation> entries;
    };
    const std::vector<ElfRelocationTable>& elfRelocationTables() const { return elfRelocationTables_; }
    bool elfRelocationsTruncated() const { return elfRelocationsTruncated_; }

    enum class ElfLinkageKind : uint8_t { Plt, Got, GotPlt };
    struct ElfLinkageSlot {
        uint64_t address = 0;
        bool addressValid = false;
        bool mapped = false;
        bool relocationValid = false;
        uint32_t relocationTableIndex = 0;
        uint32_t relocationEntryIndex = 0;
    };
    struct ElfLinkageSection {
        uint32_t sectionIndex = 0;
        std::string name;
        ElfLinkageKind kind = ElfLinkageKind::Plt;
        uint64_t address = 0;
        uint64_t size = 0;
        uint64_t entrySize = 0;
        bool addressValid = false;
        bool mapped = false;
        bool complete = true;
        bool truncated = false;
        std::vector<ElfLinkageSlot> slots;
    };
    const std::vector<ElfLinkageSection>& elfLinkageSections() const { return elfLinkageSections_; }
    bool elfLinkageTruncated() const { return elfLinkageTruncated_; }

    struct ElfDynamicDependency {
        std::string name;
        uint32_t dynamicSectionIndex = 0;
        uint64_t stringOffset = 0;
        bool stringValid = false;
    };
    struct ElfDynamicMetadata {
        bool present = false;
        bool valid = true;
        bool terminated = true;
        bool truncated = false;
        std::vector<ElfDynamicDependency> dependencies;
    };
    const ElfDynamicMetadata& elfDynamic() const { return elfDynamic_; }

    struct ElfVersionDefinition {
        uint16_t index = 0;
        uint16_t flags = 0;
        uint32_t hash = 0;
        std::string name;
        uint32_t sectionIndex = 0;
        bool valid = false;
    };
    struct ElfVersionRequirement {
        uint16_t index = 0;
        uint16_t flags = 0;
        uint32_t hash = 0;
        std::string name;
        std::string file;
        uint32_t sectionIndex = 0;
        bool valid = false;
    };
    struct ElfSymbolVersion {
        uint32_t symbolTableSectionIndex = 0;
        uint32_t symbolIndex = 0;
        uint16_t index = 0;
        std::string name;
        std::string file;
        bool hidden = false;
        bool definition = false;
        bool requirement = false;
        bool valid = false;
    };
    struct ElfVersionMetadata {
        bool definitionsTruncated = false;
        bool requirementsTruncated = false;
        bool symbolsTruncated = false;
        std::vector<ElfVersionDefinition> definitions;
        std::vector<ElfVersionRequirement> requirements;
        std::vector<ElfSymbolVersion> symbols;
    };
    const ElfVersionMetadata& elfVersions() const { return elfVersions_; }

    enum class ElfInitializerKind : uint8_t { Init, Fini, PreinitArray, InitArray, FiniArray };
    struct ElfInitializer {
        ElfInitializerKind kind = ElfInitializerKind::Init;
        uint64_t address = 0;
        uint64_t slotVA = 0;
        uint32_t sectionIndex = 0;
        bool addressValid = false;
        bool addressMapped = false;
        bool slotValid = false;
        bool slotMapped = false;
        bool fromDynamic = false;
        bool requiresRelocation = false;
    };
    struct ElfInitializationMetadata {
        bool truncated = false;
        std::vector<ElfInitializer> entries;
    };
    const ElfInitializationMetadata& elfInitializers() const { return elfInitializers_; }

    // Bounded Mach-O metadata. For a universal image, offsets in Slice refer to
    // the outer file and exactly one supported slice is selected by a stable
    // architecture preference. The remaining records describe that slice.
    struct MachOSlice {
        uint32_t cpuType = 0;
        uint32_t cpuSubtype = 0;
        uint64_t fileOffset = 0;
        uint64_t fileSize = 0;
        uint32_t alignExponent = 0;
        bool is64Bit = false;
        bool bigEndian = false;
        bool structurallyValid = false;
        bool supported = false;
        bool selected = false;
    };
    struct MachOSymbol {
        uint32_t tableIndex = 0;
        uint64_t value = 0;
        std::string name;
        uint8_t type = 0;
        uint8_t sectionIndex = 0;
        uint16_t description = 0;
        bool external = false;
        bool debug = false;
        bool undefined = false;
        bool mapped = false;
        bool isCode = false;
    };
    struct MachOBinding {
        uint64_t address = 0;
        uint64_t segmentOffset = 0;
        int64_t addend = 0;
        int32_t libraryOrdinal = 0;
        uint32_t segmentIndex = 0;
        uint8_t type = 0;
        uint8_t symbolFlags = 0;
        std::string library;
        std::string symbol;
        bool addressValid = false;
        bool mapped = false;
        bool weak = false;
        bool lazy = false;
    };
    struct MachOTrieExport {
        std::string name;
        std::string importName;
        uint64_t address = 0;
        uint64_t flags = 0;
        uint64_t other = 0;
        int32_t libraryOrdinal = 0;
        bool addressValid = false;
        bool mapped = false;
        bool reexport = false;
        bool stubAndResolver = false;
    };
    enum class MachOInitializerKind : uint8_t { ModInitSection, RoutinesCommand };
    struct MachOInitializer {
        MachOInitializerKind kind = MachOInitializerKind::ModInitSection;
        uint64_t slotVA = 0;
        uint64_t targetVA = 0;
        std::string sectionName;
        bool slotValid = false;
        bool targetValid = false;
        bool targetMapped = false;
        bool targetIsCode = false;
    };
    struct MachOMetadata {
        bool universal = false;
        bool fat64 = false;
        bool containerBigEndian = false;
        bool slicesTruncated = false;
        int32_t selectedSlice = -1;
        bool loadCommandsValid = false;
        bool loadCommandsTruncated = false;
        bool symbolTablePresent = false;
        bool symbolTableValid = false;
        bool symbolsTruncated = false;
        bool bindingsPresent = false;
        bool bindingsValid = false;
        bool bindingsTruncated = false;
        bool exportTriePresent = false;
        bool exportTrieValid = false;
        bool exportTrieTruncated = false;
        bool functionStartsPresent = false;
        bool functionStartsValid = false;
        bool functionStartsTruncated = false;
        bool initializersPresent = false;
        bool initializersValid = false;
        bool initializersTruncated = false;
        std::vector<MachOSlice> slices;
        std::vector<MachOSymbol> symbols;
        std::vector<MachOBinding> bindings;
        std::vector<MachOTrieExport> trieExports;
        std::vector<uint64_t> functionStarts;
        std::vector<MachOInitializer> initializers;
    };
    const MachOMetadata& machO() const { return machO_; }

    // Parsed Java class file (constant pool, method table) when the loaded
    // image is BinFormat::JavaClass; null otherwise. Shared so the worker's
    // JvmDisassembler can hold it across the analysis job safely.
    std::shared_ptr<const JvmClassFile> javaClass() const { return javaClass_; }
    std::shared_ptr<const GameMakerArchive> gameMakerArchive() const { return gameMakerArchive_; }

private:
    // Turn the already-loaded byte buffer into one flat executable mapping.
    // Returns false when [base, base + size) cannot be represented in uint64_t.
    // This is shared by explicit raw loads, unknown files, failed structured
    // parses, and non-PE live buffers so every BinFormat::Raw has one coherent
    // section model rather than retaining partial parser state.
    bool initializeRawLayout(uint64_t base, bool mappedImage = false);
    bool rejectLoad(BinaryLoadError code, const char* message) noexcept;
    bool parsePE();
    bool parseELF();
    bool parseMachO();
    bool parseJavaClass();
    bool parseGameMakerArchive(const std::function<bool()>& cancelled);
    void parseExports();   // PE data directory [0]
    void parseImports();   // PE data directory [1]
    void parseResources(); // PE data directory [2]
    void parseRelocs();    // PE data directory [5]
    void parseDebugDirectory();   // PE data directory [6]
    void parseTlsDirectory();     // PE data directory [9]
    void parseLoadConfig();       // PE data directory [10]
    void parseDelayImports();     // PE data directory [13]
    void parseRuntimeFunctions(); // PE data directory [3], x64

    std::string          path_;
    BinaryLoadError      loadError_ = BinaryLoadError::None;
    std::string          loadErrorText_;
    std::vector<uint8_t> data_;
    std::vector<Section> sections_;
    uint64_t             imageRevision_ = 1;
    mutable uint64_t     hash_      = 0;       // cached contentHash of the pristine file
    mutable bool         hashValid_ = false;   // false until first contentHash() / reset by clear()
    BinFormat            format_     = BinFormat::Unknown;
    MachineArch          machine_    = MachineArch::Unknown;
    bool                 is64_       = true;
    bool                 bigEndian_  = false;
    ElfDecoderMetadata   elfDecoderMetadata_;
    uint16_t             fileCharacteristics_ = 0; // PE COFF Characteristics
    bool                 mappedImage_ = false;   // image came from a live process mapping
    uint64_t             mappedBase_  = 0;        // runtime base override for a mapped image
    uint64_t             imageBase_  = 0;
    uint64_t             entryRVA_   = 0;
    bool                 entryPointPresent_ = false;
    bool                 rawEntryExplicit_ = false;
    std::vector<AnalysisLandmark> analysisLandmarks_;
    uint32_t             exportRVA_  = 0;
    uint32_t             exportSize_ = 0;
    uint32_t             importRVA_  = 0;
    uint32_t             importSize_ = 0;
    uint32_t             relocRVA_   = 0;
    uint32_t             relocSize_  = 0;
    uint32_t             exceptRVA_  = 0;   // data dir [3]: exception directory (.pdata)
    uint32_t             exceptSize_ = 0;
    uint32_t             resourceRVA_  = 0; // data dir [2]: resource directory (.rsrc)
    uint32_t             resourceSize_ = 0;
    uint32_t             debugRVA_      = 0; // data dir [6]: IMAGE_DEBUG_DIRECTORY array
    uint32_t             debugSize_     = 0;
    uint32_t             tlsRVA_        = 0; // data dir [9]: IMAGE_TLS_DIRECTORY
    uint32_t             tlsSize_       = 0;
    uint32_t             loadConfigRVA_ = 0; // data dir [10]: IMAGE_LOAD_CONFIG_DIRECTORY
    uint32_t             loadConfigSize_= 0;
    uint32_t             delayImportRVA_= 0; // data dir [13]: delay-load descriptors
    uint32_t             delayImportSize_= 0;
    uint64_t             overlayOffset_ = 0;   // file offset of PE overlay data (0 = none)
    uint64_t             overlaySize_   = 0;
    uint32_t             securityOff_   = 0;   // data dir [4]: file offset (not RVA!)
    uint32_t             securitySize_  = 0;
    uint32_t             clrRva_        = 0;   // data dir [14]: CLR/COM descriptor
    uint32_t             clrSize_       = 0;
    uint32_t             sizeOfHeaders_ = 0;   // effective PE header span (declared size clamped before sections)
    std::vector<Export>                    exports_;
    std::vector<Resource>                  resources_;
    std::vector<Import>                    imports_;
    std::vector<std::pair<uint64_t, int>>  relocs_;
    std::vector<ElfRelocationTable>        elfRelocationTables_;
    bool                                   elfRelocationsTruncated_ = false;
    std::vector<ElfLinkageSection>         elfLinkageSections_;
    bool                                   elfLinkageTruncated_ = false;
    ElfDynamicMetadata                     elfDynamic_;
    ElfVersionMetadata                     elfVersions_;
    ElfInitializationMetadata              elfInitializers_;
    MachOMetadata                          machO_;
    PeTlsInfo                              peTls_;
    std::vector<PeDelayImportDescriptor>   delayImports_;
    std::vector<PeDebugEntry>              peDebugEntries_;
    PeLoadConfig                           peLoadConfig_;
    std::vector<PeRuntimeFunction>         runtimeFunctions_;
    std::shared_ptr<const JvmClassFile>    javaClass_;   // set for BinFormat::JavaClass
    std::shared_ptr<const GameMakerArchive> gameMakerArchive_;
};

// Apply loader-owned decoder metadata to a requested configuration. Structured
// image architecture, byte order, and declared ISA feature bits are
// authoritative; Raw images retain every analyst-selected field unchanged.
DecoderConfig DecoderConfigForImage(const BinaryFile& image,
                                    DecoderConfig requested);

} // namespace ds
