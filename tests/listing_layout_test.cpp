// listing_layout_test.cpp
// Pure coverage for optional PE-header/section listing planning and bounded data
// rows, lazy code-page descriptors, and bounded cross-page decoding.

#include "Core/AnalysisJobs.h"
#include "Core/BinaryFile.h"
#include "Core/Project.h"
#include "Core/XrefIndex.h"
#include "Disasm/IDisassembler.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

using namespace ds;

static int g_fail = 0;
#define CHECK(x, msg) do { if (!(x)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

static void put16(std::vector<uint8_t>& b, size_t o, uint16_t v) {
    b[o] = (uint8_t)v; b[o + 1] = (uint8_t)(v >> 8);
}
static void put32(std::vector<uint8_t>& b, size_t o, uint32_t v) {
    b[o] = (uint8_t)v; b[o + 1] = (uint8_t)(v >> 8);
    b[o + 2] = (uint8_t)(v >> 16); b[o + 3] = (uint8_t)(v >> 24);
}
static void put64(std::vector<uint8_t>& b, size_t o, uint64_t v) {
    std::memcpy(b.data() + o, &v, sizeof(v));
}

static std::string makePe() {
    std::vector<uint8_t> b(0xA00, 0);
    b[0] = 'M'; b[1] = 'Z'; put32(b, 0x3C, 0x80);
    const size_t pe = 0x80, coff = pe + 4, opt = coff + 20;
    b[pe] = 'P'; b[pe + 1] = 'E';
    put16(b, coff + 0, 0x14C); put16(b, coff + 2, 3); put16(b, coff + 16, 0xE0);
    put16(b, coff + 18, 0x010F);
    put16(b, opt + 0, 0x10B); put32(b, opt + 16, 0x1000); put32(b, opt + 20, 0x1000);
    put32(b, opt + 28, 0x400000); put32(b, opt + 32, 0x1000); put32(b, opt + 36, 0x200);
    put32(b, opt + 56, 0x4000); put32(b, opt + 60, 0x400); put32(b, opt + 92, 16);
    const size_t sh = opt + 0xE0;
    auto sec = [&](int i, const char* name, uint32_t rva, uint32_t raw, uint32_t chars) {
        const size_t s = sh + (size_t)i * 40;
        std::memcpy(b.data() + s, name, std::min<size_t>(std::strlen(name), 8));
        put32(b, s + 8, 0x200); put32(b, s + 12, rva);
        put32(b, s + 16, 0x200); put32(b, s + 20, raw); put32(b, s + 36, chars);
    };
    sec(0, ".text",  0x1000, 0x400, 0x60000020);
    sec(1, ".rdata", 0x2000, 0x600, 0x40000040);
    sec(2, ".rsrc",  0x3000, 0x800, 0x40000040);
    std::fill(b.begin() + 0x400, b.begin() + 0x600, 0x90);
    for (size_t i = 0; i < 0x200; ++i) b[0x600 + i] = (uint8_t)i;
    for (size_t i = 0; i < 0x200; ++i) b[0x800 + i] = (uint8_t)(0xA0 + (i & 0x1F));
    std::memcpy(b.data() + 0x805, "HELLO", 5);
    const std::string path = "ds_listing_layout_tmp.exe";
    std::ofstream f(path, std::ios::binary); f.write((const char*)b.data(), (std::streamsize)b.size());
    return path;
}

static std::string makeOverflowElf() {
    std::vector<uint8_t> b(0x180, 0x90);
    std::memcpy(b.data(), "\x7F" "ELF", 4);
    b[4] = 2; b[5] = 1; b[6] = 1; // ELF64 little-endian
    put16(b, 16, 2); put16(b, 18, 0x3E); put32(b, 20, 1);
    put64(b, 24, UINT64_MAX - 15); // entry
    put64(b, 32, 64);              // program-header table
    put16(b, 52, 64); put16(b, 54, 56); put16(b, 56, 1);
    const size_t ph = 64;
    put32(b, ph, 1); put32(b, ph + 4, 5); // PT_LOAD, R-X
    put64(b, ph + 8, 0x100);
    put64(b, ph + 16, UINT64_MAX - 15);
    put64(b, ph + 32, 0x40); put64(b, ph + 40, 0x40);
    const std::string path = "ds_listing_overflow_tmp.elf";
    std::ofstream f(path, std::ios::binary);
    f.write((const char*)b.data(), (std::streamsize)b.size());
    return path;
}

struct ByteDis : IDisassembler {
    size_t calls = 0;
    Engine engine() const override { return Engine::Zydis; }
    const char* engineName() const override { return "byte"; }
    bool decodeOne(const uint8_t* p, size_t n, uint64_t va, Instruction& out) override {
        if (!p || !n) return false;
        ++calls; out = {}; out.address = va; out.length = 1; out.mnemonic = "nop"; out.bytes = "90";
        return true;
    }
    std::vector<Instruction> disassemble(const uint8_t*, size_t, uint64_t, size_t) override { return {}; }
};

struct CrossPageDis : ByteDis {
    bool decodeOne(const uint8_t* p, size_t n, uint64_t va, Instruction& out) override {
        if (!p || !n) return false;
        ++calls; out = {}; out.address = va;
        if (p[0] == 0xF0 && n >= 6) {
            out.length = 6; out.mnemonic = "cross"; out.bytes = "F0 11 22 33 44 55";
        } else {
            out.length = 1; out.mnemonic = "nop"; out.bytes = "90";
        }
        return true;
    }
};

// Deliberately does not self-synchronize after a wrong page-front start. Page 0's
// crossing instruction suppresses two bytes in page 1; honoring that checkpoint
// makes page 1 cross one byte into page 2, while incorrectly seeding page 1 at zero
// produces a different stream that ends exactly at the boundary.
struct ChainedBoundaryDis : ByteDis {
    bool decodeOne(const uint8_t* p, size_t n, uint64_t va, Instruction& out) override {
        if (!p || !n) return false;
        size_t length = 2;
        if (p[0] == 0xA0) length = 4;
        else if (p[0] == 0xB0) length = 7;
        else if (p[0] == 0xC0) length = 3;
        else if (p[0] == 0xD0) length = 5;
        if (length > n) return false;
        ++calls; out = {}; out.address = va; out.length = (uint8_t)length;
        out.mnemonic = "chain"; out.bytes = "AA";
        return true;
    }
};

struct ThumbCrossDis : ByteDis {
    uint32_t invalidDecodeWidth() const override { return 2; }
    bool decodeOne(const uint8_t* p, size_t n, uint64_t va, Instruction& out) override {
        if (!p || n < 2) return false;
        const size_t length = p[0] == 0xF0 ? 4 : 2;
        if (length > n) return false;
        ++calls; out = {}; out.address = va; out.length = (uint32_t)length;
        out.mnemonic = length == 4 ? "thumb32" : "thumb16";
        out.bytes = length == 4 ? "F0 00 00 00" : "00 00";
        return true;
    }
};

struct MalformedStepDis : ByteDis {
    explicit MalformedStepDis(uint32_t step) : step_(step) {}
    uint32_t invalidDecodeWidth() const override { return step_; }
    bool decodeOne(const uint8_t* p, size_t n, uint64_t va, Instruction& out) override {
        if (!p || n < step_ || p[0] == 0xFF) return false;
        ++calls; out = {}; out.address = va; out.length = step_;
        out.mnemonic = "ok"; out.bytes = "00";
        return true;
    }
private:
    uint32_t step_ = 1;
};

static void testInstructionSnapshots() {
    const ListingInstructionScope scope{17, 23, {}};
    std::vector<uint8_t> image{0x48, 0x89, 0xE5};
    Instruction displayed;
    displayed.address = 0;
    displayed.length = 3;
    displayed.mnemonic = "mov";
    displayed.operands = "rbp, rsp";
    displayed.bytes = "48 89 E5";
    std::vector<Instruction> pageCache{displayed};
    const auto selected = ListingInstructionSnapshot::Capture(
        scope, pageCache.front(), image.data(), image.size());
    pageCache.clear();
    pageCache.shrink_to_fit();
    CHECK(selected.valid() && selected.instruction.address == 0 &&
          selected.instruction.operands == "rbp, rsp" &&
          selected.matches(scope, displayed, image.data(), image.size()),
          "VA-zero selected instruction owns all data after display-cache eviction");
    image[1] = 0x90;
    CHECK(selected.bytes[1] == 0x89 &&
          !selected.matches(scope, displayed, image.data(), image.size()),
          "saved raw bytes are owned and a changed instruction is rejected");
    image[1] = 0x89;
    auto otherScope = scope;
    ++otherScope.documentId;
    CHECK(!selected.matches(otherScope, displayed, image.data(), image.size()),
          "identical instruction in another document is stale");
    otherScope = scope; ++otherScope.imageId;
    CHECK(!selected.matches(otherScope, displayed, image.data(), image.size()),
          "identical instruction in a replacement image is stale");
    for (unsigned change = 0; change < 7; ++change) {
        otherScope = scope;
        switch (change) {
            case 0: otherScope.decoder.engine = Engine::Capstone; break;
            case 1: otherScope.decoder.arch = Arch::X86; break;
            case 2: otherScope.decoder.byteOrder = ByteOrder::Big; break;
            case 3: otherScope.decoder.features.riscvCompressed =
                        !scope.decoder.features.riscvCompressed; break;
            case 4: otherScope.decoder.features.armV8 =
                        !scope.decoder.features.armV8; break;
            case 5: otherScope.decoder.features.armMClass =
                        !scope.decoder.features.armMClass; break;
            case 6: otherScope.decoder.features.mipsMicro =
                        !scope.decoder.features.mipsMicro; break;
        }
        CHECK(!selected.matches(otherScope, displayed, image.data(), image.size()),
              "every decoder engine/ISA/byte-order/feature change invalidates a selection");
    }
    auto decoded = displayed;
    ++decoded.address;
    CHECK(!selected.matches(scope, decoded, image.data(), image.size()),
          "fresh decode at another address cannot validate the selected start");
    decoded = displayed; --decoded.length;
    CHECK(!selected.matches(scope, decoded, image.data(), image.size()),
          "changed decoded instruction length invalidates the selection");
    CHECK(!selected.matches(scope, displayed, image.data(), image.size() - 1) &&
          !selected.matches(scope, displayed, nullptr, image.size()),
          "unreadable or truncated current bytes cannot validate the selection");
    for (const char* mnemonic : {"", "db", "dw", "dd", "dq"}) {
        decoded = displayed; decoded.mnemonic = mnemonic;
        CHECK(!ListingInstructionSnapshot::Capture(
                  scope, decoded, image.data(), image.size()).valid(),
              "pseudo data and invalid decoder rows cannot become instruction authority");
        CHECK(!selected.matches(scope, decoded, image.data(), image.size()),
              "a newly decoded data directive invalidates a formerly selected instruction");
    }
    decoded = displayed; decoded.length = 0;
    CHECK(!ListingInstructionSnapshot::Capture(
              scope, decoded, image.data(), image.size()).valid(),
          "zero-length instruction cannot create a snapshot");
    decoded.length = (uint32_t)kListingInstructionSnapshotByteCap + 1;
    CHECK(!ListingInstructionSnapshot::Capture(
              scope, decoded, image.data(), image.size()).valid(),
          "unbounded hostile instruction length is rejected before reading bytes");
    CHECK(selected.overlaps(0, 1) && selected.overlaps(2, 1) &&
          !selected.overlaps(3, 1) && !selected.overlaps(0, 0),
          "overlap includes every instruction byte but excludes the successor and empty spans");

    decoded = displayed; decoded.address = UINT64_MAX; decoded.length = 1;
    const auto lastByte = ListingInstructionSnapshot::Capture(
        scope, decoded, image.data(), image.size());
    CHECK(lastByte.valid() && lastByte.overlaps(UINT64_MAX, 1) &&
          lastByte.overlaps(UINT64_MAX - 1, 2) &&
          !lastByte.overlaps(0, UINT64_MAX) && !selected.overlaps(UINT64_MAX, UINT64_MAX),
          "last-address overlap is exact and an overflowing changed span never wraps to VA zero");
    decoded.length = 2;
    CHECK(!ListingInstructionSnapshot::Capture(
              scope, decoded, image.data(), image.size()).valid(),
          "instruction whose bytes wrap the address space is rejected");

    ListingBoundaryAuthority authority;
    const uint64_t initialRevision = authority.revision();
    CHECK(authority.acceptDisplayed(selected) &&
          authority.revision() == initialRevision + 1 &&
          authority.retainedBytes() == 3 && authority.size() == 1,
          "acceptance retains bounded byte-backed authority and advances retry revision");
    CHECK(!authority.acceptDisplayed(selected) &&
          authority.revision() == initialRevision + 1,
          "idempotent acceptance does not cause duplicate breakpoint retries");
    CHECK(authority.acceptedSnapshot(0) && authority.actionable(0, false) &&
          !authority.actionable(1, false) &&
          !ListingInstructionsHaveStart(pageCache, 0),
          "analyst authority accepts one start without proving its page or trace seeds");
    decoded = displayed; decoded.address = 10;
    const auto other = ListingInstructionSnapshot::Capture(
        scope, decoded, image.data(), image.size());
    CHECK(authority.acceptDisplayed(other), "accept a second independent selected start");
    const auto beforePatch = authority.revision();
    CHECK(authority.invalidateOverlapping(3, 7) == 0 &&
          authority.revision() == beforePatch && authority.size() == 2,
          "adjacent unrelated patch preserves selections and does not wake breakpoint retries");
    CHECK(authority.invalidateOverlapping(2, 1) == 1 &&
          !authority.analystAccepted(0) && authority.analystAccepted(10) &&
          authority.retainedBytes() == 3 && authority.revision() == beforePatch + 1,
          "patch inside an instruction invalidates its old start but preserves unaffected authority");
    decoded = displayed; decoded.length = 1; decoded.mnemonic = "nop";
    const uint8_t replacementBytes[] = {0x90};
    const auto replacement = ListingInstructionSnapshot::Capture(
        scope, decoded, replacementBytes, sizeof(replacementBytes));
    CHECK(authority.acceptDisplayed(replacement) &&
          authority.acceptedSnapshot(0)->matches(
              scope, decoded, replacementBytes, sizeof(replacementBytes)) &&
          authority.analystAccepted(10),
          "explicit instruction patch can accept its freshly decoded replacement independently");
    CHECK(authority.acceptDisplayed(lastByte) &&
          authority.invalidateOverlapping(UINT64_MAX, UINT64_MAX) == 1 &&
          authority.analystAccepted(0) && authority.analystAccepted(10),
          "overflowing invalidation retires the last byte without erasing low-address records");
    CHECK(authority.erase(0) && !authority.erase(0) && authority.retainedBytes() == 3,
          "single-site erase retires owned bytes once");
    const uint64_t beforeClear = authority.revision();
    authority.clear(); authority.clear();
    CHECK(authority.size() == 0 && authority.retainedBytes() == 0 &&
          authority.revision() == beforeClear + 1,
          "scope retirement clears all records and only actual changes advance revision");

    // A patch-set switch rebuilds the complete image, but the change can be
    // disjoint. Compare owned bytes after that rebuild, not the broad range
    // used to retire display pages, so unrelated analyst choices survive.
    std::vector<uint8_t> rebuiltImage(24, 0x90);
    for (uint64_t start : {0ull, 10ull, 20ull}) {
        decoded = displayed; decoded.address = start;
        CHECK(authority.acceptDisplayed(ListingInstructionSnapshot::Capture(
                  scope, decoded, rebuiltImage.data() + start, rebuiltImage.size() - start)),
              "capture instructions in three separate patch-set regions");
    }
    rebuiltImage[1] = 0xCC;
    rebuiltImage[21] = 0xCC;
    size_t predicateCalls = 0;
    auto changedInRebuiltImage = [&](const ListingInstructionSnapshot& record) {
        ++predicateCalls;
        if (!record.valid() || record.scope != scope) return true;
        const uint64_t start = record.instruction.address;
        return start >= rebuiltImage.size() || record.bytes.size() > rebuiltImage.size() - start ||
               !std::equal(record.bytes.begin(), record.bytes.end(), rebuiltImage.data() + start);
    };
    const uint64_t beforeSetSwitch = authority.revision();
    CHECK(authority.eraseIf(changedInRebuiltImage) == 2 && predicateCalls == 3 &&
          !authority.analystAccepted(0) && authority.analystAccepted(10) &&
          !authority.analystAccepted(20) && authority.size() == 1 &&
          authority.retainedBytes() == 3 && authority.revision() == beforeSetSwitch + 1,
          "patch-set rebuild retires two changed regions but preserves an unrelated accepted instruction");
    CHECK(authority.eraseIf(changedInRebuiltImage) == 0 &&
          authority.revision() == beforeSetSwitch + 1 && authority.retainedBytes() == 3,
          "unchanged rebuilt bytes neither retire authority nor repeat breakpoint retries");
    rebuiltImage.resize(11);
    CHECK(authority.eraseIf(changedInRebuiltImage) == 1 && authority.size() == 0 &&
          authority.retainedBytes() == 0 && authority.revision() == beforeSetSwitch + 2,
          "a now-unreadable complete instruction span is retired with exact budget accounting");

    // Valid JVM instructions can be much larger than native instructions. Their
    // snapshot storage is bounded across all accepted sites as well as per site.
    std::vector<uint8_t> largeBytes(kListingInstructionSnapshotByteCap, 0xAA);
    decoded = displayed;
    decoded.length = (uint32_t)largeBytes.size();
    decoded.mnemonic = "tableswitch";
    const size_t maxLargeSites = kListingInstructionRetainedByteCap / largeBytes.size();
    for (size_t site = 0; site < maxLargeSites; ++site) {
        decoded.address = site * largeBytes.size();
        CHECK(authority.acceptDisplayed(ListingInstructionSnapshot::Capture(
                  scope, decoded, largeBytes.data(), largeBytes.size())),
              "large instruction snapshots fit until the aggregate raw-byte budget");
    }
    decoded.address = maxLargeSites * largeBytes.size();
    const auto tooManyBytes = ListingInstructionSnapshot::Capture(
        scope, decoded, largeBytes.data(), largeBytes.size());
    const uint64_t fullRevision = authority.revision();
    CHECK(!authority.acceptDisplayed(tooManyBytes) &&
          authority.retainedBytes() == kListingInstructionRetainedByteCap &&
          authority.revision() == fullRevision && authority.analystAccepted(0),
          "aggregate memory exhaustion rejects admission without evicting accepted authority");
    CHECK(authority.erase(0) && authority.acceptDisplayed(tooManyBytes),
          "retiring one large instruction returns its byte budget for a later explicit action");
    authority.clear();
    for (size_t site = 0; site < kListingInstructionRecordCap; ++site)
        CHECK(authority.acceptDisplayed(site, true), "authority admits sites within its record cap");
    CHECK(!authority.acceptDisplayed(kListingInstructionRecordCap, true) &&
          authority.size() == kListingInstructionRecordCap && authority.analystAccepted(0),
          "record cap rejects admission without silently evicting prior choices");
}

int main() {
    testInstructionSnapshots();
    size_t lastReadableProbe = SIZE_MAX;
    const size_t partialLookback = LongestReadableLookback(128, [&](size_t bytes) {
        lastReadableProbe = bytes;
        return bytes <= 37;
    });
    CHECK(partialLookback == 37 && lastReadableProbe == 37,
          "partial mapped lookback retains the longest readable prefix and reloads it");
    CHECK(LongestReadableLookback(128, [](size_t) { return true; }) == 128,
          "fully readable lookback keeps the requested context");
    CHECK(LongestReadableLookback(128, [](size_t) { return false; }) == 0,
          "fully unreadable lookback falls back to the focus address");
    CHECK(LongestReadableLookback(0, [](size_t) { return true; }) == 0,
          "zero lookback performs no probe");

    // Alignment follows the same malformed-byte recovery as visible listing
    // decode. Otherwise one bad opcode turns into a false upper scroll wall.
    const uint8_t malformedBytes[] = { 0x00, 0xFF, 0x00 };
    MalformedStepDis byteRecovery(1);
    CHECK(ListingDecodeReaches(malformedBytes, sizeof(malformedBytes),
                               0x1000, 0x1003, byteRecovery),
          "byte-width malformed decode recovers to the exact target");
    const uint8_t malformedWords[] = { 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00 };
    MalformedStepDis wordRecovery(2);
    CHECK(ListingDecodeReaches(malformedWords, sizeof(malformedWords),
                               0x2000, 0x2006, wordRecovery),
          "fixed-width malformed decode preserves architectural stepping");
    CHECK(!ListingDecodeReaches(malformedWords, sizeof(malformedWords),
                                 0x2000, 0x2003, wordRecovery),
          "malformed recovery cannot overshoot and claim a false boundary");

    // Alignment must retain decoder lookahead beyond the candidate target. The
    // six-byte instruction starts one byte into this stream and crosses 0x3004,
    // so 0x3004 is not an instruction boundary. If the input is truncated at the
    // target, the decoder cannot see the complete variable-width instruction and
    // can falsely byte-step to the target instead.
    const uint8_t crossingTarget[] = { 0x90, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55 };
    CrossPageDis crossingTargetDis;
    CHECK(!ListingDecodeReaches(crossingTarget, sizeof(crossingTarget),
                                0x3000, 0x3004, crossingTargetDis),
          "full lookahead rejects a target crossed by a variable-width instruction");
    CHECK(ListingDecodeReaches(crossingTarget, 4,
                               0x3000, 0x3004, crossingTargetDis),
          "truncating at the target demonstrates the false byte-step without lookahead");

    // Mutation authority is per displayed instruction, not per provisional page.
    // This is the policy used by both Full Program and the windowed listing.
    ListingBoundaryAuthority boundaryAuthority;
    CHECK(!boundaryAuthority.actionable(0x401000, false),
          "unproven boundary starts non-actionable");
    CHECK(!boundaryAuthority.acceptDisplayed(0x401000, false) &&
          !boundaryAuthority.actionable(0x401000, false),
          "data/non-instruction cursor cannot manufacture boundary authority");
    CHECK(boundaryAuthority.acceptDisplayed(0x401000, true) &&
          boundaryAuthority.actionable(0x401000, false) &&
          !boundaryAuthority.actionable(0x401001, false),
          "explicit instruction action accepts only the selected displayed start");
    CHECK(boundaryAuthority.actionable(0x402000, true),
          "decoder-proven instruction remains actionable without analyst state");
    boundaryAuthority.clear();
    CHECK(!boundaryAuthority.actionable(0x401000, false),
          "image or ISA transition retires analyst boundary authority");

    const std::string path = makePe();
    BinaryFile bin;
    CHECK(bin.load(path), "load PE fixture");
    CHECK(bin.sections().size() == 3, "three modeled sections");

    ListingLayout def = MakeDefaultListingLayout(bin);
    CHECK(!def.peHeaderVisible && def.peHeaderFolded, "PE header is optional/folded by default");
    CHECK(def.sections.size() == 3 && def.sections[0].visible && !def.sections[0].folded,
          "executable .text is visible/unfolded by default");
    CHECK(!def.sections[1].visible && def.sections[1].folded &&
          !def.sections[2].visible && def.sections[2].folded,
          "non-code sections are optional/folded by default");

    ListingLayout persisted;
    persisted.peHeaderVisible = true; persisted.peHeaderFolded = false;
    persisted.sections.push_back({ 0x3000, ".rsrc", true, false });
    persisted.sections.push_back({ 0xDEAD, ".stale", true, false });
    ReconcileListingLayout(bin, persisted);
    CHECK(persisted.sections.size() == 3, "reconcile drops stale keys and materializes current sections");
    CHECK(persisted.sections[0].name == ".text" && persisted.sections[0].visible,
          "new executable section receives code default independent of vector order");
    CHECK(persisted.sections[2].rva == 0x3000 && persisted.sections[2].name == ".rsrc" &&
          persisted.sections[2].visible && !persisted.sections[2].folded,
          "persisted section matches by stable RVA+name key");

    std::vector<ListingRegionPlan> plan = PlanListingRegions(bin, &persisted);
    CHECK(plan.size() == 3 && plan[0].peHeader && plan[0].address == 0x400000,
          "plan includes mapped PE-header source first");
    CHECK(plan[1].name == ".text" && plan[2].name == ".rsrc",
          "plan includes only visible sections in VA order");

    // Executable layout building emits one fixed-size descriptor and performs no
    // decoder sweep. Function/loc/instruction rows are materialized by the GUI page LRU.
    std::vector<ListRowR> codeRows = BuildListingRows(bin, {});
    size_t codePages = 0; bool eagerInsn = false;
    for (const auto& r : codeRows) {
        if (r.type == ListingRowType::CodePage) {
            ++codePages;
            CHECK(r.addr == 0x401000 && r.aux == 0x200, "code descriptor covers exact mapped .text bytes");
        }
        eagerInsn |= r.type == ListingRowType::Normal || r.divider;
    }
    CHECK(codePages == 1 && !eagerInsn, "listing plan contains pages, never eager instruction rows");

    // A global code/data partition splits one executable section into independent
    // lazy code runs and typed directives. The pointer island must never be handed
    // to the decoder or used as a continuation checkpoint for the later code run.
    CodeDataMap classified;
    classified.imageRevision = bin.imageRevision();
    classified.spans = {
        {0x401000, 0x20, CodeDataKind::Code, 1, CodeDataConfidence::High, "reachable"},
        {0x401020, 0x10, CodeDataKind::PointerTable, 8, CodeDataConfidence::High, "vtable"},
        {0x401030, 0x10, CodeDataKind::Padding, 1, CodeDataConfidence::High, "fill"},
        {0x401040, 0x1C0, CodeDataKind::Unknown, 1, CodeDataConfidence::Low, "unproved"},
    };
    const auto classifiedRows = BuildListingRows(
        bin, {}, {}, nullptr, nullptr, kDefaultListingDataByteCap, &classified);
    bool pointerDq = false, paddingDb = false, codeBefore = false, codeAfter = false;
    uint32_t beforeRegion = 0, afterRegion = 0;
    for (const auto& r : classifiedRows) {
        if (r.type == ListingRowType::DataDirective && r.addr == 0x401020) {
            pointerDq = r.dataKind == CodeDataKind::PointerTable && r.dataWidth == 8 && r.dataSize == 16;
        }
        if (r.type == ListingRowType::DataDirective && r.addr == 0x401030)
            paddingDb = r.dataKind == CodeDataKind::Padding && r.dataWidth == 1;
        if (r.type == ListingRowType::CodePage && r.addr == 0x401000) {
            codeBefore = r.aux == 0x20; beforeRegion = r.codeRegion;
        }
        if (r.type == ListingRowType::CodePage && r.addr == 0x401040) {
            codeAfter = r.aux == 0x1C0; afterRegion = r.codeRegion;
        }
    }
    CHECK(pointerDq && paddingDb, "executable-section data renders as typed dq/db directives");
    CHECK(codeBefore && codeAfter && beforeRegion && afterRegion && beforeRegion != afterRegion,
          "classified data island splits independent lazy code checkpoint regions");

    // Authoritative instruction roots inside a lazy page are stream boundaries,
    // not continuation-byte prefixes. Coalesce the deliberately fragmented input
    // run, retain every byte before the first root, and repaginate independently
    // from both an existing descriptor start and an interior root.
    ListRowR rootHeader;
    rootHeader.addr = 0x1000;
    rootHeader.type = ListingRowType::RegionHeader;
    rootHeader.sectionIndex = 7;
    rootHeader.aux = 0x6000;
    std::vector<ListRowR> fragmented{rootHeader};
    auto addFragment = [&](uint64_t address, uint64_t bytes) {
        ListRowR page;
        page.addr = address;
        page.type = ListingRowType::CodePage;
        page.sectionIndex = 7;
        page.aux = bytes;
        page.codeRegion = 99;
        fragmented.push_back(page);
    };
    addFragment(0x1000, 0x180);
    addFragment(0x1180, 0x1000);
    addFragment(0x2180, 0x1000);
    addFragment(0x3180, 0x1000);
    addFragment(0x4180, 0x1000);
    addFragment(0x5180, 0x1000);
    addFragment(0x6180, 0xE80); // complete run: [0x1000, 0x7000)
    ListRowR rootTail;
    rootTail.addr = 0x8000;
    rootTail.type = ListingRowType::DataTruncated;
    rootTail.sectionIndex = 8;
    rootTail.aux = 0x55;
    fragmented.push_back(rootTail);

    const auto rooted = NormalizeListingCodePagesAtRoots(
        fragmented, {0x2180, 0x4A00, 0x4A00, 0x9000});
    uint64_t rootedBytes = 0;
    bool retainedPrefix = false, existingRootStarts = false, interiorRootStarts = false;
    bool pagesBounded = true, contiguousCoverage = true;
    bool rootRelativePaging = false, nonCodePreserved = rooted.size() >= 2;
    uint64_t nextRootedByte = 0x1000;
    size_t rootedPageCount = 0;
    std::vector<uint32_t> rootedRegions;
    for (size_t i = 0; i < rooted.size(); ++i) {
        const ListRowR& row = rooted[i];
        if (row.type != ListingRowType::CodePage) continue;
        ++rootedPageCount;
        rootedBytes += row.aux;
        contiguousCoverage = contiguousCoverage && row.addr == nextRootedByte;
        nextRootedByte = row.addr + row.aux;
        pagesBounded = pagesBounded && row.aux > 0 && row.aux <= kListingCodePageBytes &&
                       row.codeRegion != 0;
        if (row.addr == 0x1000 && row.aux == 0x1000) retainedPrefix = true;
        if (row.addr == 0x2180) existingRootStarts = true;
        if (row.addr == 0x4A00) interiorRootStarts = true;
        if (row.addr == 0x4180 && row.aux == 0x880) rootRelativePaging = true;
        if (rootedRegions.empty() || rootedRegions.back() != row.codeRegion)
            rootedRegions.push_back(row.codeRegion);
    }
    nonCodePreserved = nonCodePreserved &&
        rooted.front().type == ListingRowType::RegionHeader &&
        rooted.front().addr == rootHeader.addr && rooted.front().aux == rootHeader.aux &&
        rooted.back().type == ListingRowType::DataTruncated &&
        rooted.back().addr == rootTail.addr && rooted.back().aux == rootTail.aux;
    CHECK(rootedBytes == 0x6000 && retainedPrefix && contiguousCoverage &&
          nextRootedByte == 0x7000,
          "authoritative-root normalization preserves every pre-root code byte");
    CHECK(existingRootStarts && interiorRootStarts && rootedRegions.size() == 3 &&
          rootedRegions[0] != rootedRegions[1] &&
          rootedRegions[0] != rootedRegions[2] &&
          rootedRegions[1] != rootedRegions[2],
          "each existing/interior authoritative root starts a distinct code run");
    CHECK(pagesBounded && rootedPageCount == 8 && rootRelativePaging,
          "every normalized root-relative descriptor respects the lazy page bound");
    CHECK(nonCodePreserved,
          "authoritative-root normalization preserves non-code rows and ordering");

    CodeDataMap stale = classified;
    stale.imageRevision = bin.imageRevision() + 1;
    const auto staleRows = BuildListingRows(
        bin, {}, {}, nullptr, nullptr, kDefaultListingDataByteCap, &stale);
    size_t stalePages = 0; bool staleData = false;
    for (const auto& r : staleRows) {
        stalePages += r.type == ListingRowType::CodePage;
        staleData |= r.type == ListingRowType::DataDirective;
    }
    CHECK(stalePages == 1 && !staleData,
          "a classifier map from another image revision cannot reshape the listing");

    ByteDis dis;
    ListingLayout dataOnly = MakeDefaultListingLayout(bin);
    dataOnly.sections[0].visible = false; // visibility must prevent executable decoding
    dataOnly.sections[2].visible = true; dataOnly.sections[2].folded = false;
    std::vector<StrResult> strings = { { 0x403005, "HELLO", false, false } };
    std::vector<ListRowR> rows = BuildListingRows(bin, strings, {}, nullptr, &dataOnly, 16);
    CHECK(dis.calls == 0, "hidden executable section is not decoded");
    bool rsrcHeader = false, oneDirective = false, truncated = false, exactString = false;
    for (const auto& r : rows) {
        rsrcHeader |= r.type == ListingRowType::RegionHeader && r.sectionIndex == 2;
        oneDirective |= r.type == ListingRowType::DataDirective && r.addr == 0x403000 && r.dataSize == 16;
        truncated |= r.type == ListingRowType::DataTruncated && r.aux == 0x1F0;
        exactString |= r.strData && r.addr == 0x403005 && r.strIdx == 0;
    }
    CHECK(rsrcHeader && oneDirective && truncated, "unfolded data section gets bounded db rows + honest tail marker");
    CHECK(exactString, "known string remains an exact navigation row beyond directive alignment");

    ListingLayout folded = dataOnly; folded.sections[2].folded = true;
    rows = BuildListingRows(bin, strings, {}, nullptr, &folded, 16);
    bool anyContent = false;
    for (const auto& r : rows) anyContent |= r.type != ListingRowType::RegionHeader;
    CHECK(rows.size() == 1 && !anyContent, "folded section contributes only its region header");

    ListingLayout header = MakeDefaultListingLayout(bin);
    for (auto& s : header.sections) s.visible = false;
    header.peHeaderVisible = true; header.peHeaderFolded = false;
    rows = BuildListingRows(bin, {}, {}, nullptr, &header, 0x400);
    bool peHeader = false, headerBytes = false;
    for (const auto& r : rows) {
        peHeader |= r.type == ListingRowType::RegionHeader && r.sectionIndex == kListingPeHeaderIndex;
        headerBytes |= r.type == ListingRowType::DataDirective && r.sectionIndex == kListingPeHeaderIndex;
    }
    CHECK(peHeader && headerBytes, "unfolded PE header is a modeled byte source with data directives");

    // A variable-width instruction starting two bytes before a page boundary owns
    // its four continuation bytes. The following page suppresses that prefix.
    std::vector<uint8_t> cross(kListingCodePageBytes * 2 + 16, 0x90);
    cross[kListingCodePageBytes - 2] = 0xF0;
    CrossPageDis crossDis;
    DecodedListingPage first = DecodeListingCodePage(
        cross.data(), cross.size(), 0x100000, kListingCodePageBytes, 0, 15, crossDis);
    CHECK(!first.instructions.empty() && first.instructions.back().address ==
          0x100000 + kListingCodePageBytes - 2 && first.instructions.back().length == 6,
          "page decoder retains an instruction that crosses the descriptor boundary");
    CHECK(first.nextPrefixSkip == 4, "cross-page continuation checkpoint is exact");
    DecodedListingPage second = DecodeListingCodePage(
        cross.data() + kListingCodePageBytes, cross.size() - kListingCodePageBytes,
        0x100000 + kListingCodePageBytes, kListingCodePageBytes,
        first.nextPrefixSkip, 15, crossDis);
    CHECK(!second.instructions.empty() && second.instructions.front().address ==
          0x100000 + kListingCodePageBytes + 4,
          "next page suppresses bytes owned by the crossing instruction");
    CHECK(ListingInstructionsHaveStart(first.instructions,
          0x100000 + kListingCodePageBytes - 2),
          "trace boundary predicate accepts an exact decoded instruction start");
    CHECK(!ListingInstructionsHaveStart(second.instructions,
          0x100000 + kListingCodePageBytes),
          "trace boundary predicate rejects an uncached-style continuation-byte target");

    // JVM switch instructions can span multiple descriptors. When the inherited
    // continuation count ends exactly at a later page boundary, that target page
    // has prefix zero; copying the original skip would hide valid bytecode there.
    constexpr size_t tinyPage = 8;
    std::vector<uint8_t> multiPage(tinyPage * 4, 0x90);
    ByteDis multiPageDis;
    const DecodedListingPage hiddenOne = DecodeListingCodePage(
        multiPage.data(), multiPage.size(), 0x300000, tinyPage,
        static_cast<uint32_t>(tinyPage * 2), 1, multiPageDis);
    const DecodedListingPage hiddenTwo = DecodeListingCodePage(
        multiPage.data() + tinyPage, multiPage.size() - tinyPage,
        0x300000 + tinyPage, tinyPage, hiddenOne.nextPrefixSkip, 1,
        multiPageDis);
    const DecodedListingPage exactBoundary = DecodeListingCodePage(
        multiPage.data() + tinyPage * 2, multiPage.size() - tinyPage * 2,
        0x300000 + tinyPage * 2, tinyPage, hiddenTwo.nextPrefixSkip, 1,
        multiPageDis);
    CHECK(hiddenOne.instructions.empty() && hiddenOne.nextPrefixSkip == tinyPage &&
          hiddenTwo.instructions.empty() && hiddenTwo.nextPrefixSkip == 0,
          "multi-page continuation reaches an exact page boundary with prefix zero");
    CHECK(!exactBoundary.instructions.empty() &&
          exactBoundary.instructions.front().address == 0x300000 + tinyPage * 2,
          "bytecode at an exact continuation boundary remains visible");

    // Far random access is constant work: the page may sit 100 MiB into a section,
    // but provisional alignment looks behind at most 15 bytes and performs at most
    // 1+...+15 decoder calls. It never linearly walks from the section front.
    std::vector<uint8_t> localWindow(30, 0x90);
    ByteDis localDis;
    constexpr uint64_t farPage = 0x500000ull + 100ull * 1024ull * 1024ull;
    const ListingPrefixEstimate localEstimate = EstimateListingPagePrefix(
        localWindow.data(), localWindow.size(), farPage - 15, farPage, 15, localDis);
    CHECK(localEstimate.prefixSkip == 0 && localEstimate.candidates == 15,
          "bounded multi-candidate back-decode produces an immediate provisional alignment");
    CHECK(localEstimate.bytesExamined <= 30 && localEstimate.decodeCalls <= 120 &&
          localDis.calls == localEstimate.decodeCalls,
          "far-page provisional alignment has a strict byte/decode-call bound");

    // Thumb-2 and compressed RISC-V are variable-width even though their starts
    // are naturally halfword-aligned. A 32-bit instruction at pageEnd-2 owns the
    // first halfword of the next page; prefix=0 would emit that continuation twice.
    CHECK(ListingArchNeedsPagePrefix(Arch::THUMB) &&
          ListingArchNeedsPagePrefix(Arch::RISCV32) &&
          ListingArchNeedsPagePrefix(Arch::RISCV64),
          "Thumb-2 and compressed RISC-V route through page-prefix resolution");
    constexpr size_t thumbPageBytes = 8;
    std::vector<uint8_t> thumbBytes(thumbPageBytes * 2 + 4, 0x00);
    thumbBytes[thumbPageBytes - 2] = 0xF0;
    ThumbCrossDis thumbDis;
    const DecodedListingPage thumbFirst = DecodeListingCodePage(
        thumbBytes.data(), thumbBytes.size(), 0x510000, thumbPageBytes,
        0, ListingArchMaxInstructionBytes(Arch::THUMB), thumbDis);
    const DecodedListingPage thumbSecond = DecodeListingCodePage(
        thumbBytes.data() + thumbPageBytes, thumbBytes.size() - thumbPageBytes,
        0x510000 + thumbPageBytes, thumbPageBytes, thumbFirst.nextPrefixSkip,
        ListingArchMaxInstructionBytes(Arch::THUMB), thumbDis);
    CHECK(thumbFirst.nextPrefixSkip == 2 && !thumbSecond.instructions.empty() &&
          thumbSecond.instructions.front().address == 0x510000 + thumbPageBytes + 2,
          "Thumb-2 crossing instruction suppresses its continuation halfword exactly once");
    ThumbCrossDis thumbEstimateDis;
    const ListingPrefixEstimate thumbEstimate = EstimateListingPagePrefix(
        thumbBytes.data() + thumbPageBytes - 4, 8,
        0x510000 + thumbPageBytes - 4, 0x510000 + thumbPageBytes,
        ListingArchMaxInstructionBytes(Arch::THUMB), thumbEstimateDis,
        ListingArchInstructionAlignment(Arch::THUMB));
    CHECK(thumbEstimate.prefixSkip == 2 && thumbEstimate.candidates == 2 &&
          thumbEstimate.decodeCalls <= 3,
          "Thumb provisional back-decode uses bounded halfword-aligned candidates");

    // Exact checkpoint work is separately capped. A caller error cannot turn a
    // far-page paint into a 100 MiB worker sweep.
    ByteDis overCapDis;
    const uint8_t oneByte = 0x90;
    const ListingPrefixResult overCap = BuildListingPrefixCheckpoints(
        &oneByte, 1, 0x600000, 0x600000,
        0x600000 + kListingPrefixExactByteCap + 1, 15, overCapDis);
    CHECK(!overCap.complete && overCapDis.calls == 0,
          "exact prefix builder rejects over-budget distance before decoding");

    // A nearby trusted checkpoint later reconciles a provisional page. The exact
    // result changes the page front from target+0 to target+3, demonstrating why
    // provisional rows must be invalidated and never used as breakpoint proof.
    std::vector<uint8_t> reconcile(kListingCodePageBytes * 2 + 15, 0x90);
    const uint64_t reconcileBase = 0x700000;
    const uint64_t reconcileTarget = reconcileBase + kListingCodePageBytes;
    reconcile[kListingCodePageBytes - 3] = 0xF0;
    CrossPageDis reconcileDis;
    const size_t trustedOffset = kListingCodePageBytes - 16;
    const ListingPrefixResult exactPrefix = BuildListingPrefixCheckpoints(
        reconcile.data() + trustedOffset, reconcile.size() - trustedOffset,
        reconcileBase + trustedOffset, reconcileBase, reconcileTarget, 15,
        reconcileDis);
    CHECK(exactPrefix.complete && !exactPrefix.checkpoints.empty() &&
          exactPrefix.checkpoints.back().address == reconcileTarget &&
          exactPrefix.checkpoints.back().prefixSkip == 3,
          "nearby trusted checkpoint derives the exact replacement prefix");
    DecodedListingPage provisionalPage = DecodeListingCodePage(
        reconcile.data() + kListingCodePageBytes,
        reconcile.size() - kListingCodePageBytes, reconcileTarget,
        kListingCodePageBytes, 0, 15, reconcileDis);
    DecodedListingPage reconciledPage = DecodeListingCodePage(
        reconcile.data() + kListingCodePageBytes,
        reconcile.size() - kListingCodePageBytes, reconcileTarget,
        kListingCodePageBytes, exactPrefix.checkpoints.back().prefixSkip, 15,
        reconcileDis);
    CHECK(!provisionalPage.instructions.empty() && !reconciledPage.instructions.empty() &&
          provisionalPage.instructions.front().address == reconcileTarget &&
          reconciledPage.instructions.front().address == reconcileTarget + 3,
          "exact checkpoint reconciliation replaces provisional instruction rows");

    // Three-page adversarial chain: deriving page 2 from page 1 with an invented
    // prefix of zero gives the wrong answer. A resolver must carry page 0's proven
    // prefix through page 1 before it can establish page 2.
    constexpr size_t chainPage = 8;
    std::vector<uint8_t> chain(chainPage * 3 + 8, 0x90);
    chain[chainPage - 2] = 0xA0;      // correct page-1 prefix = 2
    chain[chainPage] = 0xC0;          // wrong page-1 stream: len 3 from offset 0
    chain[chainPage + 2] = 0xB0;      // correct stream: len 7 from offset 2 -> crosses 1
    chain[chainPage + 3] = 0xD0;      // wrong stream: len 5 from offset 3 -> exact end
    ChainedBoundaryDis chained;
    DecodedListingPage chain0 = DecodeListingCodePage(
        chain.data(), chain.size(), 0x300000, chainPage, 0, 8, chained);
    DecodedListingPage chain1Wrong = DecodeListingCodePage(
        chain.data() + chainPage, chain.size() - chainPage,
        0x300000 + chainPage, chainPage, 0, 8, chained);
    DecodedListingPage chain1 = DecodeListingCodePage(
        chain.data() + chainPage, chain.size() - chainPage,
        0x300000 + chainPage, chainPage, chain0.nextPrefixSkip, 8, chained);
    CHECK(chain0.nextPrefixSkip == 2 && chain1Wrong.nextPrefixSkip == 0 &&
          chain1.nextPrefixSkip == 1,
          "chained checkpoint provenance changes predecessor alignment and next-page ownership");
    DecodedListingPage chain2 = DecodeListingCodePage(
        chain.data() + chainPage * 2, chain.size() - chainPage * 2,
        0x300000 + chainPage * 2, chainPage, chain1.nextPrefixSkip, 8, chained);
    CHECK(!chain2.instructions.empty() && chain2.instructions.front().address ==
          0x300000 + chainPage * 2 + 1,
          "third page starts only after the full proven continuation chain");

    // A hostile ELF PT_LOAD whose virtual extent crosses UINT64_MAX is rejected
    // by the structured loader rather than publishing a partly clamped mapping.
    // Normal Open reports the failure; only the separate Open-as-Raw workflow may
    // reinterpret a recognized structured file as a blob.
    const std::string overflowElfPath = makeOverflowElf();
    BinaryFile overflowElf;
    CHECK(!overflowElf.load(overflowElfPath) && !overflowElf.loaded(),
          "hostile high-VA ELF is rejected without partial mappings");
    const auto overflowPlan = PlanListingRegions(overflowElf);
    CHECK(overflowPlan.empty(), "rejected ELF publishes no listing mappings");
    std::vector<uint8_t> ceilingBytes(4, 0x90);
    ByteDis ceilingDis;
    const auto ceiling = DecodeListingCodePage(
        ceilingBytes.data(), ceilingBytes.size(), UINT64_MAX - 1, 4, 0, 0, ceilingDis);
    CHECK(ceiling.instructions.size() == 2 &&
          ceiling.instructions[0].address == UINT64_MAX - 1 &&
          ceiling.instructions[1].address == UINT64_MAX,
          "page decoder clamps at UINT64_MAX without emitting wrapped addresses");
    std::remove(overflowElfPath.c_str());

    // Random access: request page 2 before either predecessor is materialized. The
    // production resolver advances from the proven section-root checkpoint through
    // both pages, so continuation bytes never become fake page-front instructions.
    std::vector<uint8_t> random(kListingCodePageBytes * 3 + 16, 0x90);
    random[kListingCodePageBytes * 2 - 3] = 0xF0;
    DecodedListingPage sectionRoot = DecodeListingCodePage(
        random.data(), random.size(), 0x200000, kListingCodePageBytes, 0, 15, crossDis);
    DecodedListingPage predecessor = DecodeListingCodePage(
        random.data() + kListingCodePageBytes, random.size() - kListingCodePageBytes,
        0x200000 + kListingCodePageBytes, kListingCodePageBytes,
        sectionRoot.nextPrefixSkip, 15, crossDis);
    CHECK(predecessor.nextPrefixSkip == 3,
          "far-page resolver derives a continuation checkpoint through the proven chain");
    DecodedListingPage farFirst = DecodeListingCodePage(
        random.data() + kListingCodePageBytes * 2, random.size() - kListingCodePageBytes * 2,
        0x200000 + kListingCodePageBytes * 2, kListingCodePageBytes,
        predecessor.nextPrefixSkip, 15, crossDis);
    CHECK(!farFirst.instructions.empty() && farFirst.instructions.front().address ==
          0x200000 + kListingCodePageBytes * 2 + 3,
          "page requested first suppresses predecessor-owned bytes deterministically");

    // Superseded descriptor jobs cancel at a bounded page checkpoint without
    // decoding or completing the remainder of a multi-megabyte region.
    const std::string largePath = "ds_listing_large_tmp.bin";
    {
        std::vector<uint8_t> large(kListingCodePageBytes * 600, 0x90);
        std::ofstream f(largePath, std::ios::binary);
        f.write((const char*)large.data(), (std::streamsize)large.size());
    }
    BinaryFile large;
    CHECK(large.loadRaw(largePath, 0x800000), "load large raw listing fixture");
    int cancelPolls = 0;
    rows = BuildListingRows(large, {}, [&] { ++cancelPolls; return true; });
    size_t plannedPages = 0;
    for (const auto& r : rows) plannedPages += r.type == ListingRowType::CodePage;
    CHECK(cancelPolls == 1 && plannedPages < 600,
          "descriptor planning cancellation drops a superseded large layout promptly");
    std::remove(largePath.c_str());

    // Xref planning shares positive code/data decisions but remains independent
    // of listing visibility. Adjacent Code/Unknown spans cannot split a decode.
    {
        const std::string scopePath = "ds_xref_scope_tmp.bin";
        std::vector<uint8_t> bytes(32, 0x11);
        bytes[0] = bytes[5] = bytes[10] = bytes[16] = 0xe8;
        { std::ofstream f(scopePath, std::ios::binary); f.write((const char*)bytes.data(), bytes.size()); }
        BinaryFile scopeBin;
        CHECK(scopeBin.loadRaw(scopePath, 0), "load VA-zero xref scope fixture");
        CodeDataMap map; map.imageRevision = scopeBin.imageRevision(); map.truncated = true;
        map.spans = {{0, 2, CodeDataKind::Code}, {2, 3, CodeDataKind::Unknown},
                     {5, 5, CodeDataKind::String}, {10, 1, CodeDataKind::Unknown},
                     {11, 5, CodeDataKind::Data}};
        XrefRangePlan plan = PlanXrefRanges(scopeBin, &map);
        CHECK(plan.classificationApplied && plan.classificationTruncated &&
              plan.classifiedDataBytes == 10 && plan.decodeBytes == 22 && plan.ranges.size() == 3,
              "positive islands are excluded while partial-map gaps remain decodable");
        CHECK(plan.ranges[0].address == 0 && plan.ranges[0].size == 5 &&
              plan.ranges[1].address == 10 && plan.ranges[1].size == 1 &&
              plan.ranges[2].address == 16 && plan.ranges[2].size == 16,
              "adjacent code-like spans merge and data islands split exact ranges");
        struct RefDis : ByteDis {
            bool decodeOne(const uint8_t* bytes, size_t count, uint64_t va, Instruction& out) override {
                if (!count) return false;
                if (bytes[0] == 0xe8) {
                    if (count < 5) return false;
                    out = {}; out.address = va; out.length = 5; out.mnemonic = "call";
                    out.flow.kind = FlowKind::DirectCall; out.flow.directTargetValid = true;
                    out.flow.directTarget = 0; return true;
                }
                return ByteDis::decodeOne(bytes, count, va, out);
            }
        } refDis;
        auto indexPlan = [&](const XrefRangePlan& ranges) {
            XrefIndex index;
            for (const XrefCodeRange& range : ranges.ranges) {
                size_t available = 0; const uint8_t* bytes = scopeBin.ptrFromVA(range.address, available);
                BuildXrefInto(index, bytes, static_cast<size_t>(range.size), range.address, refDis);
            }
            FinalizeXrefIndex(index); return index;
        };
        XrefIndex index = indexPlan(plan);
        CHECK(index.sources(0) && *index.sources(0) == std::vector<uint64_t>({0, 16}),
              "fake data calls and calls crossing an island never enter the xref index");
        auto changed = ApplyCodeDataOverrides(scopeBin,
            {{5, 5, PjDataKind::Code, {}}}, std::make_shared<CodeDataMap>(map));
        XrefRangePlan restored = PlanXrefRanges(scopeBin, changed.get());
        index = indexPlan(restored);
        CHECK(index.sources(0) && *index.sources(0) == std::vector<uint64_t>({0, 5, 16}) &&
              restored.scopeDigest != plan.scopeDigest && changed->scopeDigest == restored.scopeDigest,
              "analyst code override restores references with a distinct immutable scope");
        CodeDataMap stale = map; ++stale.imageRevision;
        CHECK(!PlanXrefRanges(scopeBin, &stale).classificationApplied &&
              PlanXrefRanges(scopeBin, &stale).decodeBytes == bytes.size(),
              "stale map cannot omit current image bytes");
        CodeDataMap malformed = map; malformed.spans.push_back({0, 4, CodeDataKind::Data});
        CHECK(!PlanXrefRanges(scopeBin, &malformed).classificationApplied,
              "overlapping or unsorted classification fails back to unknown scope");
        CHECK(PlanXrefRanges(scopeBin, &map, [] { return true; }).cancelled,
              "xref scope planning supports cancellation before decoding");
        std::remove(scopePath.c_str());
    }

    std::remove(path.c_str());
    if (g_fail) { std::printf("listing_layout_test: %d failure(s)\n", g_fail); return 1; }
    std::printf("listing_layout_test: all checks passed\n");
    return 0;
}
