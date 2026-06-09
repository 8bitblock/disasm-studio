#pragma once
#include "ITab.h"
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

// Memory tools: scanner (with scan options), viewer/editor, a tree-view
// memory browser, and a persistent address table (Cheat-Engine style). When a
// process is attached (via Communications) these operate on its live memory
// through Debugger::readMemory / writeMemory / regions().
class MemoryToolsTab final : public ITab {
public:
    const char* name() const override { return "Memory Tools"; }
    void render(AppContext& ctx) override;

    enum ValueType { VT_Byte, VT_Word, VT_Dword, VT_Qword, VT_Float, VT_Double };
    enum ScanType  { ST_Exact, ST_Bigger, ST_Smaller, ST_Changed, ST_Unchanged, ST_Unknown };

private:
    void renderScanner(AppContext& ctx);
    void renderViewerEditor(AppContext& ctx);
    void renderBrowser(AppContext& ctx);
    void renderAddressTable(AppContext& ctx);

    void firstScan(AppContext& ctx);
    void nextScan(AppContext& ctx);

    // prevBits holds the raw little-endian value captured at the last scan.
    struct ScanResult { uint64_t address; uint64_t prevBits; };
    struct TableEntry { bool active; std::string desc; uint64_t address; int type; std::string value; bool frozen; };

    int   valueType_ = VT_Dword;
    int   scanType_  = ST_Exact;
    char  scanValue_[64] = "100";
    bool  hexInput_  = false;
    bool  unsignedMode_ = false;  // interpret integers as unsigned for bigger/smaller compares
    bool  firstScanDone_ = false;
    size_t totalFound_ = 0;
    std::string scanStatus_;
    // Scan results, kept sorted by ascending address (an "index") so next-scan
    // re-reads them in address order and the table renders deterministically.
    std::vector<ScanResult> results_;

    std::vector<TableEntry> table_;
    char  viewAddr_[32] = "0";
    char  newAddr_[32]  = "";
};

} // namespace ds
