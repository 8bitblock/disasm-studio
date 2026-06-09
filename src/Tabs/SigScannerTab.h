#pragma once
#include "ITab.h"
#include <string>
#include <vector>

namespace ds {

// Signature scanner: define byte-pattern signatures, scan the loaded image,
// and review results, current-scan progress, signature health, and the
// all-functions list.
class SigScannerTab final : public ITab {
public:
    const char* name() const override { return "Sig Scanner"; }
    void render(AppContext& ctx) override;

private:
    void scan(AppContext& ctx);
    void refreshHealth(AppContext& ctx);   // recompute each sig's match count vs the loaded binary

    struct Result   { uint64_t address; std::string sig; std::string module; };
    struct Sig      { std::string name; std::string pattern; std::string health; int count = -1; };
    struct Function { uint64_t address; std::string name; uint32_t size; };

    // Big enough to hold the largest signature buildSignature can hand off
    // (its 512-instruction x 16-byte cap -> ~24.5k chars of "XX " tokens), so a
    // multi-instruction "Create signature from selection" is never silently clipped.
    char patternInput_[32768] = "48 89 5C 24 ?? 57 48 83 EC 20";
    char sigName_[64]       = "fn_init";
    bool live_              = false;   // scan the attached process's memory instead of the file
    bool patternClipped_   = false;   // a handed-off signature was longer than patternInput_ (defensive; shows a warning)
    // Starter example patterns; health/count are computed against the loaded binary.
    std::vector<Sig>      sigs_{
        { "fn_init",     "48 89 5C 24 ?? 57 48 83 EC 20", "?", -1 },
        { "g_world_ptr", "48 8B 05 ?? ?? ?? ?? 48 85 C0", "?", -1 },
        { "tick_hook",   "E8 ?? ?? ?? ?? 84 C0 74",       "?", -1 },
    };
    std::vector<Result>   results_;
    bool                  truncated_ = false;   // results hit the display cap (4096)
    std::vector<Function> functions_;
    std::string           analyzeSummary_;
    char  fnFilter_[64] = "";
    int  activeSub_ = 0;
    float progress_ = 0.0f;
};

} // namespace ds
