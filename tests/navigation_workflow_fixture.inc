// Included by static_listing_actions_test.cpp after Fixture. Uses the existing
// production-object harness and SymbolService's deterministic backend seam.
#include <atomic>
#include <new>

struct NavigationSymbolGate {
    std::atomic<bool> entered{false};
    std::atomic<bool> release{false};
    std::atomic<int> calls{0};
};

class NavigationSymbolBackend final : public ISymbolServiceBackend {
public:
    explicit NavigationSymbolBackend(std::shared_ptr<NavigationSymbolGate> gate)
        : gate_(std::move(gate)) {}
    void configure(const SymbolResolverOptions&) override {}
    void reset() override {}
    bool useLive(void*) override { return true; }
    bool useBinary(const std::string&, uint64_t) override { return true; }
    void ensureModule(const SymbolModuleSpec&) override {}
    bool resolve(uint64_t, std::string&, uint64_t&) override { return false; }
    bool resolveDetailed(uint64_t, SymbolRecord&) override { return false; }
    bool addressOf(const std::string& name, uint64_t& address) override {
        if (name != "async_navigation" && name != "async_late") return false;
        ++gate_->calls;
        gate_->entered = true;
        for (int i = 0; i < 5000 && !gate_->release; ++i) Sleep(1);
        address = kTarget + 16;
        return gate_->release;
    }
private:
    std::shared_ptr<NavigationSymbolGate> gate_;
};

static void checkNavigationWorkflow(const std::string& path) {
    Fixture f(path);
    CHECK(f.tab->navigation_ == &f.ctx.staticNavigation());
    CHECK(!f.tab->canNavigateBack());
    frame([&] {
        f.tab->mainView_ = 3;
        f.tab->setStaticCursor(kTarget + 2);
        f.tab->navigateToStaticView(kTarget + 8, DocumentView::Pseudocode);
        CHECK(f.tab->mainView_ == 1 && f.tab->cursorVA_ == kTarget + 8);
        f.tab->navBack();
        CHECK(f.tab->mainView_ == 3 && f.tab->cursorVA_ == kTarget + 2);
        f.tab->navForward();
        CHECK(f.tab->mainView_ == 1 && f.tab->cursorVA_ == kTarget + 8);
        f.tab->navigateToFileOffset(f.ctx, 0);
        CHECK(f.tab->mainView_ == 2 && f.tab->hexCursorOff_ == 0);
        CHECK(f.tab->navigation_->current().addressSpace == DocumentAddressSpace::FileOffset);
        f.tab->navigateToStaticView(kTarget + 12);
        f.tab->navBack();
        CHECK(f.tab->mainView_ == 2 && f.tab->hexCursorOff_ == 0);
        CHECK(!f.tab->cursorValid_); // restored offset has not been mistaken for a VA
        f.tab->navBack();
        CHECK(f.tab->mainView_ == 1 && f.tab->cursorVA_ == kTarget + 8);
        f.tab->navigateToStaticView(kTarget + 4);
        CHECK(!f.tab->canNavigateForward());

        const uint64_t before = f.tab->cursorVA_;
        CHECK(!f.tab->submitGoto(f.ctx, "0x10garbage", false));
        CHECK(!f.tab->submitGoto(f.ctx, "0x10000000000000000", true));
        CHECK(!f.tab->submitGoto(f.ctx, "live:", false));
        CHECK(!f.tab->submitGoto(f.ctx, "live:0", false));
        CHECK(f.tab->cursorVA_ == before);
        CHECK(f.tab->submitGoto(f.ctx, "file:0", false));
        CHECK(f.tab->cursorValid_ && f.tab->cursorVA_ == 0 && !f.tab->cursorLive_);
        CHECK(f.tab->submitGoto(f.ctx, "0d16", true));
        CHECK(f.tab->cursorVA_ == 16);
        f.tab->names_[24] = "deadbeef";
        f.tab->symbolIndexSig_ = ~uint64_t{0};
        CHECK(f.tab->submitGoto(f.ctx, "deadbeef", false));
        CHECK(f.tab->cursorVA_ == 24); // hexadecimal-looking symbol remains a name
    });

    auto gate = std::make_shared<NavigationSymbolGate>();
    f.tab->symbols_.cancelAndWaitIdle();
    std::destroy_at(&f.tab->symbols_);
    std::construct_at(&f.tab->symbols_, SymbolServiceLimits{},
        SymbolServiceBackendFactory([gate] { return std::make_unique<NavigationSymbolBackend>(gate); }));
    f.tab->symbolContextValid_ = false;
    frame([&] { CHECK(!f.tab->submitGoto(f.ctx, "async_navigation", false)); });
    CHECK(f.tab->pendingGoto_.active);
    for (int i = 0; i < 1000 && !gate->entered; ++i) Sleep(1);
    CHECK(gate->entered);
    frame([&] { f.tab->pollPendingGoto(f.ctx); });
    CHECK(f.tab->pendingGoto_.active && f.tab->cursorVA_ == 24);
    gate->release = true;
    for (int i = 0; i < 1000 && f.tab->pendingGoto_.active; ++i) {
        frame([&] { f.tab->pollPendingGoto(f.ctx); });
        Sleep(1);
    }
    CHECK(!f.tab->pendingGoto_.active);
    CHECK(f.tab->cursorVA_ == kTarget + 16);
    CHECK(gate->calls == 1); // one Enter, one worker lookup, automatic completion

    gate->entered = false; gate->release = false;
    frame([&] { CHECK(!f.tab->submitGoto(f.ctx, "async_late", false)); });
    CHECK(f.tab->pendingGoto_.active);
    f.tab->setStaticCursor(kTarget + 32);
    frame([&] { f.tab->pollPendingGoto(f.ctx); });
    CHECK(!f.tab->pendingGoto_.active);
    gate->release = true;
    f.tab->symbols_.cancelAndWaitIdle();
    frame([&] { f.tab->pollPendingGoto(f.ctx); });
    CHECK(f.tab->cursorVA_ == kTarget + 32);
}
