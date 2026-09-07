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

static void checkLiveGotoWorkflow(Fixture& f) {
    // A paused snapshot is sufficient for navigation: no game process, debugger
    // attachment, or preferred-base translation participates in these checks.
    DbgSnapshot live;
    live.state = DbgState::Paused;
    live.pid = 777;
    live.sessionGeneration = 8;
    live.is32 = true;
    DbgModule peggle;
    peggle.name = "Peggle.exe";
    peggle.path = "C:\\Games\\Peggle\\Peggle.exe";
    peggle.base = 0x00400000;
    peggle.size = 0x00200000;
    peggle.loadGeneration = 1;
    live.modules.push_back(peggle);
    f.tab->frameSnap_ = &live;

    frame([&] {
        const auto expectLive = [&](uint64_t address) {
            CHECK(f.tab->mainView_ == 4);
            CHECK(f.tab->cursorValid_ && f.tab->cursorLive_ && f.tab->cursorVA_ == address);
            const auto& location = f.tab->navigation_->current();
            CHECK(location.valid && location.va == address);
            CHECK(location.addressSpace == DocumentAddressSpace::Live);
            CHECK(location.view == DocumentView::LiveAssembly);
            CHECK(location.target.pid == live.pid &&
                  location.target.sessionGeneration == live.sessionGeneration);
        };
        const auto expectRejected = [&](const char* query, bool popup = false) {
            const auto current = f.tab->navigation_->current();
            const auto back = f.tab->navigation_->backStack();
            const auto forward = f.tab->navigation_->forwardStack();
            const uint64_t cursor = f.tab->cursorVA_;
            const bool valid = f.tab->cursorValid_, cursorLive = f.tab->cursorLive_;
            const int view = f.tab->mainView_;
            CHECK(!f.tab->submitGoto(f.ctx, query, popup));
            CHECK(!f.tab->pendingGoto_.active && !f.tab->gotoStatus_.empty());
            CHECK(f.tab->cursorVA_ == cursor && f.tab->cursorValid_ == valid &&
                  f.tab->cursorLive_ == cursorLive && f.tab->mainView_ == view);
            CHECK(f.tab->navigation_->current() == current);
            CHECK(f.tab->navigation_->backStack() == back);
            CHECK(f.tab->navigation_->forwardStack() == forward);
        };

        // The shared toolbar and Ctrl+G both route plain addresses according to
        // the visible representation, including runtime addresses outside FILE.
        f.tab->mainView_ = 4;
        CHECK(f.tab->submitGoto(f.ctx, "00401234", false));
        expectLive(0x00401234);
        CHECK(f.tab->submitGoto(f.ctx, "0x00402345", true));
        expectLive(0x00402345);
        f.tab->navBack();
        expectLive(0x00401234);
        CHECK(f.tab->canNavigateForward());
        expectRejected("0x100000000", true); // WOW64 address range
        expectRejected("0x401234tail");
        f.tab->navForward();
        expectLive(0x00402345);

        CHECK(f.tab->submitGoto(f.ctx, "FILE:0x20", true));
        CHECK(f.tab->mainView_ == 0 && !f.tab->cursorLive_ && f.tab->cursorVA_ == 0x20);
        CHECK(f.tab->submitGoto(f.ctx, "LIVE:00401234", false));
        expectLive(0x00401234);
        CHECK(f.tab->submitGoto(f.ctx, "VA:0x30", false));
        CHECK(f.tab->mainView_ == 0 && !f.tab->cursorLive_ && f.tab->cursorVA_ == 0x30);
        CHECK(f.tab->submitGoto(f.ctx, "0d16", true));
        CHECK(!f.tab->cursorLive_ && f.tab->cursorVA_ == 16);

        // Cheat Engine's module+offset form is explicitly runtime, even when
        // entered from FILE Assembly. Unsuffixed offsets are hexadecimal.
        CHECK(f.tab->submitGoto(f.ctx, "peggle.exe+1234", false));
        expectLive(peggle.base + 0x1234);
        CHECK(f.tab->submitGoto(f.ctx, "\"PeGGLe.ExE\"+1A", true));
        expectLive(peggle.base + 0x1A);
        CHECK(f.tab->submitGoto(f.ctx, "LIVE:\"C:\\Games\\Peggle\\Peggle.exe\"+2A", true));
        expectLive(peggle.base + 0x2A);
        live.modules.front().path = "C:\\Games\\operator+mods\\Peggle.exe";
        CHECK(f.tab->submitGoto(f.ctx, "LIVE:\"C:\\Games\\operator+mods\\Peggle.exe\"+AB", true));
        expectLive(peggle.base + 0xAB);
        live.modules.front().path = peggle.path;
        CHECK(f.tab->submitGoto(f.ctx, "peggle.exe+0", false));
        expectLive(peggle.base);
        CHECK(f.tab->submitGoto(f.ctx, "peggle.exe+1fffff", false));
        expectLive(peggle.base + peggle.size - 1);

        // A stale or malformed module expression must never become a fuzzy
        // FILE symbol match or enqueue an asynchronous name lookup.
        f.tab->names_[24] = "missing.dll+1234";
        f.tab->symbolIndexSig_ = ~uint64_t{0};
        expectRejected("missing.dll+1234");
        expectRejected("peggle+1234"); // basename matching retains the extension
        expectRejected("peggle.exe+");
        expectRejected("peggle.exe+1234tail");
        expectRejected("peggle.exe+200000");
        expectRejected("FILE:peggle.exe+1234");
        expectRejected("VA:peggle.exe+1234", true);

        DbgModule duplicate = peggle;
        duplicate.path = "C:\\Other\\Peggle.exe";
        duplicate.base = 0x00800000;
        duplicate.loadGeneration = 2;
        live.modules.push_back(duplicate);
        expectRejected("peggle.exe+1234");
        CHECK(f.tab->submitGoto(f.ctx, "\"c:\\games\\peggle\\peggle.exe\"+3B", false));
        expectLive(peggle.base + 0x3B); // exact full path disambiguates the basename
        live.modules.erase(live.modules.begin());
        CHECK(f.tab->submitGoto(f.ctx, "peggle.exe+1234", true));
        expectLive(duplicate.base + 0x1234); // current frame's mapping, never a stale base
        expectRejected("\"C:\\Games\\Peggle\\Peggle.exe\"+1234");

        live.modules.front().base = 0x100000000ULL;
        expectRejected("peggle.exe+0");
        live.is32 = false;
        live.modules.front().base = UINT64_MAX - 15;
        live.modules.front().size = 0x100;
        expectRejected("peggle.exe+10"); // checked base-plus-offset overflow
        live.modules.front().base = 0x00400000;
        live.modules.front().size = 0;
        expectRejected("peggle.exe+0"); // no known mapped extent

        live.state = DbgState::Detached;
        expectRejected("LIVE:00401234");
        expectRejected("peggle.exe+1234");
        f.tab->mainView_ = 4;
        expectRejected("00401234", true);
    });
    f.tab->frameSnap_ = &f.detached;
}

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
    checkLiveGotoWorkflow(f);
}
