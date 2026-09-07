// Actual Binary View methods, linked from the Release application objects.
// The frame identity is synthetic; the real debugger remains detached.
static void checkTraceWorkflow(const std::string& path) {
    Fixture f(path);
    f.detached.state = DbgState::Paused;
    f.detached.pid = 77; f.detached.sessionGeneration = 123;
    DbgModule module;
    module.base = 0x10000; module.size = 128 * 4096;
    module.name = "trace_fixture"; module.path = f.path; module.loadGeneration = 4;
    f.detached.modules.push_back(module);
    DocumentRuntimeMetadata::LiveImageIdentity identity;
    identity.valid = true; identity.pid = f.detached.pid;
    identity.sessionGeneration = f.detached.sessionGeneration;
    identity.moduleBase = module.base; identity.moduleSize = module.size;
    identity.moduleName = module.name; identity.modulePath = module.path;
    identity.moduleLoadGeneration = module.loadGeneration;
    f.ctx.setStaticDebugImageIdentity(identity);

    auto initializePlan = [&] {
        f.tab->cancelTraceSeedPlan(f.ctx, false);
        f.tab->traceSeedPlanning_ = true;
        f.tab->traceSeedTarget_ = {f.detached.pid, f.detached.sessionGeneration};
        f.tab->traceSeedFunctionPos_ = 0;
        f.tab->traceSeedSkippedPages_ = f.tab->traceSeedInvalidRows_ = 0;
        f.tab->tracePrevEndsBlock_ = true;
        f.tab->traceSeedStreamExact_ = false;
        f.tab->tracePlanImageRevision_ = f.ctx.staticBinary().imageRevision();
        f.tab->tracePlanListingSig_ = f.tab->listingSig(f.ctx);
        f.tab->tracePlanTopology_ = f.tab->listingTopologyGeneration_;
        f.tab->tracePlanDecoder_ = AnalysisIsaSignature(f.ctx.staticDecoderConfig());
        f.tab->tracePlanModuleBase_ = module.base;
        f.tab->tracePlanModuleSize_ = module.size;
        f.tab->tracePlanModuleGeneration_ = module.loadGeneration;
    };
    // Neither a million data descriptors nor a large root list can be scanned
    // in a single frame. The first test previously ran the whole descriptor list.
    f.tab->listRows_.assign(8192, BinaryViewTab::ListRow{});
    for (auto& row : f.tab->listRows_) row.type = ListingRowType::DataDirective;
    initializePlan();
    frame([&] { f.tab->advanceTraceSeedPlan(f.ctx); });
    CHECK(f.tab->traceSeedPlanning_);
    CHECK(f.tab->traceSeedRow_ == BinaryViewTab::kTraceRowsPerFrame);
    f.tab->functions_.assign(4096, BinaryViewTab::Func{});
    initializePlan();
    frame([&] { f.tab->advanceTraceSeedPlan(f.ctx); });
    CHECK(f.tab->traceSeedFunctionPos_ == BinaryViewTab::kTraceRowsPerFrame);
    CHECK(f.tab->traceSeedRow_ == 0);
    f.tab->functions_.clear();

    // An exact page may contain decoder fallback bytes. Neither those bytes
    // nor a root pointing at them is sufficient authority for a trace site.
    f.layout();
    auto* page = f.tab->ensureListingCodePage(f.ctx, 0);
    CHECK(page != nullptr);
    if (page) {
        page->boundaryExact = true;
        page->insns.clear();
        for (uint64_t at = 0; at < 4096; at += 2) {
            Instruction in;
            in.address = at; in.length = 2; in.mnemonic = at == 8 ? "db" : "mov";
            if (at == 4) in.flow.kind = FlowKind::DirectCall;
            page->insns.push_back(in);
        }
        initializePlan();
        frame([&] { f.tab->advanceTraceSeedPlan(f.ctx); });
        CHECK(f.tab->traceSeedPlanning_);
        CHECK(f.tab->traceSeedInvalidRows_ == 1);
        CHECK(f.tab->traceSeedDedup_.count(0));
        CHECK(!f.tab->traceSeedDedup_.count(8));
        CHECK(!f.tab->traceSeedDedup_.count(10)); // fallback does not prove later alignment
        CHECK(f.tab->traceSeedDedup_.count(6)); // typed-only call continuation
        CHECK(f.tab->traceSeedSpans_.size() == 2);
        CHECK(f.tab->traceSeedSpans_[0].begin == 0 && f.tab->traceSeedSpans_[0].end == 6);
        CHECK(f.tab->traceSeedSpans_[1].begin == 6 && f.tab->traceSeedSpans_[1].end == 8);
        frame([&] { f.tab->advanceTraceSeedPlan(f.ctx); }); // finish first page
        frame([&] { f.tab->advanceTraceSeedPlan(f.ctx); }); // inherited next-page prefix
        CHECK(!f.tab->traceSeedDedup_.count(4096));
        CHECK(f.tab->traceSeedSpans_.back().end == 8);
        f.tab->traceSeedValidating_ = true;
        f.tab->traceSeedCandidatePos_ = 0;
        f.tab->traceSeedCandidates_ = {{0, 8}, {0, 10}, {1, 4096}, {2, 8192},
                                       {3, 12288}, {4, 16384}};
        frame([&] { f.tab->advanceTraceSeedPlan(f.ctx); });
        CHECK(f.tab->traceSeedPlanning_); // validation yields after four groups
        CHECK(!f.tab->traceSeedDedup_.count(8) && !f.tab->traceSeedDedup_.count(10));
        CHECK(!f.tab->traceSeedDedup_.count(4096));
        // A separate trusted root can recover authority, without blessing the
        // malformed prefix in the preceding page or its candidate addresses.
        f.tab->codePageRootCheckpoints_.insert(1);
        initializePlan();
        f.tab->traceSeedRow_ = 1;
        frame([&] { f.tab->advanceTraceSeedPlan(f.ctx); });
        CHECK(f.tab->traceSeedDedup_.count(4096));
        CHECK(f.tab->traceSeedSpans_.front().begin == 4096);
    }

    // Index replacement or decoder/module changes invalidate the entire plan
    // before a previously captured descriptor index can be dereferenced.
    initializePlan();
    ++f.tab->listingTopologyGeneration_;
    frame([&] { f.tab->advanceTraceSeedPlan(f.ctx); });
    CHECK(!f.tab->traceSeedPlanning_);
    initializePlan();
    ++f.tab->tracePlanDecoder_;
    frame([&] { f.tab->advanceTraceSeedPlan(f.ctx); });
    CHECK(!f.tab->traceSeedPlanning_);
    initializePlan();
    ++f.detached.modules[0].loadGeneration;
    frame([&] { f.tab->advanceTraceSeedPlan(f.ctx); });
    CHECK(!f.tab->traceSeedPlanning_);
    f.detached.modules[0].loadGeneration = module.loadGeneration;

    TraceCoverageSnapshot trace;
    trace.active = true; trace.generation = 9; trace.revision = 27;
    trace.instructions = {{module.base, 1}};
    trace.blocks = {{module.base, 1}};
    f.ctx.frameTraceCoverageSnapshot = &trace;
    auto bindCoverage = [&] {
        f.tab->traceBlockGeneration_ = trace.generation;
        f.tab->traceBlockImageRevision_ = f.ctx.staticBinary().imageRevision();
        f.tab->traceBlockDecoder_ = AnalysisIsaSignature(f.ctx.staticDecoderConfig());
        f.tab->traceBlockTarget_ = {f.detached.pid, f.detached.sessionGeneration};
        f.tab->traceBlockModuleBase_ = module.base;
        f.tab->traceBlockModuleGeneration_ = module.loadGeneration;
        f.tab->traceBlockStartsFile_ = {0, 100};
        f.tab->traceBlockStartsLive_ = {module.base, module.base + 100};
        f.tab->traceBlockSpansFile_ = {{0, 8}, {100, 108}};
        f.tab->traceBlockSpansLive_ = {{module.base, module.base + 8},
                                      {module.base + 100, module.base + 108}};
        f.tab->traceDisplayRevision_ = ~0ull;
        f.tab->refreshTraceDisplay(f.ctx);
    };
    bindCoverage();
    CHECK(f.tab->traceFileExecuted(0));
    CHECK(f.tab->traceFileExecuted(6));
    CHECK(!f.tab->traceFileExecuted(8));
    CHECK(!f.tab->traceFileExecuted(50)); // unknown/data/fold gap
    CHECK(!f.tab->traceFileExecuted(100));
    CHECK(f.tab->traceLiveExecuted(module.base + 6));
    CHECK(!f.tab->traceLiveExecuted(module.base + 50));
    // The trace revision need not change when the image/decoder is replaced.
    ++f.tab->traceBlockImageRevision_;
    f.tab->refreshTraceDisplay(f.ctx);
    CHECK(!f.tab->traceFileExecuted(6));
    CHECK(!f.tab->traceFileExecuted(0));
    CHECK(!f.tab->traceLiveExecuted(module.base + 6));
    CHECK(f.tab->traceLiveExecuted(module.base)); // point observation remains historical evidence
    bindCoverage();
    ++f.detached.modules[0].loadGeneration;
    f.tab->refreshTraceDisplay(f.ctx);
    CHECK(!f.tab->traceFileExecuted(0));
    CHECK(!f.tab->traceFileExecuted(6));
    CHECK(f.tab->traceBlockSpansFile_.empty());
    f.ctx.frameTraceCoverageSnapshot = nullptr;
}
