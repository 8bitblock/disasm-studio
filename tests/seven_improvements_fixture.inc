// Production-object regressions: no target process or user project is used.
namespace ds {
// Explicit template instantiation is exempt from member access checking. Keep
// this fixture's private member pointer here without changing the app's API or
// class definition; the pointer retains the production method's access mangling.
template<class Tag, typename Tag::type Member>
struct FixturePrivateMember {
    friend typename Tag::type fixtureMember(Tag) { return Member; }
};
struct ActiveDocumentMember {
    using type = DocumentContext& (AppContext::*)();
    friend type fixtureMember(ActiveDocumentMember);
};
template struct FixturePrivateMember<ActiveDocumentMember,
    static_cast<ActiveDocumentMember::type>(&AppContext::activeStaticDocument)>;
struct AppContextFixtureAccess {
    static DocumentContext& active(AppContext& ctx) {
        return (ctx.*fixtureMember(ActiveDocumentMember{}))();
    }
};
}

static void checkNotesAndTypesPreservation(const std::string& path) {
    Fixture f(path);
    const std::string note = std::string(20000, 'n') + "\nUTF-8: \xCE\xA9 \xF0\x9F\x94\x8D\n";
    f.ctx.staticProject().notes = note;
    f.tab->loadProjectState(f.ctx);
    CHECK(f.tab->notes_ == note);
    frame([&] { f.tab->saveProjectState(f.ctx); });
    CHECK(f.ctx.staticProject().notes == note);
    ProjectState reopened;
    CHECK(DeserializeProject(SerializeProject(f.ctx.staticProject()), reopened));
    CHECK(reopened.notes == note);
    f.tab->notes_ += "edited tail";
    f.tab->notesDirty_ = true;
    CHECK(f.tab->prepareDocumentTransition(f.ctx, false, f.tab->typeStatus_));
    CHECK(f.ctx.staticProject().notes == note + "edited tail");

    auto& draft = f.tab->typeDraft_;
    draft = {}; draft.id = 1; draft.name = "kept_type";
    draft.kind = TypeKind::Integer; draft.sizeBytes = 4;
    f.tab->typeDraftDirty_ = true;
    f.tab->typeDraftGeneration_ = f.ctx.staticImageGeneration();
    f.tab->typeDraftImage_ = f.tab->investigationImageSerial_;
    std::string error;
    CHECK(!f.tab->prepareDocumentTransition(f.ctx, true, error));
    CHECK(f.tab->typeDraftDirty_ && error.find("Types") != std::string::npos);
    CHECK(!f.ctx.clearStaticImage(&error));
    CHECK(f.ctx.staticBinary().loaded() && f.tab->typeDraftDirty_);
    CHECK(f.tab->prepareDocumentTransition(f.ctx, false, error));
    CHECK(f.tab->typeDraft_.name == "kept_type");

    // Analysis presentation changes do not replace a dirty draft.
    ++f.tab->investigationImageSerial_;
    f.tab->focusTypesTab_ = true;
    auto paintTypes = [&] {
        frame([&] {
            if (ImGui::BeginTabBar("draft_types")) {
                f.tab->renderTypeWorkbench(f.ctx);
                ImGui::EndTabBar();
            }
        });
    };
    paintTypes(); paintTypes();
    CHECK(f.tab->typeDraftDirty_ && f.tab->typeDraft_.name == "kept_type");
    draft.sizeBytes = 3; // unsupported scalar size, save must be atomic
    CHECK(!f.tab->saveTypeDraft(f.ctx, false, error));
    CHECK(f.tab->typeDraftDirty_ && f.ctx.staticProject().typeRegistry.types.empty());
    draft.sizeBytes = 4;
    CHECK(f.tab->saveTypeDraft(f.ctx, false, error));
    CHECK(!f.tab->typeDraftDirty_);
    CHECK(FindType(f.ctx.staticProject().typeRegistry, 1) != nullptr);
    CHECK(f.tab->prepareDocumentTransition(f.ctx, true, error));

    // A failed durable save keeps the previous registry and the editable draft.
    struct TypeStoreState { bool fail = true; size_t writes = 0; ProjectState saved; };
    const auto store = std::make_shared<TypeStoreState>();
    auto* owner = &AppContextFixtureAccess::active(f.ctx);
    const DocumentId ownerId = owner->id();
    owner->setSaveCallback([store](const BinaryFile&, const ProjectState& state, std::string& why) {
        ++store->writes;
        if (store->fail) { why = "injected Types save failure"; return false; }
        store->saved = state;
        return true;
    });
    draft.name = "retry_type";
    f.tab->typeDraftDirty_ = true;
    f.ctx.setTypeDraftPending(ownerId, true);
    CHECK(!f.tab->saveTypeDraft(f.ctx, true, error));
    CHECK(error == "injected Types save failure");
    CHECK(f.tab->hasUnsavedTypeDraft() && owner->typeDraftPending());
    CHECK(FindType(owner->project().typeRegistry, 1)->name == "kept_type");
    store->fail = false;
    CHECK(f.tab->saveTypeDraft(f.ctx, true, error));
    CHECK(!f.tab->hasUnsavedTypeDraft() && !owner->typeDraftPending());
    CHECK(FindType(store->saved.typeRegistry, 1)->name == "retry_type");

    // Save the original child while another document owns AppContext's active aliases.
    const std::string otherPath = path + ".inactive-types.raw";
    { std::ofstream other(otherPath, std::ios::binary); other.put('\x90'); other.put('\xC3'); }
    CHECK(f.ctx.beginRawLoadPath(otherPath, 0, Arch::X64, 0, {}, {}));
    bool otherLoaded = false;
    for (int i = 0; i < 1000; ++i) {
        const auto loaded = f.ctx.pollBinaryLoad();
        if (loaded.completed) { otherLoaded = loaded.success; break; }
        Sleep(2);
    }
    CHECK(otherLoaded && f.ctx.applyPendingDocumentCommand().success);
    CHECK(f.ctx.staticDocumentId() != ownerId);
    draft.name = "inactive_saved_type";
    f.tab->typeDraftDirty_ = true;
    f.ctx.setTypeDraftPending(ownerId, true);
    CHECK(f.tab->saveTypeDraft(f.ctx, true, error));
    CHECK(FindType(owner->project().typeRegistry, 1)->name == "inactive_saved_type");
    CHECK(FindType(store->saved.typeRegistry, 1)->name == "inactive_saved_type");
    CHECK(f.ctx.staticProject().typeRegistry.types.empty());
    CHECK(f.ctx.queueActivateStaticDocument(ownerId));
    CHECK(f.ctx.applyPendingDocumentCommand().success);

    // Live-module images intentionally lack a durable sidecar: a closing Save
    // must fail explicitly rather than clearing the draft and deleting its owner.
    BinaryFile mapped;
    CHECK(mapped.loadFromMemory(std::vector<uint8_t>(128, 0x90), 0x180000000ull,
                               "ephemeral-types-fixture"));
    CHECK(owner->replaceImage(std::move(mapped), {}, Engine::Zydis, Arch::X64,
                              DocumentInstallPersistence::Ephemeral));
    f.tab->synchronizeDocumentImage(f.ctx);
    draft = {}; draft.id = 1; draft.name = "live_draft";
    draft.kind = TypeKind::Integer; draft.sizeBytes = 4;
    f.tab->typeDraftDirty_ = true;
    f.tab->typeDraftGeneration_ = owner->imageGeneration();
    f.ctx.setTypeDraftPending(ownerId, true);
    const size_t writesBeforeEphemeral = store->writes;
    CHECK(!f.tab->saveTypeDraft(f.ctx, true, error));
    CHECK(error.find("no persistent project sidecar") != std::string::npos);
    CHECK(store->writes == writesBeforeEphemeral);
    CHECK(f.tab->hasUnsavedTypeDraft() && owner->typeDraftPending());
    CHECK(owner->project().typeRegistry.types.empty());
    f.tab->discardTypeDraft(f.ctx);
}

static void checkCompletePinnedReferences(const std::string& path) {
    Fixture f(path);
    auto result = referenceResult(f);
    auto& sources = result.xref->toTarget[0];
    sources.clear();
    for (size_t i = 0; i < 32768; ++i) sources.push_back(kTarget + 2 * i);
    result.xref->acceptedEdges = sources.size();
    CHECK(f.tab->adoptStaticXrefResult(f.ctx, result));
    f.tab->startXrefSearch(f.ctx, 0, false);
    CHECK(f.tab->pinnedXrefSources().size() == 32768);
    CHECK(f.tab->pinnedXrefSources().data() == f.ctx.staticAnalysisCache().xrefs->sources(0)->data());
    const uint64_t last = sources.back();
    std::snprintf(f.tab->xrefFilter_, sizeof(f.tab->xrefFilter_), "0x%llX", (unsigned long long)last);
    f.tab->advancePinnedXrefFilter(f.ctx, 64);
    CHECK(f.tab->xrefFilterCursor_ <= 64);
    for (size_t frame = 0; frame < 1024 && f.tab->xrefFilterCursor_ < sources.size(); ++frame)
        f.tab->advancePinnedXrefFilter(f.ctx, 512);
    CHECK(f.tab->xrefVisible_ == std::vector<size_t>{32767});
    CHECK(f.tab->followXrefSource(f.ctx, 32767));
    CHECK(f.tab->cursorVA_ == last && f.tab->mainView_ == 0);
    f.tab->xrefFilter_[0] = 0;
    f.tab->advancePinnedXrefFilter(f.ctx);
    CHECK(f.tab->xrefVisible_.empty()); // unfiltered view indexes the shared vector directly
    CHECK(f.tab->xrefFilterCursor_ == 32768);
    // Same-identity publication replacement must update even a completed pin.
    auto replacement = referenceResult(f);
    replacement.xref->toTarget[0] = {kTarget + 12};
    replacement.xref->acceptedEdges = 1;
    CHECK(f.tab->adoptStaticXrefResult(f.ctx, replacement));
    f.tab->updateStaticXrefSearch(f.ctx);
    CHECK(f.tab->pinnedXrefSources() == std::vector<uint64_t>{kTarget + 12});
    f.ctx.staticAnalysis().bumpEpoch();
    CHECK(!f.tab->followXrefSource(f.ctx, 0));
    CHECK(f.tab->pinnedXrefSources().empty() && !f.tab->xrefFileHits_);
}

static void checkTypesClosePrompt(const std::string& path) {
    Fixture f(path);
    BinaryViewHostTab host;
    auto child = std::make_unique<BinaryViewTab>(f.ctx.staticDocumentId());
    child->synchronizeDocumentImage(f.ctx);
    child->typeDraft_ = {};
    child->typeDraft_.id = 1; child->typeDraft_.name = "unsaved";
    child->typeDraft_.kind = TypeKind::Integer; child->typeDraft_.sizeBytes = 4;
    child->typeDraftDirty_ = true;
    child->typeDraftGeneration_ = f.ctx.staticImageGeneration();
    auto* retained = child.get();
    const auto id = f.ctx.staticDocumentId();
    host.children_.emplace(id.value, std::move(child));
    std::string error;
    CHECK(!host.prepareDocumentTransition(f.ctx, id, true, error));
    CHECK(host.pendingTypeDraft_ == id);
    frame([&] { CHECK(!host.renderTypeDraftPrompt(f.ctx)); });
    frame([&] { CHECK(!host.renderTypeDraftPrompt(f.ctx)); });
    auto* window = ImGui::FindWindowByName("Unsaved Types definition");
    CHECK(window != nullptr);
    if (window) {
        ImGui::ActivateItemByID(window->GetID("Cancel"));
        frame([&] { CHECK(!host.renderTypeDraftPrompt(f.ctx)); });
        CHECK(!host.pendingTypeDraft_ && retained->hasUnsavedTypeDraft());
    }
    CHECK(!host.prepareTypeDraftsForExit(f.ctx));
    frame([&] { CHECK(!host.renderTypeDraftPrompt(f.ctx)); });
    if (window) {
        ImGui::ActivateItemByID(window->GetID("Save"));
        bool resumeExit = false;
        frame([&] { resumeExit = host.renderTypeDraftPrompt(f.ctx); });
        CHECK(resumeExit && !retained->hasUnsavedTypeDraft());
    }
    CHECK(host.prepareTypeDraftsForExit(f.ctx));
    retained->discardTypeDraft(f.ctx);
}
