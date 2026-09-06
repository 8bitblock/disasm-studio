#include "Core/InvestigationIndex.h"

#include <cstdio>
#include <limits>
#include <string>
#include <vector>

using namespace ds;

namespace {
int failures = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++failures; } } while (0)

InvestigationAddress File(uint64_t address) {
    return { InvestigationIdentity::File, true, address };
}

InvestigationAddress Live(uint64_t address) {
    return { InvestigationIdentity::Live, true, address };
}

const InvestigationResult* FindCategory(const InvestigationSearchResult& result,
                                         InvestigationCategory category) {
    for (const auto& item : result.results) {
        if (item.category == category) return &item;
    }
    return nullptr;
}

const InvestigationResult* FindAuthorizationFlow(
    const InvestigationSearchResult& result, const char* flowId) {
    for (const auto& item : result.results) {
        if (item.category == InvestigationCategory::Authorization &&
            item.focusId == flowId) return &item;
    }
    return nullptr;
}

void CheckCategory(const InvestigationIndex& index, const char* query,
                   InvestigationCategory category, const char* message) {
    const auto result = index.search(query);
    CHECK(result.complete && FindCategory(result, category), message);
}
}

int main() {
    InvestigationSnapshot snapshot;
    snapshot.functions.push_back({ File(0), "CreateFileW", "HANDLE CreateFileW(...) intern", "loader symbol" });
    snapshot.functions.push_back({ File(0x1010), "CreateFileWorker", "void worker()", "analyst name" });
    snapshot.functions.push_back({ File(0x1020), "CrateFleW", "void fuzzy()", "heuristic fixture" });
    snapshot.strings.push_back({ File(0x2000), "license accepted", "UTF-8", "string scan" });
    snapshot.imports.push_back({ File(0x3000), "RegOpenKeyExW", "ADVAPI32.dll", false, "PE import" });
    snapshot.comments.push_back({ File(0x4000), "decrypt payload here", "analyst comment" });
    snapshot.resources.push_back({ File(0x5000), "RT_MANIFEST", "requestedExecutionLevel", "en-US", "PE resource" });
    snapshot.byteResults.push_back({ File(0x6000), "48 8B ?? DE AD", "masked byte match" });
    snapshot.xrefs.push_back({ File(0x7000), File(0), "call to image entry", "direct call xref" });
    snapshot.liveModules.push_back({ Live(0), 0x1000, "zero.dll", "C:\\fixtures\\zero.dll", "debug module snapshot" });
    snapshot.networkTrail.push_back({ File(0), 0, true,
                                      "https://reply.example/activate",
                                      "host + request route", "high-confidence correlated endpoint" });
    snapshot.networkTrail.push_back({ { InvestigationIdentity::File, false, 0 }, 0x90, true,
                                      "overlay.example", "overlay host",
                                      "file-only endpoint evidence" });
    snapshot.authorization.push_back({ File(0), 0, true, "auth-flow-zero",
        "remembered access startup gate", "Startup gate", "Likely allow",
        "Registry HKCU\\Software\\Crackme / licensed",
        "registry state read reaches the allow successor", true });
    snapshot.authorization.push_back({ File(0x8010), 0, false, "auth-flow-deny",
        "failure outcome", "Deny path", "Likely deny", {},
        "process termination supports the failure branch" });
    snapshot.authorization.push_back({ File(0x8020), 0, false, "auth-flow-pro",
        "startup entitlement · pro", "Startup gate", "Likely allow", {},
        "exact persistent identity token labels this entitlement as pro" });
    snapshot.authorization.push_back({ File(0x8030), 0, false, "auth-flow-premium",
        "startup entitlement · premium", "Startup gate", "Likely allow", {},
        "exact persistent identity token labels this entitlement as premium" });
    snapshot.authorization.push_back({ File(0x8040), 0, false, "auth-flow-validated",
        "startup entitlement · validated", "Startup gate", "Likely allow", {},
        "exact persistent identity token labels this entitlement as validated" });
    snapshot.authorization.push_back({ File(0x8050), 0x250, true, "local:0",
        "local:0 · Input read", "Input read", "Unknown", {},
        "gate source Local credential/input check | expected value \"swordfish\"" });
    snapshot.authorization.push_back({ File(0x8060), 0x260, true, "state:7",
        "unlinked read · File / JSON format hint C:\\ProgramData\\Acme\\state.json",
        "Persistent state operation", "Unknown",
        "File / JSON format hint C:\\ProgramData\\Acme\\state.json",
        "kernel32!ReadFile exact operation; no exact remembered-access link" });
    snapshot.recentQueries.push_back({ InvestigationIdentity::File, "previous needle" });

    const auto built = InvestigationIndex::Build(snapshot);
    CHECK(built.complete && built.index, "complete fixture builds an immutable index");
    CHECK(!built.cancelled && built.index && built.index->size() == 20,
          "every supplied category record is retained");
    if (!built.index) return 1;
    const InvestigationIndex& index = *built.index;

    // Every source category is independently searchable.
    CheckCategory(index, "license accepted", InvestigationCategory::StringLiteral,
                  "string category is indexed");
    CheckCategory(index, "regopenkeyexw", InvestigationCategory::Import,
                  "import category is indexed case-insensitively");
    CheckCategory(index, "decrypt payload", InvestigationCategory::Comment,
                  "comment category is indexed");
    CheckCategory(index, "requestedExecutionLevel", InvestigationCategory::Resource,
                  "resource category is indexed");
    CheckCategory(index, "DE AD", InvestigationCategory::ByteResult,
                  "byte-result category is indexed");
    CheckCategory(index, "image entry", InvestigationCategory::Xref,
                  "xref category is indexed");
    CheckCategory(index, "zero.dll", InvestigationCategory::LiveModule,
                  "live-module category is indexed");
    CheckCategory(index, "reply.example", InvestigationCategory::NetworkTrail,
                  "network-trail category is indexed");
    CheckCategory(index, "remembered access", InvestigationCategory::Authorization,
                  "authorization flow is searchable");
    CheckCategory(index, "likely allow", InvestigationCategory::Authorization,
                  "authorization outcome is searchable");
    CheckCategory(index, "accepted", InvestigationCategory::Authorization,
                  "allow outcome has the deterministic accepted alias");
    CheckCategory(index, "denied", InvestigationCategory::Authorization,
                  "deny outcome has the deterministic denied alias");
    CheckCategory(index, "launch gate", InvestigationCategory::Authorization,
                  "startup gate has the deterministic launch-gate alias");
    CheckCategory(index, "validation", InvestigationCategory::Authorization,
                  "generic validation vocabulary opens authorization results");
    for (const char* query : { "local input", "password", "serial",
                               "credential", "expected value" }) {
        const auto local = index.search(query);
        CHECK(FindAuthorizationFlow(local, "local:0"),
              "local credential/input query aliases open the retained local flow");
    }
    {
        const auto pro = index.search("pro");
        CHECK(FindAuthorizationFlow(pro, "auth-flow-pro"),
              "pro vocabulary opens an exactly labelled pro entitlement");
        CHECK(!FindAuthorizationFlow(pro, "auth-flow-deny"),
              "pro does not match the unrelated word process in deny evidence");
        CHECK(!FindAuthorizationFlow(pro, "auth-flow-zero"),
              "pro is not globally aliased onto unrelated authorization flows");
    }
    {
        const auto premium = index.search("premium");
        CHECK(FindAuthorizationFlow(premium, "auth-flow-premium"),
              "premium vocabulary opens an exactly labelled premium entitlement");
        CHECK(!FindAuthorizationFlow(premium, "auth-flow-zero"),
              "premium is not globally aliased onto unrelated authorization flows");
    }
    {
        const auto validated = index.search("already validated");
        CHECK(FindAuthorizationFlow(validated, "auth-flow-validated"),
              "already-validated vocabulary opens an exactly labelled validated entitlement");
        CHECK(!FindAuthorizationFlow(validated, "auth-flow-zero"),
              "already validated is not inferred from a generic remembered-access link");
    }
    CheckCategory(index, "registered", InvestigationCategory::Authorization,
                  "registered vocabulary opens an exact licensed entitlement family");
    CheckCategory(index, "licensed", InvestigationCategory::Authorization,
                  "licensed vocabulary opens an exact licensed entitlement");
    CheckCategory(index, "existing license", InvestigationCategory::Authorization,
                  "existing-license vocabulary opens authorization results");
    CheckCategory(index, "hkcu", InvestigationCategory::Authorization,
                  "authorization state identity is searchable");
    CheckCategory(index, "registry", InvestigationCategory::Authorization,
                  "authorization persistence kind is searchable");
    {
        const auto jsonState = index.search("state.json");
        const InvestigationResult* hit =
            FindAuthorizationFlow(jsonState, "state:7");
        CHECK(hit && hit->location.valid && hit->location.value == 0x8060,
              "persistent-file result retains its exact navigation address");
        CHECK(hit && hit->fileOffsetValid && hit->fileOffset == 0x260,
              "persistent-file result retains its independent file offset");
        CHECK(hit && hit->focusId == "state:7",
              "persistent-file result preserves exact operation-row focus");
    }
    {
        const auto auth = index.search("startup gate");
        const InvestigationResult* hit = FindCategory(auth, InvestigationCategory::Authorization);
        CHECK(hit && hit->location.valid && hit->location.value == 0,
              "authorization VA zero remains navigable");
        CHECK(hit && hit->fileOffsetValid && hit->fileOffset == 0,
              "authorization file-offset zero remains valid");
        CHECK(hit && hit->focusId == "auth-flow-zero",
              "authorization result preserves stable flow focus");
    }
    {
        const auto zeroOffset = index.search("reply.example");
        const InvestigationResult* hit = FindCategory(zeroOffset, InvestigationCategory::NetworkTrail);
        CHECK(hit && hit->location.valid && hit->location.value == 0,
              "network-trail mapped VA zero retains explicit validity");
        CHECK(hit && hit->fileOffsetValid && hit->fileOffset == 0,
              "network-trail file offset zero retains separate validity");
        const auto overlay = index.search("overlay.example");
        hit = FindCategory(overlay, InvestigationCategory::NetworkTrail);
        CHECK(hit && !hit->location.valid && hit->fileOffsetValid && hit->fileOffset == 0x90,
              "file-only network trail retains exact Hex navigation offset");
    }
    CheckCategory(index, "previous needle", InvestigationCategory::RecentQuery,
                  "recent-query category is indexed");

    // Case-insensitive exact labels outrank prefixes and fuzzy subsequences.
    const auto ranked = index.search("cReAtEfIlEw");
    CHECK(ranked.complete && ranked.results.size() >= 2,
          "rank fixture yields multiple candidates");
    CHECK(!ranked.results.empty() && ranked.results[0].label == "CreateFileW" &&
          ranked.results[0].match == InvestigationMatchKind::ExactText,
          "case-insensitive exact match ranks first");
    if (ranked.results.size() >= 2)
        CHECK(ranked.results[0].score > ranked.results[1].score,
              "exact score exceeds prefix/fuzzy score");

    const auto fuzzy = index.search("crtfw");
    CHECK(fuzzy.complete && FindCategory(fuzzy, InvestigationCategory::Function),
          "ordered fuzzy function match is available");

    // Address parsing carries validity separately, so VA zero is never lost.
    const auto parsedZero = ParseInvestigationAddress(" file:0x0 ");
    CHECK(parsedZero.status == InvestigationAddressParseStatus::Valid &&
          parsedZero.identity == InvestigationIdentity::File && parsedZero.value == 0,
          "FILE VA zero parses as a valid address");
    const auto zero = index.search("file:0x0");
    CHECK(zero.complete && zero.results.size() >= 2 &&
          zero.results[0].category == InvestigationCategory::Address &&
          zero.results[0].location.valid && zero.results[0].location.value == 0,
          "direct FILE VA zero result is explicit and ranked first");
    const auto* zeroFunction = FindCategory(zero, InvestigationCategory::Function);
    CHECK(zeroFunction && zeroFunction->location.valid && zeroFunction->location.value == 0,
          "indexed function at VA zero remains navigable");

    const auto liveZero = index.search("LIVE:0");
    const auto* liveModule = FindCategory(liveZero, InvestigationCategory::LiveModule);
    CHECK(liveZero.complete && liveModule &&
          liveModule->location.identity == InvestigationIdentity::Live &&
          liveModule->location.valid && liveModule->location.value == 0,
          "LIVE address identity and module base zero are preserved");

    const auto xrefTarget = index.search("0");
    const auto* xref = FindCategory(xrefTarget, InvestigationCategory::Xref);
    CHECK(xref && xref->match == InvestigationMatchKind::ExactAddress,
          "an exact xref target address produces a typed xref result");

    CHECK(ParseInvestigationAddress("401000").status == InvestigationAddressParseStatus::Valid &&
          ParseInvestigationAddress("401000").value == 0x401000,
          "bare debugger-style address is hexadecimal");
    CHECK(ParseInvestigationAddress("0d1234").status == InvestigationAddressParseStatus::Valid &&
          ParseInvestigationAddress("0d1234").value == 1234,
          "explicit decimal address is supported");
    CHECK(ParseInvestigationAddress("deadbeef").status == InvestigationAddressParseStatus::NotAddress,
          "hex-like symbol beginning with a letter remains text");

    // Malformed/overflow address syntax is rejected, never reinterpreted as a
    // broad fuzzy query.
    const auto malformed = index.search("0xGG");
    CHECK(malformed.invalidQuery && !malformed.complete && malformed.results.empty(),
          "malformed explicit hex is rejected");
    CHECK(index.search("live:").invalidQuery, "missing LIVE address is rejected");
    const auto overflow = index.search("0x10000000000000000");
    CHECK(overflow.invalidQuery &&
          overflow.parsedAddress.status == InvestigationAddressParseStatus::Overflow,
          "64-bit address overflow is distinguished from text");
    CHECK(index.search("  ").invalidQuery, "empty trimmed query is rejected");

    // Rebuilding/searching the same snapshot keeps ties in source order.
    const auto deterministicA = index.search("create");
    const auto deterministicB = index.search("create");
    CHECK(deterministicA.results.size() == deterministicB.results.size(),
          "deterministic searches return equal result counts");
    for (size_t i = 0; i < deterministicA.results.size() &&
                       i < deterministicB.results.size(); ++i) {
        CHECK(deterministicA.results[i].stableOrder == deterministicB.results[i].stableOrder &&
              deterministicA.results[i].score == deterministicB.results[i].score,
              "stable order and score repeat deterministically");
    }

    // Per-category, total-record, text, query and output limits are hard.
    InvestigationSnapshot boundedSnapshot;
    for (uint64_t i = 0; i < 5; ++i) {
        boundedSnapshot.functions.push_back({ File(i), "same-item-" + std::to_string(i), {}, {} });
    }
    boundedSnapshot.strings.push_back({ File(0x80), std::string(100, 'x'), {}, {} });
    InvestigationLimits small;
    small.maxFunctions = 3;
    small.maxStrings = 1;
    small.maxTotalRecords = 4;
    small.maxFieldBytes = 8;
    small.maxSearchBytes = 16;
    small.maxTotalTextBytes = 128;
    small.maxResults = 2;
    small.maxQueryBytes = 8;
    const auto bounded = InvestigationIndex::Build(boundedSnapshot, small);
    CHECK(bounded.complete && bounded.index && bounded.truncated,
          "bounded rebuild completes with explicit truncation");
    CHECK(bounded.stats.acceptedRecords <= 4 && bounded.stats.droppedRecords >= 2 &&
          bounded.stats.truncatedStrings > 0 && bounded.stats.retainedTextBytes <= 128,
          "record and total-text caps are enforced and reported");
    if (bounded.index) {
        const auto capped = bounded.index->search("same", { 99 });
        CHECK(capped.complete && capped.results.size() == 2 && capped.truncated,
              "returned results cannot exceed the index result cap");
        CHECK(bounded.index->search("query-too-long").invalidQuery,
              "query byte cap is enforced");
    }

    InvestigationSnapshot prioritySnapshot;
    for (uint64_t i = 0; i < 16; ++i)
        prioritySnapshot.functions.push_back(
            { File(0x9000 + i), "bulk-function-" + std::to_string(i), {}, {} });
    prioritySnapshot.networkTrail.push_back({ File(0xA000), 0, false,
        "priority.example", "endpoint", "priority network trail" });
    prioritySnapshot.authorization.push_back({ File(0xA100), 0x310, true,
        "state:42", "persistent read priority-state.json",
        "Persistent state operation", "Unknown",
        "File / JSON format hint C:\\ProgramData\\priority-state.json",
        "exact cataloged read" });
    InvestigationLimits priorityLimits;
    priorityLimits.maxFunctions = 16;
    priorityLimits.maxNetworkTrail = 1;
    priorityLimits.maxAuthorization = 1;
    priorityLimits.maxTotalRecords = 2;
    priorityLimits.maxTotalTextBytes = 8192;
    const auto priority = InvestigationIndex::Build(
        prioritySnapshot, priorityLimits);
    CHECK(priority.complete && priority.index && priority.truncated &&
              priority.index->size() == 2,
          "priority build keeps its strict global record ceiling");
    if (priority.index) {
        CHECK(FindCategory(priority.index->search("priority.example"),
                           InvestigationCategory::NetworkTrail),
              "network trail survives bulk-function record pressure");
        CHECK(FindAuthorizationFlow(
                  priority.index->search("priority-state.json"), "state:42"),
              "persistent-state focus survives bulk-function record pressure");
    }

    InvestigationLimits hostile;
    hostile.maxTotalRecords = std::numeric_limits<size_t>::max();
    hostile.maxResults = std::numeric_limits<size_t>::max();
    hostile.maxFieldBytes = std::numeric_limits<size_t>::max();
    const auto clamped = BoundInvestigationLimits(hostile);
    CHECK(clamped.maxTotalRecords == kInvestigationHardMaxRecords &&
          clamped.maxResults == kInvestigationHardMaxResults &&
          clamped.maxFieldBytes == kInvestigationHardMaxFieldBytes,
          "hostile requested limits cannot raise hard ceilings");
    InvestigationLimits noText;
    noText.maxTotalTextBytes = 0;
    const auto noTextBuild = InvestigationIndex::Build(boundedSnapshot, noText);
    CHECK(noTextBuild.complete && noTextBuild.index && noTextBuild.index->size() == 0 &&
          noTextBuild.truncated,
          "a zero aggregate-text budget cannot retain hidden records");

    // Cancellation publishes neither a partial index nor partial search hits.
    int buildPolls = 0;
    const auto cancelledBuild = InvestigationIndex::Build(
        boundedSnapshot, {}, [&] { return ++buildPolls >= 3; });
    CHECK(cancelledBuild.cancelled && !cancelledBuild.complete && !cancelledBuild.index,
          "rebuild cancellation discards the partial index");
    int searchPolls = 0;
    const auto cancelledSearch = index.search(
        "e", {}, [&] { return ++searchPolls >= 4; });
    CHECK(cancelledSearch.cancelled && !cancelledSearch.complete &&
          cancelledSearch.results.empty(),
          "search cancellation discards partial results");

    if (!failures) std::printf("investigation_index_test: all checks passed\n");
    return failures ? 1 : 0;
}
