#include "Core/AuthorizationPatchAdvisor.h"

#include <algorithm>
#include <cstdio>
#include <limits>
#include <string>
#include <vector>

using namespace ds;

static int failures = 0;
#define CHECK(c) do { if (!(c)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); ++failures; } } while (0)

static AuthorizationPatchAdvisorInput safeInput() {
    AuthorizationPatchAdvisorInput input;
    input.architecture = AuthorizationPatchArchitecture::X64;
    input.functionAddress = 0x140001000ull;
    input.functionAddressValid = true;
    input.functionBytes = {0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x90, 0x90};
    input.replacementExtentOwned = true;
    input.contiguousEntryOwnedBytes = input.functionBytes.size();
    input.sectionExecutionKnown = true;
    input.sectionExecutable = true;
    input.returnAnalysisComplete = true;
    input.booleanContract = AuthorizationPatchBooleanContract::CanonicalZeroOrOne;
    input.returnWidthBits = 8;
    input.authorizationStateLinked = true;
    input.centralizedPredicate = true;
    input.entryCoverageComplete = true;
    input.returnStyleAnalysisComplete = true;
    input.returnStyle = AuthorizationPatchReturnStyle::NearReturn;
    input.sideEffectAnalysisComplete = true;
    input.proofConfidence = 0.94f;
    input.evidence = "all three reachable exits return 0 or 1; 19 exact branch consumers";
    return input;
}

static bool hasRefusal(const AuthorizationPatchAdvice& advice,
                       AuthorizationPatchRefusal refusal) {
    return std::find(advice.refusals.begin(), advice.refusals.end(), refusal) !=
           advice.refusals.end();
}

static void canonicalX64PlansAndVaZero() {
    auto input = safeInput();
    input.functionAddress = 0;
    input.returnWidthBits = 64;
    const auto advice = AdviseAuthorizationPredicatePatch(input);
    CHECK(advice.eligible);
    CHECK(advice.refusals.empty());
    CHECK(advice.suggestions.size() == 2);
    CHECK(advice.suggestions[0].effect == AuthorizationPatchEffect::ForceFalse);
    CHECK(advice.suggestions[1].effect == AuthorizationPatchEffect::ForceTrue);
    CHECK(advice.suggestions[0].addressValid);
    CHECK(advice.suggestions[0].address == 0); // valid VA zero is not "missing"
    const std::vector<uint8_t> expectedOriginal{0x40, 0x53, 0x48, 0x83, 0xEC, 0x20};
    const std::vector<uint8_t> expectedFalse{0xB8, 0, 0, 0, 0, 0xC3};
    const std::vector<uint8_t> expectedTrue{0xB8, 1, 0, 0, 0, 0xC3};
    CHECK(advice.suggestions[0].originalBytes == expectedOriginal);
    CHECK(advice.suggestions[0].replacementBytes == expectedFalse);
    CHECK(advice.suggestions[1].replacementBytes == expectedTrue);
    CHECK(advice.suggestions[1].confidence == input.proofConfidence);
    CHECK(advice.suggestions[1].evidence.find("19 exact branch consumers") !=
          std::string::npos);
}

static void preservesProvenX86RetImmediate() {
    auto input = safeInput();
    input.architecture = AuthorizationPatchArchitecture::X86;
    input.functionAddress = 0x401000;
    input.returnWidthBits = 32;
    input.functionBytes = {0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x90, 0x90};
    input.returnStyle = AuthorizationPatchReturnStyle::NearReturnPop;
    input.stackPopBytes = 0x10;
    const auto advice = AdviseAuthorizationPredicatePatch(input);
    CHECK(advice.eligible);
    CHECK(advice.suggestions.size() == 2);
    const std::vector<uint8_t> expectedFalse{0xB8, 0, 0, 0, 0, 0xC2, 0x10, 0};
    const std::vector<uint8_t> expectedTrue{0xB8, 1, 0, 0, 0, 0xC2, 0x10, 0};
    CHECK(advice.suggestions[0].replacementBytes == expectedFalse);
    CHECK(advice.suggestions[1].replacementBytes == expectedTrue);
    CHECK(advice.suggestions[1].evidence.find("ret 16") != std::string::npos);
}

static void preservesExactPredicatePolarity() {
    auto nonzero = safeInput();
    nonzero.booleanContract =
        AuthorizationPatchBooleanContract::NonzeroIsTrue;
    auto advice = AdviseAuthorizationPredicatePatch(nonzero);
    CHECK(advice.eligible);
    CHECK(advice.suggestions.size() == 2);
    CHECK(advice.suggestions[0].replacementBytes[1] == 0);
    CHECK(advice.suggestions[1].replacementBytes[1] == 1);

    auto one = safeInput();
    one.booleanContract = AuthorizationPatchBooleanContract::OneIsTrue;
    advice = AdviseAuthorizationPredicatePatch(one);
    CHECK(advice.eligible);
    CHECK(advice.suggestions[0].replacementBytes[1] == 0);
    CHECK(advice.suggestions[1].replacementBytes[1] == 1);

    auto zero = safeInput();
    zero.booleanContract = AuthorizationPatchBooleanContract::ZeroIsTrue;
    advice = AdviseAuthorizationPredicatePatch(zero);
    CHECK(advice.eligible);
    CHECK(advice.suggestions[0].replacementBytes[1] == 1);
    CHECK(advice.suggestions[1].replacementBytes[1] == 0);
}

template <typename Mutate>
static void expectsRefusal(AuthorizationPatchRefusal expected, Mutate mutate) {
    auto input = safeInput();
    mutate(input);
    const auto advice = AdviseAuthorizationPredicatePatch(input);
    CHECK(!advice.eligible);
    CHECK(advice.suggestions.empty());
    CHECK(hasRefusal(advice, expected));
    CHECK(AuthorizationPatchRefusalText(expected) != nullptr);
    CHECK(AuthorizationPatchRefusalText(expected)[0] != '\0');
}

static void everyUnsafeOrIncompleteFactRefuses() {
    expectsRefusal(AuthorizationPatchRefusal::InvalidFunctionAddress,
        [](auto& i) { i.functionAddressValid = false; });
    expectsRefusal(AuthorizationPatchRefusal::UnsupportedArchitecture,
        [](auto& i) { i.architecture = AuthorizationPatchArchitecture::Unsupported; });
    expectsRefusal(AuthorizationPatchRefusal::SectionExecutionUnknown,
        [](auto& i) { i.sectionExecutionKnown = false; });
    expectsRefusal(AuthorizationPatchRefusal::NonExecutableDestination,
        [](auto& i) { i.sectionExecutable = false; });
    expectsRefusal(AuthorizationPatchRefusal::ReturnAnalysisIncomplete,
        [](auto& i) { i.returnAnalysisComplete = false; });
    expectsRefusal(AuthorizationPatchRefusal::AmbiguousBooleanContract,
        [](auto& i) { i.booleanContract = AuthorizationPatchBooleanContract::ZeroOrNonzero; });
    expectsRefusal(AuthorizationPatchRefusal::UnsupportedReturnWidth,
        [](auto& i) { i.returnWidthBits = 16; });
    expectsRefusal(AuthorizationPatchRefusal::AuthorizationLinkUnproven,
        [](auto& i) { i.authorizationStateLinked = false; });
    expectsRefusal(AuthorizationPatchRefusal::NotCentralizedPredicate,
        [](auto& i) { i.centralizedPredicate = false; });
    expectsRefusal(AuthorizationPatchRefusal::EntryCoverageIncomplete,
        [](auto& i) { i.entryCoverageComplete = false; });
    expectsRefusal(AuthorizationPatchRefusal::AlternateEntryPresent,
        [](auto& i) { i.alternateEntryPresent = true; });
    expectsRefusal(AuthorizationPatchRefusal::ReturnStyleAnalysisIncomplete,
        [](auto& i) { i.returnStyleAnalysisComplete = false; });
    expectsRefusal(AuthorizationPatchRefusal::UnsupportedReturnStyle,
        [](auto& i) { i.returnStyle = AuthorizationPatchReturnStyle::Unknown; });
    expectsRefusal(AuthorizationPatchRefusal::SideEffectAnalysisIncomplete,
        [](auto& i) { i.sideEffectAnalysisComplete = false; });
    expectsRefusal(AuthorizationPatchRefusal::StringOrHeapCleanup,
        [](auto& i) { i.stringOrHeapCleanupPresent = true; });
    expectsRefusal(AuthorizationPatchRefusal::OtherSideEffects,
        [](auto& i) { i.otherSideEffectsPresent = true; });
    expectsRefusal(AuthorizationPatchRefusal::StackCookieOrSecurityEpilogue,
        [](auto& i) { i.stackCookieOrSecurityEpiloguePresent = true; });
    expectsRefusal(AuthorizationPatchRefusal::TransportWithoutAuthorizationState,
        [](auto& i) {
            i.authorizationStateLinked = false;
            i.transportBehaviorOnly = true;
        });
    expectsRefusal(AuthorizationPatchRefusal::EvidenceMissing,
        [](auto& i) { i.evidence.clear(); });
    expectsRefusal(AuthorizationPatchRefusal::InsufficientProofConfidence,
        [](auto& i) { i.proofConfidence = 0.84f; });
    expectsRefusal(AuthorizationPatchRefusal::InsufficientBytes,
        [](auto& i) { i.functionBytes.resize(5); });
    expectsRefusal(AuthorizationPatchRefusal::ReplacementExtentUnproven,
        [](auto& i) { i.replacementExtentOwned = false; });
    expectsRefusal(AuthorizationPatchRefusal::ReplacementExtentUnproven,
        [](auto& i) { i.contiguousEntryOwnedBytes = 5; });
    expectsRefusal(AuthorizationPatchRefusal::AddressRangeOverflow,
        [](auto& i) {
            i.functionAddress = (std::numeric_limits<uint64_t>::max)() - 4;
        });

    // x64 cannot silently copy an x86 callee-pop convention.
    expectsRefusal(AuthorizationPatchRefusal::UnsupportedReturnStyle,
        [](auto& i) {
            i.architecture = AuthorizationPatchArchitecture::X64;
            i.returnStyle = AuthorizationPatchReturnStyle::NearReturnPop;
            i.stackPopBytes = 8;
        });

    // Even a contradictory "linked" flag cannot legitimize transport-only
    // behavior as an authorization-state patch.
    expectsRefusal(AuthorizationPatchRefusal::TransportWithoutAuthorizationState,
        [](auto& i) { i.transportBehaviorOnly = true; });
}

static void multipleFailuresAreReportedTogetherAndNeverEmitBytes() {
    auto input = safeInput();
    input.sectionExecutionKnown = false;
    input.returnAnalysisComplete = false;
    input.sideEffectAnalysisComplete = false;
    input.stackCookieOrSecurityEpiloguePresent = true;
    input.functionBytes.clear();
    const auto advice = AdviseAuthorizationPredicatePatch(input);
    CHECK(!advice.eligible);
    CHECK(advice.suggestions.empty());
    CHECK(hasRefusal(advice, AuthorizationPatchRefusal::SectionExecutionUnknown));
    CHECK(hasRefusal(advice, AuthorizationPatchRefusal::ReturnAnalysisIncomplete));
    CHECK(hasRefusal(advice, AuthorizationPatchRefusal::SideEffectAnalysisIncomplete));
    CHECK(hasRefusal(advice, AuthorizationPatchRefusal::StackCookieOrSecurityEpilogue));
    CHECK(hasRefusal(advice, AuthorizationPatchRefusal::InsufficientBytes));
}

int main() {
    canonicalX64PlansAndVaZero();
    preservesProvenX86RetImmediate();
    preservesExactPredicatePolarity();
    everyUnsafeOrIncompleteFactRefuses();
    multipleFailuresAreReportedTogetherAndNeverEmitBytes();

    if (failures) {
        std::printf("authorization_patch_advisor_test: %d failure(s)\n", failures);
        return 1;
    }
    std::printf("authorization_patch_advisor_test: all checks passed\n");
    return 0;
}
