#include "AuthorizationPatchAdvisor.h"

#include <algorithm>
#include <cmath>
#include <limits>

namespace ds {
namespace {

constexpr float kMinimumProofConfidence = 0.85f;
constexpr size_t kMaximumEvidenceLength = 512;

void refuse(AuthorizationPatchAdvice& advice,
            AuthorizationPatchRefusal refusal) {
    if (std::find(advice.refusals.begin(), advice.refusals.end(), refusal) ==
        advice.refusals.end()) {
        advice.refusals.push_back(refusal);
    }
}

std::string boundedEvidence(const std::string& evidence,
                            AuthorizationPatchReturnStyle style,
                            uint16_t stackPopBytes) {
    std::string result = evidence.substr(0, kMaximumEvidenceLength);
    if (!result.empty()) result += "; ";
    result += "inert centralized proven-boolean return plan: mov eax, imm32; ";
    if (style == AuthorizationPatchReturnStyle::NearReturnPop) {
        result += "ret " + std::to_string(stackPopBytes) +
                  " (proven x86 callee-pop ABI preserved)";
    } else {
        result += "ret";
    }
    return result;
}

std::vector<uint8_t> replacement(bool value,
                                 AuthorizationPatchReturnStyle style,
                                 uint16_t stackPopBytes) {
    std::vector<uint8_t> bytes{
        0xB8, value ? uint8_t{1} : uint8_t{0}, 0x00, 0x00, 0x00
    };
    if (style == AuthorizationPatchReturnStyle::NearReturnPop) {
        bytes.push_back(0xC2);
        bytes.push_back(static_cast<uint8_t>(stackPopBytes & 0xFFu));
        bytes.push_back(static_cast<uint8_t>((stackPopBytes >> 8) & 0xFFu));
    } else {
        bytes.push_back(0xC3);
    }
    return bytes;
}

} // namespace

const char* AuthorizationPatchRefusalText(
    AuthorizationPatchRefusal refusal) noexcept {
    switch (refusal) {
    case AuthorizationPatchRefusal::InvalidFunctionAddress:
        return "the function address is not valid";
    case AuthorizationPatchRefusal::UnsupportedArchitecture:
        return "only x86 and x64 canonical predicate returns are supported";
    case AuthorizationPatchRefusal::SectionExecutionUnknown:
        return "the destination section's execute status is unknown";
    case AuthorizationPatchRefusal::NonExecutableDestination:
        return "the destination is not executable; no branch or return patch is suggested";
    case AuthorizationPatchRefusal::ReturnAnalysisIncomplete:
        return "return analysis is incomplete";
    case AuthorizationPatchRefusal::AmbiguousBooleanContract:
        return "the function's logical true/false return convention is not proven";
    case AuthorizationPatchRefusal::UnsupportedReturnWidth:
        return "the predicate return width is unknown or unsupported";
    case AuthorizationPatchRefusal::AuthorizationLinkUnproven:
        return "the predicate is not proven to read or control authorization state";
    case AuthorizationPatchRefusal::NotCentralizedPredicate:
        return "the target is not proven to be a centralized authorization predicate";
    case AuthorizationPatchRefusal::EntryCoverageIncomplete:
        return "entry coverage is incomplete";
    case AuthorizationPatchRefusal::AlternateEntryPresent:
        return "an alternate interior entry would bypass the proposed function-entry patch";
    case AuthorizationPatchRefusal::ReturnStyleAnalysisIncomplete:
        return "the return instruction and ABI cleanup style are not fully proven";
    case AuthorizationPatchRefusal::UnsupportedReturnStyle:
        return "the proven return style cannot be preserved by this narrow advisor";
    case AuthorizationPatchRefusal::SideEffectAnalysisIncomplete:
        return "side-effect analysis is incomplete";
    case AuthorizationPatchRefusal::StringOrHeapCleanup:
        return "the target performs string, heap, handle, or resource cleanup";
    case AuthorizationPatchRefusal::OtherSideEffects:
        return "the target has side effects which a direct return would bypass";
    case AuthorizationPatchRefusal::StackCookieOrSecurityEpilogue:
        return "the target contains stack-cookie or security-epilogue behavior";
    case AuthorizationPatchRefusal::TransportWithoutAuthorizationState:
        return "the target changes HTTP/network transport behavior without establishing authorization state";
    case AuthorizationPatchRefusal::EvidenceMissing:
        return "no bounded evidence summary accompanies the safety proof";
    case AuthorizationPatchRefusal::InsufficientProofConfidence:
        return "the typed safety proof does not meet the conservative confidence threshold";
    case AuthorizationPatchRefusal::InsufficientBytes:
        return "the function entry does not contain enough captured bytes for an equal-size plan";
    case AuthorizationPatchRefusal::ReplacementExtentUnproven:
        return "the entire replacement span is not proven to belong to this function entry";
    case AuthorizationPatchRefusal::AddressRangeOverflow:
        return "the proposed byte range overflows the address space";
    }
    return "unknown authorization patch refusal";
}

AuthorizationPatchAdvice AdviseAuthorizationPredicatePatch(
    const AuthorizationPatchAdvisorInput& input) {
    AuthorizationPatchAdvice advice;

    if (!input.functionAddressValid)
        refuse(advice, AuthorizationPatchRefusal::InvalidFunctionAddress);
    if (input.architecture != AuthorizationPatchArchitecture::X86 &&
        input.architecture != AuthorizationPatchArchitecture::X64)
        refuse(advice, AuthorizationPatchRefusal::UnsupportedArchitecture);
    if (!input.sectionExecutionKnown)
        refuse(advice, AuthorizationPatchRefusal::SectionExecutionUnknown);
    else if (!input.sectionExecutable)
        refuse(advice, AuthorizationPatchRefusal::NonExecutableDestination);

    if (!input.returnAnalysisComplete)
        refuse(advice, AuthorizationPatchRefusal::ReturnAnalysisIncomplete);
    else {
        switch (input.booleanContract) {
        case AuthorizationPatchBooleanContract::CanonicalZeroOrOne:
        case AuthorizationPatchBooleanContract::NonzeroIsTrue:
        case AuthorizationPatchBooleanContract::ZeroIsTrue:
        case AuthorizationPatchBooleanContract::OneIsTrue:
            break;
        case AuthorizationPatchBooleanContract::Unknown:
        case AuthorizationPatchBooleanContract::ZeroOrNonzero:
            refuse(advice, AuthorizationPatchRefusal::AmbiguousBooleanContract);
            break;
        }
    }

    if (input.returnWidthBits != 8 && input.returnWidthBits != 32 &&
        input.returnWidthBits != 64)
        refuse(advice, AuthorizationPatchRefusal::UnsupportedReturnWidth);

    if (!input.authorizationStateLinked) {
        refuse(advice, input.transportBehaviorOnly
            ? AuthorizationPatchRefusal::TransportWithoutAuthorizationState
            : AuthorizationPatchRefusal::AuthorizationLinkUnproven);
    }
    if (!input.centralizedPredicate)
        refuse(advice, AuthorizationPatchRefusal::NotCentralizedPredicate);
    if (!input.entryCoverageComplete)
        refuse(advice, AuthorizationPatchRefusal::EntryCoverageIncomplete);
    if (input.alternateEntryPresent)
        refuse(advice, AuthorizationPatchRefusal::AlternateEntryPresent);

    if (!input.returnStyleAnalysisComplete) {
        refuse(advice, AuthorizationPatchRefusal::ReturnStyleAnalysisIncomplete);
    } else {
        const bool plain = input.returnStyle ==
                           AuthorizationPatchReturnStyle::NearReturn;
        const bool provenX86Pop =
            input.architecture == AuthorizationPatchArchitecture::X86 &&
            input.returnStyle == AuthorizationPatchReturnStyle::NearReturnPop;
        if (!plain && !provenX86Pop)
            refuse(advice, AuthorizationPatchRefusal::UnsupportedReturnStyle);
    }

    if (!input.sideEffectAnalysisComplete)
        refuse(advice, AuthorizationPatchRefusal::SideEffectAnalysisIncomplete);
    if (input.stringOrHeapCleanupPresent)
        refuse(advice, AuthorizationPatchRefusal::StringOrHeapCleanup);
    if (input.otherSideEffectsPresent)
        refuse(advice, AuthorizationPatchRefusal::OtherSideEffects);
    if (input.stackCookieOrSecurityEpiloguePresent)
        refuse(advice, AuthorizationPatchRefusal::StackCookieOrSecurityEpilogue);
    // Do not let a contradictory adapter claim (transport-only yet linked) turn
    // an HTTP behavior patch into an authorization predicate suggestion.
    if (input.transportBehaviorOnly && input.authorizationStateLinked)
        refuse(advice, AuthorizationPatchRefusal::TransportWithoutAuthorizationState);

    if (input.evidence.empty())
        refuse(advice, AuthorizationPatchRefusal::EvidenceMissing);
    if (!std::isfinite(input.proofConfidence) ||
        input.proofConfidence < kMinimumProofConfidence ||
        input.proofConfidence > 1.0f)
        refuse(advice, AuthorizationPatchRefusal::InsufficientProofConfidence);

    // Derive the exact replacement before byte/range checks.  An unknown style
    // uses the shorter form only for sizing diagnostics; it cannot reach output
    // because UnsupportedReturnStyle/ReturnStyleAnalysisIncomplete is present.
    const bool preserveX86Pop =
        input.architecture == AuthorizationPatchArchitecture::X86 &&
        input.returnStyle == AuthorizationPatchReturnStyle::NearReturnPop;
    const AuthorizationPatchReturnStyle plannedStyle = preserveX86Pop
        ? AuthorizationPatchReturnStyle::NearReturnPop
        : AuthorizationPatchReturnStyle::NearReturn;
    const bool zeroMeansTrue = input.booleanContract ==
        AuthorizationPatchBooleanContract::ZeroIsTrue;
    const std::vector<uint8_t> falseBytes =
        replacement(zeroMeansTrue, plannedStyle, input.stackPopBytes);
    const std::vector<uint8_t> trueBytes =
        replacement(!zeroMeansTrue, plannedStyle, input.stackPopBytes);
    const size_t planSize = falseBytes.size();

    if (input.functionBytes.size() < planSize)
        refuse(advice, AuthorizationPatchRefusal::InsufficientBytes);
    if (!input.replacementExtentOwned ||
        input.contiguousEntryOwnedBytes < static_cast<uint64_t>(planSize))
        refuse(advice, AuthorizationPatchRefusal::ReplacementExtentUnproven);
    if (input.functionAddressValid && planSize != 0 &&
        static_cast<uint64_t>(planSize - 1) >
            (std::numeric_limits<uint64_t>::max)() - input.functionAddress)
        refuse(advice, AuthorizationPatchRefusal::AddressRangeOverflow);

    if (!advice.refusals.empty()) return advice;

    const std::vector<uint8_t> original(
        input.functionBytes.begin(), input.functionBytes.begin() + planSize);
    const std::string evidence = boundedEvidence(
        input.evidence, plannedStyle, input.stackPopBytes);

    AuthorizationPatchBytePlan forceFalse;
    forceFalse.effect = AuthorizationPatchEffect::ForceFalse;
    forceFalse.address = input.functionAddress;
    forceFalse.addressValid = true;
    forceFalse.originalBytes = original;
    forceFalse.replacementBytes = falseBytes;
    forceFalse.confidence = input.proofConfidence;
    forceFalse.evidence = evidence;
    advice.suggestions.push_back(std::move(forceFalse));

    AuthorizationPatchBytePlan forceTrue;
    forceTrue.effect = AuthorizationPatchEffect::ForceTrue;
    forceTrue.address = input.functionAddress;
    forceTrue.addressValid = true;
    forceTrue.originalBytes = original;
    forceTrue.replacementBytes = trueBytes;
    forceTrue.confidence = input.proofConfidence;
    forceTrue.evidence = evidence;
    advice.suggestions.push_back(std::move(forceTrue));

    advice.eligible = true;
    return advice;
}

} // namespace ds
