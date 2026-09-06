#include "InvestigationIndex.h"

#include <algorithm>
#include <cctype>
#include <exception>
#include <limits>
#include <new>
#include <utility>

namespace ds {
namespace {

constexpr size_t kHardFunctions = 100000;
constexpr size_t kHardStrings = 150000;
constexpr size_t kHardImports = 100000;
constexpr size_t kHardComments = 150000;
constexpr size_t kHardResources = 100000;
constexpr size_t kHardByteResults = 150000;
constexpr size_t kHardXrefs = 200000;
constexpr size_t kHardLiveModules = 16384;
constexpr size_t kHardNetworkTrail = 16384;
constexpr size_t kHardAuthorization = 16384;
constexpr size_t kHardRecentQueries = 1024;

bool IsSpace(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
}

std::string_view Trim(std::string_view value) noexcept {
    while (!value.empty() && IsSpace(value.front())) value.remove_prefix(1);
    while (!value.empty() && IsSpace(value.back())) value.remove_suffix(1);
    return value;
}

char LowerAscii(char c) noexcept {
    if (c >= 'A' && c <= 'Z') return static_cast<char>(c + ('a' - 'A'));
    return c;
}

bool StartsWithInsensitive(std::string_view value, std::string_view prefix) noexcept {
    if (value.size() < prefix.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        if (LowerAscii(value[i]) != LowerAscii(prefix[i])) return false;
    }
    return true;
}

bool EqualsInsensitive(std::string_view left, std::string_view right) noexcept {
    return left.size() == right.size() && StartsWithInsensitive(left, right);
}

size_t FindInsensitive(std::string_view haystack, std::string_view needle) noexcept {
    if (needle.empty()) return 0;
    if (needle.size() > haystack.size()) return std::string_view::npos;
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        if (StartsWithInsensitive(haystack.substr(i), needle)) return i;
    }
    return std::string_view::npos;
}

std::string LowerCopy(std::string_view value, size_t cap) {
    const size_t count = std::min(value.size(), cap);
    std::string result;
    result.resize(count);
    for (size_t i = 0; i < count; ++i) result[i] = LowerAscii(value[i]);
    return result;
}

bool IsTokenBoundary(char c) noexcept {
    return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
             (c >= '0' && c <= '9') || c == '_');
}

bool HasTokenPrefix(std::string_view value, std::string_view query) noexcept {
    if (query.empty() || query.size() > value.size()) return false;
    for (size_t i = 0; i + query.size() <= value.size(); ++i) {
        if (i != 0 && !IsTokenBoundary(value[i - 1])) continue;
        if (StartsWithInsensitive(value.substr(i), query)) return true;
    }
    return false;
}

bool HasExactToken(std::string_view value, std::string_view token) noexcept {
    if (token.empty() || token.size() > value.size()) return false;
    for (size_t i = 0; i + token.size() <= value.size(); ++i) {
        if (i != 0 && !IsTokenBoundary(value[i - 1])) continue;
        if (!StartsWithInsensitive(value.substr(i), token)) continue;
        const size_t end = i + token.size();
        if (end == value.size() || IsTokenBoundary(value[end])) return true;
    }
    return false;
}

bool IsEntitlementSpecificQuery(std::string_view query) noexcept {
    static constexpr std::string_view queries[] = {
        "pro", "premium", "registered", "licensed", "existing license",
        "validated", "already validated", "activated", "activation"
    };
    for (std::string_view candidate : queries) {
        if (EqualsInsensitive(query, candidate)) return true;
    }
    return false;
}

uint64_t SaturatingAdd(uint64_t left, uint64_t right) noexcept {
    if (right > std::numeric_limits<uint64_t>::max() - left)
        return std::numeric_limits<uint64_t>::max();
    return left + right;
}

int HexDigit(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    c = LowerAscii(c);
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return -1;
}

bool ParseUnsigned(std::string_view digits, unsigned base, uint64_t& value) noexcept {
    if (digits.empty()) return false;
    uint64_t parsed = 0;
    for (char c : digits) {
        int digit = HexDigit(c);
        if (digit < 0 || static_cast<unsigned>(digit) >= base) return false;
        if (parsed > (std::numeric_limits<uint64_t>::max() - static_cast<uint64_t>(digit)) / base)
            return false;
        parsed = parsed * base + static_cast<unsigned>(digit);
    }
    value = parsed;
    return true;
}

std::string FormatHex(uint64_t value) {
    static constexpr char digits[] = "0123456789abcdef";
    char buffer[18]{};
    buffer[0] = '0';
    buffer[1] = 'x';
    size_t first = 17;
    do {
        buffer[first--] = digits[value & 0xfu];
        value >>= 4u;
    } while (value != 0);
    return std::string(buffer, 2) + std::string(buffer + first + 1, buffer + 18);
}

const char* IdentityName(InvestigationIdentity identity) noexcept {
    return identity == InvestigationIdentity::Live ? "LIVE" : "FILE";
}

const char* CategoryName(InvestigationCategory category) noexcept {
    switch (category) {
    case InvestigationCategory::Address: return "address";
    case InvestigationCategory::Function: return "function";
    case InvestigationCategory::StringLiteral: return "string";
    case InvestigationCategory::Import: return "import";
    case InvestigationCategory::Comment: return "comment";
    case InvestigationCategory::Resource: return "resource";
    case InvestigationCategory::ByteResult: return "byte result";
    case InvestigationCategory::Xref: return "xref";
    case InvestigationCategory::LiveModule: return "live module";
    case InvestigationCategory::NetworkTrail: return "network trail";
    case InvestigationCategory::Authorization: return "authorization";
    case InvestigationCategory::RecentQuery: return "recent query";
    }
    return "item";
}

bool AddressInSpan(uint64_t address, uint64_t base, uint64_t size) noexcept {
    if (size == 0 || address < base) return false;
    return address - base < size;
}

struct TextMatch {
    bool matched = false;
    InvestigationMatchKind kind = InvestigationMatchKind::Fuzzy;
    uint32_t score = 0;
    const char* evidence = "";
};

TextMatch FuzzyMatch(std::string_view key, std::string_view query) noexcept {
    if (query.empty() || key.empty()) return {};
    size_t q = 0;
    uint32_t consecutive = 0;
    uint32_t bestConsecutive = 0;
    uint32_t boundaries = 0;
    size_t previous = std::string_view::npos;
    for (size_t i = 0; i < key.size() && q < query.size(); ++i) {
        if (LowerAscii(key[i]) != LowerAscii(query[q])) continue;
        if (i == 0 || IsTokenBoundary(key[i - 1])) ++boundaries;
        if (previous != std::string_view::npos && i == previous + 1) ++consecutive;
        else consecutive = 1;
        bestConsecutive = std::max(bestConsecutive, consecutive);
        previous = i;
        ++q;
    }
    if (q != query.size()) return {};
    const uint32_t lengthPenalty = static_cast<uint32_t>(std::min<size_t>(key.size(), 600));
    const uint32_t score = 4000u + std::min<uint32_t>(bestConsecutive * 35u, 700u) +
                           std::min<uint32_t>(boundaries * 25u, 250u) -
                           std::min<uint32_t>(lengthPenalty, 900u);
    return { true, InvestigationMatchKind::Fuzzy, score,
             "ordered fuzzy text match" };
}

template <typename RecordT>
TextMatch MatchText(const RecordT& record, std::string_view query) noexcept {
    if (EqualsInsensitive(record.label, query))
        return { true, InvestigationMatchKind::ExactText, 10000, "case-insensitive exact label match" };
    if (!record.detail.empty() && EqualsInsensitive(record.detail, query))
        return { true, InvestigationMatchKind::ExactText, 9600, "case-insensitive exact detail match" };
    if (StartsWithInsensitive(record.label, query))
        return { true, InvestigationMatchKind::Prefix, 8500, "case-insensitive label prefix match" };
    if (!record.detail.empty() && StartsWithInsensitive(record.detail, query))
        return { true, InvestigationMatchKind::Prefix, 8250, "case-insensitive detail prefix match" };
    if (HasTokenPrefix(record.searchKey, query))
        return { true, InvestigationMatchKind::TokenPrefix, 7900, "case-insensitive token-prefix match" };

    const size_t labelAt = FindInsensitive(record.label, query);
    if (labelAt != std::string_view::npos) {
        return { true, InvestigationMatchKind::Substring,
                 7200u - static_cast<uint32_t>(std::min<size_t>(labelAt, 500)),
                 "case-insensitive label substring match" };
    }
    const size_t keyAt = FindInsensitive(record.searchKey, query);
    if (keyAt != std::string_view::npos) {
        return { true, InvestigationMatchKind::Substring,
                 6800u - static_cast<uint32_t>(std::min<size_t>(keyAt, 500)),
                 "case-insensitive indexed-text substring match" };
    }
    return FuzzyMatch(record.searchKey, query);
}

bool BetterResult(const InvestigationResult& left,
                  const InvestigationResult& right) noexcept {
    if (left.score != right.score) return left.score > right.score;
    if (left.category != right.category)
        return static_cast<uint8_t>(left.category) < static_cast<uint8_t>(right.category);
    return left.stableOrder < right.stableOrder;
}

std::string CombineEvidence(std::string_view match, std::string_view source,
                            size_t cap) {
    std::string combined;
    const size_t reserve = std::min(cap, match.size() + source.size() + 3);
    combined.reserve(reserve);
    auto append = [&](std::string_view text) {
        if (combined.size() >= cap) return;
        combined.append(text.substr(0, cap - combined.size()));
    };
    append(match);
    if (!source.empty() && combined.size() < cap) {
        append("; ");
        append(source);
    }
    return combined;
}

} // namespace

InvestigationLimits BoundInvestigationLimits(const InvestigationLimits& requested) noexcept {
    InvestigationLimits bounded = requested;
    bounded.maxFunctions = std::min(bounded.maxFunctions, kHardFunctions);
    bounded.maxStrings = std::min(bounded.maxStrings, kHardStrings);
    bounded.maxImports = std::min(bounded.maxImports, kHardImports);
    bounded.maxComments = std::min(bounded.maxComments, kHardComments);
    bounded.maxResources = std::min(bounded.maxResources, kHardResources);
    bounded.maxByteResults = std::min(bounded.maxByteResults, kHardByteResults);
    bounded.maxXrefs = std::min(bounded.maxXrefs, kHardXrefs);
    bounded.maxLiveModules = std::min(bounded.maxLiveModules, kHardLiveModules);
    bounded.maxNetworkTrail = std::min(bounded.maxNetworkTrail, kHardNetworkTrail);
    bounded.maxAuthorization = std::min(bounded.maxAuthorization, kHardAuthorization);
    bounded.maxRecentQueries = std::min(bounded.maxRecentQueries, kHardRecentQueries);
    bounded.maxTotalRecords = std::min(bounded.maxTotalRecords, kInvestigationHardMaxRecords);
    bounded.maxResults = std::min(bounded.maxResults, kInvestigationHardMaxResults);
    bounded.maxFieldBytes = std::min(bounded.maxFieldBytes, kInvestigationHardMaxFieldBytes);
    bounded.maxSearchBytes = std::min(bounded.maxSearchBytes, kInvestigationHardMaxSearchBytes);
    bounded.maxQueryBytes = std::min(bounded.maxQueryBytes, kInvestigationHardMaxQueryBytes);
    bounded.maxTotalTextBytes = std::min(bounded.maxTotalTextBytes,
                                         kInvestigationHardMaxTotalTextBytes);
    return bounded;
}

InvestigationParsedAddress ParseInvestigationAddress(std::string_view query) noexcept {
    InvestigationParsedAddress result;
    query = Trim(query);
    if (query.empty()) return result;

    bool explicitIdentity = false;
    if (StartsWithInsensitive(query, "file:")) {
        explicitIdentity = true;
        result.identity = InvestigationIdentity::File;
        query = Trim(query.substr(5));
    } else if (StartsWithInsensitive(query, "va:")) {
        explicitIdentity = true;
        result.identity = InvestigationIdentity::File;
        query = Trim(query.substr(3));
    } else if (StartsWithInsensitive(query, "live:")) {
        explicitIdentity = true;
        result.identity = InvestigationIdentity::Live;
        query = Trim(query.substr(5));
    }

    if (query.empty()) {
        result.status = explicitIdentity ? InvestigationAddressParseStatus::Malformed
                                         : InvestigationAddressParseStatus::NotAddress;
        return result;
    }

    unsigned base = 16;
    bool explicitlyNumeric = explicitIdentity;
    if (query.size() >= 2 && query[0] == '0' && LowerAscii(query[1]) == 'x') {
        explicitlyNumeric = true;
        query.remove_prefix(2);
    } else if (query.size() >= 2 && query[0] == '0' && LowerAscii(query[1]) == 'd') {
        explicitlyNumeric = true;
        base = 10;
        query.remove_prefix(2);
    } else if (!query.empty() && LowerAscii(query.back()) == 'h') {
        explicitlyNumeric = true;
        query.remove_suffix(1);
    } else {
        if (explicitIdentity) {
            explicitlyNumeric = true;
        } else {
            // A bare hexadecimal address must start with a decimal digit so symbol
            // names such as "deadbeef" remain ordinary search text.
            if (query.front() < '0' || query.front() > '9') return result;
            bool allHex = true;
            for (char c : query) allHex = allHex && HexDigit(c) >= 0;
            if (!allHex) return result;
            explicitlyNumeric = true;
        }
    }

    if (!explicitlyNumeric || query.empty()) {
        result.status = InvestigationAddressParseStatus::Malformed;
        return result;
    }
    for (char c : query) {
        if (IsSpace(c)) {
            result.status = InvestigationAddressParseStatus::Malformed;
            return result;
        }
    }

    uint64_t value = 0;
    if (!ParseUnsigned(query, base, value)) {
        bool validDigits = !query.empty();
        for (char c : query) {
            const int digit = HexDigit(c);
            validDigits = validDigits && digit >= 0 && static_cast<unsigned>(digit) < base;
        }
        result.status = validDigits ? InvestigationAddressParseStatus::Overflow
                                    : InvestigationAddressParseStatus::Malformed;
        return result;
    }
    result.status = InvestigationAddressParseStatus::Valid;
    result.value = value;
    return result;
}

InvestigationBuildResult InvestigationIndex::Build(
    const InvestigationSnapshot& snapshot,
    const InvestigationLimits& requestedLimits,
    const InvestigationCancel& cancelled) noexcept {
    InvestigationBuildResult result;
    try {
        auto index = std::shared_ptr<InvestigationIndex>(new InvestigationIndex());
        index->limits_ = BoundInvestigationLimits(requestedLimits);
        InvestigationBuildStats& stats = index->stats_;

        auto addInputCount = [&](size_t count) {
            stats.inputRecords = SaturatingAdd(stats.inputRecords, static_cast<uint64_t>(count));
        };
        addInputCount(snapshot.functions.size());
        addInputCount(snapshot.strings.size());
        addInputCount(snapshot.imports.size());
        addInputCount(snapshot.comments.size());
        addInputCount(snapshot.resources.size());
        addInputCount(snapshot.byteResults.size());
        addInputCount(snapshot.xrefs.size());
        addInputCount(snapshot.liveModules.size());
        addInputCount(snapshot.networkTrail.size());
        addInputCount(snapshot.authorization.size());
        addInputCount(snapshot.recentQueries.size());

        index->records_.reserve(std::min<size_t>(
            static_cast<size_t>(std::min<uint64_t>(stats.inputRecords,
                                                    std::numeric_limits<size_t>::max())),
            index->limits_.maxTotalRecords));

        size_t textRemaining = index->limits_.maxTotalTextBytes;
        bool textExhausted = textRemaining == 0;
        uint64_t ordinal = 1;

        auto takeText = [&](std::string_view text, size_t fieldCap) {
            const size_t count = std::min({ text.size(), fieldCap, textRemaining });
            std::string stored(text.substr(0, count));
            textRemaining -= count;
            stats.retainedTextBytes = SaturatingAdd(stats.retainedTextBytes, count);
            if (count < text.size()) {
                ++stats.truncatedStrings;
                result.truncated = true;
            }
            if (textRemaining == 0) textExhausted = true;
            return stored;
        };

        auto add = [&](InvestigationCategory category,
                       InvestigationAddress location,
                       InvestigationAddress related,
                       uint64_t spanSize,
                       std::string_view label,
                       std::string_view detail,
                       std::string_view evidence,
                       uint64_t fileOffset = 0,
                       bool fileOffsetValid = false,
                       std::string_view focusId = {},
                       std::string_view searchAliases = {}) {
            if (index->records_.size() >= index->limits_.maxTotalRecords || textExhausted)
                return false;
            Record record;
            record.category = category;
            record.location = location;
            record.relatedLocation = related;
            record.fileOffset = fileOffset;
            record.fileOffsetValid = fileOffsetValid;
            record.spanSize = spanSize;
            record.stableOrder = ordinal++;
            if (label.empty()) label = CategoryName(category);
            record.label = takeText(label, index->limits_.maxFieldBytes);
            record.detail = takeText(detail, index->limits_.maxFieldBytes);
            record.evidence = takeText(evidence, index->limits_.maxFieldBytes);
            record.focusId = takeText(focusId, index->limits_.maxFieldBytes);

            std::string searchable;
            const size_t searchCap = index->limits_.maxSearchBytes;
            searchable.reserve(std::min(searchCap,
                record.label.size() + record.detail.size() + record.evidence.size() +
                searchAliases.size() + 48));
            auto appendSearch = [&](std::string_view text) {
                if (searchable.size() >= searchCap) return;
                if (!searchable.empty()) searchable.push_back(' ');
                if (searchable.size() < searchCap)
                    searchable.append(text.substr(0, searchCap - searchable.size()));
            };
            appendSearch(record.label);
            appendSearch(record.detail);
            appendSearch(record.evidence);
            appendSearch(record.focusId);
            appendSearch(searchAliases);
            if (location.valid) appendSearch(FormatHex(location.value));
            if (related.valid) appendSearch(FormatHex(related.value));
            if (fileOffsetValid) {
                appendSearch("file offset");
                appendSearch(FormatHex(fileOffset));
            }
            record.searchKey = takeText(LowerCopy(searchable, searchCap), searchCap);
            index->records_.push_back(std::move(record));
            ++stats.acceptedRecords;
            return true;
        };

        // Compose display fields without first duplicating an arbitrarily large
        // hostile snapshot string into an unbounded temporary.
        auto compose = [&](std::string_view first, std::string_view separator,
                           std::string_view second) {
            std::string value;
            const size_t cap = index->limits_.maxFieldBytes;
            value.reserve(std::min(cap, first.size()));
            bool truncatedField = false;
            auto append = [&](std::string_view part) {
                const size_t available = value.size() < cap ? cap - value.size() : 0;
                const size_t count = std::min(part.size(), available);
                value.append(part.substr(0, count));
                truncatedField = truncatedField || count < part.size();
            };
            append(first);
            if (!second.empty()) {
                append(separator);
                append(second);
            }
            if (truncatedField) {
                ++stats.truncatedStrings;
                result.truncated = true;
            }
            return value;
        };

        auto shouldCancel = [&] { return cancelled && cancelled(); };
        bool wasCancelled = shouldCancel();
        auto canContinue = [&] {
            if (wasCancelled || index->records_.size() >= index->limits_.maxTotalRecords || textExhausted)
                return false;
            if (shouldCancel()) {
                wasCancelled = true;
                return false;
            }
            return true;
        };

        // Trail records are small, high-value investigation entry points. Add
        // them before bulk function/string/xref categories so a hostile or very
        // large image cannot consume the global record/text ceilings first.
        for (size_t i = 0; i < std::min(snapshot.networkTrail.size(), index->limits_.maxNetworkTrail) && canContinue(); ++i) {
            const auto& item = snapshot.networkTrail[i];
            add(InvestigationCategory::NetworkTrail, item.location, {}, 0,
                item.endpoint, item.role, item.evidence,
                item.fileOffset, item.fileOffsetValid);
        }
        for (size_t i = 0; i < std::min(snapshot.authorization.size(), index->limits_.maxAuthorization) && canContinue(); ++i) {
            const auto& item = snapshot.authorization[i];
            std::string detail = compose(item.stage,
                item.stage.empty() || item.outcome.empty() ? "" : " · ", item.outcome);
            if (!item.stateIdentity.empty())
                detail = compose(detail, detail.empty() ? "" : " · ", item.stateIdentity);
            // Keep analyst-facing labels concise while making the vocabulary in
            // the Authorization palette category deterministic. These aliases
            // are indexed only; they are not presented as additional evidence.
            std::string aliases;
            auto appendAlias = [&](std::string_view alias) {
                if (!aliases.empty()) aliases.push_back(' ');
                aliases.append(alias);
            };
            const bool allow = FindInsensitive(item.outcome, "allow") != std::string_view::npos ||
                               FindInsensitive(item.stage, "allow") != std::string_view::npos;
            const bool deny = FindInsensitive(item.outcome, "deny") != std::string_view::npos ||
                              FindInsensitive(item.stage, "deny") != std::string_view::npos;
            const bool localInput =
                StartsWithInsensitive(item.flowId, "local:") ||
                FindInsensitive(item.stage, "input read") != std::string_view::npos ||
                FindInsensitive(item.label, "local credential/input") !=
                    std::string_view::npos ||
                FindInsensitive(item.evidence, "local credential/input") !=
                    std::string_view::npos ||
                FindInsensitive(item.evidence, "local input buffer") !=
                    std::string_view::npos;
            auto hasEntitlementToken = [&](std::string_view token) {
                return HasExactToken(item.label, token) ||
                       HasExactToken(item.stateIdentity, token) ||
                       HasExactToken(item.evidence, token);
            };
            appendAlias("authorization validation entitlement");
            if (hasEntitlementToken("pro"))
                appendAlias("pro");
            if (hasEntitlementToken("premium"))
                appendAlias("premium");
            if (hasEntitlementToken("registered") ||
                hasEntitlementToken("licensed") ||
                hasEntitlementToken("license"))
                appendAlias("registered licensed existing license");
            if (hasEntitlementToken("validated") ||
                hasEntitlementToken("valid"))
                appendAlias("validated already validated");
            if (hasEntitlementToken("activated") ||
                hasEntitlementToken("active") ||
                hasEntitlementToken("activation"))
                appendAlias("activated activation");
            if (allow) appendAlias("accepted access allowed");
            if (deny) appendAlias("denied access denied");
            if (FindInsensitive(item.stage, "startup gate") != std::string_view::npos)
                appendAlias("launch gate startup check");
            if (localInput) {
                // Query vocabulary only: these aliases route common crackme
                // questions to the retained local-input record. They are never
                // copied into the result's analyst-facing evidence or used to
                // claim which credential format/value the binary accepts.
                appendAlias(
                    "local input password serial credential expected value local check");
            }
            if (item.rememberedAccessLinked)
                appendAlias("remembered existing access");
            add(InvestigationCategory::Authorization, item.location, {}, 0,
                item.label, detail, item.evidence,
                item.fileOffset, item.fileOffsetValid, item.flowId, aliases);
        }
        for (size_t i = 0; i < std::min(snapshot.liveModules.size(), index->limits_.maxLiveModules) && canContinue(); ++i) {
            const auto& item = snapshot.liveModules[i];
            InvestigationAddress base = item.base;
            base.identity = InvestigationIdentity::Live;
            add(InvestigationCategory::LiveModule, base, {}, item.size,
                item.name, item.path, item.evidence);
        }

        for (size_t i = 0; i < std::min(snapshot.functions.size(), index->limits_.maxFunctions) && canContinue(); ++i) {
            const auto& item = snapshot.functions[i];
            add(InvestigationCategory::Function, item.location, {}, 0,
                item.name, item.prototype, item.evidence);
        }
        for (size_t i = 0; i < std::min(snapshot.strings.size(), index->limits_.maxStrings) && canContinue(); ++i) {
            const auto& item = snapshot.strings[i];
            add(InvestigationCategory::StringLiteral, item.location, {}, 0,
                item.text, item.encoding, item.evidence);
        }
        for (size_t i = 0; i < std::min(snapshot.imports.size(), index->limits_.maxImports) && canContinue(); ++i) {
            const auto& item = snapshot.imports[i];
            std::string detail = compose(item.module,
                item.module.empty() ? "" : " ", item.delayed ? "(delayed)" : "");
            add(InvestigationCategory::Import, item.location, {}, 0,
                item.name, detail, item.evidence);
        }
        for (size_t i = 0; i < std::min(snapshot.comments.size(), index->limits_.maxComments) && canContinue(); ++i) {
            const auto& item = snapshot.comments[i];
            add(InvestigationCategory::Comment, item.location, {}, 0,
                item.text, "analyst comment", item.evidence);
        }
        for (size_t i = 0; i < std::min(snapshot.resources.size(), index->limits_.maxResources) && canContinue(); ++i) {
            const auto& item = snapshot.resources[i];
            std::string detail = compose(item.type,
                item.type.empty() ? "" : " / ", item.language);
            add(InvestigationCategory::Resource, item.location, {}, 0,
                item.name, detail, item.evidence);
        }
        for (size_t i = 0; i < std::min(snapshot.byteResults.size(), index->limits_.maxByteResults) && canContinue(); ++i) {
            const auto& item = snapshot.byteResults[i];
            add(InvestigationCategory::ByteResult, item.location, {}, 0,
                item.preview, "byte-pattern result", item.evidence);
        }
        for (size_t i = 0; i < std::min(snapshot.xrefs.size(), index->limits_.maxXrefs) && canContinue(); ++i) {
            const auto& item = snapshot.xrefs[i];
            std::string detail;
            if (item.target.valid) detail = "to " + FormatHex(item.target.value);
            add(InvestigationCategory::Xref, item.source, item.target, 0,
                item.context, detail, item.evidence);
        }
        for (size_t i = 0; i < std::min(snapshot.recentQueries.size(), index->limits_.maxRecentQueries) && canContinue(); ++i) {
            const auto& item = snapshot.recentQueries[i];
            add(InvestigationCategory::RecentQuery,
                { item.identity, false, 0 }, {}, 0,
                item.query, "recent query", "query history snapshot");
        }

        stats.droppedRecords = stats.inputRecords >= stats.acceptedRecords
            ? stats.inputRecords - stats.acceptedRecords : 0;
        if (stats.droppedRecords != 0 || stats.truncatedStrings != 0)
            result.truncated = true;
        result.stats = stats;

        if (wasCancelled) {
            result.cancelled = true;
            result.error = "Investigation index rebuild cancelled";
            return result;
        }
        result.complete = true;
        result.index = std::move(index);
        return result;
    } catch (const std::exception& error) {
        result.error = std::string("Investigation index rebuild failed: ") + error.what();
    } catch (...) {
        result.error = "Investigation index rebuild failed";
    }
    return result;
}

InvestigationSearchResult InvestigationIndex::search(
    std::string_view query,
    const InvestigationSearchOptions& options,
    const InvestigationCancel& cancelled) const noexcept {
    InvestigationSearchResult result;
    try {
        query = Trim(query);
        if (query.empty()) {
            result.invalidQuery = true;
            result.error = "Enter an address or search text";
            return result;
        }
        if (query.size() > limits_.maxQueryBytes) {
            result.invalidQuery = true;
            result.error = "Investigation query exceeds the configured byte limit";
            return result;
        }

        result.parsedAddress = ParseInvestigationAddress(query);
        if (result.parsedAddress.status == InvestigationAddressParseStatus::Malformed ||
            result.parsedAddress.status == InvestigationAddressParseStatus::Overflow) {
            result.invalidQuery = true;
            result.error = result.parsedAddress.status == InvestigationAddressParseStatus::Overflow
                ? "Address expression overflows 64 bits"
                : "Malformed address expression";
            return result;
        }

        const size_t resultCap = std::min({ options.maxResults, limits_.maxResults,
                                            kInvestigationHardMaxResults });
        std::string normalized = LowerCopy(query, limits_.maxQueryBytes);
        auto cancelledNow = [&] { return cancelled && cancelled(); };
        if (cancelledNow()) {
            result.cancelled = true;
            result.error = "Investigation search cancelled";
            return result;
        }

        auto retain = [&](InvestigationResult candidate) {
            if (resultCap == 0) {
                result.truncated = true;
                return;
            }
            if (result.results.size() < resultCap) {
                result.results.push_back(std::move(candidate));
                return;
            }
            result.truncated = true;
            auto worst = std::max_element(result.results.begin(), result.results.end(), BetterResult);
            if (worst != result.results.end() && BetterResult(candidate, *worst))
                *worst = std::move(candidate);
        };

        if (result.parsedAddress.status == InvestigationAddressParseStatus::Valid) {
            InvestigationResult direct;
            direct.category = InvestigationCategory::Address;
            direct.location = { result.parsedAddress.identity, true,
                                result.parsedAddress.value };
            direct.match = InvestigationMatchKind::ExactAddress;
            direct.score = 20000;
            direct.stableOrder = 0;
            direct.label = std::string("Go to ") + IdentityName(direct.location.identity) +
                           " " + FormatHex(direct.location.value);
            direct.detail = "exact address expression";
            direct.evidence = "parsed without an address-zero sentinel";
            retain(std::move(direct));
        }

        for (const Record& record : records_) {
            if (cancelledNow()) {
                result.results.clear();
                result.cancelled = true;
                result.truncated = false;
                result.error = "Investigation search cancelled";
                return result;
            }

            TextMatch match;
            if (result.parsedAddress.status == InvestigationAddressParseStatus::Valid) {
                const InvestigationIdentity identity = result.parsedAddress.identity;
                const uint64_t address = result.parsedAddress.value;
                if (record.location.valid && record.location.identity == identity &&
                    record.location.value == address) {
                    match = { true, InvestigationMatchKind::ExactAddress, 19000,
                              "exact indexed address match" };
                } else if (record.relatedLocation.valid && record.relatedLocation.identity == identity &&
                           record.relatedLocation.value == address) {
                    match = { true, InvestigationMatchKind::ExactAddress, 18500,
                              "exact related-address match" };
                } else if (record.category == InvestigationCategory::LiveModule &&
                           identity == InvestigationIdentity::Live && record.location.valid &&
                           AddressInSpan(address, record.location.value, record.spanSize)) {
                    match = { true, InvestigationMatchKind::ExactAddress, 17000,
                              "live address falls inside module mapping" };
                }
            }
            if (!match.matched) {
                // Short entitlement terms must be whole, explicitly indexed
                // concepts for authorization records.  In particular, a query
                // for "pro" must not match incidental words such as "process",
                // "progress", or "provenance" in unrelated flow evidence.
                if (record.category == InvestigationCategory::Authorization &&
                    IsEntitlementSpecificQuery(normalized) &&
                    !HasExactToken(record.searchKey, normalized))
                    continue;
                match = MatchText(record, normalized);
            }
            if (!match.matched) continue;

            InvestigationResult candidate;
            candidate.category = record.category;
            candidate.location = record.location;
            candidate.fileOffset = record.fileOffset;
            candidate.fileOffsetValid = record.fileOffsetValid;
            candidate.match = match.kind;
            candidate.score = match.score;
            candidate.stableOrder = record.stableOrder;
            candidate.label = record.label;
            candidate.detail = record.detail;
            candidate.evidence = CombineEvidence(match.evidence, record.evidence,
                                                  limits_.maxFieldBytes);
            candidate.focusId = record.focusId;
            retain(std::move(candidate));
        }

        std::stable_sort(result.results.begin(), result.results.end(), BetterResult);
        result.complete = true;
        return result;
    } catch (const std::exception& error) {
        result.results.clear();
        result.error = std::string("Investigation search failed: ") + error.what();
    } catch (...) {
        result.results.clear();
        result.error = "Investigation search failed";
    }
    return result;
}

size_t InvestigationIndex::size() const noexcept {
    return records_.size();
}

const InvestigationLimits& InvestigationIndex::limits() const noexcept {
    return limits_;
}

const InvestigationBuildStats& InvestigationIndex::stats() const noexcept {
    return stats_;
}

} // namespace ds
