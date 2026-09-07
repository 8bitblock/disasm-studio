#pragma once
// Parsed function-list search shared by the navigator and Functions drawer.
// Whitespace-separated terms are ANDed across display name, raw name and hex VA;
// a leading '-' excludes a term. Double quotes preserve spaces, including while
// the closing quote is still being typed. Empty quoted terms are ignored; a lone
// '-' is literal. Backslashes and non-ASCII bytes remain literal.
//
// Parse only when the query changes. Storage and preprocessing are O(query size),
// with no per-function allocation. Precomputed substring failure tables avoid
// quadratic matching against long, repetitive linker/demangled names.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace ds {

class FunctionFilter {
public:
    FunctionFilter() = default;
    explicit FunctionFilter(std::string_view query) { reset(query); }

    void reset(std::string_view query) {
        text_.clear();
        terms_.clear();
        fallback_.clear();
        text_.reserve(query.size());
        for (size_t pos = 0; pos < query.size();) {
            while (pos < query.size() && isSpace(query[pos])) ++pos;
            if (pos == query.size()) break;

            const bool exclude = query[pos] == '-' && pos + 1 < query.size() &&
                                 !isSpace(query[pos + 1]);
            if (exclude) ++pos;
            const size_t begin = text_.size();
            bool quoted = false;
            while (pos < query.size()) {
                const char ch = query[pos];
                if (ch == '"') quoted = !quoted;
                else {
                    if (!quoted && isSpace(ch)) break;
                    text_.push_back(fold(ch));
                }
                ++pos;
            }
            if (text_.size() != begin)
                terms_.push_back({begin, text_.size() - begin, exclude});
        }

        fallback_.resize(text_.size());
        for (const Term& term : terms_) {
            fallback_[term.begin] = 0;
            size_t matched = 0;
            for (size_t i = 1; i < term.size; ++i) {
                while (matched && text_[term.begin + i] != text_[term.begin + matched])
                    matched = fallback_[term.begin + matched - 1];
                if (text_[term.begin + i] == text_[term.begin + matched]) ++matched;
                fallback_[term.begin + i] = matched;
            }
        }
    }

    [[nodiscard]] bool empty() const noexcept { return terms_.empty(); }

    [[nodiscard]] bool matches(std::string_view displayName, std::string_view rawName,
                               uint64_t va) const noexcept {
        char address[18]; // "0x" + at most 16 digits; string_view needs no terminator.
        std::string_view addressView;
        for (const Term& term : terms_) {
            bool found = contains(displayName, term) || contains(rawName, term);
            if (!found) {
                if (addressView.empty()) {
                    char* begin = address + sizeof(address);
                    uint64_t remaining = va;
                    do {
                        *--begin = "0123456789abcdef"[remaining & 0xf];
                        remaining >>= 4;
                    } while (remaining);
                    *--begin = 'x';
                    *--begin = '0';
                    addressView = {begin, static_cast<size_t>(address + sizeof(address) - begin)};
                }
                found = contains(addressView, term);
            }
            if (found == term.exclude) return false;
        }
        return true;
    }

private:
    struct Term {
        size_t begin;
        size_t size;
        bool exclude;
    };

    static constexpr bool isSpace(char ch) noexcept {
        return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '\f' || ch == '\v';
    }

    static constexpr char fold(char ch) noexcept {
        return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch + ('a' - 'A')) : ch;
    }

    bool contains(std::string_view value, const Term& term) const noexcept {
        if (value.size() < term.size) return false;
        size_t matched = 0;
        for (char ch : value) {
            ch = fold(ch);
            while (matched && ch != text_[term.begin + matched])
                matched = fallback_[term.begin + matched - 1];
            if (ch == text_[term.begin + matched]) ++matched;
            if (matched == term.size) return true;
        }
        return false;
    }

    std::string text_;
    std::vector<Term> terms_;
    std::vector<size_t> fallback_;
};

} // namespace ds
