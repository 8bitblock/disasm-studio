// Pure function-navigator query regression tests.
#include "Core/FunctionFilter.h"
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <new>

static int g_failed = 0;
static bool g_trackAllocations = false;
static size_t g_allocations = 0;

// Matching runs on every candidate when the visible index is rebuilt. Detect
// accidental per-row string copies, including names longer than small strings.
void* operator new(size_t size) {
    if (g_trackAllocations) ++g_allocations;
    if (void* memory = std::malloc(size ? size : 1)) return memory;
    throw std::bad_alloc();
}
void* operator new[](size_t size) { return ::operator new(size); }
void operator delete(void* memory) noexcept { std::free(memory); }
void operator delete[](void* memory) noexcept { std::free(memory); }
void operator delete(void* memory, size_t) noexcept { std::free(memory); }
void operator delete[](void* memory, size_t) noexcept { std::free(memory); }

#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_failed; \
} } while (0)

int main() {
    using ds::FunctionFilter;

    CHECK(FunctionFilter().empty());
    CHECK(FunctionFilter().matches("", "", 0));
    CHECK(FunctionFilter(" \t\r\n\f\v \"\" ").empty());
    CHECK(FunctionFilter("\"\"").matches("Anything", "", 0));

    // Names and addresses form one searchable row, without joining field edges.
    CHECK(FunctionFilter("CREATEFILE").matches("CreateFileW", "", 0));
    CHECK(FunctionFilter("createfile").matches("Open configuration", "__imp_CreateFileW", 0));
    CHECK(FunctionFilter("configuration CREATEFILE 0X140001").matches(
        "Open configuration", "__imp_CreateFileW", 0x140001230));
    CHECK(!FunctionFilter("configuration createfile missing").matches(
        "Open configuration", "__imp_CreateFileW", 0x140001230));
    CHECK(!FunctionFilter("abcdef").matches("abc", "def", 0));
    CHECK(!FunctionFilter("abc").matches("a_b_c", "", 0));

    // Exclusions search all fields and may appear before or after positive terms.
    CHECK(FunctionFilter("open -socket -0x99").matches("Open configuration", "CreateFileW", 0x100));
    CHECK(!FunctionFilter("open -CREATEFILE").matches("Open configuration", "CreateFileW", 0x100));
    CHECK(!FunctionFilter("-configuration open").matches("Open configuration", "CreateFileW", 0x100));
    CHECK(!FunctionFilter("-0x100").matches("Open configuration", "CreateFileW", 0x100));
    CHECK(FunctionFilter("-socket").matches("", "", 0));
    CHECK(FunctionFilter("-").matches("operator-", "", 1));
    CHECK(!FunctionFilter("-").matches("operator+", "", 1));
    CHECK(FunctionFilter("\"-socket\"").matches("prefix-socket", "", 0));

    // Quoted phrases stay contiguous; unfinished quotes work while typing.
    CHECK(FunctionFilter("\"open configuration\" FILE").matches(
        "Open configuration", "CreateFileW", 0));
    CHECK(!FunctionFilter("\"open configuration\"").matches("Open saved configuration", "", 0));
    CHECK(FunctionFilter("\"open configuration").matches("Open configuration", "", 0));
    CHECK(!FunctionFilter("-\"open configuration").matches("Open configuration", "", 0));
    CHECK(FunctionFilter("open\" configuration\"").matches("Open configuration", "", 0));
    CHECK(FunctionFilter("\"\" -\"\" create").matches("CreateFileW", "", 0));
    CHECK(FunctionFilter("\" a  b \"").matches(" a  b ", "", 0));
    CHECK(!FunctionFilter("\" a  b \"").matches(" a b ", "", 0));

    // Full-width addresses, zero, and non-terminated views remain valid.
    CHECK(FunctionFilter("0x0").matches("", "", 0));
    CHECK(FunctionFilter("0").matches("", "", 0));
    CHECK(FunctionFilter("FFFFFFFFFFFFFFFF").matches("", "", std::numeric_limits<uint64_t>::max()));
    CHECK(FunctionFilter("0XFFFFFFFFFFFFFFFF").matches("", "", std::numeric_limits<uint64_t>::max()));
    CHECK(!FunctionFilter("0x0001").matches("", "", 1)); // displayed hex has no padding
    const char boundedName[] = {'O', 'p', 'e', 'n', 'X'};
    CHECK(FunctionFilter(std::string_view("open ignored", 4)).matches(
        std::string_view(boundedName, 4), "", 1));
    CHECK(!FunctionFilter("openx").matches(std::string_view(boundedName, 4), "", 1));
    CHECK(FunctionFilter("A\xC4").matches("a\xC4", "", 1));
    CHECK(!FunctionFilter("A\xC4").matches("a\xE4", "", 1)); // ASCII folding only
    CHECK(FunctionFilter("path\\file").matches("PATH\\FILE", "", 1));

    // A parsed query owns its data and stays valid across source edits and copies.
    std::string query = "open -socket";
    FunctionFilter filter(query);
    query.assign("other");
    CHECK(filter.matches("Open", "", 1));
    FunctionFilter copied = filter;
    filter.reset("close");
    CHECK(copied.matches("Open", "", 1));
    CHECK(!filter.matches("Open", "", 1));
    filter.reset("");
    CHECK(filter.empty() && filter.matches("Anything", "", 1));

    // Overlapping/repetitive prefixes exercise fallback and long-name matching.
    CHECK(FunctionFilter("ababac").matches("ababababac", "", 1));
    CHECK(!FunctionFilter("ababac").matches("ababababab", "", 1));
    const std::string repetitive(65536, 'a');
    const std::string longName = repetitive + "B readable configuration";
    const FunctionFilter expensive(std::string(126, 'a') + 'b');
    const FunctionFilter absent(std::string(126, 'a') + 'c');
    const FunctionFilter multi("READABLE -socket 0XABC");
    g_trackAllocations = true;
    for (int i = 0; i < 32; ++i) {
        CHECK(expensive.matches(longName, repetitive, 0xabc));
        CHECK(!absent.matches(longName, repetitive, 0xabc));
        CHECK(multi.matches(longName, repetitive, 0xabc));
    }
    g_trackAllocations = false;
    CHECK(g_allocations == 0);

    if (g_failed) { std::printf("%d check(s) FAILED\n", g_failed); return 1; }
    std::printf("function_filter_test: all checks passed; matching allocated zero times\n");
    return 0;
}
