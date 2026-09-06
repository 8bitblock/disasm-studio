#include "Core/Demangle.h"

#include <atomic>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

using namespace ds;

static int failures = 0;

static void expectEq(const char* raw, const char* expected) {
    const DemangleResult got = DemangleSymbol(raw);
    if (got.text != expected) {
        std::cerr << raw << "\n  expected: " << expected << "\n  got:      " << got.text << "\n";
        ++failures;
    }
}

static void expectContains(const char* raw, const char* first, const char* second = nullptr) {
    const DemangleResult got = DemangleSymbol(raw);
    if (got.text.find(first) == std::string::npos ||
        (second && got.text.find(second) == std::string::npos)) {
        std::cerr << raw << "\n  expected fragments: " << first;
        if (second) std::cerr << ", " << second;
        std::cerr << "\n  got: " << got.text << "\n";
        ++failures;
    }
}

int main() {
    // Itanium ABI: free/member functions, qualifiers, templates, substitutions,
    // special names, operators, constructors, literals, and clone suffixes.
    expectEq("_Z3foov", "foo()");
    expectEq("_ZN3foo3barEi", "foo::bar(int)");
    expectEq("_ZNK3Foo3barERKi", "Foo::bar(const int&) const");
    expectEq("_ZN3FooC1Ev", "Foo::Foo()");
    expectEq("_ZN3FooD1Ev", "Foo::~Foo()");
    expectEq("_ZN3FooplERKS_", "Foo::operator+(const Foo&)");
    expectEq("_ZTVN3foo3BarE", "vtable for foo::Bar");
    expectEq("_Z3fooILi42EEvv", "void foo<42>()");
    expectEq("_Z3foov.isra.7", "foo() .isra.7");
    expectContains("_ZNSt6vectorIiSaIiEE3popEv", "std::vector<int, std::allocator<int>>", "::pop()");
    expectContains("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEE5clearEv",
                   "std::__cxx11::basic_string<char", "::clear()");
    if (DemangleForLabel("_ZNSt6vectorIiSaIiEE3popEv") !=
        "std::vector<int, std::allocator<int>>::pop") {
        std::cerr << "compact Itanium label failed\n";
        ++failures;
    }

    // Microsoft names are delegated to the OS DbgHelp undecorator under the
    // process-global lock. Exact keyword spacing varies by SDK, so test meaning.
    expectContains("?sum@math@@YAHHH@Z", "math::sum", "int");
    expectContains("?push@Widget@demo@@QEAAXH@Z", "demo::Widget::push", "int");
    expectContains("__imp_?sum@math@@YAHHH@Z", "import thunk for", "math::sum");

    // x86 C calling-convention decorations are deterministic and do not cause
    // ordinary leading-underscore ELF names to be rewritten.
    expectEq("_CreateThing@8", "CreateThing");
    expectEq("@FastThing@12", "FastThing");
    expectEq("vectorCall@@16", "vectorCall");
    expectEq("_start", "_start");
    expectEq("plain_name", "plain_name");
    if (DemangleForLabel("?push@Widget@demo@@QEAAXH@Z").find("demo::Widget::push") == std::string::npos) {
        std::cerr << "compact Microsoft label failed\n";
        ++failures;
    }

    // Malformed/adversarial names fail closed and preserve the exact raw text.
    expectEq("_Z999999999999999999999999x", "_Z999999999999999999999999x");
    expectEq("_ZN3foo", "_ZN3foo");
    std::string oversized(5000, 'A');
    if (DemangleSymbol(oversized).text != oversized) ++failures;

    // The shared cache must be deterministic and safe under analysis/UI races.
    ClearDemangleCache();
    std::atomic<bool> bad = false;
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) threads.emplace_back([&] {
        for (int i = 0; i < 1000; ++i)
            if (DemangleForDisplay("_ZN3foo3barEi") != "foo::bar(int)") bad = true;
    });
    for (auto& t : threads) t.join();
    if (bad || DemangleCacheSize() != 1) {
        std::cerr << "thread-safe cache invariant failed\n";
        ++failures;
    }

    if (failures) {
        std::cerr << failures << " demangle test(s) failed\n";
        return 1;
    }
    std::cout << "demangle tests passed\n";
    return 0;
}
