#include <cstdio>
#include <string>

int main() {
    const char* test_values[] = {
        "0x7FFFFFFFFFFFFFFF",  // INT64_MAX
        "0x8000000000000000",  // INT64_MAX+1
        "0xFFFFFFFFFFFFFFFF",  // UINT64_MAX
    };
    
    for (const char* s : test_values) {
        char* end = nullptr;
        long long v = std::strtoll(s, &end, 16);
        char dec[48];
        std::snprintf(dec, sizeof(dec), "%lld", v);
        printf("Input: %s  ->  decimal: %s\n", s, dec);
    }
    
    return 0;
}
