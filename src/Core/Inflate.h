#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
// Hand-rolled RFC 1951 raw-DEFLATE decoder (no zlib). Bounded: fails cleanly on
// malformed input instead of crashing or spinning; output capped at maxOut.
bool InflateRaw(const uint8_t* src, size_t srcLen, std::vector<uint8_t>& out,
                size_t maxOut = (size_t)1 << 29);
