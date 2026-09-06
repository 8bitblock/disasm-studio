#pragma once
//
// NetworkEndpoint.h
// Allocation-bounded, platform-independent presentation of IP Helper address
// bytes. IPv6 follows RFC 5952-style longest-zero compression and preserves a
// numeric scope ID so link-local endpoints from different interfaces remain
// distinguishable.
//

#include <cstdint>
#include <string>

namespace ds {

std::string FormatIpv4Address(const uint8_t address[4]);
std::string FormatIpv6Address(const uint8_t address[16], uint32_t scopeId = 0);
std::string FormatIpv4Endpoint(const uint8_t address[4], uint16_t hostPort);
std::string FormatIpv6Endpoint(const uint8_t address[16], uint16_t hostPort,
                               uint32_t scopeId = 0);

} // namespace ds
