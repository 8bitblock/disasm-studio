#pragma once

#include <cstdint>

namespace ds {

// A PID is not sufficient to identify a debugger target: Windows can reuse it
// after detach.  The monotonically changing session generation disambiguates
// reattachments, while the PID catches an accidentally mismatched handle.
struct DebugTargetIdentity {
    uint32_t pid = 0;
    uint64_t sessionGeneration = 0;

    constexpr bool valid() const noexcept {
        return pid != 0 && sessionGeneration != 0;
    }
};

inline constexpr bool DebugTargetIdentityMatches(DebugTargetIdentity current,
                                                 DebugTargetIdentity expected) noexcept {
    return current.valid() && expected.valid() &&
           current.pid == expected.pid &&
           current.sessionGeneration == expected.sessionGeneration;
}

} // namespace ds
