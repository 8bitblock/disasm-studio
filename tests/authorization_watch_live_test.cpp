// Build the Authorization Watch core fixture with its debugger-backed integration
// path enabled. Keeping the live variant separate lets the default pure suite stay
// deterministic while the manifest can select this launch/debugger regression.
#define DS_AUTHORIZATION_WATCH_LIVE_TEST 1
#include "authorization_watch_test.cpp"
