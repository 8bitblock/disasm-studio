//
// connection_schema_test.cpp
// Pure tests for the local API schema/config framework (additions.md E).
//
#include "Core/ConnectionSchema.h"

#include <cstdio>
#include <string>

using namespace ds;

static int g_fail = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++g_fail; } } while (0)

int main() {
    CHECK(IsLoopbackHost("localhost"));
    CHECK(IsLoopbackHost("127.0.0.42"));
    CHECK(IsLoopbackHost("[::1]"));
    CHECK(!IsLoopbackHost("192.168.1.10"));

    ConnectionConfig cfg;
    CHECK(!cfg.enabled && cfg.localhostOnly);
    CHECK(ValidateConnectionConfig(cfg));
    cfg.enabled = true;
    cfg.authEnabled = true;
    std::string err;
    CHECK(!ValidateConnectionConfig(cfg, &err));
    CHECK(err.find("token") != std::string::npos);
    cfg.accessToken = "abc";
    CHECK(ValidateConnectionConfig(cfg));
    cfg.localhostOnly = false;
    CHECK(!ValidateConnectionConfig(cfg, &err));

    ConnectionEnvelope msg;
    msg.type = "event";
    msg.source = "tool";
    msg.projectId = "p";
    msg.artifactId = "a";
    msg.address = "0x140000123";
    msg.method = "breakpoint.hit";
    msg.payloadJson = "{\"tid\":7}";
    msg.timestamp = "2026-06-12T00:00:00Z";
    CHECK(ValidateConnectionEnvelope(msg, &err));

    std::string js = SerializeConnectionEnvelope(msg);
    ConnectionEnvelope rt;
    CHECK(DeserializeConnectionEnvelope(js, rt, &err));
    CHECK(rt.type == "event" && rt.source == "tool");
    CHECK(rt.address == "0x140000123");
    CHECK(rt.payloadJson.find("\"tid\"") != std::string::npos);

    msg.type = "execute";
    CHECK(!ValidateConnectionEnvelope(msg, &err));
    msg.type = "event";
    msg.payloadJson = "[]";
    CHECK(!ValidateConnectionEnvelope(msg, &err));
    msg.payloadJson = "{}";
    msg.address = "0xZZ";
    CHECK(!ValidateConnectionEnvelope(msg, &err));
    msg.address = "0x10000000000000000";
    CHECK(!ValidateConnectionEnvelope(msg, &err));
    msg.address = "0xFFFFFFFFFFFFFFFF";
    CHECK(ValidateConnectionEnvelope(msg, &err));

    // Present known fields are schema-authoritative. A numeric address must not
    // be coerced to the optional empty string and accepted as if it were absent.
    ConnectionEnvelope malformed;
    CHECK(!DeserializeConnectionEnvelope(
        "{\"type\":\"event\",\"source\":\"tool\",\"address\":16,\"payload\":{}}",
        malformed, &err));

    if (g_fail) { std::printf("%d CHECK(s) FAILED\n", g_fail); return 1; }
    std::printf("connection_schema_test: all checks passed\n");
    return 0;
}
