#pragma once
//
// ConnectionSchema.h
// Dependency-light schema/config layer for the future local connection API
// (additions.md section E). This is intentionally only a typed envelope,
// validation, and project-persisted config/event model; it is not a scripting or
// plugin API and does not start any listener by itself.
//
#include "Json.h"

#include <string>

namespace ds {

struct ConnectionConfig {
    bool        enabled = false;       // disabled by default
    bool        localhostOnly = true;  // local-only by default
    bool        authEnabled = false;
    std::string accessToken;           // per-project token when authEnabled
};

struct ConnectionEnvelope {
    std::string type;       // "event" | "request" | "response"
    std::string source;     // "tool" / "agent" / "user" / ...
    std::string projectId;
    std::string artifactId;
    std::string address;    // kept as string for exact 64-bit/foreign IDs
    std::string method;
    std::string payloadJson = "{}";   // JSON object text
    std::string timestamp;
};

bool IsLoopbackHost(const std::string& host);
bool ValidateConnectionConfig(const ConnectionConfig& cfg, std::string* err = nullptr);
bool ValidateConnectionEnvelope(const ConnectionEnvelope& msg, std::string* err = nullptr);

json::Value ConnectionEnvelopeToJsonValue(const ConnectionEnvelope& msg);
bool ConnectionEnvelopeFromJsonValue(const json::Value& v, ConnectionEnvelope& out,
                                     std::string* err = nullptr);

std::string SerializeConnectionEnvelope(const ConnectionEnvelope& msg);
bool DeserializeConnectionEnvelope(const std::string& text, ConnectionEnvelope& out,
                                   std::string* err = nullptr);

} // namespace ds
