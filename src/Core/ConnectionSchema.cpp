#include "ConnectionSchema.h"

#include <algorithm>
#include <cctype>

namespace ds {

namespace {

std::string lower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

void setErr(std::string* err, const char* s) {
    if (err) *err = s;
}

bool validType(const std::string& t) {
    return t == "event" || t == "request" || t == "response";
}

bool safeSmallText(const std::string& s, size_t cap) {
    if (s.size() > cap) return false;
    for (unsigned char c : s)
        if (c < 0x20 && c != '\t') return false;
    return true;
}

bool validAddressString(const std::string& s) {
    if (s.empty()) return true;
    size_t first = 0;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) first = 2;
    const size_t digits = s.size() - first;
    // Project addresses are exact uint64 values, not arbitrary-width foreign
    // identifiers. Enforce the same full-token rule as the other sidecar fields.
    if (!digits || digits > 16) return false;
    for (size_t i = first; i < s.size(); ++i)
        if (!std::isxdigit(static_cast<unsigned char>(s[i]))) return false;
    return true;
}

bool optionalStringField(const json::Value& object, const char* key,
                         std::string& out, std::string* err) {
    const json::Value* value = object.find(key);
    if (!value) {
        out.clear();
        return true;
    }
    if (!value->isStr()) {
        if (err) *err = std::string(key) + " must be a string";
        return false;
    }
    out = value->str;
    return true;
}

bool payloadIsObject(const std::string& text) {
    json::Value v;
    return json::Parse(text.empty() ? "{}" : text, v) && v.isObj();
}

} // namespace

bool IsLoopbackHost(const std::string& host) {
    std::string h = lower(host);
    if (h == "localhost" || h == "::1" || h == "[::1]" || h == "0:0:0:0:0:0:0:1") return true;
    if (h == "127.0.0.1") return true;
    if (h.rfind("127.", 0) == 0) return true;   // 127.0.0.0/8
    return false;
}

bool ValidateConnectionConfig(const ConnectionConfig& cfg, std::string* err) {
    if (cfg.authEnabled && cfg.accessToken.empty()) {
        setErr(err, "auth is enabled but the project access token is empty");
        return false;
    }
    if (cfg.accessToken.size() > 256) {
        setErr(err, "project access token is too long");
        return false;
    }
    if (!cfg.enabled) return true;
    if (!cfg.localhostOnly) {
        setErr(err, "non-local listeners are intentionally not supported by this framework");
        return false;
    }
    return true;
}

bool ValidateConnectionEnvelope(const ConnectionEnvelope& msg, std::string* err) {
    if (!validType(msg.type)) {
        setErr(err, "type must be event, request, or response");
        return false;
    }
    if (msg.source.empty() || !safeSmallText(msg.source, 64)) {
        setErr(err, "source is required and must be short text");
        return false;
    }
    if (!safeSmallText(msg.projectId, 128) || !safeSmallText(msg.artifactId, 128) ||
        !safeSmallText(msg.method, 160) || !safeSmallText(msg.timestamp, 80)) {
        setErr(err, "project/artifact/method/timestamp field is too long or contains control characters");
        return false;
    }
    if (!validAddressString(msg.address)) {
        setErr(err, "address must be empty or a hex string");
        return false;
    }
    if (!payloadIsObject(msg.payloadJson)) {
        setErr(err, "payload must be a JSON object");
        return false;
    }
    return true;
}

json::Value ConnectionEnvelopeToJsonValue(const ConnectionEnvelope& msg) {
    json::Value root = json::Value::Obj();
    root.set("type",        json::Value::Str(msg.type));
    root.set("source",      json::Value::Str(msg.source));
    root.set("project_id",  json::Value::Str(msg.projectId));
    root.set("artifact_id", json::Value::Str(msg.artifactId));
    root.set("address",     json::Value::Str(msg.address));
    root.set("method",      json::Value::Str(msg.method));
    json::Value payload = json::Value::Obj();
    json::Parse(msg.payloadJson.empty() ? "{}" : msg.payloadJson, payload);
    if (!payload.isObj()) payload = json::Value::Obj();
    root.set("payload", std::move(payload));
    root.set("timestamp", json::Value::Str(msg.timestamp));
    return root;
}

bool ConnectionEnvelopeFromJsonValue(const json::Value& v, ConnectionEnvelope& out,
                                     std::string* err) {
    if (!v.isObj()) {
        setErr(err, "message must be a JSON object");
        return false;
    }
    ConnectionEnvelope msg;
    if (!optionalStringField(v, "type", msg.type, err) ||
        !optionalStringField(v, "source", msg.source, err) ||
        !optionalStringField(v, "project_id", msg.projectId, err) ||
        !optionalStringField(v, "artifact_id", msg.artifactId, err) ||
        !optionalStringField(v, "address", msg.address, err) ||
        !optionalStringField(v, "method", msg.method, err) ||
        !optionalStringField(v, "timestamp", msg.timestamp, err))
        return false;
    if (const json::Value* p = v.find("payload")) {
        if (!p->isObj()) {
            setErr(err, "payload must be a JSON object");
            return false;
        }
        msg.payloadJson = json::Dump(*p, false);
    } else {
        msg.payloadJson = "{}";
    }
    if (!ValidateConnectionEnvelope(msg, err)) return false;
    out = std::move(msg);
    return true;
}

std::string SerializeConnectionEnvelope(const ConnectionEnvelope& msg) {
    return json::Dump(ConnectionEnvelopeToJsonValue(msg), true);
}

bool DeserializeConnectionEnvelope(const std::string& text, ConnectionEnvelope& out,
                                   std::string* err) {
    json::Value root;
    if (!json::Parse(text, root)) {
        setErr(err, "message is not valid JSON");
        return false;
    }
    return ConnectionEnvelopeFromJsonValue(root, out, err);
}

} // namespace ds
