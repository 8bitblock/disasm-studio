#include "GameContext.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <unordered_map>

namespace ds {

const char* GameStringCategoryName(GameStringCategory c) {
    switch (c) {
        case GameStringCategory::Asset:         return "asset";
        case GameStringCategory::Config:        return "config";
        case GameStringCategory::Save:          return "save";
        case GameStringCategory::Replay:        return "replay";
        case GameStringCategory::Network:       return "network";
        case GameStringCategory::UI:            return "ui";
        case GameStringCategory::Error:         return "error";
        case GameStringCategory::Debug:         return "debug";
        case GameStringCategory::ScriptRuntime: return "script/runtime";
        case GameStringCategory::Other:         return "other";
    }
    return "other";
}

const char* GameFunctionKindName(GameFunctionKind k) {
    switch (k) {
        case GameFunctionKind::UpdateLoop:     return "update/tick loop";
        case GameFunctionKind::Render:         return "render";
        case GameFunctionKind::Input:          return "input";
        case GameFunctionKind::EntityObject:   return "entity/object";
        case GameFunctionKind::ResourceLoad:   return "resource load";
        case GameFunctionKind::Audio:          return "audio";
        case GameFunctionKind::Network:        return "network";
        case GameFunctionKind::VtableVirtual:  return "vtable/virtual";
        case GameFunctionKind::NativeBoundary: return "native boundary";
        case GameFunctionKind::Validation:     return "validation/check";
        case GameFunctionKind::Encoding:       return "encoding/hash";
        case GameFunctionKind::Timer:          return "timer";
        case GameFunctionKind::Callback:       return "callback";
        case GameFunctionKind::ConfigSave:     return "config/save";
    }
    return "candidate";
}

namespace {

std::string lower(std::string s) {
    for (char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

bool has(const std::string& s, const char* needle) {
    return s.find(needle) != std::string::npos;
}

bool any(const std::string& s, std::initializer_list<const char*> needles) {
    for (const char* n : needles) if (has(s, n)) return true;
    return false;
}

bool endsWithAny(const std::string& s, std::initializer_list<const char*> suffixes) {
    for (const char* suf : suffixes) {
        const size_t n = std::strlen(suf);
        if (s.size() >= n && s.compare(s.size() - n, n, suf) == 0) return true;
    }
    return false;
}

GameStringFinding classifyString(const StrResult& r) {
    GameStringFinding out;
    out.address = r.address;
    out.text = r.text;
    out.category = GameStringCategory::Other;
    out.confidence = 0.0f;

    std::string s = lower(r.text);
    auto set = [&](GameStringCategory c, float conf, const char* why) {
        if (conf <= out.confidence) return;
        out.category = c;
        out.confidence = conf;
        out.evidence = why;
    };

    if (endsWithAny(s, { ".png", ".jpg", ".jpeg", ".dds", ".tga", ".bmp", ".webp",
                        ".wav", ".ogg", ".mp3", ".flac", ".fbx", ".obj", ".mesh",
                        ".shader", ".mat", ".prefab", ".atlas", ".sprite", ".pak",
                        ".uasset", ".umap", ".unity3d", ".bundle" }))
        set(GameStringCategory::Asset, 0.85f, "file extension commonly used for game assets");
    if (endsWithAny(s, { ".ini", ".cfg", ".json", ".xml", ".yaml", ".yml", ".toml",
                        ".properties", ".prefs", ".settings" }) ||
        any(s, { "config", "settings", "options", "preferences" }))
        set(GameStringCategory::Config, 0.75f, "configuration-looking path or keyword");
    if (endsWithAny(s, { ".sav", ".save", ".profile" }) ||
        any(s, { "savegame", "save_game", "save slot", "profile.dat", "highscore" }))
        set(GameStringCategory::Save, 0.78f, "save/profile/high-score string");
    if (endsWithAny(s, { ".replay", ".demo", ".ghost" }) || any(s, { "replay", "ghost run" }))
        set(GameStringCategory::Replay, 0.72f, "replay/demo-looking string");
    if (any(s, { "localhost", "127.0.0.1", "[::1]", "http://", "https://", "ws://", "wss://",
                 "server", "socket", "connect", "matchmaking", "leaderboard", "port ",
                 "keep-alive", "heartbeat", "authorization", "bearer", "token", "signature", "key=" }))
        set(GameStringCategory::Network, any(s, { "localhost", "127.0.0.1", "[::1]" }) ? 0.82f : 0.70f,
            "network endpoint, localhost handoff, or auth/keep-alive keyword");
    if (any(s, { "menu", "button", "dialog", "hud", "score", "pause", "press start",
                 "loading...", "game over" }))
        set(GameStringCategory::UI, 0.62f, "user-interface text");
    if (any(s, { "error", "failed", "failure", "exception", "fatal", "invalid" }))
        set(GameStringCategory::Error, 0.66f, "error/failure text");
    if (any(s, { "debug", "assert", "trace", "log:", "verbose" }))
        set(GameStringCategory::Debug, 0.66f, "debug/log/assert text");
    if (endsWithAny(s, { ".lua", ".py", ".js", ".cs", ".class", ".jar" }) ||
        any(s, { "lua_", "mono", "il2cpp", "jni", "jvm", "lwjgl", "node_modules" }))
        set(GameStringCategory::ScriptRuntime, 0.72f, "script/runtime boundary string");
    return out;
}

void addFunction(std::vector<GameFunctionFinding>& out, uint64_t va, const std::string& name,
                 GameFunctionKind kind, float conf, const std::string& evidence) {
    for (GameFunctionFinding& f : out) {
        if (f.address == va && f.kind == kind) {
            if (conf > f.confidence) { f.confidence = conf; f.evidence = evidence; f.name = name; }
            return;
        }
    }
    out.push_back({ va, name, kind, conf, evidence });
}

void classifyFunction(const FuncResult& f, std::vector<GameFunctionFinding>& out) {
    const std::string hay = lower(f.name + " " + f.reason);
    auto add = [&](GameFunctionKind k, float conf, const char* why) {
        addFunction(out, f.address, f.name, k, conf, why);
    };
    if (any(hay, { "update", "tick", "frame", "game_loop", "main_loop", "message pump" }))
        add(GameFunctionKind::UpdateLoop, 0.72f, "function name/evidence suggests a recurring update loop");
    if (any(hay, { "render", "draw", "present", "paint", "swapchain", "d3d", "directx", "opengl", "vulkan" }))
        add(GameFunctionKind::Render, 0.74f, "function name/evidence suggests rendering");
    if (any(hay, { "input", "keyboard", "mouse", "controller", "joystick", "get_async_key", "read_user_input", "scanf" }))
        add(GameFunctionKind::Input, 0.75f, "function name/evidence suggests input handling");
    if (any(hay, { "entity", "actor", "player", "npc", "object_manager", "component", "gameobject" }))
        add(GameFunctionKind::EntityObject, 0.66f, "function name/evidence suggests entity or object management");
    if (any(hay, { "resource", "asset", "texture", "load_file", "read_file", "open_file", "load_config" }))
        add(GameFunctionKind::ResourceLoad, 0.70f, "function name/evidence suggests loading assets or files");
    if (any(hay, { "audio", "sound", "music", "wave", "ogg" }))
        add(GameFunctionKind::Audio, 0.68f, "function name/evidence suggests audio");
    if (any(hay, { "net_", "network", "socket", "send", "recv", "connect", "http" }))
        add(GameFunctionKind::Network, 0.72f, "function name/evidence suggests networking");
    if (any(hay, { "vtable", "virtual", "this-pointer", "thiscall" }))
        add(GameFunctionKind::VtableVirtual, 0.64f, "function evidence suggests object dispatch");
    if (any(hay, { "jni", "native", "load_library", "loadlibrary", "lwjgl", "jvm" }))
        add(GameFunctionKind::NativeBoundary, 0.70f, "function name/evidence suggests a managed/native boundary");
    if (any(hay, { "check", "validate", "password", "serial", "license", "strcmp", "string compare", "input validation" }))
        add(GameFunctionKind::Validation, 0.76f, "function name/evidence suggests validation");
    if (any(hay, { "xor", "decode", "encode", "checksum", "hash", "crc", "base64", "encrypt", "decrypt" }))
        add(GameFunctionKind::Encoding, 0.72f, "function name/evidence suggests encoding/hash/crypto");
    if (any(hay, { "timer", "time", "get_tick_count", "query_performance" }))
        add(GameFunctionKind::Timer, 0.62f, "function name/evidence suggests timer use");
    if (any(hay, { "callback", "wndproc", "hook", "register_class", "message pump" }))
        add(GameFunctionKind::Callback, 0.62f, "function name/evidence suggests callback registration/dispatch");
    if (any(hay, { "config", "save", "replay", "profile", "settings" }))
        add(GameFunctionKind::ConfigSave, 0.66f, "function name/evidence suggests config/save/replay handling");
}

Finding makeHint(const char* title, float conf, std::string detail, std::string evidence, uint64_t va = 0) {
    Finding f;
    f.analyzer = "GameContext";
    f.title = title;
    f.category = "workflow";
    f.confidence = conf;
    f.detail = std::move(detail);
    if (!evidence.empty()) {
        FindingEvidence ev;
        ev.what = std::move(evidence);
        ev.va = va;
        f.evidence.push_back(std::move(ev));
    }
    f.address = va;
    return f;
}

} // namespace

GameContextReport BuildGameContext(const GameContextInput& in) {
    GameContextReport out;

    for (const Finding& f : in.runtime.findings) {
        if (f.category == "runtime" || f.category == "container")
            out.runtimeBoundaries.push_back(f);
    }
    if (in.runtime.wrapperLikely) {
        out.crackmeHints.push_back(makeHint(
            "Runtime handoff",
            in.runtime.wrapperConfidence,
            "Start at the runtime payload before spending too long in launcher code.",
            in.runtime.wrapperDetail));
    }

    for (const StrResult& s : in.strings) {
        GameStringFinding gs = classifyString(s);
        if (gs.category != GameStringCategory::Other)
            out.strings.push_back(std::move(gs));

        std::string lo = lower(s.text);
        if (any(lo, { "password", "serial", "license", "success", "correct", "wrong",
                     "invalid", "try again", "congrat", "access granted", "access denied" })) {
            std::string ev = "string at this address contains crackme-style feedback or secret-input wording";
            out.crackmeHints.push_back(makeHint("Crackme string", 0.70f, s.text, ev, s.address));
        }
        if (any(lo, { "localhost", "127.0.0.1", "[::1]" }) &&
            any(lo, { "token", "key=", "signature", "sign=", "keep-alive", "heartbeat" })) {
            std::string ev = "loopback endpoint string includes auth/key/signature or keep-alive wording";
            out.crackmeHints.push_back(makeHint("Localhost handoff", 0.82f, s.text, ev, s.address));
        }
    }

    for (const FuncResult& f : in.functions) classifyFunction(f, out.functions);

    for (const AlgoMatch& a : in.algorithms) {
        if (!(a.category == "crypto" || a.category == "hash" ||
              a.category == "checksum" || a.category == "encoding")) continue;
        if (a.referencedBy.empty()) {
            out.crackmeHints.push_back(makeHint("Algorithm constants", a.confidence,
                a.name, "recognized constants or alphabets present in the image", a.address));
            continue;
        }
        for (const AlgoXref& xr : a.referencedBy) {
            std::string ev = "references " + a.name + " (" + a.category + ")";
            addFunction(out.functions, xr.funcAddress, xr.funcName, GameFunctionKind::Encoding,
                        std::max(0.55f, a.confidence * 0.85f), ev);
            out.crackmeHints.push_back(makeHint("Algorithm-backed routine", a.confidence,
                xr.funcName.empty() ? a.name : xr.funcName, ev, xr.funcAddress));
        }
    }

    for (const GameFunctionFinding& f : out.functions) {
        if (f.kind == GameFunctionKind::Validation || f.kind == GameFunctionKind::Input ||
            f.kind == GameFunctionKind::Encoding) {
            out.crackmeHints.push_back(makeHint(
                GameFunctionKindName(f.kind), f.confidence,
                f.name.empty() ? std::string("candidate function") : f.name,
                f.evidence, f.address));
        }
    }

    auto byConf = [](const auto& a, const auto& b) {
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        return a.address < b.address;
    };
    std::sort(out.strings.begin(), out.strings.end(), byConf);
    std::sort(out.functions.begin(), out.functions.end(), byConf);
    std::sort(out.crackmeHints.begin(), out.crackmeHints.end(),
              [](const Finding& a, const Finding& b) {
                  if (a.confidence != b.confidence) return a.confidence > b.confidence;
                  return a.address < b.address;
              });
    return out;
}

} // namespace ds
