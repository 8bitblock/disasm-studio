#include "Core/Project.h"
#include "Core/Json.h"
#include <cstdio>
#include <stdexcept>
#include <string>

using namespace ds;
static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::printf("FAIL line %d: %s\n", __LINE__, #x); ++failures; } } while (0)

int main() {
    ProjectState project;
    project.hash = 0xF123456789ABCDEFull;
    CHECK(!project.hasContent());
    project.gmlBreakpoints.push_back({ { project.hash, 0, 0 }, true });
    project.gmlBreakpoints.push_back({ { project.hash, 1, 0xFFFFFFFCu, 0 }, false });
    GmlSavedWatch global;
    global.target.archiveHash = project.hash;
    global.target.variableName = "score";
    global.label = "Current score";
    project.gmlWatches.push_back(global);
    auto object = global;
    object.target.scope = GmlVariableScope::UniqueObject;
    object.target.objectIndex = 0;
    object.target.variableName = "health";
    project.gmlWatches.push_back(object);
    CHECK(project.hasContent());
    const std::string serialized = SerializeProject(project);
    CHECK(serialized.find("\"version\": 5") != std::string::npos);
    ProjectState loaded;
    CHECK(DeserializeProject(serialized, loaded));
    CHECK(loaded.gmlBreakpoints.size() == 2 && loaded.gmlWatches.size() == 2);
    CHECK(loaded.gmlBreakpoints[0].location == project.gmlBreakpoints[0].location);
    CHECK(!loaded.gmlBreakpoints[1].enabled && loaded.gmlBreakpoints[1].location.byteOffset == 0xFFFFFFFCu);
    CHECK(loaded.gmlWatches[0].target.archiveHash == project.hash);
    CHECK(loaded.gmlWatches[1].target.objectIndex == 0);
    CHECK(loaded.gmlWatches[0].target.owner == GmlPauseIdentity{});
    CHECK(SerializeProject(loaded) == serialized);
    for (int version = 1; version <= 5; ++version) {
        ProjectState legacy;
        CHECK(DeserializeProject("{\"version\":" + std::to_string(version) + "}", legacy));
        CHECK(legacy.gmlBreakpoints.empty() && legacy.gmlWatches.empty());
    }
    CHECK(!DeserializeProject("{\"version\":6}", loaded));

    json::Value root;
    CHECK(json::Parse(serialized, root));
    auto reject = [&](json::Value invalid) {
        ProjectState untouched;
        untouched.name = "retained";
        CHECK(!DeserializeProject(json::Dump(invalid), untouched));
        CHECK(untouched.name == "retained" && untouched.gmlBreakpoints.empty());
    };
    auto invalid = root;
    invalid.set("version", json::Value::Int(4)); reject(invalid);
    invalid = root;
    invalid.find("gmlBreakpoints")->arr[0].set("archiveHash", json::Value::Str("0x0")); reject(invalid);
    invalid = root;
    invalid.find("gmlBreakpoints")->arr[0].set("archiveHash", json::Value::Num(12)); reject(invalid);
    invalid = root;
    invalid.find("gmlBreakpoints")->arr[0].set("byteOffset", json::Value::Int(-1)); reject(invalid);
    invalid = root;
    invalid.find("gmlBreakpoints")->arr[0].set("codeIndex", json::Value::Int(UINT32_MAX)); reject(invalid);
    invalid = root;
    invalid.find("gmlBreakpoints")->arr[0].set("parentCodeIndex", json::Value::Int(0)); reject(invalid);
    invalid = root;
    invalid.find("gmlBreakpoints")->arr[0].set("enabled", json::Value::Str("true")); reject(invalid);
    invalid = root;
    invalid.find("gmlBreakpoints")->arr[1] = invalid.find("gmlBreakpoints")->arr[0]; reject(invalid);
    invalid = root;
    invalid.find("gmlBreakpoints")->arr.resize(kGmlMaxBreakpoints + 1); reject(invalid);
    invalid = root;
    invalid.find("gmlWatches")->arr.resize(kGmlMaxWatches + 1); reject(invalid);
    invalid = root;
    invalid.find("gmlWatches")->arr[0].set("scope", json::Value::Str("session_instance")); reject(invalid);
    invalid = root;
    invalid.find("gmlWatches")->arr[0].set("variable", json::Value::Str(std::string(kGmlMaxVariableNameBytes + 1, 'x'))); reject(invalid);
    invalid = root;
    invalid.find("gmlWatches")->arr[0].set("objectIndex", json::Value::Int(0)); reject(invalid);
    for (const char* forbidden : { "address", "instanceId", "frameId", "owner", "armed", "freezeActive" }) {
        invalid = root;
        invalid.find("gmlWatches")->arr[0].set(forbidden, json::Value::Str("0x123"));
        reject(invalid);
    }
    auto transient = project;
    transient.gmlWatches[0].target.owner = { 1, 2, 3, 4, 5 };
    bool rejected = false;
    try { (void)SerializeProject(transient); } catch (const std::invalid_argument&) { rejected = true; }
    CHECK(rejected);
    project.reset();
    CHECK(!project.hasContent() && project.gmlBreakpoints.empty() && project.gmlWatches.empty());
    std::printf("gamemaker_project_test: %s\n", failures ? "FAILED" : "all checks passed");
    return failures ? 1 : 0;
}
