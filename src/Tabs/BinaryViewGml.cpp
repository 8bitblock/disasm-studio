#include "BinaryViewTab.h"
#include "../Core/GameMakerArchive.h"
#include "../Core/GameMakerDebug.h"
#include "../Ui/Theme.h"
#include "../Ui/Widgets.h"
#include "imgui.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>

namespace ds {
namespace {
bool locationForOffset(const BinaryFile& binary, uint64_t offset, GmlCodeLocation& location) {
    const auto archive = binary.gameMakerArchive();
    if (!archive || !archive->isInstructionOffset(offset)) return false;
    const auto* root = archive->codeAtOffset(offset);
    if (!root || offset < root->bytecodeOffset || offset - root->bytecodeOffset > UINT32_MAX)
        return false;
    location = {};
    location.archiveHash = binary.contentHash();
    location.codeIndex = root->index;
    location.byteOffset = static_cast<uint32_t>(offset - root->bytecodeOffset);
    location.parentCodeIndex = kGmlNoCodeIndex;
    return true;
}
std::string foldName(std::string_view value) {
    std::string out(value);
    for (char& c : out) if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
    return out;
}
void syncBreakpoints(AppContext& ctx) {
    const auto current=ctx.debug.gameMakerSnapshot();
    if(current.archiveHash!=ctx.staticBinary().contentHash() || current.state==GameMakerSessionState::Disconnected || current.state==GameMakerSessionState::Inert)return;
    std::string error;
    if(!ctx.debug.setGameMakerBreakpoints(ctx.staticBinary().contentHash(),ctx.staticProject().gmlBreakpoints,error))ui::Toast(ui::ToastKind::Warn,error);
}
std::string numericText(const GmlHelperNumericSlot& slot) {
    if(slot.availability!=GmlValueAvailability::Available)return "unavailable";
    switch(slot.kind){
    case GmlNumericKind::Real:{double n;std::memcpy(&n,&slot.value.payload,sizeof(n));char text[64];std::snprintf(text,sizeof(text),"%.17g",n);return text;}
    case GmlNumericKind::Int32:return std::to_string(static_cast<int32_t>(slot.value.payload));
    case GmlNumericKind::Int64:return std::to_string(static_cast<int64_t>(slot.value.payload));
    // The verified Nubby adapter stores boolean payloads as Float64.
    case GmlNumericKind::Boolean:{double n;std::memcpy(&n,&slot.value.payload,sizeof(n));return n!=0.0?"true":"false";}
    default:return "opaque value";
    }
}
const char* numericType(GmlNumericKind kind){switch(kind){case GmlNumericKind::Real:return "real";case GmlNumericKind::Int32:return "int32";case GmlNumericKind::Int64:return "int64";case GmlNumericKind::Boolean:return "boolean";default:return "opaque";}}
const char* scopeText(GmlVariableScope scope){switch(scope){case GmlVariableScope::Global:return "global";case GmlVariableScope::UniqueObject:return "unique object";case GmlVariableScope::SessionInstance:return "instance";case GmlVariableScope::FrameLocal:return "local / stack";default:return "unknown";}}
const char* resolveText(GmlVariableResolveStatus s){switch(s){case GmlVariableResolveStatus::Resolved:return "resolved";case GmlVariableResolveStatus::Missing:return "unresolved";case GmlVariableResolveStatus::Ambiguous:return "ambiguous: select an instance";case GmlVariableResolveStatus::Incomplete:return "incomplete enumeration";case GmlVariableResolveStatus::StaleOwner:return "expired session/frame";default:return "invalid target";}}
bool exactSlotName(const GmlHelperNumericSlot& slot){return slot.nameLength>0 && slot.nameLength<sizeof(slot.name) && slot.name[slot.nameLength]=='\0';}
bool scopeComplete(const GmlHelperStop& stop,const GmlVariableTarget& target){
    if(target.scope==GmlVariableScope::Global)return stop.globalsComplete==1;
    if(target.scope==GmlVariableScope::UniqueObject){
        if(!stop.instancesComplete)return false;
        for(uint32_t i=0;i<stop.instanceCount;++i)if(stop.instances[i].objectIndex==target.objectIndex && stop.instances[i].variablesAvailability!=GmlValueAvailability::Available)return false;
        return true;
    }
    if(target.scope==GmlVariableScope::SessionInstance && stop.instancesComplete){
        for(uint32_t i=0;i<stop.instanceCount;++i)if(stop.instances[i].instanceId==target.instanceId)return stop.instances[i].variablesAvailability==GmlValueAvailability::Available;
        return true; // Complete registry proves destruction when the token is absent.
    }
    for(uint32_t i=0;i<stop.frameCount;++i){const auto& frame=stop.frames[i];
        if(target.scope==GmlVariableScope::FrameLocal && frame.frameId==target.frameId)
            return frame.localsAvailability==GmlValueAvailability::Available;
        if(target.scope==GmlVariableScope::SessionInstance && frame.instanceId==target.instanceId)
            return frame.selfAvailability==GmlValueAvailability::Available;
    }
    if(target.scope==GmlVariableScope::FrameLocal)return stop.framesComplete==1;
    return stop.variablesComplete==1;
}
const char* availabilityText(GmlValueAvailability value){switch(value){case GmlValueAvailability::Available:return "available";case GmlValueAvailability::Truncated:return "partial";default:return "unavailable";}}
}

bool BinaryViewTab::hasGmlBreakpoint(const AppContext& ctx, uint64_t fileOffset) const {
    GmlCodeLocation location;
    if (!locationForOffset(ctx.staticBinary(), fileOffset, location)) return false;
    const auto& rows = ctx.staticProject().gmlBreakpoints;
    return std::any_of(rows.begin(), rows.end(), [&](const auto& row) {
        return row.enabled && row.location == location;
    });
}

void BinaryViewTab::addGmlBreakpoints(AppContext& ctx,const std::vector<uint64_t>& fileOffsets){
    auto& rows=ctx.staticProject().gmlBreakpoints;bool changed=false;
    for(uint64_t offset:fileOffsets){GmlCodeLocation location;if(!locationForOffset(ctx.staticBinary(),offset,location))continue;
        auto existing=std::find_if(rows.begin(),rows.end(),[&](const auto& row){return row.location==location;});
        if(existing!=rows.end()){if(!existing->enabled){existing->enabled=true;changed=true;}}
        else if(rows.size()<kGmlMaxBreakpoints){rows.push_back({location,true});changed=true;}
        else{ui::Toast(ui::ToastKind::Warn,"The GML breakpoint limit has been reached.");break;}
    }
    if(changed){ctx.markProjectDirty();syncBreakpoints(ctx);}
}

void BinaryViewTab::toggleGmlBreakpoint(AppContext& ctx, uint64_t fileOffset) {
    GmlCodeLocation location;
    if (!locationForOffset(ctx.staticBinary(), fileOffset, location)) {
        ui::Toast(ui::ToastKind::Warn, "GML breakpoints require a validated bytecode instruction.");
        return;
    }
    auto& rows = ctx.staticProject().gmlBreakpoints;
    const auto found = std::find_if(rows.begin(), rows.end(), [&](const auto& row) {
        return row.location == location;
    });
    if (found != rows.end()) rows.erase(found);
    else {
        if (rows.size() >= kGmlMaxBreakpoints) {
            ui::Toast(ui::ToastKind::Warn, "The GML breakpoint limit has been reached.");
            return;
        }
        rows.push_back({location, true});
    }
    ctx.markProjectDirty();
    syncBreakpoints(ctx);
}

void BinaryViewTab::renderGameMakerTab(AppContext& ctx) {
    const auto archive = ctx.staticBinary().gameMakerArchive();
    if (!archive || !ImGui::BeginTabItem("GML")) return;
    const auto session=ctx.debug.gameMakerSnapshot();
    const auto* native=ctx.frameDebugSnapshot;
    const bool paused=session.state==GameMakerSessionState::Paused && session.stop && native &&
        native->state==DbgState::Paused && native->activeTid==session.stop->identity.tid &&
        DebugTargetIdentityMatches(session.target,{native->pid,native->sessionGeneration}) &&
        session.archiveHash==ctx.staticBinary().contentHash();
    const auto stop=paused?session.stop:std::shared_ptr<const GmlHelperStop>{};
    bool openEdit=false;
    auto editSlot=[&](uint32_t index){if(!stop || index>=stop->numericSlotCount)return;gmlEditOwner_=stop->identity;gmlEditRevision_=session.revision;gmlEditSlot_=index;std::snprintf(gmlEditText_,sizeof(gmlEditText_),"%s",numericText(stop->numericSlots[index]).c_str());openEdit=true;};
    auto addWatch=[&](const GmlHelperNumericSlot& slot,bool persistent){
        if(!stop || !exactSlotName(slot))return;
        GmlVariableTarget target;target.archiveHash=ctx.staticBinary().contentHash();target.variableName.assign(slot.name,slot.nameLength);target.scope=slot.scope;
        if(slot.scope==GmlVariableScope::SessionInstance){target.objectIndex=slot.objectIndex;if(persistent)target.scope=GmlVariableScope::UniqueObject;else{target.owner=stop->identity;target.instanceId=slot.instanceId;}}
        else if(slot.scope==GmlVariableScope::FrameLocal){target.owner=stop->identity;target.frameId=slot.frameId;}
        auto& watches=GmlVariableTargetPersistent(target)?ctx.staticProject().gmlWatches:gmlTransientWatches_;
        const bool duplicate=std::any_of(watches.begin(),watches.end(),[&](const auto& w){const auto& t=w.target;return t.archiveHash==target.archiveHash && t.variableName==target.variableName && t.scope==target.scope && t.objectIndex==target.objectIndex && t.instanceId==target.instanceId && t.frameId==target.frameId && t.owner==target.owner;});
        if(!duplicate && watches.size()<kGmlMaxWatches){bool save=GmlVariableTargetPersistent(target);std::string label=std::string(scopeText(target.scope))+"."+target.variableName;watches.push_back({std::move(target),std::move(label)});if(save)ctx.markProjectDirty();}
    };
    auto editable=[&](const GmlHelperNumericSlot& slot){return paused && slot.writable==1 && slot.storage==GmlSlotStorage::Canonical && slot.availability==GmlValueAvailability::Available && slot.kind!=GmlNumericKind::None;};
    const float scale = theme::UiScale();
    ImGui::TextColored(theme::col::accent(), "%s", archive->gameName.empty()
        ? "GameMaker archive" : archive->gameName.c_str());
    ImGui::TextDisabled("%zu code records | %zu variables | bytecode %u",
        archive->code.size(), archive->variables.size(), archive->bytecodeVersion);
    if (!archive->bytecodeSupported)
        ImGui::TextColored(theme::col::warn(), "This archive's bytecode is unsupported.");
    ImGui::TextDisabled("Saved GML targets use archive and code identities; FILE offsets are not process addresses.");
    if(ImGui::SmallButton("GameMaker connection")){ctx.requestedGameMakerConnection=true;ctx.requestedTab="Communications";}
    const char* connectionStatus = session.archiveHash == ctx.staticBinary().contentHash()
        ? session.status.c_str() : "No matching live connection";
    ui::SameLineIfFits(ImGui::CalcTextSize(connectionStatus).x);
    ImGui::TextDisabled("%s", connectionStatus);
    if (paused) {
        char pauseStatus[64];
        std::snprintf(pauseStatus, sizeof(pauseStatus), "GML pause #%llu",
                      static_cast<unsigned long long>(stop->identity.stopSequence));
        ui::SameLineIfFits(ImGui::CalcTextSize(pauseStatus).x);
        ImGui::TextColored(theme::col::good(), "%s", pauseStatus);
    }
    if(!session.lastEdit.empty())ImGui::TextWrapped("%s",session.lastEdit.c_str());

    ImGui::SetNextItemWidth(std::min(180 * scale, ImGui::GetContentRegionAvail().x));
    ImGui::Combo("##gml_kind", &gmlBrowseKind_, "Scripts / code\0Variables\0Objects / events\0Breakpoints\0Watches\0Live frames\0Live variables\0Live instances\0");
    ui::SameLineIfFits(220 * scale);
    ui::SearchBox("##gml_filter", "Filter names", gmlFilter_, sizeof(gmlFilter_),
                  std::min(300 * scale, ImGui::GetContentRegionAvail().x));

    const std::string filter = foldName(gmlFilter_);
    if (gmlArchiveView_ != archive || gmlFilterApplied_ != filter || gmlBrowseKindApplied_ != gmlBrowseKind_) {
        gmlArchiveView_ = archive;
        gmlFilterApplied_ = filter;
        gmlBrowseKindApplied_ = gmlBrowseKind_;
        gmlFilteredRows_.clear();
        auto admit = [&](uint32_t index, std::string_view name) {
            if (filter.empty() || foldName(name).find(filter) != std::string::npos)
                gmlFilteredRows_.push_back(index);
        };
        if (gmlBrowseKind_ == 0)
            for (const auto& row : archive->code) admit(row.index, row.name);
        else if (gmlBrowseKind_ == 1)
            for (const auto& row : archive->variables) admit(row.index, row.name);
        else if (gmlBrowseKind_ == 2)
            for (const auto& row : archive->objects) admit(row.index, row.name);
    }

    const auto tableFlags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg |
        ImGuiTableFlags_Resizable;
    if (gmlBrowseKind_ <= 2 && ImGui::BeginTable("gml_archive", 4, tableFlags, ImVec2(0, 0))) {
        ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 76 * scale);
        ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Kind", ImGuiTableColumnFlags_WidthFixed, 130 * scale);
        ImGui::TableSetupColumn("FILE / references", ImGuiTableColumnFlags_WidthFixed, 160 * scale);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        ImGuiListClipper clip;
        clip.Begin(static_cast<int>(gmlFilteredRows_.size()), ImGui::GetFrameHeightWithSpacing());
        while (clip.Step()) for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
            const uint32_t index = gmlFilteredRows_[i];
            ImGui::PushID(static_cast<int>(index));
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (gmlBrowseKind_ == 0) {
                const auto& code = archive->code[index];
                const bool valid = archive->isInstructionOffset(code.entryFileOffset());
                ImGui::BeginDisabled(!valid);
                if (ImGui::SmallButton(hasGmlBreakpoint(ctx, code.entryFileOffset()) ? "Clear BP" : "Set BP"))
                    toggleGmlBreakpoint(ctx, code.entryFileOffset());
                ImGui::TableSetColumnIndex(1);
                if (ImGui::Selectable(code.name.c_str())) {
                    mainView_ = 0;
                    navigateTo(code.entryFileOffset());
                }
                ImGui::EndDisabled();
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(code.parentIndex == GmlNoIndex ? "Root body" : "Child / shared body");
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("0x%llX%s", static_cast<unsigned long long>(code.entryFileOffset()),
                    code.instructionsComplete ? "" : " (partial)");
            } else if (gmlBrowseKind_ == 1) {
                const auto& variable = archive->variables[index];
                ImGui::BeginDisabled(variable.instanceType != -5);
                if (ImGui::SmallButton("Watch")) {
                    auto& watches = ctx.staticProject().gmlWatches;
                    GmlVariableTarget target;
                    target.archiveHash = ctx.staticBinary().contentHash();
                    target.variableName = variable.name;
                    const bool duplicate = std::any_of(watches.begin(), watches.end(), [&](const auto& row) {
                        return row.target.scope == GmlVariableScope::Global &&
                               row.target.archiveHash == target.archiveHash &&
                               row.target.variableName == target.variableName;
                    });
                    if (!duplicate && watches.size() < kGmlMaxWatches) {
                        watches.push_back({std::move(target), variable.name});
                        ctx.markProjectDirty();
                    }
                }
                ImGui::EndDisabled();
                ImGui::TableSetColumnIndex(1);
                if (ImGui::Selectable(variable.name.c_str())) {
                    const auto ref = std::find_if(archive->references.begin(), archive->references.end(), [&](const auto& row) {
                        return row.kind == GmlReferenceKind::Variable && row.symbolIndex == index;
                    });
                    if (ref != archive->references.end()) { mainView_ = 0; navigateTo(ref->instructionOffset); }
                }
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(GmlScopeName(variable.instanceType));
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%u%s", variable.occurrences, variable.referencesComplete ? " references" : " (partial)");
            } else {
                const auto& object = archive->objects[index];
                ImGui::Text("%u", index);
                ImGui::TableSetColumnIndex(1);
                if (ImGui::Selectable(object.name.c_str())) {
                    gmlSelectedObject_ = static_cast<int>(index);
                    ImGui::OpenPopup("GML object events");
                }
                if (ImGui::BeginPopup("GML object events")) {
                    ImGui::TextUnformatted(object.name.c_str());
                    if (!object.eventsComplete) ImGui::TextDisabled("Event associations are partial.");
                    ImGui::BeginChild("event_list",ImVec2(580*scale,260*scale));
                    ImGuiListClipper eventClip;eventClip.Begin(static_cast<int>(object.events.size()));
                    while(eventClip.Step())for (int eventIndex = eventClip.DisplayStart; eventIndex < eventClip.DisplayEnd; ++eventIndex) {
                        const auto& event = object.events[eventIndex];
                        ImGui::PushID(static_cast<int>(eventIndex));
                        if (event.codeIndex < archive->code.size()) {
                            const auto& code = archive->code[event.codeIndex];
                            const std::string label = std::string(GmlEventName(event.type)) + " / " +
                                std::to_string(event.subtype) + " : " + code.name;
                            if (ImGui::Selectable(label.c_str())) { mainView_ = 0; navigateTo(code.entryFileOffset()); }
                        }
                        ImGui::PopID();
                    }
                    ImGui::EndChild();
                    ImGui::EndPopup();
                }
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("Parent %d", object.parentIndex);
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%zu events%s", object.events.size(), object.eventsComplete ? "" : " (partial)");
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    } else if (gmlBrowseKind_ == 3) {
        auto& rows = ctx.staticProject().gmlBreakpoints;
        if(session.archiveHash==ctx.staticBinary().contentHash())ImGui::TextDisabled("%u requested / %u bound | %s",session.requestedBreakpoints,session.boundBreakpoints,session.status.c_str());
        else ImGui::TextDisabled("Saved symbolic intent; no matching GameMaker connection.");
        ImGui::BeginChild("gml_breakpoints");
        ImGuiListClipper clip; clip.Begin(static_cast<int>(rows.size()));
        int remove = -1;
        while (clip.Step()) for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
            auto& row = rows[i];
            ImGui::PushID(i);
            if (ImGui::Checkbox("##enabled", &row.enabled)) {ctx.markProjectDirty();syncBreakpoints(ctx);}
            ImGui::SameLine();
            const bool mapped = row.location.archiveHash == ctx.staticBinary().contentHash() &&
                row.location.codeIndex < archive->code.size();
            const auto* code = mapped ? &archive->code[row.location.codeIndex] : nullptr;
            std::string label = code ? code->name : "Unresolved code";
            label += " + " + std::to_string(row.location.byteOffset);
            if(!row.enabled)label+=" (disabled)";
            if (ImGui::Selectable(label.c_str(), false, 0, ImVec2(0, 0)) && code) {
                mainView_ = 0; navigateTo(code->bytecodeOffset + row.location.byteOffset);
            }
            if (ImGui::BeginPopupContextItem()) {
                if (ImGui::MenuItem("Remove")) remove = i;
                ImGui::EndPopup();
            }
            ImGui::PopID();
        }
        if (remove >= 0) { rows.erase(rows.begin() + remove); ctx.markProjectDirty();syncBreakpoints(ctx); }
        ImGui::EndChild();
    } else if (gmlBrowseKind_ == 4) {
        auto& saved=ctx.staticProject().gmlWatches;
        // Request one frozen object projection at a time. The host retains
        // previously inspected domains and publishes a new immutable revision.
        if(stop && gmlWatchInspectionOwner_!=stop->identity){gmlWatchInspectionOwner_=stop->identity;gmlWatchInspectedObjects_.clear();gmlWatchInspectionRevision_=0;}
        if(stop && stop->instancesComplete && !ImGui::IsPopupOpen("Edit GML numeric value") && (gmlWatchInspectionRevision_==0 || gmlWatchInspectionRevision_!=session.revision)){
            for(const auto& watch:saved)if(watch.target.scope==GmlVariableScope::UniqueObject && watch.target.archiveHash==session.archiveHash && !gmlWatchInspectedObjects_.count(watch.target.objectIndex) && !scopeComplete(*stop,watch.target)){
                uint32_t matches=0;for(uint32_t i=0;i<stop->instanceCount;++i)if(stop->instances[i].objectIndex==watch.target.objectIndex)++matches;
                gmlWatchInspectedObjects_.insert(watch.target.objectIndex);
                if(matches!=1)continue;
                std::string error;if(!ctx.debug.inspectGameMakerInstance(stop->identity,watch.target.objectIndex,0,error))ui::Toast(ui::ToastKind::Warn,error);else gmlWatchInspectionRevision_=session.revision;break;
            }
        }
        ImGui::TextDisabled("Globals and unique objects are saved. Specific instances and locals retain session/frame ownership.");
        if(!paused)ImGui::TextDisabled("Live values require a matching GML pause.");
        std::vector<GmlVariableCandidate> candidates;
        if(stop){candidates.reserve(stop->numericSlotCount);for(uint32_t i=0;i<stop->numericSlotCount;++i){const auto& slot=stop->numericSlots[i];if(exactSlotName(slot))candidates.push_back({slot.scope,slot.objectIndex,std::string_view(slot.name,slot.nameLength),slot.instanceId,slot.frameId,i});}}
        std::vector<size_t> rows;
        const size_t savedCount=saved.size(),total=savedCount+gmlTransientWatches_.size();
        for(size_t i=0;i<total;++i){const auto& w=i<savedCount?saved[i]:gmlTransientWatches_[i-savedCount];if(filter.empty() || foldName(w.label+" "+w.target.variableName).find(filter)!=std::string::npos)rows.push_back(i);}
        size_t remove=SIZE_MAX;
        if(ImGui::BeginTable("gml_watches",4,tableFlags,ImVec2(0,0))){
            ImGui::TableSetupColumn("Watch");ImGui::TableSetupColumn("Scope");ImGui::TableSetupColumn("Value / status");ImGui::TableSetupColumn("Action",ImGuiTableColumnFlags_WidthFixed,70*scale);ImGui::TableSetupScrollFreeze(0,1);ImGui::TableHeadersRow();
            ImGuiListClipper clip;clip.Begin(static_cast<int>(rows.size()),ImGui::GetFrameHeightWithSpacing());
            while(clip.Step())for(int i=clip.DisplayStart;i<clip.DisplayEnd;++i){
                const size_t index=rows[i];const auto& watch=index<savedCount?saved[index]:gmlTransientWatches_[index-savedCount];
                const bool sameWatchSession=stop && watch.target.owner.pid==stop->identity.pid && watch.target.owner.sessionGeneration==stop->identity.sessionGeneration && watch.target.owner.helperGeneration==stop->identity.helperGeneration;
                const bool inspectable=stop && watch.target.archiveHash==session.archiveHash && (watch.target.scope==GmlVariableScope::UniqueObject || (watch.target.scope==GmlVariableScope::SessionInstance && sameWatchSession));
                GmlVariableResolveResult resolution;
                if(stop)resolution=ResolveGmlVariableTarget(watch.target,session.archiveHash,stop->identity,candidates,scopeComplete(*stop,watch.target));
                if(stop && stop->instancesComplete && watch.target.scope==GmlVariableScope::UniqueObject){
                    uint32_t matches=0;for(uint32_t n=0;n<stop->instanceCount;++n)if(stop->instances[n].objectIndex==watch.target.objectIndex)++matches;
                    if(matches>1)resolution={GmlVariableResolveStatus::Ambiguous};
                }
                const auto* slot=stop && resolution.resolved() && resolution.slotIndex<stop->numericSlotCount?&stop->numericSlots[resolution.slotIndex]:nullptr;
                ImGui::PushID(static_cast<int>(index));ImGui::TableNextRow();ImGui::TableSetColumnIndex(0);
                ImGui::Selectable(watch.label.empty()?watch.target.variableName.c_str():watch.label.c_str());
                if(ImGui::BeginPopupContextItem()){
                    if(ImGui::MenuItem("Remove watch"))remove=index;
                    if(slot && slot->storage==GmlSlotStorage::Canonical && ImGui::MenuItem("Inspect resolved address in Memory Tools (session)"))ctx.openMemoryToolsAt(slot->address,stop->identity.pid,stop->identity.sessionGeneration);
                    if(inspectable && watch.target.scope==GmlVariableScope::UniqueObject && ImGui::BeginMenu("Select instance from registry")){
                        for(uint32_t n=0;n<stop->instanceCount;++n){const auto& instance=stop->instances[n];if(instance.objectIndex!=watch.target.objectIndex)continue;
                            ImGui::PushID(static_cast<int>(n));const std::string label="Instance "+std::to_string(instance.runtimeInstanceNumber)+" / token "+std::to_string(instance.instanceId);
                            if(ImGui::MenuItem(label.c_str())){GmlSavedWatch selected=watch;selected.target.scope=GmlVariableScope::SessionInstance;selected.target.owner=stop->identity;selected.target.instanceId=instance.instanceId;selected.label+=" (selected instance)";if(gmlTransientWatches_.size()<kGmlMaxWatches)gmlTransientWatches_.push_back(std::move(selected));std::string error;if(!ctx.debug.inspectGameMakerInstance(stop->identity,kGmlNoCodeIndex,instance.instanceId,error))ui::Toast(ui::ToastKind::Warn,error);}
                            ImGui::PopID();
                        }
                        ImGui::EndMenu();
                    }
                    ImGui::EndPopup();
                }
                ImGui::TableSetColumnIndex(1);ImGui::Text("%s%s",scopeText(watch.target.scope),index<savedCount?" (saved)":" (transient)");
                ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(slot?numericText(*slot).c_str():paused?resolveText(resolution.status):"not at a GML pause");
                ImGui::TableSetColumnIndex(3);
                if(!slot && inspectable){
                    if(ImGui::SmallButton("Inspect")){std::string error;if(!ctx.debug.inspectGameMakerInstance(stop->identity,watch.target.scope==GmlVariableScope::UniqueObject?watch.target.objectIndex:kGmlNoCodeIndex,watch.target.scope==GmlVariableScope::SessionInstance?watch.target.instanceId:0,error))ui::Toast(ui::ToastKind::Warn,error);}
                }else{ImGui::BeginDisabled(!slot || !editable(*slot));if(ImGui::SmallButton("Edit"))editSlot(static_cast<uint32_t>(resolution.slotIndex));ImGui::EndDisabled();}ImGui::PopID();
            }
            ImGui::EndTable();
        }
        if(remove!=SIZE_MAX){if(remove<savedCount){saved.erase(saved.begin()+remove);ctx.markProjectDirty();}else gmlTransientWatches_.erase(gmlTransientWatches_.begin()+(remove-savedCount));}
    } else if(gmlBrowseKind_==5){
        if(!stop)ImGui::TextDisabled("Frames are available while paused at a verified GML instruction.");
        else{
            if(!stop->framesComplete)ImGui::TextDisabled("Frame ancestry is partial.");
            if(ImGui::BeginTable("gml_frames",4,tableFlags,ImVec2(0,0))){
                ImGui::TableSetupColumn("Frame",ImGuiTableColumnFlags_WidthFixed,90*scale);ImGui::TableSetupColumn("Script / location");ImGui::TableSetupColumn("Scope availability");ImGui::TableSetupColumn("Action",ImGuiTableColumnFlags_WidthFixed,120*scale);ImGui::TableSetupScrollFreeze(0,1);ImGui::TableHeadersRow();
                ImGuiListClipper clip;clip.Begin(static_cast<int>(stop->frameCount),ImGui::GetFrameHeightWithSpacing());
                while(clip.Step())for(int i=clip.DisplayStart;i<clip.DisplayEnd;++i){const auto& frame=stop->frames[i];const auto* code=frame.location.codeIndex<archive->code.size()?&archive->code[frame.location.codeIndex]:nullptr;
                    ImGui::PushID(i);ImGui::TableNextRow();ImGui::TableSetColumnIndex(0);const std::string label="#"+std::to_string(frame.frameId);if(ImGui::Selectable(label.c_str(),gmlSelectedFrameId_==frame.frameId))gmlSelectedFrameId_=frame.frameId;
                    ImGui::TableSetColumnIndex(1);ImGui::Text("%s + %u%s",code?code->name.c_str():"Unresolved code",frame.location.byteOffset,(frame.flags&kGmlFrameLocationIsContinuation)?" (return continuation)":"");
                    ImGui::TableSetColumnIndex(2);ImGui::Text("locals %s | self %s",availabilityText(frame.localsAvailability),availabilityText(frame.selfAvailability));
                    ImGui::TableSetColumnIndex(3);if(ImGui::SmallButton("Values")){gmlSelectedFrameId_=frame.frameId;gmlSelectedInstanceId_=0;gmlBrowseKind_=6;}ImGui::SameLine();
                    const uint64_t offset=code?code->bytecodeOffset+frame.location.byteOffset:0;ImGui::BeginDisabled(!code || !archive->isInstructionOffset(offset));if(ImGui::SmallButton("Code")){mainView_=0;navigateTo(offset);}ImGui::EndDisabled();ImGui::PopID();
                }
                ImGui::EndTable();
            }
        }
    } else if(gmlBrowseKind_==6){
        if(!stop)ImGui::TextDisabled("Variables are available while paused at a verified GML instruction.");
        else{
            const GmlHelperFrame* selected=nullptr;for(uint32_t i=0;i<stop->frameCount;++i)if(stop->frames[i].frameId==gmlSelectedFrameId_)selected=&stop->frames[i];
            if(!selected && stop->frameCount){selected=&stop->frames[0];gmlSelectedFrameId_=selected->frameId;}
            ImGui::TextDisabled("Frame #%llu | globals %s | locals %s | self %s",static_cast<unsigned long long>(gmlSelectedFrameId_),stop->globalsComplete?"complete":"partial",selected?availabilityText(selected->localsAvailability):"unavailable",selected?availabilityText(selected->selfAvailability):"unavailable");
            if(gmlSelectedInstanceId_){ImGui::Text("Selected instance token: %llu",static_cast<unsigned long long>(gmlSelectedInstanceId_));ImGui::SameLine();if(ImGui::SmallButton("Show frame self"))gmlSelectedInstanceId_=0;}
            ImGui::TextDisabled("Copied and computed values are read-only. Right-click a named variable to add a watch.");
            std::vector<uint32_t> rows;
            for(uint32_t i=0;i<stop->numericSlotCount;++i){const auto& slot=stop->numericSlots[i];if(slot.scope==GmlVariableScope::FrameLocal && slot.frameId!=gmlSelectedFrameId_)continue;if(slot.scope==GmlVariableScope::SessionInstance && selected && slot.instanceId!=(gmlSelectedInstanceId_?gmlSelectedInstanceId_:selected->instanceId))continue;const std::string_view name=exactSlotName(slot)?std::string_view(slot.name,slot.nameLength):std::string_view{};if(filter.empty() || foldName(name).find(filter)!=std::string::npos)rows.push_back(i);}
            if(ImGui::BeginTable("gml_live_values",5,tableFlags,ImVec2(0,0))){
                ImGui::TableSetupColumn("Variable");ImGui::TableSetupColumn("Scope");ImGui::TableSetupColumn("Type / storage");ImGui::TableSetupColumn("Value");ImGui::TableSetupColumn("Action",ImGuiTableColumnFlags_WidthFixed,70*scale);ImGui::TableSetupScrollFreeze(0,1);ImGui::TableHeadersRow();
                ImGuiListClipper clip;clip.Begin(static_cast<int>(rows.size()),ImGui::GetFrameHeightWithSpacing());
                while(clip.Step())for(int i=clip.DisplayStart;i<clip.DisplayEnd;++i){const uint32_t index=rows[i];const auto& slot=stop->numericSlots[index];const std::string name=exactSlotName(slot)?std::string(slot.name,slot.nameLength):"runtime #"+std::to_string(slot.runtimeVariableId)+" (name unavailable)";
                    ImGui::PushID(static_cast<int>(index));ImGui::TableNextRow();ImGui::TableSetColumnIndex(0);ImGui::Selectable(name.c_str());
                    if(ImGui::BeginPopupContextItem()){
                        ImGui::BeginDisabled(!exactSlotName(slot));
                        if(slot.scope==GmlVariableScope::Global && ImGui::MenuItem("Save global watch"))addWatch(slot,true);
                        if(slot.scope==GmlVariableScope::SessionInstance){if(ImGui::MenuItem("Watch this instance (session)"))addWatch(slot,false);ImGui::BeginDisabled(slot.objectIndex==kGmlNoCodeIndex);if(ImGui::MenuItem("Save unique-object watch"))addWatch(slot,true);ImGui::EndDisabled();}
                        if(slot.scope==GmlVariableScope::FrameLocal && ImGui::MenuItem("Watch this local (frame)"))addWatch(slot,false);
                        ImGui::EndDisabled();
                        if(slot.storage==GmlSlotStorage::Canonical && ImGui::MenuItem("Inspect address in Memory Tools (session)"))ctx.openMemoryToolsAt(slot.address,stop->identity.pid,stop->identity.sessionGeneration);
                        ImGui::EndPopup();
                    }
                    ImGui::TableSetColumnIndex(1);ImGui::TextUnformatted(scopeText(slot.scope));ImGui::TableSetColumnIndex(2);ImGui::Text("%s / %s",numericType(slot.kind),slot.storage==GmlSlotStorage::Canonical?"storage":slot.storage==GmlSlotStorage::Copied?"copy":"unavailable");
                    ImGui::TableSetColumnIndex(3);ImGui::TextUnformatted(numericText(slot).c_str());ImGui::TableSetColumnIndex(4);ImGui::BeginDisabled(!editable(slot));if(ImGui::SmallButton("Edit"))editSlot(index);ImGui::EndDisabled();ImGui::PopID();
                }
                ImGui::EndTable();
            }
        }
    } else if(gmlBrowseKind_==7){
        if(!stop)ImGui::TextDisabled("The instance registry is available at a verified GML pause.");
        else{
            ImGui::TextDisabled("%u instances | registry %s | instance tokens expire on destruction or detach",stop->instanceCount,stop->instancesComplete?"complete":"partial");
            std::vector<uint32_t> rows;for(uint32_t i=0;i<stop->instanceCount;++i){const auto& instance=stop->instances[i];const auto* object=instance.objectIndex<archive->objects.size()?&archive->objects[instance.objectIndex]:nullptr;if(filter.empty() || (object && foldName(object->name).find(filter)!=std::string::npos))rows.push_back(i);}
            if(ImGui::BeginTable("gml_instances",4,tableFlags,ImVec2(0,0))){
                ImGui::TableSetupColumn("Object");ImGui::TableSetupColumn("Runtime id / session token");ImGui::TableSetupColumn("Variables");ImGui::TableSetupColumn("Action",ImGuiTableColumnFlags_WidthFixed,90*scale);ImGui::TableSetupScrollFreeze(0,1);ImGui::TableHeadersRow();
                ImGuiListClipper clip;clip.Begin(static_cast<int>(rows.size()),ImGui::GetFrameHeightWithSpacing());
                while(clip.Step())for(int i=clip.DisplayStart;i<clip.DisplayEnd;++i){const uint32_t index=rows[i];const auto& instance=stop->instances[index];const auto* object=instance.objectIndex<archive->objects.size()?&archive->objects[instance.objectIndex]:nullptr;
                    ImGui::PushID(static_cast<int>(index));ImGui::TableNextRow();ImGui::TableSetColumnIndex(0);ImGui::TextUnformatted(object?object->name.c_str():"Unknown object");ImGui::TableSetColumnIndex(1);ImGui::Text("%u / %llu",instance.runtimeInstanceNumber,static_cast<unsigned long long>(instance.instanceId));ImGui::TableSetColumnIndex(2);ImGui::TextUnformatted(availabilityText(instance.variablesAvailability));ImGui::TableSetColumnIndex(3);
                    if(ImGui::SmallButton("Inspect")){std::string error;if(ctx.debug.inspectGameMakerInstance(stop->identity,kGmlNoCodeIndex,instance.instanceId,error)){gmlSelectedInstanceId_=instance.instanceId;gmlBrowseKind_=6;}else ui::Toast(ui::ToastKind::Warn,error);}ImGui::PopID();
                }
                ImGui::EndTable();
            }
        }
    }
    if(openEdit)ImGui::OpenPopup("Edit GML numeric value");
    if(ImGui::BeginPopupModal("Edit GML numeric value",nullptr,ImGuiWindowFlags_AlwaysAutoResize)){
        const bool current=stop && GmlPauseIdentityMatches(gmlEditOwner_,stop->identity) && gmlEditRevision_==session.revision && gmlEditSlot_<stop->numericSlotCount;
        const auto* slot=current?&stop->numericSlots[gmlEditSlot_]:nullptr;
        if(slot){ImGui::Text("%s (%s)",exactSlotName(*slot)?slot->name:"Numeric value",numericType(slot->kind));ImGui::TextDisabled("Current value: %s",numericText(*slot).c_str());}
        else ImGui::TextColored(theme::col::warn(),"The captured GML pause has expired.");
        ImGui::SetNextItemWidth(340*scale);ImGui::InputText("Value",gmlEditText_,sizeof(gmlEditText_));
        ImGui::TextDisabled("The debugger revalidates the storage and preserves its numeric type.");
        ImGui::BeginDisabled(!slot || !editable(*slot));
        if(ImGui::Button("Apply")){std::string error;if(ctx.debug.editGameMakerNumeric(gmlEditOwner_,gmlEditRevision_,gmlEditSlot_,gmlEditText_,error))ImGui::CloseCurrentPopup();else ui::Toast(ui::ToastKind::Error,error);}
        ImGui::EndDisabled();ImGui::SameLine();if(ImGui::Button("Cancel"))ImGui::CloseCurrentPopup();ImGui::EndPopup();
    }
    ImGui::EndTabItem();
}
} // namespace ds
