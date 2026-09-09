#include "StringActionTrace.h"
#include "BinaryFile.h"
#include "InstructionReference.h"
#include <deque>
#include <limits>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace ds {
namespace {
void limitation(StringActionTraceResult& result, const std::string& text) {
    result.complete = false;
    if (std::find(result.limitations.begin(), result.limitations.end(), text) == result.limitations.end())
        result.limitations.push_back(text);
}
bool referencesString(const Instruction& in, uint64_t target) {
    if (InstructionIsCall(in) || InstructionEndsBlock(in)) return false;
    if (!in.typedOperands.empty()) {
        for (const auto& operand : in.typedOperands) {
            uint64_t address = 0;
            if ((OperandReads(operand.access) || in.mnemonic == "lea") &&
                TryGetStaticMemoryAddress(in, operand, address) && address == target) return true;
        }
    } else {
        uint64_t address = 0;
        // Compatibility decoders have no reliable memory access metadata.
        if (in.mnemonic == "lea" && TryGetInstrDataRef(in, address) && address == target) return true;
    }
    uint64_t immediate = 0;
    return TryGetInstrImmRef(in, immediate) && immediate == target;
}
bool directCall(const Instruction& in, uint64_t& target) {
    return InstructionIsCall(in) &&
        (in.flow.kind == FlowKind::None || in.flow.kind == FlowKind::DirectCall) &&
        TryGetDirectTarget(in, target);
}
struct Node {
    const Instruction* instruction = nullptr;
    std::vector<size_t> next, previous;
};
struct FunctionNodes {
    const ControlFlowGraph* graph = nullptr;
    std::vector<Node> nodes;
    std::unordered_map<uint64_t, size_t> byVA;
    std::vector<StringActionMutation> mutations;
    std::vector<bool> reachable;
};
} // namespace

StringActionTraceResult TraceStringActions(const std::vector<StringActionTraceFunction>& functions,
    Arch arch, uint64_t stringVA, const std::string& stringText,
    const StringActionTraceLimits& limits) {
    StringActionTraceResult result;
    result.stringVA = stringVA; result.stringText = stringText.substr(0, 2048);
    result.complete = true;
    auto stopped = [&] {
        if (!limits.cancelled || !limits.cancelled()) return false;
        result.cancelled = true; result.complete = false; result.candidates.clear();
        result.status = "String trace cancelled."; return true;
    };
    if (stopped()) return result;
    if (!ArchIsX86_32Or64(arch)) {
        result.complete = false; result.status = "String action tracing currently requires x86/x64 decoded operands.";
        return result;
    }
    if (functions.size() > limits.maxInputFunctions || !limits.maxFunctions ||
        !limits.maxReferences || !limits.maxCandidates || !limits.maxInstructionDistance) {
        result.complete = false; result.status = "String trace input or work budget was exceeded."; return result;
    }
    const size_t count = std::min(functions.size(), limits.maxFunctions);
    if (count != functions.size()) limitation(result, "Function budget reached; additional related functions may exist.");
    std::vector<FunctionNodes> decoded(count);
    std::unordered_map<uint64_t, size_t> entries;
    size_t total = 0;
    for (size_t f = 0; f < count; ++f) {
        if (stopped()) return result;
        auto& data = decoded[f]; data.graph = &functions[f].graph;
        if (!entries.emplace(data.graph->funcStart, f).second) {
            limitation(result, "Duplicate function entries were excluded."); continue;
        }
        if (!data.graph->complete) limitation(result, "One or more decoded functions have incomplete ownership or control flow.");
        std::vector<std::vector<size_t>> blockNodes(data.graph->blocks.size());
        for (size_t b = 0; b < data.graph->blocks.size(); ++b) {
            if (stopped()) return result;
            const auto& block = data.graph->blocks[b];
            for (const auto& in : block.insns) {
                if (data.nodes.size() >= limits.maxInstructionsPerFunction || total >= limits.maxTotalInstructions) {
                    limitation(result, "Instruction budget reached; additional operations may exist."); break;
                }
                if (!in.length || data.byVA.count(in.address)) {
                    limitation(result, "Invalid or overlapping decoded instructions were excluded."); continue;
                }
                const size_t index = data.nodes.size();
                data.byVA.emplace(in.address, index);
                data.nodes.push_back({&in, {}, {}}); blockNodes[b].push_back(index); ++total;
            }
            if (blockNodes[b].size() == block.insns.size()) {
                auto found = FindStringActionMutations(block.insns, arch);
                data.mutations.insert(data.mutations.end(), std::make_move_iterator(found.begin()),
                                      std::make_move_iterator(found.end()));
            }
        }
        auto edge = [&](size_t from, size_t to) {
            data.nodes[from].next.push_back(to); data.nodes[to].previous.push_back(from);
        };
        for (size_t b = 0; b < blockNodes.size(); ++b) {
            const auto& nodes = blockNodes[b];
            for (size_t n = 1; n < nodes.size(); ++n) {
                const auto& previous = *data.nodes[nodes[n - 1]].instruction;
                if (previous.address <= (std::numeric_limits<uint64_t>::max)() - previous.length &&
                    previous.address + previous.length == data.nodes[nodes[n]].instruction->address &&
                    !InstructionEndsBlock(previous)) edge(nodes[n - 1], nodes[n]);
            }
            if (nodes.empty()) continue;
            for (size_t successor : data.graph->blocks[b].succ) {
                if (successor < blockNodes.size() && !blockNodes[successor].empty())
                    edge(nodes.back(), blockNodes[successor].front());
                else limitation(result, "Unresolved control-flow edges remain outside the decoded scope.");
            }
        }
        data.reachable.assign(data.nodes.size(), false);
        const auto entry = data.byVA.find(data.graph->funcStart);
        if (entry == data.byVA.end()) { limitation(result, "A function entry could not be decoded."); continue; }
        std::vector<size_t> queue{entry->second}; data.reachable[entry->second] = true;
        for (size_t q = 0; q < queue.size(); ++q) {
            if ((q & 63u) == 0 && stopped()) return result;
            for (size_t next : data.nodes[queue[q]].next)
                if (!data.reachable[next]) { data.reachable[next] = true; queue.push_back(next); }
        }
    }

    struct CallEdge { size_t caller, callee, source; };
    std::vector<std::vector<CallEdge>> incoming(count), outgoing(count);
    for (size_t f = 0; f < count; ++f) for (size_t n = 0; n < decoded[f].nodes.size(); ++n) {
        if ((n & 63u) == 0 && stopped()) return result;
        if (!decoded[f].reachable[n]) continue;
        uint64_t target = 0;
        if (!directCall(*decoded[f].nodes[n].instruction, target)) continue;
        const auto callee = entries.find(target);
        if (callee != entries.end() && callee->second != f) {
            CallEdge edge{f, callee->second, n};
            outgoing[f].push_back(edge); incoming[edge.callee].push_back(edge);
        }
    }
    struct State {
        size_t function, anchor, depth;
        uint64_t reference;
        std::vector<StringActionTraceStep> path;
        std::vector<size_t> ancestors;
    };
    std::deque<State> queue;
    size_t references = 0;
    for (size_t f = 0; f < count; ++f) for (size_t n = 0; n < decoded[f].nodes.size(); ++n) {
        if ((n & 63u) == 0 && stopped()) return result;
        const auto& data = decoded[f]; const auto& in = *data.nodes[n].instruction;
        if (!data.reachable[n] || !referencesString(in, stringVA)) continue;
        if (references >= limits.maxReferences) {
            limitation(result, "String-reference budget reached; additional references may exist."); continue;
        }
        ++references;
        queue.push_back({f, n, 0, in.address,
            {{stringVA, data.graph->funcStart, "Selected string"},
             {in.address, data.graph->funcStart, "Decoded reference to the selected string"}}, {f}});
    }
    result.valid = references != 0;
    if (!result.valid) {
        result.complete = false;
        result.status = "No decoder-verified, entry-reachable reference to this string was found in the bounded function scope.";
        return result;
    }
    size_t work = 0, states = 0;
    constexpr size_t kMaxNodeWork = 262144, kMaxStates = 256;
    std::set<std::tuple<size_t, size_t, uint64_t>> visited;
    std::map<std::pair<uint64_t, uint64_t>, StringActionTraceCandidate> ranked;
    while (!queue.empty() && work < kMaxNodeWork && states < kMaxStates) {
        if (stopped()) return result;
        State state = std::move(queue.front()); queue.pop_front();
        if (!visited.emplace(state.function, state.anchor, state.reference).second) continue;
        ++states;
        const auto& data = decoded[state.function];
        auto distances = [&](bool backward) {
            std::vector<int> distance(data.nodes.size(), -1);
            std::vector<size_t> frontier{state.anchor}; distance[state.anchor] = 0;
            for (size_t q = 0; q < frontier.size() && work < kMaxNodeWork; ++q) {
                if ((q & 63u) == 0 && stopped()) break;
                const size_t node = frontier[q]; ++work;
                const auto& edges = backward ? data.nodes[node].previous : data.nodes[node].next;
                for (size_t next : edges) {
                    if (!data.reachable[next] || distance[next] >= 0) continue;
                    if (static_cast<size_t>(distance[node]) >= limits.maxInstructionDistance) {
                        limitation(result, "Instruction-distance boundary reached; more distant operations were not inspected.");
                        continue;
                    }
                    distance[next] = distance[node] + 1; frontier.push_back(next);
                }
            }
            return distance;
        };
        auto before = distances(true), after = distances(false);
        if (result.cancelled) return result;
        auto distanceTo = [&](size_t node) {
            if (before[node] < 0) return after[node];
            return after[node] < 0 ? before[node] : std::min(before[node], after[node]);
        };
        for (const auto& mutation : data.mutations) {
            const auto location = data.byVA.find(mutation.instructionVA);
            if (location == data.byVA.end()) continue;
            const int distance = distanceTo(location->second);
            if (distance < 0) continue; // Includes mutually exclusive branches.
            StringActionTraceCandidate candidate;
            candidate.instructionVA = mutation.instructionVA;
            candidate.functionVA = data.graph->funcStart;
            candidate.stringRefVA = state.reference;
            candidate.producerVA = mutation.producerVA;
            candidate.producerVAValid = mutation.producerVAValid;
            candidate.instruction = mutation.instruction;
            candidate.action = StringActionKindName(mutation.kind);
            candidate.suggestedName = StringActionSuggestedName(stringText, mutation.kind);
            const bool precedes = before[location->second] >= 0;
            candidate.confidence = (mutation.kind == StringActionKind::Write ? 0.36f : 0.78f) -
                static_cast<float>(state.depth) * 0.12f - std::min(0.20f, distance * 0.003f) -
                (precedes ? 0.0f : 0.07f) + (candidate.suggestedName.empty() ? 0.0f : 0.04f);
            candidate.confidence = std::clamp(candidate.confidence, 0.05f, 0.85f);
            candidate.evidence = mutation.evidence + " A decoded control-flow path places this operation " +
                (precedes ? "before" : "after") + " the route anchor (" + std::to_string(distance) +
                " instruction edges, " + std::to_string(state.depth) + " direct-call hops). " +
                "String proximity and call reachability do not prove field meaning or runtime execution.";
            candidate.path = state.path;
            if (mutation.producerVAValid)
                candidate.path.push_back({mutation.producerVA, candidate.functionVA, "Arithmetic producer of the stored register value"});
            candidate.path.push_back({candidate.instructionVA, candidate.functionVA,
                candidate.action + (precedes ? " (before route anchor)" : " (after route anchor)")});
            const auto key = std::make_pair(candidate.functionVA, candidate.instructionVA);
            auto found = ranked.find(key);
            if (found == ranked.end()) {
                if (ranked.size() < limits.maxCandidates) ranked.emplace(key, std::move(candidate));
                else {
                    limitation(result, "Candidate budget reached; only the highest-ranked retained operations are shown.");
                    auto weakest = std::min_element(ranked.begin(), ranked.end(), [](const auto& a, const auto& b) {
                        return a.second.confidence < b.second.confidence;
                    });
                    if (weakest != ranked.end() && candidate.confidence > weakest->second.confidence) {
                        ranked.erase(weakest); ranked.emplace(key, std::move(candidate));
                    }
                }
            } else if (candidate.confidence > found->second.confidence) found->second = std::move(candidate);
        }
        if (state.depth >= std::min<size_t>(limits.maxDepth, 4)) continue;
        const auto enqueue = [&](size_t function, size_t anchor, std::vector<StringActionTraceStep> path) {
            if (std::find(state.ancestors.begin(), state.ancestors.end(), function) != state.ancestors.end()) return;
            if (queue.size() >= kMaxStates) { limitation(result, "Call-route budget reached; additional routes may exist."); return; }
            auto ancestors = state.ancestors; ancestors.push_back(function);
            queue.push_back({function, anchor, state.depth + 1, state.reference, std::move(path), std::move(ancestors)});
        };
        for (const auto& call : outgoing[state.function]) {
            if (distanceTo(call.source) < 0) continue;
            const auto entry = decoded[call.callee].byVA.find(decoded[call.callee].graph->funcStart);
            if (entry == decoded[call.callee].byVA.end()) continue;
            auto path = state.path;
            path.push_back({data.nodes[call.source].instruction->address, data.graph->funcStart,
                "Reachable direct call from the string's function neighborhood"});
            path.push_back({decoded[call.callee].graph->funcStart, decoded[call.callee].graph->funcStart, "Decoded callee entry"});
            enqueue(call.callee, entry->second, std::move(path));
        }
        for (const auto& call : incoming[state.function]) {
            auto path = state.path;
            const auto& caller = decoded[call.caller];
            path.push_back({caller.nodes[call.source].instruction->address, caller.graph->funcStart,
                "Decoded caller of this function (candidate call context)"});
            enqueue(call.caller, call.source, std::move(path));
        }
    }
    if (!queue.empty() || work >= kMaxNodeWork || states >= kMaxStates)
        limitation(result, "Traversal work budget reached; additional call routes may exist.");
    for (auto& item : ranked) result.candidates.push_back(std::move(item.second));
    std::sort(result.candidates.begin(), result.candidates.end(), [](const auto& a, const auto& b) {
        if (a.confidence != b.confidence) return a.confidence > b.confidence;
        return std::tie(a.functionVA, a.instructionVA) < std::tie(b.functionVA, b.instructionVA);
    });
    result.status = result.candidates.empty()
        ? "No supported value-write candidate was found within the decoded call and instruction-distance scope."
        : std::to_string(result.candidates.size()) + " candidate value changes linked to the string by decoded references and bounded call/control-flow paths.";
    if (!result.complete) result.status += " Partial scope; review the limits.";
    return result;
}

StringActionTraceResult BuildStringActionTrace(const BinaryFile& bin, IDisassembler& decoder,
    Arch arch, const StringActionTraceRequest& request,
    const std::function<bool()>& cancelled) {
    StringActionTraceLimits limits;
    limits.cancelled = [&] { return (cancelled && cancelled()) ||
        (request.cancellation && request.cancellation->load(std::memory_order_acquire)); };
    StringActionTraceResult rejected;
    rejected.stringVA = request.stringVA; rejected.stringText = request.stringText.substr(0, 2048);
    const auto stopped = [&] {
        if (!limits.cancelled()) return false;
        rejected.cancelled = true; rejected.status = "String trace cancelled."; return true;
    };
    if (stopped()) return rejected;
    if (!ArchIsX86_32Or64(arch) || !request.xrefs ||
        request.functions.size() > limits.maxInputFunctions) {
        rejected.status = "String action tracing requires x86/x64, a published reference index, and bounded function ownership.";
        return rejected;
    }
    const auto* sources = request.xrefs->sources(request.stringVA);
    if (!sources || sources->empty()) {
        rejected.status = "No indexed references to this string; the current index may not cover runtime-generated or indirect references.";
        return rejected;
    }
    struct Extent { uint64_t begin, last, prefixLast; size_t function; };
    std::vector<Extent> extents;
    std::unordered_map<uint64_t, size_t> entries;
    std::unordered_set<uint64_t> noreturnTargets;
    bool ownershipLimited = false;
    constexpr size_t kMaxExtents = 262144;
    for (size_t f = 0; f < request.functions.size(); ++f) {
        if ((f & 63u) == 0 && stopped()) return rejected;
        const auto& function = request.functions[f];
        entries.emplace(function.address, f);
        if (function.noreturn) noreturnTargets.insert(function.address);
        const auto add = [&](uint64_t begin, uint32_t size) {
            if (!size) return;
            if (extents.size() >= kMaxExtents) { ownershipLimited = true; return; }
            const uint64_t last = begin + std::min<uint64_t>(size - 1, (std::numeric_limits<uint64_t>::max)() - begin);
            extents.push_back({begin, last, 0, f});
        };
        if (function.chunks.empty()) add(function.address, function.size);
        else {
            const size_t count = std::min<size_t>(function.chunks.size(), 256);
            ownershipLimited |= count != function.chunks.size();
            for (size_t c = 0; c < count; ++c) add(function.chunks[c].address, function.chunks[c].size);
        }
    }
    std::sort(extents.begin(), extents.end(), [](const auto& a, const auto& b) {
        return std::tie(a.begin, a.function) < std::tie(b.begin, b.function);
    });
    uint64_t prefix = 0;
    for (auto& extent : extents) { prefix = std::max(prefix, extent.last); extent.prefixLast = prefix; }
    size_t ownerWork = 0;
    const auto owner = [&](uint64_t va, size_t& function) {
        auto end = std::upper_bound(extents.begin(), extents.end(), va,
            [](uint64_t address, const Extent& extent) { return address < extent.begin; });
        bool found = false;
        while (end != extents.begin()) {
            --end;
            if (++ownerWork > 1048576) { ownershipLimited = true; return false; }
            if (end->prefixLast < va) break;
            if (end->last < va) continue;
            if (found && function != end->function) { ownershipLimited = true; return false; }
            function = end->function; found = true;
        }
        return found;
    };
    struct Pending { size_t function, depth; };
    std::deque<Pending> pending;
    std::unordered_set<size_t> seen;
    const auto enqueue = [&](size_t function, size_t depth) {
        if (seen.count(function)) return;
        if (seen.size() >= limits.maxFunctions) { ownershipLimited = true; return; }
        seen.insert(function); pending.push_back({function, depth});
    };
    for (size_t s = 0; s < std::min(sources->size(), limits.maxReferences); ++s) {
        size_t function = 0;
        if (owner((*sources)[s], function)) enqueue(function, 0);
        else ownershipLimited = true;
    }
    struct CheckedDecoder final : IDisassembler {
        IDisassembler& decoder; const std::function<bool()>& stopped;
        CheckedDecoder(IDisassembler& d, const std::function<bool()>& s) : decoder(d), stopped(s) {}
        Engine engine() const override { return decoder.engine(); }
        const char* engineName() const override { return decoder.engineName(); }
        bool decodeOne(const uint8_t* p, size_t n, uint64_t va, Instruction& in) override {
            return !stopped() && decoder.decodeOne(p, n, va, in);
        }
        std::vector<Instruction> disassemble(const uint8_t* p, size_t n, uint64_t va, size_t cap) override {
            std::vector<Instruction> out;
            for (size_t offset = 0; offset < n && (!cap || out.size() < cap);) {
                Instruction in;
                if (!decodeOne(p + offset, n - offset, va + offset, in) || !in.length || in.length > n - offset) break;
                offset += in.length; out.push_back(std::move(in));
            }
            return out;
        }
    } checked(decoder, limits.cancelled);
    std::vector<StringActionTraceFunction> functions;
    size_t total = 0;
    while (!pending.empty() && total < limits.maxTotalInstructions) {
        if (stopped()) return rejected;
        const auto next = pending.front(); pending.pop_front();
        const auto& function = request.functions[next.function];
        std::vector<CFGCodeChunk> chunks;
        bool incomplete = function.ownershipTruncated;
        const auto add = [&](uint64_t va, uint32_t size) {
            size_t available = 0;
            const uint8_t* bytes = bin.ptrFromVA(va, available);
            if (!bytes || !size) { incomplete = true; return; }
            const size_t bounded = std::min<size_t>(size, available);
            incomplete |= bounded != size;
            chunks.push_back({bytes, bounded, va});
        };
        if (function.chunks.empty()) add(function.address, function.size);
        else for (size_t c = 0; c < std::min<size_t>(256, function.chunks.size()); ++c)
            add(function.chunks[c].address, function.chunks[c].size);
        auto graph = BuildCFG(chunks, checked,
            std::min(limits.maxInstructionsPerFunction, limits.maxTotalInstructions - total), {},
            [&noreturnTargets](uint64_t target) { return noreturnTargets.count(target) != 0; },
            [&bin](const Instruction& in, uint64_t& target) { return bin.resolveInstructionTarget(in, target); });
        if (stopped()) return rejected;
        graph.funcStart = function.address;
        if (incomplete) { graph.complete = false; graph.incompleteReason += " incomplete ownership/backing"; }
        size_t instructions = 0;
        for (const auto& block : graph.blocks) instructions += block.insns.size();
        total += instructions;
        if (next.depth < limits.maxDepth) {
            for (const auto& block : graph.blocks) for (const auto& in : block.insns) {
                uint64_t target = 0;
                if (directCall(in, target)) {
                    const auto found = entries.find(target);
                    if (found != entries.end()) enqueue(found->second, next.depth + 1);
                }
            }
            if (const auto* callers = request.xrefs->sources(function.address)) {
                ownershipLimited |= callers->size() > limits.maxReferences;
                for (size_t c = 0; c < std::min(callers->size(), limits.maxReferences); ++c) {
                    size_t caller = 0;
                    if (owner((*callers)[c], caller)) enqueue(caller, next.depth + 1);
                }
            }
        }
        functions.push_back({std::move(graph)});
    }
    if (stopped()) return rejected;
    auto result = TraceStringActions(functions, arch, request.stringVA, request.stringText, limits);
    if (result.cancelled) return result;
    if (ownershipLimited || !pending.empty())
        limitation(result, "Function/reference ownership, ambiguity or decode budget left additional scope uninspected.");
    if (sources->size() > limits.maxReferences)
        limitation(result, "String-reference index exceeded the selected-reference budget.");
    if (!request.xrefs->complete || request.xrefs->classificationTruncated)
        limitation(result, "The source reference index is incomplete; missing references remain unknown.");
    if (!result.complete && result.status.find("Partial scope") == std::string::npos)
        result.status += " Partial scope; review the limits.";
    return result;
}
} // namespace ds
