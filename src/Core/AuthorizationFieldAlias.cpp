#include "AuthorizationFieldAlias.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <limits>
#include <map>
#include <queue>
#include <set>
#include <sstream>
#include <tuple>
#include <utility>

namespace ds {

namespace {

constexpr size_t kHardAccessInputs = 131072;
constexpr size_t kHardBindingInputs = 131072;
constexpr size_t kHardRoots = 32768;
constexpr size_t kHardObjects = 32768;
constexpr size_t kHardFields = 65536;
constexpr size_t kHardAliasesPerObject = 8192;
constexpr size_t kHardAccessesPerField = 16384;
constexpr size_t kHardEvidencePerObject = 2048;
constexpr size_t kHardRejectedRows = 16384;

template <typename T>
size_t bounded(T requested, size_t hardLimit) {
    return (std::min)(static_cast<size_t>(requested), hardLimit);
}

void appendReason(std::string& destination, const std::string& reason) {
    if (reason.empty()) return;
    if (!destination.empty()) destination += "; ";
    destination += reason;
}

float finiteConfidence(float value) {
    if (!std::isfinite(value)) return 0.0f;
    return (std::max)(0.0f, (std::min)(1.0f, value));
}

bool cancellationRequested(const AuthorizationFieldAliasInput& input) {
    if (!input.cancelled) return false;
    try {
        return input.cancelled();
    } catch (...) {
        // A cancellation callback is outside the pure boundary.  Treat an
        // exception as a stop request rather than allowing partial identities
        // to escape as complete.
        return true;
    }
}

class CancellationGate {
public:
    explicit CancellationGate(const AuthorizationFieldAliasInput& input)
        : input_(input), interval_((std::max)(
              size_t{1}, bounded(input.limits.cancellationCheckInterval,
                                 size_t{1} << 20))) {}

    bool initial() const { return cancellationRequested(input_); }

    bool checkpoint() {
        ++work_;
        return (work_ % interval_) == 0 && cancellationRequested(input_);
    }

    bool final() const { return cancellationRequested(input_); }

private:
    const AuthorizationFieldAliasInput& input_;
    size_t interval_ = 1;
    size_t work_ = 0;
};

struct RootLess {
    bool operator()(const AuthorizationFieldRoot& left,
                    const AuthorizationFieldRoot& right) const noexcept {
        if (left.functionVAValid != right.functionVAValid)
            return left.functionVAValid;
        if (left.functionVA != right.functionVA)
            return left.functionVA < right.functionVA;
        if (left.formalParameterIndexValid !=
            right.formalParameterIndexValid)
            return left.formalParameterIndexValid;
        return left.formalParameterIndex < right.formalParameterIndex;
    }
};

bool rootValid(const AuthorizationFieldRoot& root) {
    return root.functionVAValid && root.formalParameterIndexValid;
}

AuthorizationFieldRoot rootOf(const ObjectFieldAccessObservation& access) {
    AuthorizationFieldRoot root;
    root.functionVA = access.functionVA;
    root.functionVAValid = access.functionVAValid;
    root.formalParameterIndex = access.rootParameterIndex;
    root.formalParameterIndexValid = access.rootParameterIndexValid;
    return root;
}

std::string rootId(const AuthorizationFieldRoot& root) {
    std::ostringstream text;
    text << "object@0x" << std::hex << std::uppercase << std::setfill('0')
         << std::setw(16) << root.functionVA << std::dec << ":p"
         << root.formalParameterIndex;
    return text.str();
}

uint64_t magnitudeOf(int64_t value) {
    if (value >= 0) return static_cast<uint64_t>(value);
    // Avoid negating INT64_MIN.
    return static_cast<uint64_t>(-(value + 1)) + 1u;
}

std::string fieldId(const std::string& objectId, int64_t displacement,
                    uint16_t widthBits) {
    std::ostringstream text;
    text << objectId << (displacement < 0 ? "-0x" : "+0x")
         << std::hex << std::uppercase << magnitudeOf(displacement)
         << std::dec << ':' << widthBits;
    return text.str();
}

class DisjointSet {
public:
    explicit DisjointSet(size_t count) : parent_(count), rank_(count, 0) {
        for (size_t i = 0; i < count; ++i) parent_[i] = i;
    }

    size_t find(size_t value) {
        size_t root = value;
        while (parent_[root] != root) root = parent_[root];
        while (parent_[value] != value) {
            const size_t next = parent_[value];
            parent_[value] = root;
            value = next;
        }
        return root;
    }

    void unite(size_t left, size_t right) {
        left = find(left);
        right = find(right);
        if (left == right) return;
        if (rank_[left] < rank_[right]) std::swap(left, right);
        parent_[right] = left;
        if (rank_[left] == rank_[right]) ++rank_[left];
    }

private:
    std::vector<size_t> parent_;
    std::vector<uint8_t> rank_;
};

enum class BindingState : uint8_t {
    Pending = 0,
    Accepted,
    Rejected,
};

struct BindingWork {
    BindingState state = BindingState::Pending;
    AuthorizationFieldBindingRejectReason reason =
        AuthorizationFieldBindingRejectReason::InvalidRoot;
    size_t source = 0;
    size_t target = 0;
    bool sourceIndexed = false;
    bool targetIndexed = false;
    bool rootsIndexed = false;
};

struct AccessWork {
    bool accepted = false;
    AuthorizationFieldAccessRejectReason reason =
        AuthorizationFieldAccessRejectReason::InvalidRoot;
    size_t root = 0;
    bool rootIndexed = false;
};

AuthorizationFieldBindingRejectReason validateBinding(
    const AuthorizationFieldRootBindingInput& binding, bool& valid) {
    valid = false;
    if (!rootValid(binding.callerRoot) || !rootValid(binding.calleeFormal))
        return AuthorizationFieldBindingRejectReason::InvalidRoot;
    if (!binding.callVAValid || !binding.directTargetVAValid ||
        !binding.argumentIndexValid)
        return AuthorizationFieldBindingRejectReason::MissingCallsite;
    if (!binding.directCallExact)
        return AuthorizationFieldBindingRejectReason::InexactDirectCall;
    if (!binding.argumentSourceExact)
        return AuthorizationFieldBindingRejectReason::InexactArgumentSource;
    if (!binding.complete)
        return AuthorizationFieldBindingRejectReason::IncompleteFact;
    if (binding.directTargetVA != binding.calleeFormal.functionVA)
        return AuthorizationFieldBindingRejectReason::CalleeTargetMismatch;
    if (binding.argumentIndex != binding.calleeFormal.formalParameterIndex)
        return AuthorizationFieldBindingRejectReason::FormalArgumentMismatch;
    if (!binding.callerRootBiasValid)
        return AuthorizationFieldBindingRejectReason::MissingRootBias;
    if (binding.callerRootBias != 0)
        return AuthorizationFieldBindingRejectReason::AdjustedRoot;
    if (binding.callerRoot.functionVA == binding.calleeFormal.functionVA)
        return AuthorizationFieldBindingRejectReason::CyclicBinding;
    valid = true;
    return AuthorizationFieldBindingRejectReason::InvalidRoot;
}

AuthorizationFieldAccessRejectReason validateAccess(
    const ObjectFieldAccessObservation& access, bool& valid) {
    valid = false;
    if (!rootValid(rootOf(access)))
        return AuthorizationFieldAccessRejectReason::InvalidRoot;
    if (!access.instructionVAValid)
        return AuthorizationFieldAccessRejectReason::MissingInstruction;
    if (!access.operandIndexValid)
        return AuthorizationFieldAccessRejectReason::MissingOperand;
    if (!access.displacementValid)
        return AuthorizationFieldAccessRejectReason::MissingDisplacement;
    if (!access.widthKnown || access.widthBits == 0)
        return AuthorizationFieldAccessRejectReason::MissingWidth;
    if (!access.exact)
        return AuthorizationFieldAccessRejectReason::InexactObservation;
    valid = true;
    return AuthorizationFieldAccessRejectReason::InvalidRoot;
}

void cancelReport(AuthorizationFieldAliasReport& report) {
    report.objects.clear();
    report.fields.clear();
    report.acceptedBindings.clear();
    report.rejectedBindings.clear();
    report.rejectedAccesses.clear();
    report.completeness.complete = false;
    report.completeness.cancelled = true;
    report.completeness.allBindingsResolved = false;
    report.completeness.reason = "authorization field-alias correlation cancelled";
}

std::string bindingRejectionEvidence(
    const AuthorizationFieldRootBindingInput& binding,
    AuthorizationFieldBindingRejectReason reason) {
    std::string result = AuthorizationFieldBindingRejectReasonText(reason);
    if (!binding.evidence.empty()) {
        result += ": ";
        result += binding.evidence;
    }
    return result;
}

std::string accessRejectionEvidence(
    const ObjectFieldAccessObservation& access,
    AuthorizationFieldAccessRejectReason reason) {
    std::string result = AuthorizationFieldAccessRejectReasonText(reason);
    if (!access.evidence.empty()) {
        result += ": ";
        result += access.evidence;
    }
    return result;
}

AuthorizationFieldAliasReport correlateImpl(
    const AuthorizationFieldAliasInput& input) {
    AuthorizationFieldAliasReport report;
    auto& complete = report.completeness;
    complete.inputAccessCount = input.accesses.size();
    complete.inputBindingCount = input.bindings.size();
    complete.accessesScopeComplete = input.accessesComplete;
    complete.bindingsScopeComplete = input.bindingsComplete;

    if (!input.accessesComplete) {
        complete.complete = false;
        appendReason(complete.reason,
                     input.accessesIncompleteReason.empty()
                         ? "field-access input scope was incomplete"
                         : input.accessesIncompleteReason);
    }
    if (!input.bindingsComplete) {
        complete.complete = false;
        appendReason(complete.reason,
                     input.bindingsIncompleteReason.empty()
                         ? "direct-call binding input scope was incomplete"
                         : input.bindingsIncompleteReason);
    }

    const size_t accessCap = bounded(input.limits.maxAccessInputs,
                                     kHardAccessInputs);
    const size_t bindingCap = bounded(input.limits.maxBindingInputs,
                                      kHardBindingInputs);
    const size_t rootCap = bounded(input.limits.maxRoots, kHardRoots);
    const size_t objectCap = bounded(input.limits.maxObjects, kHardObjects);
    const size_t fieldCap = bounded(input.limits.maxFields, kHardFields);
    const size_t aliasCap = bounded(input.limits.maxAliasesPerObject,
                                    kHardAliasesPerObject);
    const size_t accessPerFieldCap = bounded(
        input.limits.maxAccessesPerField, kHardAccessesPerField);
    const size_t evidenceCap = bounded(input.limits.maxEvidencePerObject,
                                       kHardEvidencePerObject);
    const size_t rejectedAccessCap = bounded(
        input.limits.maxRejectedAccesses, kHardRejectedRows);
    const size_t rejectedBindingCap = bounded(
        input.limits.maxRejectedBindings, kHardRejectedRows);

    const size_t accessCount = (std::min)(input.accesses.size(), accessCap);
    const size_t bindingCount = (std::min)(input.bindings.size(), bindingCap);
    if (accessCount != input.accesses.size()) {
        complete.complete = false;
        complete.accessInputsTruncated = true;
        appendReason(complete.reason, "field-access input cap reached");
    }
    if (bindingCount != input.bindings.size()) {
        complete.complete = false;
        complete.bindingInputsTruncated = true;
        complete.allBindingsResolved = false;
        appendReason(complete.reason, "direct-call binding input cap reached");
    }

    CancellationGate cancellation(input);
    if (cancellation.initial()) {
        cancelReport(report);
        return report;
    }

    std::vector<AccessWork> accessWork(accessCount);
    std::vector<BindingWork> bindingWork(bindingCount);
    std::vector<AuthorizationFieldRoot> roots;
    roots.reserve((std::min)(rootCap, accessCount + bindingCount * 2u));

    for (size_t i = 0; i < accessCount; ++i) {
        ++complete.processedAccessCount;
        bool valid = false;
        accessWork[i].reason = validateAccess(input.accesses[i], valid);
        if (valid) roots.push_back(rootOf(input.accesses[i]));
        if (cancellation.checkpoint()) {
            cancelReport(report);
            return report;
        }
    }
    for (size_t i = 0; i < bindingCount; ++i) {
        ++complete.processedBindingCount;
        bool valid = false;
        bindingWork[i].reason = validateBinding(input.bindings[i], valid);
        if (valid) {
            roots.push_back(input.bindings[i].callerRoot);
            roots.push_back(input.bindings[i].calleeFormal);
        } else {
            bindingWork[i].state = BindingState::Rejected;
        }
        if (cancellation.checkpoint()) {
            cancelReport(report);
            return report;
        }
    }

    std::sort(roots.begin(), roots.end(), RootLess{});
    roots.erase(std::unique(roots.begin(), roots.end(),
                            [](const AuthorizationFieldRoot& left,
                               const AuthorizationFieldRoot& right) {
                                return AuthorizationFieldRootEquivalentExact(
                                    left, right);
                            }),
                roots.end());
    if (roots.size() > rootCap) {
        roots.resize(rootCap);
        complete.complete = false;
        complete.rootsTruncated = true;
        complete.allBindingsResolved = false;
        appendReason(complete.reason, "formal-root cap reached");
    }

    std::map<AuthorizationFieldRoot, size_t, RootLess> rootIndex;
    for (size_t i = 0; i < roots.size(); ++i) rootIndex.emplace(roots[i], i);

    auto indexRoot = [&](const AuthorizationFieldRoot& root, size_t& index) {
        const auto found = rootIndex.find(root);
        if (found == rootIndex.end()) return false;
        index = found->second;
        return true;
    };

    for (size_t i = 0; i < accessCount; ++i) {
        bool baseValid = false;
        (void)validateAccess(input.accesses[i], baseValid);
        if (!baseValid) continue;
        if (!indexRoot(rootOf(input.accesses[i]), accessWork[i].root)) {
            accessWork[i].reason =
                AuthorizationFieldAccessRejectReason::RootLimit;
            continue;
        }
        accessWork[i].rootIndexed = true;
        accessWork[i].accepted = true;
    }

    for (size_t i = 0; i < bindingCount; ++i) {
        bindingWork[i].sourceIndexed = indexRoot(
            input.bindings[i].callerRoot, bindingWork[i].source);
        bindingWork[i].targetIndexed = indexRoot(
            input.bindings[i].calleeFormal, bindingWork[i].target);
        bindingWork[i].rootsIndexed = bindingWork[i].sourceIndexed &&
                                      bindingWork[i].targetIndexed;
        if (bindingWork[i].state == BindingState::Rejected) continue;
        if (!bindingWork[i].rootsIndexed) {
            bindingWork[i].state = BindingState::Rejected;
            bindingWork[i].reason =
                AuthorizationFieldBindingRejectReason::RootLimit;
            continue;
        }
    }

    // Build the directed exact-binding graph.  Kosaraju is iterative so hostile
    // call chains cannot exhaust the native stack.  Every intra-SCC binding is
    // rejected before union: recursive/cyclic static formals do not identify a
    // unique concrete object instance.
    std::vector<std::vector<size_t>> forward(roots.size());
    std::vector<std::vector<size_t>> reverse(roots.size());
    for (size_t i = 0; i < bindingCount; ++i) {
        if (bindingWork[i].state != BindingState::Pending ||
            !bindingWork[i].rootsIndexed)
            continue;
        forward[bindingWork[i].source].push_back(bindingWork[i].target);
        reverse[bindingWork[i].target].push_back(bindingWork[i].source);
    }

    std::vector<uint8_t> seen(roots.size(), 0);
    std::vector<size_t> finish;
    finish.reserve(roots.size());
    for (size_t start = 0; start < roots.size(); ++start) {
        if (seen[start]) continue;
        seen[start] = 1;
        std::vector<std::pair<size_t, size_t>> stack;
        stack.emplace_back(start, 0);
        while (!stack.empty()) {
            auto& frame = stack.back();
            if (frame.second < forward[frame.first].size()) {
                const size_t next = forward[frame.first][frame.second++];
                if (!seen[next]) {
                    seen[next] = 1;
                    stack.emplace_back(next, 0);
                }
            } else {
                finish.push_back(frame.first);
                stack.pop_back();
            }
            if (cancellation.checkpoint()) {
                cancelReport(report);
                return report;
            }
        }
    }

    const size_t noComponent = (std::numeric_limits<size_t>::max)();
    std::vector<size_t> component(roots.size(), noComponent);
    std::vector<size_t> componentSizes;
    for (auto cursor = finish.rbegin(); cursor != finish.rend(); ++cursor) {
        if (component[*cursor] != noComponent) continue;
        const size_t componentId = componentSizes.size();
        size_t componentSize = 0;
        std::vector<size_t> stack{*cursor};
        component[*cursor] = componentId;
        while (!stack.empty()) {
            const size_t value = stack.back();
            stack.pop_back();
            ++componentSize;
            for (const size_t next : reverse[value]) {
                if (component[next] == noComponent) {
                    component[next] = componentId;
                    stack.push_back(next);
                }
            }
            if (cancellation.checkpoint()) {
                cancelReport(report);
                return report;
            }
        }
        componentSizes.push_back(componentSize);
    }

    for (size_t i = 0; i < bindingCount; ++i) {
        BindingWork& row = bindingWork[i];
        if (row.state != BindingState::Pending || !row.rootsIndexed) continue;
        if (row.source == row.target ||
            (component[row.source] == component[row.target] &&
             componentSizes[component[row.source]] > 1)) {
            row.state = BindingState::Rejected;
            row.reason = AuthorizationFieldBindingRejectReason::CyclicBinding;
        }
    }

    // Removing all intra-SCC edges leaves a DAG.  Process it in topological
    // order.  A formal with several incoming roots is accepted only if those
    // roots are already equivalent through upstream facts; this admits a
    // proved diamond but refuses unrelated callers sharing one helper formal.
    std::vector<std::vector<size_t>> incoming(roots.size());
    std::vector<std::vector<size_t>> outgoing(roots.size());
    std::vector<size_t> indegree(roots.size(), 0);
    for (size_t i = 0; i < bindingCount; ++i) {
        const BindingWork& row = bindingWork[i];
        if (row.state != BindingState::Pending || !row.rootsIndexed) continue;
        incoming[row.target].push_back(i);
        outgoing[row.source].push_back(i);
        ++indegree[row.target];
    }

    std::priority_queue<size_t, std::vector<size_t>, std::greater<size_t>> ready;
    for (size_t i = 0; i < roots.size(); ++i) {
        if (indegree[i] == 0) ready.push(i);
    }

    DisjointSet aliases(roots.size());
    size_t visited = 0;
    while (!ready.empty()) {
        const size_t target = ready.top();
        ready.pop();
        ++visited;

        std::vector<size_t> pendingIncoming;
        for (const size_t bindingIndex : incoming[target]) {
            if (bindingWork[bindingIndex].state == BindingState::Pending)
                pendingIncoming.push_back(bindingIndex);
        }

        bool parentsAgree = true;
        size_t parentIdentity = noComponent;
        for (const size_t bindingIndex : pendingIncoming) {
            const size_t identity = aliases.find(
                bindingWork[bindingIndex].source);
            if (parentIdentity == noComponent) parentIdentity = identity;
            else if (identity != parentIdentity) parentsAgree = false;
        }

        if (!parentsAgree) {
            bool sameCallConflict = false;
            std::map<uint64_t, size_t> sourceByCall;
            for (const size_t bindingIndex : pendingIncoming) {
                const auto& binding = input.bindings[bindingIndex];
                const size_t identity = aliases.find(
                    bindingWork[bindingIndex].source);
                const auto inserted = sourceByCall.emplace(binding.callVA,
                                                            identity);
                if (!inserted.second && inserted.first->second != identity)
                    sameCallConflict = true;
            }
            for (const size_t bindingIndex : pendingIncoming) {
                bindingWork[bindingIndex].state = BindingState::Rejected;
                bindingWork[bindingIndex].reason = sameCallConflict
                    ? AuthorizationFieldBindingRejectReason::ConflictingBinding
                    : AuthorizationFieldBindingRejectReason::AmbiguousCalleeFormal;
            }
        } else {
            for (const size_t bindingIndex : pendingIncoming) {
                bindingWork[bindingIndex].state = BindingState::Accepted;
                aliases.unite(bindingWork[bindingIndex].source,
                              bindingWork[bindingIndex].target);
            }
        }

        for (const size_t bindingIndex : outgoing[target]) {
            const size_t next = bindingWork[bindingIndex].target;
            if (indegree[next] > 0 && --indegree[next] == 0) ready.push(next);
        }
        if (cancellation.checkpoint()) {
            cancelReport(report);
            return report;
        }
    }

    // All remaining pending rows would imply an unremoved cycle.  Reject them
    // defensively rather than merging under an inconsistent adapter graph.
    if (visited != roots.size()) {
        for (BindingWork& row : bindingWork) {
            if (row.state == BindingState::Pending) {
                row.state = BindingState::Rejected;
                row.reason =
                    AuthorizationFieldBindingRejectReason::CyclicBinding;
            }
        }
    }

    for (size_t i = 0; i < bindingCount; ++i) {
        const auto& row = input.bindings[i];
        if (bindingWork[i].state == BindingState::Accepted) {
            ++complete.acceptedBindingCount;
            AuthorizationAcceptedFieldBinding accepted;
            accepted.inputIndex = i;
            accepted.binding = row;
            accepted.binding.confidence = finiteConfidence(row.confidence);
            accepted.evidence = row.evidence.empty()
                ? "exact direct-call argument root binds caller formal to callee formal"
                : row.evidence;
            report.acceptedBindings.push_back(std::move(accepted));
        } else {
            ++complete.rejectedBindingCount;
            complete.allBindingsResolved = false;
            if (report.rejectedBindings.size() < rejectedBindingCap) {
                AuthorizationRejectedFieldBinding rejected;
                rejected.inputIndex = i;
                rejected.binding = row;
                rejected.binding.confidence = finiteConfidence(row.confidence);
                rejected.reason = bindingWork[i].reason;
                rejected.evidence = bindingRejectionEvidence(
                    row, bindingWork[i].reason);
                report.rejectedBindings.push_back(std::move(rejected));
            } else {
                complete.rejectedBindingsTruncated = true;
            }
        }
    }
    if (complete.rejectedBindingsTruncated) {
        complete.complete = false;
        appendReason(complete.reason, "rejected-binding output cap reached");
    }

    // Build deterministic object components from accepted unions.
    std::map<size_t, std::vector<size_t>> rootsByLeader;
    for (size_t i = 0; i < roots.size(); ++i)
        rootsByLeader[aliases.find(i)].push_back(i);

    std::vector<size_t> acceptedIndegree(roots.size(), 0);
    for (size_t i = 0; i < bindingCount; ++i) {
        if (bindingWork[i].state == BindingState::Accepted)
            ++acceptedIndegree[bindingWork[i].target];
    }

    struct ObjectWork {
        std::vector<size_t> roots;
        size_t canonical = 0;
    };
    std::vector<ObjectWork> objectWork;
    objectWork.reserve(rootsByLeader.size());
    for (auto& pair : rootsByLeader) {
        ObjectWork object;
        object.roots = std::move(pair.second);
        object.canonical = object.roots.front();
        for (const size_t root : object.roots) {
            if (acceptedIndegree[root] == 0) {
                object.canonical = root;
                break; // roots are already in canonical sorted order
            }
        }
        objectWork.push_back(std::move(object));
    }
    std::sort(objectWork.begin(), objectWork.end(),
              [&](const ObjectWork& left, const ObjectWork& right) {
                  return RootLess{}(roots[left.canonical],
                                    roots[right.canonical]);
              });

    const size_t admittedObjects = (std::min)(objectWork.size(), objectCap);
    if (admittedObjects != objectWork.size()) {
        complete.complete = false;
        complete.objectsTruncated = true;
        appendReason(complete.reason, "stable-object output cap reached");
    }
    std::vector<size_t> rootToObject(roots.size(), noComponent);
    report.objects.reserve(admittedObjects);
    for (size_t objectIndex = 0; objectIndex < admittedObjects; ++objectIndex) {
        const ObjectWork& work = objectWork[objectIndex];
        AuthorizationStableObjectIdentity object;
        object.index = objectIndex;
        object.canonicalRoot = roots[work.canonical];
        object.stableId = rootId(object.canonicalRoot);
        object.complete = input.accessesComplete && input.bindingsComplete;
        if (!input.accessesComplete)
            appendReason(object.incompleteReason,
                         input.accessesIncompleteReason.empty()
                             ? "field-access scope incomplete"
                             : input.accessesIncompleteReason);
        if (!input.bindingsComplete)
            appendReason(object.incompleteReason,
                         input.bindingsIncompleteReason.empty()
                             ? "binding scope incomplete"
                             : input.bindingsIncompleteReason);

        std::vector<size_t> orderedRoots;
        orderedRoots.reserve(work.roots.size());
        orderedRoots.push_back(work.canonical);
        for (const size_t root : work.roots) {
            if (root != work.canonical) orderedRoots.push_back(root);
            rootToObject[root] = objectIndex;
        }
        const size_t aliasesToKeep = (std::min)(orderedRoots.size(), aliasCap);
        for (size_t i = 0; i < aliasesToKeep; ++i)
            object.aliases.push_back(roots[orderedRoots[i]]);
        if (aliasesToKeep != orderedRoots.size()) {
            object.complete = false;
            complete.complete = false;
            complete.aliasesTruncated = true;
            appendReason(object.incompleteReason, "object alias output cap reached");
        }
        report.objects.push_back(std::move(object));
    }
    if (complete.aliasesTruncated)
        appendReason(complete.reason, "object alias output cap reached");

    auto addObjectEvidence = [&](size_t objectIndex,
                                 AuthorizationFieldAliasEvidence evidence) {
        if (objectIndex == noComponent || objectIndex >= report.objects.size())
            return;
        auto& object = report.objects[objectIndex];
        if (object.evidence.size() < evidenceCap) {
            object.evidence.push_back(std::move(evidence));
        } else {
            object.complete = false;
            complete.complete = false;
            complete.evidenceTruncated = true;
            appendReason(object.incompleteReason,
                         "object evidence output cap reached");
        }
    };

    for (size_t i = 0; i < bindingCount; ++i) {
        if (!bindingWork[i].sourceIndexed && !bindingWork[i].targetIndexed)
            continue;
        const size_t sourceObject = bindingWork[i].sourceIndexed
            ? rootToObject[bindingWork[i].source] : noComponent;
        const size_t targetObject = bindingWork[i].targetIndexed
            ? rootToObject[bindingWork[i].target] : noComponent;
        if (bindingWork[i].state == BindingState::Accepted) {
            if (sourceObject < report.objects.size()) {
                report.objects[sourceObject].acceptedBindingInputIndices.push_back(i);
                AuthorizationFieldAliasEvidence evidence;
                evidence.kind =
                    AuthorizationFieldAliasEvidenceKind::ExactDirectCallBinding;
                evidence.inputIndex = i;
                evidence.inputIndexValid = true;
                evidence.address = input.bindings[i].callVA;
                evidence.addressValid = input.bindings[i].callVAValid;
                evidence.text = input.bindings[i].evidence.empty()
                    ? "exact direct-call argument-root binding"
                    : input.bindings[i].evidence;
                addObjectEvidence(sourceObject, std::move(evidence));
            }
        } else {
            std::set<size_t> affected;
            if (sourceObject < report.objects.size()) affected.insert(sourceObject);
            if (targetObject < report.objects.size()) affected.insert(targetObject);
            for (const size_t objectIndex : affected) {
                auto& object = report.objects[objectIndex];
                object.complete = false;
                appendReason(object.incompleteReason,
                             AuthorizationFieldBindingRejectReasonText(
                                 bindingWork[i].reason));
                AuthorizationFieldAliasEvidence evidence;
                evidence.kind =
                    AuthorizationFieldAliasEvidenceKind::BindingRejected;
                evidence.inputIndex = i;
                evidence.inputIndexValid = true;
                evidence.address = input.bindings[i].callVA;
                evidence.addressValid = input.bindings[i].callVAValid;
                evidence.text = bindingRejectionEvidence(
                    input.bindings[i], bindingWork[i].reason);
                addObjectEvidence(objectIndex, std::move(evidence));
            }
        }
        if (cancellation.checkpoint()) {
            cancelReport(report);
            return report;
        }
    }

    // Record access validation only after identity construction so every valid
    // admitted observation can be placed in deterministic field-key order.
    struct AcceptedAccess {
        size_t inputIndex = 0;
        size_t root = 0;
        size_t object = 0;
    };
    std::vector<AcceptedAccess> acceptedAccesses;
    acceptedAccesses.reserve(accessCount);
    for (size_t i = 0; i < accessCount; ++i) {
        if (accessWork[i].accepted) {
            ++complete.acceptedAccessCount;
            const size_t object = rootToObject[accessWork[i].root];
            if (object != noComponent && object < report.objects.size())
                acceptedAccesses.push_back({i, accessWork[i].root, object});
        } else {
            ++complete.rejectedAccessCount;
            if (report.rejectedAccesses.size() < rejectedAccessCap) {
                AuthorizationRejectedFieldAccess rejected;
                rejected.inputIndex = i;
                rejected.access = input.accesses[i];
                rejected.access.confidence = finiteConfidence(
                    rejected.access.confidence);
                rejected.reason = accessWork[i].reason;
                rejected.evidence = accessRejectionEvidence(
                    input.accesses[i], accessWork[i].reason);
                report.rejectedAccesses.push_back(std::move(rejected));
            } else {
                complete.rejectedAccessesTruncated = true;
            }
        }
    }
    if (complete.rejectedAccessesTruncated) {
        complete.complete = false;
        appendReason(complete.reason, "rejected-access output cap reached");
    }

    std::sort(acceptedAccesses.begin(), acceptedAccesses.end(),
              [&](const AcceptedAccess& left, const AcceptedAccess& right) {
                  const auto& a = input.accesses[left.inputIndex];
                  const auto& b = input.accesses[right.inputIndex];
                  return std::tie(left.object, a.displacement, a.widthBits,
                                  a.instructionVA, a.operandIndex,
                                  left.inputIndex) <
                         std::tie(right.object, b.displacement, b.widthBits,
                                  b.instructionVA, b.operandIndex,
                                  right.inputIndex);
              });

    using FieldKey = std::tuple<size_t, int64_t, uint16_t>;
    std::map<FieldKey, size_t> fieldByKey;
    std::vector<size_t> observationCounts;
    for (const AcceptedAccess& accepted : acceptedAccesses) {
        const auto& source = input.accesses[accepted.inputIndex];
        const FieldKey key{accepted.object, source.displacement,
                           source.widthBits};
        auto found = fieldByKey.find(key);
        if (found == fieldByKey.end()) {
            if (report.fields.size() >= fieldCap) {
                complete.complete = false;
                complete.fieldsTruncated = true;
                continue;
            }
            AuthorizationStableFieldIdentity field;
            field.objectIndex = accepted.object;
            field.displacement = source.displacement;
            field.widthBits = source.widthBits;
            field.stableId = fieldId(report.objects[accepted.object].stableId,
                                     source.displacement, source.widthBits);
            field.complete = report.objects[accepted.object].complete;
            field.incompleteReason =
                report.objects[accepted.object].incompleteReason;
            const size_t index = report.fields.size();
            report.fields.push_back(std::move(field));
            observationCounts.push_back(0);
            found = fieldByKey.emplace(key, index).first;
        }

        AuthorizationStableFieldIdentity& field = report.fields[found->second];
        if (observationCounts[found->second] >= accessPerFieldCap) {
            field.complete = false;
            complete.complete = false;
            complete.fieldAccessesTruncated = true;
            appendReason(field.incompleteReason,
                         "per-field access output cap reached");
            continue;
        }
        ++observationCounts[found->second];

        AuthorizationStableFieldAccess access;
        access.inputIndex = accepted.inputIndex;
        access.observedRoot = roots[accepted.root];
        access.instructionVA = source.instructionVA;
        access.instructionVAValid = source.instructionVAValid;
        access.operandIndex = source.operandIndex;
        access.operandIndexValid = source.operandIndexValid;
        access.access = source.access;
        access.exact = source.exact;
        access.confidence = finiteConfidence(source.confidence);
        access.evidence = source.evidence;
        if (source.access == ObjectFieldAccessKind::Read ||
            source.access == ObjectFieldAccessKind::ReadWrite)
            field.reads.push_back(access);
        if (source.access == ObjectFieldAccessKind::Write ||
            source.access == ObjectFieldAccessKind::ReadWrite)
            field.writes.push_back(access);

        AuthorizationFieldAliasEvidence evidence;
        evidence.kind = source.access == ObjectFieldAccessKind::Write
            ? AuthorizationFieldAliasEvidenceKind::FieldWrite
            : AuthorizationFieldAliasEvidenceKind::FieldRead;
        evidence.inputIndex = accepted.inputIndex;
        evidence.inputIndexValid = true;
        evidence.address = source.instructionVA;
        evidence.addressValid = source.instructionVAValid;
        evidence.text = source.evidence.empty()
            ? (source.access == ObjectFieldAccessKind::Write
                   ? "exact rooted field write"
                   : source.access == ObjectFieldAccessKind::ReadWrite
                         ? "exact rooted field read/write"
                         : "exact rooted field read")
            : source.evidence;
        if (field.evidence.size() < evidenceCap)
            field.evidence.push_back(std::move(evidence));
        else {
            field.complete = false;
            complete.complete = false;
            complete.evidenceTruncated = true;
            appendReason(field.incompleteReason,
                         "field evidence output cap reached");
        }

        if (cancellation.checkpoint()) {
            cancelReport(report);
            return report;
        }
    }
    if (complete.fieldsTruncated)
        appendReason(complete.reason, "stable-field output cap reached");
    if (complete.fieldAccessesTruncated)
        appendReason(complete.reason, "per-field access output cap reached");
    if (complete.evidenceTruncated)
        appendReason(complete.reason, "identity evidence output cap reached");

    // Width is part of the key.  Explicitly flag same-object/same-offset rows
    // with another width so consumers cannot mistake separate records for one
    // confidently typed field.
    for (size_t first = 0; first < report.fields.size();) {
        size_t end = first + 1;
        while (end < report.fields.size() &&
               report.fields[end].objectIndex ==
                   report.fields[first].objectIndex &&
               report.fields[end].displacement ==
                   report.fields[first].displacement)
            ++end;
        if (end - first > 1) {
            for (size_t i = first; i < end; ++i)
                report.fields[i].overlapsDifferentWidth = true;
        }
        first = end;
    }

    if (cancellation.final()) {
        cancelReport(report);
        return report;
    }
    return report;
}

} // namespace

AuthorizationFieldRootBindingInput AdaptAuthorizationFieldRootBinding(
    const DirectCallFormalBindingObservation& observation) {
    AuthorizationFieldRootBindingInput result;
    result.callerRoot.functionVA = observation.callerFunctionVA;
    result.callerRoot.functionVAValid =
        observation.callerFunctionVAValid;
    result.callerRoot.formalParameterIndex =
        observation.callerRootParameterIndex;
    result.callerRoot.formalParameterIndexValid =
        observation.callerRootParameterIndexValid;
    result.calleeFormal.functionVA = observation.calleeFunctionVA;
    result.calleeFormal.functionVAValid =
        observation.calleeFunctionVAValid;
    result.calleeFormal.formalParameterIndex =
        observation.calleeFormalParameterIndex;
    result.calleeFormal.formalParameterIndexValid =
        observation.calleeFormalParameterIndexValid;
    result.callVA = observation.callVA;
    result.callVAValid = observation.callVAValid;
    result.directTargetVA = observation.calleeFunctionVA;
    result.directTargetVAValid = observation.calleeFunctionVAValid;
    result.argumentIndex = observation.calleeFormalParameterIndex;
    result.argumentIndexValid =
        observation.calleeFormalParameterIndexValid;
    result.callerRootBias = observation.callerRootBias;
    result.callerRootBiasValid = observation.callerRootBiasValid;
    result.directCallExact = observation.directCallTargetExact;
    result.argumentSourceExact = observation.argumentRootExact;
    result.complete = observation.directCallTargetExact &&
                      observation.argumentRootExact &&
                      observation.callerRootBiasValid;
    result.confidence = finiteConfidence(observation.confidence);
    result.evidence = observation.evidence;
    return result;
}

void AppendAuthorizationFieldAliasFacts(
    AuthorizationFieldAliasInput& destination,
    const FuncAnnotations& annotations) {
    destination.accesses.insert(destination.accesses.end(),
                                annotations.fieldAccesses.begin(),
                                annotations.fieldAccesses.end());
    for (const DirectCallFormalBindingObservation& observation :
         annotations.directCallFormalBindings) {
        destination.bindings.push_back(
            AdaptAuthorizationFieldRootBinding(observation));
    }

    auto appendBounded = [](std::string& text, const std::string& reason) {
        if (reason.empty() || text.size() >= 4096) return;
        if (!text.empty()) text += "; ";
        const size_t remaining = 4096 - text.size();
        text.append(reason, 0, (std::min)(remaining, reason.size()));
    };
    if (!annotations.fieldAccessAnalysisAttempted ||
        !annotations.fieldAccessesComplete) {
        destination.accessesComplete = false;
        appendBounded(destination.accessesIncompleteReason,
                      annotations.fieldAccessIncompleteReason.empty()
                          ? "a function's field-access analysis was incomplete"
                          : annotations.fieldAccessIncompleteReason);
    }
    if (!annotations.directCallFormalBindingAnalysisAttempted ||
        !annotations.directCallFormalBindingsComplete) {
        destination.bindingsComplete = false;
        appendBounded(destination.bindingsIncompleteReason,
                      annotations.directCallFormalBindingIncompleteReason.empty()
                          ? "a function's direct-call formal-binding analysis was incomplete"
                          : annotations.directCallFormalBindingIncompleteReason);
    }
}

bool AuthorizationFieldRootEquivalentExact(
    const AuthorizationFieldRoot& left,
    const AuthorizationFieldRoot& right) noexcept {
    return left.functionVAValid && right.functionVAValid &&
           left.formalParameterIndexValid &&
           right.formalParameterIndexValid &&
           left.functionVA == right.functionVA &&
           left.formalParameterIndex == right.formalParameterIndex;
}

const char* AuthorizationFieldBindingRejectReasonText(
    AuthorizationFieldBindingRejectReason reason) noexcept {
    switch (reason) {
        case AuthorizationFieldBindingRejectReason::InvalidRoot:
            return "binding has no exact caller/callee formal root";
        case AuthorizationFieldBindingRejectReason::MissingCallsite:
            return "binding is missing an exact direct callsite/target/argument";
        case AuthorizationFieldBindingRejectReason::InexactDirectCall:
            return "call target was not resolved exactly";
        case AuthorizationFieldBindingRejectReason::InexactArgumentSource:
            return "call argument was not proved to originate from the caller formal root";
        case AuthorizationFieldBindingRejectReason::IncompleteFact:
            return "adapter marked the call-root fact incomplete";
        case AuthorizationFieldBindingRejectReason::CalleeTargetMismatch:
            return "resolved call target conflicts with the callee-formal function";
        case AuthorizationFieldBindingRejectReason::FormalArgumentMismatch:
            return "call argument index conflicts with the callee formal index";
        case AuthorizationFieldBindingRejectReason::MissingRootBias:
            return "call argument root has no proved base adjustment";
        case AuthorizationFieldBindingRejectReason::AdjustedRoot:
            return "interior/adjusted object roots are not merged";
        case AuthorizationFieldBindingRejectReason::RootLimit:
            return "formal root was outside the admitted root cap";
        case AuthorizationFieldBindingRejectReason::CyclicBinding:
            return "cyclic/recursive root binding was rejected";
        case AuthorizationFieldBindingRejectReason::ConflictingBinding:
            return "one callsite supplied conflicting roots for the same callee formal";
        case AuthorizationFieldBindingRejectReason::AmbiguousCalleeFormal:
            return "unrelated callers supplied ambiguous roots for the same callee formal";
    }
    return "field-root binding rejected";
}

const char* AuthorizationFieldAccessRejectReasonText(
    AuthorizationFieldAccessRejectReason reason) noexcept {
    switch (reason) {
        case AuthorizationFieldAccessRejectReason::InvalidRoot:
            return "field access has no exact formal-parameter root";
        case AuthorizationFieldAccessRejectReason::MissingInstruction:
            return "field access has no exact instruction location";
        case AuthorizationFieldAccessRejectReason::MissingOperand:
            return "field access has no exact operand identity";
        case AuthorizationFieldAccessRejectReason::MissingDisplacement:
            return "field access has no exact displacement";
        case AuthorizationFieldAccessRejectReason::MissingWidth:
            return "field access has no exact nonzero width";
        case AuthorizationFieldAccessRejectReason::InexactObservation:
            return "field access was not marked exact";
        case AuthorizationFieldAccessRejectReason::RootLimit:
            return "field access root was outside the admitted root cap";
    }
    return "field access rejected";
}

AuthorizationFieldAliasReport CorrelateAuthorizationFieldAliases(
    const AuthorizationFieldAliasInput& input) {
    try {
        return correlateImpl(input);
    } catch (const std::exception& error) {
        AuthorizationFieldAliasReport report;
        report.completeness.inputAccessCount = input.accesses.size();
        report.completeness.inputBindingCount = input.bindings.size();
        report.completeness.complete = false;
        report.completeness.allBindingsResolved = false;
        report.completeness.reason =
            std::string("authorization field-alias correlation failed: ") +
            error.what();
        return report;
    } catch (...) {
        AuthorizationFieldAliasReport report;
        report.completeness.inputAccessCount = input.accesses.size();
        report.completeness.inputBindingCount = input.bindings.size();
        report.completeness.complete = false;
        report.completeness.allBindingsResolved = false;
        report.completeness.reason =
            "authorization field-alias correlation failed";
        return report;
    }
}

} // namespace ds
