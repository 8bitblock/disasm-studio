#include "FunctionNamer.h"
#include "BinaryFile.h"
#include "../Disasm/IDisassembler.h"
#include "../Tabs/DataRef.h"   // instrDataRef/instrImmRef: referenced data addresses

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <unordered_map>
#include <unordered_set>

namespace ds {
namespace {

// Lowercase + strip leading underscores so "__imp_CreateFileW", "_malloc" and
// "CreateFileW" all compare uniformly.
std::string norm(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (char c : s) o.push_back((char)std::tolower((unsigned char)c));
    size_t i = 0; while (i < o.size() && o[i] == '_') ++i;
    return o.substr(i);
}

// Runtime/compiler-emitted helpers that never tell us what a function *does*.
bool isNoiseApi(const std::string& n) {
    static const char* kNoise[] = {
        "security_check_cookie", "security_cookie", "stack_chk_fail", "chkstk",
        "gshandlercheck", "cxxframehandler", "except_handler", "rtc_",
        "guard_check_icall", "guard_dispatch_icall", "guard_",
    };
    std::string low = norm(n);
    for (const char* t : kNoise) if (low.find(t) != std::string::npos) return true;
    return false;
}

// Bare API name from a possibly-qualified "dll.func" (and reject ordinals).
std::string bareApi(const std::string& full) {
    if (full.empty()) return "";
    size_t dot = full.rfind('.');
    std::string n = (dot == std::string::npos) ? full : full.substr(dot + 1);
    // BinaryFile spells ordinal-only PE imports as "#123".  Older producers may
    // use "ordinal_123"; neither carries semantic naming evidence.
    if (n.empty() || n[0] == '#' || norm(n).rfind("ordinal", 0) == 0) return "";
    return n;
}

bool isIdentifier(const std::string& s) {
    if (s.empty() || !(std::isalpha((unsigned char)s[0]) || s[0] == '_')) return false;
    for (char c : s)
        if (!(std::isalnum((unsigned char)c) || c == '_')) return false;
    return true;
}

// FunctionAnalyzer's anonymous names have one exact shape.  Merely starting
// with "sub_" is not enough: a real export such as sub_handler must survive.
bool isAnonymousSubName(const std::string& s) {
    if (s.size() <= 4 || s.rfind("sub_", 0) != 0) return false;
    for (size_t i = 4; i < s.size(); ++i)
        if (!std::isxdigit((unsigned char)s[i])) return false;
    return true;
}

// Case-insensitive allocation avoids visually ambiguous guesses beside PE/PDB
// names ("Read_File" and "read_file") while preserving the chosen spelling.
std::string nameKey(const std::string& s) {
    std::string k; k.reserve(s.size());
    for (char c : s) k.push_back((char)std::tolower((unsigned char)c));
    return k;
}

// Strip import-pointer and stdcall decoration without changing the API's useful
// display case.  Used for j_<API> thunk names.
std::string thunkIdentifier(const std::string& full) {
    std::string n = bareApi(full);
    if (n.empty() || n[0] == '?') return {};             // MSVC-mangled tail: no safe short name
    size_t lead = 0; while (lead < n.size() && n[lead] == '_') ++lead;
    n.erase(0, lead);
    std::string low = nameKey(n);
    if (low.rfind("imp_", 0) == 0) n.erase(0, 4);       // __imp_CreateFileW
    if (size_t at = n.find('@'); at != std::string::npos) n.resize(at); // _foo@8

    std::string out;
    for (char c : n) {
        if (std::isalnum((unsigned char)c) || c == '_') out.push_back(c);
        else if (!out.empty() && out.back() != '_')     out.push_back('_');
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    if (out.empty()) return {};
    if (std::isdigit((unsigned char)out[0])) out = "fn_" + out;
    return isIdentifier(out) ? out : std::string();
}

std::string joinApis(const std::vector<std::string>& v) {
    std::string r; int n = 0;
    for (const auto& a : v) {
        if (n >= 4) { r += ", ..."; break; }
        if (n++) r += ", ";
        r += a;
    }
    return r;
}

// The semantic-classification table: map a function's set of called APIs to a
// meaningful verb. Ordered most-specific / most-telling first so a function that
// e.g. reads a file *and* memcpys gets "read_file" rather than "copy_memory".
// Returns "" when nothing recognizable is called.
std::string semanticName(const std::vector<std::string>& apis) {
    std::vector<std::string> N;
    for (const auto& a : apis) N.push_back(norm(a));
    auto has = [&](const char* t) {
        for (const auto& n : N) if (n.find(t) != std::string::npos) return true;
        return false;
    };
    // Exact match (insensitive to a trailing ANSI/Wide A/W) so "send" can't match
    // "SendMessage" or "connect" match "InternetConnect".
    auto eq = [&](const char* t) {
        const std::string s = t;
        for (const auto& n : N) {
            std::string m = n;
            if (m.size() >= 2 && (m.back() == 'a' || m.back() == 'w')) m.pop_back();
            if (n == s || m == s) return true;
        }
        return false;
    };

    // --- code injection / process manipulation (high RE signal) ---
    if (has("writeprocessmemory") && (has("virtualallocex") || has("createremotethread") ||
                                      has("ntcreatethreadex") || has("queueuserapc")))
        return "inject_code";
    if (has("createremotethread") || has("ntcreatethreadex") || has("rtlcreateuserthread"))
        return "inject_thread";
    if (has("writeprocessmemory"))      return "write_process_memory";
    if (has("readprocessmemory"))       return "read_process_memory";
    if (has("virtualallocex"))          return "alloc_remote_memory";
    if (has("virtualprotect") && has("virtualalloc")) return "alloc_exec_memory";
    if (has("virtualalloc"))            return "allocate_memory";
    if (has("virtualprotect"))          return "change_protection";

    // --- anti-analysis / privilege / enumeration ---
    if (has("isdebuggerpresent") || has("checkremotedebugger")) return "check_debugger";
    if (has("createtoolhelp32snapshot") || has("process32"))    return "enumerate_processes";
    if (has("module32"))                                        return "enumerate_modules";
    if (has("adjusttokenprivileges") || has("lookupprivilege") || has("openprocesstoken"))
        return "adjust_privileges";

    // --- cryptography ---
    if (has("cryptencrypt") || has("bcryptencrypt"))            return "encrypt_data";
    if (has("cryptdecrypt") || has("bcryptdecrypt"))            return "decrypt_data";
    if (has("crypthashdata") || has("cryptcreatehash") || has("bcrypthash")) return "hash_data";
    if (has("cryptgenkey") || has("cryptacquirecontext") || has("cryptimportkey") ||
        has("bcryptopenalgorithm"))                            return "crypto_init";

    // --- network ---
    if (has("urldownloadtofile"))                              return "download_file";
    if (has("internetreadfile") || has("winhttpreaddata"))    return "http_read";
    if (has("httpsendrequest") || has("winhttpsendrequest"))  return "http_request";
    if (has("internetopen") || has("winhttpopen") || has("internetconnect")) return "http_connect";
    {
        bool snd = eq("send") || eq("sendto") || has("wsasend");
        bool rcv = eq("recv") || eq("recvfrom") || has("wsarecv");
        if (snd && rcv) return "net_transfer";
        if (snd)        return "net_send";
        if (rcv)        return "net_recv";
        if (eq("connect"))                                    return "net_connect";
        if (eq("socket") || has("wsastartup") || eq("bind") || eq("listen") || eq("accept"))
            return "socket_setup";
    }

    // --- registry ---
    if (has("regsetvalue") || has("regcreatekey"))            return "write_registry";
    if (has("regdeletekey") || has("regdeletevalue"))         return "delete_registry";
    if (has("regopenkey") || has("regqueryvalue") || has("reggetvalue") ||
        has("regenumkey") || has("regenumvalue"))            return "read_registry";

    // --- process launch ---
    if (has("createprocess") || has("shellexecute") || has("winexec") || eq("system"))
        return "launch_process";

    // --- service control ---
    if (has("createservice") || has("openscmanager") || has("startservice") || has("controlservice"))
        return "manage_service";

    // --- filesystem ---
    if (has("writefile") || eq("fwrite"))                     return "write_file";
    if (has("readfile") || eq("fread"))                       return "read_file";
    if (has("deletefile") || eq("unlink") || eq("remove"))    return "delete_file";
    if (has("copyfile"))                                      return "copy_file";
    if (has("movefile") || eq("rename"))                      return "move_file";
    if (has("findfirstfile") || has("findnextfile"))          return "enumerate_files";
    if (has("createfile") || eq("fopen") || has("createfilemapping")) return "open_file";

    // --- synchronization / library / ui / lifecycle ---
    if (has("createmutex") || has("openmutex"))               return "create_mutex";
    if (has("createevent"))                                   return "create_event";
    if (has("loadlibrary") && has("getprocaddress"))          return "resolve_imports";
    if (has("loadlibrary"))                                   return "load_library";
    if (has("getprocaddress"))                                return "resolve_proc";
    if (has("messagebox"))                                    return "show_message";
    if (has("exitprocess") || has("terminateprocess") || eq("exit") || eq("abort") || eq("_exit"))
        return "exit_process";
    if (has("outputdebugstring"))                             return "debug_print";
    if (has("getenvironmentvariable") || eq("getenv"))        return "read_env";
    if (has("setenvironmentvariable"))                        return "set_env";

    // --- weaker, generic helpers (only reached if nothing above matched) ---
    if (has("sprintf") || has("wsprintf") || has("printf") || has("vsnprintf")) return "format_string";
    if (has("strcpy") || has("wcscpy") || has("lstrcpy") || eq("strncpy"))      return "copy_string";
    if (has("strcat") || has("lstrcat"))                                        return "concat_string";
    if (has("strlen") || has("lstrlen") || eq("wcslen"))                        return "string_length";
    if (has("strcmp") || has("wcscmp") || has("memcmp") || has("strncmp"))      return "compare_buffer";
    if (has("memcpy") || has("memmove"))                                        return "copy_memory";
    if (has("memset") || has("zeromemory"))                                     return "fill_memory";
    if (has("malloc") || has("calloc") || has("heapalloc") || has("localalloc") ||
        has("globalalloc") || has("realloc"))                                   return "allocate_buffer";
    // Exact `free`: substring matching misclassified FreeLibrary/VirtualFree as
    // CRT buffer releases (their thin-wrapper names are more truthful).
    if (eq("free") || has("heapfree") || has("localfree") || has("globalfree")) return "free_buffer";
    return "";
}

// Pick the most "name-like" referenced string: a bare C identifier (often a
// __FUNCTION__ / class / symbol name embedded for logging or asserts). Prefers
// shorter, mixed-case / underscored tokens; rejects plain dictionary noise.
std::string identifierString(const std::vector<std::string>& strings) {
    std::string best; int bestScore = -1;
    for (const std::string& s : strings) {
        if (s.size() < 4 || s.size() > 40) continue;
        if (!(std::isalpha((unsigned char)s[0]) || s[0] == '_')) continue;
        bool ok = true, hasUpper = false, hasLower = false, hasUnder = false, hasDigit = false;
        for (char c : s) {
            if (!(std::isalnum((unsigned char)c) || c == '_')) { ok = false; break; }
            if (std::isupper((unsigned char)c)) hasUpper = true;
            if (std::islower((unsigned char)c)) hasLower = true;
            if (c == '_') hasUnder = true;
            if (std::isdigit((unsigned char)c)) hasDigit = true;
        }
        if (!ok) continue;
        // A short lowercase word ("error", "password", "success") is data, not
        // credible embedded symbol evidence.  Require an identifier-shaped cue.
        if (!((hasUpper && hasLower) || hasUnder || (hasUpper && hasDigit))) continue;
        if (isAnonymousSubName(s)) continue;             // don't rename A to B's placeholder
        std::string low = nameKey(s);
        if (low == "__function__" || low == "__file__" || low == "__line__") continue;
        // Score: camelCase or snake_case identifiers look like real symbol names.
        int score = 0;
        if (hasUpper && hasLower) score += 3;
        if (hasUnder) score += 2;
        if (hasDigit) score += 1;
        score += (int)(40 - s.size()) / 10;           // mild preference for shorter
        if (score > bestScore) { bestScore = score; best = s; }
    }
    return best;
}

std::string compactLower(const std::string& s) {
    std::string out; out.reserve(s.size());
    for (char c : s)
        if (!std::isspace((unsigned char)c)) out.push_back((char)std::tolower((unsigned char)c));
    return out;
}

bool isFrameNoise(const Instruction& in, bool sawRet) {
    const std::string m = nameKey(in.mnemonic);
    const std::string o = compactLower(in.operands);
    if (m == "nop" || m == "endbr64" || m == "endbr32" || m == "leave") return true;
    // INT3 is common alignment after a completed body, but before the first RET
    // it is an observable trap and must not turn "int3; ret" into nullsub.
    if (sawRet && m == "int3") return true;
    if ((m == "push" || m == "pop") && (o == "rbp" || o == "ebp")) return true;
    if (m == "mov" && (o == "rbp,rsp" || o == "ebp,esp")) return true;
    return false;
}

bool zeroLiteral(std::string s) {
    if (s.size() >= 2 && s[0] == '0' && s[1] == 'x') s.erase(0, 2);
    if (!s.empty() && s.back() == 'h') s.pop_back();
    if (s.empty()) return false;
    for (char c : s) if (c != '0') return false;
    return true;
}

bool zeroesAccumulator(const Instruction& in) {
    const std::string m = nameKey(in.mnemonic);
    const std::string o = compactLower(in.operands);
    if ((m == "xor" || m == "sub") && (o == "eax,eax" || o == "rax,rax")) return true;
    if (m != "mov") return false;
    size_t comma = o.find(',');
    if (comma == std::string::npos) return false;
    const std::string dst = o.substr(0, comma);
    return (dst == "eax" || dst == "rax") && zeroLiteral(o.substr(comma + 1));
}

// Conservative x86 accumulator-clobber tracking for ret_zero.  False negatives
// are preferable to claiming "returns 0" after a later write made that untrue.
bool writesAccumulator(const Instruction& in) {
    const std::string m = nameKey(in.mnemonic);
    const std::string o = compactLower(in.operands);
    size_t comma = o.find(',');
    const std::string dst = o.substr(0, comma);
    const bool explicitAcc = dst == "rax" || dst == "eax" || dst == "ax" ||
                             dst == "al"  || dst == "ah";
    if (explicitAcc && m != "cmp" && m != "test" && m != "bt" && m != "push") return true;
    return m == "mul" || (m == "imul" && comma == std::string::npos) ||
           m == "div" || m == "idiv" ||
           m == "cpuid" || m == "rdtsc" || m == "rdtscp" || m == "xgetbv" ||
           m == "cmpxchg" || m == "cmpxchg8b" || m == "cmpxchg16b" ||
           m == "syscall" || m == "sysenter" || m == "lahf" || m == "popad" ||
           m.rfind("lods", 0) == 0;
}

} // namespace

std::string ToSnakeIdentifier(const std::string& api) {
    std::string a = bareApi(api);
    if (a.empty() || a[0] == '?') return {};
    size_t i = 0; while (i < a.size() && a[i] == '_') ++i;
    a.erase(0, i);
    std::string low = nameKey(a);
    if (low.rfind("imp_", 0) == 0) a.erase(0, 4);      // __imp_Foo -> Foo
    if (size_t at = a.find('@'); at != std::string::npos) a.resize(at);
    // Drop a trailing ANSI/Wide variant suffix ("CreateFileW" -> "CreateFile").
    if (a.size() >= 2 && (a.back() == 'A' || a.back() == 'W') &&
        std::islower((unsigned char)a[a.size() - 2]))
        a.pop_back();

    std::string out;
    for (size_t k = 0; k < a.size(); ++k) {
        char c = a[k];
        if (c == '@' || c == '?' || c == '$') break;             // decorated tail
        bool up = std::isupper((unsigned char)c) != 0;
        bool prevAlnumLower = k > 0 && (std::islower((unsigned char)a[k - 1]) ||
                                        std::isdigit((unsigned char)a[k - 1]));
        bool nextLower = k + 1 < a.size() && std::islower((unsigned char)a[k + 1]);
        if (up && !out.empty() && out.back() != '_' && (prevAlnumLower || nextLower))
            out.push_back('_');
        if (std::isalnum((unsigned char)c)) out.push_back((char)std::tolower((unsigned char)c));
        else if (!out.empty() && out.back() != '_') out.push_back('_');
    }
    while (!out.empty() && out.back() == '_') out.pop_back();
    size_t b = 0; while (b < out.size() && out[b] == '_') ++b;
    out = out.substr(b);
    if (out.empty()) return {};
    if (std::isdigit((unsigned char)out[0])) out = "fn_" + out;
    return out;
}

GuessedName GuessFromEvidence(const FuncEvidence& e) {
    GuessedName g;
    auto set = [&](std::string name, std::string reason) {
        g.name = std::move(name); g.reason = std::move(reason); g.guessed = true;
    };

    // 1) Image entry point.
    if (e.isEntry) { set("start", "image entry point"); return g; }

    // 2) Thunk / wrapper that tail-jumps straight to a known import.
    if (e.isThunk && !e.thunkApi.empty()) {
        if (std::string api = thunkIdentifier(e.thunkApi); !api.empty()) {
            set("j_" + api, "tail-jumps to " + e.thunkApi);
            return g;
        }
    }

    // 3) Trivial stubs.
    if (e.retOnly && e.callCount == 0) { set("nullsub", "empty stub (returns immediately)"); return g; }
    if (e.retZero && e.callCount == 0) { set("ret_zero", "returns 0"); return g; }

    // 4) Semantic name from the set of imported APIs it calls.
    if (!e.apis.empty()) {
        std::string s = semanticName(e.apis);
        if (!s.empty()) {
            std::string r = "calls " + joinApis(e.apis);
            if (e.selfRecursive) r += "; recursive";
            set(std::move(s), std::move(r));
            return g;
        }
        // 5) Thin wrapper around exactly one notable API.
        if (e.apis.size() == 1 && e.callCount <= 2 && e.instrCount <= 24) {
            if (std::string name = ToSnakeIdentifier(e.apis[0]); !name.empty()) {
                set(std::move(name), "wrapper around " + e.apis[0]);
                return g;
            }
        }
    }

    // 6) A distinctive identifier-like referenced string (embedded symbol name).
    if (std::string id = identifierString(e.strings); !id.empty()) {
        set(id, "references \"" + id + "\"");
        return g;
    }

    return g;   // no confident guess; caller keeps sub_<addr>
}

// ----------------------------------------------------------------- the pass ---

std::vector<GuessedName>
FunctionNamer::name(const BinaryFile& bin, IDisassembler& dis,
                    const std::vector<NamerInput>& funcs, uint64_t entryVA,
                    const std::function<std::string(uint64_t)>& importNameFor,
                    const std::function<std::string(uint64_t)>& stringRefFor) {
    guessed_ = 0;
    std::vector<GuessedName> out(funcs.size());

    auto isGuessable = [](const NamerInput& f) {
        return !f.isExport && isAnonymousSubName(f.name);
    };

    // Resolve a call/jmp instruction's target to an import name (direct target or
    // an IAT slot referenced through memory). "" when it isn't an import.
    auto resolveTargetApi = [&](const Instruction& in) -> std::string {
        std::string nm;
        if (in.branchTarget && importNameFor) nm = importNameFor(in.branchTarget);
        if (nm.empty()) {
            uint64_t mem = instrDataRef(in);                     // call/jmp [iat]
            if (mem && importNameFor) nm = importNameFor(mem);
        }
        return nm;
    };

    // Decode a function body into a window of instructions (bounded for speed).
    auto decodeBody = [&](const NamerInput& f, std::vector<Instruction>& insns) {
        size_t avail = 0;
        const uint8_t* p = bin.ptrFromVA(f.address, avail);
        if (!p) return;
        size_t win = f.size ? std::min<size_t>(avail, f.size) : std::min<size_t>(avail, 2048);
        win = std::min<size_t>(win, 8192);
        insns = dis.disassemble(p, win, f.address, 512);
    };

    // ---- Pass 1: detect thunks so calls *to* a thunk resolve to its API. ----
    struct ThunkInfo { bool isThunk = false; std::string api; uint64_t target = 0; };
    std::unordered_map<uint64_t, ThunkInfo> thunks;
    std::vector<std::vector<Instruction>> bodies(funcs.size());
    for (size_t i = 0; i < funcs.size(); ++i) {
        decodeBody(funcs[i], bodies[i]);
        const auto& insns = bodies[i];
        ThunkInfo t;
        for (const auto& in : insns) {
            if (in.mnemonic == "endbr64" || in.mnemonic == "endbr32" || in.mnemonic == "nop")
                continue;                                        // skip CET/padding prologue
            if (in.mnemonic == "jmp") {                          // unconditional -> tail call
                t.isThunk = true;
                t.api    = bareApi(resolveTargetApi(in));
                t.target = in.branchTarget;
            }
            break;                                               // only the first real instruction matters
        }
        if (t.isThunk) thunks[funcs[i].address] = t;
    }

    // Follow chains such as jmp sub_X -> jmp [IAT].  The previous one-level pass
    // left the outer thunk anonymous even though its final import was known.
    for (size_t pass = 0; pass < thunks.size(); ++pass) {
        bool changed = false;
        for (auto& [address, t] : thunks) {
            (void)address;
            if (!t.api.empty() || !t.target) continue;
            auto next = thunks.find(t.target);
            if (next != thunks.end() && !next->second.api.empty()) {
                t.api = next->second.api;
                changed = true;
            }
        }
        if (!changed) break;
    }

    // ---- Pass 2: full evidence + synthesis. ----
    // Keep synthesis separate from allocation so we know exactly which anonymous
    // originals will remain occupied before assigning any guessed names.
    std::vector<GuessedName> synthesized(funcs.size());

    for (size_t i = 0; i < funcs.size(); ++i) {
        const NamerInput& f = funcs[i];
        out[i].name = f.name;                 // default: keep existing name
        if (!isGuessable(f)) continue;

        FuncEvidence e;
        e.isEntry = (entryVA && f.address == entryVA);
        if (auto it = thunks.find(f.address); it != thunks.end()) {
            e.isThunk  = it->second.isThunk;
            e.thunkApi = it->second.api;
        }

        const auto& insns = bodies[i];
        int meaningful = 0;     // instrs that aren't padding/frame noise
        int retCount = 0;
        bool accKnownZero = false, allReturnsZero = true, hasControlBranch = false;
        std::unordered_set<std::string> apiSeen, strSeen;
        for (const auto& in : insns) {
            ++e.instrCount;
            bool noise = isFrameNoise(in, retCount != 0);
            if (!noise) ++meaningful;
            if (in.isRet) {
                ++retCount;
                allReturnsZero = allReturnsZero && accKnownZero;
                continue;
            }
            if (in.isBranch && !in.isCall) hasControlBranch = true;

            if (in.isCall) {
                ++e.callCount;
                accKnownZero = false;                                // x86 calls return through eax/rax
                std::string nm = resolveTargetApi(in);
                if (nm.empty() && in.branchTarget) {                 // call to another local fn?
                    if (in.branchTarget == f.address) e.selfRecursive = true;
                    else if (auto it = thunks.find(in.branchTarget); it != thunks.end() && !it->second.api.empty())
                        nm = it->second.api;                          // call to a thunk -> its API
                }
                std::string bare = bareApi(nm);
                if (!bare.empty() && !isNoiseApi(bare) && apiSeen.insert(norm(bare)).second)
                    e.apis.push_back(bare);
            } else {
                // String reference?
                uint64_t d = instrDataRef(in);
                if (!d) d = instrImmRef(in);                         // x86-32 mov/push offset string
                if (d && stringRefFor) {
                    std::string s = stringRefFor(d);
                    if (!s.empty() && e.strings.size() < 32 && strSeen.insert(s).second)
                        e.strings.push_back(s);
                }
                if (zeroesAccumulator(in)) accKnownZero = true;
                else if (writesAccumulator(in)) accKnownZero = false;
            }
        }
        e.retOnly = (e.callCount == 0 && retCount == 1 && !hasControlBranch && meaningful <= 1);
        e.retZero = (e.callCount == 0 && retCount == 1 && !hasControlBranch &&
                     allReturnsZero && meaningful <= 4);

        GuessedName g = GuessFromEvidence(e);
        if (!g.guessed) continue;
        synthesized[i] = std::move(g);
    }

    // Reserve every current name, including anonymous names that will remain
    // unguessed.  Release all originals known to be replaced, then allocate in
    // stable function order.  This avoids both duplicate unresolved sub_ names
    // and needless suffixes for placeholders that another guess will vacate.
    std::unordered_map<std::string, size_t> used;
    for (const auto& f : funcs) if (!f.name.empty()) ++used[nameKey(f.name)];
    for (size_t i = 0; i < funcs.size(); ++i) {
        if (!synthesized[i].guessed) continue;
        const std::string oldKey = nameKey(funcs[i].name);
        if (auto it = used.find(oldKey); it != used.end()) {
            if (it->second > 1) --it->second;
            else used.erase(it);
        }
    }

    for (size_t i = 0; i < funcs.size(); ++i) {
        GuessedName& g = synthesized[i];
        if (!g.guessed) continue;
        std::string base = g.name, cand = base;
        for (int k = 1; used.count(nameKey(cand)); ++k) {
            char suf[16]; std::snprintf(suf, sizeof(suf), "_%d", k);
            cand = base + suf;
        }
        ++used[nameKey(cand)];
        if (cand != base)
            g.reason += "; name \"" + base + "\" already existed, shown as \"" + cand + "\"";
        out[i].name    = std::move(cand);
        out[i].reason  = std::move(g.reason);
        out[i].guessed = true;
        ++guessed_;
    }

    return out;
}

} // namespace ds
