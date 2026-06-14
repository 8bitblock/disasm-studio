//
// PatchCompiler.cpp — see PatchCompiler.h.
//
// Tier availability is compile-gated so the default build links with zero extra deps:
//   * Asm    — always (Keystone).
//   * C      — DS_HAVE_LIBTCC: vendored libtcc compiles to memory; we copy the 'hot'
//              function's bytes. CAVEAT: libtcc relocates against its own runtime, so
//              injected bytes only run correctly when 'hot' is self-contained +
//              position-independent (no external calls / absolute data refs). The UI
//              warns; a future pass can emit an object file + do proper relocation.
//   * Python — DS_HAVE_PYTHON: an embedded interpreter runs the snippet, which sets a
//              `patch = bytes([...])` global of position-independent machine code. Python
//              SCRIPTS the patch bytes (it does not compile to native).
//
#include "PatchCompiler.h"
#include "../Disasm/Assembler.h"   // ds::Assemble (Keystone)

#include <string>

#ifdef DS_HAVE_LIBTCC
#include <libtcc.h>
#endif
#ifdef DS_HAVE_PYTHON
#include <Python.h>
#endif

namespace ds {

const char* PatchLangName(PatchLang l) {
    switch (l) { case PatchLang::Asm: return "asm"; case PatchLang::C: return "c"; case PatchLang::Python: return "python"; }
    return "?";
}

static CompileResult CompileAsm(const std::string& src, const PatchCtx& ctx) {
    CompileResult r;
    AsmResult a = Assemble(ctx.arch, src, ctx.siteVA);
    r.ok = a.ok;
    r.bytes = std::move(a.bytes);
    if (!a.ok) r.diagnostics = a.error;
    return r;
}

#ifdef DS_HAVE_LIBTCC
static void tccErr(void* opaque, const char* msg) {
    if (opaque && msg) static_cast<std::string*>(opaque)->append(msg).append("\n");
}
#endif

static CompileResult CompileC(const std::string& src, const PatchCtx&) {
    CompileResult r;
#ifdef DS_HAVE_LIBTCC
    TCCState* s = tcc_new();
    if (!s) { r.diagnostics = "tcc_new failed"; return r; }
    std::string diag;
    tcc_set_error_func(s, &diag, tccErr);
    tcc_set_output_type(s, TCC_OUTPUT_MEMORY);
    if (tcc_compile_string(s, src.c_str()) == -1) {
        r.diagnostics = diag.empty() ? "C compile failed" : diag;
        tcc_delete(s); return r;
    }
    const int size = tcc_relocate(s, nullptr);   // query required size
    if (size <= 0) { r.diagnostics = "tcc_relocate sizing failed"; tcc_delete(s); return r; }
    r.bytes.resize((size_t)size);                 // own the relocated image
    if (tcc_relocate(s, r.bytes.data()) < 0) { r.diagnostics = "tcc_relocate failed"; r.bytes.clear(); tcc_delete(s); return r; }
    void* fn = tcc_get_symbol(s, "hot");
    if (!fn) { r.diagnostics = "define an entry function named 'hot' (e.g. int hot(...){...})"; r.bytes.clear(); tcc_delete(s); return r; }
    const size_t off = (size_t)((uint8_t*)fn - r.bytes.data());
    if (off >= r.bytes.size()) { r.diagnostics = "could not locate 'hot' in the compiled image"; r.bytes.clear(); tcc_delete(s); return r; }
    r.bytes.erase(r.bytes.begin(), r.bytes.begin() + off);   // start at 'hot'
    r.ok = true;
    r.diagnostics = "compiled " + std::to_string(r.bytes.size()) + " bytes \xE2\x80\x94 must be position-independent + leaf";
    tcc_delete(s);
#else
    (void)src;
    r.diagnostics = "inline C requires the libtcc-enabled build (DS_HAVE_LIBTCC + vendored libtcc); use the Asm tier";
#endif
    return r;
}

static CompileResult CompilePython(const std::string& src, const PatchCtx&) {
    CompileResult r;
#ifdef DS_HAVE_PYTHON
    if (!Py_IsInitialized()) Py_Initialize();
    PyObject* main = PyImport_AddModule("__main__");     // borrowed
    PyObject* dict = PyModule_GetDict(main);             // borrowed
    PyObject* res = PyRun_String(src.c_str(), Py_file_input, dict, dict);
    if (!res) {
        PyObject *t = nullptr, *v = nullptr, *tb = nullptr;
        PyErr_Fetch(&t, &v, &tb);
        if (v) { PyObject* sv = PyObject_Str(v); if (sv) { const char* m = PyUnicode_AsUTF8(sv); if (m) r.diagnostics = m; Py_DECREF(sv); } }
        Py_XDECREF(t); Py_XDECREF(v); Py_XDECREF(tb);
        PyErr_Clear();
        return r;
    }
    Py_DECREF(res);
    PyObject* pb = PyDict_GetItemString(dict, "patch");  // borrowed; expect a bytes object
    if (pb && PyBytes_Check(pb)) {
        char* buf = nullptr; Py_ssize_t n = 0;
        if (PyBytes_AsStringAndSize(pb, &buf, &n) == 0 && buf && n > 0) {
            r.bytes.assign((uint8_t*)buf, (uint8_t*)buf + n);
            r.ok = true;
            r.diagnostics = "scripted " + std::to_string((size_t)n) + " bytes from `patch`";
        } else r.diagnostics = "`patch` was empty";
    } else {
        r.diagnostics = "set a global `patch = bytes([...])` of position-independent machine code";
    }
#else
    (void)src;
    r.diagnostics = "embedded Python requires the python-enabled build (DS_HAVE_PYTHON); use the Asm tier";
#endif
    return r;
}

CompileResult CompilePatch(PatchLang lang, const std::string& source, const PatchCtx& ctx) {
    switch (lang) {
        case PatchLang::Asm:    return CompileAsm(source, ctx);
        case PatchLang::C:      return CompileC(source, ctx);
        case PatchLang::Python: return CompilePython(source, ctx);
    }
    CompileResult r; r.diagnostics = "unknown patch language"; return r;
}

} // namespace ds
