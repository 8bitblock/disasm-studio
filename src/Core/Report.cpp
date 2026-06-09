#include "Report.h"

#include <cstdio>

namespace ds {

static std::string hex(uint64_t v) {
    char b[24]; std::snprintf(b, sizeof(b), "0x%llX", (unsigned long long)v);
    return b;
}

// A raw '|' or newline in a user-controlled string (a comment/rename/bookmark
// label) would break a Markdown table row; escape pipes and flatten newlines.
static std::string mdcell(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (char c : s) {
        if (c == '|')                 o += "\\|";
        else if (c == '\n' || c == '\r') o += ' ';
        else                          o += c;
    }
    return o;
}

// ---- Markdown ---------------------------------------------------------------

std::string RenderReportMarkdown(const ReportInput& in) {
    std::string o;
    o += "# Analysis report: " + (in.title.empty() ? std::string("(unnamed)") : in.title) + "\n\n";
    o += "| Field | Value |\n|---|---|\n";
    if (!in.hashHex.empty()) o += "| Content hash | `" + in.hashHex + "` |\n";
    if (!in.arch.empty())    o += "| Architecture | " + in.arch + " |\n";
    if (!in.engine.empty())  o += "| Engine | " + in.engine + " |\n";
    o += "| Functions | " + std::to_string(in.functionCount) + " |\n";
    o += "| Strings | " + std::to_string(in.stringCount) + " |\n\n";

    auto table = [&](const char* title, const std::vector<std::pair<uint64_t, std::string>>& rows,
                     const char* col) {
        o += "## " + std::string(title) + " (" + std::to_string(rows.size()) + ")\n\n";
        if (rows.empty()) { o += "_none_\n\n"; return; }
        o += std::string("| Address | ") + col + " |\n|---|---|\n";
        for (const auto& kv : rows) o += "| `" + hex(kv.first) + "` | " + mdcell(kv.second) + " |\n";
        o += "\n";
    };
    table("Renamed symbols", in.renames,   "Name");
    table("Comments",        in.comments,  "Comment");
    table("Bookmarks",       in.bookmarks, "Label");

    o += "## Notes\n\n";
    o += in.notes.empty() ? "_none_\n\n" : ("```\n" + in.notes + "\n```\n\n");

    if (!in.functions.empty()) {
        o += "## Decompiled functions (" + std::to_string(in.functions.size()) + ")\n\n";
        for (const auto& f : in.functions) {
            o += "### " + (f.name.empty() ? hex(f.address) : f.name) + "  `" + hex(f.address) + "`\n\n";
            if (!f.signature.empty()) o += "_" + f.signature + "_\n\n";
            o += "```c\n" + f.pseudocode + "\n```\n\n";
        }
    }
    return o;
}

// ---- HTML -------------------------------------------------------------------

static std::string esc(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&': o += "&amp;";  break;
            case '<': o += "&lt;";   break;
            case '>': o += "&gt;";   break;
            case '"': o += "&quot;"; break;
            default:  o += c;        break;
        }
    }
    return o;
}

std::string RenderReportHtml(const ReportInput& in) {
    std::string o;
    o += "<!doctype html><html><head><meta charset=\"utf-8\"><title>"
       + esc(in.title) + " - analysis</title><style>"
       "body{font-family:Segoe UI,Arial,sans-serif;background:#1e1f22;color:#dfe2e8;margin:24px;}"
       "h1,h2,h3{color:#8ab4f8;} table{border-collapse:collapse;margin:8px 0;}"
       "td,th{border:1px solid #3a3d44;padding:4px 10px;text-align:left;}"
       "th{background:#2a2d33;} code,pre{font-family:Consolas,monospace;}"
       "pre{background:#15161a;border:1px solid #3a3d44;padding:10px;overflow:auto;}"
       ".addr{color:#c0a060;}</style></head><body>";
    o += "<h1>Analysis report: " + esc(in.title.empty() ? "(unnamed)" : in.title) + "</h1>";
    o += "<table>";
    if (!in.hashHex.empty()) o += "<tr><th>Content hash</th><td><code>" + esc(in.hashHex) + "</code></td></tr>";
    if (!in.arch.empty())    o += "<tr><th>Architecture</th><td>" + esc(in.arch) + "</td></tr>";
    if (!in.engine.empty())  o += "<tr><th>Engine</th><td>" + esc(in.engine) + "</td></tr>";
    o += "<tr><th>Functions</th><td>" + std::to_string(in.functionCount) + "</td></tr>";
    o += "<tr><th>Strings</th><td>" + std::to_string(in.stringCount) + "</td></tr></table>";

    auto table = [&](const char* title, const std::vector<std::pair<uint64_t, std::string>>& rows,
                     const char* col) {
        o += "<h2>" + std::string(title) + " (" + std::to_string(rows.size()) + ")</h2>";
        if (rows.empty()) { o += "<p><em>none</em></p>"; return; }
        o += std::string("<table><tr><th>Address</th><th>") + col + "</th></tr>";
        for (const auto& kv : rows)
            o += "<tr><td class=\"addr\">" + hex(kv.first) + "</td><td>" + esc(kv.second) + "</td></tr>";
        o += "</table>";
    };
    table("Renamed symbols", in.renames,   "Name");
    table("Comments",        in.comments,  "Comment");
    table("Bookmarks",       in.bookmarks, "Label");

    o += "<h2>Notes</h2>";
    o += in.notes.empty() ? "<p><em>none</em></p>" : ("<pre>" + esc(in.notes) + "</pre>");

    if (!in.functions.empty()) {
        o += "<h2>Decompiled functions (" + std::to_string(in.functions.size()) + ")</h2>";
        for (const auto& f : in.functions) {
            o += "<h3>" + esc(f.name.empty() ? hex(f.address) : f.name)
               + " <span class=\"addr\">" + hex(f.address) + "</span></h3>";
            if (!f.signature.empty()) o += "<p><em>" + esc(f.signature) + "</em></p>";
            o += "<pre>" + esc(f.pseudocode) + "</pre>";
        }
    }
    o += "</body></html>";
    return o;
}

} // namespace ds
