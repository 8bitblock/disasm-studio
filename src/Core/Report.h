#pragma once
//
// Report.h
// Pure formatters that turn a binary's analysis (comments, renames, bookmarks,
// notes, and decompiled functions) into a shareable Markdown or HTML report.
// No ImGui / Win32 dependency, so the rendering is unit-testable in the sandbox.
//
#include <cstdint>
#include <string>
#include <vector>

namespace ds {

struct ReportFunction {
    uint64_t    address = 0;
    std::string name;
    std::string signature;    // inferred prototype (optional)
    std::string pseudocode;   // decompiled body (optional)
};

struct ReportInput {
    std::string title;        // binary name / path
    std::string hashHex;      // content hash (hex)
    std::string arch;
    std::string engine;
    int         functionCount = 0;
    int         stringCount   = 0;

    std::vector<std::pair<uint64_t, std::string>> renames;    // addr -> user name
    std::vector<std::pair<uint64_t, std::string>> comments;   // addr -> comment
    std::vector<std::pair<uint64_t, std::string>> bookmarks;  // addr -> label
    std::string                                   notes;
    std::vector<ReportFunction>                   functions;  // those with pseudocode
};

std::string RenderReportMarkdown(const ReportInput& in);
std::string RenderReportHtml(const ReportInput& in);

} // namespace ds
