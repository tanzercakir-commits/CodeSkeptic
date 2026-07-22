#include "reporter/SarifReporter.h"

#include "core/Messages.h"

#include <fstream>
#include <iostream>
#include <set>

namespace {

std::string escapeJson(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

const char* sarifLevel(codeskeptic::Severity severity) {
    switch (severity) {
        case codeskeptic::Severity::Error:   return "error";
        case codeskeptic::Severity::Warning: return "warning";
        case codeskeptic::Severity::Info:    return "note";
    }
    return "none";
}

// SARIF artifactLocation.uri: absolute paths with the file:// scheme,
// relative paths as-is. Windows absolute paths (drive-letter C:\ or
// C:/, and UNC \\server\share) are absolute too — mis-classifying
// them as relative used to emit URIs GitHub code scanning cannot
// ingest (docs/windows-support.md §4).
bool isWindowsAbsolute(const std::string& path) {
    if (path.size() >= 2 && path[0] == '\\' && path[1] == '\\')
        return true; // UNC
    return path.size() >= 3 &&
           ((path[0] >= 'A' && path[0] <= 'Z') ||
            (path[0] >= 'a' && path[0] <= 'z')) &&
           path[1] == ':' && (path[2] == '\\' || path[2] == '/');
}

std::string toUri(const std::string& path) {
    if (!path.empty() && path[0] == '/')
        return "file://" + path;
    if (isWindowsAbsolute(path)) {
        std::string p = path;
        for (char& c : p)
            if (c == '\\') c = '/';
        if (p[0] == '/')           // UNC //server/share/...
            return "file:" + p;    // -> file://server/share/...
        return "file:///" + p;     // -> file:///C:/...
    }
    return path;
}

} // anonymous namespace

namespace codeskeptic {

SarifReporter::SarifReporter(const std::string& output_path)
    : output_path_(output_path) {}

void SarifReporter::report(const DiagnosticList& diagnostics) {
    std::ofstream file(output_path_);
    if (!file.is_open()) {
        std::cerr << msg(MsgId::OutputFileOpenError, output_path_) << "\n";
        return;
    }

    std::set<std::string> ruleIds;
    for (const auto& diag : diagnostics)
        ruleIds.insert(diag.rule_id);

    file << "{\n";
    file << "  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/"
            "sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\n";
    file << "  \"version\": \"2.1.0\",\n";
    file << "  \"runs\": [\n";
    file << "    {\n";
    file << "      \"tool\": {\n";
    file << "        \"driver\": {\n";
    file << "          \"name\": \"CodeSkeptic\",\n";
    file << "          \"informationUri\": "
            "\"https://github.com/tanzercakir-commits/CodeSkeptic\",\n";
    file << "          \"rules\": [";
    {
        bool first = true;
        for (const auto& id : ruleIds) {
            if (!first) file << ",";
            first = false;
            file << "\n            { \"id\": \"" << escapeJson(id) << "\" }";
        }
    }
    file << (ruleIds.empty() ? "]" : "\n          ]") << "\n";
    file << "        }\n";
    file << "      },\n";
    file << "      \"results\": [";

    for (size_t i = 0; i < diagnostics.size(); ++i) {
        const auto& diag = diagnostics[i];
        if (i > 0) file << ",";
        file << "\n        {\n";
        file << "          \"ruleId\": \"" << escapeJson(diag.rule_id)
             << "\",\n";
        file << "          \"level\": \"" << sarifLevel(diag.severity)
             << "\",\n";
        file << "          \"message\": { \"text\": \""
             << escapeJson(diag.message) << "\" },\n";
        file << "          \"locations\": [\n";
        file << "            {\n";
        file << "              \"physicalLocation\": {\n";
        file << "                \"artifactLocation\": { \"uri\": \""
             << escapeJson(toUri(diag.file)) << "\" },\n";
        file << "                \"region\": { \"startLine\": " << diag.line
             << ", \"startColumn\": " << diag.column << " }\n";
        file << "              }";
        if (!diag.function.empty()) {
            file << ",\n              \"logicalLocations\": [\n";
            file << "                { \"name\": \""
                 << escapeJson(diag.function)
                 << "\", \"kind\": \"function\" }\n";
            file << "              ]\n";
        } else {
            file << "\n";
        }
        file << "            }\n";
        file << (diag.notes.empty() ? "          ]\n" : "          ],\n");
        if (!diag.notes.empty()) {
            file << "          \"relatedLocations\": [";
            for (size_t n = 0; n < diag.notes.size(); ++n) {
                const auto& note = diag.notes[n];
                if (n > 0) file << ",";
                file << "\n            {\n";
                file << "              \"physicalLocation\": {\n";
                file << "                \"artifactLocation\": { \"uri\": \""
                     << escapeJson(toUri(note.file)) << "\" },\n";
                file << "                \"region\": { \"startLine\": "
                     << note.line << ", \"startColumn\": " << note.column
                     << " }\n";
                file << "              },\n";
                file << "              \"message\": { \"text\": \""
                     << escapeJson(note.message) << "\" }\n";
                file << "            }";
            }
            file << "\n          ]\n";
        }
        file << "        }";
    }

    file << (diagnostics.empty() ? "]" : "\n      ]") << "\n";
    file << "    }\n";
    file << "  ]\n";
    file << "}\n";
}

std::string SarifReporter::format() const {
    return "sarif";
}

} // namespace codeskeptic
