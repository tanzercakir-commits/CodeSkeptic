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

const char* sarifLevel(zerodefect::Severity severity) {
    switch (severity) {
        case zerodefect::Severity::Error:   return "error";
        case zerodefect::Severity::Warning: return "warning";
        case zerodefect::Severity::Info:    return "note";
    }
    return "none";
}

// SARIF artifactLocation.uri: mutlak path'ler file:// semasiyla,
// goreceli path'ler oldugu gibi
std::string toUri(const std::string& path) {
    if (!path.empty() && path[0] == '/')
        return "file://" + path;
    return path;
}

} // anonymous namespace

namespace zerodefect {

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
    file << "          \"name\": \"ZeroDefect\",\n";
    file << "          \"informationUri\": "
            "\"https://github.com/tanzercakir-commits/ZeroDefect\",\n";
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
        file << "              }\n";
        file << "            }\n";
        file << "          ]\n";
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

} // namespace zerodefect
