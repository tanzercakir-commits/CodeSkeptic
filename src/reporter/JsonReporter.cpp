#include "reporter/JsonReporter.h"

#include <fstream>
#include <iostream>

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

} // anonymous namespace

namespace zerodefect {

JsonReporter::JsonReporter(const std::string& output_path)
    : output_path_(output_path) {}

void JsonReporter::report(const DiagnosticList& diagnostics) {
    std::ofstream file(output_path_);
    if (!file.is_open()) {
        std::cerr << "[ZeroDefect] JSON dosyasi acilamadi: "
                  << output_path_ << "\n";
        return;
    }

    file << "{\n";
    file << "  \"tool\": \"ZeroDefect\",\n";
    file << "  \"total\": " << diagnostics.size() << ",\n";
    file << "  \"diagnostics\": [";

    for (size_t i = 0; i < diagnostics.size(); ++i) {
        const auto& diag = diagnostics[i];
        if (i > 0) file << ",";
        file << "\n    {\n";
        file << "      \"severity\": \"" << diag.severityToString() << "\",\n";
        file << "      \"rule_id\": \"" << escapeJson(diag.rule_id) << "\",\n";
        file << "      \"file\": \"" << escapeJson(diag.file) << "\",\n";
        file << "      \"line\": " << diag.line << ",\n";
        file << "      \"column\": " << diag.column << ",\n";
        file << "      \"message\": \"" << escapeJson(diag.message) << "\"\n";
        file << "    }";
    }

    file << "\n  ]\n";
    file << "}\n";
}

std::string JsonReporter::format() const {
    return "json";
}

} // namespace zerodefect
