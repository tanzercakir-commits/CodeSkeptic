#include "reporter/JsonReporter.h"

#include "core/Capabilities.h"
#include "core/FindingFingerprint.h"
#include "core/Messages.h"

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

namespace codeskeptic {

JsonReporter::JsonReporter(const std::string& output_path)
    : output_path_(output_path) {}

bool JsonReporter::report(const DiagnosticList& diagnostics,
                          const AnalysisResult* result) {
    std::ofstream file(output_path_);
    if (!file.is_open()) {
        std::cerr << msg(MsgId::OutputFileOpenError, output_path_) << "\n";
        return false;
    }

    file << "{\n";
    file << "  \"tool\": \"CodeSkeptic\",\n";
    if (result) {
        file << "  \"status\": \"" << result->statusName() << "\",\n";
        file << "  \"complete\": " << (result->complete() ? "true" : "false")
             << ",\n";
        file << "  \"exit_code\": " << result->exitCode() << ",\n";
        file << "  \"coverage\": { \"attempted_tus\": "
             << result->attempted_tus << ", \"analyzed_tus\": "
             << result->analyzed_tus << ", \"broken_tus\": "
             << result->broken_tus << ", \"incomplete_functions\": "
             << result->incomplete_functions << " },\n";
        file << "  \"evidence\": { \"no_inputs\": "
             << (result->no_inputs ? "true" : "false")
             << ", \"no_rules\": "
             << (result->no_rules ? "true" : "false")
             << ", \"tool_failed\": "
             << (result->tool_failed ? "true" : "false")
             << ", \"summary_load_failed\": "
             << (result->summary_load_failed ? "true" : "false")
             << ", \"summary_stale\": "
             << (result->summary_stale ? "true" : "false")
             << ", \"summary_save_failed\": "
             << (result->summary_save_failed ? "true" : "false")
             << ", \"baseline_load_failed\": "
             << (result->baseline_load_failed ? "true" : "false")
             << ", \"baseline_write_failed\": "
             << (result->baseline_write_failed ? "true" : "false")
             << ", \"baseline_recorded\": "
             << (result->baseline_recorded ? "true" : "false")
             << ", \"report_write_failed\": "
             << (result->report_write_failed ? "true" : "false")
             << " },\n";
        file << "  \"finding_counts\": { \"total\": "
             << result->findings << ", \"blocking\": "
             << result->blockingFindings() << ", \"report_only\": "
             << result->report_only_findings << " },\n";
    }
    file << "  \"total\": " << diagnostics.size() << ",\n";
    file << "  \"diagnostics\": [";

    for (size_t i = 0; i < diagnostics.size(); ++i) {
        const auto& diag = diagnostics[i];
        const std::string fingerprint = diag.fingerprint.empty()
            ? findingFingerprint(diag)
            : diag.fingerprint;
        if (i > 0) file << ",";
        file << "\n    {\n";
        file << "      \"severity\": \"" << diag.severityToString() << "\",\n";
        file << "      \"rule_id\": \"" << escapeJson(diag.rule_id) << "\",\n";
        const RuleCapability* capability =
            findRuleCapability(diag.rule_id);
        file << "      \"capability_tier\": \""
             << (capability ? capabilityTierName(capability->tier)
                            : "unclassified")
             << "\",\n";
        file << "      \"blocks_verdict\": "
             << (findingBlocksVerdict(diag.rule_id) ? "true" : "false")
             << ",\n";
        file << "      \"fingerprint\": \""
             << escapeJson(fingerprint) << "\",\n";
        file << "      \"file\": \"" << escapeJson(diag.file) << "\",\n";
        file << "      \"line\": " << diag.line << ",\n";
        file << "      \"column\": " << diag.column << ",\n";
        file << "      \"function\": \"" << escapeJson(diag.function)
             << "\",\n";
        file << "      \"message\": \"" << escapeJson(diag.message) << "\",\n";
        file << "      \"notes\": [";
        for (size_t n = 0; n < diag.notes.size(); ++n) {
            const auto& note = diag.notes[n];
            if (n > 0) file << ",";
            file << "\n        { \"file\": \"" << escapeJson(note.file)
                 << "\", \"line\": " << note.line
                 << ", \"column\": " << note.column
                 << ", \"message\": \"" << escapeJson(note.message)
                 << "\" }";
        }
        file << (diag.notes.empty() ? "]" : "\n      ]") << "\n";
        file << "    }";
    }

    file << "\n  ]\n";
    file << "}\n";
    file.flush();
    if (!file.good()) {
        std::cerr << msg(MsgId::OutputFileOpenError, output_path_) << "\n";
        return false;
    }
    return true;
}

std::string JsonReporter::format() const {
    return "json";
}

} // namespace codeskeptic
