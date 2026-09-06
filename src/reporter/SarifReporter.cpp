#include "reporter/SarifReporter.h"

#include "core/Capabilities.h"
#include "core/FindingFingerprint.h"

#include "core/Messages.h"
#include "reporter/Coverage.h"
#include "reporter/ReportContract.h"

#include <fstream>
#include <iostream>
#include <set>

namespace {

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
    const bool windows = isWindowsAbsolute(path);
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string encoded;
    for (std::size_t i = 0; i < path.size(); ++i) {
        unsigned char c = path[i];
        if (windows && c == '\\') c = '/';
        const bool unreserved = (c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '.' || c == '_' || c == '~';
        // Relative backslash paths retain the established Windows fixture
        // representation. This legacy exception is not general URI normalization.
        const bool legacyBackslash = !windows && !path.empty() &&
                                     path[0] != '/' && c == '\\';
        if (unreserved || c == '/' || (windows && i == 1 && c == ':') ||
            legacyBackslash) encoded += static_cast<char>(c);
        else {
            encoded += '%';
            encoded += hex[c >> 4];
            encoded += hex[c & 15];
        }
    }
    if (!path.empty() && path[0] == '/')
        return "file://" + encoded;
    if (windows) {
        if (encoded[0] == '/')         // UNC //server/share/...
            return "file:" + encoded; // -> file://server/share/...
        return "file:///" + encoded;  // -> file:///C:/...
    }
    return encoded;
}

} // anonymous namespace

namespace codeskeptic {

SarifReporter::SarifReporter(const std::string& output_path)
    : output_path_(output_path) {}

bool SarifReporter::report(const DiagnosticList& diagnostics,
                           const AnalysisResult* result) {
    std::ofstream file(output_path_);
    if (!file.is_open()) {
        std::cerr << msg(MsgId::OutputFileOpenError, output_path_) << "\n";
        return false;
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
    file << "          \"version\": \"" << escapeJson(toolVersion()) << "\",\n";
    file << "          \"informationUri\": "
            "\"https://github.com/tanzercakir-commits/CodeSkeptic\",\n";
    file << "          \"rules\": [";
    {
        bool first = true;
        for (const auto& id : ruleIds) {
            if (!first) file << ",";
            first = false;
            file << "\n            { \"id\": \"" << escapeJson(id) << "\"";
            if (const auto* rule = findRuleCapability(id)) {
                file << ", \"shortDescription\": { \"text\": \""
                     << escapeJson(std::string(rule->description))
                     << "\" }, \"helpUri\": \"" << escapeJson(std::string(rule->help_uri))
                     << "\", \"properties\": { \"codeskeptic/potentialCwes\": ";
                writeCweReferencesJson(file, rule->cwe_ids);
                file << " }";
            }
            file << " }";
        }
    }
    file << (ruleIds.empty() ? "]" : "\n          ]") << "\n";
    file << "        }\n";
    file << "      },\n";
    file << "      \"properties\": { \"codeskeptic/report\": ";
    writeReportRunJson(file, diagnostics.size(), result);
    file << " },\n";
    if (result) {
        file << "      \"invocations\": [ { \"executionSuccessful\": "
             << (result->complete() ? "true" : "false")
             << ", \"properties\": { \"codeskeptic/status\": \""
             << result->statusName() << "\", \"codeskeptic/exitCode\": "
             << result->exitCode()
             << ", \"codeskeptic/attemptedTUs\": "
             << result->attempted_tus
             << ", \"codeskeptic/analyzedTUs\": " << result->analyzed_tus
             << ", \"codeskeptic/brokenTUs\": " << result->broken_tus
             << ", \"codeskeptic/incompleteFunctions\": "
             << result->incomplete_functions
             << ", \"codeskeptic/blockingFindings\": "
             << result->blockingFindings()
             << ", \"codeskeptic/reportOnlyFindings\": "
             << result->report_only_findings << ", \"codeskeptic/coverage\": ";
        writeCoverageJson(file, *result);
        file << " } } ],\n";
    }
    file << "      \"results\": [";

    for (size_t i = 0; i < diagnostics.size(); ++i) {
        const auto& diag = diagnostics[i];
        const std::string fingerprint = diag.fingerprint.empty()
            ? findingFingerprint(diag)
            : diag.fingerprint;
        if (i > 0) file << ",";
        file << "\n        {\n";
        file << "          \"ruleId\": \"" << escapeJson(diag.rule_id)
             << "\",\n";
        const RuleCapability* capability =
            findRuleCapability(diag.rule_id);
        file << "          \"properties\": { \"codeskeptic/capabilityTier\": \""
             << (capability ? capabilityTierName(capability->tier)
                            : "unclassified")
             << "\", \"codeskeptic/blocksVerdict\": "
             << (findingBlocksVerdict(diag.rule_id) ? "true" : "false")
             << ", \"codeskeptic/ruleMetadata\": ";
        writeFindingMetadataJson(file, diag);
        file << ", \"codeskeptic/baselineFunction\": \"" << escapeJson(diag.baseline_function) << "\" },\n";
        file << "          \"partialFingerprints\": { "
             << "\"codeskeptic/v1\": \"" << escapeJson(fingerprint)
             << "\" },\n";
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
    file.flush();
    if (!file.good()) {
        std::cerr << msg(MsgId::OutputFileOpenError, output_path_) << "\n";
        return false;
    }
    return true;
}

std::string SarifReporter::format() const {
    return "sarif";
}

} // namespace codeskeptic
