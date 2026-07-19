#include "analyzer/SuppressionFilter.h"

#include <algorithm>
#include <cctype>
#include <fstream>

namespace codeskeptic {

namespace {

const char kDisableLine[] = "codeskeptic-disable-line";
const char kDisableNextLine[] = "codeskeptic-disable-next-line";

bool isRuleChar(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '-' ||
           c == '_';
}

} // anonymous namespace

bool markerSuppressesRule(const std::string& line_text,
                          const std::string& marker,
                          const std::string& rule_id) {
    auto pos = line_text.find(marker);
    if (pos == std::string::npos) return false;

    // Rule list after the marker: space/comma-separated tokens.
    // Verify the marker ends on its own so that searching for
    // "codeskeptic-disable-line" does not match the "-next-line" variant.
    size_t after = pos + marker.size();
    if (after < line_text.size() && isRuleChar(line_text[after]))
        return false;

    std::vector<std::string> rules;
    std::string token;
    for (size_t i = after; i <= line_text.size(); ++i) {
        char c = (i < line_text.size()) ? line_text[i] : '\0';
        if (isRuleChar(c)) {
            token += c;
        } else {
            if (!token.empty()) {
                rules.push_back(token);
                token.clear();
            }
            // The rule list continues ONLY through spaces and commas;
            // any other character ends the list
            if (c != ' ' && c != '\t' && c != ',' && c != '\0') break;
        }
    }

    if (rules.empty()) return true;  // no rules specified -> all of them
    return std::find(rules.begin(), rules.end(), rule_id) != rules.end();
}

const std::vector<std::string>*
SuppressionFilter::linesFor(const std::string& path) {
    auto it = file_cache_.find(path);
    if (it != file_cache_.end()) return &it->second;

    std::vector<std::string> lines;
    std::ifstream file(path);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line))
            lines.push_back(line);
    }
    auto [inserted, _] = file_cache_.emplace(path, std::move(lines));
    return &inserted->second;
}

bool SuppressionFilter::isSuppressed(const Diagnostic& diag) {
    if (diag.line == 0) return false;
    const auto* lines = linesFor(diag.file);
    if (lines->empty()) return false;

    // disable-line on the same line
    if (diag.line <= lines->size() &&
        markerSuppressesRule((*lines)[diag.line - 1], kDisableLine,
                             diag.rule_id))
        return true;

    // disable-next-line on the previous line
    if (diag.line >= 2 && diag.line - 1 <= lines->size() &&
        markerSuppressesRule((*lines)[diag.line - 2], kDisableNextLine,
                             diag.rule_id))
        return true;

    return false;
}

size_t SuppressionFilter::filter(DiagnosticList& diagnostics) {
    size_t before = diagnostics.size();
    diagnostics.erase(
        std::remove_if(diagnostics.begin(), diagnostics.end(),
                       [this](const Diagnostic& d) {
                           return isSuppressed(d);
                       }),
        diagnostics.end());
    return before - diagnostics.size();
}

} // namespace codeskeptic
