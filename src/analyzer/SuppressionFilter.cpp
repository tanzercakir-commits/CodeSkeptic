#include "analyzer/SuppressionFilter.h"

#include "core/Capabilities.h"
#include "core/FindingFingerprint.h"
#include <clang/Basic/LangOptions.h>
#include <clang/Lex/Lexer.h>
#include <algorithm>
#include <fstream>
#include <iterator>
#include <optional>
#include <string_view>

namespace codeskeptic {
namespace {

constexpr const char* kDisableLine = "codeskeptic-disable-line";
constexpr const char* kDisableNextLine = "codeskeptic-disable-next-line";

std::string_view trim(std::string_view text) {
    const auto first = text.find_first_not_of(" \t\r");
    if (first == std::string_view::npos) return {};
    return text.substr(first, text.find_last_not_of(" \t\r") - first + 1);
}

bool ruleChar(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_';
}

std::optional<SuppressionRecord> parseDirective(std::string_view body, unsigned line) {
    body = trim(body);
    if (!body.empty() && body.front() == '*') body = trim(body.substr(1));
    SuppressionRecord directive;
    for (const char* marker : {kDisableLine, kDisableNextLine}) {
        const std::string_view name(marker);
        if (body.substr(0, name.size()) != name) continue;
        auto rest = body.substr(name.size());
        if (!rest.empty() && rest.front() != ' ' && rest.front() != '\t' && rest.front() != '\r')
            return {};
        directive.marker = marker;
        directive.marker_line = line;
        directive.target_line = line + (name == kDisableNextLine ? 1 : 0);
        rest = trim(rest);
        bool afterComma = false;
        while (!rest.empty()) {
            if (rest.substr(0, 2) == "--" &&
                (rest.size() == 2 || rest[2] == ' ' || rest[2] == '\t')) {
                if (afterComma) return {};
                const auto reason = trim(rest.substr(2));
                if (reason.empty()) return {};
                directive.reason = std::string(reason);
                directive.has_reason = true;
                rest = {};
                break;
            }
            if (rest.front() == '(') {
                if (afterComma || rest.back() != ')') return {};
                const auto reason = trim(rest.substr(1, rest.size() - 2));
                if (reason.empty()) return {};
                directive.reason = std::string(reason);
                directive.has_reason = true;
                rest = {};
                break;
            }
            std::size_t length = 0;
            while (length < rest.size() && ruleChar(rest[length])) ++length;
            if (!length || rest.front() == '-') return {};
            directive.rules.emplace_back(rest.substr(0, length));
            afterComma = false;
            rest = rest.substr(length);
            const bool separated = !rest.empty() && (rest.front() == ' ' || rest.front() == '\t' || rest.front() == '\r');
            rest = trim(rest);
            if (!rest.empty() && rest.front() == ',') {
                afterComma = true;
                rest = trim(rest.substr(1));
                if (rest.empty()) return {};
            } else if (!rest.empty() && !separated) {
                return {};
            }
        }
        if (afterComma) return {};
        return directive;
    }
    return {};
}

// Raw Clang lexing recognizes ordinary/raw strings and multiline comments using
// the same token boundaries as source code, without preprocessing or execution.
std::vector<SuppressionRecord> directivesIn(const std::string& text) {
    clang::LangOptions options;
    options.CPlusPlus = options.CPlusPlus11 = options.CPlusPlus14 = options.LineComment = true;
    clang::Lexer lexer(clang::SourceLocation::getFromRawEncoding(1), options,
                       text.data(), text.data(), text.data() + text.size());
    lexer.SetCommentRetentionState(true);
    std::vector<SuppressionRecord> directives;
    std::size_t counted = 0;
    unsigned line = 1;
    while (true) {
        clang::Token token;
        const bool atEnd = lexer.LexFromRawLexer(token);
        if (token.is(clang::tok::comment)) {
            const auto offset = static_cast<std::size_t>(token.getLocation().getRawEncoding() - 1);
            if (offset > text.size() || token.getLength() > text.size() - offset) break;
            for (auto index = counted; index < offset; ++index) {
                if (text[index] == '\r') {
                    ++line;
                    if (index + 1 < offset && text[index + 1] == '\n') ++index;
                } else if (text[index] == '\n') ++line;
            }
            counted = offset;
            auto body = std::string_view(text).substr(offset, token.getLength());
            const bool block = body.substr(0, 2) == "/*";
            if (body.size() >= 2) body.remove_prefix(2);
            if (block && body.size() >= 2 && body.substr(body.size() - 2) == "*/") body.remove_suffix(2);
            unsigned markerLine = line;
            while (true) {
                const auto newline = body.find_first_of("\r\n");
                const auto fragment = body.substr(0, newline);
                if (auto directive = parseDirective(fragment, markerLine))
                    directives.push_back(std::move(*directive));
                if (newline == std::string_view::npos) break;
                const auto width = body[newline] == '\r' && newline + 1 < body.size() &&
                                   body[newline + 1] == '\n' ? 2 : 1;
                body.remove_prefix(newline + width);
                ++markerLine;
            }
        }
        if (atEnd || token.is(clang::tok::eof)) break;
    }
    return directives;
}

bool selects(const SuppressionRecord& directive, const std::string& rule) {
    return directive.rules.empty() ||
           std::find(directive.rules.begin(), directive.rules.end(), rule) != directive.rules.end();
}

} // namespace

bool markerSuppressesRule(const std::string& line_text, const std::string& marker,
                          const std::string& rule_id) {
    for (const auto& directive : directivesIn(line_text))
        if (directive.marker == marker && selects(directive, rule_id)) return true;
    return false;
}

const SuppressionRecord* SuppressionFilter::directiveFor(const Diagnostic& diag) {
    if (diag.line == 0) return nullptr;
    auto found = file_cache_.find(diag.file);
    if (found == file_cache_.end()) {
        std::ifstream file(diag.file, std::ios::binary);
        std::string text{std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
        auto directives = file.bad() ? std::vector<SuppressionRecord>{} : directivesIn(text);
        found = file_cache_.emplace(diag.file, std::move(directives)).first;
    }
    for (const auto& directive : found->second)
        if (directive.target_line == diag.line && selects(directive, diag.rule_id)) return &directive;
    return nullptr;
}

bool SuppressionFilter::isSuppressed(const Diagnostic& diag) {
    return directiveFor(diag) != nullptr;
}

size_t SuppressionFilter::filter(DiagnosticList& diagnostics) {
    file_cache_.clear();
    records_.clear();
    std::map<Diagnostic, std::size_t> recorded;
    FindingFingerprintContext fingerprints;
    const auto before = diagnostics.size();
    diagnostics.erase(std::remove_if(diagnostics.begin(), diagnostics.end(), [&](const Diagnostic& finding) {
        const auto* directive = directiveFor(finding);
        if (!directive) return false;
        const auto [entry, inserted] = recorded.emplace(finding, records_.size());
        if (inserted) {
            auto record = *directive;
            record.finding = finding;
            if (record.finding.fingerprint.empty()) record.finding.fingerprint = fingerprints.fingerprint(finding);
            records_.push_back(std::move(record));
        } else {
            auto& record = records_[entry->second];
            ++record.occurrences;
            mergeFindingMetadata(record.finding, finding);
        }
        return true;
    }), diagnostics.end());
    return before - diagnostics.size();
}

} // namespace codeskeptic
