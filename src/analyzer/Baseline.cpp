#include "analyzer/Baseline.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <set>
#include <vector>
#include <charconv>
#include <limits>
#include <string_view>
#include <iterator>

namespace codeskeptic {

namespace {

constexpr const char* kHeaderV2 = "# codeskeptic-baseline v2";
constexpr const char* kHeaderV3 = "# codeskeptic-baseline v3";

std::string trimmed(const std::string& s) {
    const char* ws = " \t\r\n";
    auto b = s.find_first_not_of(ws);
    if (b == std::string::npos) return {};
    auto e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

// Hash that is STABLE across platforms/compilers: the baseline file is
// checked into the repo and must match one produced on a different
// machine (std::hash does not guarantee this)
std::string fnv1a64Hex(const std::string& s) {
    std::uint64_t h = 1469598103934665603ull;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    char buf[17];
    std::snprintf(buf, sizeof(buf), "%016llx",
                  static_cast<unsigned long long>(h));
    return buf;
}

// Per-file line cache: a single read for N findings in the same file
using LineCache = std::map<std::string, std::vector<std::string>>;

const std::string& sourceLine(LineCache& cache, const std::string& file,
                              unsigned line) {
    static const std::string empty;
    auto it = cache.find(file);
    if (it == cache.end()) {
        std::vector<std::string> lines;
        std::ifstream in(file);
        std::string l;
        while (std::getline(in, l)) lines.push_back(l);
        it = cache.emplace(file, std::move(lines)).first;
    }
    if (line == 0 || line > it->second.size()) return empty;
    return it->second[line - 1];
}

// Trimming is deliberate: re-indenting must not resurface a finding
std::string keyV2Cached(const Diagnostic& d, LineCache& cache) {
    return d.rule_id + "|" + d.file + "|" +
           fnv1a64Hex(trimmed(sourceLine(cache, d.file, d.line))) + "|" +
           d.message;
}

std::string hex(std::string_view input) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(input.size() * 2);
    for (const unsigned char byte : input) {
        result += digits[byte >> 4];
        result += digits[byte & 15];
    }
    return result;
}

bool hexField(std::string_view field, bool allowEmpty = false) {
    return (allowEmpty || !field.empty()) && field.size() % 2 == 0 &&
        std::all_of(field.begin(), field.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        });
}

bool positiveNumber(std::string_view field) {
    unsigned value = 0;
    const auto parsed = std::from_chars(field.data(), field.data() + field.size(), value);
    return !field.empty() && field.front() != '0' && parsed.ec == std::errc{} &&
           parsed.ptr == field.data() + field.size() && value > 0;
}

std::vector<std::string_view> fieldsOf(std::string_view row, std::size_t maximum) {
    std::vector<std::string_view> fields;
    while (fields.size() + 1 < maximum) {
        const auto delimiter = row.find('|');
        if (delimiter == std::string_view::npos) break;
        fields.push_back(row.substr(0, delimiter));
        row.remove_prefix(delimiter + 1);
    }
    fields.push_back(row);
    return fields;
}

bool validRow(const std::string& row, unsigned version) {
    const auto fields = fieldsOf(row, version == 3 ? 9 : 4);
    if (version == 3) {
        if (fields.size() == 2 && fields[0] == "unbound") return hexField(fields[1]);
        if (fields.size() != 9 || fields[0] != "v3" || !positiveNumber(fields[5]) ||
            (fields[6] != "info" && fields[6] != "warning" && fields[6] != "error")) return false;
        for (const auto index : {1u, 2u, 3u, 4u, 7u, 8u})
            if (!hexField(fields[index], index == 8)) return false;
        const auto prefix = hex("csb-fn1:");
        return fields[4].size() > prefix.size() && fields[4].substr(0, prefix.size()) == prefix;
    }
    if (fields.size() != 4 || fields[0].empty() || fields[1].empty()) return false;
    return version == 1 ? positiveNumber(fields[2])
                        : fields[2].size() == 16 && hexField(fields[2]);
}

std::string keyV3Cached(const Diagnostic& d, LineCache& cache) {
    if (d.baseline_function.rfind("csb-fn1:", 0) != 0 || d.baseline_function.size() <= 8 ||
        d.function.empty() || d.file.empty() || d.rule_id.empty() || !d.line || !d.column)
        return {};
    auto found = cache.find(d.file);
    if (found == cache.end()) {
        std::ifstream input(d.file, std::ios::binary);
        const std::string text{std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
        std::vector<std::string> lines;
        if (input.is_open() && !input.bad()) {
            std::size_t begin = 0;
            for (std::size_t index = 0; index < text.size(); ++index) {
                if (text[index] != '\r' && text[index] != '\n') continue;
                lines.push_back(text.substr(begin, index - begin));
                if (text[index] == '\r' && index + 1 < text.size() && text[index + 1] == '\n') ++index;
                begin = index + 1;
            }
            if (begin < text.size()) lines.push_back(text.substr(begin));
        }
        found = cache.emplace(d.file, std::move(lines)).first;
    }
    if (d.line > found->second.size()) return {};
    const auto& line = found->second[d.line - 1];
    const auto leading = line.find_first_not_of(" \t\r\n");
    if (leading == std::string::npos || d.column <= leading || d.column > line.size()) return {};
    const auto severity = d.severityToString();
    if (severity == "unknown") return {};
    return "v3|" + hex(d.rule_id) + "|" + hex(d.file) + "|" + hex(d.function) + "|" +
        hex(d.baseline_function) + "|" + std::to_string(d.column - leading) + "|" +
        severity + "|" + hex(trimmed(line)) + "|" + hex(d.message);
}

// Existing Diagnostic equivalence is preserved. All compilation variants must
// agree on strong identity; one missing/conflicting proof leaves the group new.
using Groups = std::map<Diagnostic, std::vector<const Diagnostic*>>;
Groups groupsOf(const DiagnosticList& diagnostics) {
    Groups groups;
    for (const auto& diagnostic : diagnostics) groups[diagnostic].push_back(&diagnostic);
    return groups;
}
std::string groupKey(const std::vector<const Diagnostic*>& group, LineCache& cache) {
    const auto key = keyV3Cached(*group.front(), cache);
    if (key.empty()) return {};
    for (const auto* diagnostic : group)
        if (keyV3Cached(*diagnostic, cache) != key) return {};
    return key;
}

} // anonymous namespace

std::string Baseline::keyV1(const Diagnostic& diag) {
    return diag.rule_id + "|" + diag.file + "|" +
           std::to_string(diag.line) + "|" + diag.message;
}

std::string Baseline::keyV2(const Diagnostic& diag) {
    LineCache cache;
    return keyV2Cached(diag, cache);
}

std::string Baseline::keyV3(const Diagnostic& diag) {
    LineCache cache;
    return keyV3Cached(diag, cache);
}

bool Baseline::write(const std::string& path,
                     const DiagnosticList& diagnostics, std::size_t* unbound) {
    if (unbound) *unbound = 0;
    std::ofstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    file << kHeaderV3 << "\n";
    LineCache cache;
    std::multiset<std::string> keys;
    for (const auto& [diagnostic, group] : groupsOf(diagnostics)) {
        auto key = groupKey(group, cache);
        if (key.empty()) {
            key = "unbound|" + hex(keyV1(diagnostic));
            if (unbound) ++*unbound;
        }
        keys.insert(std::move(key));
    }
    for (const auto& k : keys)
        file << k << "\n";
    file.flush();
    file.close();
    return !file.fail();
}

bool Baseline::load(const std::string& path) {
    counts_.clear();
    version_ = 0;
    unbound_ = 0;
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return false;

    std::map<std::string, std::size_t> parsed;
    unsigned version = 1;
    std::size_t unbound = 0;
    bool seenHeader = false, seenRecord = false;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line.front() == '#') {
            if (line.rfind("# codeskeptic-baseline", 0) != 0) continue;
            if (seenHeader || seenRecord) return false;
            if (line == kHeaderV2) version = 2;
            else if (line == kHeaderV3) version = 3;
            else if (line == "# codeskeptic-baseline v1") version = 1;
            else return false;
            seenHeader = true;
            continue;
        }
        if (std::any_of(line.begin(), line.end(), [](unsigned char c) { return c < 32 || c == 127; }) ||
            !validRow(line, version)) return false;
        seenRecord = true;
        if (version == 3 && line.rfind("unbound|", 0) == 0) ++unbound;
        else ++parsed[line];
    }
    if (file.bad() || !file.eof()) return false;
    counts_ = std::move(parsed);
    version_ = version;
    unbound_ = unbound;
    return true;
}

size_t Baseline::filter(DiagnosticList& diagnostics) const {
    if (counts_.empty()) return 0;

    // Local copy: the counters are consumed within this call — filter
    // stays const, and repeated calls are independent of each other
    auto budget = counts_;
    LineCache cache;

    auto consume = [&budget](const std::string& k) {
        auto it = budget.find(k);
        if (it == budget.end() || it->second == 0) return false;
        --it->second;
        return true;
    };

    size_t before = diagnostics.size();
    if (version_ == 3) {
        std::set<Diagnostic> matched;
        for (const auto& [diagnostic, group] : groupsOf(diagnostics)) {
            const auto key = groupKey(group, cache);
            if (!key.empty() && consume(key)) matched.insert(diagnostic);
        }
        diagnostics.erase(std::remove_if(diagnostics.begin(), diagnostics.end(),
            [&](const Diagnostic& diagnostic) { return matched.count(diagnostic) != 0; }), diagnostics.end());
        return before - diagnostics.size();
    }
    diagnostics.erase(
        std::remove_if(diagnostics.begin(), diagnostics.end(),
                       [&](const Diagnostic& d) {
                           // v1 first: old (headerless) files keep
                           // matching with their old line-number meaning
                           return consume(version_ == 1 ? keyV1(d) : keyV2Cached(d, cache));
                       }),
        diagnostics.end());
    return before - diagnostics.size();
}

} // namespace codeskeptic
