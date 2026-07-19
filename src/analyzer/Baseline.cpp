#include "analyzer/Baseline.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <set>
#include <vector>

namespace codeskeptic {

namespace {

constexpr const char* kHeaderV2 = "# codeskeptic-baseline v2";

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

} // anonymous namespace

std::string Baseline::keyV1(const Diagnostic& diag) {
    return diag.rule_id + "|" + diag.file + "|" +
           std::to_string(diag.line) + "|" + diag.message;
}

std::string Baseline::keyV2(const Diagnostic& diag) {
    LineCache cache;
    return keyV2Cached(diag, cache);
}

bool Baseline::write(const std::string& path,
                     const DiagnosticList& diagnostics) {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    file << kHeaderV2 << "\n";
    // Sorted for deterministic output; multiset — identical keys are
    // preserved with their COUNTS (filter suppresses that many findings)
    LineCache cache;
    std::multiset<std::string> keys;
    for (const auto& diag : diagnostics)
        keys.insert(keyV2Cached(diag, cache));
    for (const auto& k : keys)
        file << k << "\n";
    return file.good();
}

bool Baseline::load(const std::string& path) {
    counts_.clear();
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        ++counts_[line];
    }
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
    diagnostics.erase(
        std::remove_if(diagnostics.begin(), diagnostics.end(),
                       [&](const Diagnostic& d) {
                           // v1 first: old (headerless) files keep
                           // matching with their old line-number meaning
                           return consume(keyV1(d)) ||
                                  consume(keyV2Cached(d, cache));
                       }),
        diagnostics.end());
    return before - diagnostics.size();
}

} // namespace codeskeptic
