#include "analyzer/Baseline.h"

#include <algorithm>
#include <fstream>

namespace zerodefect {

std::string Baseline::key(const Diagnostic& diag) {
    return diag.rule_id + "|" + diag.file + "|" +
           std::to_string(diag.line) + "|" + diag.message;
}

bool Baseline::write(const std::string& path,
                     const DiagnosticList& diagnostics) {
    std::ofstream file(path);
    if (!file.is_open()) return false;

    // Deterministik cikti icin sirali yaz
    std::set<std::string> keys;
    for (const auto& diag : diagnostics)
        keys.insert(key(diag));
    for (const auto& k : keys)
        file << k << "\n";
    return true;
}

bool Baseline::load(const std::string& path) {
    keys_.clear();
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty())
            keys_.insert(line);
    }
    return true;
}

size_t Baseline::filter(DiagnosticList& diagnostics) const {
    size_t before = diagnostics.size();
    diagnostics.erase(
        std::remove_if(diagnostics.begin(), diagnostics.end(),
                       [this](const Diagnostic& d) {
                           return keys_.count(key(d)) > 0;
                       }),
        diagnostics.end());
    return before - diagnostics.size();
}

} // namespace zerodefect
