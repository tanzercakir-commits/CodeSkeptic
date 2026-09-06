#include "contracts/Sidecar.h"
#include "contracts/ModelInput.h"
#include "source_manager/InputIdentity.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/Basic/SourceManager.h>

#include <filesystem>
#include <map>
#include <set>
#include <sstream>

using namespace clang;

namespace codeskeptic {

namespace {

struct SidecarFileData {
    bool exists = false;
    bool witnessed = false;
    std::string consumed_text;
    // anchor -> entries (an anchor may carry several clauses)
    std::map<std::string, std::vector<ContractClause>> byAnchor;
};

std::map<std::string, SidecarFileData>& cache() {
    static std::map<std::string, SidecarFileData> c;
    return c;
}

std::vector<std::pair<std::string, ContractSyntaxIssue>>& pendingIssues() {
    static std::vector<std::pair<std::string, ContractSyntaxIssue>> v;
    return v;
}

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r");
    return s.substr(b, e - b + 1);
}

const SidecarFileData& loadSidecar(const std::string& cskPath) {
    auto it = cache().find(cskPath);
    if (it != cache().end()) {
        const auto& data = it->second;
        if (!data.witnessed) refuseInputReuse("sidecar_input_unavailable");
        else if (!data.exists) observeSidecarAbsence(cskPath);
        else observeSidecarText(cskPath, data.consumed_text);
        return data;
    }

    SidecarFileData& data = cache()[cskPath];
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(cskPath, ec);
    if (status.type() == std::filesystem::file_type::not_found) {
        data.witnessed = !ec || ec == std::errc::no_such_file_or_directory || ec == std::errc::not_a_directory;
        if (data.witnessed) observeSidecarAbsence(cskPath);
        else refuseInputReuse("sidecar_status_unavailable");
        return data; // optional sidecar is genuinely absent
    }
    data.exists = true;

    std::string text;
    if (!model_input::readTextFile(cskPath, 1024 * 1024, text)) {
        refuseInputReuse("sidecar_input_unavailable");
        pendingIssues().push_back({cskPath, {1,
            "unreadable, non-regular, oversized or binary sidecar input"}});
        return data;
    }
    data.witnessed = true;
    data.consumed_text = text;
    observeSidecarText(cskPath, text);

    std::vector<SidecarEntry> entries;
    std::vector<ContractSyntaxIssue> issues;
    parseSidecarText(text, entries, issues);

    // Validate unmatched anchors too; grammar validity is independent of the
    // declaration that happens to trigger this load. Never publish a prefix.
    decltype(data.byAnchor) staged;
    for (const auto& e : entries) {
        auto clause = parseContractClause(e.clause);
        if (!clause) {
            issues.push_back({e.line, e.clause});
            continue;
        }
        clause->line = e.line;
        staged[e.anchor].push_back(std::move(*clause));
    }
    if (issues.empty()) data.byAnchor.swap(staged);
    for (auto& iss : issues)
        pendingIssues().emplace_back(cskPath, std::move(iss));
    return data;
}

} // anonymous namespace

void parseSidecarText(const std::string& text,
                      std::vector<SidecarEntry>& entries,
                      std::vector<ContractSyntaxIssue>& issues) {
    if (text.size() > 1024 * 1024) {
        issues.push_back({1, "sidecar input exceeds 1 MiB"});
        return;
    }
    std::string normalized = text;
    if (!model_input::normalizeText(normalized, 1024 * 1024)) {
        issues.push_back({1, "sidecar input contains NUL or bare CR"});
        return;
    }
    std::istringstream in(std::move(normalized));
    std::string raw;
    unsigned lineNo = 0;
    size_t recordCount = 0;
    while (std::getline(in, raw)) {
        ++lineNo;
        if (raw.size() > 16384) {
            issues.push_back({lineNo, "sidecar line exceeds 16 KiB"});
            return;
        }
        std::string line = trim(raw);
        if (line.empty() || line[0] == '#') continue;
        if (++recordCount > 4096) {
            issues.push_back({lineNo, "sidecar input exceeds 4096 entries"});
            return;
        }
        auto colon = line.find(':');
        // A namespace separator belongs to the qualified anchor, not to the
        // anchor/clause delimiter (ns::name/arity: clause).
        while (colon != std::string::npos && colon + 1 < line.size() &&
               line[colon + 1] == ':')
            colon = line.find(':', colon + 2);
        // Every entry must be anchored — a colonless line, or one with
        // an empty anchor/clause, is a syntax issue, never skipped.
        if (colon == std::string::npos || colon == 0 ||
            trim(line.substr(colon + 1)).empty()) {
            issues.push_back({lineNo, line});
            continue;
        }
        SidecarEntry e;
        e.line = lineNo;
        e.anchor = trim(line.substr(0, colon));
        e.clause = trim(line.substr(colon + 1));
        entries.push_back(std::move(e));
    }
}

ParsedContracts sidecarContractsForDecl(const FunctionDecl* func,
                                        ASTContext& ctx,
                                        std::string* sidecarFile) {
    if (sidecarFile) sidecarFile->clear();
    ParsedContracts out;
    if (!func) return out;

    const SourceManager& sm = ctx.getSourceManager();
    const std::string file =
        sm.getFilename(sm.getExpansionLoc(func->getLocation())).str();
    if (file.empty()) return out;
    // Bind the lexical alias in the compiler directory, not a process-wide
    // relative cache key shared by differently rooted compile variants. Never
    // canonicalize a symlink before appending the alias-specific .csk suffix.
    const std::string cskPath = std::filesystem::absolute(file + ".csk").string();

    const SidecarFileData& data = loadSidecar(cskPath);
    if (!data.exists || data.byAnchor.empty()) return out;

    // Anchor candidates: qualified and plain names, each with an
    // optional /arity suffix (overload disambiguation).
    const std::string qual = func->getQualifiedNameAsString();
    const std::string plain = func->getNameAsString();
    const std::string arity = "/" + std::to_string(func->getNumParams());
    std::set<std::string> candidates = {qual, plain, qual + arity,
                                        plain + arity};

    for (const auto& anchor : candidates) {
        auto it = data.byAnchor.find(anchor);
        if (it == data.byAnchor.end()) continue;
        for (const auto& entry : it->second) {
            out.clauses.push_back(entry);
        }
        if (sidecarFile) *sidecarFile = cskPath;
    }
    return out;
}

std::vector<std::pair<std::string, ContractSyntaxIssue>>
takeSidecarIssues() {
    auto drained = std::move(pendingIssues());
    pendingIssues().clear();
    return drained;
}

void clearSidecarCache() {
    cache().clear();
    pendingIssues().clear();
}

} // namespace codeskeptic
