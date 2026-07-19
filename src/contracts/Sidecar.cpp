#include "contracts/Sidecar.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/Basic/SourceManager.h>

#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

using namespace clang;

namespace codeskeptic {

namespace {

struct SidecarFileData {
    bool exists = false;
    // anchor -> entries (an anchor may carry several clauses)
    std::map<std::string, std::vector<SidecarEntry>> byAnchor;
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
    if (it != cache().end()) return it->second;

    SidecarFileData& data = cache()[cskPath];
    std::ifstream in(cskPath);
    if (!in) return data;  // exists stays false
    data.exists = true;

    std::vector<SidecarEntry> entries;
    std::vector<ContractSyntaxIssue> issues;
    std::stringstream buf;
    buf << in.rdbuf();
    parseSidecarText(buf.str(), entries, issues);

    for (auto& e : entries)
        data.byAnchor[e.anchor].push_back(e);
    for (auto& iss : issues)
        pendingIssues().emplace_back(cskPath, std::move(iss));
    return data;
}

} // anonymous namespace

void parseSidecarText(const std::string& text,
                      std::vector<SidecarEntry>& entries,
                      std::vector<ContractSyntaxIssue>& issues) {
    std::istringstream in(text);
    std::string raw;
    unsigned lineNo = 0;
    while (std::getline(in, raw)) {
        ++lineNo;
        std::string line = trim(raw);
        if (line.empty() || line[0] == '#') continue;
        auto colon = line.find(':');
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
    const std::string cskPath = file + ".csk";

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
            // Reuse the one contract grammar: a sidecar clause is
            // exactly a cs: line without the comment leader. Clause
            // line numbers are rewritten to the ABSOLUTE .csk line.
            ParsedContracts one =
                parseContractComment("// cs: " + entry.clause + "\n");
            for (auto& clause : one.clauses) {
                clause.line = entry.line;
                out.clauses.push_back(std::move(clause));
            }
            for (auto& err : one.syntaxErrors) {
                err.line = entry.line;
                out.syntaxErrors.push_back(std::move(err));
            }
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
