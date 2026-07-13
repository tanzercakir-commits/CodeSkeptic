#ifndef ZERODEFECT_CONTRACT_SIDECAR_H
#define ZERODEFECT_CONTRACT_SIDECAR_H

// Sidecar contract files (CONTRACTS.md §2.4, Round E): for code you
// cannot annotate, contracts live next to the source —
// `src/core.c` -> `src/core.c.zdc`. Every entry is EXPLICITLY
// anchored to a function name:
//
//     find_config: ensures return != null if n != 0
//     git_commit_create: requires repo != null
//     push_back/2: borrows(item)        # /arity disambiguates
//
// Order/position-based mapping is forbidden by design: a silently
// shifted mapping would attach guarantees to the WRONG functions.
// Unparseable lines are collected as syntax issues and reported by
// ContractRule — never silently dropped. Anchors that match no
// function in the current TU are NOT reported (the function may
// legitimately live in another TU); a whole-program anchor coverage
// check is a recorded residual.

#include "contracts/ContractParser.h"

#include <string>
#include <utility>
#include <vector>

namespace clang {
class ASTContext;
class FunctionDecl;
}

namespace zerodefect {

// Contracts for `func` from the sidecar of the file DECLARING it.
// Clause line numbers are absolute lines in the .zdc file (unlike the
// block-relative lines of inline comments). `sidecarFile` receives
// the .zdc path when anything was found. Results are cached per file
// for the process lifetime; clearSidecarCache() resets (tests, and
// long-lived server processes between runs).
ParsedContracts sidecarContractsForDecl(const clang::FunctionDecl* func,
                                        clang::ASTContext& ctx,
                                        std::string* sidecarFile = nullptr);

// Malformed sidecar LINES (missing anchor colon, unparseable clause)
// accumulated by the loads since the last call. Drained once —
// ContractRule reports them at the .zdc file/line.
std::vector<std::pair<std::string, ContractSyntaxIssue>>
takeSidecarIssues();

void clearSidecarCache();

// Parses sidecar text (exposed for unit tests): fills anchor->entries
// and syntax issues exactly as the file loader does.
struct SidecarEntry {
    unsigned line = 0;          // 1-based line in the .zdc file
    std::string anchor;         // function name [ "/" arity ]
    std::string clause;         // clause text after the colon
};
void parseSidecarText(const std::string& text,
                      std::vector<SidecarEntry>& entries,
                      std::vector<ContractSyntaxIssue>& issues);

} // namespace zerodefect

#endif // ZERODEFECT_CONTRACT_SIDECAR_H
