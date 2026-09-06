#ifndef CODESKEPTIC_CONTRACT_SIDECAR_H
#define CODESKEPTIC_CONTRACT_SIDECAR_H

// Sidecar contract files (CONTRACTS.md §2.4, Round E): for code you
// cannot annotate, contracts live next to the source —
// `src/core.c` -> `src/core.c.csk`. Every entry is EXPLICITLY
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
// The loader validates every clause before publishing any usable guarantee;
// framing, binary/limit or clause-grammar errors reject the file, with issues
// reported once per load. Parameter binding remains a later per-declaration
// semantic check; this loader does not claim whole-program model validation.
// Inclusive input ceilings: 1 MiB raw bytes, 16 KiB normalized physical line,
// 4096 non-comment/nonblank entries (duplicates included). LF/CRLF accepted;
// embedded NUL, bare CR, non-regular and unreadable inputs are rejected.

#include "contracts/ContractParser.h"

#include <string>
#include <utility>
#include <vector>

namespace clang {
class ASTContext;
class FunctionDecl;
}

namespace codeskeptic {

// Contracts for `func` from the sidecar of the file DECLARING it.
// Clause line numbers are absolute lines in the .csk file (unlike the
// block-relative lines of inline comments). `sidecarFile` receives
// the .csk path when anything was found. Results are cached per file
// for the process lifetime; clearSidecarCache() resets (tests, and
// long-lived server processes between runs).
ParsedContracts sidecarContractsForDecl(const clang::FunctionDecl* func,
                                        clang::ASTContext& ctx,
                                        std::string* sidecarFile = nullptr);

// Malformed sidecar LINES (missing anchor colon, unparseable clause)
// accumulated by the loads since the last call. Drained once —
// ContractRule reports them at the .csk file/line.
std::vector<std::pair<std::string, ContractSyntaxIssue>>
takeSidecarIssues();

void clearSidecarCache();

// Parses sidecar text (exposed for unit tests): fills anchor->entries
// and framing/integrity issues. Partial entries are useful for diagnostics;
// they are NOT safe to apply. The loader additionally validates all clauses
// using the shared grammar and publishes only if there are no issues.
struct SidecarEntry {
    unsigned line = 0;          // 1-based line in the .csk file
    std::string anchor;         // function name [ "/" arity ]
    std::string clause;         // clause text after the colon
};
void parseSidecarText(const std::string& text,
                      std::vector<SidecarEntry>& entries,
                      std::vector<ContractSyntaxIssue>& issues);

} // namespace codeskeptic

#endif // CODESKEPTIC_CONTRACT_SIDECAR_H
