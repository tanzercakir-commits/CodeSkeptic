#ifndef ZERODEFECT_CONTRACT_INFO_H
#define ZERODEFECT_CONTRACT_INFO_H

// Rule-consumable view of a function's contracts (CONTRACTS.md,
// Round C). ContractRule owns REPORTING decisions; the dataflow rules
// (NullDeref, DivByZero) consume RequiresInfo for callee-side seeding
// and caller-side checking. Both go through this one recognizer so
// "which clauses are enforced" can never drift between rules.

#include "contracts/ContractParser.h"
#include "engine/PathFacts.h"

#include <optional>
#include <set>
#include <string>
#include <vector>

namespace clang {
class ASTContext;
class Expr;
class FunctionDecl;
}

namespace zerodefect {

// Fetches the raw comment attached to the declaration and parses its
// zd: lines. Also usable on declarations without a body (headers) —
// that is how caller-side checks see contracts of out-of-TU callees.
// commentLine receives the 1-based source line of the comment block
// start (0 when there is no comment).
ParsedContracts contractsForDecl(const clang::FunctionDecl* func,
                                 clang::ASTContext& ctx,
                                 unsigned* commentLine = nullptr,
                                 std::string* commentFile = nullptr);

// Inline comment clauses MERGED with the declaring file's .zdc
// sidecar clauses (Round E): what the ENFORCING rules consume —
// seeding and call-site checks must not care where a contract was
// written. ContractRule keeps the two sources separate for reporting
// (their line numbers map to different files).
ParsedContracts allContractClausesForDecl(const clang::FunctionDecl* func,
                                          clang::ASTContext& ctx);

// One enforced `requires` clause.
struct RequiresInfo {
    enum class Kind {
        NonNullParam,       // requires p != null
        NonZeroParam,       // requires n != 0
        NonNullUnlessCond,  // requires p != null || <n REL lit>
    };
    Kind kind = Kind::NonNullParam;
    unsigned paramIndex = 0;      // the constrained parameter
    // NonNullUnlessCond escape condition: TRUE releases the pointer.
    unsigned condParamIndex = 0;
    ContractCmpOp condOp = ContractCmpOp::EQ;
    long long condLiteral = 0;
    bool machineProposed = false;
    std::string text;             // clause verbatim (for messages)
    unsigned line = 0;            // line within the comment block
};

struct RequiresAnalysis {
    std::vector<RequiresInfo> enforced;
    // Clause lines recognized above — ContractRule must NOT report
    // these as unverified (they are enforced by the dataflow rules).
    std::set<unsigned> enforcedLines;
    // requires clauses naming a parameter the function does not have:
    // reported as contract-syntax by ContractRule.
    std::vector<ContractSyntaxIssue> unknownParams;
};

RequiresAnalysis analyzeRequires(const ParsedContracts& parsed,
                                 const clang::FunctionDecl* func);

// One enforced guarded postcondition:
// `ensures return != null if <param REL lit>` (CONTRACTS.md Round D).
// The guard is reduced to a canonical fact key — checking happens
// per-disjunct at return statements inside NullDeref.
struct GuardedEnsuresInfo {
    FactKey guardKey;
    bool guardWanted = true;  // key value WHEN THE GUARD IS TRUE
    bool machineProposed = false;
    std::string text;
    unsigned line = 0;
};

struct GuardedEnsuresAnalysis {
    std::vector<GuardedEnsuresInfo> enforced;
    // ContractRule must not report these lines as unverified.
    std::set<unsigned> enforcedLines;
};

// Recognizes the enforceable guarded null-postconditions of `func`:
// pred must be `return != null`, the guard a single
// parameter-vs-integer-literal comparison whose parameter is KEYABLE
// (not address-taken/assigned-nonlocal — collectUnkeyableDecls — and
// canonicalizable by compareFact). Everything else stays unenforced,
// and ContractRule keeps reporting it as unverified: keyability is
// decided HERE so the two sides can never disagree silently.
GuardedEnsuresAnalysis analyzeNullEnsuresGuards(
    const ParsedContracts& parsed, const clang::FunctionDecl* func);

// Call-site argument helpers for the caller-side checks.
bool isNullPointerArg(const clang::Expr* arg);
std::optional<long long> intLiteralArg(const clang::Expr* arg);

// Evaluates `value REL literal` for the NonNullUnlessCond escape.
bool evalCmp(long long value, ContractCmpOp op, long long literal);

// Contract comparison operator -> the clang BinaryOperatorKind that
// compareFact/normalizeCompare canonicalize.
clang::BinaryOperatorKind toBinaryOp(ContractCmpOp op);

} // namespace zerodefect

#endif // ZERODEFECT_CONTRACT_INFO_H
