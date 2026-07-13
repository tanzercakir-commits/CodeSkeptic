#ifndef ZERODEFECT_CONTRACT_INFO_H
#define ZERODEFECT_CONTRACT_INFO_H

// Rule-consumable view of a function's contracts (CONTRACTS.md,
// Round C). ContractRule owns REPORTING decisions; the dataflow rules
// (NullDeref, DivByZero) consume RequiresInfo for callee-side seeding
// and caller-side checking. Both go through this one recognizer so
// "which clauses are enforced" can never drift between rules.

#include "contracts/ContractParser.h"

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

// Call-site argument helpers for the caller-side checks.
bool isNullPointerArg(const clang::Expr* arg);
std::optional<long long> intLiteralArg(const clang::Expr* arg);

// Evaluates `value REL literal` for the NonNullUnlessCond escape.
bool evalCmp(long long value, ContractCmpOp op, long long literal);

} // namespace zerodefect

#endif // ZERODEFECT_CONTRACT_INFO_H
