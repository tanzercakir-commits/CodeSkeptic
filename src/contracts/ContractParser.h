#ifndef ZERODEFECT_CONTRACT_PARSER_H
#define ZERODEFECT_CONTRACT_PARSER_H

// Contract comment parser (CONTRACTS.md §3).
//
// Grammar (v1):
//   contract-line := "zd:" [ "ai" ] clause
//   clause  := "requires" pred
//            | "ensures" pred [ "if" pred ]
//            | "owns" "(" param ")"
//            | "borrows" "(" param ")"
//            | "returns" "owned"
//            | "policy" name
//   pred    := or-expr
//   or-expr := and-expr { "||" and-expr }
//   and-expr:= unary { "&&" unary }
//   unary   := "!" unary | atom
//   atom    := "(" pred ")" | operand relop operand | operand
//   operand := "return" | identifier | integer | "null"
//
// Deliberately tiny and hand-parsed: the binding constraint is not
// parser technology but the fact machinery every construct must map
// onto (CONTRACTS.md §4). Parse errors are NEVER silent — the caller
// receives them and reports contract-syntax diagnostics.

#include <string>
#include <vector>

namespace zerodefect {

enum class ContractClauseKind {
    Requires,
    Ensures,
    Owns,
    Borrows,
    ReturnsOwned,
    Policy,
};

enum class ContractCmpOp { EQ, NE, LT, LE, GT, GE };

enum class ContractOperandKind { Return, Param, IntLit, Null };

struct ContractOperand {
    ContractOperandKind kind = ContractOperandKind::Null;
    std::string param;    // Param
    long long value = 0;  // IntLit
};

// Small predicate tree. Kind Cmp uses lhs/op/rhs; And/Or use
// children (>= 2); Not uses children[0]; Truth uses lhs only
// (`if (flag)`-style bare operand).
struct ContractPred {
    enum Kind { Cmp, And, Or, Not, Truth } kind = Truth;
    ContractOperand lhs;
    ContractCmpOp op = ContractCmpOp::EQ;
    ContractOperand rhs;
    std::vector<ContractPred> children;
};

struct ContractClause {
    ContractClauseKind kind = ContractClauseKind::Ensures;
    bool machineProposed = false;  // zd:ai
    std::string text;              // clause verbatim (after the tag)
    unsigned line = 0;             // 1-based line within the comment block

    ContractPred pred;             // Requires / Ensures
    bool hasGuard = false;
    ContractPred guard;            // Ensures ... if <guard>
    std::string paramName;         // Owns / Borrows
    std::string policyName;        // Policy
};

struct ContractSyntaxIssue {
    unsigned line = 0;   // 1-based line within the comment block
    std::string text;    // the offending line, verbatim
};

struct ParsedContracts {
    std::vector<ContractClause> clauses;
    std::vector<ContractSyntaxIssue> syntaxErrors;
    bool empty() const { return clauses.empty() && syntaxErrors.empty(); }
};

// Scans a raw comment block for `zd:` lines and parses each one.
// Non-`zd:` lines are ignored (ordinary prose). Line numbers in the
// result are relative to the block (1-based); the caller offsets them
// with the block's source location.
ParsedContracts parseContractComment(const std::string& commentText);

} // namespace zerodefect

#endif // ZERODEFECT_CONTRACT_PARSER_H
