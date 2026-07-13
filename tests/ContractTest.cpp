#include "TestHelper.h"
#include "contracts/ContractParser.h"
#include "rules/ContractRule.h"

#include <gtest/gtest.h>

using namespace zerodefect;
using namespace zerodefect::testing;

// Contracts Round B (CONTRACTS.md): comment surface + parser +
// unconditional return postconditions checked against the inferred
// summaries. A contract is a DECLARED summary; violation semantics:
// bare zd: = error, zd:ai = warning, unparseable = contract-syntax
// error, not-yet/never-checkable = explicit warning (never silent).

// --- Parser unit tests ---

TEST(ContractParserTest, ParsesEnsuresWithGuard) {
    auto parsed = parseContractComment(
        "// zd: ensures return != null if n != 0\n");
    ASSERT_EQ(parsed.clauses.size(), 1u);
    ASSERT_TRUE(parsed.syntaxErrors.empty());
    const auto& c = parsed.clauses[0];
    EXPECT_EQ(c.kind, ContractClauseKind::Ensures);
    EXPECT_TRUE(c.hasGuard);
    EXPECT_FALSE(c.machineProposed);
    EXPECT_EQ(c.pred.kind, ContractPred::Cmp);
    EXPECT_EQ(c.pred.lhs.kind, ContractOperandKind::Return);
    EXPECT_EQ(c.pred.op, ContractCmpOp::NE);
    EXPECT_EQ(c.pred.rhs.kind, ContractOperandKind::Null);
}

TEST(ContractParserTest, ParsesRequiresDisjunction) {
    auto parsed = parseContractComment(
        "// zd: requires p != null || n == 0\n");
    ASSERT_EQ(parsed.clauses.size(), 1u);
    const auto& c = parsed.clauses[0];
    EXPECT_EQ(c.kind, ContractClauseKind::Requires);
    EXPECT_EQ(c.pred.kind, ContractPred::Or);
    ASSERT_EQ(c.pred.children.size(), 2u);
}

TEST(ContractParserTest, ParsesEffectsAndPolicy) {
    auto parsed = parseContractComment(
        "/* zd: owns(cfg)\n"
        "   zd: borrows(name)\n"
        "   zd: returns owned\n"
        "   zd:policy no-absolute-paths */\n");
    ASSERT_EQ(parsed.clauses.size(), 4u);
    EXPECT_EQ(parsed.clauses[0].kind, ContractClauseKind::Owns);
    EXPECT_EQ(parsed.clauses[0].paramName, "cfg");
    EXPECT_EQ(parsed.clauses[1].kind, ContractClauseKind::Borrows);
    EXPECT_EQ(parsed.clauses[2].kind, ContractClauseKind::ReturnsOwned);
    EXPECT_EQ(parsed.clauses[3].kind, ContractClauseKind::Policy);
    EXPECT_EQ(parsed.clauses[3].policyName, "no-absolute-paths");
}

TEST(ContractParserTest, MachineProposedTag) {
    auto parsed = parseContractComment("// zd:ai ensures return != null\n");
    ASSERT_EQ(parsed.clauses.size(), 1u);
    EXPECT_TRUE(parsed.clauses[0].machineProposed);
}

TEST(ContractParserTest, SyntaxErrorsAreNeverSilent) {
    auto parsed = parseContractComment(
        "// zd: ensure return != null\n"     // typo: ensure
        "// zd: ensures return !=\n"          // missing operand
        "// ordinary prose, ignored\n");
    EXPECT_TRUE(parsed.clauses.empty());
    ASSERT_EQ(parsed.syntaxErrors.size(), 2u);
}

// --- Rule tests (attachment + verification) ---

TEST(ContractRuleTest, EnsuresNonNull_Violated_IsError) {
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd: ensures return != null
        int *find(int c) {
            if (c) return nullptr;
            static int g;
            return &g;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_NE(results[0].message.find("return != null"), std::string::npos);
}

TEST(ContractRuleTest, EnsuresNonNull_Satisfied_Silent) {
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd: ensures return != null
        int *find() {
            static int g;
            return &g;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRuleTest, EnsuresNonZero_Violated) {
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd: ensures return != 0
        int divisor(int c) {
            if (c) return 8;
            return 0;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(ContractRuleTest, MachineProposed_ViolationIsWarning) {
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd:ai ensures return != null
        int *find(int c) {
            if (c) return nullptr;
            static int g;
            return &g;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ContractRuleTest, SyntaxError_IsContractSyntaxError) {
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd: ensure return != null
        int *find() {
            static int g;
            return &g;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract-syntax");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(ContractRuleTest, LaterRoundClause_ReportedNotSilent) {
    // `requires` lands in Round C: until then the contract is
    // explicitly reported as unverified — never silently "accepted".
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd: requires p != null
        int deref(int *p) { return *p; }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract-unsupported");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ContractRuleTest, ParamVsParam_Unsupported) {
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd: requires n < m
        int slice(int n, int m) { return m - n; }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract-unsupported");
}

TEST(ContractRuleTest, NoContract_NoNoise) {
    ContractRule rule;
    auto results = runRule(rule, R"(
        // ordinary comment about the function
        int *find(int c) {
            if (c) return nullptr;
            static int g;
            return &g;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRuleTest, MultipleClauses_CheckedIndependently) {
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd: ensures return != null
        // zd: ensures return != 0
        int *find(int c) {
            if (c) return nullptr;
            static int g;
            return &g;
        }
    )");
    // Pointer contract violated (error); the != 0 clause on a pointer
    // return has no zeroness summary -> explicitly unverified.
    ASSERT_EQ(results.size(), 2u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[1].rule_id, "contract-unsupported");
}
