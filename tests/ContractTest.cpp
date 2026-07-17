#include "TestHelper.h"
#include "contracts/ContractParser.h"
#include "contracts/Policy.h"
#include "contracts/Sidecar.h"
#include "rules/ContractRule.h"
#include "rules/DivByZeroRule.h"
#include "rules/NullDerefRule.h"
#include "rules/PolicyRule.h"

#include <gtest/gtest.h>

#include <fstream>

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
    // `returns owned` needs a return-ownership summary the engine
    // does not infer yet: until then the contract is explicitly
    // reported as unverified — never silently "accepted".
    ContractRule rule;
    auto results = runRule(rule, R"(
        char *dup(const char *s);
        // zd: returns owned
        char *make_name(const char *base) { return dup(base); }
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

// --- Round C: requires — callee seeding + caller-side checks ---
// Assume/guarantee split: the callee ASSUMES its declared requires
// (parameters seeded), every visible call site is CHECKED against the
// caller's own dataflow state. NullDeref owns the non-null clauses,
// DivByZero the non-zero ones; ContractRule no longer reports enforced
// clauses as unverified.

TEST(ContractRoundCTest, EnforcedRequires_NotReportedUnverified) {
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd: requires p != null
        int deref(int *p) { return *p; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRoundCTest, UnknownParamName_IsContractSyntax) {
    // A requires clause naming a parameter the function does not have
    // can never bind — that is a contract error, not a later round.
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd: requires q != null
        int deref(int *p) { return p ? *p : 0; }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract-syntax");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(ContractRoundCTest, RequiresNonNull_CalleeSeeded_NoNoise) {
    // The contract carries the proof burden: inside the body p is
    // NonNull, the dereference is silent.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd: requires p != null
        int deref(int *p) { return *p; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRoundCTest, RequiresNonNull_PartialGuard_ProofBurdenDischarged) {
    // The seeding must survive a PARTIAL guard (2026-07-17). Godot's
    // `ERR_FAIL_COND_V(!p && n > 0, ...)` — a compound `if (!p && n>0)
    // return;` — short-circuits to a fall-through where `!p` held and
    // `n>0` did not (n==0, p null). Without the contract that
    // fall-through is a REAL deref; WITH `requires p != null` the
    // p-null path is impossible, so the disjunct where `!p` refined p
    // to null contradicts the seed and must DROP. Before the leaf-
    // refute drop this fabricated a spurious "may be null".
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        // zd: requires p != null
        int f(T *p, unsigned n) {
            if (!p && n > 0) return -1;
            return p->x;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRoundCTest, RequiresUnlessZero_ThroughLoop_ProofDischarged) {
    // #87: the relational escape `requires p != null unless n == 0`
    // seeds a {n==0: p free} disjunct. A deref inside `for (i=0; i<n;
    // ++i)` must be clean: on the body edge `i < n` holds, so (both
    // unsigned) n != 0, which refutes the n==0 escape — the loop body
    // is unreachable when n==0. Before the loop-bound-nonzero fact the
    // escape survived into the body and the guard/short-circuit
    // fabricated a null p there.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        extern int sink(int);
        // zd: requires p != null unless n == 0
        int f(T *p, unsigned n) {
            int s = 0;
            for (unsigned i = 0; i < n; i++) s += sink(p->x);
            return s;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRuleTest, PartialGuard_NoContract_RealDerefStillWarns) {
    // Control: WITHOUT the contract the same partial guard leaves a
    // genuine null deref on the n==0 path — the drop is scoped to a
    // seeded/established NonNull, it does not blanket-silence compound
    // guards.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        T *get();
        int f(unsigned n) {
            T *p = get();
            if (!p && n > 0) return -1;
            return p->x;
        }
    )");
    ASSERT_GE(results.size(), 1u);
}

TEST(ContractRoundCTest, CallSite_NullLiteral_IsError) {
    // The caller has no pointer variables of its own — the contract
    // call alone must wake the dataflow pass.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd: requires p != null
        int f(int *p);
        int g() { return f(nullptr); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_NE(results[0].message.find("p != null"), std::string::npos);
}

TEST(ContractRoundCTest, CallSite_MaybeNullVar_IsWarning) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd: requires p != null
        int f(int *p);
        int *mk();
        int g(int c) {
            int *q = nullptr;
            if (c) q = mk();
            return f(q);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ContractRoundCTest, CallSite_GuardedVar_Silent) {
    // The caller honors the contract: q is checked before the call.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd: requires p != null
        int f(int *p);
        int *mk();
        int g() {
            int *q = mk();
            if (!q) return -1;
            return f(q);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRoundCTest, CallSite_MachineProposed_IsWarning) {
    // zd:ai contracts never produce errors — a machine guess must not
    // block a build.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd:ai requires p != null
        int f(int *p);
        int g() { return f(nullptr); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ContractRoundCTest, RelationalEscape_Satisfied_Silent) {
    // `p != null || n <= 0`: a literal escape argument that holds
    // releases the pointer — null is allowed on this call.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd: requires p != null || n <= 0
        int f(int *p, int n);
        int g() { return f(nullptr, 0); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRoundCTest, RelationalEscape_Violated_IsError) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd: requires p != null || n <= 0
        int f(int *p, int n);
        int g() { return f(nullptr, 5); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(ContractRoundCTest, RelationalEscape_CalleeSplitSeed_NoNoise) {
    // Callee side of the relational form: the escape disjunct leaves p
    // free, the pinned disjunct makes it NonNull; the guarded
    // dereference stays silent.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd: requires p != null || n <= 0
        int f(int *p, int n) {
            if (n > 0) return *p;
            return 0;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRoundCTest, RequiresNonZero_ZeroLiteral_IsError) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        // zd: requires n != 0
        int divide(int a, int n);
        int g() { return divide(10, 0); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_NE(results[0].message.find("n != 0"), std::string::npos);
}

TEST(ContractRoundCTest, RequiresNonZero_TrackedZeroVar_IsError) {
    // z is not a divisor anywhere in g — only the contract call makes
    // it tracked.
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        // zd: requires n != 0
        int divide(int a, int n);
        int g() { int z = 0; return divide(10, z); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(ContractRoundCTest, RequiresNonZero_MaybeZeroVar_IsWarning) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        // zd: requires n != 0
        int divide(int a, int n);
        int g(int c) {
            int z = 0;
            if (c) z = 4;
            return divide(10, z);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ContractRoundCTest, RequiresNonZero_GuardedVar_Silent) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        // zd: requires n != 0
        int divide(int a, int n);
        int g(int z) {
            if (z == 0) return -1;
            return divide(10, z);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRoundCTest, RequiresNonZero_CalleeSeeded_NoNoise) {
    DivByZeroRule rule;
    auto results = runRule(rule, R"(
        // zd: requires n != 0
        int divide(int a, int n) { return a / n; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

// --- Round D: guarded ensures + ownership effects + traces ---
// `ensures return != null if <g>` is checked per disjunct at every
// return: paths that REFUTE the guard are exempt, a path that PROVES
// it and returns null is a violation. owns/borrows are checked
// against the inferred parameter effects.

TEST(ContractRoundDTest, GuardedEnsures_ViolatedOnGuardTruePath_IsError) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd: ensures return != null if n != 0
        int *lookup(int n) {
            static int g;
            if (n != 0) return 0;   // exactly the promised case
            return &g;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_NE(results[0].message.find("if n != 0"), std::string::npos);
}

TEST(ContractRoundDTest, GuardedEnsures_NullOnGuardFalsePath_Silent) {
    // The guard-refuting path is exactly what the guard licenses.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd: ensures return != null if n != 0
        int *lookup(int n) {
            static int g;
            if (n == 0) return 0;   // licensed: guard is false here
            return &g;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRoundDTest, GuardedEnsures_NullUnderUndecidedGuard_IsWarning) {
    // No branch ever decides n: the null return MAY fall under the
    // guard — evidence is partial, so a warning, not an error.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd: ensures return != null if n != 0
        int *lookup(int n) { return 0; }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ContractRoundDTest, GuardedEnsures_MachineProposed_IsWarning) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd:ai ensures return != null if n != 0
        int *lookup(int n) {
            static int g;
            if (n != 0) return 0;
            return &g;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ContractRoundDTest, GuardedEnsures_ViolatingVarReturn_HasTrace) {
    // The violation carries the "why null" trace (which assignment).
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd: ensures return != null if n != 0
        int *lookup(int n) {
            int *r = 0;
            if (n != 0) return r;
            static int g;
            return &g;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_FALSE(results[0].notes.empty());
}

TEST(ContractRoundDTest, GuardedEnsures_EnforcedLine_NotUnverified) {
    // ContractRule no longer reports the enforced guarded clause.
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd: ensures return != null if n != 0
        int *lookup(int n) {
            static int g;
            if (n != 0) return 0;
            return &g;
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRoundDTest, GuardedEnsures_UnkeyableGuard_StaysUnverified) {
    // The guard parameter is address-taken (unkeyable): NullDeref
    // cannot enforce, so ContractRule must keep reporting — the
    // keyability decision is shared, a silent hole cannot open.
    ContractRule rule;
    auto results = runRule(rule, R"(
        void touch(int *p);
        // zd: ensures return != null if n != 0
        int *lookup(int n) {
            touch(&n);
            static int g;
            if (n != 0) return 0;
            return &g;
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract-unsupported");
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(ContractRoundDTest, Borrows_CalleeFrees_IsError) {
    // Declared borrowed, provably freed: the caller's ownership is
    // broken (double-free shape).
    ContractRule rule;
    auto results = runRule(rule, R"(
        void free(void *);
        // zd: borrows(buf)
        void use(char *buf) { free(buf); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_NE(results[0].message.find("borrows(buf)"), std::string::npos);
}

TEST(ContractRoundDTest, Borrows_ReadOnlyBody_Silent) {
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd: borrows(buf)
        int use(const char *buf) { return buf[0]; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRoundDTest, Owns_ReadOnlyBody_IsError) {
    // Ownership claimed, parameter provably only read: the handoff
    // leaks — the claim is false.
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd: owns(cfg)
        int consume(char *cfg) { return cfg[0]; }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(ContractRoundDTest, Owns_CalleeFrees_Silent) {
    ContractRule rule;
    auto results = runRule(rule, R"(
        void free(void *);
        // zd: owns(cfg)
        void consume(char *cfg) { free(cfg); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(ContractRoundDTest, Owns_UnknownParamName_IsContractSyntax) {
    ContractRule rule;
    auto results = runRule(rule, R"(
        // zd: owns(config)
        int consume(char *cfg) { return cfg[0]; }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract-syntax");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(ContractRoundDTest, CallSiteViolation_HasTrace) {
    // Round C's caller-side finding now carries the "why null" trace.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        // zd: requires p != null
        int f(int *p);
        int g() {
            int *q = 0;
            return f(q);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_FALSE(results[0].notes.empty());
}

// --- Round E: policies + sidecar files ---
// Policies are AST-level pattern prohibitions under the shared zd:
// surface; v1 ships no-absolute-paths (the founding Ruledsl release
// incident). Sidecars (.zdc) carry contracts for code you cannot
// annotate — every entry explicitly anchored to a function name.

TEST(PolicyTest, AbsolutePathHeuristic) {
    EXPECT_TRUE(looksLikeAbsolutePath("/etc/app.conf"));
    EXPECT_TRUE(looksLikeAbsolutePath("/home/user/rules.dsl"));
    EXPECT_TRUE(looksLikeAbsolutePath("C:\\Users\\x\\cfg.ini"));
    EXPECT_FALSE(looksLikeAbsolutePath("/"));
    EXPECT_FALSE(looksLikeAbsolutePath("/tmp"));           // one segment
    EXPECT_FALSE(looksLikeAbsolutePath("config/app.conf")); // relative
    EXPECT_FALSE(looksLikeAbsolutePath("either / or that"));
    EXPECT_FALSE(looksLikeAbsolutePath("http://x/y"));
}

TEST(PolicyRuleTest, FileComment_CatchesAbsolutePath) {
    PolicyRule rule;
    auto results = runRule(rule, R"(
        // zd:policy no-absolute-paths
        const char *config_path() { return "/etc/app/config.ini"; }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "policy");
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_NE(results[0].message.find("/etc/app/config.ini"),
              std::string::npos);
}

TEST(PolicyRuleTest, NoPolicy_NoNoise) {
    PolicyRule rule;
    auto results = runRule(rule, R"(
        const char *config_path() { return "/etc/app/config.ini"; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(PolicyRuleTest, PathLikeButNotAbsolute_Silent) {
    PolicyRule rule;
    auto results = runRule(rule, R"(
        // zd:policy no-absolute-paths
        const char *a() { return "config/app.ini"; }
        const char *b() { return "/"; }
        const char *c() { return "use / to divide"; }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(PolicyRuleTest, UnknownPolicyName_IsContractSyntax) {
    // A policy that silently fails to activate would be a false
    // comfort — unknown names are errors.
    PolicyRule rule;
    auto results = runRule(rule, R"(
        // zd:policy no-such-policy
        int f() { return 0; }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract-syntax");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(PolicyRuleTest, ProfilePolicy_ActsProjectWide) {
    setProfilePolicies({"no-absolute-paths"});
    PolicyRule rule;
    auto results = runRule(rule, R"(
        const char *config_path() { return "/etc/app/config.ini"; }
    )");
    setProfilePolicies({});
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "policy");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(PolicyRuleTest, MachineProposedActivation_IsWarning) {
    PolicyRule rule;
    auto results = runRule(rule, R"(
        // zd:ai policy no-absolute-paths
        const char *config_path() { return "/etc/app/config.ini"; }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(SidecarTest, ParseText_EntriesAndIssues) {
    std::vector<SidecarEntry> entries;
    std::vector<ContractSyntaxIssue> issues;
    parseSidecarText(
        "# comment line\n"
        "\n"
        "find_config: ensures return != null\n"
        "push_back/2: borrows(item)\n"
        "a prose line without anchor\n",
        entries, issues);
    ASSERT_EQ(entries.size(), 2u);
    EXPECT_EQ(entries[0].anchor, "find_config");
    EXPECT_EQ(entries[0].line, 3u);
    EXPECT_EQ(entries[1].anchor, "push_back/2");
    ASSERT_EQ(issues.size(), 1u);
    EXPECT_EQ(issues[0].line, 5u);
}

namespace {
// Writes a sidecar next to the virtual source name and returns the
// pair of paths. Unique names per test — the suite also runs as
// parallel ctest processes.
std::string writeSidecar(const std::string& srcName,
                         const std::string& content) {
    const std::string src = ::testing::TempDir() + srcName;
    std::ofstream(src + ".zdc") << content;
    return src;
}
} // namespace

TEST(SidecarTest, RequiresFromSidecar_CallSiteViolation) {
    NullDerefRule rule;
    const std::string src = writeSidecar(
        "zd_sc_req.cc", "f: requires p != null\n");
    auto results = runRule(rule, R"(
        int f(int *p);
        int g() { return f(nullptr); }
    )", src);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(SidecarTest, EnsuresFromSidecar_ViolationPointsAtZdcFile) {
    ContractRule rule;
    const std::string src = writeSidecar(
        "zd_sc_ens.cc", "find: ensures return != null\n");
    auto results = runRule(rule, R"(
        int *find(int c) {
            if (c) return nullptr;
            static int g;
            return &g;
        }
    )", src);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_NE(results[0].file.find(".zdc"), std::string::npos);
    EXPECT_EQ(results[0].line, 1u);
}

TEST(SidecarTest, ArityAnchor_Binds) {
    NullDerefRule rule;
    const std::string src = writeSidecar(
        "zd_sc_arity.cc", "f/2: requires p != null\n");
    auto results = runRule(rule, R"(
        int f(int *p, int n);
        int g() { return f(nullptr, 3); }
    )", src);
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
}

TEST(SidecarTest, MalformedLines_AreContractSyntaxErrors) {
    ContractRule rule;
    const std::string src = writeSidecar(
        "zd_sc_bad.cc",
        "prose without an anchor\n"
        "find: ensure return != null\n");  // typo'd clause
    auto results = runRule(rule, R"(
        int *find(int c) {
            if (c) return nullptr;
            static int g;
            return &g;
        }
    )", src);
    ASSERT_EQ(results.size(), 2u);
    EXPECT_EQ(results[0].rule_id, "contract-syntax");
    EXPECT_EQ(results[1].rule_id, "contract-syntax");
    for (const auto& r : results)
        EXPECT_NE(r.file.find(".zdc"), std::string::npos);
}

TEST(SidecarTest, NoSidecarFile_NoEffect) {
    ContractRule rule;
    auto results = runRule(rule, R"(
        int *find(int c) {
            if (c) return nullptr;
            static int g;
            return &g;
        }
    )", ::testing::TempDir() + "zd_sc_none.cc");
    EXPECT_EQ(results.size(), 0u);
}

// --- Guard-as-contract (#89, §4.A v1) ---
//
// The callee's OWN entry guard is lifted into a caller-side check.
// Severity by consequence class (user decision, 2026-07-17): an
// assert vanishes in NDEBUG builds, so a definite violation CRASHES
// there -> error; an if-return guard always runs and the callee just
// refuses -> warning. v1 reports definite violations only.

TEST(GuardContractTest, AssertGuard_NullLiteral_IsError) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        extern "C" void __assert_fail(const char*, const char*,
                                      unsigned, const char*)
            __attribute__((noreturn));
        struct T { int x; };
        int callee(T *p) {
            (p != nullptr) ? void(0)
                           : __assert_fail("p", "f.cpp", 1, "callee");
            return p->x;
        }
        int caller() { return callee(nullptr); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_NE(results[0].message.find("crash"), std::string::npos);
}

TEST(GuardContractTest, CheckMacroShape_IdentityWrapper_IsError) {
    // The CARBON_CHECK expansion: `CheckCondition(true && (cond)) ?
    // void(0) : CheckFail(...)`. CheckCondition is an exact identity
    // (`return condition;`) and `true &&` only forces bool conversion
    // — both must peel so the guard reads as `assert(n != nullptr)`.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        constexpr bool check_cond(bool condition) { return condition; }
        [[noreturn]] void check_fail();
        int callee(T *p) {
            check_cond(true && (p != nullptr)) ? void(0) : check_fail();
            return p->x;
        }
        int caller() { return callee(nullptr); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(GuardContractTest, CheckMacroShape_NonIdentityWrapper_StaysOpaque) {
    // A wrapper that TRANSFORMS its argument is not an identity —
    // peeling it would misread the guard. Must stay opaque (no
    // contract, no report).
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        constexpr bool inverted(bool condition) { return !condition; }
        [[noreturn]] void check_fail();
        int callee(T *p) {
            inverted(p != nullptr) ? void(0) : check_fail();
            return p->x;
        }
        int caller() { return callee(nullptr); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(GuardContractTest, CheckMacroShape_VariableConjunct_StillBails) {
    // Peeling strips only a LITERAL true conjunct. `flag && !p` keeps
    // the compound-condition bail: half-reading it would fabricate an
    // unconditional requires.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        extern void log_fail(const char *);
        bool flag();
        int callee(T *p) {
            if (flag() && !p) {
                log_fail("callee: p is null");
                return -1;
            }
            return p->x;
        }
        int caller() { return callee(nullptr); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(GuardContractTest, TransitiveNoreturn_BodyNeverReturns_IsError) {
    // Carbon's CheckFail is `[[noreturn]]` only #ifdef NDEBUG — but in
    // every build its body is a single call to an unconditionally
    // noreturn function. A visible body whose exit provably aborts
    // makes the call noreturn, attribute or not.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        [[noreturn]] void fail_impl(const char *);
        void check_fail() { fail_impl("check"); }
        int callee(T *p) {
            (p != nullptr) ? void(0) : check_fail();
            return p->x;
        }
        int caller() { return callee(nullptr); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Error);
}

TEST(GuardContractTest, TransitiveNoreturn_BodyReturns_NotAGuard) {
    // The false arm calls a function that RETURNS: the "guard" falls
    // through — no contract may be inferred from it.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        void just_logs(const char *);
        void soft_fail() { just_logs("check"); }
        int callee(T *p) {
            (p != nullptr) ? void(0) : soft_fail();
            return p ? p->x : 0;
        }
        int caller() { return callee(nullptr); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(GuardContractTest, SameLine_DifferentCallees_BothReported) {
    // The dedup key must include the CALLEE: two same-line calls to
    // different guarded functions are two violations.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        [[noreturn]] void die();
        int f(T *p) { (p != nullptr) ? void(0) : die(); return p->x; }
        int g(T *p) { (p != nullptr) ? void(0) : die(); return p->x; }
        int caller() { return f(nullptr) + g(nullptr); }
    )");
    EXPECT_EQ(results.size(), 2u);
}

TEST(GuardContractTest, ComplainThenReturnGuard_NullLiteral_IsWarning) {
    // The ERR_FAIL shape: the guard COMPLAINS (error-report call) and
    // then returns — the author marked null a caller bug.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        extern void log_fail(const char *);
        int callee(T *p) {
            if (!p) {
                log_fail("callee: p is null");
                return -1;
            }
            return p->x;
        }
        int caller() { return callee(nullptr); }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].rule_id, "contract");
    EXPECT_EQ(results[0].severity, Severity::Warning);
    EXPECT_NE(results[0].message.find("refuse"), std::string::npos);
}

TEST(GuardContractTest, SilentReturnGuard_NullTolerantApi_NotAContract) {
    // The cJSON lesson: `if (item == NULL) return false;` is a
    // null-TOLERANT API (null has a defined answer) — callers pass
    // null deliberately. A silent early return is NOT a contract.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        bool is_valid(T *p) {
            if (!p) {
                return false;
            }
            return p->x != 0;
        }
        bool caller() { return is_valid(nullptr); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(GuardContractTest, WorkThenReturnGuard_NotAContract) {
    // The cJSON_InitHooks shape: the null branch DOES the function's
    // work (reset to defaults) and returns — null means "use
    // defaults", a documented feature, not a refusal. Assignments are
    // not a complaint.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct Hooks { int mode; };
        int g_mode;
        void init_hooks(Hooks *h) {
            if (!h) {
                g_mode = 0;
                return;
            }
            g_mode = h->mode;
        }
        void caller() { init_hooks(nullptr); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(GuardContractTest, DefinitelyNullVariable_Reported) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        extern void log_fail(const char *);
        int callee(T *p) {
            if (!p) {
                log_fail("callee: p is null");
                return -1;
            }
            return p->x;
        }
        int caller() {
            T *q = nullptr;
            return callee(q);
        }
    )");
    ASSERT_EQ(results.size(), 1u);
    EXPECT_EQ(results[0].severity, Severity::Warning);
}

TEST(GuardContractTest, MaybeNull_NotReported_V1DefiniteOnly) {
    // v1 is the zero-noise slice: a possibly-null argument stays
    // silent (the compiler-silent DEFINITE cases are the point).
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        extern T *mk();
        extern void log_fail(const char *);
        int callee(T *p) {
            if (!p) {
                log_fail("callee: p is null");
                return -1;
            }
            return p->x;
        }
        int caller(int c) {
            T *q = c ? mk() : nullptr;
            return callee(q);
        }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(GuardContractTest, CompoundGuard_SkippedInV1) {
    // `if (!p && n > 0) return;` does NOT enforce unconditional
    // non-null (p==null with n==0 passes) — v1 must not fabricate a
    // requires from half of a conjunction.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        extern void log_fail(const char *);
        int callee(T *p, unsigned n) {
            if (!p && n > 0) {
                log_fail("callee: p is null");
                return -1;
            }
            int s = 0;
            for (unsigned i = 0; i < n; i++) s += p->x;
            return s;
        }
        int caller() { return callee(nullptr, 0); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(GuardContractTest, GuardAfterWork_NotAnEntryGuard) {
    // A guard below real work is not an ENTRY precondition — the
    // leading-statement scan must stop before it.
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        extern void log_call();
        extern void log_fail(const char *);
        int callee(T *p) {
            log_call();
            if (!p) {
                log_fail("callee: p is null");
                return -1;
            }
            return p->x;
        }
        int caller() { return callee(nullptr); }
    )");
    EXPECT_EQ(results.size(), 0u);
}

TEST(GuardContractTest, DeclaredContractOwnsTheParam_NoDoubleReport) {
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        extern void log_fail(const char *);
        // zd: requires p != null
        int callee(T *p) {
            if (!p) {
                log_fail("callee: p is null");
                return -1;
            }
            return p->x;
        }
        int caller() { return callee(nullptr); }
    )");
    ASSERT_EQ(results.size(), 1u);
    // The author's declared clause reports (error), not the inferred
    // guard warning.
    EXPECT_EQ(results[0].severity, Severity::Error);
    EXPECT_NE(results[0].message.find("requires p != null"),
              std::string::npos);
}

TEST(GuardContractTest, CallerWithNoPointerLocals_StillChecked) {
    // The dataflow pass must wake for a caller whose ONLY sin is the
    // literal argument (no pointer locals of its own).
    NullDerefRule rule;
    auto results = runRule(rule, R"(
        struct T { int x; };
        extern void log_fail(const char *);
        int callee(T *p) {
            if (!p) {
                log_fail("callee: p is null");
                return -1;
            }
            return p->x;
        }
        void caller() { callee(nullptr); }
    )");
    ASSERT_EQ(results.size(), 1u);
}
