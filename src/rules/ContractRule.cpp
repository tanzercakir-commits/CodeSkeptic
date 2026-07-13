#include "rules/ContractRule.h"

#include "contracts/ContractInfo.h"
#include "contracts/ContractParser.h"
#include "core/Messages.h"
#include "engine/FunctionSummary.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Basic/SourceManager.h>

using namespace clang;
using namespace clang::ast_matchers;

namespace zerodefect {

namespace {

// Round-B classification of one clause.
enum class ClauseStatus {
    Satisfied,
    Violated,
    Unverified,   // in the v1 spec, not yet checked by the engine
    Unsupported,  // outside what the engine will be able to key
};

bool isReturnVsNull(const ContractPred& p) {
    return p.kind == ContractPred::Cmp &&
           p.lhs.kind == ContractOperandKind::Return &&
           p.rhs.kind == ContractOperandKind::Null;
}

bool isReturnVsInt(const ContractPred& p, long long value) {
    return p.kind == ContractPred::Cmp &&
           p.lhs.kind == ContractOperandKind::Return &&
           p.rhs.kind == ContractOperandKind::IntLit &&
           p.rhs.value == value;
}

// Both sides parameters: relational reasoning between variables —
// outside the fact machinery's domain even at spec completion.
bool isParamVsParam(const ContractPred& p) {
    return p.kind == ContractPred::Cmp &&
           p.lhs.kind == ContractOperandKind::Param &&
           p.rhs.kind == ContractOperandKind::Param;
}

bool containsParamVsParam(const ContractPred& p) {
    if (isParamVsParam(p)) return true;
    for (const auto& c : p.children)
        if (containsParamVsParam(c)) return true;
    return false;
}

ClauseStatus classifyAndCheck(const ContractClause& clause,
                              const SummaryRegistry::FunctionSummary* summary) {
    using RN = SummaryRegistry::ReturnNullness;
    using RZ = SummaryRegistry::ReturnZeroness;

    if (clause.kind == ContractClauseKind::Ensures && !clause.hasGuard) {
        if (isReturnVsNull(clause.pred)) {
            if (clause.pred.op == ContractCmpOp::EQ)
                return ClauseStatus::Unverified;  // no AlwaysNull lattice point
            if (clause.pred.op != ContractCmpOp::NE)
                return ClauseStatus::Unsupported;  // ordering vs null
            if (!summary) return ClauseStatus::Unverified;
            switch (summary->returnNullness) {
                case RN::NeverNull: return ClauseStatus::Satisfied;
                case RN::MaybeNull: return ClauseStatus::Violated;
                case RN::Unknown: return ClauseStatus::Unverified;
            }
        }
        if (isReturnVsInt(clause.pred, 0)) {
            if (clause.pred.op == ContractCmpOp::EQ)
                return ClauseStatus::Unverified;  // no AlwaysZero lattice point
            if (clause.pred.op != ContractCmpOp::NE)
                return ClauseStatus::Unverified;  // orderings: later rounds
            if (!summary) return ClauseStatus::Unverified;
            switch (summary->returnZeroness) {
                case RZ::NeverZero: return ClauseStatus::Satisfied;
                case RZ::MaybeZero: return ClauseStatus::Violated;
                case RZ::Unknown: return ClauseStatus::Unverified;
            }
        }
    }

    if (containsParamVsParam(clause.pred) ||
        (clause.hasGuard && containsParamVsParam(clause.guard)))
        return ClauseStatus::Unsupported;

    // Everything else is in the v1 spec but lands in rounds C-E
    // (requires, guarded ensures, ownership effects, policies).
    return ClauseStatus::Unverified;
}

} // anonymous namespace

void ContractRule::check(ASTContext& ctx, DiagnosticList& results) {
    const SourceManager& sm = ctx.getSourceManager();

    auto matcher = functionDecl(isDefinition()).bind("func");
    for (const auto& match : match(matcher, ctx)) {
        const auto* func = match.getNodeAs<FunctionDecl>("func");
        if (!func || !func->hasBody()) continue;

        unsigned commentLine = 0;
        std::string file;
        ParsedContracts parsed = contractsForDecl(func, ctx, &commentLine,
                                                  &file);
        if (parsed.empty()) continue;

        const std::string funcName = func->getQualifiedNameAsString();

        auto makeDiag = [&](unsigned lineInBlock, const std::string& ruleId,
                            Severity sev, MsgId msgId,
                            const std::string& arg) {
            Diagnostic diag;
            diag.file = file;
            diag.line = commentLine + (lineInBlock > 0 ? lineInBlock - 1 : 0);
            diag.column = 1;
            diag.rule_id = ruleId;
            diag.severity = sev;
            diag.message = msg(msgId, arg);
            diag.function = funcName;
            results.push_back(std::move(diag));
        };

        for (const auto& err : parsed.syntaxErrors)
            makeDiag(err.line, "contract-syntax", Severity::Error,
                     MsgId::ContractSyntaxError, err.text);

        if (parsed.clauses.empty()) continue;

        // Round C: requires clauses the dataflow rules enforce
        // (NullDeref: non-null, DivByZero: non-zero). Those clauses are
        // NOT unverified — callee seeding + caller-side checks cover
        // them — so they are skipped below. A requires clause naming a
        // parameter the function does not have can never bind: that is
        // a contract error, not a later-round feature.
        const RequiresAnalysis req = analyzeRequires(parsed, func);
        for (const auto& unknown : req.unknownParams)
            makeDiag(unknown.line, "contract-syntax", Severity::Error,
                     MsgId::ContractSyntaxError, unknown.text);

        const SummaryRegistry::FunctionSummary* summary =
            SummaryRegistry::instance().lookup(func);

        for (const auto& clause : parsed.clauses) {
            if (req.enforcedLines.count(clause.line)) continue;
            bool isUnknownParam = false;
            for (const auto& unknown : req.unknownParams)
                if (unknown.line == clause.line) isUnknownParam = true;
            if (isUnknownParam) continue;
            switch (classifyAndCheck(clause, summary)) {
                case ClauseStatus::Satisfied:
                    break;
                case ClauseStatus::Violated:
                    makeDiag(clause.line, "contract",
                             clause.machineProposed ? Severity::Warning
                                                    : Severity::Error,
                             MsgId::ContractViolated, clause.text);
                    break;
                case ClauseStatus::Unverified:
                    makeDiag(clause.line, "contract-unsupported",
                             Severity::Warning, MsgId::ContractUnverified,
                             clause.text);
                    break;
                case ClauseStatus::Unsupported:
                    makeDiag(clause.line, "contract-unsupported",
                             Severity::Warning, MsgId::ContractUnsupported,
                             clause.text);
                    break;
            }
        }
    }
}

} // namespace zerodefect
