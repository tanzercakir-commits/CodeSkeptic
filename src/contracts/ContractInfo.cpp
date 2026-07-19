#include "contracts/ContractInfo.h"

#include "contracts/Sidecar.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RawCommentList.h>
#include <clang/Basic/SourceManager.h>

#include <optional>

using namespace clang;

namespace codeskeptic {

ParsedContracts contractsForDecl(const FunctionDecl* func, ASTContext& ctx,
                                 unsigned* commentLine,
                                 std::string* commentFile) {
    if (commentLine) *commentLine = 0;
    if (commentFile) commentFile->clear();
    if (!func) return {};

    const RawComment* comment = ctx.getRawCommentForDeclNoCache(func);
    if (!comment) return {};

    const SourceManager& sm = ctx.getSourceManager();
    const std::string text = comment->getRawText(sm).str();
    if (text.find("cs:") == std::string::npos) return {};

    if (commentLine)
        *commentLine = sm.getSpellingLineNumber(comment->getBeginLoc());
    if (commentFile)
        *commentFile =
            sm.getFilename(sm.getExpansionLoc(comment->getBeginLoc())).str();
    return parseContractComment(text);
}

ParsedContracts allContractClausesForDecl(const FunctionDecl* func,
                                          ASTContext& ctx) {
    ParsedContracts merged = contractsForDecl(func, ctx);
    ParsedContracts sidecar = sidecarContractsForDecl(func, ctx);
    for (auto& clause : sidecar.clauses)
        merged.clauses.push_back(std::move(clause));
    // Sidecar syntax errors are ContractRule's to report (with the
    // .csk file attached) — enforcement only reads clauses.
    return merged;
}

namespace {

std::optional<unsigned> paramIndexByName(const FunctionDecl* func,
                                         const std::string& name) {
    for (unsigned i = 0; i < func->getNumParams(); ++i) {
        const ParmVarDecl* p = func->getParamDecl(i);
        if (p && p->getName() == name) return i;
    }
    return std::nullopt;
}

// Cmp(Param NE Null) — the simple non-null form.
bool isParamNeNull(const ContractPred& p, std::string* name) {
    if (p.kind != ContractPred::Cmp || p.op != ContractCmpOp::NE)
        return false;
    if (p.lhs.kind == ContractOperandKind::Param &&
        p.rhs.kind == ContractOperandKind::Null) {
        *name = p.lhs.param;
        return true;
    }
    if (p.rhs.kind == ContractOperandKind::Param &&
        p.lhs.kind == ContractOperandKind::Null) {
        *name = p.rhs.param;
        return true;
    }
    return false;
}

// Cmp(Param REL IntLit) — a keyable escape condition.
bool isParamVsInt(const ContractPred& p, std::string* name,
                  ContractCmpOp* op, long long* lit) {
    if (p.kind != ContractPred::Cmp) return false;
    if (p.lhs.kind == ContractOperandKind::Param &&
        p.rhs.kind == ContractOperandKind::IntLit) {
        *name = p.lhs.param;
        *op = p.op;
        *lit = p.rhs.value;
        return true;
    }
    return false;
}

} // anonymous namespace

bool isNullPointerArg(const Expr* arg) {
    if (!arg) return false;
    arg = arg->IgnoreParenCasts();
    if (isa<CXXNullPtrLiteralExpr>(arg) || isa<GNUNullExpr>(arg))
        return true;
    if (const auto* lit = dyn_cast<IntegerLiteral>(arg))
        return lit->getValue() == 0;
    return false;
}

std::optional<long long> intLiteralArg(const Expr* arg) {
    if (!arg) return std::nullopt;
    arg = arg->IgnoreParenImpCasts();
    if (const auto* lit = dyn_cast<IntegerLiteral>(arg)) {
        if (lit->getValue().getSignificantBits() > 64) return std::nullopt;
        return lit->getValue().getSExtValue();
    }
    if (const auto* unary = dyn_cast<UnaryOperator>(arg)) {
        if (unary->getOpcode() == UO_Minus)
            if (auto v = intLiteralArg(unary->getSubExpr())) return -*v;
    }
    return std::nullopt;
}

bool evalCmp(long long value, ContractCmpOp op, long long literal) {
    switch (op) {
        case ContractCmpOp::EQ: return value == literal;
        case ContractCmpOp::NE: return value != literal;
        case ContractCmpOp::LT: return value < literal;
        case ContractCmpOp::LE: return value <= literal;
        case ContractCmpOp::GT: return value > literal;
        case ContractCmpOp::GE: return value >= literal;
    }
    return false;
}

BinaryOperatorKind toBinaryOp(ContractCmpOp op) {
    switch (op) {
        case ContractCmpOp::EQ: return BO_EQ;
        case ContractCmpOp::NE: return BO_NE;
        case ContractCmpOp::LT: return BO_LT;
        case ContractCmpOp::LE: return BO_LE;
        case ContractCmpOp::GT: return BO_GT;
        case ContractCmpOp::GE: return BO_GE;
    }
    return BO_EQ;
}

GuardedEnsuresAnalysis analyzeNullEnsuresGuards(
    const ParsedContracts& parsed, const clang::FunctionDecl* func) {
    GuardedEnsuresAnalysis out;
    if (!func || !func->getReturnType()->isPointerType()) return out;

    // Computed lazily — most functions carry no guarded clauses.
    std::optional<std::set<const ValueDecl*>> unkeyable;

    for (const auto& clause : parsed.clauses) {
        if (clause.kind != ContractClauseKind::Ensures || !clause.hasGuard)
            continue;
        // Pred: return != null (the only per-disjunct form in v1).
        const ContractPred& p = clause.pred;
        if (p.kind != ContractPred::Cmp || p.op != ContractCmpOp::NE ||
            p.lhs.kind != ContractOperandKind::Return ||
            p.rhs.kind != ContractOperandKind::Null)
            continue;
        // Guard: single param-vs-int-literal comparison.
        std::string guardName;
        ContractCmpOp guardOp;
        long long guardLit;
        if (!isParamVsInt(clause.guard, &guardName, &guardOp, &guardLit))
            continue;
        auto idx = paramIndexByName(func, guardName);
        if (!idx) continue;  // reported via ensures? keep unverified
        const ParmVarDecl* guardParam = func->getParamDecl(*idx);

        if (!unkeyable) unkeyable = collectUnkeyableDecls(func);
        if (unkeyable->count(guardParam)) continue;  // stays unverified

        auto fact = compareFact(guardParam, toBinaryOp(guardOp), guardLit);
        if (!fact) continue;  // e.g. unsigned u < 0: no information

        GuardedEnsuresInfo info;
        info.guardKey = fact->first;
        info.guardWanted = fact->second;
        info.machineProposed = clause.machineProposed;
        info.text = clause.text;
        info.line = clause.line;
        out.enforced.push_back(info);
        out.enforcedLines.insert(clause.line);
    }
    return out;
}

RequiresAnalysis analyzeRequires(const ParsedContracts& parsed,
                                 const FunctionDecl* func) {
    RequiresAnalysis out;
    if (!func) return out;

    for (const auto& clause : parsed.clauses) {
        if (clause.kind != ContractClauseKind::Requires) continue;

        std::string ptrName;
        // Simple: requires p != null
        if (isParamNeNull(clause.pred, &ptrName)) {
            auto idx = paramIndexByName(func, ptrName);
            if (!idx) {
                out.unknownParams.push_back({clause.line, clause.text});
                continue;
            }
            RequiresInfo info;
            info.kind = RequiresInfo::Kind::NonNullParam;
            info.paramIndex = *idx;
            info.machineProposed = clause.machineProposed;
            info.text = clause.text;
            info.line = clause.line;
            out.enforced.push_back(info);
            out.enforcedLines.insert(clause.line);
            continue;
        }

        // Simple: requires n != 0
        {
            std::string intName;
            ContractCmpOp op;
            long long lit;
            if (isParamVsInt(clause.pred, &intName, &op, &lit) &&
                op == ContractCmpOp::NE && lit == 0) {
                auto idx = paramIndexByName(func, intName);
                if (!idx) {
                    out.unknownParams.push_back({clause.line, clause.text});
                    continue;
                }
                if (func->getParamDecl(*idx)->getType()->isIntegerType()) {
                    RequiresInfo info;
                    info.kind = RequiresInfo::Kind::NonZeroParam;
                    info.paramIndex = *idx;
                    info.machineProposed = clause.machineProposed;
                    info.text = clause.text;
                    info.line = clause.line;
                    out.enforced.push_back(info);
                    out.enforcedLines.insert(clause.line);
                    continue;
                }
            }
        }

        // Relational: requires p != null || <n REL lit>  (either order)
        if (clause.pred.kind == ContractPred::Or &&
            clause.pred.children.size() == 2) {
            std::string condName;
            ContractCmpOp condOp;
            long long condLit;
            const ContractPred* ptrSide = nullptr;
            const ContractPred* condSide = nullptr;
            for (int i = 0; i < 2; ++i) {
                const auto& a = clause.pred.children[i];
                const auto& b = clause.pred.children[1 - i];
                std::string n;
                if (isParamNeNull(a, &n) &&
                    isParamVsInt(b, &condName, &condOp, &condLit)) {
                    ptrName = n;
                    ptrSide = &a;
                    condSide = &b;
                    break;
                }
            }
            if (ptrSide && condSide) {
                auto pIdx = paramIndexByName(func, ptrName);
                auto cIdx = paramIndexByName(func, condName);
                if (!pIdx || !cIdx) {
                    out.unknownParams.push_back({clause.line, clause.text});
                    continue;
                }
                RequiresInfo info;
                info.kind = RequiresInfo::Kind::NonNullUnlessCond;
                info.paramIndex = *pIdx;
                info.condParamIndex = *cIdx;
                info.condOp = condOp;
                info.condLiteral = condLit;
                info.machineProposed = clause.machineProposed;
                info.text = clause.text;
                info.line = clause.line;
                out.enforced.push_back(info);
                out.enforcedLines.insert(clause.line);
                continue;
            }
        }
        // Anything else stays unenforced — ContractRule reports it.
    }
    return out;
}

} // namespace codeskeptic
