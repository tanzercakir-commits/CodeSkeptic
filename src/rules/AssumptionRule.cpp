#include "rules/AssumptionRule.h"

#include "contracts/ContractInfo.h"
#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/AssumptionMode.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Basic/SourceManager.h>

#include <set>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

const ParmVarDecl* asParam(const Expr* e) {
    if (!e) return nullptr;
    e = e->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(e))
        return dyn_cast<ParmVarDecl>(ref->getDecl());
    return nullptr;
}

// Splits a function body's parameter uses into two sets: parameters that
// are DEREFERENCED (*p, p->m, p[i]) and parameters that are CHECKED
// (appear in any branch/loop condition, a null/equality comparison, or a
// logical-not). "Checked" is deliberately over-approximated — a
// parameter guarded even indirectly is suppressed — so the report leans
// toward precision.
struct ParamUsageVisitor : RecursiveASTVisitor<ParamUsageVisitor> {
    std::set<const ParmVarDecl*> deref;
    std::set<const ParmVarDecl*> checked;

    void checkAllRefsIn(const Stmt* s) {
        if (!s) return;
        struct RefV : RecursiveASTVisitor<RefV> {
            std::set<const ParmVarDecl*>* out;
            bool VisitDeclRefExpr(DeclRefExpr* r) {
                if (auto* p = dyn_cast<ParmVarDecl>(r->getDecl()))
                    out->insert(p);
                return true;
            }
        } rv;
        rv.out = &checked;
        rv.TraverseStmt(const_cast<Stmt*>(s));
    }

    bool VisitUnaryOperator(UnaryOperator* u) {
        if (u->getOpcode() == UO_Deref)
            if (const auto* p = asParam(u->getSubExpr())) deref.insert(p);
        if (u->getOpcode() == UO_LNot)
            if (const auto* p = asParam(u->getSubExpr())) checked.insert(p);
        return true;
    }
    bool VisitMemberExpr(MemberExpr* m) {
        if (m->isArrow())
            if (const auto* p = asParam(m->getBase())) deref.insert(p);
        return true;
    }
    bool VisitArraySubscriptExpr(ArraySubscriptExpr* s) {
        if (const auto* p = asParam(s->getBase())) deref.insert(p);
        return true;
    }
    bool VisitBinaryOperator(BinaryOperator* b) {
        if (b->getOpcode() == BO_EQ || b->getOpcode() == BO_NE) {
            if (const auto* p = asParam(b->getLHS())) checked.insert(p);
            if (const auto* p = asParam(b->getRHS())) checked.insert(p);
        }
        return true;
    }
    // Any parameter referenced inside a condition is guarded.
    bool VisitIfStmt(IfStmt* s) { checkAllRefsIn(s->getCond()); return true; }
    bool VisitWhileStmt(WhileStmt* s) { checkAllRefsIn(s->getCond()); return true; }
    bool VisitForStmt(ForStmt* s) { checkAllRefsIn(s->getCond()); return true; }
    bool VisitDoStmt(DoStmt* s) { checkAllRefsIn(s->getCond()); return true; }
    bool VisitConditionalOperator(ConditionalOperator* c) {
        checkAllRefsIn(c->getCond());
        return true;
    }
};

// Parameter indices the function already declares non-null via contract
// — the "where verified?" answer, so these assumptions stay silent.
std::set<unsigned> declaredNonNullParams(const FunctionDecl* fn,
                                         ASTContext& ctx) {
    std::set<unsigned> declared;
    codeskeptic::ParsedContracts parsed =
        codeskeptic::allContractClausesForDecl(fn, ctx);
    if (parsed.clauses.empty()) return declared;
    auto req = codeskeptic::analyzeRequires(parsed, fn);
    for (const auto& info : req.enforced)
        if (info.kind == codeskeptic::RequiresInfo::Kind::NonNullParam ||
            info.kind == codeskeptic::RequiresInfo::Kind::NonNullUnlessCond)
            declared.insert(info.paramIndex);
    return declared;
}

void analyzeFunction(const FunctionDecl* fn, ASTContext& ctx,
                     codeskeptic::DiagnosticList& results) {
    if (!fn->hasBody()) return;

    ParamUsageVisitor usage;
    usage.TraverseStmt(fn->getBody());

    const std::set<unsigned> declared = declaredNonNullParams(fn, ctx);
    const SourceManager& sm = ctx.getSourceManager();

    for (unsigned i = 0; i < fn->getNumParams(); ++i) {
        const ParmVarDecl* p = fn->getParamDecl(i);
        if (!p->getType()->isPointerType()) continue;
        if (!usage.deref.count(p)) continue;     // not dereferenced — no claim
        if (usage.checked.count(p)) continue;    // guarded — assumption is met
        if (declared.count(i)) continue;         // declared — verified in contract

        SourceLocation loc = sm.getExpansionLoc(p->getLocation());
        codeskeptic::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = sm.getSpellingLineNumber(loc);
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "assumption";
        diag.function = fn->getQualifiedNameAsString();
        diag.severity = codeskeptic::Severity::Info;
        diag.message = codeskeptic::msg(
            codeskeptic::MsgId::AssumptionNonNullParam, p->getNameAsString());
        results.push_back(std::move(diag));
    }
}

class AssumptionCallback : public MatchFinder::MatchCallback {
public:
    explicit AssumptionCallback(codeskeptic::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* fn = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!fn || !fn->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(fn->getLocation())) return;
        if (!codeskeptic::functionFilterAllows(*fn)) return;
        if (!codeskeptic::lineFilterAllows(*fn, sm)) return;

        analyzeFunction(fn, *result.Context, results_);
    }

private:
    codeskeptic::DiagnosticList& results_;
};

} // anonymous namespace

namespace codeskeptic {

void AssumptionRule::check(clang::ASTContext& ctx, DiagnosticList& results) {
    // Opt-in intent-debt report: silent unless --assumptions is set.
    if (!assumptionMode()) return;

    MatchFinder finder;
    AssumptionCallback callback(results);

    auto matcher =
        functionDecl(isDefinition(), hasBody(anything())).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace codeskeptic
