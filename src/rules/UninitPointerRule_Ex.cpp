#include "rules/UninitPointerRule_Ex.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/DataflowEngine.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

#include <map>
#include <set>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// --- PtrState lattice ---

enum class PtrState { Uninit, MaybeInit, Init };

PtrState mergePtrStates(PtrState a, PtrState b) {
    if (a == b) return a;
    return PtrState::MaybeInit;
}

// --- Statement classification ---
// CFG elemanlari alt ifadeleri ayri elemanlar olarak icerir; her elemanin
// yalnizca tepe dugumune bakmak yeterli (statement icinde nested arama
// gerekmez). Dugum hangi degiskene dokundugunu kendisi soyler — degisken
// basina dongu de gerekmez.

enum class EffectKind { None, Assigns, Dereferences };

struct Effect {
    const VarDecl* var = nullptr;
    EffectKind kind = EffectKind::None;
};

const VarDecl* asVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

Effect classifyStmt(const Stmt* stmt) {
    if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
        if (binOp->getOpcode() == BO_Assign)
            if (const auto* var = asVar(binOp->getLHS()))
                return {var, EffectKind::Assigns};
        return {};
    }
    if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
        // &p: out-param ile init edilmis olabilir — muhafazakar Assigns
        if (unary->getOpcode() == UO_AddrOf)
            if (const auto* var = asVar(unary->getSubExpr()))
                return {var, EffectKind::Assigns};
        if (unary->getOpcode() == UO_Deref)
            if (const auto* var = asVar(unary->getSubExpr()))
                return {var, EffectKind::Dereferences};
        return {};
    }
    if (const auto* member = dyn_cast<MemberExpr>(stmt)) {
        if (member->isArrow())
            if (const auto* var = asVar(member->getBase()))
                return {var, EffectKind::Dereferences};
        return {};
    }
    if (const auto* subscript = dyn_cast<ArraySubscriptExpr>(stmt)) {
        if (const auto* var = asVar(subscript->getBase()))
            return {var, EffectKind::Dereferences};
        return {};
    }
    return {};
}

// --- Collect tracked pointer variables ---

std::vector<const VarDecl*> collectTrackedVars(const FunctionDecl* funcDecl,
                                                ASTContext& ctx) {
    std::set<const VarDecl*> vars;

    auto uninitPtrMatcher = varDecl(
        hasType(pointerType()),
        unless(hasInitializer(anything())),
        unless(parmVarDecl())
    ).bind("var");

    auto wrapper = functionDecl(equalsNode(funcDecl),
                                 forEachDescendant(uninitPtrMatcher));
    for (const auto& result : match(wrapper, *funcDecl, ctx)) {
        if (const auto* v = result.getNodeAs<VarDecl>("var"))
            vars.insert(v);
    }
    return {vars.begin(), vars.end()};
}

// --- Analysis struct for DataflowEngine ---

using PtrVarState = std::map<const VarDecl*, PtrState>;

class UninitPtrAnalysis {
public:
    using State = PtrVarState;

    UninitPtrAnalysis(const std::vector<const VarDecl*>& trackedVars,
                      std::string funcName,
                      zerodefect::DiagnosticList& results)
        : funcName_(std::move(funcName)), results_(results) {
        for (const auto* var : trackedVars)
            initState_[var] = PtrState::Uninit;
    }

    State initialState() const { return initState_; }

    // Degisken basina zincir: Uninit -> MaybeInit -> Init (yukseklik 2)
    unsigned latticeHeight() const {
        return static_cast<unsigned>(initState_.size()) * 2 + 1;
    }

    State merge(const State& a, const State& b) const {
        State result = a;
        for (const auto& [var, stateB] : b) {
            auto it = result.find(var);
            if (it == result.end())
                result[var] = stateB;
            else
                it->second = mergePtrStates(it->second, stateB);
        }
        return result;
    }

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext& /*ctx*/) const {
        Effect effect = classifyStmt(stmt);
        if (effect.kind != EffectKind::Assigns) return in;
        if (in.find(effect.var) == in.end()) return in;  // izlenmiyor

        State out = in;
        out[effect.var] = PtrState::Init;
        return out;
    }

    void onStatement(const Stmt* stmt, const State& before,
                     const State& /*after*/, ASTContext& ctx) {
        Effect effect = classifyStmt(stmt);
        if (effect.kind != EffectKind::Dereferences) return;

        auto it = before.find(effect.var);
        if (it == before.end() || it->second == PtrState::Init) return;

        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);

        if (reported_.emplace(effect.var, line).second) {
            zerodefect::Diagnostic diag;
            diag.severity = zerodefect::Severity::Error;
            diag.file = sm.getFilename(loc).str();
            diag.line = line;
            diag.column = sm.getSpellingColumnNumber(loc);
            diag.rule_id = "uninit-ptr";
            diag.function = funcName_;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::UninitPtrDeref,
                effect.var->getNameAsString());

            // Iz: bildirim noktasi (baslangic degeri olmayan tanim)
            SourceLocation declLoc =
                sm.getExpansionLoc(effect.var->getLocation());
            zerodefect::TraceNote note;
            note.file = sm.getFilename(declLoc).str();
            note.line = sm.getSpellingLineNumber(declLoc);
            note.column = sm.getSpellingColumnNumber(declLoc);
            note.message = zerodefect::msg(
                zerodefect::MsgId::TraceDeclaredHere,
                effect.var->getNameAsString());
            diag.notes.push_back(std::move(note));

            results_.push_back(diag);
        }
    }

private:
    std::string funcName_;
    zerodefect::DiagnosticList& results_;
    PtrVarState initState_;
    std::set<std::pair<const VarDecl*, unsigned>> reported_;
};

// --- Matcher callback ---

class FindUninitPtrCallback : public MatchFinder::MatchCallback {
public:
    explicit FindUninitPtrCallback(zerodefect::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* func = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!func || !func->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(func->getLocation())) return;
        if (!zerodefect::functionFilterAllows(*func)) return;
        if (!zerodefect::lineFilterAllows(*func, sm)) return;

        auto trackedVars = collectTrackedVars(func, *result.Context);
        if (trackedVars.empty()) return;

        UninitPtrAnalysis analysis(
            trackedVars, func->getQualifiedNameAsString(), results_);
        zerodefect::runDataflow(func, *result.Context, analysis);
    }

private:
    zerodefect::DiagnosticList& results_;
};

} // anonymous namespace

namespace zerodefect {

std::string UninitPointerRule_Ex::id() const {
    return "uninit-ptr";
}

std::string UninitPointerRule_Ex::description() const {
    return "CFG-based uninitialized pointer use analysis";
}

Severity UninitPointerRule_Ex::defaultSeverity() const {
    return Severity::Error;
}

void UninitPointerRule_Ex::check(clang::ASTContext& ctx,
                                  DiagnosticList& results) {
    MatchFinder finder;
    FindUninitPtrCallback callback(results);

    auto matcher = functionDecl(
        isDefinition(),
        hasBody(anything())
    ).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
