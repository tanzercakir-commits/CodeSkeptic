#include "rules/NullDerefRule.h"

#include "core/Messages.h"
#include "engine/DataflowEngine.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

#include <map>
#include <set>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// --- NullState lattice ---
//
// Unknown : bilgi yok (parametre, opak fonksiyon donusu)
// Null    : tum yollarda kesin null
// NonNull : tum yollarda kesin null degil
// MaybeNull: en az bir yolda null (raporlanabilir sinyal)

enum class NullState { Unknown, Null, NonNull, MaybeNull };

NullState mergeNullStates(NullState a, NullState b) {
    if (a == b) return a;
    // Herhangi bir yolda null bilgisi varsa korunur; yalnizca
    // NonNull + Unknown bilgisizlige duser (DivByZero merge'iyle ayni sekil)
    bool anyNullInfo = a == NullState::Null || a == NullState::MaybeNull ||
                       b == NullState::Null || b == NullState::MaybeNull;
    return anyNullInfo ? NullState::MaybeNull : NullState::Unknown;
}

// --- Expression null-ness evaluation ---

const VarDecl* asVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

NullState evaluateNullness(const Expr* expr) {
    if (!expr) return NullState::Unknown;
    // Acik cast'leri de soy: (int*)0, (Node*)nullptr
    expr = expr->IgnoreParenCasts();

    if (isa<CXXNullPtrLiteralExpr>(expr)) return NullState::Null;
    if (isa<GNUNullExpr>(expr)) return NullState::Null;
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr))
        return lit->getValue() == 0 ? NullState::Null : NullState::NonNull;

    if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
        if (unary->getOpcode() == UO_AddrOf) return NullState::NonNull;
    }
    if (isa<CXXNewExpr>(expr)) return NullState::NonNull;
    if (isa<StringLiteral>(expr)) return NullState::NonNull;
    if (isa<CXXThisExpr>(expr)) return NullState::NonNull;

    return NullState::Unknown;
}

// --- Statement classification ---

enum class EffectKind { None, Assign, AssignUnknown, Deref };

struct Effect {
    const VarDecl* var = nullptr;
    EffectKind kind = EffectKind::None;
    NullState value = NullState::Unknown;  // yalnizca Assign icin
};

Effect classifyStmt(const Stmt* stmt) {
    if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
        // Coklu bildirimde ilk pointer init'i alinir; kalanlar Unknown
        // baslar (muhafazakar). Nadir durum, todo'da not edildi.
        for (const auto* decl : declStmt->decls()) {
            if (const auto* vd = dyn_cast<VarDecl>(decl)) {
                if (vd->getType()->isPointerType() && vd->hasInit())
                    return {vd, EffectKind::Assign,
                            evaluateNullness(vd->getInit())};
            }
        }
        return {};
    }
    if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
        if (binOp->getOpcode() == BO_Assign)
            if (const auto* var = asVar(binOp->getLHS()))
                return {var, EffectKind::Assign,
                        evaluateNullness(binOp->getRHS())};
        return {};
    }
    if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
        // &p bir fonksiyona gidiyorsa p'ye deger atanmis olabilir
        if (unary->getOpcode() == UO_AddrOf)
            if (const auto* var = asVar(unary->getSubExpr()))
                return {var, EffectKind::AssignUnknown};
        if (unary->getOpcode() == UO_Deref)
            if (const auto* var = asVar(unary->getSubExpr()))
                return {var, EffectKind::Deref};
        return {};
    }
    if (const auto* member = dyn_cast<MemberExpr>(stmt)) {
        if (member->isArrow())
            if (const auto* var = asVar(member->getBase()))
                return {var, EffectKind::Deref};
        return {};
    }
    if (const auto* subscript = dyn_cast<ArraySubscriptExpr>(stmt)) {
        if (const auto* var = asVar(subscript->getBase()))
            return {var, EffectKind::Deref};
        return {};
    }
    return {};
}

// --- Branch condition refinement (assume edges) ---

using NullVarState = std::map<const VarDecl*, NullState>;

void setIfTracked(NullVarState& state, const VarDecl* var, NullState value) {
    if (!var) return;
    auto it = state.find(var);
    if (it != state.end()) it->second = value;
}

void applyCondition(const Expr* cond, bool isTrue, NullVarState& state) {
    if (!cond) return;
    cond = cond->IgnoreParenImpCasts();

    // if (p) / while (p): truthiness
    if (const auto* var = asVar(cond)) {
        if (var->getType()->isPointerType())
            setIfTracked(state, var,
                         isTrue ? NullState::NonNull : NullState::Null);
        return;
    }

    if (const auto* unary = dyn_cast<UnaryOperator>(cond)) {
        if (unary->getOpcode() == UO_LNot)
            applyCondition(unary->getSubExpr(), !isTrue, state);
        return;
    }

    const auto* binOp = dyn_cast<BinaryOperator>(cond);
    if (!binOp) return;

    const BinaryOperatorKind opc = binOp->getOpcode();

    if (opc == BO_LAnd) {
        if (isTrue) {
            applyCondition(binOp->getLHS(), true, state);
            applyCondition(binOp->getRHS(), true, state);
        }
        return;
    }
    if (opc == BO_LOr) {
        if (!isTrue) {
            applyCondition(binOp->getLHS(), false, state);
            applyCondition(binOp->getRHS(), false, state);
        }
        return;
    }

    if (opc != BO_EQ && opc != BO_NE) return;

    // p == nullptr / nullptr == p (NULL ve 0 dahil)
    const Expr* lhs = binOp->getLHS()->IgnoreParenImpCasts();
    const Expr* rhs = binOp->getRHS()->IgnoreParenImpCasts();
    const VarDecl* var = asVar(lhs);
    const Expr* other = rhs;
    if (!var) {
        var = asVar(rhs);
        other = lhs;
    }
    if (!var || !var->getType()->isPointerType()) return;
    if (evaluateNullness(other) != NullState::Null) return;

    // eqHolds: karsilastirmanin "esittir null" yorumu bu kenarda dogru mu
    bool eqHolds = (opc == BO_EQ) == isTrue;
    setIfTracked(state, var,
                 eqHolds ? NullState::Null : NullState::NonNull);
}

// --- Collect tracked pointer variables ---

std::vector<const VarDecl*> collectTrackedVars(const FunctionDecl* funcDecl,
                                                ASTContext& ctx) {
    std::set<const VarDecl*> vars;

    // Fonksiyonda gecen tum pointer yerel degiskenleri ve parametreler.
    // Parametreler Unknown baslar — cagiran hakkinda varsayim yapilmaz.
    auto ptrVarMatcher = varDecl(hasType(pointerType())).bind("var");
    auto wrapper = functionDecl(equalsNode(funcDecl),
                                 forEachDescendant(ptrVarMatcher));
    for (const auto& result : match(wrapper, *funcDecl, ctx)) {
        if (const auto* v = result.getNodeAs<VarDecl>("var"))
            vars.insert(v);
    }
    for (const auto* param : funcDecl->parameters()) {
        if (param->getType()->isPointerType())
            vars.insert(param);
    }
    return {vars.begin(), vars.end()};
}

// --- Analysis struct for DataflowEngine ---

class NullDerefAnalysis {
public:
    using State = NullVarState;

    NullDerefAnalysis(const std::vector<const VarDecl*>& trackedVars,
                      zerodefect::DiagnosticList& results)
        : results_(results) {
        for (const auto* var : trackedVars)
            initState_[var] = NullState::Unknown;
    }

    State initialState() const { return initState_; }

    // Degisken basina NullState zinciri en fazla 3 gecis yapar
    unsigned latticeHeight() const {
        return static_cast<unsigned>(initState_.size()) * 3 + 1;
    }

    State merge(const State& a, const State& b) const {
        State result = a;
        for (const auto& [var, stateB] : b) {
            auto it = result.find(var);
            if (it == result.end())
                result[var] = stateB;
            else if (it->second != stateB)
                it->second = mergeNullStates(it->second, stateB);
        }
        return result;
    }

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext& /*ctx*/) const {
        Effect effect = classifyStmt(stmt);
        if (effect.kind != EffectKind::Assign &&
            effect.kind != EffectKind::AssignUnknown)
            return in;
        if (in.find(effect.var) == in.end()) return in;  // izlenmiyor

        State out = in;
        out[effect.var] = (effect.kind == EffectKind::Assign)
                              ? effect.value
                              : NullState::Unknown;
        return out;
    }

    void refineOnEdge(const Stmt* cond, bool isTrueBranch, State& state,
                      ASTContext& /*ctx*/) const {
        applyCondition(dyn_cast<Expr>(cond), isTrueBranch, state);
    }

    void onStatement(const Stmt* stmt, const State& before,
                     const State& /*after*/, ASTContext& ctx) {
        Effect effect = classifyStmt(stmt);
        if (effect.kind != EffectKind::Deref) return;

        auto it = before.find(effect.var);
        if (it == before.end()) return;
        if (it->second != NullState::Null &&
            it->second != NullState::MaybeNull)
            return;

        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reported_.emplace(effect.var, line).second) return;

        zerodefect::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "null-deref";
        if (it->second == NullState::Null) {
            diag.severity = zerodefect::Severity::Error;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::NullDerefDefinite,
                effect.var->getNameAsString());
        } else {
            diag.severity = zerodefect::Severity::Warning;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::NullDerefMaybe,
                effect.var->getNameAsString());
        }
        results_.push_back(diag);
    }

private:
    zerodefect::DiagnosticList& results_;
    NullVarState initState_;
    std::set<std::pair<const VarDecl*, unsigned>> reported_;
};

// --- Matcher callback ---

class NullDerefCallback : public MatchFinder::MatchCallback {
public:
    explicit NullDerefCallback(zerodefect::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* func = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!func || !func->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(func->getLocation())) return;

        auto trackedVars = collectTrackedVars(func, *result.Context);
        if (trackedVars.empty()) return;

        NullDerefAnalysis analysis(trackedVars, results_);
        zerodefect::runDataflow(func, *result.Context, analysis);
    }

private:
    zerodefect::DiagnosticList& results_;
};

} // anonymous namespace

namespace zerodefect {

std::string NullDerefRule::id() const {
    return "null-deref";
}

std::string NullDerefRule::description() const {
    return "CFG-based null pointer dereference analysis with branch "
           "condition refinement";
}

Severity NullDerefRule::defaultSeverity() const {
    return Severity::Error;
}

void NullDerefRule::check(clang::ASTContext& ctx, DiagnosticList& results) {
    MatchFinder finder;
    NullDerefCallback callback(results);

    auto matcher = functionDecl(
        isDefinition(),
        hasBody(anything())
    ).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
