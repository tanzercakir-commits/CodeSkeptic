#include "rules/DivByZeroRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/DataflowEngine.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

#include <algorithm>
#include <map>
#include <set>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// --- ZeroState lattice ---

enum class ZeroState { Unknown, Zero, NonZero, MaybeZero };

// --- Evaluate constant zero-ness ---

ZeroState evaluateAsZero(const Expr* expr) {
    if (!expr) return ZeroState::Unknown;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr))
        return lit->getValue() == 0 ? ZeroState::Zero : ZeroState::NonZero;
    if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
        if (unary->getOpcode() == UO_Minus)
            return evaluateAsZero(unary->getSubExpr());
    }
    return ZeroState::Unknown;
}

// --- Helpers ---

bool refersToVar(const Expr* expr, const VarDecl* var) {
    if (!expr) return false;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return ref->getDecl() == var;
    return false;
}

const VarDecl* getReferencedVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

// --- Collect divisor variables ---

std::set<const VarDecl*> collectDivisorVars(const FunctionDecl* funcDecl,
                                             ASTContext& ctx) {
    std::set<const VarDecl*> vars;
    auto divMatcher = binaryOperator(
        anyOf(hasOperatorName("/"), hasOperatorName("%")),
        hasRHS(expr().bind("divisor"))
    );
    for (const auto& result :
         match(findAll(divMatcher), *funcDecl->getBody(), ctx)) {
        const auto* divisor = result.getNodeAs<Expr>("divisor");
        if (!divisor) continue;
        if (const auto* var = getReferencedVar(divisor))
            vars.insert(var);
    }
    return vars;
}

// --- Statement classification ---

enum class StmtEffect { None, AssignsZero, AssignsNonZero, AssignsUnknown };

StmtEffect classifyStmt(const Stmt* stmt, const VarDecl* targetVar) {
    if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
        for (const auto* decl : declStmt->decls()) {
            if (const auto* vd = dyn_cast<VarDecl>(decl)) {
                if (vd == targetVar && vd->hasInit()) {
                    ZeroState val = evaluateAsZero(vd->getInit());
                    if (val == ZeroState::Zero) return StmtEffect::AssignsZero;
                    if (val == ZeroState::NonZero) return StmtEffect::AssignsNonZero;
                    return StmtEffect::AssignsUnknown;
                }
            }
        }
        return StmtEffect::None;
    }
    if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
        if (binOp->getOpcode() == BO_Assign &&
            refersToVar(binOp->getLHS(), targetVar)) {
            ZeroState val = evaluateAsZero(binOp->getRHS());
            if (val == ZeroState::Zero) return StmtEffect::AssignsZero;
            if (val == ZeroState::NonZero) return StmtEffect::AssignsNonZero;
            return StmtEffect::AssignsUnknown;
        }
    }
    return StmtEffect::None;
}

// --- DivFinder ---

class DivFinder : public RecursiveASTVisitor<DivFinder> {
public:
    struct DivOp {
        const BinaryOperator* op;
        const VarDecl* divisorVar;
        bool isLiteralZero;
    };

    std::vector<DivOp> divs;

    bool VisitBinaryOperator(BinaryOperator* op) {
        if (op->getOpcode() != BO_Div && op->getOpcode() != BO_Rem)
            return true;
        if (op->getType()->isFloatingType())
            return true;

        const Expr* rhs = op->getRHS()->IgnoreParenImpCasts();
        ZeroState litState = evaluateAsZero(rhs);

        DivOp d;
        d.op = op;
        if (litState == ZeroState::Zero) {
            d.divisorVar = nullptr;
            d.isLiteralZero = true;
        } else {
            d.divisorVar = getReferencedVar(rhs);
            d.isLiteralZero = false;
        }
        divs.push_back(d);
        return true;
    }
};

// --- Branch condition refinement (assume edges) ---

using VarState = std::map<const VarDecl*, ZeroState>;

void setIfTracked(VarState& state, const VarDecl* var, ZeroState value) {
    if (!var) return;
    auto it = state.find(var);
    if (it != state.end()) it->second = value;
}

// Kosul ifadesinin dogru/yanlis oldugu kenarda degisken state'lerini
// iyilestirir. Ornek: `z != 0` true kenarinda z = NonZero.
void applyCondition(const Expr* cond, bool isTrue, VarState& state) {
    if (!cond) return;
    cond = cond->IgnoreParenImpCasts();

    // if (z) / while (z): truthiness
    if (const auto* var = getReferencedVar(cond)) {
        setIfTracked(state, var, isTrue ? ZeroState::NonZero : ZeroState::Zero);
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

    // Kisa devre operatorleri: `a && b` dogruysa ikisi de dogru,
    // `a || b` yanlissa ikisi de yanlis. Diger yonde bilgi yok.
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

    // Karsilastirmalar: degisken bir tarafta, sabit diger tarafta
    const Expr* lhs = binOp->getLHS()->IgnoreParenImpCasts();
    const Expr* rhs = binOp->getRHS()->IgnoreParenImpCasts();
    const VarDecl* var = getReferencedVar(lhs);
    const Expr* literal = rhs;
    bool varOnLeft = true;
    if (!var) {
        var = getReferencedVar(rhs);
        literal = lhs;
        varOnLeft = false;
    }
    if (!var) return;

    ZeroState litState = evaluateAsZero(literal);

    if (opc == BO_EQ || opc == BO_NE) {
        // `z == 0` dogru → Zero; `z != 0` dogru → NonZero (yanlislarda tersi).
        // Sifir olmayan sabitle: `z == 5` dogru → NonZero; yanlis yonde bilgi yok.
        bool eqHolds = (opc == BO_EQ) == isTrue;
        if (litState == ZeroState::Zero)
            setIfTracked(state, var, eqHolds ? ZeroState::Zero
                                             : ZeroState::NonZero);
        else if (litState == ZeroState::NonZero && eqHolds)
            setIfTracked(state, var, ZeroState::NonZero);
        return;
    }

    // Siralama karsilastirmalari yalnizca sifir sabitiyle: esitsizligin
    // sifiri disladigi yonde NonZero cikarimi yapilabilir.
    if (litState != ZeroState::Zero) return;

    // Kosulu "var <op> 0" formuna getir (sabit soldaysa operatoru aynala)
    BinaryOperatorKind rel = opc;
    if (!varOnLeft) {
        switch (opc) {
            case BO_LT: rel = BO_GT; break;   // 0 <  z  ≡  z >  0
            case BO_GT: rel = BO_LT; break;   // 0 >  z  ≡  z <  0
            case BO_LE: rel = BO_GE; break;   // 0 <= z  ≡  z >= 0
            case BO_GE: rel = BO_LE; break;   // 0 >= z  ≡  z <= 0
            default: break;
        }
    }

    switch (rel) {
        case BO_GT:  // z > 0
        case BO_LT:  // z < 0
            if (isTrue) setIfTracked(state, var, ZeroState::NonZero);
            break;
        case BO_GE:  // z >= 0: yanlis ise z < 0 → NonZero
        case BO_LE:  // z <= 0: yanlis ise z > 0 → NonZero
            if (!isTrue) setIfTracked(state, var, ZeroState::NonZero);
            break;
        default:
            break;
    }
}

// --- Analysis struct for DataflowEngine ---

class DivByZeroAnalysis {
public:
    using State = VarState;

    DivByZeroAnalysis(const std::set<const VarDecl*>& trackedVars,
                      std::string funcName,
                      zerodefect::DiagnosticList& results,
                      std::set<unsigned>& reportedLines)
        : trackedVars_(trackedVars), funcName_(std::move(funcName)),
          results_(results), reportedLines_(reportedLines) {
        for (const auto* var : trackedVars_)
            initState_[var] = ZeroState::Unknown;
    }

    State initialState() const { return initState_; }

    // Degisken basina ZeroState zinciri en fazla 3 gecis yapar
    unsigned latticeHeight() const {
        return static_cast<unsigned>(trackedVars_.size()) * 3 + 1;
    }

    State merge(const State& a, const State& b) const {
        State result = a;
        for (const auto& [var, stateB] : b) {
            auto it = result.find(var);
            if (it == result.end())
                result[var] = stateB;
            else {
                if (it->second == stateB) continue;
                // Herhangi bir yolda kesin/olasi sifir varsa bilgi korunur:
                // Zero|MaybeZero + baska bir sey = MaybeZero.
                // Yalnizca NonZero + Unknown bilgisizlige duser.
                bool anyZeroInfo =
                    it->second == ZeroState::Zero ||
                    it->second == ZeroState::MaybeZero ||
                    stateB == ZeroState::Zero ||
                    stateB == ZeroState::MaybeZero;
                it->second = anyZeroInfo ? ZeroState::MaybeZero
                                         : ZeroState::Unknown;
            }
        }
        return result;
    }

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext& /*ctx*/) const {
        State out = in;
        for (const auto* var : trackedVars_) {
            StmtEffect effect = classifyStmt(stmt, var);
            switch (effect) {
                case StmtEffect::AssignsZero:
                    out[var] = ZeroState::Zero; break;
                case StmtEffect::AssignsNonZero:
                    out[var] = ZeroState::NonZero; break;
                case StmtEffect::AssignsUnknown:
                    out[var] = ZeroState::Unknown; break;
                case StmtEffect::None: break;
            }
        }
        return out;
    }

    void refineOnEdge(const Stmt* cond, bool isTrueBranch, State& state,
                      ASTContext& /*ctx*/) const {
        applyCondition(dyn_cast<Expr>(cond), isTrueBranch, state);
    }

    void onStatement(const Stmt* stmt, const State& before,
                     const State& after, ASTContext& ctx) {
        // Dataflow izi: sifira gecis olaylarini kaydet
        for (const auto& [var, afterState] : after) {
            auto b = before.find(var);
            if (b == before.end() || b->second == afterState) continue;
            if (afterState == ZeroState::Zero)
                recordEvent(stmt, var, ctx);
        }

        // YALNIZCA tepe dugum: ince taneli CFG'de her bolme kendi elemani
        // olarak gelir. Nested arama (eski DivFinder yaklasimi) ayni
        // bolmeyi kapsayan ifadenin elemaninda — yanlis (join) state'iyle —
        // ikinci kez kesfedip FP uretiyordu (ternary guard vakasi).
        const auto* op = dyn_cast<BinaryOperator>(stmt);
        if (!op) return;
        if (op->getOpcode() != BO_Div && op->getOpcode() != BO_Rem) return;
        if (op->getType()->isFloatingType()) return;

        const Expr* rhs = op->getRHS()->IgnoreParenImpCasts();
        if (evaluateAsZero(rhs) == ZeroState::Zero) return;  // Phase 1'de
        const VarDecl* var = getReferencedVar(rhs);
        if (!var) return;

        auto stateIt = before.find(var);
        if (stateIt == before.end()) return;
        ZeroState state = stateIt->second;
        if (state != ZeroState::Zero && state != ZeroState::MaybeZero)
            return;

        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(op->getOperatorLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reportedLines_.insert(line).second) return;

        zerodefect::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "div-by-zero";
        diag.function = funcName_;
        if (state == ZeroState::Zero) {
            diag.severity = zerodefect::Severity::Error;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::DivByZeroDefinite,
                var->getNameAsString());
        } else {
            diag.severity = zerodefect::Severity::Warning;
            diag.message = zerodefect::msg(
                zerodefect::MsgId::DivByZeroMaybe,
                var->getNameAsString());
        }
        results_.push_back(diag);
        noteTargets_.emplace_back(results_.size() - 1, var);
    }

    // Kosu bittikten sonra: sifir-atama izlerini raporlara ilistir
    void attachTraces() {
        for (const auto& [index, var] : noteTargets_) {
            auto it = events_.find(var);
            if (it == events_.end()) continue;
            auto notes = it->second;
            std::sort(notes.begin(), notes.end());
            if (notes.size() > 6) notes.resize(6);
            results_[index].notes = std::move(notes);
        }
        noteTargets_.clear();
    }

private:
    void recordEvent(const Stmt* stmt, const VarDecl* var,
                     ASTContext& ctx) {
        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        zerodefect::TraceNote note;
        note.file = sm.getFilename(loc).str();
        note.line = sm.getSpellingLineNumber(loc);
        note.column = sm.getSpellingColumnNumber(loc);
        note.message = zerodefect::msg(
            zerodefect::MsgId::TraceAssignedZeroHere,
            var->getNameAsString());

        auto& list = events_[var];
        for (const auto& existing : list)
            if (existing.line == note.line) return;
        list.push_back(std::move(note));
    }

    const std::set<const VarDecl*>& trackedVars_;
    std::string funcName_;
    zerodefect::DiagnosticList& results_;
    std::set<unsigned>& reportedLines_;
    VarState initState_;
    std::map<const VarDecl*, std::vector<zerodefect::TraceNote>> events_;
    std::vector<std::pair<size_t, const VarDecl*>> noteTargets_;
};

// --- Function-level analysis ---

void analyzeFunction(const FunctionDecl* funcDecl,
                     ASTContext& ctx,
                     zerodefect::DiagnosticList& results) {
    if (!funcDecl->hasBody()) return;

    const SourceManager& sm = ctx.getSourceManager();
    std::set<unsigned> reportedLines;

    // Phase 1: Literal zero divisions (no CFG)
    DivFinder literalFinder;
    literalFinder.TraverseStmt(funcDecl->getBody());
    for (const auto& div : literalFinder.divs) {
        if (div.isLiteralZero) {
            SourceLocation loc =
                sm.getExpansionLoc(div.op->getOperatorLoc());
            unsigned line = sm.getSpellingLineNumber(loc);
            if (reportedLines.insert(line).second) {
                zerodefect::Diagnostic diag;
                diag.severity = zerodefect::Severity::Error;
                diag.file = sm.getFilename(loc).str();
                diag.line = line;
                diag.column = sm.getSpellingColumnNumber(loc);
                diag.rule_id = "div-by-zero";
                diag.function = funcDecl->getQualifiedNameAsString();
                diag.message = zerodefect::msg(
                    zerodefect::MsgId::DivByZeroLiteral);
                results.push_back(diag);
            }
        }
    }

    // Phase 2: Variable divisor analysis via DataflowEngine
    auto trackedVars = collectDivisorVars(funcDecl, ctx);
    if (trackedVars.empty()) return;

    DivByZeroAnalysis analysis(
        trackedVars, funcDecl->getQualifiedNameAsString(), results,
        reportedLines);
    zerodefect::runDataflow(funcDecl, ctx, analysis);
    analysis.attachTraces();
}

// --- Matcher callback ---

class DivByZeroCallback : public MatchFinder::MatchCallback {
public:
    explicit DivByZeroCallback(zerodefect::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* func = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!func || !func->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(func->getLocation())) return;
        if (!zerodefect::functionFilterAllows(*func)) return;
        if (!zerodefect::lineFilterAllows(*func, sm)) return;

        analyzeFunction(func, *result.Context, results_);
    }

private:
    zerodefect::DiagnosticList& results_;
};

} // anonymous namespace

namespace zerodefect {

std::string DivByZeroRule::id() const {
    return "div-by-zero";
}

std::string DivByZeroRule::description() const {
    return "Definite and potential division-by-zero detection";
}

Severity DivByZeroRule::defaultSeverity() const {
    return Severity::Error;
}

void DivByZeroRule::check(clang::ASTContext& ctx, DiagnosticList& results) {
    MatchFinder finder;
    DivByZeroCallback callback(results);

    auto matcher = functionDecl(
        isDefinition(),
        hasBody(anything())
    ).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
