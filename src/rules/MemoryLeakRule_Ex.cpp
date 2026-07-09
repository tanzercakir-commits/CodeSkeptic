#include "rules/MemoryLeakRule_Ex.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/DataflowEngine.h"
#include "engine/FunctionSummary.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
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

// --- AllocState lattice ---

enum class AllocState { None, Allocated, Freed, Escaped };

AllocState mergeAllocStates(AllocState a, AllocState b) {
    if (a == b) return a;
    if (a == AllocState::Escaped || b == AllocState::Escaped)
        return AllocState::Escaped;
    if (a == AllocState::None || b == AllocState::None) {
        AllocState other = (a == AllocState::None) ? b : a;
        if (other == AllocState::Allocated) return AllocState::Allocated;
        return AllocState::None;
    }
    return AllocState::Allocated;
}

// --- Statement classification ---

enum class StmtEffect { None, Allocates, Frees, Escapes };

auto allocCallMatcher() {
    return callExpr(callee(functionDecl(
        hasAnyName("malloc", "calloc", "strdup"))));
}

// Operator overload'larinda getName() gecersiz — guvenli erisim
llvm::StringRef calleeName(const FunctionDecl* callee) {
    if (!callee) return {};
    if (const auto* id = callee->getIdentifier()) return id->getName();
    return {};
}

bool isAllocExpr(const Expr* expr, ASTContext& ctx) {
    if (!expr) return false;
    expr = expr->IgnoreParenImpCasts();
    if (isa<CXXNewExpr>(expr)) return true;
    if (const auto* cast = dyn_cast<CastExpr>(expr))
        return isAllocExpr(cast->getSubExpr(), ctx);
    if (const auto* call = dyn_cast<CallExpr>(expr)) {
        auto name = calleeName(call->getDirectCallee());
        return name == "malloc" || name == "calloc" ||
               name == "strdup" || name == "realloc";
    }
    return false;
}

bool refersToVar(const Expr* expr, const VarDecl* targetVar) {
    if (!expr) return false;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return ref->getDecl() == targetVar;
    return false;
}

const VarDecl* asVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

// Dereference tespiti (use-after-free icin). CFG ince taneli oldugundan
// yalnizca tepe dugume bakmak yeterli.
const VarDecl* derefTarget(const Stmt* stmt) {
    if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
        if (unary->getOpcode() == UO_Deref)
            return asVar(unary->getSubExpr());
        return nullptr;
    }
    if (const auto* member = dyn_cast<MemberExpr>(stmt)) {
        if (member->isArrow())
            return asVar(member->getBase());
        return nullptr;
    }
    if (const auto* subscript = dyn_cast<ArraySubscriptExpr>(stmt))
        return asVar(subscript->getBase());
    return nullptr;
}

StmtEffect classifyStmt(const Stmt* stmt, const VarDecl* targetVar,
                         ASTContext& ctx) {
    if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
        for (const auto* decl : declStmt->decls()) {
            if (const auto* vd = dyn_cast<VarDecl>(decl)) {
                if (vd == targetVar && vd->hasInit()) {
                    if (isAllocExpr(vd->getInit(), ctx))
                        return StmtEffect::Allocates;
                }
            }
        }
        return StmtEffect::None;
    }
    if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
        if (binOp->getOpcode() == BO_Assign) {
            if (refersToVar(binOp->getLHS(), targetVar) &&
                isAllocExpr(binOp->getRHS(), ctx))
                return StmtEffect::Allocates;
        }
    }
    if (const auto* del = dyn_cast<CXXDeleteExpr>(stmt)) {
        if (refersToVar(del->getArgument(), targetVar))
            return StmtEffect::Frees;
    }
    if (const auto* call = dyn_cast<CallExpr>(stmt)) {
        const FunctionDecl* callee = call->getDirectCallee();
        if (calleeName(callee) == "free" && call->getNumArgs() > 0) {
            if (refersToVar(call->getArg(0), targetVar))
                return StmtEffect::Frees;
        }

        // Interprosedurel: cagrilanin ozeti varsa parametre etkisine gore
        // siniflandir — free-wrapper'lar Frees (double-free/UAF gorunur),
        // salt-okur yardimcilar etkisiz (arkalarindaki leak gorunur).
        // Ayni degisken birden fazla pozisyondaysa en muhafazakari kazanir.
        const auto* summary =
            zerodefect::SummaryRegistry::instance().lookup(callee);
        using PE = zerodefect::SummaryRegistry::ParamEffect;
        bool sawFrees = false;
        bool sawReadsOnly = false;
        for (unsigned i = 0; i < call->getNumArgs(); ++i) {
            if (!refersToVar(call->getArg(i), targetVar)) continue;
            PE effect = summary ? summary->paramEffect(i) : PE::Opaque;
            switch (effect) {
                case PE::Stores:
                case PE::Opaque:    return StmtEffect::Escapes;
                case PE::Frees:     sawFrees = true; break;
                case PE::ReadsOnly: sawReadsOnly = true; break;
            }
        }
        if (sawFrees) return StmtEffect::Frees;
        if (sawReadsOnly) return StmtEffect::None;
    }
    if (const auto* ret = dyn_cast<ReturnStmt>(stmt)) {
        if (refersToVar(ret->getRetValue(), targetVar))
            return StmtEffect::Escapes;
    }
    return StmtEffect::None;
}

// --- Collect tracked pointer variables ---

std::vector<const VarDecl*> collectTrackedVars(const FunctionDecl* funcDecl,
                                                ASTContext& ctx) {
    std::set<const VarDecl*> vars;

    auto newInitMatcher = varDecl(
        hasType(pointerType()),
        hasInitializer(ignoringParenImpCasts(cxxNewExpr()))
    ).bind("var");
    auto mallocInitMatcher = varDecl(
        hasType(pointerType()),
        hasInitializer(ignoringParenImpCasts(
            castExpr(hasSourceExpression(ignoringParenImpCasts(
                allocCallMatcher())))))
    ).bind("var");
    auto mallocInitDirect = varDecl(
        hasType(pointerType()),
        hasInitializer(ignoringParenImpCasts(allocCallMatcher()))
    ).bind("var");
    auto newAssignMatcher = binaryOperator(
        hasOperatorName("="),
        hasLHS(ignoringParenImpCasts(declRefExpr(
            to(varDecl(hasType(pointerType())).bind("var"))))),
        hasRHS(ignoringParenImpCasts(cxxNewExpr()))
    );
    auto mallocAssignMatcher = binaryOperator(
        hasOperatorName("="),
        hasLHS(ignoringParenImpCasts(declRefExpr(
            to(varDecl(hasType(pointerType())).bind("var"))))),
        hasRHS(ignoringParenImpCasts(
            castExpr(hasSourceExpression(ignoringParenImpCasts(
                allocCallMatcher())))))
    );

    auto declMatchers = {newInitMatcher, mallocInitMatcher, mallocInitDirect};
    for (const auto& m : declMatchers) {
        auto wrapper = functionDecl(equalsNode(funcDecl),
                                     forEachDescendant(m));
        for (const auto& result : match(wrapper, *funcDecl, ctx)) {
            if (const auto* v = result.getNodeAs<VarDecl>("var"))
                vars.insert(v);
        }
    }
    auto assignMatchers = {newAssignMatcher, mallocAssignMatcher};
    for (const auto& m : assignMatchers) {
        for (const auto& result : match(findAll(m), *funcDecl->getBody(), ctx)) {
            if (const auto* v = result.getNodeAs<VarDecl>("var"))
                vars.insert(v);
        }
    }
    return {vars.begin(), vars.end()};
}

// --- Branch condition refinement (assume edges) ---

using VarState = std::map<const VarDecl*, AllocState>;

bool isNullLiteral(const Expr* expr) {
    if (!expr) return false;
    expr = expr->IgnoreParenCasts();
    if (isa<CXXNullPtrLiteralExpr>(expr)) return true;
    if (isa<GNUNullExpr>(expr)) return true;
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr))
        return lit->getValue() == 0;
    return false;
}

void markNullOnEdge(VarState& state, const VarDecl* var) {
    if (!var || !var->getType()->isPointerType()) return;
    auto it = state.find(var);
    if (it == state.end()) return;
    // Null oldugu bilinen kenarda "allocation" yoktur: malloc/new
    // basarisizlik yolu leak DEGILDIR (p = malloc; if (!p) return;)
    if (it->second == AllocState::Allocated)
        it->second = AllocState::None;
}

// p'nin null oldugu kenarlari tanir: `p` yanlis dali, `!p` dogru dali,
// `p == nullptr/NULL/0` dogru dali, `p != ...` yanlis dali, && / ||
void applyNullCondition(const Expr* cond, bool isTrue, VarState& state) {
    if (!cond) return;
    cond = cond->IgnoreParenImpCasts();

    if (const auto* ref = dyn_cast<DeclRefExpr>(cond)) {
        if (!isTrue)
            markNullOnEdge(state, dyn_cast<VarDecl>(ref->getDecl()));
        return;
    }
    if (const auto* unary = dyn_cast<UnaryOperator>(cond)) {
        if (unary->getOpcode() == UO_LNot)
            applyNullCondition(unary->getSubExpr(), !isTrue, state);
        return;
    }
    const auto* binOp = dyn_cast<BinaryOperator>(cond);
    if (!binOp) return;
    const BinaryOperatorKind opc = binOp->getOpcode();

    if (opc == BO_LAnd) {
        if (isTrue) {
            applyNullCondition(binOp->getLHS(), true, state);
            applyNullCondition(binOp->getRHS(), true, state);
        }
        return;
    }
    if (opc == BO_LOr) {
        if (!isTrue) {
            applyNullCondition(binOp->getLHS(), false, state);
            applyNullCondition(binOp->getRHS(), false, state);
        }
        return;
    }
    if (opc != BO_EQ && opc != BO_NE) return;

    const Expr* lhs = binOp->getLHS()->IgnoreParenImpCasts();
    const Expr* rhs = binOp->getRHS()->IgnoreParenImpCasts();
    const VarDecl* var = nullptr;
    if (isNullLiteral(rhs)) {
        if (const auto* ref = dyn_cast<DeclRefExpr>(lhs))
            var = dyn_cast<VarDecl>(ref->getDecl());
    } else if (isNullLiteral(lhs)) {
        if (const auto* ref = dyn_cast<DeclRefExpr>(rhs))
            var = dyn_cast<VarDecl>(ref->getDecl());
    }
    if (!var) return;

    bool eqHolds = (opc == BO_EQ) == isTrue;  // bu kenarda "esittir null"
    if (eqHolds) markNullOnEdge(state, var);
}

// --- Analysis struct for DataflowEngine ---

class MemLeakAnalysis {
public:
    using State = VarState;

    MemLeakAnalysis(const std::vector<const VarDecl*>& trackedVars,
                    std::string funcName,
                    zerodefect::DiagnosticList& results)
        : trackedVars_(trackedVars), funcName_(std::move(funcName)),
          results_(results) {
        for (const auto* var : trackedVars_)
            initState_[var] = AllocState::None;
    }

    State initialState() const { return initState_; }

    // Degisken basina AllocState zinciri en fazla 3 gecis yapar
    unsigned latticeHeight() const {
        return static_cast<unsigned>(trackedVars_.size()) * 3 + 1;
    }

    State merge(const State& a, const State& b) const {
        State result = a;
        for (const auto& [var, stateB] : b) {
            auto it = result.find(var);
            if (it == result.end())
                result[var] = stateB;
            else
                it->second = mergeAllocStates(it->second, stateB);
        }
        return result;
    }

    // Saf state gecisi — rapor uretmez. Raporlama, fixpoint sonrasi
    // gecis olan onStatement icindedir (engine garantisi).
    State transfer(const Stmt* stmt, const State& in, ASTContext& ctx) const {
        State out = in;
        for (const auto* var : trackedVars_) {
            StmtEffect effect = classifyStmt(stmt, var, ctx);
            switch (effect) {
                case StmtEffect::Allocates:
                    out[var] = AllocState::Allocated; break;
                case StmtEffect::Frees:
                    out[var] = AllocState::Freed; break;
                case StmtEffect::Escapes:
                    out[var] = AllocState::Escaped; break;
                case StmtEffect::None: break;
            }
        }
        return out;
    }

    void refineOnEdge(const Stmt* cond, bool isTrueBranch, State& state,
                      ASTContext& /*ctx*/) const {
        applyNullCondition(dyn_cast<Expr>(cond), isTrueBranch, state);
    }

    // Fixpoint sonrasi raporlama: reassignment leak, double free ve
    // use-after-free burada uretilir.
    void onStatement(const Stmt* stmt, const State& before,
                     const State& after, ASTContext& ctx) {
        // Dataflow izi: state degistiren olaylari kaydet (alloc/free).
        // Notlar rapora kosu SONUNDA ilistirilir — raporlama gecisinin
        // blok sirasi kaynak sirasi degildir.
        for (const auto& [var, afterState] : after) {
            auto b = before.find(var);
            if (b == before.end() || b->second == afterState) continue;
            if (afterState == AllocState::Allocated)
                recordEvent(stmt, var, ctx,
                            zerodefect::MsgId::TraceAllocatedHere);
            else if (afterState == AllocState::Freed)
                recordEvent(stmt, var, ctx,
                            zerodefect::MsgId::TraceFreedHere);
        }

        for (const auto* var : trackedVars_) {
            StmtEffect effect = classifyStmt(stmt, var, ctx);
            auto it = before.find(var);
            if (it == before.end()) continue;

            if (effect == StmtEffect::Allocates &&
                it->second == AllocState::Allocated) {
                report(stmt, var, ctx, zerodefect::Severity::Warning,
                       "memory-leak", zerodefect::MsgId::LeakReassign);
            } else if (effect == StmtEffect::Frees &&
                       it->second == AllocState::Freed) {
                report(stmt, var, ctx, zerodefect::Severity::Error,
                       "memory-leak", zerodefect::MsgId::DoubleFree);
            }
        }

        // Freed durumdaki pointer'in dereference'i: use-after-free
        if (const VarDecl* var = derefTarget(stmt)) {
            auto it = before.find(var);
            if (it != before.end() && it->second == AllocState::Freed) {
                report(stmt, var, ctx, zerodefect::Severity::Error,
                       "use-after-free", zerodefect::MsgId::UseAfterFree);
            }
        }
    }

    std::set<std::pair<const VarDecl*, unsigned>>& reported() {
        return reported_;
    }

    // Kosu bittikten sonra: biriken olay notlarini raporlara ilistir
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

    // Dis raporlar (exit-block leak) icin: hedef kaydi + olay erisimi
    void registerNoteTarget(size_t resultIndex, const VarDecl* var) {
        noteTargets_.emplace_back(resultIndex, var);
    }

private:
    std::map<const VarDecl*, std::vector<zerodefect::TraceNote>> events_;
    std::vector<std::pair<size_t, const VarDecl*>> noteTargets_;

    void recordEvent(const Stmt* stmt, const VarDecl* var, ASTContext& ctx,
                     zerodefect::MsgId msgId) {
        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        zerodefect::TraceNote note;
        note.file = sm.getFilename(loc).str();
        note.line = sm.getSpellingLineNumber(loc);
        note.column = sm.getSpellingColumnNumber(loc);
        note.message = zerodefect::msg(msgId, var->getNameAsString());

        auto& list = events_[var];
        for (const auto& existing : list)
            if (existing.line == note.line &&
                existing.message == note.message)
                return;
        list.push_back(std::move(note));
    }

    void report(const Stmt* stmt, const VarDecl* var, ASTContext& ctx,
                zerodefect::Severity severity, const char* ruleId,
                zerodefect::MsgId msgId) {
        const SourceManager& sm = ctx.getSourceManager();
        // Makro icindeki bulgular kullanim noktasina (expansion) baglanir;
        // aksi halde dosya adi bos kalabiliyor (scratch buffer)
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reported_.emplace(var, line).second) return;

        zerodefect::Diagnostic diag;
        diag.severity = severity;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = ruleId;
        diag.function = funcName_;
        diag.message = zerodefect::msg(msgId, var->getNameAsString());
        results_.push_back(diag);
        noteTargets_.emplace_back(results_.size() - 1, var);
    }

    const std::vector<const VarDecl*>& trackedVars_;
    std::string funcName_;
    zerodefect::DiagnosticList& results_;
    VarState initState_;
    std::set<std::pair<const VarDecl*, unsigned>> reported_;
};

// --- Function-level analysis ---

void analyzeFunction(const FunctionDecl* funcDecl,
                     ASTContext& ctx,
                     zerodefect::DiagnosticList& results) {
    if (!funcDecl->hasBody()) return;

    auto trackedVars = collectTrackedVars(funcDecl, ctx);
    if (trackedVars.empty()) return;

    MemLeakAnalysis analysis(
        trackedVars, funcDecl->getQualifiedNameAsString(), results);
    auto dfResult = zerodefect::runDataflow(funcDecl, ctx, analysis);

    // Exit block leak check
    auto exitIt = dfResult.blockExitStates.find(dfResult.exitBlockID);
    if (exitIt == dfResult.blockExitStates.end()) return;

    const SourceManager& sm = ctx.getSourceManager();
    SourceLocation endLoc = funcDecl->getBody()->getEndLoc();

    for (const auto& [var, state] : exitIt->second) {
        if (state == AllocState::Allocated) {
            unsigned line = sm.getSpellingLineNumber(endLoc);
            if (analysis.reported().emplace(var, line).second) {
                zerodefect::Diagnostic diag;
                diag.severity = zerodefect::Severity::Warning;
                diag.file = sm.getFilename(endLoc).str();
                diag.line = line;
                diag.column = sm.getSpellingColumnNumber(endLoc);
                diag.rule_id = "memory-leak";
                diag.function = funcDecl->getQualifiedNameAsString();
                diag.message = zerodefect::msg(
                    zerodefect::MsgId::LeakEndOfFunction,
                    var->getNameAsString());
                results.push_back(diag);
                analysis.registerNoteTarget(results.size() - 1, var);
            }
        }
    }

    analysis.attachTraces();
}

// --- Matcher callback ---

class FindMemLeakCallback : public MatchFinder::MatchCallback {
public:
    explicit FindMemLeakCallback(zerodefect::DiagnosticList& results)
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

std::string MemoryLeakRule_Ex::id() const {
    return "memory-leak";
}

std::string MemoryLeakRule_Ex::description() const {
    return "CFG-based memory leak, double-free and use-after-free analysis";
}

void MemoryLeakRule_Ex::check(clang::ASTContext& ctx,
                               DiagnosticList& results) {
    MatchFinder finder;
    FindMemLeakCallback callback(results);

    auto matcher = functionDecl(
        isDefinition(),
        hasBody(anything())
    ).bind("func");

    finder.addMatcher(matcher, &callback);
    finder.matchAST(ctx);
}

} // namespace zerodefect
