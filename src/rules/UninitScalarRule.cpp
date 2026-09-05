#include "rules/UninitScalarRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/CoverageReport.h"
#include "engine/DataflowEngine.h"
#include "engine/FatalCalls.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/Basic/Builtins.h>
#include <clang/Basic/SourceManager.h>

#include <map>
#include <set>
#include <utility>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

enum class Initialization { Uninitialized, Initialized, Maybe, Unknown };
enum class Flow { Continue, Stop, Unsupported };

const DeclRefExpr* directReference(const Expr* expr) {
    for (unsigned depth = 0; expr && depth < 32; ++depth) {
        expr = expr->IgnoreParenImpCasts();
        if (const auto* ref = dyn_cast<DeclRefExpr>(expr)) return ref;
        const auto* comma = dyn_cast<BinaryOperator>(expr);
        if (!comma || comma->getOpcode() != BO_Comma) return nullptr;
        expr = comma->getRHS();
    }
    return nullptr;
}

const VarDecl* directVariable(const Expr* expr) {
    const auto* ref = directReference(expr);
    return ref ? dyn_cast<VarDecl>(ref->getDecl()) : nullptr;
}

bool deliberateBareVoidDiscard(const CastExpr* cast) {
    // Precision policy for the conventional C unused-local marker, also used
    // by Clang's uninitialized-value analysis. This is NOT a claim that C void
    // operands are unevaluated. Only parentheses and the single implicit value
    // conversion of a bare tracked local may be ignored; never peel commas,
    // explicit intermediate casts, arithmetic, calls or side effects.
    if (!isa<CStyleCastExpr>(cast) || !cast->getType()->isVoidType()) return false;
    const Expr* operand = cast->getSubExpr()->IgnoreParens();
    if (const auto* implicit = dyn_cast<ImplicitCastExpr>(operand)) {
        if (implicit->getCastKind() != CK_LValueToRValue) return false;
        operand = implicit->getSubExpr()->IgnoreParens();
    }
    const auto* reference = dyn_cast<DeclRefExpr>(operand);
    const auto* var = reference ? dyn_cast<VarDecl>(reference->getDecl()) : nullptr;
    return var && var->isLocalVarDecl() && !var->hasGlobalStorage() &&
           var->getType()->isIntegerType() && !var->getType()->isEnumeralType() &&
           !var->getType().isVolatileQualified();
}

void reportRead(const Expr* expr, Initialization state, ASTContext& ctx,
                const FunctionDecl* function, codeskeptic::DiagnosticList& results) {
    if (state != Initialization::Uninitialized && state != Initialization::Maybe)
        return;
    const auto* ref = directReference(expr);
    const auto* var = directVariable(expr);
    if (!ref || !var) return;
    const auto& sm = ctx.getSourceManager();
    const auto loc = sm.getExpansionLoc(ref->getExprLoc());
    if (loc.isInvalid() || sm.isInSystemHeader(loc)) return;
    const bool possible = state == Initialization::Maybe;
    codeskeptic::Diagnostic diag{};
    diag.severity = possible ? codeskeptic::Severity::Warning : codeskeptic::Severity::Error;
    diag.file = sm.getFilename(loc).str();
    diag.line = sm.getSpellingLineNumber(loc);
    diag.column = sm.getSpellingColumnNumber(loc);
    diag.rule_id = "uninit-scalar";
    diag.function = function->getQualifiedNameAsString();
    diag.message = codeskeptic::currentLang() == codeskeptic::Lang::TR
        ? "Yerel tamsayı/bool '" + var->getNameAsString() +
              (possible ? "' başlatılmadan önce okunuyor olabilir (CWE-457)"
                        : "' başlatılmadan önce okunuyor (CWE-457)")
        : "Local integer/bool '" + var->getNameAsString() +
              (possible ? "' may be read before initialization (CWE-457)"
                        : "' is read before initialization (CWE-457)");
    const auto decl = sm.getExpansionLoc(var->getLocation());
    diag.notes.push_back({sm.getFilename(decl).str(),
        sm.getSpellingLineNumber(decl), sm.getSpellingColumnNumber(decl),
        codeskeptic::msg(codeskeptic::MsgId::TraceDeclaredHere, var->getNameAsString())});
    results.push_back(std::move(diag));
}

class ScalarReads {
public:
    ScalarReads(ASTContext& ctx, const FunctionDecl* function)
        : ctx_(ctx), function_(function) {}

    bool run(codeskeptic::DiagnosticList& results) {
        // Do not publish a partial proof if a later unsupported control or
        // sequencing construct invalidates the straight-line interpretation.
        if (statement(function_->getBody(), 0) == Flow::Unsupported) return false;
        results.insert(results.end(), pending_.begin(), pending_.end());
        return true;
    }

private:
    bool enter(unsigned depth) {
        if (depth >= 128 || budget_ == 0) return false;
        --budget_;
        return true;
    }

    bool emptyArray(QualType type) const {
        for (unsigned depth = 0; depth < 32; ++depth) {
            const auto* array = ctx_.getAsConstantArrayType(type);
            if (!array) return false;
            if (array->getSize().isZero()) return true;
            type = array->getElementType();
        }
        return false;
    }

    bool destructorDoesNotReturn(QualType type) const {
        for (unsigned depth = 0; depth < 32; ++depth) {
            if (const auto* array = ctx_.getAsArrayType(type)) {
                const auto* size = dyn_cast<ConstantArrayType>(array);
                if (!size || size->getSize().isZero()) return false;
                type = array->getElementType();
                continue;
            }
            const auto* record = type->getAsCXXRecordDecl();
            return record && record->isAnyDestructorNoReturn();
        }
        return false;
    }

    const CXXBindTemporaryExpr* resultTemporary(const Expr* expr) const {
        // Lifetime extension follows only the resulting object, not every
        // temporary below an MTE: in (D{}, D{}) the LHS still dies now.
        for (unsigned depth = 0; expr && depth < 32; ++depth) {
            expr = expr->IgnoreParenImpCasts();
            if (const auto* bind = dyn_cast<CXXBindTemporaryExpr>(expr)) return bind;
            if (const auto* cast = dyn_cast<CastExpr>(expr)) {
                expr = cast->getSubExpr();
            } else if (const auto* comma = dyn_cast<BinaryOperator>(expr);
                       comma && comma->getOpcode() == BO_Comma) {
                expr = comma->getRHS();
            } else {
                return nullptr;
            }
        }
        return nullptr;
    }

    void finishFullExpression() {
        terminated_ = terminated_ || fullExpressionTerminates_;
        fullExpressionTerminates_ = false;
    }

    void escape(const Expr* expr) {
        const auto* var = directVariable(expr);
        if (!escapeFrames_.empty()) {
            escapeFrames_.back().push_back(var);
            return;
        }
        auto it = states_.find(var);
        if (it != states_.end()) it->second = Initialization::Unknown;
    }

    void initialize(const Expr* expr) {
        auto it = states_.find(directVariable(expr));
        if (it != states_.end()) it->second = Initialization::Initialized;
    }

    void read(const Expr* expr) {
        if (terminated_) return;
        const auto* var = directVariable(expr);
        auto it = states_.find(var);
        if (it == states_.end() || it->second != Initialization::Uninitialized)
            return;
        reportRead(expr, it->second, ctx_, function_, pending_);
    }

    // Arguments may be evaluated in an unspecified order. This first unit
    // accepts side-effect-free arguments; it does not impose AST child order
    // on expressions such as consume(x = 1, x).
    template <typename Call>
    bool arguments(const Call* call, const FunctionDecl* callee, unsigned depth) {
        for (const Expr* arg : call->arguments())
            if (arg->HasSideEffects(ctx_)) return false;
        // Binding/passing a reference or pointer does not run the callee yet.
        // All by-value arguments must be read before its out-param writes can
        // happen, independent of argument evaluation order.
        escapeFrames_.emplace_back();
        unsigned index = 0;
        for (const Expr* arg : call->arguments()) {
            if (!expression(arg, depth + 1)) {
                escapeFrames_.pop_back();
                return false;
            }
            if (callee && index < callee->getNumParams() &&
                callee->getParamDecl(index)->getType()->isReferenceType())
                escape(arg);
            ++index;
        }
        const auto escaped = std::move(escapeFrames_.back());
        escapeFrames_.pop_back();
        for (const auto* var : escaped) {
            auto it = states_.find(var);
            if (it != states_.end()) it->second = Initialization::Unknown;
        }
        return true;
    }

    bool expression(const Expr* expr, unsigned depth) {
        if (!expr || terminated_) return true;
        if (!enter(depth) || expr->isTypeDependent() || expr->isValueDependent())
            return false;
        if (const auto* trait = dyn_cast<UnaryExprOrTypeTraitExpr>(expr)) {
            // Ordinary sizeof/alignof never read the operand. VLA evaluation
            // needs a separate runtime-type model, not generic AST recursion.
            return !trait->getTypeOfArgument()->isVariablyModifiedType();
        }
        if (isa<CXXNoexceptExpr>(expr) || isa<TypeTraitExpr>(expr)) return true;
        if (const auto* paren = dyn_cast<ParenExpr>(expr))
            return expression(paren->getSubExpr(), depth + 1);
        if (const auto* cast = dyn_cast<CastExpr>(expr)) {
            if (deliberateBareVoidDiscard(cast)) return true;
            if (!expression(cast->getSubExpr(), depth + 1)) return false;
            if (cast->getCastKind() == CK_LValueToRValue) read(cast->getSubExpr());
            // A glvalue cast can expose the same storage under a different
            // type. Do not later claim that storage remained untouched.
            if (isa<ExplicitCastExpr>(cast) && cast->isGLValue())
                escape(cast->getSubExpr());
            return true;
        }
        if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
            if (!expression(unary->getSubExpr(), depth + 1)) return false;
            if (unary->isIncrementDecrementOp()) {
                read(unary->getSubExpr());
                initialize(unary->getSubExpr());
            } else if (unary->getOpcode() == UO_AddrOf) {
                escape(unary->getSubExpr());
            }
            return true;
        }
        if (const auto* binary = dyn_cast<BinaryOperator>(expr)) {
            if (binary->isLogicalOp()) return false;
            if (binary->isAssignmentOp()) {
                if (!expression(binary->getRHS(), depth + 1) ||
                    !expression(binary->getLHS(), depth + 1)) return false;
                if (binary->isCompoundAssignmentOp()) read(binary->getLHS());
                initialize(binary->getLHS());
                return true;
            }
            if (binary->getOpcode() != BO_Comma &&
                (binary->getLHS()->HasSideEffects(ctx_) ||
                 binary->getRHS()->HasSideEffects(ctx_))) return false;
            return expression(binary->getLHS(), depth + 1) &&
                   expression(binary->getRHS(), depth + 1);
        }
        if (const auto* call = dyn_cast<CallExpr>(expr)) {
            // A CallExpr child is not always executed. Clang's generic API
            // covers constant_p/classify_type. The assume intrinsics also
            // discard evaluation, but do not carry its 'u' builtin attribute.
            const unsigned builtin = call->getBuiltinCallee();
            if (call->isUnevaluatedBuiltinCall(ctx_) ||
                builtin == Builtin::BI__builtin_assume ||
                builtin == Builtin::BI__assume) {
                terminated_ = terminated_ || call->isBuiltinAssumeFalse(ctx_);
                return true;
            }
            const auto* callee = call->getDirectCallee();
            if (!expression(call->getCallee(), depth + 1) ||
                !arguments(call, callee, depth)) return false;
            terminated_ = terminated_ || (callee && callee->isNoReturn()) ||
                          codeskeptic::isFatalCall(call);
            return true;
        }
        if (const auto* construct = dyn_cast<CXXConstructExpr>(expr)) {
            if (emptyArray(construct->getType())) return true;
            if (!arguments(construct, construct->getConstructor(), depth)) return false;
            terminated_ = terminated_ || construct->getConstructor()->isNoReturn();
            return true;
        }
        if (const auto* member = dyn_cast<MemberExpr>(expr))
            return expression(member->getBase(), depth + 1);
        if (const auto* subscript = dyn_cast<ArraySubscriptExpr>(expr)) {
            if (subscript->getBase()->HasSideEffects(ctx_) ||
                subscript->getIdx()->HasSideEffects(ctx_)) return false;
            return expression(subscript->getBase(), depth + 1) &&
                   expression(subscript->getIdx(), depth + 1);
        }
        if (const auto* init = dyn_cast<InitListExpr>(expr)) {
            for (const Expr* value : init->inits())
                if (!expression(value, depth + 1)) return false;
            return true;
        }
        if (const auto* cleanups = dyn_cast<ExprWithCleanups>(expr))
            return expression(cleanups->getSubExpr(), depth + 1);
        if (const auto* constant = dyn_cast<ConstantExpr>(expr))
            return expression(constant->getSubExpr(), depth + 1);
        if (const auto* temporary = dyn_cast<MaterializeTemporaryExpr>(expr)) {
            if (temporary->getStorageDuration() != SD_FullExpression) {
                const auto* bind = resultTemporary(temporary->getSubExpr());
                if (!bind && destructorDoesNotReturn(temporary->getType())) return false;
                if (bind) temporaryLifetimes_[bind] = temporary->getStorageDuration();
            }
            return expression(temporary->getSubExpr(), depth + 1);
        }
        if (const auto* temporary = dyn_cast<CXXBindTemporaryExpr>(expr)) {
            if (!expression(temporary->getSubExpr(), depth + 1)) return false;
            const auto* destructor = temporary->getTemporary()->getDestructor();
            if (destructor && destructor->getParent()->isAnyDestructorNoReturn()) {
                auto found = temporaryLifetimes_.find(temporary);
                if (found == temporaryLifetimes_.end() || found->second == SD_FullExpression)
                    fullExpressionTerminates_ = true;
                else if (found->second == SD_Automatic && !scopeTerminates_.empty())
                    scopeTerminates_.back() = true;
                // Static/thread lifetime extension does not destroy it here.
            }
            return true;
        }
        if (const auto* argument = dyn_cast<CXXDefaultArgExpr>(expr))
            return expression(argument->getExpr(), depth + 1);
        return isa<DeclRefExpr>(expr) || isa<IntegerLiteral>(expr) ||
               isa<CharacterLiteral>(expr) || isa<FloatingLiteral>(expr) ||
               isa<StringLiteral>(expr) || isa<CXXBoolLiteralExpr>(expr) ||
               isa<CXXNullPtrLiteralExpr>(expr) || isa<GNUNullExpr>(expr) ||
               isa<CXXThisExpr>(expr) || isa<ImplicitValueInitExpr>(expr) ||
               isa<CXXScalarValueInitExpr>(expr);
    }

    Flow statement(const Stmt* stmt, unsigned depth) {
        if (!stmt) return Flow::Continue;
        if (!enter(depth)) return Flow::Unsupported;
        if (const auto* block = dyn_cast<CompoundStmt>(stmt)) {
            scopeTerminates_.push_back(false);
            Flow flow = Flow::Continue;
            for (const Stmt* child : block->body()) {
                flow = statement(child, depth + 1);
                if (flow != Flow::Continue) break;
            }
            const bool cleanupStops = scopeTerminates_.back();
            scopeTerminates_.pop_back();
            if (flow == Flow::Continue && cleanupStops) {
                terminated_ = true;
                return Flow::Stop;
            }
            return flow;
        }
        if (const auto* declaration = dyn_cast<DeclStmt>(stmt)) {
            for (const Decl* decl : declaration->decls()) {
                const auto* var = dyn_cast<VarDecl>(decl);
                if (!var) continue;
                if (var->getType()->isVariablyModifiedType())
                    return Flow::Unsupported;
                const bool tracked = var->isLocalVarDecl() &&
                    !var->hasGlobalStorage() && var->getType()->isIntegerType() &&
                    !var->getType()->isEnumeralType() &&
                    !var->getType().isVolatileQualified();
                if (tracked) states_[var] = Initialization::Uninitialized;
                // A local static initializer has its own first-call guard;
                // do not interpret its side effects as unconditional stores.
                if (var->hasGlobalStorage() && var->hasInit() &&
                    var->getInit()->HasSideEffects(ctx_)) return Flow::Unsupported;
                if (!expression(var->getInit(), depth + 1)) return Flow::Unsupported;
                if (var->getType()->isReferenceType()) escape(var->getInit());
                if (tracked && var->hasInit())
                    states_[var] = Initialization::Initialized;
                if (!var->hasGlobalStorage() && !scopeTerminates_.empty() &&
                    destructorDoesNotReturn(var->getType()))
                    scopeTerminates_.back() = true;
                finishFullExpression();
                if (terminated_) return Flow::Stop;
            }
            return Flow::Continue;
        }
        if (const auto* ret = dyn_cast<ReturnStmt>(stmt))
            return expression(ret->getRetValue(), depth + 1)
                ? Flow::Stop : Flow::Unsupported;
        if (const auto* expr = dyn_cast<Expr>(stmt)) {
            if (!expression(expr, depth + 1)) return Flow::Unsupported;
            finishFullExpression();
            return terminated_ ? Flow::Stop : Flow::Continue;
        }
        if (isa<NullStmt>(stmt)) return Flow::Continue;
        // Branches/loops/labels/exception flow require the next CFG unit.
        return Flow::Unsupported;
    }

    ASTContext& ctx_;
    const FunctionDecl* function_;
    std::map<const VarDecl*, Initialization> states_;
    std::vector<std::vector<const VarDecl*>> escapeFrames_;
    std::map<const CXXBindTemporaryExpr*, StorageDuration> temporaryLifetimes_;
    std::vector<bool> scopeTerminates_;
    codeskeptic::DiagnosticList pending_;
    unsigned budget_ = 16384;
    bool terminated_ = false;
    bool fullExpressionTerminates_ = false;
};

// A deliberately narrow CFG extension. The straight-line interpreter above
// retains its verified C++ lifetime handling. This fallback admits scalar
// structured control, but not construction/destruction, exception edges or
// unspecified side-effect ordering. Lack of a finding outside that boundary
// is not a proof of initialization.
class ScalarFlow {
public:
    struct State {
        std::map<const VarDecl*, Initialization> values;
        bool live = true;
        bool operator!=(const State& other) const {
            return live != other.live || (live && values != other.values);
        }
    };

    ScalarFlow(ASTContext& ctx, const FunctionDecl* function)
        : ctx_(ctx), function_(function) {}

    void run(codeskeptic::DiagnosticList& results) {
        if (!collect(function_->getBody(), 0) || initial_.values.empty()) return;
        const auto flow = codeskeptic::runDataflow(function_, ctx_, *this);
        if (!flow.converged) {
            codeskeptic::CoverageReport::instance().recordDataflowFailure(
                function_->getQualifiedNameAsString(), flow.failure);
            return;
        }
        results.insert(results.end(), pending_.begin(), pending_.end());
    }

    State initialState() const { return initial_; }
    unsigned latticeHeight() const { return 3 * initial_.values.size() + 2; }

    State merge(const State& a, const State& b) const {
        if (!a.live) return b;
        if (!b.live) return a;
        State joined = a;
        for (auto& [var, value] : joined.values) {
            const auto other = b.values.at(var);
            if (value == other) continue;
            value = value == Initialization::Unknown || other == Initialization::Unknown
                ? Initialization::Unknown : Initialization::Maybe;
        }
        return joined;
    }

    State transfer(const Stmt* stmt, const State& before, ASTContext&) const {
        State after = before;
        if (!after.live) return after;
        // Clang splits a multi-declaration into synthetic single DeclStmts.
        // Their identities differ from the AST's original DeclStmt. Consume
        // the actual CFG declaration here, after its initializer's read events.
        if (const auto* decls = dyn_cast<DeclStmt>(stmt)) {
            for (const auto* decl : decls->decls()) {
                const auto* var = dyn_cast<VarDecl>(decl);
                if (!var) continue;
                if (auto stored = after.values.find(var); stored != after.values.end())
                    stored->second = var->hasInit() ? Initialization::Initialized
                                                   : Initialization::Uninitialized;
                if (var->getType()->isReferenceType()) {
                    const auto escaped = after.values.find(directVariable(var->getInit()));
                    if (escaped != after.values.end()) escaped->second = Initialization::Unknown;
                }
            }
        }
        if (const auto found = writes_.find(stmt); found != writes_.end()) {
            for (const auto& [var, value] : found->second) {
                auto stored = after.values.find(var);
                if (stored != after.values.end()) stored->second = value;
            }
        }
        if (stops_.count(stmt)) after.live = false;
        return after;
    }

    void onStatement(const Stmt* stmt, const State& before, const State&, ASTContext&) {
        if (!before.live) return;
        const auto found = reads_.find(stmt);
        if (found == reads_.end()) return;
        for (const auto& read : found->second) {
            const auto value = before.values.find(directVariable(read.expr));
            if (value != before.values.end())
                reportRead(read.expr, read.selfInitializer ? Initialization::Uninitialized
                                                         : value->second,
                           ctx_, function_, pending_);
        }
    }

private:
    struct Read { const Expr* expr; bool selfInitializer; };

    bool selectedStorage(const Expr* expr) const {
        // Selecting a scalar lvalue is not the same operation as selecting
        // a value. This domain does not retain the selected storage identity.
        for (unsigned depth = 0; expr && depth < 32; ++depth) {
            expr = expr->IgnoreParenImpCasts();
            if (isa<AbstractConditionalOperator>(expr)) return true;
            if (const auto* cast = dyn_cast<ExplicitCastExpr>(expr)) {
                expr = cast->getSubExpr();
            } else if (const auto* comma = dyn_cast<BinaryOperator>(expr);
                       comma && comma->getOpcode() == BO_Comma) {
                expr = comma->getRHS();
            } else {
                return false;
            }
        }
        return expr != nullptr;
    }

    bool enter(unsigned depth) {
        if (depth >= 128 || budget_ == 0) return false;
        --budget_;
        return true;
    }

    void read(const Stmt* event, const Expr* expr) {
        const auto* var = directVariable(expr);
        if (var) reads_[event].push_back({expr, var == initializer_});
    }

    void write(const Stmt* event, const Expr* expr, Initialization value) {
        if (const auto* var = directVariable(expr)) writes_[event].push_back({var, value});
    }

    bool expression(const Expr* expr, unsigned depth, const Stmt* escapeAt = nullptr) {
        if (!expr) return true;
        if (!enter(depth) || expr->isTypeDependent() || expr->isValueDependent()) return false;
        if (const auto* ref = dyn_cast<DeclRefExpr>(expr)) {
            // A loop-local declaration starts a new lifetime every iteration.
            // int x=x is always a fresh uninitialized read. More complicated
            // self-initializers with stores/escapes require a pre-init event;
            // do not reuse a previous iteration's initialized value for them.
            return ref->getDecl() != initializer_ ||
                !initializer_->getInit()->HasSideEffects(ctx_);
        }
        if (const auto* trait = dyn_cast<UnaryExprOrTypeTraitExpr>(expr))
            return !trait->getTypeOfArgument()->isVariablyModifiedType();
        if (isa<CXXNoexceptExpr>(expr) || isa<TypeTraitExpr>(expr)) return true;
        if (const auto* call = dyn_cast<CallExpr>(expr)) {
            const unsigned builtin = call->getBuiltinCallee();
            if (call->isUnevaluatedBuiltinCall(ctx_) ||
                builtin == Builtin::BI__builtin_assume || builtin == Builtin::BI__assume) {
                if (call->isBuiltinAssumeFalse(ctx_)) stops_.insert(call);
                return true;
            }
            if (!expression(call->getCallee(), depth + 1, call)) return false;
            const auto* callee = call->getDirectCallee();
            QualType calleeType = call->getCallee()->getType();
            if (calleeType->isPointerType() || calleeType->isReferenceType())
                calleeType = calleeType->getPointeeType();
            const auto* prototype = calleeType->getAs<FunctionProtoType>();
            unsigned index = 0;
            for (const auto* arg : call->arguments()) {
                if (arg->HasSideEffects(ctx_) || !expression(arg, depth + 1, call)) return false;
                const bool reference = callee && index < callee->getNumParams()
                    ? callee->getParamDecl(index)->getType()->isReferenceType()
                    : prototype && index < prototype->getNumParams() &&
                      prototype->getParamType(index)->isReferenceType();
                if (reference) {
                    if (selectedStorage(arg)) return false;
                    write(call, arg, Initialization::Unknown);
                }
                ++index;
            }
            if ((callee && callee->isNoReturn()) || codeskeptic::isFatalCall(call))
                stops_.insert(call);
            return true;
        }
        if (const auto* cast = dyn_cast<CastExpr>(expr)) {
            if (deliberateBareVoidDiscard(cast)) return true;
            if ((cast->getCastKind() == CK_LValueToRValue || cast->isGLValue()) &&
                selectedStorage(cast->getSubExpr())) return false;
            if (!expression(cast->getSubExpr(), depth + 1, escapeAt)) return false;
            if (cast->getCastKind() == CK_LValueToRValue) read(cast, cast->getSubExpr());
            if (isa<ExplicitCastExpr>(cast) && cast->isGLValue())
                write(escapeAt ? escapeAt : cast, cast->getSubExpr(), Initialization::Unknown);
            return true;
        }
        if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
            if ((unary->isIncrementDecrementOp() || unary->getOpcode() == UO_AddrOf) &&
                selectedStorage(unary->getSubExpr())) return false;
            if (!expression(unary->getSubExpr(), depth + 1, escapeAt)) return false;
            if (unary->isIncrementDecrementOp()) {
                read(unary, unary->getSubExpr());
                write(unary, unary->getSubExpr(), Initialization::Initialized);
            } else if (unary->getOpcode() == UO_AddrOf) {
                write(escapeAt ? escapeAt : unary, unary->getSubExpr(), Initialization::Unknown);
            }
            return true;
        }
        if (const auto* binary = dyn_cast<BinaryOperator>(expr)) {
            if (binary->isAssignmentOp() && selectedStorage(binary->getLHS())) return false;
            if (!binary->isAssignmentOp() && !binary->isLogicalOp() &&
                binary->getOpcode() != BO_Comma &&
                (binary->getLHS()->HasSideEffects(ctx_) ||
                 binary->getRHS()->HasSideEffects(ctx_))) return false;
            if (!expression(binary->getLHS(), depth + 1, escapeAt) ||
                !expression(binary->getRHS(), depth + 1, escapeAt)) return false;
            if (binary->isCompoundAssignmentOp()) read(binary, binary->getLHS());
            if (binary->isAssignmentOp()) write(binary, binary->getLHS(), Initialization::Initialized);
            return true;
        }
        if (const auto* conditional = dyn_cast<ConditionalOperator>(expr))
            return expression(conditional->getCond(), depth + 1, escapeAt) &&
                   expression(conditional->getTrueExpr(), depth + 1, escapeAt) &&
                   expression(conditional->getFalseExpr(), depth + 1, escapeAt);
        if (const auto* paren = dyn_cast<ParenExpr>(expr))
            return expression(paren->getSubExpr(), depth + 1, escapeAt);
        if (const auto* constant = dyn_cast<ConstantExpr>(expr))
            return expression(constant->getSubExpr(), depth + 1, escapeAt);
        if (const auto* member = dyn_cast<MemberExpr>(expr))
            return expression(member->getBase(), depth + 1, escapeAt);
        if (const auto* subscript = dyn_cast<ArraySubscriptExpr>(expr)) {
            if (subscript->getBase()->HasSideEffects(ctx_) || subscript->getIdx()->HasSideEffects(ctx_))
                return false;
            return expression(subscript->getBase(), depth + 1, escapeAt) &&
                   expression(subscript->getIdx(), depth + 1, escapeAt);
        }
        if (const auto* init = dyn_cast<InitListExpr>(expr)) {
            for (const auto* value : init->inits())
                if (!expression(value, depth + 1, escapeAt)) return false;
            return true;
        }
        return isa<IntegerLiteral>(expr) || isa<CharacterLiteral>(expr) ||
               isa<FloatingLiteral>(expr) || isa<StringLiteral>(expr) ||
               isa<CXXBoolLiteralExpr>(expr) || isa<CXXNullPtrLiteralExpr>(expr) ||
               isa<GNUNullExpr>(expr) || isa<CXXThisExpr>(expr) ||
               isa<ImplicitValueInitExpr>(expr) || isa<CXXScalarValueInitExpr>(expr);
    }

    bool collect(const Stmt* stmt, unsigned depth) {
        if (!stmt) return true;
        if (!enter(depth)) return false;
        if (const auto* expr = dyn_cast<Expr>(stmt)) return expression(expr, depth + 1);
        if (const auto* decls = dyn_cast<DeclStmt>(stmt)) {
            for (const auto* decl : decls->decls()) {
                const auto* var = dyn_cast<VarDecl>(decl);
                if (!var) continue;
                if (var->getType()->isVariablyModifiedType() ||
                    ctx_.getBaseElementType(var->getType())->isRecordType()) return false;
                if (var->hasGlobalStorage() && var->hasInit() &&
                    var->getInit()->HasSideEffects(ctx_)) return false;
                if (var->getType()->isReferenceType() && selectedStorage(var->getInit())) return false;
                const bool tracked = var->isLocalVarDecl() && !var->hasGlobalStorage() &&
                    var->getType()->isIntegerType() && !var->getType()->isEnumeralType() &&
                    !var->getType().isVolatileQualified();
                if (tracked) {
                    initial_.values[var] = Initialization::Uninitialized;
                }
                initializer_ = var;
                if (!expression(var->getInit(), depth + 1)) return false;
                initializer_ = nullptr;
            }
            return true;
        }
        if (isa<CompoundStmt>(stmt) || isa<IfStmt>(stmt) || isa<WhileStmt>(stmt) ||
            isa<DoStmt>(stmt) || isa<ForStmt>(stmt) || isa<ReturnStmt>(stmt)) {
            for (const auto* child : stmt->children())
                if (!collect(child, depth + 1)) return false;
            return true;
        }
        return isa<BreakStmt>(stmt) || isa<ContinueStmt>(stmt) || isa<NullStmt>(stmt);
    }

    ASTContext& ctx_;
    const FunctionDecl* function_;
    const VarDecl* initializer_ = nullptr;
    State initial_;
    std::map<const Stmt*, std::vector<Read>> reads_;
    std::map<const Stmt*, std::vector<std::pair<const VarDecl*, Initialization>>> writes_;
    std::set<const Stmt*> stops_;
    codeskeptic::DiagnosticList pending_;
    unsigned budget_ = 16384;
};

class ScalarCallback : public MatchFinder::MatchCallback {
public:
    explicit ScalarCallback(codeskeptic::DiagnosticList& results) : results_(results) {}
    void run(const MatchFinder::MatchResult& match) override {
        const auto* function = match.Nodes.getNodeAs<FunctionDecl>("function");
        if (!function || !function->hasBody() || function->isDependentContext()) return;
        const auto& sm = *match.SourceManager;
        if (sm.isInSystemHeader(function->getLocation()) ||
            !codeskeptic::functionFilterAllows(*function) ||
            !codeskeptic::lineFilterAllows(*function, sm)) return;
        if (!ScalarReads(*match.Context, function).run(results_))
            ScalarFlow(*match.Context, function).run(results_);
    }
private:
    codeskeptic::DiagnosticList& results_;
};

} // namespace

namespace codeskeptic {

std::string UninitScalarRule::id() const { return "uninit-scalar"; }
std::string UninitScalarRule::description() const {
    return "Experimental automatic integer/bool uninitialized reads and scalar CFG joins";
}
Severity UninitScalarRule::defaultSeverity() const { return Severity::Error; }
void UninitScalarRule::check(clang::ASTContext& ctx, DiagnosticList& results) {
    MatchFinder finder;
    ScalarCallback callback(results);
    finder.addMatcher(functionDecl(isDefinition(), hasBody(anything())).bind("function"),
                      &callback);
    finder.matchAST(ctx);
}

} // namespace codeskeptic
