#include "rules/UninitScalarRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
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
#include <utility>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

enum class Initialization { Uninitialized, Initialized, Unknown };
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

class ScalarReads {
public:
    ScalarReads(ASTContext& ctx, const FunctionDecl* function)
        : ctx_(ctx), function_(function) {}

    void run(codeskeptic::DiagnosticList& results) {
        // Do not publish a partial proof if a later unsupported control or
        // sequencing construct invalidates the straight-line interpretation.
        if (statement(function_->getBody(), 0) != Flow::Unsupported)
            results.insert(results.end(), pending_.begin(), pending_.end());
    }

private:
    bool enter(unsigned depth) {
        if (depth >= 128 || budget_ == 0) return false;
        --budget_;
        return true;
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
        const auto& sm = ctx_.getSourceManager();
        const auto loc = sm.getExpansionLoc(directReference(expr)->getExprLoc());
        if (loc.isInvalid() || sm.isInSystemHeader(loc)) return;
        codeskeptic::Diagnostic diag{};
        diag.severity = codeskeptic::Severity::Error;
        diag.file = sm.getFilename(loc).str();
        diag.line = sm.getSpellingLineNumber(loc);
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "uninit-scalar";
        diag.function = function_->getQualifiedNameAsString();
        diag.message = codeskeptic::currentLang() == codeskeptic::Lang::TR
            ? "Yerel tamsayı/bool '" + var->getNameAsString() +
                  "' başlatılmadan önce okunuyor (CWE-457)"
            : "Local integer/bool '" + var->getNameAsString() +
                  "' is read before initialization (CWE-457)";
        const auto decl = sm.getExpansionLoc(var->getLocation());
        diag.notes.push_back({sm.getFilename(decl).str(),
            sm.getSpellingLineNumber(decl), sm.getSpellingColumnNumber(decl),
            codeskeptic::msg(codeskeptic::MsgId::TraceDeclaredHere,
                             var->getNameAsString())});
        pending_.push_back(std::move(diag));
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
        if (const auto* construct = dyn_cast<CXXConstructExpr>(expr))
            return arguments(construct, construct->getConstructor(), depth);
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
        if (const auto* temporary = dyn_cast<MaterializeTemporaryExpr>(expr))
            return expression(temporary->getSubExpr(), depth + 1);
        if (const auto* temporary = dyn_cast<CXXBindTemporaryExpr>(expr))
            return expression(temporary->getSubExpr(), depth + 1);
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
            for (const Stmt* child : block->body()) {
                const auto flow = statement(child, depth + 1);
                if (flow != Flow::Continue) return flow;
            }
            return Flow::Continue;
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
                if (terminated_) return Flow::Stop;
            }
            return Flow::Continue;
        }
        if (const auto* ret = dyn_cast<ReturnStmt>(stmt))
            return expression(ret->getRetValue(), depth + 1)
                ? Flow::Stop : Flow::Unsupported;
        if (const auto* expr = dyn_cast<Expr>(stmt)) {
            if (!expression(expr, depth + 1)) return Flow::Unsupported;
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
    codeskeptic::DiagnosticList pending_;
    unsigned budget_ = 16384;
    bool terminated_ = false;
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
        ScalarReads(*match.Context, function).run(results_);
    }
private:
    codeskeptic::DiagnosticList& results_;
};

} // namespace

namespace codeskeptic {

std::string UninitScalarRule::id() const { return "uninit-scalar"; }
std::string UninitScalarRule::description() const {
    return "Experimental straight-line automatic integer/bool uninitialized reads";
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
