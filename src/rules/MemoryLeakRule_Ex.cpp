#include "rules/MemoryLeakRule_Ex.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/CoverageReport.h"
#include "engine/AllocFunctions.h"
#include "engine/CallRefArgs.h"
#include "engine/DataflowEngine.h"
#include "engine/FunctionSummary.h"
#include "engine/ConditionWalk.h"
#include "engine/GuardedDisjuncts.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Attr.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/ParentMapContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

#include <algorithm>
#include <functional>
#include <iostream>
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

// Per-disjunct pointer state. `binding` is a must-alias root: it is present
// only while an exact local pointer copy remains unchanged on every path
// represented by the disjunct. Allocation state stays attached to the
// variable that acquired it; bindings merely let a release/access resolve
// back to that owner. This deliberately does not model pointees, heap
// objects, fields, casts, or may-alias relations.
struct LifetimeState {
    AllocState allocation = AllocState::None;
    const VarDecl* binding = nullptr;
    bool referenceBinding = false;

    bool operator==(const LifetimeState& other) const {
        return allocation == other.allocation && binding == other.binding &&
               referenceBinding == other.referenceBinding;
    }
    bool operator!=(const LifetimeState& other) const {
        return !(*this == other);
    }
    bool operator<(const LifetimeState& other) const {
        if (allocation != other.allocation)
            return static_cast<unsigned>(allocation) <
                   static_cast<unsigned>(other.allocation);
        if (binding != other.binding)
            return std::less<const VarDecl*>{}(binding, other.binding);
        return referenceBinding < other.referenceBinding;
    }
};

LifetimeState mergeLifetimeStates(const LifetimeState& a,
                                  const LifetimeState& b) {
    LifetimeState result;
    result.allocation = mergeAllocStates(a.allocation, b.allocation);
    if (a.binding == b.binding &&
        a.referenceBinding == b.referenceBinding) {
        result.binding = a.binding;
        result.referenceBinding = a.referenceBinding;
    }
    return result;
}

// --- Statement classification ---

enum class StmtEffect { None, Allocates, Frees, Escapes };

// getName() is invalid on operator overloads — safe access
llvm::StringRef calleeName(const FunctionDecl* callee) {
    if (!callee) return {};
    if (const auto* id = callee->getIdentifier()) return id->getName();
    return {};
}

// A stdlib RESOURCE acquisition returning an owned handle that a matching
// close must release (CWE-404). fopen-family return FILE*, opendir a
// DIR* — both pointers, so the pointer-ownership machinery tracks them
// unchanged; the release side (fclose/closedir) is added to the free
// recognition. Not the raw-fd openers (open/socket/accept): those return
// an int, which the pointer-based leak domain cannot track — CWE-775
// strict is deferred to an integer-resource model (documented).
bool isResourceAcquireName(llvm::StringRef n) {
    return n == "fopen" || n == "freopen" || n == "fdopen" ||
           n == "tmpfile" || n == "opendir" || n == "fdopendir";
}

// The matching releases for the resources above.
bool isResourceReleaseName(llvm::StringRef n) {
    return n == "fclose" || n == "closedir";
}

bool isAllocExpr(const Expr* expr, ASTContext& /*ctx*/) {
    if (!expr) return false;
    expr = expr->IgnoreParenImpCasts();
    if (codeskeptic::isOwnedAllocationExpr(expr)) return true;
    if (const auto* call = dyn_cast<CallExpr>(expr)) {
        const auto* summary =
            codeskeptic::SummaryRegistry::instance().lookup(call);
        return summary &&
               summary->returnOwnership ==
                   codeskeptic::SummaryRegistry::ReturnOwnership::Owned;
    }
    return false;
}
const VarDecl* asVar(const Expr* expr) {
    if (!expr) return nullptr;
    // Explicit casts included: `(void*)copy` handed to a callback
    // registry and `reinterpret_cast<T*>(handle)` stored through an
    // out-param are still uses of the SAME pointer (shadPS4
    // SDL_AddTimer / OpenDevice FP families) — IgnoreParenImpCasts
    // alone hid the variable from the escape analysis.
    expr = expr->IgnoreParenCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

const VarDecl* asExactPointerVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    const auto* ref = dyn_cast<DeclRefExpr>(expr);
    if (!ref) return nullptr;
    const auto* var = dyn_cast<VarDecl>(ref->getDecl());
    if (!var || !var->hasLocalStorage()) return nullptr;
    QualType type = var->getType().getNonReferenceType();
    return type->isPointerType() ? var : nullptr;
}

QualType pointerBindingType(const VarDecl* var) {
    if (!var) return {};
    QualType type = var->getType().getNonReferenceType();
    return type->isPointerType()
               ? type.getCanonicalType().getUnqualifiedType()
               : QualType{};
}

bool sameExactPointerType(const VarDecl* lhs, const VarDecl* rhs) {
    QualType left = pointerBindingType(lhs);
    QualType right = pointerBindingType(rhs);
    return !left.isNull() && !right.isNull() && left == right;
}

struct BindingUpdate {
    const VarDecl* lhs = nullptr;
    const VarDecl* rhs = nullptr;
    bool deferred = false;
    bool throughReference = false;
};

std::vector<BindingUpdate> pointerBindingUpdates(const Stmt* stmt) {
    std::vector<BindingUpdate> updates;
    if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
        for (const Decl* decl : declStmt->decls()) {
            const auto* lhs = dyn_cast<VarDecl>(decl);
            if (!lhs || !lhs->hasLocalStorage() || !lhs->hasInit() ||
                pointerBindingType(lhs).isNull())
                continue;
            const VarDecl* rhs = asExactPointerVar(lhs->getInit());
            updates.push_back(
                {lhs, sameExactPointerType(lhs, rhs) ? rhs : nullptr});
        }
        return updates;
    }
    const auto* assignment = dyn_cast<BinaryOperator>(stmt);
    if (assignment && assignment->getOpcode() == BO_Assign) {
        const VarDecl* lhs = asExactPointerVar(assignment->getLHS());
        if (!lhs) return updates;
        const VarDecl* rhs = asExactPointerVar(assignment->getRHS());
        updates.push_back({lhs,
                           sameExactPointerType(lhs, rhs) ? rhs : nullptr,
                           false,
                           lhs->getType()->isReferenceType()});
        return updates;
    }

    const auto* call = dyn_cast<CallExpr>(stmt);
    if (!call) return updates;
    std::set<const VarDecl*> invalidated;
    auto addInvalidation = [&](const VarDecl* var) {
        if (var && invalidated.insert(var).second)
            updates.push_back({var, nullptr, true, false});
    };
    for (const Expr* argument : call->arguments()) {
        const Expr* core = argument->IgnoreParenCasts();
        const auto* address = dyn_cast<UnaryOperator>(core);
        if (!address || address->getOpcode() != UO_AddrOf) continue;
        addInvalidation(asExactPointerVar(address->getSubExpr()));
    }
    codeskeptic::forEachNonConstRefArg(
        call, [&](const Expr* argument) {
            addInvalidation(asExactPointerVar(argument));
        });
    return updates;
}

const CallExpr* coreCall(const Expr* expr) {
    if (!expr) return nullptr;
    const Expr* current = expr;
    while (current) {
        current = current->IgnoreParenImpCasts();
        if (const auto* cast = dyn_cast<CastExpr>(current)) {
            current = cast->getSubExpr();
            continue;
        }
        if (const auto* cleanups = dyn_cast<ExprWithCleanups>(current)) {
            current = cleanups->getSubExpr();
            continue;
        }
        break;
    }
    return dyn_cast_or_null<CallExpr>(current);
}

const VarDecl* reallocInput(const Expr* expr) {
    const CallExpr* call = coreCall(expr);
    if (!call || call->getNumArgs() == 0) return nullptr;
    const FunctionDecl* callee = call->getDirectCallee();
    const IdentifierInfo* id = callee ? callee->getIdentifier() : nullptr;
    if (!id || (id->getName() != "realloc" &&
                id->getName() != "reallocarray"))
        return nullptr;
    return asVar(call->getArg(0));
}

std::map<const VarDecl*, const VarDecl*> collectReallocSources(
        const FunctionDecl* function) {
    struct Visitor : RecursiveASTVisitor<Visitor> {
        std::map<const VarDecl*, const VarDecl*> sources;

        void record(const VarDecl* result, const Expr* value) {
            const VarDecl* source = reallocInput(value);
            if (!result || !source || !result->hasLocalStorage() ||
                !source->hasLocalStorage())
                return;
            auto [it, inserted] = sources.emplace(result, source);
            if (!inserted && it->second != source) it->second = nullptr;
        }

        bool VisitVarDecl(VarDecl* declaration) {
            if (declaration->hasInit())
                record(declaration, declaration->getInit());
            return true;
        }

        bool VisitBinaryOperator(BinaryOperator* assignment) {
            if (assignment->getOpcode() == BO_Assign)
                record(asExactPointerVar(assignment->getLHS()),
                       assignment->getRHS());
            return true;
        }

        bool TraverseLambdaExpr(LambdaExpr*) { return true; }
    } visitor;
    visitor.TraverseStmt(const_cast<Stmt*>(function->getBody()));
    return visitor.sources;
}

// `&var->member`, `&var.member`, `&var` (chained members/subscripts
// included): taking the address of an object or of one of its members
// keeps the WHOLE object reachable through the handed-out pointer —
// the object escapes wherever that address escapes. The libgit2
// iterator pattern (`*out = &it->parent;` — the caller later frees
// through the parent pointer) and the fprime font pattern
// (`*glyph_out = &boxed->glyph;`) are both this shape.
const VarDecl* addrOfMemberBase(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenCasts();
    const auto* unary = dyn_cast<UnaryOperator>(expr);
    if (!unary || unary->getOpcode() != UO_AddrOf) return nullptr;
    const Expr* inner = unary->getSubExpr()->IgnoreParenCasts();
    while (true) {
        if (const auto* member = dyn_cast<MemberExpr>(inner))
            inner = member->getBase()->IgnoreParenCasts();
        else if (const auto* sub = dyn_cast<ArraySubscriptExpr>(inner))
            inner = sub->getBase()->IgnoreParenCasts();
        else
            break;
    }
    if (const auto* ref = dyn_cast<DeclRefExpr>(inner))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

// Is this class-type an OWNING smart pointer — one that adopts (takes
// ownership of, and later frees) a raw pointer handed to its
// constructor? std::unique_ptr / shared_ptr / auto_ptr are recognized
// built-in; project wrappers (Jolt's Ref<T>, WebKit's RefPtr<T>,
// Chromium's scoped_refptr<T>) are added via --owning-pointers. NOT
// owning, deliberately excluded: non-adopting views (std::span,
// string_view) and copying wrappers (std::string(char*) copies the
// bytes — the raw pointer still leaks), which is exactly why a blanket
// "constructed-from-a-pointer" rule would be wrong and this stays a
// name allow-list.
bool isOwningSmartPointerType(QualType qt) {
    const auto* rec = qt->getAsCXXRecordDecl();
    if (!rec) return false;
    const llvm::StringRef name = rec->getName();
    if (name.empty()) return false;
    if (rec->isInStdNamespace() &&
        (name == "unique_ptr" || name == "shared_ptr" ||
         name == "auto_ptr"))
        return true;
    return codeskeptic::owningPointerNames().count(name.str()) != 0;
}

// If `expr` (a return value or a variable initializer) is the
// construction of an owning smart pointer that adopts a tracked raw
// pointer, return that raw pointer. Peels the temporary-materialization
// wrappers that sit between a `return`/init and the CXXConstructExpr:
//   return std::unique_ptr<S>(p);   // A  (explicit ctor)
//   Ref<S> f() { ... return p; }    // B  (implicit ctor, configured)
//   std::unique_ptr<S> up(p);       // D  (adoption into a local)
// The move/copy constructors take a smart-pointer argument, never a
// tracked RAW pointer, so they never match — only genuine adoption of
// a `new`-ed pointer does.
const VarDecl* adoptedRawPointer(const Expr* expr,
                                 const std::set<const VarDecl*>& tracked) {
    if (!expr) return nullptr;
    const Expr* e = expr;
    while (e) {
        e = e->IgnoreParenImpCasts();
        if (const auto* ewc = dyn_cast<ExprWithCleanups>(e)) {
            e = ewc->getSubExpr();
        } else if (const auto* mte = dyn_cast<MaterializeTemporaryExpr>(e)) {
            e = mte->getSubExpr();
        } else if (const auto* bte = dyn_cast<CXXBindTemporaryExpr>(e)) {
            e = bte->getSubExpr();
        } else if (const auto* fce = dyn_cast<CXXFunctionalCastExpr>(e)) {
            e = fce->getSubExpr();
        } else {
            break;
        }
    }
    const auto* ctor = dyn_cast_or_null<CXXConstructExpr>(e);
    if (!ctor || !isOwningSmartPointerType(ctor->getType()))
        return nullptr;
    for (unsigned i = 0; i < ctor->getNumArgs(); ++i) {
        const VarDecl* var = asVar(ctor->getArg(i));
        if (var && tracked.count(var) &&
            var->getType()->isPointerType())
            return var;
    }
    return nullptr;
}

// Any tracked pointer CAPTURED by a lambda (`[&]{ Free(p); }`,
// `[p]{...}`) leaves our view: the closure body is a separate function
// we do not analyze, and it may free, store or transfer the pointer.
// This is the scope-guard idiom (JPH_SCOPE_EXIT, absl::Cleanup,
// `[ctx]{ delete ctx; }`) and, more generally, the same
// escaped-on-opaque-call posture applied to closures. Conservative
// escape: it only silences a leak (never fabricates a free/UAF).
void collectLambdaCaptures(const Expr* expr,
                           const std::set<const VarDecl*>& tracked,
                           std::vector<const VarDecl*>& out) {
    if (!expr) return;
    const Expr* e = expr->IgnoreParenImpCasts();
    if (const auto* mte = dyn_cast<MaterializeTemporaryExpr>(e))
        e = mte->getSubExpr()->IgnoreParenImpCasts();
    if (const auto* bte = dyn_cast<CXXBindTemporaryExpr>(e))
        e = bte->getSubExpr()->IgnoreParenImpCasts();
    const auto* lambda = dyn_cast<LambdaExpr>(e);
    if (!lambda) return;
    for (const LambdaCapture& cap : lambda->captures()) {
        if (!cap.capturesVariable()) continue;
        const auto* var = dyn_cast<VarDecl>(cap.getCapturedVar());
        if (var && tracked.count(var))
            out.push_back(var);
    }
}

// Dereference detection (for use-after-free). Since the CFG is
// fine-grained, looking only at the top node is enough.
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

// If the same variable appears in multiple call positions the most
// conservative wins: Escapes > Frees > ReadsOnly.
struct VarCallEffect { bool escapes = false; bool frees = false; };

// Marks every tracked variable referenced anywhere inside a composite
// call argument as escaping (aggregate initializers, constructor
// arguments wrapping the pointer). Bare-variable arguments are handled
// separately with summary-driven precision.
void collectNestedTrackedRefs(const Stmt* stmt,
                              const std::set<const VarDecl*>& tracked,
                              std::map<const VarDecl*, VarCallEffect>& byVar) {
    if (!stmt) return;
    if (const auto* ref = dyn_cast<DeclRefExpr>(stmt)) {
        if (const auto* var = dyn_cast<VarDecl>(ref->getDecl()))
            if (tracked.count(var)) byVar[var].escapes = true;
        return;
    }
    // Do not descend through a dereference: `f(*data)` / `f(data->x)`
    // reads the POINTEE — the pointer itself is not handed over, the
    // leak must stay visible (Juliet print-the-value sinks).
    if (const auto* unary = dyn_cast<UnaryOperator>(stmt))
        if (unary->getOpcode() == UO_Deref) return;
    if (const auto* member = dyn_cast<MemberExpr>(stmt))
        if (member->isArrow()) return;
    if (isa<ArraySubscriptExpr>(stmt)) return;
    // Nested calls are their own fine-grained CFG elements and get the
    // summary-driven treatment there — descending would override a
    // ReadsOnly verdict with a blanket escape.
    if (isa<CallExpr>(stmt)) return;
    for (const Stmt* child : stmt->children())
        collectNestedTrackedRefs(child, tracked, byVar);
}

// Top-node Effect pattern (as in UninitPtr): the expression is
// classified ONCE and itself reports the effects on the tracked
// variables it touches — no per-variable rescanning. In the
// fine-grained CFG each element comes with its own top node, so no
// nested search is needed.
using StmtEffects = std::vector<std::pair<const VarDecl*, StmtEffect>>;

StmtEffects classifyStmtEffects(const Stmt* stmt,
                                const std::set<const VarDecl*>& tracked,
                                ASTContext& ctx) {
    StmtEffects effects;

    // Ownership adoption into an owning smart pointer / capture into a
    // lambda: both hand a tracked raw pointer to something that will
    // manage or free it. Detected here — ahead of the raw dyn_casts —
    // so it fires uniformly for the return-value, DeclStmt-initializer
    // and bare-construct CFG-element shapes. Appends and falls through:
    // the effect below is Escapes, which never collides with the
    // Allocates/Frees the concrete handlers emit for the same node.
    {
        const Expr* adoptExpr = nullptr;
        if (const auto* ret = dyn_cast<ReturnStmt>(stmt))
            adoptExpr = ret->getRetValue();
        else if (const auto* e = dyn_cast<Expr>(stmt))
            adoptExpr = e;

        std::vector<const VarDecl*> escaped;
        if (const VarDecl* a = adoptedRawPointer(adoptExpr, tracked))
            escaped.push_back(a);
        collectLambdaCaptures(adoptExpr, tracked, escaped);

        if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
            for (const auto* decl : declStmt->decls()) {
                const auto* vd = dyn_cast<VarDecl>(decl);
                if (!vd || !vd->hasInit()) continue;
                if (const VarDecl* a =
                        adoptedRawPointer(vd->getInit(), tracked))
                    escaped.push_back(a);
                collectLambdaCaptures(vd->getInit(), tracked, escaped);
            }
        }
        for (const VarDecl* var : escaped)
            effects.emplace_back(var, StmtEffect::Escapes);
    }

    if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
        for (const auto* decl : declStmt->decls()) {
            if (const auto* vd = dyn_cast<VarDecl>(decl)) {
                if (!vd->hasInit()) continue;
                if (tracked.count(vd) && isAllocExpr(vd->getInit(), ctx)) {
                    effects.emplace_back(vd, StmtEffect::Allocates);
                    continue;
                }
                // `typeof(b) *_b = &(b);` — systemd's free_and_replace
                // takes the pointer's OWN address in an INIT, not an
                // assignment; same conservative escape as the
                // assignment form (ownership can move through _b).
                const Expr* init = vd->getInit()->IgnoreParenCasts();
                if (const auto* u = dyn_cast<UnaryOperator>(init)) {
                    if (u->getOpcode() == UO_AddrOf &&
                        isa<DeclRefExpr>(
                            u->getSubExpr()->IgnoreParenCasts())) {
                        const VarDecl* src = addrOfMemberBase(init);
                        if (src && tracked.count(src))
                            effects.emplace_back(src,
                                                 StmtEffect::Escapes);
                    }
                }
            }
        }
        return effects;
    }
    if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
        if (binOp->getOpcode() == BO_Assign) {
            const VarDecl* lhs = asVar(binOp->getLHS());
            if (lhs && tracked.count(lhs) &&
                isAllocExpr(binOp->getRHS(), ctx))
                effects.emplace_back(lhs, StmtEffect::Allocates);

            // Storing a tracked pointer into something that outlives the
            // local scope is an escape: a `this` member (`slot_ = copy;`,
            // the abseil CrcCordState pattern), a global/static, a
            // param-reachable or deref/array target. Deliberately NOT
            // escapes (Juliet guard taught this, 2026-07-12):
            //  - a plain LOCAL-to-local copy (`dataCopy = data;` alias
            //    leaks must stay visible on the original), and
            //  - a member of a LOCAL aggregate (`myStruct.ptr = data;` —
            //    the aggregate itself dies at function end, the leak is
            //    real; the Juliet 66/67 struct-passing families).
            // Does the LHS shape make the stored value outlive our
            // view? (Independent of what the RHS turns out to be.)
            const Expr* lhsExpr = binOp->getLHS()->IgnoreParenImpCasts();
            bool lhsEscapes;
            if (lhs) {
                lhsEscapes = !lhs->hasLocalStorage();  // global/static
            } else if (const auto* member =
                           dyn_cast<MemberExpr>(lhsExpr)) {
                if (member->isArrow()) {
                    lhsEscapes = true;  // pointee may live anywhere
                } else {
                    const VarDecl* base = asVar(member->getBase());
                    // local (non-param) aggregate: stays local;
                    // param/global/this/complex base: escapes.
                    // A reference base refers to storage owned
                    // elsewhere (`ImGuiIO& io = GetIO();
                    // io.UserData = bd;` — shadPS4 imgui backends),
                    // so it escapes too.
                    lhsEscapes = !(base && base->hasLocalStorage() &&
                                   !isa<ParmVarDecl>(base) &&
                                   !base->getType()->isReferenceType());
                }
            } else {
                lhsEscapes = true;  // *p = q, arr[i] = q, this-member...
            }

            const VarDecl* rhsVar = asVar(binOp->getRHS());
            bool bareAddressTaken = false;
            if (!rhsVar) {
                rhsVar = addrOfMemberBase(binOp->getRHS());
                // Distinguish `&p` (an alias to the POINTER itself —
                // ownership can move through it, the free_and_replace
                // macro) from `&p->member` (an alias INTO the pointee —
                // storing it in an ignored local saves nothing, the
                // fprime font pin).
                if (rhsVar) {
                    const Expr* r = binOp->getRHS()->IgnoreParenCasts();
                    if (const auto* u = dyn_cast<UnaryOperator>(r))
                        bareAddressTaken = isa<DeclRefExpr>(
                            u->getSubExpr()->IgnoreParenCasts());
                }
            }
            if (!rhsVar) {
                // Chained assignment: `*out = counts = git__calloc(...)`
                // stores the same value the inner assignment gave to
                // `counts` — the escape applies to that variable (the
                // libgit2 checkout out-param idiom).
                const Expr* rhs = binOp->getRHS()->IgnoreParenCasts();
                if (const auto* inner = dyn_cast<BinaryOperator>(rhs))
                    if (inner->getOpcode() == BO_Assign)
                        rhsVar = asVar(inner->getLHS());
            }
            if (rhsVar && tracked.count(rhsVar) && rhsVar != lhs) {
                // Storing the pointer's OWN address creates an alias
                // through which ownership can move even via a local
                // (`_b = &(p); *_a = *_b;` — systemd's
                // free_and_replace macro): conservative escape
                // regardless of the LHS. A MEMBER address into an
                // ignored local saves nothing (the fprime font pin
                // stays a leak).
                if (lhsEscapes || bareAddressTaken)
                    effects.emplace_back(rhsVar, StmtEffect::Escapes);
            } else if (!rhsVar && lhsEscapes) {
                // The pointer may ride INSIDE a composite RHS assigned
                // to escaping storage: statement expressions
                // (`*ret = TAKE_PTR(cs);`), compound literals
                // (`*ret = IOVEC_MAKE(buf, n);`). Same subtree walk as
                // composite call arguments. LOCAL-lhs stashes are
                // deliberately NOT walked — `myStruct.ptr = data;`
                // stays a visible leak (the Juliet 66/67 pin).
                std::map<const VarDecl*, VarCallEffect> byVar;
                collectNestedTrackedRefs(binOp->getRHS(), tracked, byVar);
                for (const auto& [v, e] : byVar) {
                    (void)e;
                    if (v != lhs)
                        effects.emplace_back(v, StmtEffect::Escapes);
                }
            }
        }
        return effects;
    }
    if (const auto* del = dyn_cast<CXXDeleteExpr>(stmt)) {
        const VarDecl* var = asVar(del->getArgument());
        if (var && tracked.count(var))
            effects.emplace_back(var, StmtEffect::Frees);
        return effects;
    }
    if (const auto* call = dyn_cast<CallExpr>(stmt)) {
        const FunctionDecl* callee = call->getDirectCallee();
        const llvm::StringRef name = calleeName(callee);
        const bool isFreeByName =
            name == "free" || isResourceReleaseName(name) ||
            (!name.empty() &&
             codeskeptic::freeFunctionNames().count(name.str()) != 0);
        const auto* summary =
            codeskeptic::SummaryRegistry::instance().lookup(call);
        using PO = codeskeptic::SummaryRegistry::ParamOwnership;
        unsigned argOffset = 0;
        if (isa<CXXOperatorCallExpr>(call)) {
            const auto* method =
                dyn_cast_or_null<CXXMethodDecl>(call->getDirectCallee());
            if (method && !method->isStatic()) argOffset = 1;
        }

        // &var is always Escapes (the callee may reassign/free it).
        std::map<const VarDecl*, VarCallEffect> byVar;

        // Method call: `p->Track()` may stash `this` anywhere (observer/
        // registry registration — the abseil CordzInfo pattern). The
        // receiver escapes conservatively. Use-after-free stays intact:
        // the receiver's MemberExpr is its own (earlier) CFG element and
        // is checked against the pre-call state.
        if (const auto* memberCall = dyn_cast<CXXMemberCallExpr>(call)) {
            if (const VarDecl* recv =
                    asVar(memberCall->getImplicitObjectArgument()))
                if (tracked.count(recv)) byVar[recv].escapes = true;
        }

        // An argument bound to a NON-CONST reference parameter
        // (`T*& handle`) lets the callee reassign or stash the
        // caller's pointer — always an escape, whatever the summary
        // says about by-value semantics.
        codeskeptic::forEachNonConstRefArg(call, [&](const Expr* refArg) {
            const VarDecl* var = asVar(refArg);
            if (var && tracked.count(var)) byVar[var].escapes = true;
        });

        for (unsigned i = 0; i < call->getNumArgs(); ++i) {
            const Expr* arg = call->getArg(i);
            if (const auto* unary = dyn_cast<UnaryOperator>(
                    arg->IgnoreParenImpCasts())) {
                if (unary->getOpcode() == UO_AddrOf) {
                    // &var AND &var->member both hand out a way to
                    // reach (and free) the object.
                    const VarDecl* var = addrOfMemberBase(arg);
                    if (var && tracked.count(var))
                        byVar[var].escapes = true;
                }
                continue;
            }
            const VarDecl* var = asVar(arg);
            if (!var || !tracked.count(var)) {
                // The pointer may sit INSIDE a composite argument:
                // `push_back(AudioData{.buf = cast(mix_s16), ...})`
                // (shadPS4 audio3d). Any tracked variable referenced
                // anywhere within the argument subtree escapes —
                // the receiving object outlives our view of it.
                // Bare-variable args keep the summary-driven logic
                // below, so Juliet's `printLine(data)` sinks are
                // unaffected.
                collectNestedTrackedRefs(arg, tracked, byVar);
                continue;
            }
            if (isFreeByName && i == 0) {
                byVar[var].frees = true;
                continue;
            }
            PO ownership =
                summary && i >= argOffset
                    ? summary->paramOwnership(i - argOffset)
                    : PO::Unknown;
            switch (ownership) {
                case PO::Transferred:
                case PO::Unknown:  byVar[var].escapes = true; break;
                case PO::Consumed: byVar[var].frees = true; break;
                case PO::Borrowed: byVar[var]; break;  // leak stays visible
            }
        }
        for (const auto& [var, e] : byVar) {
            if (e.escapes)
                effects.emplace_back(var, StmtEffect::Escapes);
            else if (e.frees)
                effects.emplace_back(var, StmtEffect::Frees);
            // ReadsOnly-only: no effect (the leak stays visible)
        }
        return effects;
    }
    if (const auto* ret = dyn_cast<ReturnStmt>(stmt)) {
        const VarDecl* var = asVar(ret->getRetValue());
        if (!var)
            var = addrOfMemberBase(ret->getRetValue());
        if (var && tracked.count(var))
            effects.emplace_back(var, StmtEffect::Escapes);
    }
    return effects;
}

// --- Collect tracked pointer variables ---

std::vector<const VarDecl*> collectTrackedVars(const FunctionDecl* funcDecl,
                                                ASTContext& ctx) {
    std::set<const VarDecl*> vars;

    // The matchers only pre-select CANDIDATES (pointer var initialized /
    // assigned from any expression); the real allocation test is
    // isAllocExpr — one place that knows the built-in names, the
    // --alloc-functions registry, casts and the placement-new
    // exemption. The old per-name matcher list silently missed realloc
    // and could never see registered wrappers.
    auto candidateInit = varDecl(
        hasType(pointerType()),
        hasInitializer(expr())
    ).bind("var");
    auto candidateAssign = binaryOperator(
        hasOperatorName("="),
        hasLHS(ignoringParenImpCasts(declRefExpr(
            to(varDecl(hasType(pointerType())).bind("var")))))
    ).bind("assign");

    // Only automatic-storage locals are tracked. A static local or a
    // global assigned an allocation is NOT an end-of-function leak: its
    // lifetime is program-long and the "leak on purpose" singleton
    // (`static Mutex* mu = new Mutex;` — deliberate Google style to
    // dodge destruction-order fiasco) is idiomatic real-world code.
    // A variable with __attribute__((cleanup(fn))) cannot leak by
    // construction — the compiler runs fn at every scope exit
    // (systemd's _cleanup_free_, GLib's g_autofree; 111 of systemd's
    // findings were this shape). v1 excludes them from tracking
    // entirely; modeling the cleanup as a scope-exit free (to catch
    // `free(p)` double-frees under a cleanup attribute) is the v2
    // design, noted in todo.
    auto trackable = [](const VarDecl* v) {
        return v->hasLocalStorage() && !v->hasAttr<CleanupAttr>();
    };

    auto wrapper = functionDecl(equalsNode(funcDecl),
                                 forEachDescendant(candidateInit));
    for (const auto& result : match(wrapper, *funcDecl, ctx)) {
        const auto* v = result.getNodeAs<VarDecl>("var");
        if (v && trackable(v) && v->hasInit() &&
            isAllocExpr(v->getInit(), ctx))
            vars.insert(v);
    }
    for (const auto& result :
         match(findAll(candidateAssign), *funcDecl->getBody(), ctx)) {
        const auto* v = result.getNodeAs<VarDecl>("var");
        const auto* assign = result.getNodeAs<BinaryOperator>("assign");
        if (v && assign && trackable(v) &&
            isAllocExpr(assign->getRHS(), ctx))
            vars.insert(v);
    }
    return {vars.begin(), vars.end()};
}

// Flow-insensitive inventory of local pointer-copy candidates. This pass
// admits alias variables into the dataflow state; it conveys no lifetime
// evidence. Exact bindings are created, invalidated, and merged separately
// per guarded disjunct during transfer.
std::map<const VarDecl*, std::vector<const VarDecl*>> collectAliasInventory(
        const FunctionDecl* funcDecl, ASTContext& ctx,
        const std::set<const VarDecl*>& tracked) {
    std::map<const VarDecl*, const VarDecl*> parent;  // union-find
    std::function<const VarDecl*(const VarDecl*)> find =
        [&](const VarDecl* v) -> const VarDecl* {
        auto it = parent.find(v);
        if (it == parent.end() || it->second == v) return v;
        return parent[v] = find(it->second);
    };
    auto unite = [&](const VarDecl* a, const VarDecl* b) {
        parent.emplace(a, a);
        parent.emplace(b, b);
        const VarDecl* ra = find(a);
        const VarDecl* rb = find(b);
        if (ra != rb) parent[ra] = rb;
    };
    auto pointerLike = [](const VarDecl* v) {
        if (!v) return false;
        QualType type = v->getType();
        if (type->isPointerType()) return true;
        return type->isReferenceType() &&
               type->getPointeeType()->isPointerType();
    };
    auto localPair = [&](const VarDecl* l, const VarDecl* r) {
        return l && r && l != r && l->hasLocalStorage() &&
               r->hasLocalStorage() && pointerLike(l) && pointerLike(r);
    };

    auto copyAssign =
        binaryOperator(hasOperatorName("=")).bind("assign");
    for (const auto& result :
         match(findAll(copyAssign), *funcDecl->getBody(), ctx)) {
        const auto* assign = result.getNodeAs<BinaryOperator>("assign");
        if (!assign) continue;
        const VarDecl* l = asVar(assign->getLHS());
        const VarDecl* r = asVar(assign->getRHS());
        if (localPair(l, r)) unite(l, r);
    }

    auto copyInit =
        varDecl(hasInitializer(expr().bind("init"))).bind("lhs");
    auto wrapper = functionDecl(equalsNode(funcDecl),
                                 forEachDescendant(copyInit));
    for (const auto& result : match(wrapper, *funcDecl, ctx)) {
        const auto* l = result.getNodeAs<VarDecl>("lhs");
        const auto* init = result.getNodeAs<Expr>("init");
        const VarDecl* r = asVar(init);
        if (localPair(l, r)) unite(l, r);
    }

    std::map<const VarDecl*, std::vector<const VarDecl*>> byRoot;
    for (const auto& [v, _] : parent) byRoot[find(v)].push_back(v);
    std::map<const VarDecl*, std::vector<const VarDecl*>> groups;
    for (const auto& [root, members] : byRoot) {
        (void)root;
        if (members.size() < 2) continue;
        bool ownsTracked = false;
        for (const VarDecl* v : members)
            if (tracked.count(v)) {
                ownsTracked = true;
                break;
            }
        if (!ownsTracked) continue;
        for (const VarDecl* v : members) {
            auto& list = groups[v];
            for (const VarDecl* other : members)
                if (other != v) list.push_back(other);
        }
    }
    return groups;
}

// --- Branch condition refinement (assume edges) ---

using VarState = std::map<const VarDecl*, LifetimeState>;

const VarDecl* resolveBinding(const VarDecl* var, const VarState& state) {
    if (!var) return nullptr;
    std::set<const VarDecl*> seen;
    const VarDecl* current = var;
    bool followedCopy = false;
    while (current && seen.insert(current).second) {
        auto it = state.find(current);
        if (it == state.end()) return nullptr;
        if (it->second.referenceBinding) {
            if (!it->second.binding) return nullptr;
            current = it->second.binding;
            followedCopy = false;
            continue;
        }
        if (!it->second.binding)
            return followedCopy && it->second.allocation != AllocState::None
                       ? current
                       : nullptr;
        if (it->second.binding == current) return current;
        followedCopy = true;
        current = it->second.binding;
    }
    return nullptr;
}

void invalidateBindingDependents(VarState& state, const VarDecl* overwritten) {
    if (!overwritten) return;
    for (auto& [var, lifetime] : state) {
        // A local pointer reference aliases the variable itself, not the
        // variable's current pointer value. Reassigning that variable must
        // invalidate copied pointer values while leaving `T*& ref = owner`
        // bound to `owner`.
        if (var == overwritten || var->getType()->isReferenceType() ||
            !lifetime.binding)
            continue;
        std::set<const VarDecl*> seen;
        const VarDecl* current = var;
        while (current && seen.insert(current).second) {
            auto it = state.find(current);
            if (it == state.end() || !it->second.binding) break;
            if (it->second.binding == overwritten) {
                lifetime.binding = nullptr;
                break;
            }
            if (it->second.binding == current) break;
            current = it->second.binding;
        }
    }
}

void applyBindingUpdate(VarState& state, const BindingUpdate& update) {
    auto lhs = state.find(update.lhs);
    if (lhs == state.end()) return;
    if (update.rhs == update.lhs) return;
    if (update.throughReference) {
        const VarDecl* overwritten = resolveBinding(update.lhs, state);
        if (overwritten) {
            state[overwritten].allocation = AllocState::Escaped;
            state[overwritten].binding = nullptr;
            state[overwritten].referenceBinding = false;
        }
        if (!update.lhs->getType()->isReferenceType())
            state[update.lhs].binding = nullptr;
        return;
    }
    const bool bindsVariable = update.lhs->getType()->isReferenceType();
    const VarDecl* rhsRoot = bindsVariable
                                 ? update.rhs
                                 : resolveBinding(update.rhs, state);
    if (bindsVariable && rhsRoot &&
        rhsRoot->getType()->isReferenceType()) {
        auto rhs = state.find(rhsRoot);
        rhsRoot = rhs != state.end() ? rhs->second.binding : nullptr;
    }
    lhs = state.find(update.lhs);
    lhs->second.binding = rhsRoot;
    lhs->second.referenceBinding = bindsVariable && rhsRoot;
}

bool provesNonNull(const codeskeptic::Guarded<VarState>& disjunct,
                   const VarDecl* var) {
    if (!var) return false;
    auto it = disjunct.facts.find(
        codeskeptic::FactKey{var, BO_EQ, 0, nullptr});
    return it != disjunct.facts.end() && !it->second;
}

// On an edge known to be null there is no "allocation": the malloc/new
// failure path is NOT a leak (p = malloc; if (!p) return;).
// The walk comes from the shared skeleton (engine/ConditionWalk.h); this
// domain only cares about the null edge and ignores non-null knowledge.
void applyNullCondition(const Expr* cond, bool isTrue, VarState& state) {
    codeskeptic::walkNullCondition(
        cond, isTrue, [&](const VarDecl* var, bool isNull) {
            if (!isNull) return;
            const VarDecl* owner = resolveBinding(var, state);
            auto it = owner ? state.find(owner) : state.end();
            if (it != state.end() &&
                it->second.allocation == AllocState::Allocated)
                it->second.allocation = AllocState::None;
        });
}

// --- Guarded disjuncts (targeted path sensitivity) ---
//
// The Juliet FP hunt (2026-07-10) showed a single root cause: when the
// same invariant condition is tested twice ("if(g==5) alloc; ... if(g==5)
// free;"), paths get mixed at the join and a phantom "path that allocates
// but never frees" is born. The shared machinery is in
// engine/GuardedDisjuncts.h — here it is only instantiated with the
// AllocState merger.

using DisjunctState = codeskeptic::GuardedState<VarState>;

VarState flattenState(const DisjunctState& state) {
    return codeskeptic::flattenGuarded(state, mergeLifetimeStates);
}

// --- Analysis struct for DataflowEngine ---

class MemLeakAnalysis {
public:
    using State = DisjunctState;

    MemLeakAnalysis(const std::vector<const VarDecl*>& trackedVars,
                    std::set<const ValueDecl*> unkeyableDecls,
                    std::set<const ValueDecl*> stampableDecls,
                    std::string funcName,
                    std::map<const VarDecl*, const VarDecl*> reallocSources,
                    codeskeptic::DiagnosticList& results)
        : trackedVars_(trackedVars),
          trackedSet_(trackedVars.begin(), trackedVars.end()),
          mutated_(std::move(unkeyableDecls)),
          stampable_(std::move(stampableDecls)),
          reallocSources_(std::move(reallocSources)),
          funcName_(std::move(funcName)), results_(results) {
        codeskeptic::Guarded<VarState> init;
        for (const auto* var : trackedVars_) {
            init.vars[var] = LifetimeState{};
            pointerFacts_.insert(var);
        }
        initState_.push_back(std::move(init));
    }

    State initialState() const { return initState_; }

    // The per-variable AllocState chain makes at most 3 transitions;
    // the number of disjuncts multiplies the height (each disjunct can
    // rise independently)
    unsigned latticeHeight() const {
        return (static_cast<unsigned>(trackedVars_.size()) * 5 + 1) *
                   static_cast<unsigned>(codeskeptic::kMaxDisjuncts) + 4 + factBudget();
    }

    // Fact records add lattice climbs the var-state formula above
    // never counted (v2b); bounded so pathological functions do not
    // explode the iteration cap.
    unsigned factBudget() const {
        auto n = static_cast<unsigned>(stampable_.size() +
                                       pointerFacts_.size());
        return (n > 16 ? 16u : n) * 2 *
               static_cast<unsigned>(codeskeptic::kMaxDisjuncts);
    }

    // Engine convergence hook: collapse the disjuncts when a block is
    // revisited beyond any monotone explanation (see DataflowEngine).
    void widen(State& s) const {
        codeskeptic::widenGuarded(s, mergeLifetimeStates);
    }

    State merge(const State& a, const State& b) const {
        return codeskeptic::mergeGuarded(a, b, mergeLifetimeStates);
    }

    // Pure state transition — produces no reports. Reporting lives in
    // onStatement, the post-fixpoint pass (an engine guarantee).
    State transfer(const Stmt* stmt, const State& inRaw,
                   ASTContext& ctx) const {
        // Fact lifecycle first (v2b): see NullDerefRule — erase facts
        // on assigned locals, stamp integer-constant stores.
        State in = inRaw;
        codeskeptic::applyStmtFacts(in, stmt, stampable_, pointerFacts_,
                                    mergeLifetimeStates);

        const std::vector<BindingUpdate> bindings =
            pointerBindingUpdates(stmt);
        auto applyBindings = [&](bool deferred) {
            for (auto& disjunct : in) {
                for (const BindingUpdate& binding : bindings) {
                    if (binding.deferred != deferred) continue;
                    auto replacement = reallocSources_.find(binding.rhs);
                    if (replacement != reallocSources_.end() &&
                        replacement->second &&
                        provesNonNull(disjunct, binding.rhs)) {
                        const VarDecl* oldOwner =
                            resolveBinding(binding.lhs, disjunct.vars);
                        const VarDecl* reallocOwner =
                            resolveBinding(replacement->second,
                                           disjunct.vars);
                        if (oldOwner && oldOwner == reallocOwner)
                            disjunct.vars[oldOwner].allocation =
                                AllocState::Escaped;
                    }
                    applyBindingUpdate(disjunct.vars, binding);
                }
            }
        };
        applyBindings(false);

        // Effects are state-independent: classify once, apply to every disjunct
        StmtEffects effects = classifyStmtEffects(stmt, trackedSet_, ctx);
        if (effects.empty()) {
            applyBindings(true);
            return in;
        }

        State out = in;
        for (auto& d : out) {
            for (const auto& [var, effect] : effects) {
                switch (effect) {
                    case StmtEffect::Allocates:
                        invalidateBindingDependents(d.vars, var);
                        d.vars[var].binding = var;
                        d.vars[var].referenceBinding = false;
                        d.vars[var].allocation = AllocState::Allocated;
                        break;
                    case StmtEffect::Frees: {
                        const VarDecl* owner = resolveBinding(var, d.vars);
                        if (owner)
                            d.vars[owner].allocation = AllocState::Freed;
                        break;
                    }
                    case StmtEffect::Escapes: {
                        const VarDecl* owner = resolveBinding(var, d.vars);
                        if (owner)
                            d.vars[owner].allocation = AllocState::Escaped;
                        break;
                    }
                    case StmtEffect::None: break;
                }
            }
        }
        in = std::move(out);
        applyBindings(true);
        return in;
    }

    void refineOnEdge(const Stmt* cond, bool isTrueBranch, State& state,
                      ASTContext& /*ctx*/) const {
        const auto* condExpr = dyn_cast<Expr>(cond);
        codeskeptic::refineGuardedFactsWith(
            state, condExpr, isTrueBranch, mutated_, pointerFacts_,
            mergeLifetimeStates,
            [](const codeskeptic::Guarded<VarState>&, const Expr*, bool) {
                return false;
            },
            [](codeskeptic::Guarded<VarState>&, const Expr*, bool) {});
        for (auto& d : state)
            applyNullCondition(condExpr, isTrueBranch, d.vars);
    }

    // Post-fixpoint reporting: reassignment leak, double free and
    // use-after-free are produced here.
    void onStatement(const Stmt* stmt, const State& beforeDisjuncts,
                     const State& afterDisjuncts, ASTContext& ctx) {
        // Reporting works on today's single-state view; the payoff of
        // path sensitivity is that disjuncts dropped by refineOnEdge
        // never enter this merge at all.
        VarState before = flattenState(beforeDisjuncts);
        VarState after = flattenState(afterDisjuncts);
        // Dataflow trace: record state-changing events (alloc/free).
        // Notes are attached to the report at the END of the run — the
        // reporting pass's block order is not source order.
        for (const auto& [var, afterState] : after) {
            auto b = before.find(var);
            if (b == before.end() ||
                b->second.allocation == afterState.allocation)
                continue;
            if (afterState.allocation == AllocState::Allocated)
                recordEvent(stmt, var, ctx,
                            codeskeptic::MsgId::TraceAllocatedHere);
            else if (afterState.allocation == AllocState::Freed)
                recordEvent(stmt, var, ctx,
                            codeskeptic::MsgId::TraceFreedHere);
        }

        for (const auto& [var, effect] :
             classifyStmtEffects(stmt, trackedSet_, ctx)) {
            auto it = before.find(var);
            if (it == before.end()) continue;

            if (effect == StmtEffect::Allocates &&
                it->second.allocation == AllocState::Allocated) {
                report(stmt, var, ctx, codeskeptic::Severity::Warning,
                       "memory-leak", codeskeptic::MsgId::LeakReassign);
            } else if (effect == StmtEffect::Frees) {
                const VarDecl* owner = resolveBinding(var, before);
                auto ownerState = owner ? before.find(owner) : before.end();
                if (ownerState == before.end() ||
                    ownerState->second.allocation != AllocState::Freed)
                    continue;
                // Under its own identity, like UAF: so the CWE415 mapping
                // and the --disable-rule taxonomy can tell the finding
                // kinds apart
                report(stmt, var, ctx, codeskeptic::Severity::Error,
                       "double-free", codeskeptic::MsgId::DoubleFree,
                       owner);
            }
        }

        // Dereference of a pointer in the Freed state: use-after-free
        if (const VarDecl* var = derefTarget(stmt)) {
            const VarDecl* owner = resolveBinding(var, before);
            auto it = owner ? before.find(owner) : before.end();
            if (it != before.end() &&
                it->second.allocation == AllocState::Freed) {
                report(stmt, var, ctx, codeskeptic::Severity::Error,
                       "use-after-free", codeskeptic::MsgId::UseAfterFree,
                       owner);
            }
        }
    }

    std::set<std::pair<const VarDecl*, unsigned>>& reported() {
        return reported_;
    }

    // After the run finishes: attach the accumulated event notes to reports
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

    // For external reports (exit-block leak): target registration + event access
    void registerNoteTarget(size_t resultIndex, const VarDecl* var) {
        noteTargets_.emplace_back(resultIndex, var);
    }

private:
    std::map<const VarDecl*, std::vector<codeskeptic::TraceNote>> events_;
    std::vector<std::pair<size_t, const VarDecl*>> noteTargets_;

    void recordEvent(const Stmt* stmt, const VarDecl* var, ASTContext& ctx,
                     codeskeptic::MsgId msgId) {
        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        codeskeptic::TraceNote note;
        note.file = sm.getFilename(loc).str();
        note.line = sm.getSpellingLineNumber(loc);
        note.column = sm.getSpellingColumnNumber(loc);
        note.message = codeskeptic::msg(msgId, var->getNameAsString());

        auto& list = events_[var];
        for (const auto& existing : list)
            if (existing.line == note.line &&
                existing.message == note.message)
                return;
        list.push_back(std::move(note));
    }

    void report(const Stmt* stmt, const VarDecl* var, ASTContext& ctx,
                codeskeptic::Severity severity, const char* ruleId,
                codeskeptic::MsgId msgId,
                const VarDecl* traceVar = nullptr) {
        const SourceManager& sm = ctx.getSourceManager();
        // Findings inside macros are bound to the use site (expansion);
        // otherwise the file name can end up empty (scratch buffer)
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reported_.emplace(var, line).second) return;

        codeskeptic::Diagnostic diag;
        diag.severity = severity;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = ruleId;
        diag.function = funcName_;
        diag.message = codeskeptic::msg(msgId, var->getNameAsString());
        results_.push_back(diag);
        noteTargets_.emplace_back(results_.size() - 1,
                                  traceVar ? traceVar : var);
    }

    const std::vector<const VarDecl*>& trackedVars_;
    std::set<const VarDecl*> trackedSet_;
    std::set<const ValueDecl*> mutated_;
    std::set<const ValueDecl*> stampable_;
    std::set<const ValueDecl*> pointerFacts_;
    std::map<const VarDecl*, const VarDecl*> reallocSources_;
    std::string funcName_;
    codeskeptic::DiagnosticList& results_;
    State initState_;
    std::set<std::pair<const VarDecl*, unsigned>> reported_;
};

// --- Function-level analysis ---

void reportDiscardedOwnedResults(const FunctionDecl* funcDecl,
                                 ASTContext& ctx,
                                 codeskeptic::DiagnosticList& results) {
    struct Visitor : RecursiveASTVisitor<Visitor> {
        const FunctionDecl* func;
        ASTContext* ctx;
        codeskeptic::DiagnosticList* results;
        std::set<unsigned> reportedLocations;

        bool VisitExpr(Expr* expr) {
            const Expr* core = expr->IgnoreParenCasts();
            if (!isAllocExpr(core, *ctx) || !isDiscarded(expr)) return true;
            const SourceManager& sm = ctx->getSourceManager();
            SourceLocation loc = sm.getExpansionLoc(core->getBeginLoc());
            if (!loc.isValid() || sm.isInSystemHeader(loc)) return true;
            const unsigned raw = loc.getRawEncoding();
            if (!reportedLocations.insert(raw).second) return true;

            const auto* call = dyn_cast<CallExpr>(core);
            const bool resource =
                call && isResourceAcquireName(
                            calleeName(call->getDirectCallee()));
            codeskeptic::Diagnostic diag;
            diag.severity = codeskeptic::Severity::Warning;
            diag.file = sm.getFilename(loc).str();
            diag.line = sm.getSpellingLineNumber(loc);
            diag.column = sm.getSpellingColumnNumber(loc);
            diag.rule_id = resource ? "resource-leak" : "memory-leak";
            diag.function = func->getQualifiedNameAsString();
            diag.message = codeskeptic::msg(
                codeskeptic::MsgId::OwnedResultDiscarded);
            results->push_back(std::move(diag));
            return true;
        }

        bool TraverseLambdaExpr(LambdaExpr*) { return true; }

        bool isDiscarded(const Expr* expr) const {
            DynTypedNode node = DynTypedNode::create(*expr);
            auto parents = ctx->getParents(node);
            if (parents.empty()) return false;
            const Stmt* parent = parents[0].get<Stmt>();
            if (!parent) return false;
            if (isa<CompoundStmt>(parent)) return true;
            if (const auto* branch = dyn_cast<IfStmt>(parent))
                return branch->getThen() == expr ||
                       branch->getElse() == expr;
            if (const auto* loop = dyn_cast<WhileStmt>(parent))
                return loop->getBody() == expr;
            if (const auto* loop = dyn_cast<DoStmt>(parent))
                return loop->getBody() == expr;
            if (const auto* loop = dyn_cast<ForStmt>(parent))
                return loop->getBody() == expr;
            return false;
        }
    } visitor;
    visitor.func = funcDecl;
    visitor.ctx = &ctx;
    visitor.results = &results;
    visitor.TraverseStmt(const_cast<Stmt*>(funcDecl->getBody()));
}

void analyzeFunction(const FunctionDecl* funcDecl,
                     ASTContext& ctx,
                     codeskeptic::DiagnosticList& results) {
    if (!funcDecl->hasBody()) return;

    reportDiscardedOwnedResults(funcDecl, ctx, results);

    auto trackedVars = collectTrackedVars(funcDecl, ctx);
    if (trackedVars.empty()) return;

    std::set<const VarDecl*> trackedSet(trackedVars.begin(),
                                        trackedVars.end());
    auto aliasInventory = collectAliasInventory(funcDecl, ctx, trackedSet);
    // Alias-connected variables join the tracked set with no binding. Their
    // exact relation is established only when the corresponding statement is
    // transferred on a concrete guarded disjunct.
    for (const auto& [var, members] : aliasInventory) {
        (void)members;
        if (trackedSet.insert(var).second) trackedVars.push_back(var);
    }
    MemLeakAnalysis analysis(
        trackedVars, codeskeptic::collectUnkeyableDecls(funcDecl),
        codeskeptic::collectFactDecls(funcDecl),
        funcDecl->getQualifiedNameAsString(),
        collectReallocSources(funcDecl),
        results);
    auto dfResult = codeskeptic::runDataflow(funcDecl, ctx, analysis);
    if (!dfResult.converged)
        codeskeptic::CoverageReport::instance().recordDataflowFailure(
            funcDecl->getQualifiedNameAsString(), dfResult.failure);

    // Exit block leak check
    auto exitIt = dfResult.blockExitStates.find(dfResult.exitBlockID);
    if (exitIt == dfResult.blockExitStates.end()) return;

    const SourceManager& sm = ctx.getSourceManager();
    SourceLocation endLoc = funcDecl->getBody()->getEndLoc();

    const VarState exitVars = flattenState(exitIt->second);
    for (const auto& [var, state] : exitVars) {
        if (state.allocation == AllocState::Allocated) {
            // A release through an exact alias updates the owner during
            // transfer. The exit check therefore needs no flow-insensitive
            // group suppression: an allocation leaks when at least one live
            // disjunct still carries its owner as Allocated.
            bool leaksSomewhere = false;
            for (const auto& d : exitIt->second) {
                auto v = d.vars.find(var);
                if (v == d.vars.end() ||
                    v->second.allocation != AllocState::Allocated)
                    continue;
                leaksSomewhere = true;
                break;
            }
            if (!leaksSomewhere) continue;
            unsigned line = sm.getSpellingLineNumber(endLoc);
            if (analysis.reported().emplace(var, line).second) {
                codeskeptic::Diagnostic diag;
                diag.severity = codeskeptic::Severity::Warning;
                diag.file = sm.getFilename(endLoc).str();
                diag.line = line;
                diag.column = sm.getSpellingColumnNumber(endLoc);
                // Classify by the ACQUIRING name (robust — a FILE*
                // typedef's record name varies by libc). A resource
                // handle left un-closed is CWE-404, not a heap leak.
                diag.rule_id = "memory-leak";
                codeskeptic::MsgId leakMsg =
                    codeskeptic::MsgId::LeakEndOfFunction;
                if (const Expr* init = var->getInit()) {
                    const Expr* e = init->IgnoreParenImpCasts();
                    if (const auto* c = dyn_cast<CallExpr>(e))
                        if (isResourceAcquireName(
                                calleeName(c->getDirectCallee()))) {
                            diag.rule_id = "resource-leak";
                            leakMsg = codeskeptic::MsgId::
                                ResourceLeakEndOfFunction;
                        }
                }
                diag.function = funcDecl->getQualifiedNameAsString();
                diag.message =
                    codeskeptic::msg(leakMsg, var->getNameAsString());
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
    explicit FindMemLeakCallback(codeskeptic::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* func = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!func || !func->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(func->getLocation())) return;
        if (!codeskeptic::functionFilterAllows(*func)) return;
        if (!codeskeptic::lineFilterAllows(*func, sm)) return;

        analyzeFunction(func, *result.Context, results_);
    }

private:
    codeskeptic::DiagnosticList& results_;
};

} // anonymous namespace

namespace codeskeptic {

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

} // namespace codeskeptic
