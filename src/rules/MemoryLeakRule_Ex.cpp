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
    const VarDecl* reallocSource = nullptr;
    std::string allocatorFamily;
    bool allocatorFamilyKnown = true;
    std::set<const VarDecl*> smartOwners;
    bool smartOwnersKnown = true;
    bool referenceBinding = false;

    bool operator==(const LifetimeState& other) const {
        return allocation == other.allocation && binding == other.binding &&
               reallocSource == other.reallocSource &&
               allocatorFamily == other.allocatorFamily &&
               allocatorFamilyKnown == other.allocatorFamilyKnown &&
               smartOwners == other.smartOwners &&
               smartOwnersKnown == other.smartOwnersKnown &&
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
        if (reallocSource != other.reallocSource)
            return std::less<const VarDecl*>{}(reallocSource,
                                                other.reallocSource);
        if (allocatorFamily != other.allocatorFamily)
            return allocatorFamily < other.allocatorFamily;
        if (allocatorFamilyKnown != other.allocatorFamilyKnown)
            return allocatorFamilyKnown < other.allocatorFamilyKnown;
        if (smartOwners != other.smartOwners) {
            return std::lexicographical_compare(
                smartOwners.begin(), smartOwners.end(),
                other.smartOwners.begin(), other.smartOwners.end(),
                std::less<const VarDecl*>{});
        }
        if (smartOwnersKnown != other.smartOwnersKnown)
            return smartOwnersKnown < other.smartOwnersKnown;
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
    if (a.reallocSource == b.reallocSource)
        result.reallocSource = a.reallocSource;
    if (a.allocation == AllocState::None &&
        b.allocation != AllocState::None) {
        result.allocatorFamily = b.allocatorFamily;
        result.allocatorFamilyKnown = b.allocatorFamilyKnown;
    } else if (b.allocation == AllocState::None &&
               a.allocation != AllocState::None) {
        result.allocatorFamily = a.allocatorFamily;
        result.allocatorFamilyKnown = a.allocatorFamilyKnown;
    } else if (a.allocatorFamilyKnown && b.allocatorFamilyKnown &&
               a.allocatorFamily == b.allocatorFamily) {
        result.allocatorFamily = a.allocatorFamily;
        result.allocatorFamilyKnown = true;
    } else {
        result.allocatorFamilyKnown = false;
    }
    if (a.allocation == AllocState::None &&
        b.allocation != AllocState::None) {
        result.smartOwners = b.smartOwners;
        result.smartOwnersKnown = b.smartOwnersKnown;
    } else if (b.allocation == AllocState::None &&
               a.allocation != AllocState::None) {
        result.smartOwners = a.smartOwners;
        result.smartOwnersKnown = a.smartOwnersKnown;
    } else if (a.smartOwnersKnown && b.smartOwnersKnown &&
               a.smartOwners == b.smartOwners) {
        result.smartOwners = a.smartOwners;
        result.smartOwnersKnown = true;
    } else {
        result.smartOwnersKnown = false;
        if (result.allocation == AllocState::Allocated)
            result.allocation = AllocState::Escaped;
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

bool isStandardOwnerRawResult(const Expr* expr);

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
            if (isStandardOwnerRawResult(lhs->getInit())) continue;
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
        if (isStandardOwnerRawResult(assignment->getRHS())) return updates;
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

struct AllocationFamily {
    std::string name;
    bool known = true;
};

const Expr* allocationExprFor(const Stmt* stmt, const VarDecl* var) {
    if (!stmt || !var) return nullptr;
    if (const auto* declarations = dyn_cast<DeclStmt>(stmt)) {
        for (const Decl* declaration : declarations->decls()) {
            const auto* candidate = dyn_cast<VarDecl>(declaration);
            if (candidate == var && candidate->hasInit())
                return candidate->getInit();
        }
    }
    if (const auto* assignment = dyn_cast<BinaryOperator>(stmt)) {
        if (assignment->getOpcode() == BO_Assign &&
            asVar(assignment->getLHS()) == var)
            return assignment->getRHS();
    }
    return nullptr;
}

AllocationFamily allocationFamilyOf(const Expr* expr) {
    const CallExpr* call = coreCall(expr);
    if (!call) return {};
    if (auto family = codeskeptic::pairedAllocatorFamily(call))
        return {*family, true};

    const auto* summary =
        codeskeptic::SummaryRegistry::instance().lookup(call);
    if (summary &&
        summary->returnOwnership ==
            codeskeptic::SummaryRegistry::ReturnOwnership::Owned &&
        !codeskeptic::allocatorPairs().empty())
        return {{}, false};
    return {};
}

enum class ReleaseAuthority { Match, Mismatch, Unknown };

ReleaseAuthority releaseAuthority(const Stmt* stmt,
                                  const LifetimeState& lifetime) {
    if (!lifetime.allocatorFamilyKnown)
        return ReleaseAuthority::Unknown;
    if (lifetime.allocatorFamily.empty())
        return ReleaseAuthority::Match;
    if (isa<CXXDeleteExpr>(stmt)) return ReleaseAuthority::Mismatch;

    const auto* call = dyn_cast<CallExpr>(stmt);
    if (!call) return ReleaseAuthority::Unknown;
    if (codeskeptic::matchesAllocatorFamily(lifetime.allocatorFamily, call))
        return ReleaseAuthority::Match;

    const llvm::StringRef name = calleeName(call->getDirectCallee());
    const bool knownRelease =
        name == "free" || isResourceReleaseName(name) ||
        codeskeptic::isPairedDeallocatorCall(call) ||
        (!name.empty() &&
         codeskeptic::freeFunctionNames().count(name.str()) != 0);
    return knownRelease ? ReleaseAuthority::Mismatch
                        : ReleaseAuthority::Unknown;
}

struct ReallocSite {
    const VarDecl* result = nullptr;
    const VarDecl* source = nullptr;
    const CallExpr* call = nullptr;
};

bool isAuthoritativeReallocCallee(const FunctionDecl* callee) {
    const IdentifierInfo* id = callee ? callee->getIdentifier() : nullptr;
    if (!id || (id->getName() != "realloc" &&
                id->getName() != "reallocarray"))
        return false;
    const std::string qualified = callee->getQualifiedNameAsString();
    return qualified == id->getName().str() ||
           qualified == "std::" + id->getName().str();
}

ReallocSite reallocSite(const VarDecl* result, const Expr* expr) {
    const CallExpr* call = coreCall(expr);
    if (!call || call->getNumArgs() == 0) return {};
    const FunctionDecl* callee = call->getDirectCallee();
    if (!isAuthoritativeReallocCallee(callee)) return {};
    const llvm::StringRef name = calleeName(callee);
    if ((name == "realloc" && call->getNumArgs() != 2) ||
        (name == "reallocarray" && call->getNumArgs() != 3))
        return {};
    const VarDecl* source = asExactPointerVar(call->getArg(0));
    if (!result || !source || !result->hasLocalStorage() ||
        !sameExactPointerType(result, source))
        return {};
    return {result, source, call};
}

std::vector<ReallocSite> reallocUpdates(const Stmt* stmt) {
    std::vector<ReallocSite> sites;
    if (const auto* declarations = dyn_cast<DeclStmt>(stmt)) {
        for (const Decl* declaration : declarations->decls()) {
            const auto* result = dyn_cast<VarDecl>(declaration);
            ReallocSite site =
                result && result->hasInit()
                    ? reallocSite(result, result->getInit())
                    : ReallocSite{};
            if (site.call) sites.push_back(site);
        }
    } else if (const auto* assignment = dyn_cast<BinaryOperator>(stmt)) {
        if (assignment->getOpcode() == BO_Assign) {
            ReallocSite site = reallocSite(
                asExactPointerVar(assignment->getLHS()),
                assignment->getRHS());
            if (site.call) sites.push_back(site);
        }
    }
    return sites;
}

std::map<const CallExpr*, ReallocSite> collectReallocSites(
        const FunctionDecl* function) {
    if (!function) return {};
    struct Visitor : RecursiveASTVisitor<Visitor> {
        std::map<const CallExpr*, ReallocSite> sites;

        void record(const VarDecl* result, const Expr* value) {
            ReallocSite site = reallocSite(result, value);
            if (!site.call) return;
            auto [it, inserted] = sites.emplace(site.call, site);
            if (!inserted &&
                (it->second.result != site.result ||
                 it->second.source != site.source))
                it->second = {};
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
    return visitor.sites;
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
enum class StandardOwnerKind { None, Unique, Shared, Auto };

StandardOwnerKind standardOwnerKind(QualType qt) {
    const auto* record = qt->getAsCXXRecordDecl();
    if (!record || !record->isInStdNamespace())
        return StandardOwnerKind::None;
    const llvm::StringRef name = record->getName();
    if (name == "unique_ptr") return StandardOwnerKind::Unique;
    if (name == "shared_ptr") return StandardOwnerKind::Shared;
    if (name == "auto_ptr") return StandardOwnerKind::Auto;
    return StandardOwnerKind::None;
}

bool isOwningSmartPointerType(QualType qt) {
    const auto* rec = qt->getAsCXXRecordDecl();
    if (!rec) return false;
    const llvm::StringRef name = rec->getName();
    if (name.empty()) return false;
    if (standardOwnerKind(qt) != StandardOwnerKind::None)
        return true;
    return codeskeptic::owningPointerNames().count(name.str()) != 0;
}

const CXXConstructExpr* owningConstructExpr(const Expr* expr) {
    if (!expr) return nullptr;
    const Expr* current = expr;
    while (current) {
        current = current->IgnoreParenImpCasts();
        if (const auto* cleanups = dyn_cast<ExprWithCleanups>(current)) {
            current = cleanups->getSubExpr();
        } else if (const auto* materialized =
                       dyn_cast<MaterializeTemporaryExpr>(current)) {
            current = materialized->getSubExpr();
        } else if (const auto* bound =
                       dyn_cast<CXXBindTemporaryExpr>(current)) {
            current = bound->getSubExpr();
        } else if (const auto* cast =
                       dyn_cast<CXXFunctionalCastExpr>(current)) {
            current = cast->getSubExpr();
        } else {
            break;
        }
    }
    return dyn_cast_or_null<CXXConstructExpr>(current);
}

QualType standardOwnerPointee(QualType ownerType, ASTContext& ctx) {
    const auto* record = ownerType->getAsCXXRecordDecl();
    const auto* specialization =
        dyn_cast_or_null<ClassTemplateSpecializationDecl>(record);
    if (!specialization || specialization->getTemplateArgs().size() == 0)
        return {};
    const TemplateArgument& argument =
        specialization->getTemplateArgs().get(0);
    if (argument.getKind() != TemplateArgument::Type) return {};
    QualType result = argument.getAsType();
    while (const ArrayType* array = ctx.getAsArrayType(result))
        result = array->getElementType();
    return result.getCanonicalType().getUnqualifiedType();
}

bool hasSupportedImplicitDeleter(QualType ownerType) {
    if (standardOwnerKind(ownerType) != StandardOwnerKind::Unique)
        return true;
    const auto* record = ownerType->getAsCXXRecordDecl();
    const auto* specialization =
        dyn_cast_or_null<ClassTemplateSpecializationDecl>(record);
    if (!specialization) return false;
    const TemplateArgumentList& arguments =
        specialization->getTemplateArgs();
    if (arguments.size() <= 1) return true;
    if (arguments.get(1).getKind() != TemplateArgument::Type) return false;
    const auto* deleter =
        arguments.get(1).getAsType()->getAsCXXRecordDecl();
    return deleter && deleter->isInStdNamespace() &&
           deleter->getName() == "default_delete";
}

bool compatibleOwnerPointee(const VarDecl* raw, QualType ownerType,
                            ASTContext& ctx) {
    if (!raw || !raw->getType()->isPointerType()) return false;
    QualType ownerPointee = standardOwnerPointee(ownerType, ctx);
    QualType rawPointee = raw->getType()->getPointeeType();
    if (ownerPointee.isNull() || rawPointee.isNull()) return false;
    rawPointee = rawPointee.getCanonicalType().getUnqualifiedType();
    return rawPointee == ownerPointee;
}

struct AdoptionInfo {
    const CXXConstructExpr* constructor = nullptr;
    const VarDecl* raw = nullptr;
    StandardOwnerKind standardKind = StandardOwnerKind::None;
    bool compatible = false;
    bool hasCustomDeleter = false;

    bool exactStandard() const {
        return raw && standardKind != StandardOwnerKind::None &&
               compatible && !hasCustomDeleter;
    }
};

AdoptionInfo adoptionInfo(const Expr* expr,
                          const std::set<const VarDecl*>& tracked,
                          ASTContext& ctx) {
    AdoptionInfo result;
    result.constructor = owningConstructExpr(expr);
    if (!result.constructor ||
        !isOwningSmartPointerType(result.constructor->getType()))
        return result;
    result.standardKind = standardOwnerKind(result.constructor->getType());
    result.hasCustomDeleter =
        !hasSupportedImplicitDeleter(result.constructor->getType());
    for (unsigned i = 0; i < result.constructor->getNumArgs(); ++i) {
        const VarDecl* candidate = asVar(result.constructor->getArg(i));
        if (candidate && tracked.count(candidate) &&
            candidate->getType()->isPointerType()) {
            result.raw = candidate;
            result.hasCustomDeleter = result.hasCustomDeleter || i != 0 ||
                result.constructor->getNumArgs() != 1;
            break;
        }
    }
    result.compatible = result.raw &&
        compatibleOwnerPointee(result.raw,
                               result.constructor->getType(), ctx);
    return result;
}

bool hasAutomaticStandardOwner(const CXXConstructExpr* constructor,
                               ASTContext& ctx) {
    if (!constructor) return false;
    DynTypedNode current = DynTypedNode::create(*constructor);
    for (unsigned depth = 0; depth < 8; ++depth) {
        auto parents = ctx.getParents(current);
        if (parents.size() != 1) return false;
        const DynTypedNode& parent = parents[0];
        if (const auto* declaration = parent.get<VarDecl>())
            return declaration->hasLocalStorage() &&
                   standardOwnerKind(declaration->getType()) !=
                       StandardOwnerKind::None;
        if (parent.get<ReturnStmt>() || parent.get<CompoundStmt>())
            return false;
        current = parent;
    }
    return false;
}

const VarDecl* standardOwnerVar(const Expr* expr) {
    if (!expr) return nullptr;
    const Expr* current = expr->IgnoreParenImpCasts();
    if (const auto* call = dyn_cast<CallExpr>(current)) {
        const FunctionDecl* callee = call->getDirectCallee();
        if (callee && callee->getQualifiedNameAsString() == "std::move" &&
            call->getNumArgs() == 1)
            return standardOwnerVar(call->getArg(0));
    }
    const auto* reference = dyn_cast<DeclRefExpr>(current);
    const auto* owner =
        reference ? dyn_cast<VarDecl>(reference->getDecl()) : nullptr;
    if (!owner || !owner->hasLocalStorage() ||
        standardOwnerKind(owner->getType()) == StandardOwnerKind::None)
        return nullptr;
    return owner;
}

bool isMoveOwnerExpr(const Expr* expr) {
    if (!expr) return false;
    const Expr* current = expr->IgnoreParenImpCasts();
    if (const auto* call = dyn_cast<CallExpr>(current)) {
        const FunctionDecl* callee = call->getDirectCallee();
        if (callee && callee->getQualifiedNameAsString() == "std::move")
            return true;
    }
    return current->isXValue();
}

enum class OwnerMethod { None, Get, Release, Reset, Assign };

struct OwnerMemberCall {
    const CallExpr* call = nullptr;
    const VarDecl* owner = nullptr;
    StandardOwnerKind kind = StandardOwnerKind::None;
    OwnerMethod method = OwnerMethod::None;
};

OwnerMemberCall standardOwnerMemberCall(const CallExpr* call) {
    OwnerMemberCall result;
    if (!call) return result;
    const auto* method =
        dyn_cast_or_null<CXXMethodDecl>(call->getDirectCallee());
    if (!method || method->isStatic()) return result;

    const Expr* receiver = nullptr;
    if (const auto* member = dyn_cast<CXXMemberCallExpr>(call))
        receiver = member->getImplicitObjectArgument();
    else if (isa<CXXOperatorCallExpr>(call) && call->getNumArgs() > 0)
        receiver = call->getArg(0);
    result.owner = standardOwnerVar(receiver);
    if (!result.owner) return {};
    result.kind = standardOwnerKind(result.owner->getType());
    result.call = call;

    if (method->getOverloadedOperator() == OO_Equal) {
        result.method = OwnerMethod::Assign;
        return result;
    }
    const llvm::StringRef name = calleeName(method);
    if (name == "get") result.method = OwnerMethod::Get;
    else if (name == "release") result.method = OwnerMethod::Release;
    else if (name == "reset") result.method = OwnerMethod::Reset;
    return result;
}

bool isStandardOwnerRawResult(const Expr* expr) {
    const OwnerMemberCall member = standardOwnerMemberCall(coreCall(expr));
    return member.method == OwnerMethod::Get ||
           member.method == OwnerMethod::Release;
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
        auto collectAdoption = [&](const Expr* expression) {
            AdoptionInfo adoption = adoptionInfo(expression, tracked, ctx);
            if (!adoption.raw) return;
            if (adoption.exactStandard() &&
                hasAutomaticStandardOwner(adoption.constructor, ctx))
                return;
            escaped.push_back(adoption.raw);
        };
        collectAdoption(adoptExpr);
        collectLambdaCaptures(adoptExpr, tracked, escaped);

        if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
            for (const auto* decl : declStmt->decls()) {
                const auto* vd = dyn_cast<VarDecl>(decl);
                if (!vd || !vd->hasInit()) continue;
                collectAdoption(vd->getInit());
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
        if (standardOwnerMemberCall(call).method != OwnerMethod::None)
            return effects;
        const FunctionDecl* callee = call->getDirectCallee();
        const llvm::StringRef name = calleeName(callee);
        const bool isFreeByName =
            name == "free" || isResourceReleaseName(name) ||
            codeskeptic::isPairedDeallocatorCall(call) ||
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
            (isAllocExpr(v->getInit(), ctx) ||
             isStandardOwnerRawResult(v->getInit())))
            vars.insert(v);
    }
    for (const auto& result :
         match(findAll(candidateAssign), *funcDecl->getBody(), ctx)) {
        const auto* v = result.getNodeAs<VarDecl>("var");
        const auto* assign = result.getNodeAs<BinaryOperator>("assign");
        if (v && assign && trackable(v) &&
            (isAllocExpr(assign->getRHS(), ctx) ||
             isStandardOwnerRawResult(assign->getRHS())))
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

void invalidateReallocRelations(VarState& state,
                                const VarDecl* changed) {
    if (!changed) return;
    for (auto& [var, lifetime] : state)
        if (var == changed || lifetime.reallocSource == changed)
            lifetime.reallocSource = nullptr;
}

void invalidateBindingDependents(VarState& state, const VarDecl* overwritten) {
    if (!overwritten) return;
    invalidateReallocRelations(state, overwritten);
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
    invalidateReallocRelations(state, update.lhs);
    lhs = state.find(update.lhs);
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

enum class OwnerOperationKind {
    None,
    Adopt,
    EscapeRaw,
    EscapeOwner,
    Copy,
    Move,
    Reset,
    Release,
    Get,
};

struct OwnerOperation {
    OwnerOperationKind kind = OwnerOperationKind::None;
    const VarDecl* owner = nullptr;
    const VarDecl* sourceOwner = nullptr;
    const VarDecl* raw = nullptr;
    const VarDecl* result = nullptr;
    StandardOwnerKind ownerKind = StandardOwnerKind::None;
    bool replaceOwner = false;
    bool compatible = false;
};

using OwnerRawResultSites =
    std::map<const CallExpr*, const VarDecl*>;

OwnerRawResultSites collectOwnerRawResultSites(
        const FunctionDecl* function) {
    if (!function) return {};
    struct Visitor : RecursiveASTVisitor<Visitor> {
        OwnerRawResultSites sites;

        void record(const VarDecl* result, const Expr* value) {
            const CallExpr* call = coreCall(value);
            const OwnerMemberCall member = standardOwnerMemberCall(call);
            if (!result || !result->hasLocalStorage() ||
                !result->getType()->isPointerType() ||
                (member.method != OwnerMethod::Get &&
                 member.method != OwnerMethod::Release))
                return;
            auto [found, inserted] = sites.emplace(call, result);
            if (!inserted && found->second != result)
                found->second = nullptr;
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
    return visitor.sites;
}

OwnerOperation ownerConstruction(const VarDecl* owner,
                                 const Expr* initializer,
                                 const std::set<const VarDecl*>& tracked,
                                 ASTContext& ctx) {
    OwnerOperation result;
    if (!owner || !owner->hasLocalStorage()) return result;
    result.owner = owner;
    result.ownerKind = standardOwnerKind(owner->getType());
    if (result.ownerKind == StandardOwnerKind::None) return {};

    const CXXConstructExpr* constructor =
        owningConstructExpr(initializer);
    if (!constructor) return {};
    AdoptionInfo adoption = adoptionInfo(initializer, tracked, ctx);
    if (adoption.raw) {
        result.raw = adoption.raw;
        result.compatible = adoption.exactStandard();
        result.kind = result.compatible ? OwnerOperationKind::Adopt
                                        : OwnerOperationKind::EscapeRaw;
        return result;
    }

    if (constructor->getNumArgs() == 0) return {};
    const Expr* sourceExpr = constructor->getArg(0);
    result.sourceOwner = standardOwnerVar(sourceExpr);
    if (!result.sourceOwner ||
        standardOwnerKind(result.sourceOwner->getType()) != result.ownerKind)
        return {};
    if (constructor->getNumArgs() != 1) {
        result.kind = OwnerOperationKind::EscapeOwner;
        return result;
    }
    const bool transfers =
        result.ownerKind == StandardOwnerKind::Auto ||
        isMoveOwnerExpr(sourceExpr);
    if (!transfers && result.ownerKind != StandardOwnerKind::Shared)
        return {};
    result.kind = transfers ? OwnerOperationKind::Move
                            : OwnerOperationKind::Copy;
    return result;
}

std::vector<OwnerOperation> ownerOperations(
        const Stmt* stmt,
        const std::set<const VarDecl*>& tracked,
        const OwnerRawResultSites& resultSites,
        ASTContext& ctx) {
    std::vector<OwnerOperation> result;
    if (const auto* declarations = dyn_cast<DeclStmt>(stmt)) {
        for (const Decl* declaration : declarations->decls()) {
            const auto* owner = dyn_cast<VarDecl>(declaration);
            if (!owner || !owner->hasInit()) continue;
            OwnerOperation operation =
                ownerConstruction(owner, owner->getInit(), tracked, ctx);
            if (operation.kind != OwnerOperationKind::None)
                result.push_back(operation);
        }
        return result;
    }

    const auto* call = dyn_cast<CallExpr>(stmt);
    const OwnerMemberCall member = standardOwnerMemberCall(call);
    if (member.method == OwnerMethod::None) return result;

    OwnerOperation operation;
    operation.owner = member.owner;
    operation.ownerKind = member.kind;
    if (member.method == OwnerMethod::Get ||
        member.method == OwnerMethod::Release) {
        operation.kind = member.method == OwnerMethod::Get
                             ? OwnerOperationKind::Get
                             : OwnerOperationKind::Release;
        auto site = resultSites.find(call);
        if (site != resultSites.end()) operation.result = site->second;
        result.push_back(operation);
        return result;
    }

    if (member.method == OwnerMethod::Reset) {
        operation.kind = OwnerOperationKind::Reset;
        operation.replaceOwner = true;
        if (call->getNumArgs() > 0) {
            operation.raw = asExactPointerVar(call->getArg(0));
            operation.compatible = operation.raw &&
                tracked.count(operation.raw) &&
                compatibleOwnerPointee(operation.raw,
                                       member.owner->getType(), ctx);
        }
        result.push_back(operation);
        return result;
    }

    if (member.method == OwnerMethod::Assign &&
        call->getNumArgs() > 0) {
        const Expr* sourceExpr = call->getArg(call->getNumArgs() - 1);
        operation.sourceOwner = standardOwnerVar(sourceExpr);
        operation.replaceOwner = true;
        if (!operation.sourceOwner ||
            standardOwnerKind(operation.sourceOwner->getType()) !=
                operation.ownerKind)
            return result;
        const bool transfers =
            operation.ownerKind == StandardOwnerKind::Auto ||
            isMoveOwnerExpr(sourceExpr);
        if (!transfers && operation.ownerKind != StandardOwnerKind::Shared)
            return result;
        operation.kind = transfers ? OwnerOperationKind::Move
                                   : OwnerOperationKind::Copy;
        result.push_back(operation);
    }
    return result;
}

const VarDecl* allocationRoot(const VarDecl* var,
                              const VarState& state) {
    const VarDecl* root = resolveBinding(var, state);
    if (root) return root;
    auto direct = state.find(var);
    return direct != state.end() &&
                   direct->second.allocation != AllocState::None
               ? var
               : nullptr;
}

std::vector<const VarDecl*> rootsOwnedBy(const VarDecl* owner,
                                         const VarState& state) {
    std::vector<const VarDecl*> result;
    if (!owner) return result;
    for (const auto& [raw, lifetime] : state)
        if (lifetime.smartOwnersKnown &&
            lifetime.smartOwners.count(owner) != 0)
            result.push_back(raw);
    return result;
}

void escapeOwner(const VarDecl* owner, VarState& state) {
    for (const VarDecl* raw : rootsOwnedBy(owner, state)) {
        LifetimeState& lifetime = state[raw];
        lifetime.allocation = AllocState::Escaped;
        lifetime.smartOwners.clear();
        lifetime.smartOwnersKnown = false;
        invalidateReallocRelations(state, raw);
    }
}

// Clang 20 can emit an automatic-dtor element for an unwound owner without
// connecting that block to the throw-to-handler edge. Treating that orphan as
// a release would manufacture UAF/double-free evidence; retaining Allocated
// would manufacture a leak. Drop only allocations with an exact live smart
// owner. Ownerless and explicitly released allocations stay leak-reportable.
void escapeOwnersAtUnmodelledThrow(VarState& state) {
    std::vector<const VarDecl*> roots;
    for (const auto& [raw, lifetime] : state)
        if (lifetime.smartOwnersKnown && !lifetime.smartOwners.empty())
            roots.push_back(raw);
    for (const VarDecl* raw : roots) {
        invalidateReallocRelations(state, raw);
        LifetimeState& lifetime = state[raw];
        lifetime.allocation = AllocState::Escaped;
        lifetime.smartOwners.clear();
        lifetime.smartOwnersKnown = false;
    }
}

void releaseOwner(const VarDecl* owner, bool freesLast,
                  VarState& state) {
    for (const VarDecl* raw : rootsOwnedBy(owner, state)) {
        LifetimeState& lifetime = state[raw];
        lifetime.smartOwners.erase(owner);
        if (freesLast && lifetime.smartOwners.empty() &&
            lifetime.allocation == AllocState::Allocated)
            lifetime.allocation = AllocState::Freed;
    }
}

void adoptOwner(const OwnerOperation& operation, VarState& state) {
    const VarDecl* root = allocationRoot(operation.raw, state);
    if (!root) return;
    LifetimeState& lifetime = state[root];
    if (!operation.compatible || !lifetime.allocatorFamilyKnown ||
        !lifetime.allocatorFamily.empty() ||
        !lifetime.smartOwnersKnown || !lifetime.smartOwners.empty()) {
        lifetime.allocation = AllocState::Escaped;
        lifetime.smartOwners.clear();
        lifetime.smartOwnersKnown = false;
        return;
    }
    if (lifetime.allocation != AllocState::Allocated &&
        lifetime.allocation != AllocState::Freed)
        return;
    lifetime.smartOwners.insert(operation.owner);
}

void bindOwnerResult(const OwnerOperation& operation,
                     const VarDecl* root, VarState& state) {
    if (!operation.result || !root ||
        !compatibleOwnerPointee(operation.result,
                               operation.owner->getType(),
                               operation.owner->getASTContext()))
        return;
    auto target = state.find(operation.result);
    if (target == state.end()) return;
    invalidateBindingDependents(state, operation.result);
    target = state.find(operation.result);
    target->second.binding = root;
    target->second.referenceBinding = false;
}

void applyOwnerOperation(const OwnerOperation& operation,
                         VarState& state) {
    switch (operation.kind) {
        case OwnerOperationKind::Adopt:
            adoptOwner(operation, state);
            return;
        case OwnerOperationKind::EscapeRaw: {
            const VarDecl* root = allocationRoot(operation.raw, state);
            if (root) {
                state[root].allocation = AllocState::Escaped;
                state[root].smartOwners.clear();
                state[root].smartOwnersKnown = false;
            }
            return;
        }
        case OwnerOperationKind::EscapeOwner:
            escapeOwner(operation.sourceOwner, state);
            return;
        case OwnerOperationKind::Reset:
            releaseOwner(operation.owner, true, state);
            if (operation.raw) {
                if (operation.compatible)
                    adoptOwner(operation, state);
                else {
                    const VarDecl* root = allocationRoot(operation.raw, state);
                    if (root) state[root].allocation = AllocState::Escaped;
                }
            }
            return;
        case OwnerOperationKind::Release:
        case OwnerOperationKind::Get: {
            std::vector<const VarDecl*> roots =
                rootsOwnedBy(operation.owner, state);
            if (roots.size() != 1) {
                if (!roots.empty()) escapeOwner(operation.owner, state);
                return;
            }
            const VarDecl* root = roots.front();
            if (operation.kind == OwnerOperationKind::Release)
                releaseOwner(operation.owner, false, state);
            bindOwnerResult(operation, root, state);
            return;
        }
        case OwnerOperationKind::Copy:
        case OwnerOperationKind::Move: {
            if (operation.owner == operation.sourceOwner) return;
            std::vector<const VarDecl*> sourceRoots =
                rootsOwnedBy(operation.sourceOwner, state);
            if (operation.replaceOwner)
                releaseOwner(operation.owner, true, state);
            if (sourceRoots.size() != 1) {
                if (!sourceRoots.empty())
                    escapeOwner(operation.sourceOwner, state);
                return;
            }
            LifetimeState& lifetime = state[sourceRoots.front()];
            if (operation.kind == OwnerOperationKind::Move)
                lifetime.smartOwners.erase(operation.sourceOwner);
            lifetime.smartOwners.insert(operation.owner);
            return;
        }
        case OwnerOperationKind::None:
            return;
    }
}

const VarDecl* addressedStandardOwner(const Expr* expr) {
    if (!expr) return nullptr;
    const auto* address = dyn_cast<UnaryOperator>(
        expr->IgnoreParenImpCasts());
    if (!address || address->getOpcode() != UO_AddrOf) return nullptr;
    return standardOwnerVar(address->getSubExpr());
}

std::set<const VarDecl*> ownerEscapesAt(const Stmt* stmt) {
    std::set<const VarDecl*> result;
    auto add = [&](const Expr* expr) {
        if (const VarDecl* owner = standardOwnerVar(expr))
            result.insert(owner);
        if (const VarDecl* owner = addressedStandardOwner(expr))
            result.insert(owner);
    };

    if (const auto* declarations = dyn_cast<DeclStmt>(stmt)) {
        for (const Decl* declaration : declarations->decls()) {
            const auto* variable = dyn_cast<VarDecl>(declaration);
            if (!variable || !variable->hasInit()) continue;
            if (variable->getType()->isReferenceType())
                add(variable->getInit());
            else if (variable->getType()->isPointerType())
                add(variable->getInit());
        }
        return result;
    }

    if (const auto* returned = dyn_cast<ReturnStmt>(stmt)) {
        add(returned->getRetValue());
        return result;
    }

    if (const auto* lambda = dyn_cast<LambdaExpr>(stmt)) {
        for (const LambdaCapture& capture : lambda->captures()) {
            if (!capture.capturesVariable()) continue;
            const auto* variable =
                dyn_cast<VarDecl>(capture.getCapturedVar());
            if (variable &&
                standardOwnerKind(variable->getType()) !=
                    StandardOwnerKind::None)
                result.insert(variable);
        }
        return result;
    }

    const auto* call = dyn_cast<CallExpr>(stmt);
    if (!call) return result;
    const FunctionDecl* callee = call->getDirectCallee();
    if (callee && callee->getQualifiedNameAsString() == "std::move")
        return result;
    if (standardOwnerMemberCall(call).method != OwnerMethod::None)
        return result;
    if (const auto* member = dyn_cast<CXXMemberCallExpr>(call))
        add(member->getImplicitObjectArgument());
    for (const Expr* argument : call->arguments()) add(argument);
    return result;
}

bool provesNonZero(const Expr* expr,
                   const codeskeptic::Guarded<VarState>& disjunct,
                   ASTContext& ctx) {
    if (!expr) return false;
    Expr::EvalResult result;
    if (expr->EvaluateAsInt(result, ctx) && result.Val.isInt())
        return !result.Val.getInt().isZero();
    const VarDecl* var = asVar(expr);
    if (!var) return false;
    auto it = disjunct.facts.find(
        codeskeptic::FactKey{var, BO_EQ, 0, nullptr});
    return it != disjunct.facts.end() && !it->second;
}

bool provesNonZeroRequest(
        const ReallocSite& site,
        const codeskeptic::Guarded<VarState>& disjunct,
        ASTContext& ctx) {
    if (!site.call) return false;
    if (!provesNonZero(site.call->getArg(1), disjunct, ctx))
        return false;
    return calleeName(site.call->getDirectCallee()) != "reallocarray" ||
           provesNonZero(site.call->getArg(2), disjunct, ctx);
}

// On an edge known to be null there is no "allocation": the malloc/new
// failure path is NOT a leak (p = malloc; if (!p) return;).
// The walk comes from the shared skeleton (engine/ConditionWalk.h); this
// Ordinary allocations only need the null edge. A pending exact realloc
// relation also consumes the non-null edge: success invalidates the old
// pointer value, while failure preserves it.
void applyNullCondition(const Expr* cond, bool isTrue, VarState& state) {
    codeskeptic::walkNullCondition(
        cond, isTrue, [&](const VarDecl* var, bool isNull) {
            const VarDecl* guardedOwner = resolveBinding(var, state);
            auto result = guardedOwner ? state.find(guardedOwner)
                                       : state.find(var);
            if (result != state.end() && result->second.reallocSource) {
                const VarDecl* source = result->second.reallocSource;
                result->second.reallocSource = nullptr;
                if (isNull) {
                    result->second.allocation = AllocState::None;
                } else {
                    auto old = state.find(source);
                    if (old != state.end() &&
                        old->second.allocation == AllocState::Allocated)
                        old->second.allocation = AllocState::Freed;
                }
                return;
            }
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
                    std::map<const CallExpr*, ReallocSite> reallocSites,
                    OwnerRawResultSites ownerRawResultSites,
                    codeskeptic::DiagnosticList& results)
        : trackedVars_(trackedVars),
          trackedSet_(trackedVars.begin(), trackedVars.end()),
          mutated_(std::move(unkeyableDecls)),
          stampable_(std::move(stampableDecls)),
          reallocSites_(std::move(reallocSites)),
          ownerRawResultSites_(std::move(ownerRawResultSites)),
          funcName_(std::move(funcName)), results_(results) {
        codeskeptic::Guarded<VarState> init;
        for (const auto* var : trackedVars_) {
            init.vars[var] = LifetimeState{};
            pointerFacts_.insert(var);
        }
        initState_.push_back(std::move(init));
    }

    State initialState() const { return initState_; }

    // Allocation, binding and pending-reallocation state can each climb
    // independently; the guarded-disjunct count multiplies that bound.
    unsigned latticeHeight() const {
        return (static_cast<unsigned>(trackedVars_.size()) * 12 + 1) *
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
        const std::vector<ReallocSite> reallocSites =
            reallocUpdates(stmt);
        const ReallocSite* callSite = nullptr;
        if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            auto found = reallocSites_.find(call);
            if (found != reallocSites_.end() && found->second.call)
                callSite = &found->second;
        }
        auto applyBindings = [&](bool deferred) {
            for (auto& disjunct : in) {
                for (const BindingUpdate& binding : bindings) {
                    if (binding.deferred != deferred) continue;
                    applyBindingUpdate(disjunct.vars, binding);
                }
            }
        };
        applyBindings(false);

        const std::vector<OwnerOperation> ownership = ownerOperations(
            stmt, trackedSet_, ownerRawResultSites_, ctx);
        for (auto& disjunct : in)
            for (const OwnerOperation& operation : ownership)
                applyOwnerOperation(operation, disjunct.vars);
        for (const VarDecl* owner : ownerEscapesAt(stmt))
            for (auto& disjunct : in)
                escapeOwner(owner, disjunct.vars);
        if (isa<CXXThrowExpr>(stmt))
            for (auto& disjunct : in)
                escapeOwnersAtUnmodelledThrow(disjunct.vars);

        // Effects are state-independent: classify once, apply to every disjunct
        StmtEffects effects = classifyStmtEffects(stmt, trackedSet_, ctx);
        if (effects.empty()) {
            applyBindings(true);
            return in;
        }

        State out = in;
        for (auto& d : out) {
            for (const auto& [var, effect] : effects) {
                if (effect == StmtEffect::Escapes && callSite &&
                    callSite->source == var &&
                    provesNonZeroRequest(*callSite, d, ctx))
                    continue;
                switch (effect) {
                    case StmtEffect::Allocates: {
                        const ReallocSite* update = nullptr;
                        for (const ReallocSite& candidate : reallocSites)
                            if (candidate.result == var) {
                                update = &candidate;
                                break;
                            }
                        const VarDecl* sourceOwner =
                            update
                                ? resolveBinding(update->source, d.vars)
                                : nullptr;
                        if (update && !sourceOwner) {
                            auto directSource = d.vars.find(update->source);
                            if (directSource != d.vars.end() &&
                                directSource->second.allocation !=
                                    AllocState::None)
                                sourceOwner = update->source;
                        }
                        const bool provenRequest =
                            update && provesNonZeroRequest(*update, d, ctx);
                        const AllocationFamily family = allocationFamilyOf(
                            allocationExprFor(stmt, var));
                        auto source = sourceOwner
                                          ? d.vars.find(sourceOwner)
                                          : d.vars.end();
                        const bool incompatibleRealloc =
                            update && source != d.vars.end() &&
                            source->second.allocation ==
                                AllocState::Allocated &&
                            (!source->second.allocatorFamilyKnown ||
                             !source->second.allocatorFamily.empty());
                        invalidateBindingDependents(d.vars, var);
                        if (incompatibleRealloc) {
                            d.vars[var].binding = nullptr;
                            d.vars[var].reallocSource = nullptr;
                            d.vars[var].allocatorFamily.clear();
                            d.vars[var].allocatorFamilyKnown = false;
                            d.vars[var].smartOwners.clear();
                            d.vars[var].smartOwnersKnown = false;
                            d.vars[var].referenceBinding = false;
                            d.vars[var].allocation = AllocState::Escaped;
                            break;
                        }
                        d.vars[var].binding = var;
                        d.vars[var].reallocSource = nullptr;
                        d.vars[var].allocatorFamily = family.name;
                        d.vars[var].allocatorFamilyKnown = family.known;
                        d.vars[var].smartOwners.clear();
                        d.vars[var].smartOwnersKnown = true;
                        d.vars[var].referenceBinding = false;
                        d.vars[var].allocation = AllocState::Allocated;
                        if (provenRequest && sourceOwner &&
                            sourceOwner != var) {
                            source = d.vars.find(sourceOwner);
                            if (source != d.vars.end() &&
                                source->second.allocation ==
                                    AllocState::Allocated &&
                                source->second.allocatorFamilyKnown &&
                                source->second.allocatorFamily.empty())
                                d.vars[var].reallocSource = sourceOwner;
                        }
                        break;
                    }
                    case StmtEffect::Frees: {
                        const VarDecl* owner = resolveBinding(var, d.vars);
                        if (!owner) break;
                        LifetimeState& lifetime = d.vars[owner];
                        const ReleaseAuthority authority =
                            releaseAuthority(stmt, lifetime);
                        if (authority == ReleaseAuthority::Match) {
                            lifetime.allocation = AllocState::Freed;
                        } else if (authority == ReleaseAuthority::Unknown) {
                            invalidateReallocRelations(d.vars, owner);
                            lifetime.allocation = AllocState::Escaped;
                        }
                        break;
                    }
                    case StmtEffect::Escapes: {
                        const VarDecl* owner = resolveBinding(var, d.vars);
                        if (owner) {
                            invalidateReallocRelations(d.vars, owner);
                            d.vars[owner].allocation = AllocState::Escaped;
                            d.vars[owner].smartOwners.clear();
                            d.vars[owner].smartOwnersKnown = false;
                        }
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

    State transferElement(const CFGElement& element,
                          const State& input,
                          ASTContext&) const {
        auto destructor = element.getAs<CFGAutomaticObjDtor>();
        if (!destructor) return input;
        const VarDecl* owner = destructor->getVarDecl();
        if (!owner ||
            standardOwnerKind(owner->getType()) == StandardOwnerKind::None)
            return input;
        State result = input;
        for (auto& disjunct : result)
            releaseOwner(owner, true, disjunct.vars);
        return result;
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

        for (const OwnerOperation& operation : ownerOperations(
                 stmt, trackedSet_, ownerRawResultSites_, ctx)) {
            const bool releasesOld =
                operation.kind == OwnerOperationKind::Reset ||
                ((operation.kind == OwnerOperationKind::Copy ||
                  operation.kind == OwnerOperationKind::Move) &&
                 operation.replaceOwner);
            if (!releasesOld) continue;
            for (const auto& disjunct : beforeDisjuncts) {
                for (const VarDecl* raw :
                     rootsOwnedBy(operation.owner, disjunct.vars)) {
                    const LifetimeState& lifetime =
                        disjunct.vars.find(raw)->second;
                    if (lifetime.allocation == AllocState::Freed &&
                        lifetime.smartOwners.size() == 1)
                        report(stmt, raw, ctx,
                               codeskeptic::Severity::Error,
                               "double-free",
                               codeskeptic::MsgId::DoubleFree, raw);
                }
            }
        }

        for (const auto& [var, effect] :
             classifyStmtEffects(stmt, trackedSet_, ctx)) {
            auto it = before.find(var);
            if (it == before.end()) continue;

            if (effect == StmtEffect::Allocates &&
                it->second.allocation == AllocState::Allocated) {
                bool reportOverwrite = true;
                for (const ReallocSite& site : reallocUpdates(stmt)) {
                    if (site.result != var) continue;
                    bool sourceOverwriteOnly = true;
                    bool provenFailureLeak = false;
                    for (const auto& disjunct : beforeDisjuncts) {
                        auto old = disjunct.vars.find(var);
                        if (old == disjunct.vars.end() ||
                            old->second.allocation != AllocState::Allocated)
                            continue;
                        const VarDecl* sourceOwner =
                            resolveBinding(site.source, disjunct.vars);
                        if (site.source != var && sourceOwner != var) {
                            sourceOverwriteOnly = false;
                            break;
                        }
                        if (provesNonZeroRequest(site, disjunct, ctx))
                            provenFailureLeak = true;
                    }
                    if (sourceOverwriteOnly)
                        reportOverwrite = provenFailureLeak;
                    break;
                }
                if (reportOverwrite)
                    report(stmt, var, ctx,
                           codeskeptic::Severity::Warning,
                           "memory-leak",
                           codeskeptic::MsgId::LeakReassign);
            } else if (effect == StmtEffect::Frees) {
                const VarDecl* owner = resolveBinding(var, before);
                auto ownerState = owner ? before.find(owner) : before.end();
                if (ownerState == before.end() ||
                    ownerState->second.allocation != AllocState::Freed ||
                    releaseAuthority(stmt, ownerState->second) !=
                        ReleaseAuthority::Match)
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

    void onCFGElement(const CFGElement& element,
                      const State& beforeDisjuncts,
                      const State& afterDisjuncts,
                      ASTContext& ctx) {
        auto destructor = element.getAs<CFGAutomaticObjDtor>();
        if (!destructor) return;
        const VarDecl* owner = destructor->getVarDecl();
        const Stmt* trigger = destructor->getTriggerStmt();
        if (!owner || !trigger ||
            standardOwnerKind(owner->getType()) == StandardOwnerKind::None)
            return;

        VarState before = flattenState(beforeDisjuncts);
        VarState after = flattenState(afterDisjuncts);
        for (const auto& [raw, afterState] : after) {
            auto prior = before.find(raw);
            if (prior != before.end() &&
                prior->second.allocation != afterState.allocation &&
                afterState.allocation == AllocState::Freed)
                recordEvent(trigger, raw, ctx,
                            codeskeptic::MsgId::TraceFreedHere);
        }

        for (const auto& disjunct : beforeDisjuncts) {
            for (const VarDecl* raw : rootsOwnedBy(owner, disjunct.vars)) {
                const LifetimeState& lifetime =
                    disjunct.vars.find(raw)->second;
                if (lifetime.allocation == AllocState::Freed &&
                    lifetime.smartOwners.size() == 1)
                    report(trigger, raw, ctx,
                           codeskeptic::Severity::Error,
                           "double-free",
                           codeskeptic::MsgId::DoubleFree, raw);
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
    std::map<const CallExpr*, ReallocSite> reallocSites_;
    OwnerRawResultSites ownerRawResultSites_;
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
        collectReallocSites(funcDecl),
        collectOwnerRawResultSites(funcDecl),
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
                bool coveredByAlternative = false;
                for (const auto& [resultVar, resultState] : d.vars) {
                    if (resultVar != var &&
                        resultState.allocation == AllocState::Allocated &&
                        resultState.reallocSource == var) {
                        coveredByAlternative = true;
                        break;
                    }
                }
                if (coveredByAlternative) continue;
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
