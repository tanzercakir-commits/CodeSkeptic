#include "engine/FunctionSummary.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>

using namespace clang;

namespace {

constexpr unsigned kMaxSweeps = 5;

using ReturnNullness = zerodefect::SummaryRegistry::ReturnNullness;
using ParamEffect = zerodefect::SummaryRegistry::ParamEffect;
using FunctionSummary = zerodefect::SummaryRegistry::FunctionSummary;
using SummaryTable = std::map<const FunctionDecl*, FunctionSummary>;

const ParmVarDecl* asParam(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<ParmVarDecl>(ref->getDecl());
    return nullptr;
}

// expr icinde (herhangi bir derinlikte) parametreye referans var mi?
bool containsRef(const Expr* expr, const ParmVarDecl* param) {
    if (!expr) return false;
    struct Finder : RecursiveASTVisitor<Finder> {
        const ParmVarDecl* target;
        bool found = false;
        bool VisitDeclRefExpr(DeclRefExpr* ref) {
            if (ref->getDecl() == target) {
                found = true;
                return false;  // aramayi durdur
            }
            return true;
        }
    };
    Finder finder;
    finder.target = param;
    finder.TraverseStmt(const_cast<Expr*>(expr));
    return finder.found;
}

// --- Donus nullness'i ---

// Donus ifadesinin null'lugu: literal/new/&x/string dogrudan; cagri
// zinciri onceki taramanin ozetleriyle cozulur.
ReturnNullness evaluateReturnExpr(const Expr* expr,
                                  const SummaryTable& previous) {
    if (!expr) return ReturnNullness::Unknown;
    expr = expr->IgnoreParenCasts();

    if (isa<CXXNullPtrLiteralExpr>(expr)) return ReturnNullness::MaybeNull;
    if (isa<GNUNullExpr>(expr)) return ReturnNullness::MaybeNull;
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr))
        return lit->getValue() == 0 ? ReturnNullness::MaybeNull
                                    : ReturnNullness::NeverNull;
    if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
        if (unary->getOpcode() == UO_AddrOf)
            return ReturnNullness::NeverNull;
    }
    if (isa<CXXNewExpr>(expr)) return ReturnNullness::NeverNull;
    if (isa<StringLiteral>(expr)) return ReturnNullness::NeverNull;

    if (const auto* call = dyn_cast<CallExpr>(expr)) {
        if (const auto* callee = call->getDirectCallee()) {
            auto it = previous.find(callee->getCanonicalDecl());
            if (it != previous.end())
                return it->second.returnNullness;
        }
        return ReturnNullness::Unknown;
    }
    return ReturnNullness::Unknown;
}

ReturnNullness computeReturnNullness(const FunctionDecl* func,
                                     const SummaryTable& previous) {
    if (!func->getReturnType()->isPointerType())
        return ReturnNullness::Unknown;

    struct ReturnCollector : RecursiveASTVisitor<ReturnCollector> {
        std::vector<const Expr*> returns;
        bool VisitReturnStmt(ReturnStmt* ret) {
            returns.push_back(ret->getRetValue());
            return true;
        }
        // Ic ice fonksiyonlarin (lambda) return'leri sayilmasin
        bool TraverseLambdaExpr(LambdaExpr*) { return true; }
    };
    ReturnCollector collector;
    collector.TraverseStmt(func->getBody());
    if (collector.returns.empty()) return ReturnNullness::Unknown;

    bool sawNull = false;
    bool allNeverNull = true;
    for (const auto* ret : collector.returns) {
        ReturnNullness r = evaluateReturnExpr(ret, previous);
        if (r == ReturnNullness::MaybeNull) sawNull = true;
        if (r != ReturnNullness::NeverNull) allNeverNull = false;
    }
    // Herhangi bir yol null dondurebiliyorsa MaybeNull — diger yollarin
    // belirsizligi bunu zayiflatmaz. NeverNull ise TUM yollarin kesin
    // non-null olmasini gerektirir (guclu iddia).
    if (sawNull) return ReturnNullness::MaybeNull;
    if (allNeverNull) return ReturnNullness::NeverNull;
    return ReturnNullness::Unknown;
}

// --- Parametre etkileri ---

struct ParamFlags {
    bool frees = false;
    bool stores = false;
};

class ParamEffectVisitor : public RecursiveASTVisitor<ParamEffectVisitor> {
public:
    ParamEffectVisitor(const FunctionDecl* func,
                       const SummaryTable& previous,
                       std::map<const ParmVarDecl*, ParamFlags>& flags)
        : previous_(previous), flags_(flags) {
        for (const auto* p : func->parameters())
            if (p->getType()->isPointerType()) flags_[p];  // kaydi ac
    }

    bool VisitCXXDeleteExpr(CXXDeleteExpr* del) {
        if (const auto* p = tracked(asParam(del->getArgument())))
            flags_[p].frees = true;
        return true;
    }

    bool VisitCallExpr(CallExpr* call) {
        const FunctionDecl* callee = call->getDirectCallee();
        const FunctionSummary* summary = nullptr;
        bool isFreeByName = false;
        if (callee) {
            isFreeByName = callee->getName() == "free";
            auto it = previous_.find(callee->getCanonicalDecl());
            if (it != previous_.end()) summary = &it->second;
        }

        for (unsigned i = 0; i < call->getNumArgs(); ++i) {
            const Expr* arg = call->getArg(i);
            if (const auto* p = tracked(asParam(arg))) {
                if (isFreeByName && i == 0) {
                    flags_[p].frees = true;
                } else if (summary) {
                    switch (summary->paramEffect(i)) {
                        case ParamEffect::Frees:
                            flags_[p].frees = true; break;
                        case ParamEffect::ReadsOnly:
                            break;  // etkisiz
                        case ParamEffect::Stores:
                        case ParamEffect::Opaque:
                            flags_[p].stores = true; break;
                    }
                } else {
                    flags_[p].stores = true;  // opak cagri
                }
            } else {
                // Parametre argumanin ICINDE geciyorsa (p ? p : q gibi)
                // turetilmis deger kaciyor olabilir — muhafazakar
                for (auto& [param, f] : flags_) {
                    if (containsRef(arg, param)) f.stores = true;
                }
            }
        }
        return true;
    }

    bool VisitBinaryOperator(BinaryOperator* binOp) {
        if (binOp->getOpcode() != BO_Assign) return true;
        // p = ... : parametrenin YENIDEN atanmasi etki degildir (yerel
        // kopya degisir); ... = p ise alias/kacis — muhafazakar Stores
        if (const auto* p = tracked(asParam(binOp->getRHS())))
            flags_[p].stores = true;
        return true;
    }

    bool VisitVarDecl(VarDecl* var) {
        // Yerel alias: Node* q = p; (cJSON_Delete kalibi) — v1'de Stores
        if (var->hasInit())
            if (const auto* p = tracked(asParam(var->getInit())))
                flags_[p].stores = true;
        return true;
    }

    bool VisitReturnStmt(ReturnStmt* ret) {
        // return p; — cagirana geri kacis (sahiplik devri olabilir)
        if (const auto* p = tracked(asParam(ret->getRetValue())))
            flags_[p].stores = true;
        return true;
    }

    bool VisitUnaryOperator(UnaryOperator* unary) {
        if (unary->getOpcode() == UO_AddrOf)
            if (const auto* p = tracked(asParam(unary->getSubExpr())))
                flags_[p].stores = true;
        return true;
    }

private:
    const ParmVarDecl* tracked(const ParmVarDecl* p) const {
        if (!p) return nullptr;
        return flags_.count(p) ? p : nullptr;
    }

    const SummaryTable& previous_;
    std::map<const ParmVarDecl*, ParamFlags>& flags_;
};

std::vector<ParamEffect> computeParamEffects(const FunctionDecl* func,
                                             const SummaryTable& previous) {
    std::map<const ParmVarDecl*, ParamFlags> flags;
    ParamEffectVisitor visitor(func, previous, flags);
    visitor.TraverseStmt(func->getBody());

    std::vector<ParamEffect> effects;
    effects.reserve(func->getNumParams());
    for (const auto* p : func->parameters()) {
        if (!p->getType()->isPointerType()) {
            effects.push_back(ParamEffect::Opaque);
            continue;
        }
        const ParamFlags& f = flags[p];
        if (f.stores)
            effects.push_back(ParamEffect::Stores);
        else if (f.frees)
            effects.push_back(ParamEffect::Frees);
        else
            effects.push_back(ParamEffect::ReadsOnly);
    }
    return effects;
}

// --- TU'daki govdeli fonksiyonlari topla ---

struct FunctionCollector : RecursiveASTVisitor<FunctionCollector> {
    std::vector<const FunctionDecl*> functions;
    bool VisitFunctionDecl(FunctionDecl* func) {
        if (func->isThisDeclarationADefinition() && func->hasBody())
            functions.push_back(func);
        return true;
    }
};

} // anonymous namespace

namespace zerodefect {

SummaryRegistry& SummaryRegistry::instance() {
    static SummaryRegistry registry;
    return registry;
}

void SummaryRegistry::clear() { summaries_.clear(); }

void SummaryRegistry::rebuild(clang::ASTContext& ctx) {
    summaries_.clear();

    FunctionCollector collector;
    collector.TraverseDecl(ctx.getTranslationUnitDecl());

    // Sabit noktali tarama: her turda ozetler onceki turun tablosuyla
    // SIFIRDAN hesaplanir; degisiklik kalmayinca durulur. Rekursiyon
    // kendi eski ozetini gorur — guclu iddialar (NeverNull, ReadsOnly)
    // ancak desteklenirse olusur.
    SummaryTable current;
    for (unsigned sweep = 0; sweep < kMaxSweeps; ++sweep) {
        SummaryTable next;
        bool changed = false;
        for (const auto* func : collector.functions) {
            FunctionSummary summary;
            summary.returnNullness = computeReturnNullness(func, current);
            summary.params = computeParamEffects(func, current);

            const auto* key = func->getCanonicalDecl();
            next[key] = summary;

            auto prev = current.find(key);
            if (prev == current.end() ||
                prev->second.returnNullness != summary.returnNullness ||
                prev->second.params != summary.params) {
                changed = true;
            }
        }
        current = std::move(next);
        if (!changed) break;
    }
    summaries_ = std::move(current);
}

const SummaryRegistry::FunctionSummary*
SummaryRegistry::lookup(const clang::FunctionDecl* func) const {
    if (!func) return nullptr;
    auto it = summaries_.find(func->getCanonicalDecl());
    if (it == summaries_.end()) return nullptr;
    return &it->second;
}

} // namespace zerodefect
