#include "engine/FunctionSummary.h"

#include "engine/ConditionWalk.h"
#include "engine/DataflowEngine.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Stmt.h>

#include <algorithm>
#include <fstream>
#include <set>
#include <utility>
#include <vector>

using namespace clang;

namespace {

constexpr unsigned kMaxSweeps = 5;

using ReturnNullness = zerodefect::SummaryRegistry::ReturnNullness;
using ParamEffect = zerodefect::SummaryRegistry::ParamEffect;
using FunctionSummary = zerodefect::SummaryRegistry::FunctionSummary;
using SummaryTable = std::map<const FunctionDecl*, FunctionSummary>;

// --- Donus nullness'i ---

// Donus ifadesinin null'lugu: literal/new/&x/string dogrudan; cagri
// zinciri onceki taramanin ozetleriyle cozulur.
// Cagrilan ozetini once TU-yerel tabloda, yoksa cross-TU depoda ara.
// (Whole-program 1. gecisi depoyu doldurur; tek-TU modda depo bos,
// davranis eskisiyle ayni.)
const FunctionSummary* lookupPrev(const SummaryTable& previous,
                                  const FunctionDecl* callee) {
    if (!callee) return nullptr;
    auto it = previous.find(callee->getCanonicalDecl());
    if (it != previous.end()) return &it->second;
    return zerodefect::SummaryRegistry::instance().lookupGlobal(callee);
}

// Deger-duzeyi null durumu. NullDerefRule'un lattice'iyle ayni sekil;
// ozet baglaminda yasar (TU-anonim, cakisma yok).
enum class VState { Unknown, Null, NonNull, MaybeNull };

VState mergeVState(VState a, VState b) {
    if (a == b) return a;
    bool anyNullInfo = a == VState::Null || a == VState::MaybeNull ||
                       b == VState::Null || b == VState::MaybeNull;
    return anyNullInfo ? VState::MaybeNull : VState::Unknown;
}

// Ifadenin null durumu: literal/new/&x/string dogrudan; cagri zinciri
// onceki taramanin ozetleriyle (+ cross-TU depo) cozulur.
VState vstateOf(const Expr* expr, const SummaryTable& previous) {
    if (!expr) return VState::Unknown;
    expr = expr->IgnoreParenCasts();

    if (isa<CXXNullPtrLiteralExpr>(expr)) return VState::Null;
    if (isa<GNUNullExpr>(expr)) return VState::Null;
    if (const auto* lit = dyn_cast<IntegerLiteral>(expr))
        return lit->getValue() == 0 ? VState::Null : VState::NonNull;
    if (const auto* unary = dyn_cast<UnaryOperator>(expr)) {
        if (unary->getOpcode() == UO_AddrOf) return VState::NonNull;
    }
    if (isa<CXXNewExpr>(expr)) return VState::NonNull;
    if (isa<StringLiteral>(expr)) return VState::NonNull;

    if (const auto* call = dyn_cast<CallExpr>(expr)) {
        if (const auto* summary =
                lookupPrev(previous, call->getDirectCallee())) {
            if (summary->returnNullness == ReturnNullness::NeverNull)
                return VState::NonNull;
            if (summary->returnNullness == ReturnNullness::MaybeNull)
                return VState::MaybeNull;
        }
        return VState::Unknown;
    }
    return VState::Unknown;
}

const VarDecl* exprAsVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

// Kosul kenarlarinda pointer nullness iyilestirmesi — ortak yuruyus
// iskeleti uzerinden (engine/ConditionWalk.h)
void applyNullCond(const Expr* cond, bool isTrue,
                   std::map<const VarDecl*, VState>& state) {
    zerodefect::walkNullCondition(
        cond, isTrue, [&](const VarDecl* var, bool isNull) {
            auto it = state.find(var);
            if (it != state.end())
                it->second = isNull ? VState::Null : VState::NonNull;
        });
}

// --- Degisken donduren yollar icin mini null-akisi ---
//
// `return p;` yollari yapisal degerlendirmeyle Unknown kaliyordu (v1
// siniri). Simdi pointer yerelleri/parametreleri kendi motorumuzla
// (runDataflow: iki fazli raporlama + assume-edge iyilestirmesi) akis-
// DUYARLI izlenir ve her return elemani yakinsamis durumdan katki alir.
// Akis-duyarsiz kestirme bilincli reddedildi: `p = NULL; p = &g;
// return p;` kalibinda yanlis MaybeNull uretir, precision'i yakardi.
//
// Katki eslemesi: Null/MaybeNull -> "bu yol null dondurebilir";
// NonNull -> NeverNull katkisi; Unknown -> Unknown. Fonksiyon toplami
// eski kuralla ayni: herhangi bir null yolu -> MaybeNull; TUM yollar
// NonNull -> NeverNull; aksi Unknown. CFG'nin ulasamadigi return'ler
// (olu kod) katki vermez.
class ReturnNullFlowAnalysis {
public:
    using State = std::map<const VarDecl*, VState>;

    ReturnNullFlowAnalysis(std::vector<const VarDecl*> trackedVars,
                           const SummaryTable& previous)
        : previous_(previous) {
        for (const auto* var : trackedVars)
            initState_[var] = VState::Unknown;
    }

    State initialState() const { return initState_; }

    unsigned latticeHeight() const {
        return static_cast<unsigned>(initState_.size()) * 3 + 1;
    }

    State merge(const State& a, const State& b) const {
        State result = a;
        for (const auto& [var, sb] : b) {
            auto it = result.find(var);
            if (it == result.end()) result[var] = sb;
            else it->second = mergeVState(it->second, sb);
        }
        return result;
    }

    State transfer(const Stmt* stmt, const State& in,
                   ASTContext& /*ctx*/) const {
        if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
            State out = in;
            for (const auto* decl : declStmt->decls()) {
                if (const auto* vd = dyn_cast<VarDecl>(decl)) {
                    auto it = out.find(vd);
                    if (it != out.end() && vd->hasInit())
                        it->second = vstateOf(vd->getInit(), previous_);
                }
            }
            return out;
        }
        if (const auto* binOp = dyn_cast<BinaryOperator>(stmt)) {
            if (binOp->getOpcode() != BO_Assign) return in;
            const VarDecl* var = exprAsVar(binOp->getLHS());
            auto it = var ? in.find(var) : in.end();
            if (it == in.end()) return in;
            State out = in;
            out[var] = vstateOf(binOp->getRHS(), previous_);
            return out;
        }
        if (const auto* unary = dyn_cast<UnaryOperator>(stmt)) {
            // &p bir fonksiyona gidiyorsa p degismis olabilir
            if (unary->getOpcode() == UO_AddrOf) {
                const VarDecl* var = exprAsVar(unary->getSubExpr());
                auto it = var ? in.find(var) : in.end();
                if (it == in.end()) return in;
                State out = in;
                out[var] = VState::Unknown;
                return out;
            }
        }
        return in;
    }

    void refineOnEdge(const Stmt* cond, bool isTrueBranch, State& state,
                      ASTContext& /*ctx*/) const {
        applyNullCond(dyn_cast<Expr>(cond), isTrueBranch, state);
    }

    // Fixpoint sonrasi: her ULASILABILIR return'un katkisi toplanir
    void onStatement(const Stmt* stmt, const State& before,
                     const State& /*after*/, ASTContext& /*ctx*/) {
        const auto* ret = dyn_cast<ReturnStmt>(stmt);
        if (!ret || !ret->getRetValue()) return;

        const Expr* expr = ret->getRetValue();
        VState v;
        if (const VarDecl* var = exprAsVar(expr)) {
            auto it = before.find(var);
            v = (it != before.end()) ? it->second
                                     : vstateOf(expr, previous_);
        } else {
            v = vstateOf(expr, previous_);
        }
        contributions.push_back(v);
    }

    std::vector<VState> contributions;

private:
    const SummaryTable& previous_;
    State initState_;
};

ReturnNullness aggregateContributions(const std::vector<VState>& contribs) {
    if (contribs.empty()) return ReturnNullness::Unknown;
    bool sawNull = false;
    bool allNeverNull = true;
    for (VState v : contribs) {
        if (v == VState::Null || v == VState::MaybeNull) sawNull = true;
        if (v != VState::NonNull) allNeverNull = false;
    }
    // Herhangi bir yol null dondurebiliyorsa MaybeNull — diger yollarin
    // belirsizligi bunu zayiflatmaz. NeverNull ise TUM yollarin kesin
    // non-null olmasini gerektirir (guclu iddia).
    if (sawNull) return ReturnNullness::MaybeNull;
    if (allNeverNull) return ReturnNullness::NeverNull;
    return ReturnNullness::Unknown;
}

ReturnNullness computeReturnNullness(const FunctionDecl* func,
                                     ASTContext& ctx,
                                     const SummaryTable& previous) {
    if (!func->getReturnType()->isPointerType())
        return ReturnNullness::Unknown;

    struct ReturnCollector : RecursiveASTVisitor<ReturnCollector> {
        std::vector<const Expr*> returns;
        bool anyVarReturn = false;
        bool VisitReturnStmt(ReturnStmt* ret) {
            returns.push_back(ret->getRetValue());
            if (exprAsVar(ret->getRetValue())) anyVarReturn = true;
            return true;
        }
        // Ic ice fonksiyonlarin (lambda) return'leri sayilmasin
        bool TraverseLambdaExpr(LambdaExpr*) { return true; }
    };
    ReturnCollector collector;
    collector.TraverseStmt(func->getBody());
    if (collector.returns.empty()) return ReturnNullness::Unknown;

    // Hizli yol: degisken donduren return yoksa CFG'siz yapisal
    // degerlendirme yeterli (yaygin durum; dataflow maliyeti odenmez)
    if (!collector.anyVarReturn) {
        std::vector<VState> contribs;
        contribs.reserve(collector.returns.size());
        for (const auto* ret : collector.returns)
            contribs.push_back(vstateOf(ret, previous));
        return aggregateContributions(contribs);
    }

    // Degisken donduren yol var: pointer yerelleri/parametreleri topla
    // ve mini null-akisini kos
    struct PtrVarCollector : RecursiveASTVisitor<PtrVarCollector> {
        std::set<const VarDecl*> vars;
        bool VisitVarDecl(VarDecl* vd) {
            if (vd->getType()->isPointerType()) vars.insert(vd);
            return true;
        }
        bool TraverseLambdaExpr(LambdaExpr*) { return true; }
    };
    PtrVarCollector ptrVars;
    ptrVars.TraverseStmt(func->getBody());
    for (const auto* param : func->parameters())
        if (param->getType()->isPointerType()) ptrVars.vars.insert(param);

    ReturnNullFlowAnalysis analysis(
        {ptrVars.vars.begin(), ptrVars.vars.end()}, previous);
    zerodefect::runDataflow(func, ctx, analysis);
    return aggregateContributions(analysis.contributions);
}

// --- Parametre etkileri (v2: alias izlemeli) ---
//
// Iki gecis:
//  A) Kopya kenarlari toplanir (`T* L = X;` / `L = X;`, X dogrudan
//     param/yerel referansi, L yerel) + taint tohumlari (dogrudan-ref
//     olmayan atama, adresi alinan yerel, static yerel).
//  B) Etki baglamlar temiz alias'lar uzerinden parametreye cozulur.
//
// Taint kurallari: kirli kaynaktan beslenen, adresi alinan veya birden
// fazla parametreden ulasilabilen yerel "temiz alias" DEGILDIR; boyle
// bir yerele ulasan parametre muhafazakar olarak Stores'a duser (yanlis
// Frees/ReadsOnly iddiasi FP uretebilirdi).
//
// Bilinen asiri-yaklasim (may-semantik): parametrenin kendisi yeniden
// atansa da adi orijinal degeri temsil etmeye devam eder — cJSON_Delete
// tarzi `while(item){ ...; free(item); item = next; }` donguleri boylece
// Frees gorulur (ilk iterasyon orijinali serbest birakir).

struct ParamFlags {
    bool frees = false;
    bool stores = false;
};

llvm::StringRef calleeIdentifier(const FunctionDecl* callee) {
    if (!callee) return {};
    if (const auto* id = callee->getIdentifier()) return id->getName();
    return {};
}

const ValueDecl* asVarOrParam(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());  // ParmVarDecl dahil
    return nullptr;
}

bool isPlainLocal(const ValueDecl* d) {
    const auto* var = dyn_cast_or_null<VarDecl>(d);
    return var && !isa<ParmVarDecl>(var) && var->hasLocalStorage();
}

// Pass A: kopya grafi + taint tohumlari
class AliasCollector : public RecursiveASTVisitor<AliasCollector> {
public:
    std::vector<std::pair<const ValueDecl*, const VarDecl*>> edges;
    std::set<const VarDecl*> tainted;

    bool VisitVarDecl(VarDecl* var) {
        if (!var->hasInit() || isa<ParmVarDecl>(var)) return true;
        if (!var->hasLocalStorage()) return true;  // static yerel: pass B
        recordAssign(var, var->getInit());
        return true;
    }

    bool VisitBinaryOperator(BinaryOperator* binOp) {
        if (binOp->getOpcode() != BO_Assign) return true;
        const ValueDecl* lhs = asVarOrParam(binOp->getLHS());
        if (isPlainLocal(lhs))
            recordAssign(cast<VarDecl>(lhs), binOp->getRHS());
        return true;
    }

    bool VisitUnaryOperator(UnaryOperator* unary) {
        if (unary->getOpcode() != UO_AddrOf) return true;
        // Adresi alinan yerel disaridan yazilabilir — izlenemez
        const ValueDecl* operand = asVarOrParam(unary->getSubExpr());
        if (isPlainLocal(operand))
            tainted.insert(cast<VarDecl>(operand));
        return true;
    }

private:
    void recordAssign(const VarDecl* target, const Expr* value) {
        const ValueDecl* source = asVarOrParam(value);
        bool directRef = source && (isa<ParmVarDecl>(source) ||
                                    isPlainLocal(source));
        if (directRef)
            edges.emplace_back(source, target);
        else
            tainted.insert(target);  // kirli kaynak (cagri, uye, aritmetik)
    }
};

struct AliasInfo {
    // temiz yerel alias -> tek parametre kaynagi
    std::map<const VarDecl*, const ParmVarDecl*> cleanAlias;
    // parametre -> {parametre + temiz alias'lari} (containment icin)
    std::map<const ParmVarDecl*, std::set<const ValueDecl*>> family;
    // kirli/cok-kaynakli yerele ulasan parametreler
    std::set<const ParmVarDecl*> taintedReach;
};

AliasInfo computeAliases(const FunctionDecl* func,
                         const AliasCollector& collected) {
    AliasInfo info;

    // Taint yayilimi: kirli yerelden kopyalanan da kirlidir
    std::set<const VarDecl*> tainted = collected.tainted;
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto& [from, to] : collected.edges) {
            const auto* fromLocal = dyn_cast<VarDecl>(from);
            if (fromLocal && !isa<ParmVarDecl>(fromLocal) &&
                tainted.count(fromLocal) && tainted.insert(to).second)
                changed = true;
        }
    }

    // Koken kumeleri: parametrelerden temiz yereller uzerinden BFS.
    // Kirli yerele ULASAN parametre taintedReach'e girer.
    std::map<const VarDecl*, std::set<const ParmVarDecl*>> origins;
    for (const auto* p : func->parameters()) {
        if (!p->getType()->isPointerType()) continue;
        std::set<const ValueDecl*> frontier{p};
        std::set<const ValueDecl*> visited{p};
        while (!frontier.empty()) {
            std::set<const ValueDecl*> next;
            for (const auto& [from, to] : collected.edges) {
                if (!frontier.count(from) || visited.count(to)) continue;
                visited.insert(to);
                if (tainted.count(to)) {
                    info.taintedReach.insert(p);
                    continue;  // kirliden oteye koken tasimayiz
                }
                origins[to].insert(p);
                next.insert(to);
            }
            frontier = std::move(next);
        }
    }

    for (const auto& [local, params] : origins) {
        if (params.size() == 1) {
            const ParmVarDecl* p = *params.begin();
            info.cleanAlias[local] = p;
            info.family[p].insert(local);
        } else {
            // Birden fazla parametreden ulasilabilen yerel: hicbirine
            // guvenle baglanamaz — ilgili parametreler muhafazakar
            for (const auto* p : params) info.taintedReach.insert(p);
        }
    }
    for (const auto* p : func->parameters())
        if (p->getType()->isPointerType()) info.family[p].insert(p);

    return info;
}

// expr icinde ailedeki (param + temiz alias'lar) herhangi bir uye var mi?
bool containsAnyRef(const Expr* expr,
                    const std::set<const ValueDecl*>& family) {
    if (!expr) return false;
    struct Finder : RecursiveASTVisitor<Finder> {
        const std::set<const ValueDecl*>* family;
        bool found = false;
        bool VisitDeclRefExpr(DeclRefExpr* ref) {
            if (family->count(ref->getDecl())) {
                found = true;
                return false;
            }
            return true;
        }
    };
    Finder finder;
    finder.family = &family;
    finder.TraverseStmt(const_cast<Expr*>(expr));
    return finder.found;
}

// Pass B: etkiler — baglamlar alias'lar uzerinden parametreye cozulur
class ParamEffectVisitor : public RecursiveASTVisitor<ParamEffectVisitor> {
public:
    ParamEffectVisitor(const FunctionDecl* func,
                       const SummaryTable& previous,
                       const AliasInfo& aliases,
                       std::map<const ParmVarDecl*, ParamFlags>& flags)
        : previous_(previous), aliases_(aliases), flags_(flags) {
        for (const auto* p : func->parameters())
            if (p->getType()->isPointerType()) flags_[p];  // kaydi ac
    }

    bool VisitCXXDeleteExpr(CXXDeleteExpr* del) {
        if (const auto* p = resolve(del->getArgument()))
            flags_[p].frees = true;
        return true;
    }

    bool VisitCallExpr(CallExpr* call) {
        const FunctionDecl* callee = call->getDirectCallee();
        bool isFreeByName = calleeIdentifier(callee) == "free";
        const FunctionSummary* summary = lookupPrev(previous_, callee);

        for (unsigned i = 0; i < call->getNumArgs(); ++i) {
            const Expr* arg = call->getArg(i);
            if (const auto* p = resolve(arg)) {
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
                // Aile uyesi argumanin ICINDE geciyorsa (p ? p : q)
                // turetilmis deger kaciyor olabilir — muhafazakar
                for (auto& [param, f] : flags_) {
                    if (containsAnyRef(arg, aliases_.family.at(param)))
                        f.stores = true;
                }
            }
        }
        return true;
    }

    bool VisitBinaryOperator(BinaryOperator* binOp) {
        if (binOp->getOpcode() != BO_Assign) return true;
        const auto* p = resolve(binOp->getRHS());
        if (!p) return true;
        // Yerel/param hedefe kopya alias grafinin isi (pass A + taint);
        // diger her hedef (global, uye, deref, dizi) gercek kacis
        const ValueDecl* lhs = asVarOrParam(binOp->getLHS());
        bool lhsIsLocalish =
            lhs && (isa<ParmVarDecl>(lhs) || isPlainLocal(lhs));
        if (!lhsIsLocalish) flags_[p].stores = true;
        return true;
    }

    bool VisitVarDecl(VarDecl* var) {
        // static yerel init: fonksiyon omrunu asan saklama
        if (isa<ParmVarDecl>(var) || !var->hasInit()) return true;
        if (var->hasLocalStorage()) return true;  // pass A halletti
        if (const auto* p = resolve(var->getInit()))
            flags_[p].stores = true;
        return true;
    }

    bool VisitReturnStmt(ReturnStmt* ret) {
        // return p / return alias — cagirana geri kacis
        if (const auto* p = resolve(ret->getRetValue()))
            flags_[p].stores = true;
        return true;
    }

    bool VisitUnaryOperator(UnaryOperator* unary) {
        if (unary->getOpcode() != UO_AddrOf) return true;
        // &p (parametrenin adresi) — izlenemez yazma kanali.
        // (&alias pass A'da taint tohumu; taintedReach halleder.)
        const ValueDecl* operand = asVarOrParam(unary->getSubExpr());
        if (const auto* p = dyn_cast_or_null<ParmVarDecl>(operand))
            if (flags_.count(p)) flags_[p].stores = true;
        return true;
    }

private:
    const ParmVarDecl* resolve(const Expr* expr) const {
        const ValueDecl* d = asVarOrParam(expr);
        if (!d) return nullptr;
        if (const auto* p = dyn_cast<ParmVarDecl>(d))
            return flags_.count(p) ? p : nullptr;
        auto it = aliases_.cleanAlias.find(cast<VarDecl>(d));
        return it != aliases_.cleanAlias.end() ? it->second : nullptr;
    }

    const SummaryTable& previous_;
    const AliasInfo& aliases_;
    std::map<const ParmVarDecl*, ParamFlags>& flags_;
};

std::vector<ParamEffect> computeParamEffects(const FunctionDecl* func,
                                             const SummaryTable& previous) {
    AliasCollector collector;
    collector.TraverseStmt(func->getBody());
    AliasInfo aliases = computeAliases(func, collector);

    std::map<const ParmVarDecl*, ParamFlags> flags;
    ParamEffectVisitor visitor(func, previous, aliases, flags);
    visitor.TraverseStmt(func->getBody());

    // Kirli/cok-kaynakli yerele ulasan parametre: izlenemez akis
    for (const auto* p : aliases.taintedReach)
        if (flags.count(p)) flags[p].stores = true;

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
            summary.returnNullness = computeReturnNullness(func, ctx, current);
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
    if (it != summaries_.end()) return &it->second;
    return lookupGlobal(func);
}

namespace {

std::string globalKey(const FunctionDecl* func) {
    return func->getQualifiedNameAsString() + "/" +
           std::to_string(func->getNumParams());
}

// Ayni anahtara dusen farkli ozetler (C++ overload'lari) muhafazakar
// birlesir: uyusmayan alan zayif iddiaya duser — yanlis guclu iddia
// (NeverNull/Frees/ReadsOnly) cakismadan dogamaz.
void mergeConservative(SummaryRegistry::FunctionSummary& into,
                       const SummaryRegistry::FunctionSummary& from) {
    using RN = SummaryRegistry::ReturnNullness;
    using PE = SummaryRegistry::ParamEffect;
    if (into.returnNullness != from.returnNullness)
        into.returnNullness = RN::Unknown;
    if (into.params.size() != from.params.size()) {
        into.params.clear();  // paramEffect() varsayilani Opaque'tir
        return;
    }
    for (size_t i = 0; i < into.params.size(); ++i)
        if (into.params[i] != from.params[i]) into.params[i] = PE::Opaque;
}

// --- Disk formati (v1) ---
//
// Baslik satiri + kayit basina bir satir: anahtar<TAB>donus<TAB>paramlar
// Donus: U/N/M; parametreler O/R/F/S karakter dizisi, bos vektor "-".
// Nitelikli adlar TAB/yenisatir iceremez — anahtar guvenli.
constexpr const char* kSummaryFileHeader = "zerodefect-summaries v1";

char rnToChar(ReturnNullness v) {
    switch (v) {
        case ReturnNullness::NeverNull: return 'N';
        case ReturnNullness::MaybeNull: return 'M';
        case ReturnNullness::Unknown:   break;
    }
    return 'U';
}

bool rnFromChar(char c, ReturnNullness& out) {
    switch (c) {
        case 'U': out = ReturnNullness::Unknown;   return true;
        case 'N': out = ReturnNullness::NeverNull; return true;
        case 'M': out = ReturnNullness::MaybeNull; return true;
    }
    return false;
}

char peToChar(ParamEffect v) {
    switch (v) {
        case ParamEffect::ReadsOnly: return 'R';
        case ParamEffect::Frees:     return 'F';
        case ParamEffect::Stores:    return 'S';
        case ParamEffect::Opaque:    break;
    }
    return 'O';
}

bool peFromChar(char c, ParamEffect& out) {
    switch (c) {
        case 'O': out = ParamEffect::Opaque;    return true;
        case 'R': out = ParamEffect::ReadsOnly; return true;
        case 'F': out = ParamEffect::Frees;     return true;
        case 'S': out = ParamEffect::Stores;    return true;
    }
    return false;
}

} // anonymous namespace

void SummaryRegistry::harvestGlobal() {
    for (const auto& [func, summary] : summaries_) {
        if (!func->isExternallyVisible()) continue;
        auto [it, inserted] = globalStore_.emplace(globalKey(func), summary);
        if (!inserted) mergeConservative(it->second, summary);
    }
}

const SummaryRegistry::FunctionSummary*
SummaryRegistry::lookupGlobal(const clang::FunctionDecl* func) const {
    if (!func || globalStore_.empty()) return nullptr;
    if (!func->isExternallyVisible()) return nullptr;
    auto it = globalStore_.find(globalKey(func));
    if (it == globalStore_.end()) return nullptr;
    return &it->second;
}

void SummaryRegistry::clearGlobal() { globalStore_.clear(); }

bool SummaryRegistry::saveGlobal(const std::string& path) const {
    std::ofstream out(path);
    if (!out.is_open()) return false;
    out << kSummaryFileHeader << "\n";
    // std::map sirali gezinir — cikti deterministik (diff'lenebilir;
    // "ozet degisti mi" sorusu dosya karsilastirmasiyla cevaplanir)
    for (const auto& [key, summary] : globalStore_) {
        out << key << '\t' << rnToChar(summary.returnNullness) << '\t';
        if (summary.params.empty()) {
            out << '-';
        } else {
            for (ParamEffect effect : summary.params)
                out << peToChar(effect);
        }
        out << '\n';
    }
    return out.good();
}

bool SummaryRegistry::loadGlobal(const std::string& path) {
    std::ifstream in(path);
    if (!in.is_open()) return false;

    std::string line;
    if (!std::getline(in, line) || line != kSummaryFileHeader)
        return false;

    // Once tumuyle ayristir, sonra depoya kat: bozuk dosya kismi durum
    // birakmadan reddedilir
    std::map<std::string, FunctionSummary> parsed;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        const auto tab1 = line.find('\t');
        const auto tab2 =
            tab1 == std::string::npos ? tab1 : line.find('\t', tab1 + 1);
        if (tab2 == std::string::npos) return false;

        std::string key = line.substr(0, tab1);
        const std::string rn = line.substr(tab1 + 1, tab2 - tab1 - 1);
        const std::string pe = line.substr(tab2 + 1);
        if (key.empty() || rn.size() != 1 || pe.empty()) return false;

        FunctionSummary summary;
        if (!rnFromChar(rn[0], summary.returnNullness)) return false;
        if (pe != "-") {
            summary.params.reserve(pe.size());
            for (char c : pe) {
                ParamEffect effect;
                if (!peFromChar(c, effect)) return false;
                summary.params.push_back(effect);
            }
        }
        auto [it, inserted] = parsed.emplace(std::move(key), summary);
        if (!inserted) mergeConservative(it->second, summary);
    }

    for (const auto& [key, summary] : parsed) {
        auto [it, inserted] = globalStore_.emplace(key, summary);
        if (!inserted) mergeConservative(it->second, summary);
    }
    return true;
}

} // namespace zerodefect
