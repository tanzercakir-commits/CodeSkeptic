#include "rules/NullDerefRule.h"

#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/CoverageReport.h"
#include "engine/DataflowEngine.h"
#include "engine/FunctionSummary.h"
#include "engine/IntervalEval.h"
#include "engine/CallRefArgs.h"
#include "engine/ConditionWalk.h"
#include "engine/GuardedDisjuncts.h"
#include "engine/AllocFunctions.h"
#include "contracts/ContractInfo.h"
#include "contracts/GuardContracts.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/AST/Expr.h>
#include <clang/AST/ExprCXX.h>
#include <clang/AST/Stmt.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>
#include <clang/ASTMatchers/ASTMatchers.h>

#include <algorithm>
#include <iostream>
#include <map>
#include <optional>
#include <set>
#include <vector>

using namespace clang;
using namespace clang::ast_matchers;

namespace {

// --- NullState lattice ---
//
// Unknown : no information (parameter, opaque function return)
// Null    : definitely null on all paths
// NonNull : definitely not null on all paths
// MaybeNull: null on at least one path (reportable signal)

enum class NullState { Unknown, Null, NonNull, MaybeNull };

// The C heap allocators that return NULL on failure. A result
// dereferenced without a null check is the single most common
// first-draft / AI-generated defect (CWE-690/476); the thesis corpus
// (12 blind AI programs) put ~15 of its 23 real bugs in this class,
// all silent because an opaque call return is Unknown. Treating a
// KNOWN allocator's return as MaybeNull (not Unknown) hands the
// existing guard/refinement machinery its signal: an unguarded deref
// warns, `if (p)` / `if (!p) return` / `assert(p)` refines to NonNull
// and stays clean. Deliberately the KNOWN allocators only (plus the
// --alloc-functions wrappers) — never arbitrary opaque returns, which
// is the FP flood the NullDeref rule was built to avoid.
bool isKnownAllocatorCall(const CallExpr* call) {
    if (!call) return false;
    const FunctionDecl* callee = call->getDirectCallee();
    if (!callee) return false;
    const IdentifierInfo* id = callee->getIdentifier();
    if (!id) return false;
    const llvm::StringRef name = id->getName();
    // Standard C allocators that can return NULL. `new`/`new[]` are
    // NOT here: throwing new never returns null (handled as NonNull
    // above); the nothrow form is rarer and left to v-next.
    if (name == "malloc" || name == "calloc" || name == "realloc" ||
        name == "strdup" || name == "strndup" || name == "aligned_alloc" ||
        name == "reallocarray")
        return true;
    return codeskeptic::allocFunctionNames().count(name.str()) != 0;
}

// Intrinsic NULL-returning library calls that are not allocators. Same
// #92 discipline (key on an intrinsic property of the CALLEE, never on
// caller data), extended to the lookup functions an AI reaches for on a
// first draft: getenv returns NULL when the variable is unset, the
// fopen family returns NULL on failure. The result flows into a
// dereference (`strchr(getenv(x), ':')`, `fread(buf, 1, n, fopen(...))`)
// with no NULL check — the thesis-v3 p07 shape. A downstream `if (p)`
// refines to NonNull exactly as for malloc, so a validated result stays
// silent; only the unchecked use warns.
bool isIntrinsicNullSource(const CallExpr* call) {
    if (isKnownAllocatorCall(call)) return true;
    if (!call) return false;
    const FunctionDecl* callee = call->getDirectCallee();
    if (!callee) return false;
    const IdentifierInfo* id = callee->getIdentifier();
    if (!id) return false;
    const llvm::StringRef name = id->getName();
    return name == "getenv" || name == "fopen" || name == "freopen" ||
           name == "fdopen" || name == "tmpfile";
}

NullState mergeNullStates(NullState a, NullState b) {
    if (a == b) return a;
    // Null knowledge on any path is preserved; only NonNull + Unknown
    // decays to no knowledge (same shape as the DivByZero merge)
    bool anyNullInfo = a == NullState::Null || a == NullState::MaybeNull ||
                       b == NullState::Null || b == NullState::MaybeNull;
    return anyNullInfo ? NullState::MaybeNull : NullState::Unknown;
}

// Per-variable value with an optional GUARD IMPLICATION (#70): on
// paths where `fact` holds with value `factVal`, this pointer is
// NonNull. Implications are mined the moment widening collapses the
// disjunct set — they are what survives the collapse when more
// independent guards exist than kMaxDisjuncts can hold as explicit
// path splits (stb_image TGA: `tga_palette` is guarded by
// `tga_indexed`, but the loop's RLE/read-next noise conditions
// cross-multiply the disjuncts and the collapse used to erase the
// correlation). Linear by construction: four guarded pointers are
// four implications inside ONE disjunct, never 2^4 disjuncts.
//
// Lifecycle: CREATED only by the widening miner (or kept by the merge
// meet below); CONSUMED on assume-edges — a disjunct that records the
// matching fact sharpens st to NonNull; DROPPED by any direct set
// (assignment, out-param, refinement — the implicit NullState
// constructor makes a fresh unannotated value, which is exactly the
// sound default) and when the guard variable itself is reassigned.
struct NullVal {
    NullState st = NullState::Unknown;
    std::optional<codeskeptic::FactKey> fact;
    bool factVal = true;
    // The state this pointer holds ON PATHS WHERE fact=factVal — the
    // implication's payload (2026-07-22 generalization; was implicitly
    // NonNull). Unknown is a legitimate payload: an out-param factory
    // (`getaddrinfo(&res)` under `if (c.has_x)`) leaves the pointer
    // Unknown-not-proven-NonNull on the guarded path, and the
    // cap-collapse used to decay it to an unrecoverable MaybeNull the
    // second `if (c.has_x)` could not repair — the surviving
    // rtp2httpd msrc_res/fcc_res family. Activation restores condSt.
    NullState condSt = NullState::NonNull;

    NullVal() = default;
    /*implicit*/ NullVal(NullState s) : st(s) {}

    bool operator==(const NullVal& o) const {
        if (st != o.st || fact.has_value() != o.fact.has_value())
            return false;
        return !fact || (*fact == *o.fact && factVal == o.factVal &&
                         condSt == o.condSt);
    }
    bool operator!=(const NullVal& o) const { return !(*this == o); }
    bool operator<(const NullVal& o) const {
        if (st != o.st) return st < o.st;
        if (fact.has_value() != o.fact.has_value())
            return !fact.has_value();
        if (!fact) return false;
        if (!(*fact == *o.fact)) return *fact < *o.fact;
        if (factVal != o.factVal) return factVal < o.factVal;
        return condSt < o.condSt;
    }
};

// No null-knowledge: the states an implication may promise (payload)
// and that a plain side may hold without breaking one.
bool hasNoNullInfo(NullState s) {
    return s == NullState::NonNull || s == NullState::Unknown;
}

NullVal mergeNullVals(const NullVal& a, const NullVal& b) {
    NullVal out(mergeNullStates(a.st, b.st));
    // Implication meet: (F=v ⟹ condSt) survives the join when the
    // other side either carries the SAME implication (payloads merge)
    // or holds a no-null-info state outright — such a side cannot put
    // null on any F=v path, it merely weakens the payload (NonNull
    // side keeps it as-is, an Unknown side degrades a NonNull promise
    // to Unknown; both remain silent at a dereference).
    const NullVal* impl = a.fact ? &a : (b.fact ? &b : nullptr);
    if (impl) {
        const NullVal& other = (impl == &a) ? b : a;
        if (other.fact && *other.fact == *impl->fact &&
            other.factVal == impl->factVal) {
            out.fact = impl->fact;
            out.factVal = impl->factVal;
            out.condSt = mergeNullStates(impl->condSt, other.condSt);
        } else if (hasNoNullInfo(other.st)) {
            out.fact = impl->fact;
            out.factVal = impl->factVal;
            out.condSt = mergeNullStates(impl->condSt, other.st);
        }
        if (out.fact && !hasNoNullInfo(out.condSt)) out.fact.reset();
    }
    return out;
}

// Same-facts meet (#70): when two disjuncts with an IDENTICAL fact
// map merge, an implication additionally survives if the shared facts
// CONTRADICT its condition — no path either side represents can have
// F = v, so "F=v ⟹ NonNull" holds vacuously. This is the poison
// antidote: `{indexed==0, MaybeNull+impl}` meeting
// `{indexed==0, Null}` used to drop the implication (the Null side
// cannot prove it value-only), and that one drop re-merged into every
// later join until no implication survived anywhere (measured: 13
// such drops seeded ~1300 downstream ones on stb_image's tga loader).
NullVal meetNullVals(const std::map<codeskeptic::FactKey, bool>& facts,
                     const NullVal& a, const NullVal& b) {
    NullVal out = mergeNullVals(a, b);
    if (out.fact) return out;
    const NullVal* impl = a.fact ? &a : (b.fact ? &b : nullptr);
    if (impl &&
        codeskeptic::factsContradict(facts, *impl->fact, impl->factVal)) {
        out.fact = impl->fact;
        out.factVal = impl->factVal;
        out.condSt = impl->condSt;  // vacuous survival keeps the payload
    }
    return out;
}

// --- Expression null-ness evaluation ---

const VarDecl* asVar(const Expr* expr) {
    if (!expr) return nullptr;
    expr = expr->IgnoreParenImpCasts();
    if (const auto* ref = dyn_cast<DeclRefExpr>(expr))
        return dyn_cast<VarDecl>(ref->getDecl());
    return nullptr;
}

// #69b: the sole-definition interval map of the function being
// analyzed (set for the duration of each per-function run; the
// analyzer is single-threaded). evaluateNullness sits several free
// functions below the analysis object — a scoped pointer keeps the
// plumbing flat, matching the process-global registry discipline used
// elsewhere (FunctionFilter, AllocFunctions).
const codeskeptic::IntervalMap* g_soleDefIntervals = nullptr;
const clang::ASTContext* g_soleDefContext = nullptr;

struct SoleDefScope {
    SoleDefScope(const codeskeptic::IntervalMap* map,
                 const clang::ASTContext* ctx) {
        g_soleDefIntervals = map;
        g_soleDefContext = ctx;
    }
    ~SoleDefScope() {
        g_soleDefIntervals = nullptr;
        g_soleDefContext = nullptr;
    }
};

NullState evaluateNullness(const Expr* expr) {
    if (!expr) return NullState::Unknown;
    // Strip explicit casts too: (int*)0, (Node*)nullptr
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

    // Interprocedural: the null-ness of a call's return comes from the
    // function summary. A "may return null" summary produces MaybeNull —
    // an unguarded dereference becomes a warning; guarded use stays
    // clean via the assume-edge.
    if (const auto* call = dyn_cast<CallExpr>(expr)) {
        using RN = codeskeptic::SummaryRegistry::ReturnNullness;
        const auto* summary =
            codeskeptic::SummaryRegistry::instance().lookup(
                call->getDirectCallee());
        if (summary) {
            if (summary->returnNullness == RN::NeverNull)
                return NullState::NonNull;
            if (summary->returnNullness == RN::MaybeNull) {
                // #69b: a value-conditioned summary ("null only if
                // param #i outside R") is refuted at THIS call site
                // when the argument's interval provably lies inside R.
                // Stateless evaluation (every variable = top) is
                // enough for the masked-index idiom: `(x>>3)&2` is
                // [0,2] whatever x is (the picojpeg getHuffVal FP).
                if (summary->hasNullCondition() &&
                    static_cast<unsigned>(summary->nullCondParam) <
                        call->getNumArgs()) {
                    static const codeskeptic::IntervalMap kEmpty;
                    const codeskeptic::IntervalMap& defs =
                        g_soleDefIntervals ? *g_soleDefIntervals : kEmpty;
                    codeskeptic::Interval arg = codeskeptic::evalInterval(
                        call->getArg(summary->nullCondParam), defs,
                        g_soleDefContext);
                    const codeskeptic::Interval& safe =
                        summary->nullCondRange;
                    const bool loOk =
                        safe.loIsInf() ||
                        (!arg.loIsInf() && arg.lo() >= safe.lo());
                    const bool hiOk =
                        safe.hiIsInf() ||
                        (!arg.hiIsInf() && arg.hi() <= safe.hi());
                    if (!arg.isEmpty() && loOk && hiOk)
                        return NullState::NonNull;
                }
                return NullState::MaybeNull;
            }
        }
        // No summary (opaque call). A KNOWN intrinsic null source
        // (allocator, getenv, fopen family) can return NULL: MaybeNull so
        // an unguarded deref is caught; everything else stays Unknown
        // (silent) — the anti-FP-flood default.
        if (isIntrinsicNullSource(call)) return NullState::MaybeNull;
        return NullState::Unknown;
    }

    return NullState::Unknown;
}

// --- Statement classification ---

enum class EffectKind { None, Assign, AssignUnknown, Deref };

struct Effect {
    const VarDecl* var = nullptr;
    EffectKind kind = EffectKind::None;
    NullState value = NullState::Unknown;  // only for Assign
};

Effect classifyStmt(const Stmt* stmt) {
    if (const auto* declStmt = dyn_cast<DeclStmt>(stmt)) {
        // In a multi-declaration the first pointer init is taken; the
        // rest start Unknown (conservative). Rare case, noted in the todo.
        for (const auto* decl : declStmt->decls()) {
            if (const auto* vd = dyn_cast<VarDecl>(decl)) {
                if (vd->getType()->isPointerType() && vd->hasInit()) {
                    // A STATIC local's initializer runs once per
                    // program, not once per call — on every later
                    // call the variable holds whatever earlier calls
                    // left in it. Modeling the init as a per-call
                    // assignment invented a fresh NULL on each entry
                    // and flooded Godot's GDCLASS double-checked
                    // lazy-init (`static T *inst = nullptr; ...
                    // if (initialized) return *inst;`) with
                    // "definitely null" errors. Unknown is the honest
                    // per-call state (#86).
                    if (vd->isStaticLocal())
                        return {vd, EffectKind::AssignUnknown};
                    return {vd, EffectKind::Assign,
                            evaluateNullness(vd->getInit())};
                }
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
        // If &p goes to a function, p may have been assigned a value
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

// libc functions that UNCONDITIONALLY dereference a pointer argument — a
// NULL there is definite UB, with NO length parameter that could be 0 to
// excuse it. Passing a Null/MaybeNull pointer to one of these is a
// dereference BY PROXY: `strchr(getenv(x), ':')` (thesis-v3 p07) and the
// everyday `strcpy(buf, getenv(x))`. The curated whitelist keeps this as
// precise as a direct deref — only callees whose contract makes the
// access certain are listed (the n-bounded mem*/strn* forms are omitted:
// a 0 length dereferences nothing, so they are not unconditional). This
// is the intrinsic-signal discipline pointed at the callee's contract,
// the same as isIntrinsicNullSource. Appends the tracked pointer vars at
// the dereferenced positions to `out`.
void collectLibcDerefArgs(const CallExpr* call,
                          std::vector<const VarDecl*>& out) {
    const FunctionDecl* fd = call->getDirectCallee();
    if (!fd) return;
    const IdentifierInfo* id = fd->getIdentifier();
    if (!id) return;
    const llvm::StringRef n = id->getName();

    unsigned mask = 0;  // bit i set => argument i is dereferenced
    if (n == "strlen" || n == "strchr" || n == "strrchr" || n == "strdup" ||
        n == "atoi" || n == "atol" || n == "atoll" || n == "atof" ||
        n == "strtol" || n == "strtoul" || n == "strtoll" ||
        n == "strtoull" || n == "puts")
        mask = 0b01;  // the single string argument (endptr etc. is nullable)
    else if (n == "strcpy" || n == "strcat" || n == "stpcpy" ||
             n == "strcmp" || n == "strcasecmp" || n == "strstr" ||
             n == "strcasestr" || n == "strpbrk" || n == "strspn" ||
             n == "strcspn")
        mask = 0b11;  // both pointer operands are read/written
    else
        return;

    const unsigned nargs = call->getNumArgs();
    for (unsigned i = 0; i < nargs && i < 2; ++i)
        if (mask & (1u << i))
            if (const VarDecl* v = asVar(call->getArg(i)))
                out.push_back(v);
}

// --- Branch condition refinement (assume edges) ---

using NullVarState = std::map<const VarDecl*, NullVal>;

void setIfTracked(NullVarState& state, const VarDecl* var, NullState value) {
    if (!var) return;
    auto it = state.find(var);
    if (it != state.end()) it->second = value;  // fresh NullVal: any
}                                               // implication drops

// The correlation miner (#70), run by widenGuarded/normalizeGuarded at
// the moment the disjunct set is about to collapse. For each pointer
// whose collapsed state decays to MaybeNull, look for a fact F and a
// value v such that EVERY pre-collapse disjunct compatible with F=v
// knows the pointer NonNull — directly, or via the same implication it
// already carries (repeated widenings re-offer their own product).
// A disjunct that never recorded F is compatible with BOTH values of F
// (its paths may carry either), so it must pass the check on both
// sides it joins. Soundness: facts recorded in a disjunct are true on
// every path it represents, and stale facts are erased on assignment
// (applyStmtFacts) — so "all F=v-compatible disjuncts are NonNull"
// really does mean "every path reaching this point with F=v has the
// pointer NonNull".
void mineGuardImplications(
    const codeskeptic::GuardedState<NullVarState>& pre,
    codeskeptic::Guarded<NullVarState>& widened) {
    std::set<codeskeptic::FactKey> candidates;
    for (const auto& d : pre)
        for (const auto& [key, value] : d.facts) candidates.insert(key);
    if (candidates.empty()) return;

    for (auto& [var, val] : widened.vars) {
        if (val.st != NullState::MaybeNull || val.fact) continue;
        for (const auto& key : candidates) {
            for (bool wanted : {true, false}) {
                // The witness keeps the implication non-vacuous (#84):
                // either a disjunct that RECORDED key=wanted, or one
                // that already CARRIES this implication — proof a real
                // partition mined it upstream. The second clause is
                // load-bearing at collapses where every key=wanted-
                // recording disjunct has already been folded into
                // implication-carrying form (the mid-loop joins of
                // stbi__tga_load: only explicit `indexed == 0`
                // recordings remained, the indexed-side lived on
                // solely inside implications). Demanding a fresh
                // explicit recording there silently discarded a
                // still-valid implication at every such collapse —
                // the exact last link of the #70 residual FP.
                bool sawWitness = false;
                bool allNoNullInfo = true;
                NullState payload = NullState::NonNull;
                for (const auto& d : pre) {
                    // Entailment-aware compatibility and witness (the
                    // libgit2 hashmap __resize family, 2026-07-22).
                    // Exact-key tests were blind to STAMPED equalities
                    // on other literals: with D1{(j EQ 0)=true, Null}
                    // and D2{(j EQ 1)=true, NonNull}, the consumable
                    // candidate ((j EQ 0), false) failed both ways —
                    // D1 never recorded that exact key (so it wrongly
                    // stayed "compatible" for the (j EQ 1) candidate),
                    // and D2's stamp, which ENTAILS (j EQ 0)=false,
                    // did not count as a witness. factsContradict
                    // already decides every EQ/LT/LE key from an
                    // EQ=true stamp — use it for both directions:
                    // a disjunct contradicting key=wanted has no path
                    // with F=v (excluded, vacuous truth), one
                    // contradicting key=!wanted entails F=v (witness;
                    // covers the old exact-recording case too).
                    const bool compatible =
                        !codeskeptic::factsContradict(d.facts, key, wanted);
                    if (codeskeptic::factsContradict(d.facts, key, !wanted))
                        sawWitness = true;
                    if (!compatible) continue;
                    auto it = d.vars.find(var);
                    const bool viaImpl =
                        it != d.vars.end() && it->second.fact &&
                        *it->second.fact == key &&
                        it->second.factVal == wanted;
                    if (viaImpl) sawWitness = true;
                    // The mined payload is the merge over compatible
                    // disjuncts of what F=v promises there: the plain
                    // state, or a same-key implication's own payload.
                    // ANY null-info kills the candidate — the point of
                    // the implication is that F=v paths carry none.
                    // Unknown is a legitimate payload (out-param
                    // factories — the msrc_res family): activation
                    // restores Unknown, which a dereference reporter
                    // treats as silence, instead of the collapsed
                    // MaybeNull it would otherwise inherit.
                    NullState contrib;
                    if (viaImpl) {
                        contrib = it->second.condSt;
                    } else if (it != d.vars.end() &&
                               hasNoNullInfo(it->second.st)) {
                        contrib = it->second.st;
                    } else {
                        allNoNullInfo = false;
                        break;
                    }
                    payload = mergeNullStates(payload, contrib);
                    if (!hasNoNullInfo(payload)) {
                        allNoNullInfo = false;
                        break;
                    }
                }
                if (sawWitness && allNoNullInfo) {
                    val.fact = key;
                    val.factVal = wanted;
                    val.condSt = payload;
                    break;
                }
            }
            if (val.fact) break;
        }
    }
}

// Via the shared walk skeleton (engine/ConditionWalk.h): `if (p)`,
// `!p`, `p ==/!= nullptr/NULL/0`, && / || short-circuiting.
void applyCondition(const Expr* cond, bool isTrue, NullVarState& state) {
    codeskeptic::walkNullCondition(
        cond, isTrue, [&](const VarDecl* var, bool isNull) {
            setIfTracked(state, var,
                         isNull ? NullState::Null : NullState::NonNull);
        });
}

// --- Collect tracked pointer variables ---

std::vector<const VarDecl*> collectTrackedVars(const FunctionDecl* funcDecl,
                                                ASTContext& ctx) {
    std::set<const VarDecl*> vars;

    // All pointer local variables and parameters appearing in the
    // function. Parameters start Unknown — no assumption is made about
    // the caller.
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

// Whether any call in the body targets a callee with an enforced
// non-null requires clause (CONTRACTS.md Round C). A function with no
// pointer variables of its own still needs the dataflow pass then —
// `g() { f(NULL); }` is exactly the call-site violation the contract
// exists to catch.
bool hasNonNullContractCalls(const FunctionDecl* funcDecl, ASTContext& ctx) {
    auto callMatcher = callExpr().bind("call");
    for (const auto& result :
         match(findAll(callMatcher), *funcDecl->getBody(), ctx)) {
        const auto* call = result.getNodeAs<CallExpr>("call");
        if (!call) continue;
        const FunctionDecl* callee = call->getDirectCallee();
        if (!callee) continue;
        auto parsed = codeskeptic::allContractClausesForDecl(callee, ctx);
        if (parsed.clauses.empty()) {
            // Guard-as-contract (#89): a body-visible callee whose own
            // entry guard implies a precondition also wakes the pass —
            // `g() { f(nullptr); }` with f's guard is exactly the
            // caller-side violation the lift exists to catch.
            if (callee->hasBody() &&
                !codeskeptic::inferGuardRequires(callee, ctx).empty())
                return true;
            continue;
        }
        auto req = codeskeptic::analyzeRequires(parsed, callee);
        for (const auto& info : req.enforced)
            if (info.kind != codeskeptic::RequiresInfo::Kind::NonZeroParam)
                return true;
    }
    return false;
}

// --- Analysis struct for DataflowEngine ---

class NullDerefAnalysis {
public:
    // Guarded disjuncts (targeted path sensitivity): the Juliet
    // int_07/08/09 pattern — `if(staticTrue) data = alloc; ...
    // if(staticTrue) *data;` — produced a false "may be null" under
    // correlation-free analysis. The shared machinery is in
    // engine/GuardedDisjuncts.h; the pointer nullness refinement
    // (applyCondition) is additionally applied per disjunct.
    using State = codeskeptic::GuardedState<NullVarState>;

    NullDerefAnalysis(const std::vector<const VarDecl*>& trackedVars,
                      std::set<const ValueDecl*> unkeyableDecls,
                      std::set<const ValueDecl*> stampableDecls,
                      std::set<const ValueDecl*> ptrFactDecls,
                      std::string funcName,
                      codeskeptic::DiagnosticList& results)
        : mutated_(std::move(unkeyableDecls)),
          stampable_(std::move(stampableDecls)),
          ptrFacts_(std::move(ptrFactDecls)),
          funcName_(std::move(funcName)), results_(results) {
        codeskeptic::Guarded<NullVarState> init;
        for (const auto* var : trackedVars)
            init.vars[var] = NullState::Unknown;
        initState_.push_back(std::move(init));
    }

    State initialState() const { return initState_; }

    // Callee-side contract seeding (CONTRACTS.md Round C): a declared
    // `requires p != null` carries the proof burden — p starts NonNull
    // inside the body (callers are checked at every visible call
    // site). The relational form seeds a SPLIT initial state: the
    // escape-condition disjunct leaves p unconstrained, the other
    // pins it NonNull.
    void seedRequires(const FunctionDecl* func,
                      const std::vector<codeskeptic::RequiresInfo>& infos) {
        for (const auto& info : infos) {
            if (info.paramIndex >= func->getNumParams()) continue;
            const ParmVarDecl* p = func->getParamDecl(info.paramIndex);
            if (info.kind == codeskeptic::RequiresInfo::Kind::NonNullParam) {
                for (auto& d : initState_) setIfTracked(d.vars, p,
                                                        NullState::NonNull);
            } else if (info.kind ==
                       codeskeptic::RequiresInfo::Kind::NonNullUnlessCond) {
                if (info.condParamIndex >= func->getNumParams()) continue;
                const ParmVarDecl* c =
                    func->getParamDecl(info.condParamIndex);
                if (mutated_.count(c)) continue;  // unkeyable: no seed
                auto fact = codeskeptic::compareFact(
                    c, codeskeptic::toBinaryOp(info.condOp),
                    info.condLiteral);
                if (!fact) continue;
                State next;
                for (auto& d : initState_) {
                    auto escape = d;             // cond TRUE: p free
                    escape.facts[fact->first] = fact->second;
                    auto pinned = d;             // cond FALSE: p NonNull
                    pinned.facts[fact->first] = !fact->second;
                    setIfTracked(pinned.vars, p, NullState::NonNull);
                    next.push_back(std::move(escape));
                    next.push_back(std::move(pinned));
                }
                initState_ = std::move(next);
                codeskeptic::normalizeGuarded(initState_, mergeNullVals);
            }
        }
    }

    // Guarded postconditions of THIS function (CONTRACTS.md Round D):
    // `ensures return != null if <g>` — checked per disjunct at every
    // return statement (checkGuardedEnsures).
    void setGuardedEnsures(std::vector<codeskeptic::GuardedEnsuresInfo> v) {
        guardedEnsures_ = std::move(v);
    }

    // The per-variable NullState chain makes at most 3 transitions;
    // the number of disjuncts multiplies the height
    unsigned latticeHeight() const {
        return (static_cast<unsigned>(initState_.front().vars.size()) * 3 +
                1) * static_cast<unsigned>(codeskeptic::kMaxDisjuncts) + 4 + factBudget();
    }

    // Fact records add lattice climbs the var-state formula above
    // never counted (v2b); bounded so pathological functions do not
    // explode the iteration cap.
    unsigned factBudget() const {
        auto n = static_cast<unsigned>(stampable_.size());
        return (n > 16 ? 16u : n) * 2 *
               static_cast<unsigned>(codeskeptic::kMaxDisjuncts);
    }

    // Engine convergence hook: collapse the disjuncts when a block is
    // revisited beyond any monotone explanation (see DataflowEngine).
    // Both collapse points run the #70 correlation miner, so a guard
    // implication survives where the explicit path split cannot; the
    // fact-aware meet keeps vacuous implications alive across
    // same-facts merges (see meetNullVals).
    static auto ops() {
        return codeskeptic::makeGuardedOps(mergeNullVals, meetNullVals,
                                          mineGuardImplications);
    }

    void widen(State& s) const { codeskeptic::widenGuardedOps(s, ops()); }

    State merge(const State& a, const State& b) const {
        return codeskeptic::mergeGuardedOps(a, b, ops());
    }

    State transfer(const Stmt* stmt, const State& inRaw,
                   ASTContext& /*ctx*/) const {
        // Fact lifecycle first (v2b): assignments to locals erase the
        // facts keyed on them; integer-constant stores stamp the new
        // truth. Domain logic below then reads the fact-current state.
        State in = inRaw;
        codeskeptic::applyStmtFactsOps(in, stmt, stampable_, ptrFacts_,
                                      ops());
        // #70: an assignment to a guard variable stales every
        // implication keyed on it — the exact mirror of the fact
        // erasure applyStmtFacts just performed.
        if (const clang::ValueDecl* target = codeskeptic::assignedDecl(stmt)) {
            for (auto& d : in)
                for (auto& [var, val] : d.vars)
                    if (val.fact && val.fact->var == target)
                        val.fact.reset();
        }
        // Member-keyed implications mirror the member fact lifecycle
        // (2026-07-22): a store to c.f stales implications keyed on
        // exactly (c, f); a call receiving &c stales every (c, *) one.
        if (auto ma = codeskeptic::assignedMemberFact(stmt)) {
            for (auto& d : in)
                for (auto& [var, val] : d.vars)
                    if (val.fact && val.fact->var == ma->base &&
                        val.fact->field == ma->field)
                        val.fact.reset();
        }
        if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            if (const auto* bases = codeskeptic::activeMemberFactBases()) {
                for (const Expr* arg : call->arguments()) {
                    const VarDecl* base = codeskeptic::addrOfBaseVar(arg);
                    if (!base || !bases->count(base)) continue;
                    for (auto& d : in)
                        for (auto& [var, val] : d.vars)
                            if (val.fact && val.fact->var == base &&
                                val.fact->field)
                                val.fact.reset();
                }
            }
        }

        // A tracked pointer passed by non-const reference is an
        // out-param: the callee may rebind it, so its fact drops to
        // Unknown. There is no AddrOf node to see — only the parameter
        // type reveals it (the shadPS4 ResolveEpollBinding FP family:
        // `int* p = nullptr; f(id, p); *p` is NOT a definite null
        // deref when f takes `int*&`).
        if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            State out = in;
            bool changed = false;
            codeskeptic::forEachNonConstRefArg(call, [&](const Expr* arg) {
                const VarDecl* var = asVar(arg);
                if (!var) return;
                for (auto& d : out) {
                    auto it = d.vars.find(var);
                    if (it == d.vars.end()) continue;
                    it->second = NullState::Unknown;
                    changed = true;
                }
            });
            return changed ? out : in;
        }

        Effect effect = classifyStmt(stmt);
        if (effect.kind != EffectKind::Assign &&
            effect.kind != EffectKind::AssignUnknown)
            return in;

        State out = in;
        for (auto& d : out) {
            auto it = d.vars.find(effect.var);
            if (it == d.vars.end()) continue;  // not tracked
            it->second = (effect.kind == EffectKind::Assign)
                             ? effect.value
                             : NullState::Unknown;
        }
        return out;
    }

    void refineOnEdge(const Stmt* cond, bool isTrueBranch, State& state,
                      ASTContext& /*ctx*/) const {
        const auto* condExpr = dyn_cast<Expr>(cond);
        codeskeptic::refineGuardedFactsOps(
            state, condExpr, isTrueBranch, mutated_, ptrFacts_,
            ops(),
            // Domain refuter for disjunction elimination: an operand
            // whose REQUIRED nullness contradicts this disjunct's var
            // state cannot have held here (walkNullCondition yields
            // the operand's necessary conditions).
            [](const codeskeptic::Guarded<NullVarState>& d, const Expr* e,
               bool wanted) {
                bool refuted = false;
                codeskeptic::walkNullCondition(
                    e, wanted, [&](const VarDecl* var, bool isNull) {
                        auto it = d.vars.find(var);
                        if (it == d.vars.end()) return;
                        if (isNull && it->second.st == NullState::NonNull)
                            refuted = true;
                        if (!isNull && it->second.st == NullState::Null)
                            refuted = true;
                    });
                return refuted;
            },
            // Per-disjunct var refinement of every leaf this disjunct
            // is known to satisfy (including survivors of an
            // eliminated disjunction — whole-state applyCondition
            // never sees those).
            [](codeskeptic::Guarded<NullVarState>& d, const Expr* leaf,
               bool leafTrue) {
                applyCondition(leaf, leafTrue, d.vars);
                // #70: the leaf's fact was just recorded into d.facts
                // (applyFactLeaf runs before this hook) — a recorded
                // fact ACTIVATES every matching guard implication.
                // Null stays Null: sharpening a definitely-null
                // disjunct would hide its report, and if the
                // implication proves that path infeasible, dropping
                // the warning is the engine's call, not this hook's.
                for (auto& [var, val] : d.vars) {
                    if (!val.fact || val.st == NullState::NonNull ||
                        val.st == NullState::Null)
                        continue;
                    // Entailment-aware activation (same principle as
                    // the miner, 2026-07-22): the disjunct's facts
                    // ENTAIL key=factVal when they contradict its
                    // negation — covers both the exact recording the
                    // old find() saw and a stamped equality on the
                    // guard ((j EQ 1)=true activating the mined
                    // (j EQ 0)=false implication). The restored state
                    // is the implication's PAYLOAD — NonNull for the
                    // classic mined guard, Unknown for the out-param-
                    // factory shape (silent at a dereference either
                    // way).
                    if (codeskeptic::factsContradict(d.facts, *val.fact,
                                                     !val.factVal))
                        val.st = val.condSt;
                }
            });
    }

    // Caller-side contract check (CONTRACTS.md Round C): every
    // visible call into a function with a declared `requires` on a
    // pointer parameter is checked against the caller's own nullness
    // state. Null literal / definitely-null argument -> error
    // (warning for cs:ai); possibly-null -> warning. The relational
    // escape is honored when the condition argument is an integer
    // literal; a non-literal escape stays conservative (silent).
    // Guard-as-contract (#89, §4.A v1): the callee's OWN entry guard
    // (`assert(p)` / `if (!p) return X;`) is a precondition the code
    // already enforces — lifted here into a caller-side check no
    // compiler performs. v1 reports DEFINITE violations only (null
    // literal / definitely-null variable): zero noise by design. The
    // guard's kind decides the severity (user decision, 2026-07-17):
    // an assert vanishes in release builds, so a violating call
    // CRASHES there -> error; an if-return guard always runs, the
    // callee just refuses -> warning ("this call can never do its
    // work" — a logic bug, not a crash). A param with a DECLARED
    // contract is skipped — the author's clause owns that check.
    void checkGuardContracts(const CallExpr* call,
                             const FunctionDecl* callee,
                             const State& before, ASTContext& ctx,
                             const std::set<unsigned>& declaredParams) {
        auto [cacheIt, inserted] = guardCache_.try_emplace(callee);
        if (inserted)
            cacheIt->second = codeskeptic::inferGuardRequires(callee, ctx);
        if (cacheIt->second.empty()) return;

        NullVarState flat;
        bool flatComputed = false;
        for (const auto& g : cacheIt->second) {
            if (declaredParams.count(g.paramIndex)) continue;
            if (g.paramIndex >= call->getNumArgs() ||
                g.paramIndex >= callee->getNumParams())
                continue;
            const Expr* arg = call->getArg(g.paramIndex);

            bool definite = codeskeptic::isNullPointerArg(arg);
            if (!definite) {
                if (const VarDecl* var = asVar(arg)) {
                    if (!flatComputed) {
                        flat = codeskeptic::flattenGuarded(before,
                                                          mergeNullVals);
                        flatComputed = true;
                    }
                    auto f = flat.find(var);
                    definite = f != flat.end() &&
                               f->second.st == NullState::Null;
                }
            }
            if (!definite) continue;  // v1: definite violations only

            const SourceManager& sm = ctx.getSourceManager();
            SourceLocation loc = sm.getExpansionLoc(call->getBeginLoc());
            const unsigned line = sm.getSpellingLineNumber(loc);
            const std::string paramName =
                callee->getParamDecl(g.paramIndex)->getNameAsString();
            const bool crash =
                g.consequence == codeskeptic::GuardConsequence::Crash;
            // Callee name is part of the key: two same-line calls to
            // DIFFERENT guarded callees are two violations, not one.
            const std::string text =
                (crash ? "guard-crash:" : "guard-reject:") +
                callee->getNameAsString() + ":" + paramName;
            if (!reportedContracts_.emplace(line, text).second) continue;

            codeskeptic::Diagnostic diag;
            diag.file = sm.getFilename(loc).str();
            diag.line = line;
            diag.column = sm.getSpellingColumnNumber(loc);
            diag.rule_id = "contract";
            diag.severity = crash ? codeskeptic::Severity::Error
                                  : codeskeptic::Severity::Warning;
            diag.message = codeskeptic::msg(
                crash ? codeskeptic::MsgId::ContractGuardCrash
                      : codeskeptic::MsgId::ContractGuardRejected,
                paramName, callee->getNameAsString(),
                std::to_string(g.guardLine));
            diag.function = funcName_;
            results_.push_back(std::move(diag));
            if (const VarDecl* var = asVar(arg))
                noteTargets_.emplace_back(results_.size() - 1, var);
        }
    }

    void checkCallContracts(const CallExpr* call, const State& before,
                            ASTContext& ctx) {
        const FunctionDecl* callee = call->getDirectCallee();
        if (!callee) return;

        auto parsed = codeskeptic::allContractClausesForDecl(callee, ctx);
        std::vector<codeskeptic::RequiresInfo> enforced;
        std::set<unsigned> declaredParams;
        if (!parsed.clauses.empty()) {
            auto req = codeskeptic::analyzeRequires(parsed, callee);
            enforced = std::move(req.enforced);
            for (const auto& info : enforced)
                declaredParams.insert(info.paramIndex);
        }
        checkGuardContracts(call, callee, before, ctx, declaredParams);
        if (enforced.empty()) return;
        auto req = codeskeptic::RequiresAnalysis{};
        req.enforced = std::move(enforced);

        NullVarState flat =
            codeskeptic::flattenGuarded(before, mergeNullVals);

        for (const auto& info : req.enforced) {
            if (info.kind == codeskeptic::RequiresInfo::Kind::NonZeroParam)
                continue;  // DivByZero owns the zero domain
            if (info.paramIndex >= call->getNumArgs()) continue;
            const Expr* arg = call->getArg(info.paramIndex);

            if (info.kind ==
                codeskeptic::RequiresInfo::Kind::NonNullUnlessCond) {
                if (info.condParamIndex >= call->getNumArgs()) continue;
                auto lit = codeskeptic::intLiteralArg(
                    call->getArg(info.condParamIndex));
                if (!lit) continue;  // non-literal escape: conservative
                if (codeskeptic::evalCmp(*lit, info.condOp,
                                        info.condLiteral))
                    continue;  // escape holds, contract satisfied
            }

            bool definite = false;
            bool maybe = false;
            if (codeskeptic::isNullPointerArg(arg)) {
                definite = true;
            } else if (const VarDecl* var = asVar(arg)) {
                auto it = flat.find(var);
                if (it != flat.end()) {
                    definite = (it->second.st == NullState::Null);
                    maybe = (it->second.st == NullState::MaybeNull);
                }
            }
            if (!definite && !maybe) continue;

            const SourceManager& sm = ctx.getSourceManager();
            SourceLocation loc = sm.getExpansionLoc(call->getBeginLoc());
            const unsigned line = sm.getSpellingLineNumber(loc);
            if (!reportedContracts_.emplace(line, info.text).second)
                continue;

            codeskeptic::Diagnostic diag;
            diag.file = sm.getFilename(loc).str();
            diag.line = line;
            diag.column = sm.getSpellingColumnNumber(loc);
            diag.rule_id = "contract";
            diag.severity = (definite && !info.machineProposed)
                                ? codeskeptic::Severity::Error
                                : codeskeptic::Severity::Warning;
            diag.message = codeskeptic::msg(
                codeskeptic::MsgId::ContractViolated, info.text);
            diag.function = funcName_;
            results_.push_back(std::move(diag));
            // Violation trace (Round D): why is the argument null?
            if (const VarDecl* var = asVar(arg))
                noteTargets_.emplace_back(results_.size() - 1, var);
        }
    }

    // Guarded postcondition check (CONTRACTS.md Round D): at a return
    // statement, every disjunct that does not REFUTE the guard must
    // satisfy the postcondition. A disjunct that PROVES the guard and
    // returns definite null is a violation (error for bare cs:); null
    // under an undecided guard, or possibly-null, is a warning —
    // evidence-per-path, the same ladder as everywhere else.
    void checkGuardedEnsures(const ReturnStmt* ret, const State& before,
                             ASTContext& ctx) {
        if (guardedEnsures_.empty()) return;
        const Expr* val = ret->getRetValue();
        if (!val) return;
        const NullState literal = evaluateNullness(val);
        const VarDecl* var = asVar(val);
        if (literal == NullState::Unknown && !var) return;

        for (const auto& info : guardedEnsures_) {
            bool definite = false;
            bool maybe = false;
            for (const auto& d : before) {
                // Guard provably false on this path: exempt.
                if (codeskeptic::factsContradict(d.facts, info.guardKey,
                                                info.guardWanted))
                    continue;
                bool guardProven = codeskeptic::factsContradict(
                    d.facts, info.guardKey, !info.guardWanted);
                NullState v = literal;
                if (v == NullState::Unknown) {
                    auto it = d.vars.find(var);
                    if (it == d.vars.end()) continue;
                    v = it->second.st;
                }
                if (v == NullState::Null)
                    (guardProven ? definite : maybe) = true;
                else if (v == NullState::MaybeNull)
                    maybe = true;
            }
            if (!definite && !maybe) continue;

            const SourceManager& sm = ctx.getSourceManager();
            SourceLocation loc = sm.getExpansionLoc(ret->getBeginLoc());
            const unsigned line = sm.getSpellingLineNumber(loc);
            if (!reportedContracts_.emplace(line, info.text).second)
                continue;

            codeskeptic::Diagnostic diag;
            diag.file = sm.getFilename(loc).str();
            diag.line = line;
            diag.column = sm.getSpellingColumnNumber(loc);
            diag.rule_id = "contract";
            diag.severity = (definite && !info.machineProposed)
                                ? codeskeptic::Severity::Error
                                : codeskeptic::Severity::Warning;
            diag.message = codeskeptic::msg(
                codeskeptic::MsgId::ContractViolated, info.text);
            diag.function = funcName_;
            results_.push_back(std::move(diag));
            if (var)
                noteTargets_.emplace_back(results_.size() - 1, var);
        }
    }

    // Guard trace (Trace v2): during the reporting pass, if the edge
    // refinement made a variable DEFINITELY null, a trace note is added
    // at the condition point — the "why null" question for the
    // `if (p == 0) { *p }` finding now has an answer (null coming purely
    // from a guard, with no assignment, used to be traceless).
    void onEdgeRefined(const Stmt* cond, bool /*isTrueBranch*/,
                       const State& beforeDisjuncts,
                       const State& afterDisjuncts, ASTContext& ctx) {
        NullVarState before =
            codeskeptic::flattenGuarded(beforeDisjuncts, mergeNullVals);
        NullVarState after =
            codeskeptic::flattenGuarded(afterDisjuncts, mergeNullVals);
        for (const auto& [var, afterState] : after) {
            auto b = before.find(var);
            if (b == before.end() || b->second == afterState) continue;
            if (afterState.st == NullState::Null)
                recordEvent(cond, var, ctx,
                            codeskeptic::MsgId::TraceAssumedNullHere);
        }
    }

    void onStatement(const Stmt* stmt, const State& beforeDisjuncts,
                     const State& afterDisjuncts, ASTContext& ctx) {
        if (const auto* call = dyn_cast<CallExpr>(stmt))
            checkCallContracts(call, beforeDisjuncts, ctx);
        if (const auto* ret = dyn_cast<ReturnStmt>(stmt))
            checkGuardedEnsures(ret, beforeDisjuncts, ctx);

        NullVarState before =
            codeskeptic::flattenGuarded(beforeDisjuncts, mergeNullVals);
        NullVarState after =
            codeskeptic::flattenGuarded(afterDisjuncts, mergeNullVals);
        // Dataflow trace: record transitions to null / possibly-null
        for (const auto& [var, afterState] : after) {
            auto b = before.find(var);
            if (b == before.end() || b->second == afterState) continue;
            if (afterState.st == NullState::Null)
                recordEvent(stmt, var, ctx,
                            codeskeptic::MsgId::TraceAssignedNullHere);
            else if (afterState.st == NullState::MaybeNull)
                recordEvent(stmt, var, ctx,
                            codeskeptic::MsgId::TraceAssignedMaybeNullHere);
        }

        // Direct dereference (`*p`, `p->x`, `p[i]`).
        Effect effect = classifyStmt(stmt);
        if (effect.kind == EffectKind::Deref)
            reportDerefOf(effect.var, stmt, before, ctx);

        // Dereference by proxy: a Null/MaybeNull pointer passed to a libc
        // function that dereferences that argument (#98). Reuses the same
        // report path — dedup, severity, trace notes — as a direct deref.
        if (const auto* call = dyn_cast<CallExpr>(stmt)) {
            std::vector<const VarDecl*> derefArgs;
            collectLibcDerefArgs(call, derefArgs);
            for (const VarDecl* v : derefArgs)
                reportDerefOf(v, stmt, before, ctx);
        }
    }

    // Emit a null-deref finding for `var` dereferenced at `stmt`, if its
    // pre-statement state is Null/MaybeNull. Shared by direct derefs and
    // libc deref-by-proxy; owns the dedup, severity ladder, and the
    // report-flood collapse to "also dereferenced here" trace notes.
    void reportDerefOf(const VarDecl* var, const Stmt* stmt,
                       const NullVarState& before, ASTContext& ctx) {
        auto it = before.find(var);
        if (it == before.end()) return;
        if (it->second.st != NullState::Null &&
            it->second.st != NullState::MaybeNull)
            return;

        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        unsigned line = sm.getSpellingLineNumber(loc);
        if (!reported_.emplace(var, line).second) return;

        const bool definite = (it->second.st == NullState::Null);

        // Report-flood dedup (warnings only): one MaybeNull origin can
        // reach dozens of dereferences (shadPS4 internal__Foprep: a
        // single missing return produced 25 identical warnings). The
        // FIRST dereference carries the report; the rest become "also
        // dereferenced here" trace notes on it. Definite (error)
        // reports keep per-line granularity — they are rare and each
        // site matters.
        if (!definite) {
            auto first = firstWarnIndex_.find(var);
            if (first != firstWarnIndex_.end()) {
                codeskeptic::TraceNote note;
                note.file = sm.getFilename(loc).str();
                note.line = line;
                note.column = sm.getSpellingColumnNumber(loc);
                note.message = codeskeptic::msg(
                    codeskeptic::MsgId::TraceAlsoDerefHere,
                    var->getNameAsString());
                alsoDerefs_[var].push_back(std::move(note));
                return;
            }
        }

        codeskeptic::Diagnostic diag;
        diag.file = sm.getFilename(loc).str();
        diag.line = line;
        diag.column = sm.getSpellingColumnNumber(loc);
        diag.rule_id = "null-deref";
        diag.function = funcName_;
        if (definite) {
            diag.severity = codeskeptic::Severity::Error;
            diag.message = codeskeptic::msg(
                codeskeptic::MsgId::NullDerefDefinite,
                var->getNameAsString());
        } else {
            diag.severity = codeskeptic::Severity::Warning;
            diag.message = codeskeptic::msg(
                codeskeptic::MsgId::NullDerefMaybe,
                var->getNameAsString());
        }
        results_.push_back(diag);
        if (!definite)
            firstWarnIndex_[var] = results_.size() - 1;
        noteTargets_.emplace_back(results_.size() - 1, var);
    }

    // After the run finishes: attach the null-assignment traces to
    // reports, then the deduplicated "also dereferenced here" sites.
    void attachTraces() {
        for (const auto& [index, var] : noteTargets_) {
            std::vector<codeskeptic::TraceNote> notes;
            auto it = events_.find(var);
            if (it != events_.end()) {
                notes = it->second;
                std::sort(notes.begin(), notes.end());
                if (notes.size() > 6) notes.resize(6);
            }
            auto also = alsoDerefs_.find(var);
            if (also != alsoDerefs_.end()) {
                auto extra = also->second;
                std::sort(extra.begin(), extra.end());
                for (auto& n : extra) {
                    if (notes.size() >= 10) break;
                    notes.push_back(std::move(n));
                }
            }
            if (!notes.empty()) results_[index].notes = std::move(notes);
        }
        noteTargets_.clear();
        firstWarnIndex_.clear();
        alsoDerefs_.clear();
    }

private:
    void recordEvent(const Stmt* stmt, const VarDecl* var,
                     ASTContext& ctx, codeskeptic::MsgId msgId) {
        const SourceManager& sm = ctx.getSourceManager();
        SourceLocation loc = sm.getExpansionLoc(stmt->getBeginLoc());
        codeskeptic::TraceNote note;
        note.file = sm.getFilename(loc).str();
        note.line = sm.getSpellingLineNumber(loc);
        note.column = sm.getSpellingColumnNumber(loc);
        note.message = codeskeptic::msg(msgId, var->getNameAsString());

        auto& list = events_[var];
        for (const auto& existing : list)
            if (existing.line == note.line) return;
        list.push_back(std::move(note));
    }

    std::set<const ValueDecl*> mutated_;
    std::set<const ValueDecl*> stampable_;
    std::set<const ValueDecl*> ptrFacts_;
    std::string funcName_;
    codeskeptic::DiagnosticList& results_;
    State initState_;
    std::set<std::pair<const VarDecl*, unsigned>> reported_;
    std::map<const VarDecl*, std::vector<codeskeptic::TraceNote>> events_;
    std::vector<std::pair<size_t, const VarDecl*>> noteTargets_;
    std::map<const VarDecl*, size_t> firstWarnIndex_;
    std::map<const VarDecl*, std::vector<codeskeptic::TraceNote>> alsoDerefs_;
    std::set<std::pair<unsigned, std::string>> reportedContracts_;
    std::map<const clang::FunctionDecl*,
             std::vector<codeskeptic::GuardRequire>> guardCache_;
    std::vector<codeskeptic::GuardedEnsuresInfo> guardedEnsures_;
};

// --- Matcher callback ---

class NullDerefCallback : public MatchFinder::MatchCallback {
public:
    explicit NullDerefCallback(codeskeptic::DiagnosticList& results)
        : results_(results) {}

    void run(const MatchFinder::MatchResult& result) override {
        const auto* func = result.Nodes.getNodeAs<FunctionDecl>("func");
        if (!func || !func->hasBody()) return;

        const SourceManager& sm = *result.SourceManager;
        if (sm.isInSystemHeader(func->getLocation())) return;
        if (!codeskeptic::functionFilterAllows(*func)) return;
        if (!codeskeptic::lineFilterAllows(*func, sm)) return;

        auto parsed = codeskeptic::allContractClausesForDecl(func, *result.Context);
        auto guardedEnsures =
            codeskeptic::analyzeNullEnsuresGuards(parsed, func);

        auto trackedVars = collectTrackedVars(func, *result.Context);
        // A function with no pointer variables still needs the pass
        // when a contract must be checked in it: a call into a
        // contracted callee, or its own guarded postcondition
        // (`return NULL;` needs no variable).
        if (trackedVars.empty() && guardedEnsures.enforced.empty() &&
            !hasNonNullContractCalls(func, *result.Context))
            return;

        // #69b: sole-definition intervals for this function's locals —
        // scoped for the whole run (transfer AND the reporting pass
        // both evaluate call nullness).
        codeskeptic::IntervalMap soleDefs =
            codeskeptic::soleDefIntervals(func, *result.Context);
        SoleDefScope soleDefScope(&soleDefs, result.Context);

        // Member fact keying (2026-07-22): dot-members of admitted
        // local structs join the fact domain for this run — the
        // `if (c.has_x) produce; ... if (c.has_x) consume;` correlation
        // (rtp2httpd service.c msrc_res/fcc_res family). Scoped RAII:
        // no other rule sees member keys.
        std::set<const VarDecl*> memberBases =
            codeskeptic::collectMemberFactBases(func, *result.Context);
        codeskeptic::MemberFactScope memberScope(&memberBases);

        NullDerefAnalysis analysis(
            trackedVars, codeskeptic::collectUnkeyableDecls(func),
            codeskeptic::collectFactDecls(func),
            codeskeptic::collectPtrFactDecls(func),
            func->getQualifiedNameAsString(), results_);
        if (!parsed.clauses.empty()) {
            auto req = codeskeptic::analyzeRequires(parsed, func);
            if (!req.enforced.empty())
                analysis.seedRequires(func, req.enforced);
            if (!guardedEnsures.enforced.empty())
                analysis.setGuardedEnsures(
                    std::move(guardedEnsures.enforced));
        }
        auto df = codeskeptic::runDataflow(func, *result.Context, analysis);
        if (!df.converged)
            codeskeptic::CoverageReport::instance().recordNonConvergence(
                func->getQualifiedNameAsString());
        analysis.attachTraces();
    }

private:
    codeskeptic::DiagnosticList& results_;
};

} // anonymous namespace

namespace codeskeptic {

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

} // namespace codeskeptic
