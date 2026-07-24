#ifndef CODESKEPTIC_FUNCTION_SUMMARY_H
#define CODESKEPTIC_FUNCTION_SUMMARY_H

#include "engine/Interval.h"

#include <map>
#include <string>
#include <vector>

namespace clang {
class ASTContext;
class FunctionDecl;
}

namespace codeskeptic {

// Interprocedural analysis v1: TU-local function summaries.
//
// Two pieces of information are extracted:
//  1. Return nullness — if the function returns a pointer, can the
//     return value never be null on any path (NeverNull), be null on
//     some paths (MaybeNull), or is it unknown (Unknown)?
//  2. Parameter effects — does the body free the parameter (Frees),
//     only read it (ReadsOnly), or store/escape it (Stores)?
//     Functions whose body is not visible are Opaque.
//
// Scope and safety limits (v1):
//  - Only functions whose BODY is visible in the same TU get
//    summarized; outsiders stay Opaque (callers act conservatively).
//  - Blind to aliases: assigning the parameter to ANYTHING ELSE
//    (locals included) counts as Stores — cJSON_Delete's
//    `q = p; free(q)` pattern is deliberately left Escaped
//    (v2: alias tracking).
//  - Return nullness is limited to literal/new/&x/string and call
//    chains; paths that return a variable fall to Unknown.
//
// Convergence: summaries are recomputed from scratch over a bounded
// number of sweeps (<= kMaxSweeps); we stop once nothing changes. A
// recursive function sees its own previous summary — the
// Unknown/Opaque start keeps strong claims such as NeverNull and
// ReadsOnly/Frees from leaking in through recursion (no optimism in
// the wrong direction).
class SummaryRegistry {
public:
    enum class ReturnNullness { Unknown, NeverNull, MaybeNull };
    // Zero-possibility for integer-returning functions: lets DivByZero
    // see across functions (the divisor is flagged even when the
    // `data = 0; return data;` source lives in another function/file).
    // The mirror of null: same mini-flow, with the zero domain.
    enum class ReturnZeroness { Unknown, NeverZero, MaybeZero };
    enum class ParamEffect { Opaque, ReadsOnly, Frees, Stores };

    struct FunctionSummary {
        ReturnNullness returnNullness = ReturnNullness::Unknown;
        ReturnZeroness returnZeroness = ReturnZeroness::Unknown;
        std::vector<ParamEffect> params;

        // Zero-passthrough (the zeroness-through-summaries slice): when
        // returnZeroness is Unknown ONLY because some paths return
        // parameter #zeroFromParam's UNMODIFIED entry value (directly,
        // or through a chain of such functions) and every other path is
        // proven NeverZero, the claim "the result is zero only if
        // argument #zeroFromParam is zero" is recorded here. A caller
        // that knows its argument's zero-state may substitute it for
        // the call's; an Unknown argument stays Unknown — MaybeZero is
        // never manufactured. -1 = no claim.
        int zeroFromParam = -1;

        // The pointer twin (F7A.1): when returnNullness is Unknown
        // ONLY because some paths return pointer parameter
        // #nullFromParam's UNMODIFIED entry value (directly or through
        // a chain of such functions) and every other path is proven
        // NeverNull, the claim "the result is null only if argument
        // #nullFromParam is null" is recorded. dynamic_cast and any
        // non-pointer hop block the claim (either can break the
        // null-correspondence). -1 = no claim.
        int nullFromParam = -1;

        // Value-conditioned null return (#69b). When returnNullness is
        // MaybeNull AND the harvest PROVED that every null-returning
        // path is guarded by "parameter #nullCondParam outside
        // nullCondRange", the pair is recorded here: a caller that
        // proves its argument lies INSIDE the range may treat the call
        // as NeverNull at that site (the picojpeg getHuffVal shape —
        // null only in the switch default, argument provably within
        // the cases). nullCondParam < 0 = no condition (plain
        // MaybeNull, today's behavior). Merges drop the condition on
        // any disagreement — ambiguity always loses.
        int nullCondParam = -1;
        Interval nullCondRange = Interval::top();

        bool hasNullCondition() const { return nullCondParam >= 0; }

        ParamEffect paramEffect(unsigned index) const {
            if (index >= params.size()) return ParamEffect::Opaque;
            return params[index];
        }
    };

    static SummaryRegistry& instance();

    // Once per TU: computes summaries for all functions with a body.
    // FunctionDecl* keys are TU-specific — each call clears the
    // previous table COMPLETELY (no dangling pointers).
    void rebuild(clang::ASTContext& ctx);

    // Returns nullptr if there is no summary. The TU-local table is
    // tried first, then the cross-TU store (external linkage only).
    const FunctionSummary* lookup(const clang::FunctionDecl* func) const;

    // --- Cross-TU layer (Horizon 2: whole-program mode) ---
    //
    // Key: qualified name + "/" + parameter count. Only EXTERNALLY
    // linked functions are stored/looked up — static (file-local)
    // functions cannot be called from outside the TU and, in corpora
    // like Juliet, occur in every file under the same name; keying
    // them would produce false matches. C++ overloads may land on the
    // same key: on collision, fields merge conservatively
    // (returnNullness -> Unknown, param -> Opaque) — ambiguity always
    // loses, no false strong claim can arise.

    // Folds the externally-linked summaries of the TU-local table into
    // the store (called once per TU in whole-program pass 1).
    void harvestGlobal();

    // Lookup from the store; for externally-linked decls only.
    const FunctionSummary* lookupGlobal(
        const clang::FunctionDecl* func) const;

    // --- Persistence (Cross-TU v2: incremental whole-program) ---
    //
    // The store is saved/loaded to disk as line-based versioned text:
    // harvest the whole project once (--summary-out), then analyze a
    // changed file on its own but with project knowledge
    // (--summary-in).
    //
    // Loading adds into the EXISTING store; on key collision, the same
    // conservative merge as harvest (a mismatched field falls to the
    // weak claim). A corrupt file is REJECTED wholesale (false; store
    // unchanged) — partial/wrong data can never silently become a
    // strong claim.
    bool saveGlobal(const std::string& path) const;
    bool loadGlobal(const std::string& path);

    // Parses the file WITHOUT mixing it into the store: for callers
    // like summary-diff that need two harvests side by side. The
    // accept/reject rules match loadGlobal exactly (versions,
    // wholesale reject on corruption).
    static bool parseSummaryFile(
        const std::string& path,
        std::map<std::string, FunctionSummary>& out);

    void clear();
    void clearGlobal();
    size_t size() const { return summaries_.size(); }
    size_t globalSize() const { return globalStore_.size(); }

    // True once rebuild() has COMPLETED for the current TU. Consumers
    // that would otherwise read half-built summaries during the
    // inference fixpoint (the engine's call-flag edge folding,
    // ImmutableFlags.cpp) must check this — folding on an unstable
    // table would make results depend on function processing order.
    bool stable() const { return stable_; }

private:
    std::map<const clang::FunctionDecl*, FunctionSummary> summaries_;
    std::map<std::string, FunctionSummary> globalStore_;
    bool stable_ = false;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_FUNCTION_SUMMARY_H
