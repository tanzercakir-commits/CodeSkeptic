#ifndef CODESKEPTIC_FUNCTION_SUMMARY_H
#define CODESKEPTIC_FUNCTION_SUMMARY_H

#include "engine/Interval.h"

#include <map>
#include <set>
#include <string>
#include <vector>

namespace clang {
class ASTContext;
class CallExpr;
class FunctionDecl;
}

namespace codeskeptic {

// Interprocedural analysis v2: deterministic function summaries.
//
// Independent relations cover return nullness/zeroness/ownership and
// identity, parameter effects/access/ownership, entry preconditions,
// output postconditions, and exact one-hop record fields that may be
// written. Keeping the axes separate lets callers consume a strong fact
// without inventing strength on an unrelated relation.
//
// Visible bodies are solved TU-locally; externally linked summaries can
// be harvested, persisted, and loaded for cross-TU callers. Clean local
// aliases, direct calls, and controlled local function-pointer target sets
// compose. Unresolved indirect calls, ambiguous
// aliases, captures, and conflicting paths degrade only the affected
// relations to their conservative value.
//
// Visible direct calls form a call graph. Acyclic components are evaluated
// callee-first; recursive strongly connected components iterate
// synchronously from conservative seeds to an exact fixed point. A safety
// guard falls back conservatively if a future relation fails to converge.
class SummaryRegistry {
public:
    enum class ReturnNullness { Unknown, NeverNull, MaybeNull };
    // Zero-possibility for integer-returning functions: lets DivByZero
    // see across functions (the divisor is flagged even when the
    // `data = 0; return data;` source lives in another function/file).
    // The mirror of null: same mini-flow, with the zero domain.
    enum class ReturnZeroness { Unknown, AlwaysZero, NeverZero, MaybeZero };
    enum class ReturnOwnership { Unknown, Owned, Borrowed };
    enum class ParamEffect { Opaque, ReadsOnly, Frees, Stores };
    enum class ParamAccess { Unknown, None, Reads, Writes, ReadsWrites };
    enum class ParamOwnership {
        Unknown, Borrowed, Consumed, Transferred
    };
    enum class ParamPrecondition { None, NonNullCrash, NonNullRejected };
    enum class ParamPostcondition { Unknown, Null, NonNull };

    // Exact one-hop fields that may be written through a record pointer
    // or reference. known=false is conservative; known=true with an empty
    // set proves that the callee writes no fields through this parameter.
    struct FieldWriteSet {
        bool known = false;
        std::set<std::string> fields;
        bool operator==(const FieldWriteSet& other) const {
            return known == other.known && fields == other.fields;
        }
    };

    struct FunctionSummary {
        ReturnNullness returnNullness = ReturnNullness::Unknown;
        ReturnZeroness returnZeroness = ReturnZeroness::Unknown;
        ReturnOwnership returnOwnership = ReturnOwnership::Unknown;
        std::vector<ParamEffect> params;

        // Independent interprocedural-v2 relations. ParamAccess describes
        // reads/writes through the pointer, while ParamOwnership describes
        // what happens to responsibility for the pointed-to allocation.
        // Keeping these axes separate avoids treating `return p` as an
        // ownership transfer merely because the pointer value escapes.
        std::vector<ParamAccess> paramAccesses;
        std::vector<ParamOwnership> paramOwnerships;
        std::vector<FieldWriteSet> paramFieldWrites;

        // Entry requirements inferred from the callee's own leading
        // guard, and exact normal-return effects on pointer out-params.
        // The vectors are indexed like params. Missing entries (legacy
        // summary files and conservative overload merges) mean no
        // precondition / unknown postcondition.
        std::vector<ParamPrecondition> paramPreconditions;
        std::vector<ParamPostcondition> paramPostconditions;

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

        // Exact pointer return-alias relation (interprocedural v2):
        // every reachable return denotes pointer parameter
        // #returnAliasParam's entry object. Unlike nullFromParam this
        // describes identity, not merely null correspondence, and is
        // therefore valid independently of returnNullness. -1 = no
        // proven exact relation.
        int returnAliasParam = -1;

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

        ParamAccess paramAccess(unsigned index) const {
            if (index >= paramAccesses.size()) return ParamAccess::Unknown;
            return paramAccesses[index];
        }

        const FieldWriteSet* exactParamFieldWrites(unsigned index) const {
            if (index >= paramFieldWrites.size() ||
                !paramFieldWrites[index].known)
                return nullptr;
            return &paramFieldWrites[index];
        }

        ParamOwnership paramOwnership(unsigned index) const {
            if (index < paramOwnerships.size()) return paramOwnerships[index];
            // v1-v8 compatibility: preserve the old caller behavior when
            // a persisted summary predates the independent ownership axis.
            switch (paramEffect(index)) {
                case ParamEffect::ReadsOnly: return ParamOwnership::Borrowed;
                case ParamEffect::Frees: return ParamOwnership::Consumed;
                case ParamEffect::Stores: return ParamOwnership::Transferred;
                case ParamEffect::Opaque: break;
            }
            return ParamOwnership::Unknown;
        }

        ParamPrecondition paramPrecondition(unsigned index) const {
            if (index >= paramPreconditions.size())
                return ParamPrecondition::None;
            return paramPreconditions[index];
        }

        ParamPostcondition paramPostcondition(unsigned index) const {
            if (index >= paramPostconditions.size())
                return ParamPostcondition::Unknown;
            return paramPostconditions[index];
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

    // Direct calls use their declaration; controlled indirect calls use
    // the conservative merge of their exact local function-pointer target
    // set. Returns nullptr when target resolution was not provably closed.
    const FunctionSummary* lookup(const clang::CallExpr* call) const;

    // --- Cross-TU layer (Horizon 2: whole-program mode) ---
    //
    // Key: qualified name + "/" + parameter count. Only EXTERNALLY
    // linked functions are stored/looked up — static (file-local)
    // functions cannot be called from outside the TU and, in corpora
    // like Juliet, occur in every file under the same name; keying
    // them would produce false matches. C++ overloads may land on the
    // same key: on collision, fields merge conservatively
    // relation by relation toward weaker claims — ambiguity always
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
    std::map<const clang::CallExpr*, FunctionSummary> callSummaries_;
    bool stable_ = false;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_FUNCTION_SUMMARY_H
