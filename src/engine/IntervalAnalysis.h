#ifndef CODESKEPTIC_INTERVAL_ANALYSIS_H
#define CODESKEPTIC_INTERVAL_ANALYSIS_H

// IntervalAnalysis (2026-07-14): the reusable numeric dataflow. Runs the
// interval lattice over a function's CFG via the shared DataflowEngine
// and records the entry interval-state at every statement, so any
// consumer rule can ask "what range does variable v hold at statement
// s?". Div-by-zero uses it as an extra nonzero oracle; the coming
// integer-overflow and bounds rules will query it the same way.
//
// It is purely OBSERVATIONAL — it never reports. Consumers own all
// reporting decisions, which keeps the soundness reasoning local: the
// analysis over-approximates (Interval invariant), and a rule may only
// SUPPRESS on a proven-safe range or REPORT on a proven-unsafe one.

#include "engine/Interval.h"
#include "engine/IntervalEval.h"

#include <clang/AST/Decl.h>
#include <clang/AST/Stmt.h>

#include <map>
#include <set>

namespace clang {
class ASTContext;
}

namespace codeskeptic {

class IntervalAnalysis {
public:
    using State = IntervalMap;

    explicit IntervalAnalysis(std::set<const clang::VarDecl*> vars,
                              std::map<const clang::VarDecl*, Interval> seeds =
                                  {})
        : vars_(std::move(vars)), seeds_(std::move(seeds)) {}

    State initialState() const {
        State s;
        for (const auto* v : vars_) {
            // Interprocedural seed (C3): a parameter whose callers are all
            // visible (internal linkage, address-not-taken) may start at a
            // proven range instead of top(). Everything else is
            // caller-unknown -> top().
            auto it = seeds_.find(v);
            s[v] = (it == seeds_.end()) ? Interval::top() : it->second;
        }
        return s;
    }

    // Intervals have unbounded height; termination rides on widen(),
    // not this. Kept small — the engine multiplies it by block count.
    unsigned latticeHeight() const {
        return static_cast<unsigned>(vars_.size()) * 2 + 4;
    }

    State merge(const State& a, const State& b) const {
        State r = a;
        for (const auto& [v, iv] : b) {
            auto it = r.find(v);
            r[v] = (it == r.end()) ? iv : Interval::join(it->second, iv);
        }
        return r;
    }

    State transfer(const clang::Stmt* stmt, const State& in,
                   clang::ASTContext& ctx) const {
        State out = in;
        applyIntervalAssign(out, stmt, vars_, &ctx);
        return out;
    }

    void refineOnEdge(const clang::Stmt* cond, bool isTrue, State& state,
                      clang::ASTContext& ctx) const {
        if (const auto* e = clang::dyn_cast<clang::Expr>(cond))
            refineIntervalOnEdge(state, e, isTrue, vars_, &ctx);
    }

    // Convergence widening: at a re-visited (loop) block the engine has
    // already merged this state with the previous widened one, so any
    // value still not pinned to a single constant is growing — collapse
    // it to top(). Sound and terminating; the post-loop guard edge then
    // re-narrows the specific branch (e.g. `if (n <= 1) return;`), which
    // is where the useful ranges actually come from.
    void widen(State& s) const {
        for (auto& [v, iv] : s) {
            int64_t c;
            if (!iv.isSingleton(&c)) iv = Interval::top();
        }
    }

    // Reporting pass: record the entry interval-state at each statement.
    void onStatement(const clang::Stmt* stmt, const State& before,
                     const State& /*after*/, clang::ASTContext& /*ctx*/) {
        atStmt_[stmt] = before;
    }

    // Query: the interval of `var` on entry to `stmt`, if recorded.
    // Returns top() when unknown (sound default).
    Interval intervalAt(const clang::Stmt* stmt,
                        const clang::VarDecl* var) const {
        auto s = atStmt_.find(stmt);
        if (s == atStmt_.end()) return Interval::top();
        auto v = s->second.find(var);
        return v == s->second.end() ? Interval::top() : v->second;
    }

    // The full entry interval-map at `stmt` (for evaluating a whole
    // sub-expression's range, e.g. the int-overflow rule on `a * b`).
    // nullptr when the statement was never reached/recorded.
    const IntervalMap* stateAt(const clang::Stmt* stmt) const {
        auto s = atStmt_.find(stmt);
        return s == atStmt_.end() ? nullptr : &s->second;
    }

private:
    std::set<const clang::VarDecl*> vars_;
    std::map<const clang::VarDecl*, Interval> seeds_;
    std::map<const clang::Stmt*, IntervalMap> atStmt_;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_INTERVAL_ANALYSIS_H
