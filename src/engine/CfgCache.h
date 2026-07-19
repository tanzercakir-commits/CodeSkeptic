#ifndef CODESKEPTIC_CFG_CACHE_H
#define CODESKEPTIC_CFG_CACHE_H

#include <map>
#include <memory>

namespace clang {
class ASTContext;
class CFG;
class FunctionDecl;
}

namespace codeskeptic {

// Per-function CFG cache: the CFG of a function is built ONCE within
// the TU and shared by all consumers (4 rules + every sweep of the
// summary mini-flows). Previously there were 6+ builds per function.
//
// Build options (setAllAlwaysAdd) now live ONLY here — consumers must
// see the same granularity (two-phase reporting and the top-node
// contract depend on it).
//
// Validity: FunctionDecl* keys are TU-specific. Two protections:
//  1. Explicit cleanup at the end of the TU (RuleEngine::runAll /
//     TestHelper / whole-program harvest — the same points as
//     SummaryRegistry::clear).
//  2. Automatic flush when the ASTContext changes (backup safety:
//     against the chance of a false hit via address reuse — this is
//     the local embodiment of the "stale CFG is NEVER served"
//     principle).
class CfgCache {
public:
    static CfgCache& instance();

    // Returns the function's CFG (building it if needed). nullptr if
    // it cannot be built. The returned pointer is valid until the
    // next clear().
    clang::CFG* get(const clang::FunctionDecl* func,
                    clang::ASTContext& ctx);

    void clear();

    // Test/diagnostic counters (process-lifetime)
    static unsigned hits();
    static unsigned misses();
    static void resetCounters();
    size_t size() const { return cache_.size(); }

private:
    std::map<const clang::FunctionDecl*, std::unique_ptr<clang::CFG>>
        cache_;
    const clang::ASTContext* ctx_ = nullptr;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_CFG_CACHE_H
