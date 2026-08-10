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

// Per-function/options CFG cache: each requested graph is built once within
// the TU. Statement-only consumers share the original graph; analyses that
// explicitly request implicit destructors or exception-handling edges use a
// separate entry for each exact option pair.
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

    // Returns the function/options CFG (building it if needed). nullptr if it
    // cannot be built. The returned pointer is valid until the next clear().
    clang::CFG* get(const clang::FunctionDecl* func,
                    clang::ASTContext& ctx,
                    bool addImplicitDtors = false,
                    bool addEHEdges = false);

    void clear();

    // Test/diagnostic counters (process-lifetime)
    static unsigned hits();
    static unsigned misses();
    static void resetCounters();
    size_t size() const {
        size_t result = 0;
        for (const auto& [options, entries] : cache_) {
            (void)options;
            result += entries.size();
        }
        return result;
    }

private:
    using FunctionCache =
        std::map<const clang::FunctionDecl*, std::unique_ptr<clang::CFG>>;
    using OptionsKey = std::pair<bool, bool>;
    std::map<OptionsKey, FunctionCache> cache_;
    const clang::ASTContext* ctx_ = nullptr;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_CFG_CACHE_H
