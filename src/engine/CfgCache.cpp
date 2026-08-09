#include "engine/CfgCache.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/Analysis/CFG.h>

namespace {
unsigned g_hits = 0;
unsigned g_misses = 0;
} // anonymous namespace

namespace codeskeptic {

CfgCache& CfgCache::instance() {
    static CfgCache cache;
    return cache;
}

clang::CFG* CfgCache::get(const clang::FunctionDecl* func,
                          clang::ASTContext& ctx,
                          bool addImplicitDtors) {
    if (!func || !func->hasBody()) return nullptr;

    // Backup safety: if another TU's context arrives, the old keys
    // (that TU's FunctionDecl addresses) are invalid — flush entirely
    if (&ctx != ctx_) {
        cache_.clear();
        ctx_ = &ctx;
    }

    const clang::FunctionDecl* key = func->getCanonicalDecl();
    FunctionCache& selected = cache_[addImplicitDtors];
    auto it = selected.find(key);
    if (it != selected.end()) {
        ++g_hits;
        return it->second.get();
    }

    ++g_misses;
    clang::CFG::BuildOptions opts;
    // Make subexpressions CFG elements in evaluation order too (same
    // granularity as the CSA). Analyses look only at each element's
    // top node; no nested search inside a statement is needed.
    opts.setAllAlwaysAdd();
    opts.AddImplicitDtors = addImplicitDtors;
    auto cfg = clang::CFG::buildCFG(func, func->getBody(), &ctx, opts);
    clang::CFG* raw = cfg.get();
    selected[key] = std::move(cfg);  // if the build failed, the nullptr
                                   // is cached too — no repeated retries
    return raw;
}

void CfgCache::clear() {
    cache_.clear();
    ctx_ = nullptr;
}

unsigned CfgCache::hits() { return g_hits; }
unsigned CfgCache::misses() { return g_misses; }
void CfgCache::resetCounters() { g_hits = 0; g_misses = 0; }

} // namespace codeskeptic
