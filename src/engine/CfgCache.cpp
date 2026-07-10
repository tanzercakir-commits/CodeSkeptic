#include "engine/CfgCache.h"

#include <clang/AST/ASTContext.h>
#include <clang/AST/Decl.h>
#include <clang/Analysis/CFG.h>

namespace {
unsigned g_hits = 0;
unsigned g_misses = 0;
} // anonymous namespace

namespace zerodefect {

CfgCache& CfgCache::instance() {
    static CfgCache cache;
    return cache;
}

clang::CFG* CfgCache::get(const clang::FunctionDecl* func,
                          clang::ASTContext& ctx) {
    if (!func || !func->hasBody()) return nullptr;

    // Yedek emniyet: baska bir TU'nun baglami geldiyse eski anahtarlar
    // (o TU'nun FunctionDecl adresleri) gecersizdir — tumden bosalt
    if (&ctx != ctx_) {
        cache_.clear();
        ctx_ = &ctx;
    }

    const clang::FunctionDecl* key = func->getCanonicalDecl();
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        ++g_hits;
        return it->second.get();
    }

    ++g_misses;
    clang::CFG::BuildOptions opts;
    // Alt ifadeler de degerlendirme sirasinda birer CFG elemani olsun
    // (CSA ile ayni granulerlik). Analizler her elemanin yalnizca tepe
    // dugumune bakar; statement icinde nested arama gerekmez.
    opts.setAllAlwaysAdd();
    auto cfg = clang::CFG::buildCFG(func, func->getBody(), &ctx, opts);
    clang::CFG* raw = cfg.get();
    cache_[key] = std::move(cfg);  // kurulamadiysa nullptr da onbellege
                                   // girer — tekrar tekrar denenmez
    return raw;
}

void CfgCache::clear() {
    cache_.clear();
    ctx_ = nullptr;
}

unsigned CfgCache::hits() { return g_hits; }
unsigned CfgCache::misses() { return g_misses; }
void CfgCache::resetCounters() { g_hits = 0; g_misses = 0; }

} // namespace zerodefect
