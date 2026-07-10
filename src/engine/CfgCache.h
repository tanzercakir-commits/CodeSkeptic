#ifndef ZERODEFECT_CFG_CACHE_H
#define ZERODEFECT_CFG_CACHE_H

#include <map>
#include <memory>

namespace clang {
class ASTContext;
class CFG;
class FunctionDecl;
}

namespace zerodefect {

// Fonksiyon basina CFG onbellegi: ayni fonksiyonun CFG'si TU icinde BIR
// kez kurulur, tum tuketiciler (4 kural + ozet mini-akislarinin her
// taramasi) paylasir. Onceden fonksiyon basina 6+ insa vardi.
//
// Kurulum secenekleri (setAllAlwaysAdd) artik YALNIZCA burada yasar —
// tuketiciler ayni granulerligi gormek zorunda (iki fazli raporlama ve
// tepe-dugum sozlesmesi buna dayanir).
//
// Gecerlilik: FunctionDecl* anahtarlari TU'ya ozgudur. Iki koruma:
//  1. TU sonunda acik temizlik (RuleEngine::runAll / TestHelper /
//     whole-program hasadi — SummaryRegistry::clear ile ayni noktalar).
//  2. ASTContext degisiminde otomatik bosaltma (yedek emniyet: adres
//     yeniden kullanimiyla sahte isabet olasiligina karsi — bayat CFG
//     ASLA servis edilmez ilkesinin burada karsiligi).
class CfgCache {
public:
    static CfgCache& instance();

    // Fonksiyonun CFG'sini dondurur (gerekirse kurar). Kurulamazsa
    // nullptr. Donen isaretci bir sonraki clear()'a kadar gecerli.
    clang::CFG* get(const clang::FunctionDecl* func,
                    clang::ASTContext& ctx);

    void clear();

    // Test/teshis sayaclari (surec-omurlu)
    static unsigned hits();
    static unsigned misses();
    static void resetCounters();
    size_t size() const { return cache_.size(); }

private:
    std::map<const clang::FunctionDecl*, std::unique_ptr<clang::CFG>>
        cache_;
    const clang::ASTContext* ctx_ = nullptr;
};

} // namespace zerodefect

#endif // ZERODEFECT_CFG_CACHE_H
