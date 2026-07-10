#include "analyzer/StaticAnalyzer.h"

#include "analyzer/Baseline.h"
#include "analyzer/SuppressionFilter.h"
#include "core/FunctionFilter.h"
#include "core/Messages.h"
#include "engine/FunctionSummary.h"
#include "reporter/ConsoleReporter.h"
#include "reporter/JsonReporter.h"
#include "reporter/SarifReporter.h"

#include <algorithm>
#include <filesystem>
#include <iostream>

namespace zerodefect {

StaticAnalyzer::StaticAnalyzer(Config config)
    : config_(std::move(config)) {
    setLang(parseLang(config_.lang()));
    setFunctionFilter(config_.functions());
    setLineRanges(config_.lines());

    source_mgr_ = std::make_unique<SourceManager>(config_.buildPath());
    if (config_.warmCache()) source_mgr_->enableWarmCache(true);

    if (!config_.sourcePath().empty()) {
        if (std::filesystem::is_directory(config_.sourcePath())) {
            source_mgr_->scanDirectory(config_.sourcePath());
        } else {
            source_mgr_->addSourceFile(config_.sourcePath());
        }
    }
    for (const auto& file : config_.sourceFiles()) {
        source_mgr_->addSourceFile(file);
    }

    if (config_.outputFormat() == "json") {
        reporter_ = std::make_unique<JsonReporter>(config_.jsonOutputPath());
    } else if (config_.outputFormat() == "sarif") {
        reporter_ = std::make_unique<SarifReporter>(config_.sarifOutputPath());
    } else {
        reporter_ = std::make_unique<ConsoleReporter>();
    }
}

StaticAnalyzer::~StaticAnalyzer() {
    // Global filtre durumu bu analizin omruyle sinirli kalsin: uzun
    // omurlu surecte (MCP server) filtreli bir kosum sonrakileri sessizce
    // budamasin. (Testlerde ayni sizinti InterproceduralTest'in 11
    // testini dusurmustu — ctest'in surec-basina izolasyonu gizliyordu.)
    setFunctionFilter({});
    setLineRanges({});
    // Ayni gerekce cross-TU ozet deposu icin: bir kosunun ozetleri
    // sonraki kosuya sizmasin (MCP server ayni surecte cok analiz kosar)
    SummaryRegistry::instance().clearGlobal();
}

int StaticAnalyzer::run() {
    diagnostics_.clear();

    if (source_mgr_->fileCount() == 0) {
        std::cerr << msg(MsgId::NoFilesToAnalyze) << "\n";
        return 0;
    }

    if (engine_.ruleCount() == 0) {
        std::cerr << msg(MsgId::NoRulesRegistered) << "\n";
        return 0;
    }

    for (const auto& rule_id : engine_.ruleIds()) {
        if (!config_.isRuleEnabled(rule_id)) {
            engine_.enableRule(rule_id, false);
        }
    }

    std::cerr << msg(MsgId::AnalysisStarting,
                     std::to_string(source_mgr_->fileCount()),
                     std::to_string(engine_.ruleCount())) << "\n";

    // Kayitli ozetleri yukle (Cross-TU v2): onceki bir kosunun hasadi
    // depoya katilir — tek dosya, tum-proje bilgisiyle analiz edilir.
    // Yukleme hatasi analizi DURDURMAZ ama sessiz de gecmez: ozetsiz
    // kosu daha az bulgu verir, kullanici bunu bilmeli.
    if (!config_.summaryIn().empty()) {
        auto& registry = SummaryRegistry::instance();
        if (registry.loadGlobal(config_.summaryIn())) {
            std::cerr << msg(MsgId::SummariesLoaded,
                             std::to_string(registry.globalSize()),
                             config_.summaryIn()) << "\n";
            // Tazelik: analiz edilen bir kaynak ozet dosyasindan YENIYSE
            // ozetler o dosya icin bayat olabilir — analiz durmaz
            // (muhafazakar yon: bayat ozet en fazla eksik/ekstra iddia
            // tasir, dogrulugu anahtar degil) ama kullanici tazelemeyi
            // bilmeli. Yalniz uyari, dosya basina degil bir kez.
            std::error_code ec;
            auto summaryTime = std::filesystem::last_write_time(
                config_.summaryIn(), ec);
            if (!ec) {
                for (const auto& file : source_mgr_->files()) {
                    std::error_code fec;
                    auto srcTime =
                        std::filesystem::last_write_time(file, fec);
                    if (!fec && srcTime > summaryTime) {
                        std::cerr << msg(MsgId::SummaryStaleWarning,
                                         config_.summaryIn(), file) << "\n";
                        break;
                    }
                }
            }
        } else {
            std::cerr << msg(MsgId::SummaryLoadError, config_.summaryIn())
                      << "\n";
        }
    }

    // Whole-program modu (Ufuk 2): 1. gecis tum TU'lardan harici
    // baglantili fonksiyon ozetlerini toplar; 2. gecisteki kurallar
    // dosyalar arasi cagrilarda Opaque yerine gercek ozeti gorur.
    // Bedeli ikinci parse'tir — bilincli, bayrakla acilir.
    if (config_.wholeProgram()) {
        std::cerr << msg(MsgId::WholeProgramPass,
                         std::to_string(source_mgr_->fileCount())) << "\n";
        source_mgr_->processAll([](clang::ASTContext& ctx) {
            auto& registry = SummaryRegistry::instance();
            registry.rebuild(ctx);
            registry.harvestGlobal();
            registry.clear();
        });
    }

    // --summary-out: runAll'in TU basina kurdugu yerel tablodan hasat —
    // whole-program'in ikinci parse bedeli odenmeden depo dolar
    // (whole-program modunda ikinci hasat es-degerlerle birlesir,
    // zararsiz)
    if (!config_.summaryOut().empty()) engine_.enableGlobalHarvest(true);

    source_mgr_->processAll([this](clang::ASTContext& ctx) {
        auto findings = engine_.runAll(ctx);
        diagnostics_.insert(diagnostics_.end(), findings.begin(), findings.end());
    });

    if (!config_.summaryOut().empty()) {
        auto& registry = SummaryRegistry::instance();
        if (registry.saveGlobal(config_.summaryOut())) {
            std::cerr << msg(MsgId::SummariesSaved,
                             std::to_string(registry.globalSize()),
                             config_.summaryOut()) << "\n";
        } else {
            std::cerr << msg(MsgId::SummarySaveError, config_.summaryOut())
                      << "\n";
        }
    }

    // Ayni dosya farkli path'lerle gelebilir (compile DB'de "tests/../x.c"
    // gibi) — tekillestirme ve baseline anahtarlari icin kanonik path
    for (auto& diag : diagnostics_) {
        if (diag.file.empty()) continue;
        std::error_code ec;
        auto canonical = std::filesystem::weakly_canonical(diag.file, ec);
        if (!ec) diag.file = canonical.string();
    }

    SuppressionFilter suppression;
    size_t suppressed = suppression.filter(diagnostics_);
    if (suppressed > 0) {
        std::cerr << msg(MsgId::SuppressedCount, std::to_string(suppressed))
                  << "\n";
    }

    // Kayit modu: bulgular baseline'a yazilir, raporlama yapilmaz,
    // temiz cikilir (CI'da baseline uretmek icin)
    if (!config_.writeBaselinePath().empty()) {
        if (Baseline::write(config_.writeBaselinePath(), diagnostics_)) {
            std::cerr << msg(MsgId::BaselineWritten,
                             std::to_string(diagnostics_.size()),
                             config_.writeBaselinePath()) << "\n";
            return 0;
        }
        std::cerr << msg(MsgId::OutputFileOpenError,
                         config_.writeBaselinePath()) << "\n";
        return 0;
    }

    if (!config_.baselinePath().empty()) {
        Baseline baseline;
        baseline.load(config_.baselinePath());
        size_t matched = baseline.filter(diagnostics_);
        if (matched > 0) {
            std::cerr << msg(MsgId::BaselineFiltered,
                             std::to_string(matched)) << "\n";
        }
    }

    auto severity_below = [this](const Diagnostic& d) {
        return d.severity < config_.minSeverity();
    };
    diagnostics_.erase(
        std::remove_if(diagnostics_.begin(), diagnostics_.end(), severity_below),
        diagnostics_.end());

    std::sort(diagnostics_.begin(), diagnostics_.end());

    // Header'da tanimli fonksiyonlar birden cok TU'da analiz edilir;
    // ayni bulgu her TU'dan bir kez gelir — tekillestir.
    diagnostics_.erase(
        std::unique(diagnostics_.begin(), diagnostics_.end()),
        diagnostics_.end());

    reporter_->report(diagnostics_);

    return static_cast<int>(diagnostics_.size());
}

} // namespace zerodefect
