#include "analyzer/StaticAnalyzer.h"

#include "reporter/ConsoleReporter.h"
#include "reporter/JsonReporter.h"

#include <algorithm>
#include <filesystem>
#include <iostream>

namespace zerodefect {

StaticAnalyzer::StaticAnalyzer(Config config)
    : config_(std::move(config)) {
    source_mgr_ = std::make_unique<SourceManager>(config_.buildPath());

    if (!config_.sourcePath().empty()) {
        if (std::filesystem::is_directory(config_.sourcePath())) {
            source_mgr_->scanDirectory(config_.sourcePath());
        } else {
            source_mgr_->addSourceFile(config_.sourcePath());
        }
    }

    if (config_.outputFormat() == "json") {
        reporter_ = std::make_unique<JsonReporter>(config_.jsonOutputPath());
    } else {
        reporter_ = std::make_unique<ConsoleReporter>();
    }
}

int StaticAnalyzer::run() {
    diagnostics_.clear();

    if (source_mgr_->fileCount() == 0) {
        std::cerr << "[ZeroDefect] Analiz edilecek dosya yok.\n";
        return 0;
    }

    if (engine_.ruleCount() == 0) {
        std::cerr << "[ZeroDefect] Kayitli kural yok.\n";
        return 0;
    }

    for (const auto& rule_id : engine_.ruleIds()) {
        if (!config_.isRuleEnabled(rule_id)) {
            engine_.enableRule(rule_id, false);
        }
    }

    std::cerr << "[ZeroDefect] Analiz basliyor... ("
              << source_mgr_->fileCount() << " dosya, "
              << engine_.ruleCount() << " kural)\n";

    source_mgr_->processAll([this](clang::ASTContext& ctx) {
        auto findings = engine_.runAll(ctx);
        diagnostics_.insert(diagnostics_.end(), findings.begin(), findings.end());
    });

    auto severity_below = [this](const Diagnostic& d) {
        return d.severity < config_.minSeverity();
    };
    diagnostics_.erase(
        std::remove_if(diagnostics_.begin(), diagnostics_.end(), severity_below),
        diagnostics_.end());

    std::sort(diagnostics_.begin(), diagnostics_.end());

    reporter_->report(diagnostics_);

    return static_cast<int>(diagnostics_.size());
}

} // namespace zerodefect
