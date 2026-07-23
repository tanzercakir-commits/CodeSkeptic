#include "analyzer/StaticAnalyzer.h"
#include "core/ExitPolicy.h"
#include "config/Config.h"
#include "core/Messages.h"
#include "engine/SummaryDiff.h"
#include "rules/DivByZeroRule.h"
#include "rules/IntOverflowRule.h"
#include "rules/BoundsRule.h"
#include "rules/AssumptionRule.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/NullDerefRule.h"
#include "rules/ContractRule.h"
#include "rules/PolicyRule.h"
#include "rules/UninitPointerRule_Ex.h"
#include "server/McpServer.h"

#include <cstring>
#include <iostream>

#ifndef CODESKEPTIC_VERSION
#define CODESKEPTIC_VERSION "0.0.0-dev"
#endif

int main(int argc, char* argv[]) {
    // --version exits 0 by convention (unlike --help's usage-error exit)
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::cout << "CodeSkeptic " << CODESKEPTIC_VERSION << "\n";
            return 0;
        }
    }

    codeskeptic::Config config;
    config.loadFromFile(".codeskeptic.conf");

    if (!config.parseArgs(argc, argv)) {
        return 1;
    }

    codeskeptic::setLang(codeskeptic::parseLang(config.lang()));

    if (config.serve()) {
        return codeskeptic::runMcpServer();
    }

    // Summary-diff mode: not analysis, but a contract-diff report
    // between two harvests. Exit 1 if anything is WEAKENED — a semantic
    // regression CI gate.
    if (!config.summaryDiffOld().empty()) {
        return codeskeptic::reportSummaryDiff(
            config.summaryDiffOld(), config.summaryDiffNew(), std::cout,
            config.summaryDiffGate() != "warn");
    }

    if (config.sourcePath().empty() && config.sourceFiles().empty()) {
        std::cerr << codeskeptic::msg(codeskeptic::MsgId::UsageError) << "\n";
        return 1;
    }

    const bool analyze_broken = config.analyzeBrokenTUs();
    codeskeptic::StaticAnalyzer analyzer(std::move(config));

    analyzer.addRule<codeskeptic::UninitPointerRule_Ex>();
    analyzer.addRule<codeskeptic::MemoryLeakRule_Ex>();
    analyzer.addRule<codeskeptic::DivByZeroRule>();
    analyzer.addRule<codeskeptic::IntOverflowRule>();
    analyzer.addRule<codeskeptic::BoundsRule>();
    analyzer.addRule<codeskeptic::AssumptionRule>();
    analyzer.addRule<codeskeptic::NullDerefRule>();
    analyzer.addRule<codeskeptic::ContractRule>();
    analyzer.addRule<codeskeptic::PolicyRule>();

    int findings = analyzer.run();

    const int exit_code = codeskeptic::analysisExitCode(
        findings, analyzer.totalTUs(), analyzer.brokenTUCount(),
        analyze_broken);
    if (exit_code == 2)
        std::cerr << codeskeptic::msg(codeskeptic::MsgId::NothingAnalyzed)
                  << "\n";
    return exit_code;
}
