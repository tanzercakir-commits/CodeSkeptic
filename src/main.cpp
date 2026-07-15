#include "analyzer/StaticAnalyzer.h"
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

#ifndef ZERODEFECT_VERSION
#define ZERODEFECT_VERSION "0.0.0-dev"
#endif

int main(int argc, char* argv[]) {
    // --version exits 0 by convention (unlike --help's usage-error exit)
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::cout << "ZeroDefect " << ZERODEFECT_VERSION << "\n";
            return 0;
        }
    }

    zerodefect::Config config;
    config.loadFromFile(".zerodefect.conf");

    if (!config.parseArgs(argc, argv)) {
        return 1;
    }

    zerodefect::setLang(zerodefect::parseLang(config.lang()));

    if (config.serve()) {
        return zerodefect::runMcpServer();
    }

    // Summary-diff mode: not analysis, but a contract-diff report
    // between two harvests. Exit 1 if anything is WEAKENED — a semantic
    // regression CI gate.
    if (!config.summaryDiffOld().empty()) {
        return zerodefect::reportSummaryDiff(
            config.summaryDiffOld(), config.summaryDiffNew(), std::cout,
            config.summaryDiffGate() != "warn");
    }

    if (config.sourcePath().empty() && config.sourceFiles().empty()) {
        std::cerr << zerodefect::msg(zerodefect::MsgId::UsageError) << "\n";
        return 1;
    }

    zerodefect::StaticAnalyzer analyzer(std::move(config));

    analyzer.addRule<zerodefect::UninitPointerRule_Ex>();
    analyzer.addRule<zerodefect::MemoryLeakRule_Ex>();
    analyzer.addRule<zerodefect::DivByZeroRule>();
    analyzer.addRule<zerodefect::IntOverflowRule>();
    analyzer.addRule<zerodefect::BoundsRule>();
    analyzer.addRule<zerodefect::AssumptionRule>();
    analyzer.addRule<zerodefect::NullDerefRule>();
    analyzer.addRule<zerodefect::ContractRule>();
    analyzer.addRule<zerodefect::PolicyRule>();

    int findings = analyzer.run();

    return (findings > 0) ? 1 : 0;
}
