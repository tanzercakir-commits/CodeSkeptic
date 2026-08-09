#include "analyzer/StaticAnalyzer.h"
#include "core/Capabilities.h"
#include "config/Config.h"
#include "core/Messages.h"
#include "engine/SummaryDiff.h"
#include "rules/DivByZeroRule.h"
#include "rules/IntOverflowRule.h"
#include "rules/SignConversionRule.h"
#include "rules/AllocSizeOverflowRule.h"
#include "rules/BoundsRule.h"
#include "rules/AssumptionRule.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/FdResourceRule.h"
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

    bool capabilities = false;
    bool capabilities_json = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--capabilities") == 0)
            capabilities = true;
        else if (std::strcmp(argv[i], "--json") == 0)
            capabilities_json = true;
    }
    if (capabilities) {
        for (int i = 1; i < argc; ++i) {
            if (std::strcmp(argv[i], "--capabilities") != 0 &&
                std::strcmp(argv[i], "--json") != 0) {
                std::cerr << "[CodeSkeptic] --capabilities accepts only "
                             "the optional --json flag\n";
                return 2;
            }
        }
        codeskeptic::writeCapabilities(std::cout, capabilities_json);
        return 0;
    }

    // Help must work even when the current directory contains a malformed
    // project config; discovery/control flow does not depend on analysis input.
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0) {
            codeskeptic::Config help_config;
            if (!help_config.parseArgs(argc, argv)) return 2;
            return help_config.helpRequested() ? 0 : 2;
        }
    }

    codeskeptic::Config config;
    if (!config.loadFromFile(".codeskeptic.conf")) {
        return 2;
    }

    if (!config.parseArgs(argc, argv)) {
        return 2;
    }
    if (config.helpRequested()) return 0;

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

    codeskeptic::StaticAnalyzer analyzer(std::move(config));

    analyzer.addRule<codeskeptic::UninitPointerRule_Ex>();
    analyzer.addRule<codeskeptic::MemoryLeakRule_Ex>();
    analyzer.addRule<codeskeptic::FdResourceRule>();
    analyzer.addRule<codeskeptic::DivByZeroRule>();
    analyzer.addRule<codeskeptic::IntOverflowRule>();
    analyzer.addRule<codeskeptic::SignConversionRule>();
    analyzer.addRule<codeskeptic::AllocSizeOverflowRule>();
    analyzer.addRule<codeskeptic::BoundsRule>();
    analyzer.addRule<codeskeptic::AssumptionRule>();
    analyzer.addRule<codeskeptic::NullDerefRule>();
    analyzer.addRule<codeskeptic::ContractRule>();
    analyzer.addRule<codeskeptic::PolicyRule>();

    const codeskeptic::AnalysisResult result = analyzer.run();
    const int exit_code = result.exitCode();
    if (exit_code == 2)
        std::cerr << codeskeptic::msg(codeskeptic::MsgId::VerdictUnavailable)
                  << "\n";
    return exit_code;
}
