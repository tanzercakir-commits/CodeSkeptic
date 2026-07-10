#include "analyzer/StaticAnalyzer.h"
#include "config/Config.h"
#include "core/Messages.h"
#include "engine/SummaryDiff.h"
#include "rules/DivByZeroRule.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/NullDerefRule.h"
#include "rules/UninitPointerRule_Ex.h"
#include "server/McpServer.h"

#include <iostream>

int main(int argc, char* argv[]) {
    zerodefect::Config config;
    config.loadFromFile(".zerodefect.conf");

    if (!config.parseArgs(argc, argv)) {
        return 1;
    }

    zerodefect::setLang(zerodefect::parseLang(config.lang()));

    if (config.serve()) {
        return zerodefect::runMcpServer();
    }

    // Ozet-diff modu: analiz degil, iki hasat arasinda sozlesme farki
    // raporu. WEAKENED varsa exit 1 — semantik regresyon CI kapisi.
    if (!config.summaryDiffOld().empty()) {
        return zerodefect::reportSummaryDiff(
            config.summaryDiffOld(), config.summaryDiffNew(), std::cout);
    }

    if (config.sourcePath().empty() && config.sourceFiles().empty()) {
        std::cerr << zerodefect::msg(zerodefect::MsgId::UsageError) << "\n";
        return 1;
    }

    zerodefect::StaticAnalyzer analyzer(std::move(config));

    analyzer.addRule<zerodefect::UninitPointerRule_Ex>();
    analyzer.addRule<zerodefect::MemoryLeakRule_Ex>();
    analyzer.addRule<zerodefect::DivByZeroRule>();
    analyzer.addRule<zerodefect::NullDerefRule>();

    int findings = analyzer.run();

    return (findings > 0) ? 1 : 0;
}
