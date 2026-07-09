#include "analyzer/StaticAnalyzer.h"
#include "config/Config.h"
#include "core/Messages.h"
#include "rules/DivByZeroRule.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/NullDerefRule.h"
#include "rules/UninitPointerRule_Ex.h"

#include <iostream>

int main(int argc, char* argv[]) {
    zerodefect::Config config;
    config.loadFromFile(".zerodefect.conf");

    if (!config.parseArgs(argc, argv)) {
        return 1;
    }

    zerodefect::setLang(zerodefect::parseLang(config.lang()));

    if (config.sourcePath().empty()) {
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
