#include "analyzer/StaticAnalyzer.h"
#include "config/Config.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/UninitPointerRule_Ex.h"

#include <iostream>

int main(int argc, char* argv[]) {
    zerodefect::Config config;
    config.loadFromFile(".zerodefect.conf");

    if (!config.parseArgs(argc, argv)) {
        return 1;
    }

    if (config.sourcePath().empty()) {
        std::cerr << "Hata: Kaynak dizin belirtilmedi.\n"
                  << "Kullanim: zerodefect <kaynak_yolu> [secenekler]\n"
                  << "Detay icin: zerodefect --help\n";
        return 1;
    }

    zerodefect::StaticAnalyzer analyzer(std::move(config));

    analyzer.addRule<zerodefect::UninitPointerRule_Ex>();
    analyzer.addRule<zerodefect::MemoryLeakRule_Ex>();

    int findings = analyzer.run();

    return (findings > 0) ? 1 : 0;
}
