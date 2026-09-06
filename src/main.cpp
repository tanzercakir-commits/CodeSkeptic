#include "analyzer/StaticAnalyzer.h"
#include "analyzer/AnalysisCoordinator.h"
#include "analyzer/BuiltinRules.h"
#include "core/Capabilities.h"
#include "config/Config.h"
#include "core/Messages.h"
#include "engine/SummaryDiff.h"
#include "server/McpServer.h"
#include "source_manager/CompilationDatabaseDiscovery.h"

#include <cstring>
#include <iostream>
#include <llvm/Support/FileSystem.h>

#ifndef CODESKEPTIC_VERSION
#define CODESKEPTIC_VERSION "0.0.0-dev"
#endif

int main(int argc, char* argv[]) {
    // Internal transport is exclusive and precedes every ordinary shortcut or
    // project-config read. A child cannot recursively start a coordinator.
    for (int i = 1; i < argc; ++i) {
        if (std::strncmp(argv[i], "--codeskeptic-worker", sizeof("--codeskeptic-worker") - 1) == 0) {
            if (i != 1 || argc != 4 || std::strcmp(argv[1], "--codeskeptic-worker-v1") != 0) {
                std::cerr << "[CodeSkeptic] invalid internal worker invocation\n";
                return 2;
            }
            return codeskeptic::runAnalysisWorker(argv[2], argv[3]);
        }
    }
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

    if (config.doctor()) {
        if (config.serve() || !config.summaryDiffOld().empty() ||
            config.outputFormat() != "console") {
            std::cerr << "[CodeSkeptic] --doctor is a text-only input check; "
                         "do not combine it with server, summary-diff or report output modes\n";
            return 2;
        }
        auto selection = codeskeptic::discoverCompilationDatabase(config);
        codeskeptic::writeCompilationDoctor(selection,
                                            selection.ready ? std::cout : std::cerr);
        return selection.ready ? 0 : 2;
    }

    const auto executable = llvm::sys::fs::getMainExecutable(argv[0], reinterpret_cast<void*>(&main));
    if (executable.empty()) {
        std::cerr << "[CodeSkeptic] cannot resolve the analysis worker executable\n";
        return 2;
    }
    codeskeptic::setWorkerExecutable(executable);

    if (config.serve()) {
        return codeskeptic::runMcpServer(config);
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

    codeskeptic::addBuiltinRules(analyzer);

    const codeskeptic::AnalysisResult result = analyzer.run();
    const int exit_code = result.exitCode();
    if (exit_code == 2)
        std::cerr << codeskeptic::msg(codeskeptic::MsgId::VerdictUnavailable)
                  << "\n";
    return exit_code;
}
