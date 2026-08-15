#include "analyzer/DefaultRules.h"
#include "analyzer/StaticAnalyzer.h"
#include "config/Config.h"
#include "server/McpServer.h"

#include <gtest/gtest.h>
#include <llvm/ADT/SmallString.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#ifndef CODESKEPTIC_BINARY
#error "CODESKEPTIC_BINARY must name the production executable"
#endif
#ifndef CODESKEPTIC_BUDGET_WORKER_PROBE
#error "CODESKEPTIC_BUDGET_WORKER_PROBE must name the budget worker probe"
#endif

using namespace codeskeptic;

namespace {

class TemporaryProject {
public:
    TemporaryProject() {
        llvm::SmallString<256> path;
        if (!llvm::sys::fs::createUniqueDirectory(
                "codeskeptic-budgeted-analysis-test", path))
            path_ = std::filesystem::path(path.str().str());
    }
    ~TemporaryProject() {
        std::error_code ec;
        if (!path_.empty()) std::filesystem::remove_all(path_, ec);
    }
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

void writeProject(
    const std::filesystem::path& root,
    const std::vector<std::pair<std::string, std::string>>& sources) {
    llvm::json::Array database;
    for (const auto& [name, contents] : sources) {
        const auto path = root / name;
        std::ofstream source(path, std::ios::binary | std::ios::trunc);
        source << contents;
        source.close();

        llvm::json::Array arguments;
        arguments.push_back("clang++");
        arguments.push_back("-std=c++17");
        arguments.push_back("-fsyntax-only");
        arguments.push_back(path.string());
        database.push_back(llvm::json::Object{
            {"directory", root.string()},
            {"arguments", std::move(arguments)},
            {"file", path.string()},
        });
    }
    std::ofstream output(root / "compile_commands.json",
                         std::ios::binary | std::ios::trunc);
    std::string text;
    llvm::raw_string_ostream stream(text);
    stream << llvm::json::Value(std::move(database));
    stream.flush();
    output << text << '\n';
}

bool configure(Config& config, const std::filesystem::path& root,
               const char* worker, unsigned timeout, unsigned memory,
               bool whole_program = false) {
    std::vector<std::string> storage{
        "codeskeptic-test", "--source", root.string(),
        "--build-path", root.string(),
        "--tu-timeout-seconds", std::to_string(timeout),
        "--tu-memory-mib", std::to_string(memory),
    };
    if (whole_program) storage.push_back("--whole-program");
    std::vector<char*> argv;
    for (auto& argument : storage) argv.push_back(argument.data());
    if (!config.parseArgs(static_cast<int>(argv.size()), argv.data()))
        return false;
    config.setWorkerProgram(worker);
    return true;
}

bool configureArgs(Config& config, std::vector<std::string> storage,
                   const char* worker) {
    std::vector<char*> argv;
    for (auto& argument : storage) argv.push_back(argument.data());
    if (!config.parseArgs(static_cast<int>(argv.size()), argv.data()))
        return false;
    config.setWorkerProgram(worker);
    return true;
}

AnalysisResult analyze(Config config, DiagnosticList& diagnostics) {
    StaticAnalyzer analyzer(std::move(config));
    registerDefaultRules(analyzer);
    AnalysisResult result = analyzer.run();
    diagnostics = analyzer.diagnostics();
    return result;
}

const TranslationUnitReceipt* receiptFor(
    const AnalysisResult& result, const std::string& filename) {
    const auto found = std::find_if(
        result.tu_receipts.begin(), result.tu_receipts.end(),
        [&filename](const TranslationUnitReceipt& receipt) {
            return std::filesystem::path(receipt.canonical_path).filename() ==
                   filename;
        });
    return found == result.tu_receipts.end() ? nullptr : &*found;
}

} // anonymous namespace

TEST(BudgetedAnalysisTest, WholeProgramProductionWorkersPreserveCrossTuFinding) {
    TemporaryProject project;
    ASSERT_FALSE(project.path().empty());
    writeProject(project.path(), {
        {"callee.cpp",
         "int* find(int c) { static int value = 1; "
         "if (c) return &value; return nullptr; }\n"},
        {"caller.cpp",
         "int* find(int); void consume(int c) { int* p = find(c); "
         "int value = *p; (void)value; }\n"},
    });
    Config config;
    ASSERT_TRUE(configure(config, project.path(), CODESKEPTIC_BINARY,
                          30, 1024, true));
    DiagnosticList diagnostics;

    testing::internal::CaptureStderr();
    const AnalysisResult result = analyze(std::move(config), diagnostics);
    const std::string stderr_output = testing::internal::GetCapturedStderr();

    EXPECT_EQ(result.attempted_tus, 2u);
    EXPECT_EQ(result.analyzed_tus, 2u);
    EXPECT_EQ(result.exitCode(), 1);
    EXPECT_EQ(result.tu_receipts.size(), 4u);
    EXPECT_EQ(result.completedReceiptCount(), 4u);
    EXPECT_EQ(std::count_if(result.tu_receipts.begin(),
                            result.tu_receipts.end(),
                            [](const TranslationUnitReceipt& receipt) {
                                return receipt.phase == "summary-harvest";
                            }), 2);
    EXPECT_NE(stderr_output.find("Whole-program pass"), std::string::npos);
    EXPECT_NE(std::find_if(diagnostics.begin(), diagnostics.end(),
                           [](const Diagnostic& diagnostic) {
                               return diagnostic.rule_id == "null-deref";
                           }), diagnostics.end());
}

TEST(BudgetedAnalysisTest, TimeoutPreservesCompletedReceiptsAndContinues) {
    TemporaryProject project;
    ASSERT_FALSE(project.path().empty());
    writeProject(project.path(), {
        {"01-complete.cpp", "int first() { return 1; }\n"},
        {"02-timeout.cpp", "int second() { return 2; }\n"},
        {"03-complete.cpp", "int third() { return 3; }\n"},
    });
    Config config;
    ASSERT_TRUE(configure(config, project.path(),
                          CODESKEPTIC_BUDGET_WORKER_PROBE, 1, 256));
    DiagnosticList diagnostics;

    const AnalysisResult result = analyze(std::move(config), diagnostics);

    EXPECT_EQ(result.attempted_tus, 3u);
    EXPECT_EQ(result.analyzed_tus, 2u);
    EXPECT_EQ(result.exitCode(), 2);
    EXPECT_TRUE(result.hasResourceFailure());
    EXPECT_EQ(result.completedReceiptCount(), 2u);
    ASSERT_EQ(result.tu_receipts.size(), 3u);
    EXPECT_EQ(result.tu_receipts[0].status,
              TranslationUnitStatus::Completed);
    EXPECT_EQ(result.tu_receipts[1].status,
              TranslationUnitStatus::TimedOut);
    EXPECT_EQ(result.tu_receipts[2].status,
              TranslationUnitStatus::Completed);
    EXPECT_EQ(result.tu_receipts[1].timeout_seconds, 1u);
    EXPECT_EQ(result.tu_receipts[1].memory_mib, 256u);
    EXPECT_GE(result.tu_receipts[1].duration_ms, 900u);
    EXPECT_LT(result.tu_receipts[1].duration_ms, 5000u);
    EXPECT_TRUE(diagnostics.empty());
}

TEST(BudgetedAnalysisTest, MemoryCeilingFailsExactTranslationUnitClosed) {
    TemporaryProject project;
    ASSERT_FALSE(project.path().empty());
    writeProject(project.path(), {
        {"memory.cpp", "int memory_case() { return 0; }\n"},
    });
    Config config;
    ASSERT_TRUE(configure(config, project.path(),
                          CODESKEPTIC_BUDGET_WORKER_PROBE, 10, 256));
    DiagnosticList diagnostics;

    const AnalysisResult result = analyze(std::move(config), diagnostics);

    EXPECT_EQ(result.attempted_tus, 1u);
    EXPECT_EQ(result.analyzed_tus, 0u);
    EXPECT_EQ(result.exitCode(), 2);
    EXPECT_TRUE(result.hasResourceFailure());
    ASSERT_EQ(result.tu_receipts.size(), 1u);
    const auto* receipt = receiptFor(result, "memory.cpp");
    ASSERT_NE(receipt, nullptr);
    EXPECT_EQ(receipt->status, TranslationUnitStatus::MemoryExceeded);
    EXPECT_EQ(receipt->timeout_seconds, 10u);
    EXPECT_EQ(receipt->memory_mib, 256u);
    EXPECT_LT(receipt->duration_ms, 10000u);
    EXPECT_TRUE(diagnostics.empty());
}

TEST(BudgetedAnalysisTest, ProductionWorkersPreserveMissingAndBrokenCoverage) {
    TemporaryProject project;
    ASSERT_FALSE(project.path().empty());
    writeProject(project.path(), {
        {"complete.cpp", "int complete_case() { return 0; }\n"},
        {"broken.cpp", "int broken_case( { return 0; }\n"},
    });
    const auto missing = project.path() / "missing.cpp";
    const auto file_list = project.path() / "requested-files.txt";
    {
        std::ofstream list(file_list, std::ios::binary | std::ios::trunc);
        list << (project.path() / "complete.cpp").string() << '\n'
             << (project.path() / "broken.cpp").string() << '\n'
             << missing.string() << '\n';
    }
    Config config;
    ASSERT_TRUE(configureArgs(
        config,
        {"codeskeptic-test", "--files", file_list.string(),
         "--build-path", project.path().string(),
         "--tu-timeout-seconds", "30", "--tu-memory-mib", "1024"},
        CODESKEPTIC_BINARY));
    DiagnosticList diagnostics;

    const AnalysisResult result = analyze(std::move(config), diagnostics);

    EXPECT_EQ(result.attempted_tus, 3u);
    EXPECT_EQ(result.analyzed_tus, 1u);
    EXPECT_EQ(result.broken_tus, 1u);
    EXPECT_EQ(result.exitCode(), 2);
    ASSERT_EQ(result.tu_receipts.size(), 3u);
    const auto* complete = receiptFor(result, "complete.cpp");
    const auto* broken = receiptFor(result, "broken.cpp");
    const auto* missing_receipt = receiptFor(result, "missing.cpp");
    ASSERT_NE(complete, nullptr);
    ASSERT_NE(broken, nullptr);
    ASSERT_NE(missing_receipt, nullptr);
    EXPECT_EQ(complete->status, TranslationUnitStatus::Completed);
    EXPECT_EQ(broken->status, TranslationUnitStatus::Broken);
    EXPECT_EQ(missing_receipt->status, TranslationUnitStatus::Missing);
}

TEST(BudgetedAnalysisTest, ProductionPlanPreservesDistinctCompileCommands) {
    TemporaryProject project;
    ASSERT_FALSE(project.path().empty());
    writeProject(project.path(), {
        {"multi.cpp", "int configured_value() { return VALUE; }\n"},
    });
    const auto source = project.path() / "multi.cpp";
    llvm::json::Array database;
    for (const char* definition : {"-DVALUE=1", "-DVALUE=2"}) {
        database.push_back(llvm::json::Object{
            {"directory", project.path().string()},
            {"arguments", llvm::json::Array{
                "clang++", "-std=c++17", definition, "-fsyntax-only",
                source.string()}},
            {"file", source.string()},
        });
    }
    {
        std::ofstream output(project.path() / "compile_commands.json",
                             std::ios::binary | std::ios::trunc);
        std::string text;
        llvm::raw_string_ostream stream(text);
        stream << llvm::json::Value(std::move(database));
        stream.flush();
        output << text << '\n';
    }
    Config config;
    ASSERT_TRUE(configureArgs(
        config,
        {"codeskeptic-test", "--source", source.string(),
         "--build-path", project.path().string(),
         "--tu-timeout-seconds", "30", "--tu-memory-mib", "1024"},
        CODESKEPTIC_BINARY));
    DiagnosticList diagnostics;

    const AnalysisResult result = analyze(std::move(config), diagnostics);

    EXPECT_EQ(result.attempted_tus, 2u);
    EXPECT_EQ(result.analyzed_tus, 2u);
    EXPECT_EQ(result.exitCode(), 0);
    ASSERT_EQ(result.tu_receipts.size(), 2u);
    EXPECT_EQ(result.tu_receipts[0].command_ordinal, 0u);
    EXPECT_EQ(result.tu_receipts[1].command_ordinal, 1u);
    EXPECT_NE(result.tu_receipts[0].compile_command_sha256,
              result.tu_receipts[1].compile_command_sha256);
    EXPECT_EQ(result.completedReceiptCount(), 2u);
}

TEST(BudgetedAnalysisTest, ProductionWorkersPreserveSummaryAndModelInputs) {
    TemporaryProject project;
    ASSERT_FALSE(project.path().empty());
    writeProject(project.path(), {
        {"callee.cpp",
         "int* find(int c) { static int value = 1; "
         "if (c) return &value; return nullptr; }\n"},
        {"caller.cpp",
         "int* find(int); int* vendor_find(int); "
         "int consume(int c) { int* a = find(c); int* b = vendor_find(c); "
         "return *a + *b; }\n"},
    });
    const auto summary = project.path() / "harvested.csk";
    const auto model = project.path() / "vendor.csk";
    {
        std::ofstream output(model, std::ios::binary | std::ios::trunc);
        output << "codeskeptic-summaries v10\n"
                  "vendor_find/1\tM\tO\tU\t-\t-\t-\t-\tO\tU\tU\tU\tU\t?\n";
    }

    Config harvest_config;
    ASSERT_TRUE(configureArgs(
        harvest_config,
        {"codeskeptic-test", "--source",
         (project.path() / "callee.cpp").string(), "--build-path",
         project.path().string(), "--summary-out", summary.string(),
         "--tu-timeout-seconds", "30", "--tu-memory-mib", "1024"},
        CODESKEPTIC_BINARY));
    DiagnosticList harvest_diagnostics;
    const AnalysisResult harvest =
        analyze(std::move(harvest_config), harvest_diagnostics);
    ASSERT_EQ(harvest.exitCode(), 0);
    ASSERT_TRUE(std::filesystem::is_regular_file(summary));

    Config caller_config;
    ASSERT_TRUE(configureArgs(
        caller_config,
        {"codeskeptic-test", "--source",
         (project.path() / "caller.cpp").string(), "--build-path",
         project.path().string(), "--summary-in", summary.string(),
         "--model-file", model.string(), "--tu-timeout-seconds", "30",
         "--tu-memory-mib", "1024"},
        CODESKEPTIC_BINARY));
    DiagnosticList diagnostics;
    const AnalysisResult result = analyze(std::move(caller_config), diagnostics);

    EXPECT_FALSE(result.summary_load_failed);
    EXPECT_FALSE(result.summary_stale);
    EXPECT_EQ(result.exitCode(), 1);
    EXPECT_EQ(result.completedReceiptCount(), 1u);
    EXPECT_EQ(std::count_if(
                  diagnostics.begin(), diagnostics.end(),
                  [](const Diagnostic& diagnostic) {
                      return diagnostic.rule_id == "null-deref";
                  }),
              2);
}

TEST(BudgetedAnalysisTest, ProductionArtifactFailuresRemainFailClosed) {
    TemporaryProject project;
    ASSERT_FALSE(project.path().empty());
    writeProject(project.path(), {
        {"clean.cpp", "int artifact_case() { return 0; }\n"},
    });
    const auto source = project.path() / "clean.cpp";
    const auto missing_dir = project.path() / "missing-output-directory";

    for (const auto& [option, filename] :
         std::vector<std::pair<std::string, std::string>>{
             {"--json", "result.json"},
             {"--sarif", "result.sarif"},
             {"--html", "result.html"}}) {
        Config config;
        ASSERT_TRUE(configureArgs(
            config,
            {"codeskeptic-test", "--source", source.string(),
             "--build-path", project.path().string(), option,
             (missing_dir / filename).string(), "--tu-timeout-seconds", "30",
             "--tu-memory-mib", "1024"},
            CODESKEPTIC_BINARY));
        DiagnosticList diagnostics;
        const AnalysisResult result = analyze(std::move(config), diagnostics);
        EXPECT_EQ(result.analyzed_tus, 1u) << option;
        EXPECT_TRUE(result.report_write_failed) << option;
        EXPECT_EQ(result.exitCode(), 2) << option;
    }

    Config load_config;
    ASSERT_TRUE(configureArgs(
        load_config,
        {"codeskeptic-test", "--source", source.string(), "--build-path",
         project.path().string(), "--baseline",
         (project.path() / "missing.baseline").string(),
         "--tu-timeout-seconds", "30", "--tu-memory-mib", "1024"},
        CODESKEPTIC_BINARY));
    DiagnosticList load_diagnostics;
    const AnalysisResult load_result =
        analyze(std::move(load_config), load_diagnostics);
    EXPECT_TRUE(load_result.baseline_load_failed);
    EXPECT_EQ(load_result.exitCode(), 2);

    Config write_config;
    ASSERT_TRUE(configureArgs(
        write_config,
        {"codeskeptic-test", "--source", source.string(), "--build-path",
         project.path().string(), "--write-baseline",
         (missing_dir / "result.baseline").string(),
         "--tu-timeout-seconds", "30", "--tu-memory-mib", "1024"},
        CODESKEPTIC_BINARY));
    DiagnosticList write_diagnostics;
    const AnalysisResult write_result =
        analyze(std::move(write_config), write_diagnostics);
    EXPECT_TRUE(write_result.baseline_write_failed);
    EXPECT_FALSE(write_result.baseline_recorded);
    EXPECT_EQ(write_result.exitCode(), 2);
}

TEST(BudgetedAnalysisTest, ConfigFileBudgetsReachProductionReceipt) {
    TemporaryProject project;
    ASSERT_FALSE(project.path().empty());
    writeProject(project.path(), {
        {"config-complete.cpp", "int configured() { return 0; }\n"},
    });
    Config config;
    ASSERT_TRUE(config.loadFromText(
        "source_path = " + project.path().string() + "\n" +
        "build_path = " + project.path().string() + "\n" +
        "tu_timeout_seconds = 7\n"
        "tu_memory_mib = 384\n"));
    config.setWorkerProgram(CODESKEPTIC_BUDGET_WORKER_PROBE);
    DiagnosticList diagnostics;

    const AnalysisResult result = analyze(std::move(config), diagnostics);

    ASSERT_EQ(result.tu_receipts.size(), 1u);
    EXPECT_EQ(result.tu_receipts[0].status,
              TranslationUnitStatus::Completed);
    EXPECT_EQ(result.tu_receipts[0].timeout_seconds, 7u);
    EXPECT_EQ(result.tu_receipts[0].memory_mib, 384u);
    EXPECT_EQ(result.exitCode(), 0);
}

TEST(BudgetedAnalysisTest, McpRequestUsesProductionWorkerAndResolvedBudgets) {
    TemporaryProject project;
    ASSERT_FALSE(project.path().empty());
    writeProject(project.path(), {
        {"mcp-clean.cpp", "int mcp_clean() { return 0; }\n"},
    });
    Config base;
    base.setWorkerProgram(CODESKEPTIC_BINARY);
    llvm::json::Object arguments{
        {"path", (project.path() / "mcp-clean.cpp").string()},
        {"build_path", project.path().string()},
        {"tu_timeout_seconds", 5},
        {"tu_memory_mib", 512},
    };
    llvm::json::Object request{
        {"jsonrpc", "2.0"},
        {"id", 80},
        {"method", "tools/call"},
        {"params", llvm::json::Object{
            {"name", "analyze"},
            {"arguments", std::move(arguments)},
        }},
    };
    std::string request_text;
    llvm::raw_string_ostream request_stream(request_text);
    request_stream << llvm::json::Value(std::move(request));
    request_stream.flush();

    testing::internal::CaptureStdout();
    const std::string response = handleMcpMessage(request_text, base);
    std::cout.flush();
    const std::string protocol_noise = testing::internal::GetCapturedStdout();
    EXPECT_TRUE(protocol_noise.empty()) << protocol_noise;
    auto outer = llvm::json::parse(response);
    ASSERT_TRUE(static_cast<bool>(outer)) << response;
    const auto* result = outer->getAsObject()->getObject("result");
    ASSERT_NE(result, nullptr) << response;
    const auto* content = result->getArray("content");
    ASSERT_NE(content, nullptr);
    ASSERT_EQ(content->size(), 1u);
    const auto text = (*content)[0].getAsObject()->getString("text");
    ASSERT_TRUE(text.has_value());
    auto payload = llvm::json::parse(*text);
    ASSERT_TRUE(static_cast<bool>(payload)) << text->str();
    const auto* payload_object = payload->getAsObject();
    ASSERT_NE(payload_object, nullptr);
    EXPECT_EQ(payload_object->getInteger("exit_code"), 0);
    EXPECT_EQ(payload_object->getBoolean("complete"), true);
    const auto* units = payload_object->getArray("translation_units");
    ASSERT_NE(units, nullptr);
    ASSERT_EQ(units->size(), 1u);
    const auto* unit = (*units)[0].getAsObject();
    ASSERT_NE(unit, nullptr);
    EXPECT_EQ(unit->getString("status"), "completed");
    EXPECT_EQ(unit->getInteger("timeout_seconds"), 5);
    EXPECT_EQ(unit->getInteger("memory_mib"), 512);
}
