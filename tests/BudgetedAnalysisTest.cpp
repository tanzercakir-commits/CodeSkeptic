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
#include <chrono>
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
               bool whole_program = false,
               const std::string& checkpoint = {}) {
    std::vector<std::string> storage{
        "codeskeptic-test", "--source", root.string(),
        "--build-path", root.string(),
        "--tu-timeout-seconds", std::to_string(timeout),
        "--tu-memory-mib", std::to_string(memory),
    };
    if (whole_program) storage.push_back("--whole-program");
    if (!checkpoint.empty()) {
        storage.push_back("--checkpoint-dir");
        storage.push_back(checkpoint);
    }
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

TEST(BudgetedAnalysisTest, CheckpointMissSharesOnePerTuDeadline) {
    TemporaryProject project;
    ASSERT_FALSE(project.path().empty());
    writeProject(project.path(), {
        {"deadline.cpp",
         "// SLOW_DEPENDENCY_PROBE\n"
         "// SLOW_ANALYSIS_WORKER\n"
         "int deadline_case() { return 0; }\n"},
    });
    Config config;
    ASSERT_TRUE(configure(
        config, project.path(), CODESKEPTIC_BUDGET_WORKER_PROBE,
        1, 256, false, (project.path() / "checkpoint").string()));
    DiagnosticList diagnostics;
    const auto started = std::chrono::steady_clock::now();

    const AnalysisResult result = analyze(std::move(config), diagnostics);
    const auto elapsed_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count());

    ASSERT_EQ(result.tu_receipts.size(), 1u);
    EXPECT_EQ(result.tu_receipts[0].status,
              TranslationUnitStatus::TimedOut);
    EXPECT_EQ(result.exitCode(), 2);
    EXPECT_GE(result.tu_receipts[0].duration_ms, 900u);
    EXPECT_LT(result.tu_receipts[0].duration_ms, 2000u);
    EXPECT_LT(elapsed_ms, 3000u);
}

TEST(BudgetedAnalysisTest, CheckpointHitVerificationSharesOnePerTuDeadline) {
    TemporaryProject project;
    ASSERT_FALSE(project.path().empty());
    writeProject(project.path(), {
        {"checkpoint-deadline.cpp", "int checkpoint_case() { return 0; }\n"},
    });
    const auto checkpoint = project.path() / "checkpoint";
    const auto run = [&]() {
        Config config;
        EXPECT_TRUE(configure(
            config, project.path(), CODESKEPTIC_BUDGET_WORKER_PROBE,
            1, 256, false, checkpoint.string()));
        DiagnosticList diagnostics;
        return analyze(std::move(config), diagnostics);
    };
    const AnalysisResult first = run();
    ASSERT_EQ(first.exitCode(), 0);
    ASSERT_EQ(first.tu_receipts.size(), 1u);
    ASSERT_EQ(first.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);
    {
        std::ofstream delay(
            project.path() / "checkpoint-deadline.cpp.probe-delay",
            std::ios::binary | std::ios::trunc);
        delay << "700\n";
    }
    const auto started = std::chrono::steady_clock::now();

    const AnalysisResult resumed = run();
    const auto elapsed_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count());

    ASSERT_EQ(resumed.tu_receipts.size(), 1u);
    EXPECT_EQ(resumed.tu_receipts[0].status,
              TranslationUnitStatus::TimedOut);
    EXPECT_EQ(resumed.exitCode(), 2);
    EXPECT_GE(resumed.tu_receipts[0].duration_ms, 900u);
    EXPECT_LT(resumed.tu_receipts[0].duration_ms, 2000u);
    EXPECT_LT(elapsed_ms, 3000u);
}

TEST(BudgetedAnalysisTest, CheckpointResumesOnlyExactCompletedUnits) {
    TemporaryProject project;
    ASSERT_FALSE(project.path().empty());
    writeProject(project.path(), {
        {"01-complete.cpp", "int first() { return 1; }\n"},
        {"02-resumable.cpp", "// TIMEOUT_ONCE\nint second() { return 2; }\n"},
        {"03-complete.cpp", "int third() { return 3; }\n"},
    });
    const auto checkpoint = project.path() / "checkpoint";
    Config first_config;
    ASSERT_TRUE(configure(first_config, project.path(),
                          CODESKEPTIC_BUDGET_WORKER_PROBE, 1, 256, false,
                          checkpoint.string()));
    DiagnosticList first_diagnostics;
    const AnalysisResult first =
        analyze(std::move(first_config), first_diagnostics);
    ASSERT_EQ(first.exitCode(), 2);
    ASSERT_EQ(first.tu_receipts.size(), 3u);
    EXPECT_EQ(first.completedReceiptCount(), 2u);

    Config resumed_config;
    ASSERT_TRUE(configure(resumed_config, project.path(),
                          CODESKEPTIC_BUDGET_WORKER_PROBE, 1, 256, false,
                          checkpoint.string()));
    DiagnosticList resumed_diagnostics;
    const AnalysisResult resumed =
        analyze(std::move(resumed_config), resumed_diagnostics);

    EXPECT_EQ(resumed.exitCode(), 0);
    EXPECT_EQ(resumed.attempted_tus, 3u);
    EXPECT_EQ(resumed.analyzed_tus, 3u);
    ASSERT_EQ(resumed.tu_receipts.size(), 3u);
    EXPECT_EQ(std::count_if(
                  resumed.tu_receipts.begin(), resumed.tu_receipts.end(),
                  [](const TranslationUnitReceipt& receipt) {
                      return receipt.origin == TranslationUnitOrigin::Checkpoint;
                  }), 2);
    EXPECT_EQ(std::count_if(
                  resumed.tu_receipts.begin(), resumed.tu_receipts.end(),
                  [](const TranslationUnitReceipt& receipt) {
                      return receipt.origin == TranslationUnitOrigin::Executed;
                  }), 1);
    for (const auto& receipt : resumed.tu_receipts) {
        EXPECT_EQ(receipt.status, TranslationUnitStatus::Completed);
        EXPECT_EQ(receipt.checkpoint_key_sha256.size(), 64u);
        EXPECT_EQ(receipt.payload_sha256.size(), 64u);
    }
    EXPECT_TRUE(resumed_diagnostics.empty());

    Config cold_config;
    ASSERT_TRUE(configure(cold_config, project.path(),
                          CODESKEPTIC_BUDGET_WORKER_PROBE, 1, 256, false,
                          (project.path() / "cold-checkpoint").string()));
    DiagnosticList cold_diagnostics;
    const AnalysisResult cold = analyze(std::move(cold_config), cold_diagnostics);
    EXPECT_EQ(cold.exitCode(), resumed.exitCode());
    EXPECT_EQ(cold.attempted_tus, resumed.attempted_tus);
    EXPECT_EQ(cold.analyzed_tus, resumed.analyzed_tus);
    EXPECT_EQ(cold.findings, resumed.findings);
    EXPECT_EQ(cold_diagnostics, resumed_diagnostics);
}

TEST(BudgetedAnalysisTest, CheckpointInvalidatesSameSizeSameMtimeSource) {
    TemporaryProject project;
    writeProject(project.path(), {
        {"same-size.cpp", "int value() { return 1; }\n"},
    });
    const auto checkpoint = project.path() / "checkpoint";
    const auto source = project.path() / "same-size.cpp";
    std::error_code ec;
    const auto original_time = std::filesystem::last_write_time(source, ec);
    ASSERT_FALSE(ec);

    Config first_config;
    ASSERT_TRUE(configure(first_config, project.path(),
                          CODESKEPTIC_BUDGET_WORKER_PROBE, 10, 256, false,
                          checkpoint.string()));
    DiagnosticList diagnostics;
    const AnalysisResult first = analyze(std::move(first_config), diagnostics);
    ASSERT_EQ(first.exitCode(), 0);
    ASSERT_EQ(first.tu_receipts.size(), 1u);
    const auto first_key = first.tu_receipts[0].checkpoint_key_sha256;

    {
        std::ofstream changed(source, std::ios::binary | std::ios::trunc);
        changed << "int value() { return 2; }\n";
    }
    std::filesystem::last_write_time(source, original_time, ec);
    ASSERT_FALSE(ec);

    Config changed_config;
    ASSERT_TRUE(configure(changed_config, project.path(),
                          CODESKEPTIC_BUDGET_WORKER_PROBE, 10, 256, false,
                          checkpoint.string()));
    const AnalysisResult changed =
        analyze(std::move(changed_config), diagnostics);
    ASSERT_EQ(changed.exitCode(), 0);
    ASSERT_EQ(changed.tu_receipts.size(), 1u);
    EXPECT_EQ(changed.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);
    EXPECT_NE(changed.tu_receipts[0].checkpoint_key_sha256, first_key);

    Config stable_config;
    ASSERT_TRUE(configure(stable_config, project.path(),
                          CODESKEPTIC_BUDGET_WORKER_PROBE, 10, 256, false,
                          checkpoint.string()));
    const AnalysisResult stable = analyze(std::move(stable_config), diagnostics);
    ASSERT_EQ(stable.exitCode(), 0);
    ASSERT_EQ(stable.tu_receipts.size(), 1u);
    EXPECT_EQ(stable.tu_receipts[0].origin,
              TranslationUnitOrigin::Checkpoint);
}

TEST(BudgetedAnalysisTest, CacheHitRejectsDependencyDriftAfterProbe) {
    TemporaryProject project;
    writeProject(project.path(), {
        {"drift.cpp",
         "// SIDECAR_AFTER_SECOND_PROBE\nint value() { return 1; }\n"},
    });
    const auto checkpoint = project.path() / "checkpoint";
    const auto run = [&]() {
        Config config;
        EXPECT_TRUE(configure(config, project.path(),
                              CODESKEPTIC_BUDGET_WORKER_PROBE, 10, 256,
                              false, checkpoint.string()));
        DiagnosticList diagnostics;
        return analyze(std::move(config), diagnostics);
    };

    const AnalysisResult first = run();
    ASSERT_EQ(first.exitCode(), 0);
    ASSERT_EQ(first.tu_receipts.size(), 1u);
    EXPECT_EQ(first.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);

    const AnalysisResult drifted = run();
    EXPECT_EQ(drifted.exitCode(), 2);
    ASSERT_EQ(drifted.tu_receipts.size(), 1u);
    EXPECT_EQ(drifted.tu_receipts[0].status,
              TranslationUnitStatus::WorkerFailed);
    EXPECT_NE(drifted.tu_receipts[0].origin,
              TranslationUnitOrigin::Checkpoint);

    const AnalysisResult refreshed = run();
    ASSERT_EQ(refreshed.exitCode(), 0);
    EXPECT_EQ(refreshed.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);

    const AnalysisResult stable = run();
    ASSERT_EQ(stable.exitCode(), 0);
    EXPECT_EQ(stable.tu_receipts[0].origin,
              TranslationUnitOrigin::Checkpoint);
}

TEST(BudgetedAnalysisTest, CheckpointBypassesVolatilePreprocessorInputs) {
    TemporaryProject project;
    writeProject(project.path(), {
        {"volatile.cpp",
         "const char* build_date() { return __DATE__ \" \" __TIME__; }\n"},
    });
    const auto checkpoint = project.path() / "checkpoint";
    const auto run = [&]() {
        Config config;
        EXPECT_TRUE(configure(config, project.path(), CODESKEPTIC_BINARY,
                              30, 1024, false, checkpoint.string()));
        DiagnosticList diagnostics;
        return analyze(std::move(config), diagnostics);
    };

    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        const AnalysisResult result = run();
        ASSERT_EQ(result.exitCode(), 0);
        ASSERT_EQ(result.tu_receipts.size(), 1u);
        EXPECT_EQ(result.tu_receipts[0].origin,
                  TranslationUnitOrigin::Executed);
        EXPECT_TRUE(result.tu_receipts[0].checkpoint_key_sha256.empty());
        EXPECT_TRUE(result.tu_receipts[0].payload_sha256.empty());
    }
}

TEST(BudgetedAnalysisTest, CheckpointBypassesVolatileCompileCommandMacro) {
    TemporaryProject project;
    writeProject(project.path(), {
        {"volatile-command.cpp",
         "const char* build_stamp() { return BUILD_STAMP; }\n"},
    });
    const auto source = project.path() / "volatile-command.cpp";
    llvm::json::Array arguments;
    for (const auto& argument : std::vector<std::string>{
             "clang++", "-std=c++17", "-fsyntax-only",
             "-DBUILD_STAMP=__TIME__", source.string()})
        arguments.push_back(argument);
    llvm::json::Array database;
    database.push_back(llvm::json::Object{
        {"directory", project.path().string()},
        {"arguments", std::move(arguments)},
        {"file", source.string()},
    });
    {
        std::ofstream output(project.path() / "compile_commands.json",
                             std::ios::binary | std::ios::trunc);
        std::string text;
        llvm::raw_string_ostream stream(text);
        stream << llvm::json::Value(std::move(database));
        stream.flush();
        output << text << '\n';
    }

    const auto checkpoint = project.path() / "checkpoint";
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        Config config;
        ASSERT_TRUE(configure(config, project.path(), CODESKEPTIC_BINARY,
                              30, 1024, false, checkpoint.string()));
        DiagnosticList diagnostics;
        const AnalysisResult result = analyze(std::move(config), diagnostics);
        ASSERT_EQ(result.exitCode(), 0);
        ASSERT_EQ(result.tu_receipts.size(), 1u);
        EXPECT_EQ(result.tu_receipts[0].origin,
                  TranslationUnitOrigin::Executed);
        EXPECT_TRUE(result.tu_receipts[0].checkpoint_key_sha256.empty());
        EXPECT_TRUE(result.tu_receipts[0].payload_sha256.empty());
    }
}

TEST(BudgetedAnalysisTest,
     CheckpointBypassesTokenPastedVolatileBuiltinsAcrossInputKinds) {
    TemporaryProject project;
    const auto source_case = project.path() / "source-case.cpp";
    const auto header_case = project.path() / "header-case.cpp";
    const auto response_case = project.path() / "response-case.cpp";
    const auto header = project.path() / "volatile-input.h";
    const auto response = project.path() / "volatile-input.rsp";
    {
        std::ofstream output(source_case, std::ios::binary);
        output << "#define CAT_I(a,b) a##b\n"
               << "#define CAT(a,b) CAT_I(a,b)\n"
               << "const char* source_stamp() { return CAT(__TI,ME__); }\n";
    }
    {
        std::ofstream output(header, std::ios::binary);
        output << "#define HCAT_I(a,b) a##b\n"
               << "#define HCAT(a,b) HCAT_I(a,b)\n"
               << "inline const char* header_stamp() "
                  "{ return HCAT(__DA,TE__); }\n";
    }
    {
        std::ofstream output(header_case, std::ios::binary);
        output << "#include \"volatile-input.h\"\n"
               << "const char* use_header_stamp() { return header_stamp(); }\n";
    }
    {
        std::ofstream output(response_case, std::ios::binary);
        output << "#define RCAT_I(a,b) a##b\n"
               << "#define RCAT(a,b) RCAT_I(a,b)\n"
               << "const char* response_stamp() { return BUILD_STAMP; }\n";
    }
    {
        std::ofstream output(response, std::ios::binary);
        output << "-DBUILD_STAMP=RCAT(__TIMEST,AMP__)\n";
    }
    llvm::json::Array database;
    for (const auto& source : {source_case, header_case, response_case}) {
        llvm::json::Array arguments{"clang++", "-std=c++17"};
        if (source == response_case)
            arguments.push_back("@" + response.string());
        arguments.push_back("-fsyntax-only");
        arguments.push_back(source.string());
        database.push_back(llvm::json::Object{
            {"directory", project.path().string()},
            {"arguments", std::move(arguments)},
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

    const auto checkpoint = project.path() / "checkpoint";
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        Config config;
        ASSERT_TRUE(configure(config, project.path(), CODESKEPTIC_BINARY,
                              30, 1024, false, checkpoint.string()));
        DiagnosticList diagnostics;
        const AnalysisResult result = analyze(std::move(config), diagnostics);
        ASSERT_EQ(result.exitCode(), 0);
        ASSERT_EQ(result.tu_receipts.size(), 3u);
        for (const auto& receipt : result.tu_receipts) {
            EXPECT_EQ(receipt.origin, TranslationUnitOrigin::Executed);
            EXPECT_TRUE(receipt.checkpoint_key_sha256.empty());
            EXPECT_TRUE(receipt.payload_sha256.empty());
        }
    }
}

TEST(BudgetedAnalysisTest, CheckpointInvalidatesShadowHeaderAndSidecar) {
    TemporaryProject project;
    const auto high = project.path() / "high";
    const auto low = project.path() / "low";
    std::filesystem::create_directories(high);
    std::filesystem::create_directories(low);
    writeProject(project.path(), {
        {"main.cpp", "#include \"value.h\"\nint value() { return VALUE; }\n"},
    });
    {
        std::ofstream header(low / "value.h", std::ios::binary);
        header << "#define VALUE 1\n";
    }
    const auto source = project.path() / "main.cpp";
    {
        llvm::json::Array arguments{
            "clang++", "-std=c++17", "-I", high.string(), "-I",
            low.string(), "-fsyntax-only", source.string()};
        llvm::json::Array database;
        database.push_back(llvm::json::Object{
            {"directory", project.path().string()},
            {"arguments", std::move(arguments)},
            {"file", source.string()},
        });
        std::ofstream output(project.path() / "compile_commands.json",
                             std::ios::binary | std::ios::trunc);
        std::string text;
        llvm::raw_string_ostream stream(text);
        stream << llvm::json::Value(std::move(database));
        stream.flush();
        output << text << '\n';
    }
    const auto checkpoint = project.path() / "checkpoint";
    const auto run = [&]() {
        Config config;
        EXPECT_TRUE(configure(config, project.path(), CODESKEPTIC_BINARY,
                              30, 1024, false, checkpoint.string()));
        DiagnosticList diagnostics;
        return analyze(std::move(config), diagnostics);
    };

    const AnalysisResult initial = run();
    ASSERT_EQ(initial.exitCode(), 0);
    ASSERT_EQ(initial.tu_receipts.size(), 1u);
    EXPECT_EQ(initial.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);

    {
        std::ofstream shadow(high / "value.h", std::ios::binary);
        shadow << "#define VALUE 2\n";
    }
    const AnalysisResult shadowed = run();
    ASSERT_EQ(shadowed.exitCode(), 0);
    ASSERT_EQ(shadowed.tu_receipts.size(), 1u);
    EXPECT_EQ(shadowed.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);

    const AnalysisResult stable = run();
    ASSERT_EQ(stable.exitCode(), 0);
    EXPECT_EQ(stable.tu_receipts[0].origin,
              TranslationUnitOrigin::Checkpoint);

    {
        std::ofstream sidecar(source.string() + ".csk", std::ios::binary);
        sidecar << "# existence is semantic evidence\n";
    }
    const AnalysisResult sidecar_changed = run();
    ASSERT_EQ(sidecar_changed.exitCode(), 0);
    EXPECT_EQ(sidecar_changed.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);

    {
        std::ofstream sidecar(source.string() + ".csk",
                              std::ios::binary | std::ios::trunc);
        sidecar << "# changed semantic evidence\n";
    }
    const AnalysisResult sidecar_modified = run();
    ASSERT_EQ(sidecar_modified.exitCode(), 0);
    EXPECT_EQ(sidecar_modified.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);
    std::filesystem::remove(source.string() + ".csk");
    const AnalysisResult sidecar_removed = run();
    ASSERT_EQ(sidecar_removed.exitCode(), 0);
    EXPECT_EQ(sidecar_removed.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);

    {
        std::ofstream shadow(high / "value.h",
                             std::ios::binary | std::ios::trunc);
        shadow << "#define VALUE 3\n";
    }
    const AnalysisResult header_modified = run();
    ASSERT_EQ(header_modified.exitCode(), 0);
    EXPECT_EQ(header_modified.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);
    std::filesystem::remove(high / "value.h");
    const AnalysisResult header_removed = run();
    ASSERT_EQ(header_removed.exitCode(), 0);
    EXPECT_EQ(header_removed.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);
}

#ifndef _WIN32
TEST(BudgetedAnalysisTest, CheckpointInvalidatesLexicalSymlinkSidecar) {
    TemporaryProject project;
    const auto include = project.path() / "include";
    const auto real = project.path() / "real";
    std::filesystem::create_directories(include);
    std::filesystem::create_directories(real);
    {
        std::ofstream header(real / "value.h", std::ios::binary);
        header << "#pragma once\ninline int alias_value() { return 1; }\n";
    }
    std::error_code symlink_error;
    std::filesystem::create_symlink(
        std::filesystem::path("../real/value.h"), include / "alias.h",
        symlink_error);
    ASSERT_FALSE(symlink_error) << symlink_error.message();
    writeProject(project.path(), {
        {"main.cpp",
         "#include \"alias.h\"\nint value() { return alias_value(); }\n"},
    });
    const auto source = project.path() / "main.cpp";
    llvm::json::Array arguments{
        "clang++", "-std=c++17", "-I", include.string(),
        "-fsyntax-only", source.string()};
    llvm::json::Array database;
    database.push_back(llvm::json::Object{
        {"directory", project.path().string()},
        {"arguments", std::move(arguments)},
        {"file", source.string()},
    });
    {
        std::ofstream output(project.path() / "compile_commands.json",
                             std::ios::binary | std::ios::trunc);
        std::string text;
        llvm::raw_string_ostream stream(text);
        stream << llvm::json::Value(std::move(database));
        stream.flush();
        output << text << '\n';
    }

    const auto checkpoint = project.path() / "checkpoint";
    const auto run = [&]() {
        Config config;
        EXPECT_TRUE(configure(config, project.path(), CODESKEPTIC_BINARY,
                              30, 1024, false, checkpoint.string()));
        DiagnosticList diagnostics;
        return analyze(std::move(config), diagnostics);
    };
    const auto expect_origin = [&run](TranslationUnitOrigin origin) {
        const AnalysisResult result = run();
        EXPECT_EQ(result.exitCode(), 0);
        EXPECT_EQ(result.tu_receipts.size(), 1u);
        if (result.tu_receipts.size() == 1u)
            EXPECT_EQ(result.tu_receipts[0].origin, origin);
    };

    expect_origin(TranslationUnitOrigin::Executed);
    expect_origin(TranslationUnitOrigin::Checkpoint);
    const auto sidecar = include / "alias.h.csk";
    {
        std::ofstream output(sidecar, std::ios::binary);
        output << "# lexical alias sidecar v1\n";
    }
    expect_origin(TranslationUnitOrigin::Executed);
    {
        std::ofstream output(sidecar,
                             std::ios::binary | std::ios::trunc);
        output << "# lexical alias sidecar v2\n";
    }
    expect_origin(TranslationUnitOrigin::Executed);
    ASSERT_TRUE(std::filesystem::remove(sidecar));
    expect_origin(TranslationUnitOrigin::Executed);
}
#endif

TEST(BudgetedAnalysisTest, CheckpointInvalidatesOrderedModelAndSummaryContent) {
    TemporaryProject project;
    writeProject(project.path(), {
        {"clean.cpp", "int clean() { return 0; }\n"},
    });
    const auto model = project.path() / "model.csk";
    const auto summary = project.path() / "summary.csk";
    const auto write_summary = [](const std::filesystem::path& path,
                                  const char* function) {
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        output << "codeskeptic-summaries v10\n"
               << function
               << "/1\tM\tO\tU\t-\t-\t-\t-\tO\tU\tU\tU\tU\t?\n";
    };
    write_summary(model, "vendor_one");
    write_summary(summary, "project_one");
    const auto checkpoint = project.path() / "checkpoint";
    const auto run = [&]() {
        Config config;
        EXPECT_TRUE(configureArgs(
            config,
            {"codeskeptic-test", "--source", project.path().string(),
             "--build-path", project.path().string(), "--model-file",
             model.string(), "--summary-in", summary.string(),
             "--checkpoint-dir", checkpoint.string(),
             "--tu-timeout-seconds", "30", "--tu-memory-mib", "1024"},
            CODESKEPTIC_BUDGET_WORKER_PROBE));
        DiagnosticList diagnostics;
        return analyze(std::move(config), diagnostics);
    };

    const AnalysisResult first = run();
    ASSERT_EQ(first.exitCode(), 0);
    ASSERT_EQ(first.tu_receipts.size(), 1u);
    EXPECT_EQ(first.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);

    write_summary(model, "vendor_two");
    const AnalysisResult model_changed = run();
    ASSERT_EQ(model_changed.exitCode(), 0);
    EXPECT_EQ(model_changed.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);

    write_summary(summary, "project_two");
    const AnalysisResult summary_changed = run();
    ASSERT_EQ(summary_changed.exitCode(), 0);
    EXPECT_EQ(summary_changed.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);

    const AnalysisResult stable = run();
    ASSERT_EQ(stable.exitCode(), 0);
    EXPECT_EQ(stable.tu_receipts[0].origin,
              TranslationUnitOrigin::Checkpoint);
}

TEST(BudgetedAnalysisTest, CheckpointInvalidatesModuleMapContent) {
    TemporaryProject project;
    const auto source = project.path() / "main.cpp";
    const auto module_map = project.path() / "module.modulemap";
    {
        std::ofstream output(source, std::ios::binary);
        output << "int value() { return 1; }\n";
    }
    {
        std::ofstream output(module_map, std::ios::binary);
        output << "module Auxiliary {}\n";
    }
    {
        llvm::json::Array arguments{
            "clang++", "-std=c++17",
            "-fmodule-map-file=" + module_map.string(), "-fsyntax-only",
            source.string()};
        llvm::json::Array database;
        database.push_back(llvm::json::Object{
            {"directory", project.path().string()},
            {"arguments", std::move(arguments)},
            {"file", source.string()},
        });
        std::ofstream output(project.path() / "compile_commands.json",
                             std::ios::binary | std::ios::trunc);
        std::string text;
        llvm::raw_string_ostream stream(text);
        stream << llvm::json::Value(std::move(database));
        stream.flush();
        output << text << '\n';
    }
    const auto checkpoint = project.path() / "checkpoint";
    const auto run = [&]() {
        Config config;
        EXPECT_TRUE(configure(config, project.path(), CODESKEPTIC_BINARY,
                              30, 1024, false, checkpoint.string()));
        DiagnosticList diagnostics;
        return analyze(std::move(config), diagnostics);
    };

    const AnalysisResult first = run();
    ASSERT_EQ(first.exitCode(), 0);
    ASSERT_EQ(first.tu_receipts.size(), 1u);
    EXPECT_EQ(first.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);

    const AnalysisResult stable = run();
    ASSERT_EQ(stable.exitCode(), 0);
    EXPECT_EQ(stable.tu_receipts[0].origin,
              TranslationUnitOrigin::Checkpoint);

    {
        std::ofstream output(module_map,
                             std::ios::binary | std::ios::trunc);
        output << "module Auxiliary { export * }\n";
    }
    const AnalysisResult changed = run();
    ASSERT_EQ(changed.exitCode(), 0);
    EXPECT_EQ(changed.tu_receipts[0].origin,
              TranslationUnitOrigin::Executed);

    const AnalysisResult changed_stable = run();
    ASSERT_EQ(changed_stable.exitCode(), 0);
    EXPECT_EQ(changed_stable.tu_receipts[0].origin,
              TranslationUnitOrigin::Checkpoint);
}

TEST(BudgetedAnalysisTest, WholeProgramCheckpointRestoresHarvestFragments) {
    TemporaryProject project;
    writeProject(project.path(), {
        {"callee.cpp",
         "int* find(int c) { static int value = 1; "
         "if (c) return &value; return nullptr; }\n"},
        {"caller.cpp",
         "int* find(int); void consume(int c) { int* p = find(c); "
         "int value = *p; (void)value; }\n"},
    });
    const auto checkpoint = project.path() / "checkpoint";
    const auto run = [&]() {
        Config config;
        EXPECT_TRUE(configure(config, project.path(), CODESKEPTIC_BINARY,
                              30, 1024, true, checkpoint.string()));
        DiagnosticList diagnostics;
        AnalysisResult result = analyze(std::move(config), diagnostics);
        return std::make_pair(std::move(result), std::move(diagnostics));
    };

    auto first = run();
    ASSERT_EQ(first.first.exitCode(), 1);
    ASSERT_EQ(first.first.tu_receipts.size(), 4u);
    EXPECT_EQ(std::count_if(
                  first.first.tu_receipts.begin(),
                  first.first.tu_receipts.end(),
                  [](const TranslationUnitReceipt& receipt) {
                      return receipt.origin == TranslationUnitOrigin::Executed;
                  }), 4);

    auto resumed = run();
    ASSERT_EQ(resumed.first.exitCode(), first.first.exitCode());
    ASSERT_EQ(resumed.first.tu_receipts.size(), 4u);
    EXPECT_EQ(std::count_if(
                  resumed.first.tu_receipts.begin(),
                  resumed.first.tu_receipts.end(),
                  [](const TranslationUnitReceipt& receipt) {
                      return receipt.origin == TranslationUnitOrigin::Checkpoint;
                  }), 4);
    EXPECT_EQ(resumed.first.attempted_tus, first.first.attempted_tus);
    EXPECT_EQ(resumed.first.analyzed_tus, first.first.analyzed_tus);
    EXPECT_EQ(resumed.second, first.second);
}

TEST(BudgetedAnalysisTest, ExpectedCheckpointCorruptionIsWorkerFailure) {
    TemporaryProject project;
    writeProject(project.path(), {
        {"clean.cpp", "int clean() { return 0; }\n"},
    });
    const auto checkpoint = project.path() / "checkpoint";
    Config first_config;
    ASSERT_TRUE(configure(first_config, project.path(),
                          CODESKEPTIC_BUDGET_WORKER_PROBE, 10, 256, false,
                          checkpoint.string()));
    DiagnosticList diagnostics;
    const AnalysisResult first = analyze(std::move(first_config), diagnostics);
    ASSERT_EQ(first.exitCode(), 0);
    ASSERT_EQ(first.tu_receipts.size(), 1u);
    const auto key = first.tu_receipts[0].checkpoint_key_sha256;
    {
        std::ofstream corrupt(
            checkpoint / "entries" / key / "response.json",
            std::ios::binary | std::ios::trunc);
        corrupt << "{truncated";
    }

    Config second_config;
    ASSERT_TRUE(configure(second_config, project.path(),
                          CODESKEPTIC_BUDGET_WORKER_PROBE, 10, 256, false,
                          checkpoint.string()));
    const AnalysisResult second =
        analyze(std::move(second_config), diagnostics);
    EXPECT_EQ(second.exitCode(), 2);
    ASSERT_EQ(second.tu_receipts.size(), 1u);
    EXPECT_EQ(second.tu_receipts[0].status,
              TranslationUnitStatus::WorkerFailed);
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

    EXPECT_EQ(result.attempted_tus, 1u);
    EXPECT_EQ(result.analyzed_tus, 2u);
    EXPECT_EQ(result.exitCode(), 0);
    ASSERT_EQ(result.tu_receipts.size(), 2u);
    EXPECT_EQ(result.tu_receipts[0].command_ordinal, 0u);
    EXPECT_EQ(result.tu_receipts[1].command_ordinal, 1u);
    EXPECT_NE(result.tu_receipts[0].compile_command_sha256,
              result.tu_receipts[1].compile_command_sha256);
    EXPECT_EQ(result.completedReceiptCount(), 2u);
}

TEST(BudgetedAnalysisTest, CheckpointPreservesMultiCommandOrdinals) {
    TemporaryProject project;
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
    const auto checkpoint = project.path() / "checkpoint";
    const auto run = [&]() {
        Config config;
        EXPECT_TRUE(configureArgs(
            config,
            {"codeskeptic-test", "--source", source.string(),
             "--build-path", project.path().string(),
             "--tu-timeout-seconds", "30", "--tu-memory-mib", "1024",
             "--checkpoint-dir", checkpoint.string()},
            CODESKEPTIC_BINARY));
        DiagnosticList diagnostics;
        return analyze(std::move(config), diagnostics);
    };

    const AnalysisResult first = run();
    ASSERT_EQ(first.exitCode(), 0);
    ASSERT_EQ(first.tu_receipts.size(), 2u);
    EXPECT_EQ(first.tu_receipts[0].command_ordinal, 0u);
    EXPECT_EQ(first.tu_receipts[1].command_ordinal, 1u);
    EXPECT_NE(first.tu_receipts[0].checkpoint_key_sha256,
              first.tu_receipts[1].checkpoint_key_sha256);

    const AnalysisResult resumed = run();
    ASSERT_EQ(resumed.exitCode(), 0);
    ASSERT_EQ(resumed.tu_receipts.size(), 2u);
    EXPECT_EQ(resumed.tu_receipts[0].command_ordinal, 0u);
    EXPECT_EQ(resumed.tu_receipts[1].command_ordinal, 1u);
    EXPECT_EQ(std::count_if(
                  resumed.tu_receipts.begin(), resumed.tu_receipts.end(),
                  [](const TranslationUnitReceipt& receipt) {
                      return receipt.origin == TranslationUnitOrigin::Checkpoint;
                  }), 2);
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
        {"mcp-other.cpp", "int mcp_other() { return 0; }\n"},
    });
    Config base;
    ASSERT_TRUE(base.loadFromText(
        "checkpoint_dir = " + (project.path() / "mcp-checkpoint").string() +
        "\n"));
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
    EXPECT_EQ(unit->getString("origin"), "executed");
    EXPECT_EQ(unit->getString("checkpoint_key_sha256")->size(), 64u);
    EXPECT_EQ(unit->getString("payload_sha256")->size(), 64u);

    const std::string resumed_response = handleMcpMessage(request_text, base);
    EXPECT_NE(resumed_response.find("\\\"origin\\\":\\\"checkpoint\\\""),
              std::string::npos) << resumed_response;

    const std::string other_path =
        (project.path() / "mcp-other.cpp").string();
    auto other_payload = llvm::json::parse(request_text);
    ASSERT_TRUE(static_cast<bool>(other_payload)) << request_text;
    auto* other_params = other_payload->getAsObject()->getObject("params");
    ASSERT_NE(other_params, nullptr);
    auto* other_arguments = other_params->getObject("arguments");
    ASSERT_NE(other_arguments, nullptr);
    (*other_arguments)["path"] = other_path;
    std::string other_request;
    llvm::raw_string_ostream other_stream(other_request);
    other_stream << *other_payload;
    other_stream.flush();
    const std::string other_response = handleMcpMessage(other_request, base);
    EXPECT_EQ(other_response.find("\"error\""), std::string::npos)
        << other_response;
    EXPECT_NE(other_response.find("\\\"origin\\\":\\\"executed\\\""),
              std::string::npos) << other_response;

    const std::string restored_response = handleMcpMessage(request_text, base);
    EXPECT_NE(restored_response.find("\\\"origin\\\":\\\"checkpoint\\\""),
              std::string::npos) << restored_response;
}
