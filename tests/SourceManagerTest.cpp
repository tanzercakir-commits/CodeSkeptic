#include "source_manager/SourceManager.h"
#include "analyzer/StaticAnalyzer.h"
#include "rules/DivByZeroRule.h"
#include <clang/AST/ASTContext.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <llvm/Support/JSON.h>
#include <gtest/gtest.h>
#include <chrono>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using codeskeptic::SourceManager;

class SourceManagerTargetTest : public ::testing::Test {
protected:
    fs::path root;
    fs::path restricted;
    void SetUp() override {
        root = fs::path(::testing::TempDir()) / ("codeskeptic-targets-" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        ASSERT_TRUE(fs::create_directory(root));
        std::ofstream(root / "kept.cpp") << "int kept(){return 1;}\n";
    }
    void TearDown() override {
        std::error_code error;
        if (!restricted.empty()) fs::permissions(restricted, fs::perms::owner_all, error);
        fs::remove_all(root, error);
    }
};

TEST_F(SourceManagerTargetTest, InvalidFileTargetsPreserveAcceptedState) {
    SourceManager manager(root.string(), nullptr, true);
    ASSERT_TRUE(manager.addSourceFile((root / "kept.cpp").string()));
    const auto before = manager.files();
    codeskeptic::InputError error;
    EXPECT_FALSE(manager.addSourceFile(root.string(), &error));
    EXPECT_EQ(error.reason, "invalid_target");
    EXPECT_EQ(error.field, "path");
    EXPECT_EQ(manager.files(), before);
    std::ofstream(root / "not-source.txt") << "not a source";
    EXPECT_FALSE(manager.addSourceFile((root / "not-source.txt").string(), &error));
    EXPECT_EQ(manager.files(), before);
    EXPECT_FALSE(manager.addSourceFile((root / "missing.cpp").string(), &error));
    EXPECT_EQ(manager.files(), before);
}

TEST_F(SourceManagerTargetTest, FailedDirectoryScanNeverPublishesTraversedPrefix) {
    const auto tree = root / "tree";
    fs::create_directory(tree);
    for (const char* name : {"first", "second"}) {
        fs::create_directory(tree / name);
        std::ofstream(tree / name / "input.cpp") << "int f(){return 2;}\n";
    }
    // Choose the last existing child in this host's traversal order. Changing
    // its permissions does not create/remove/reorder directory entries.
    for (const auto& entry : fs::directory_iterator(tree)) restricted = entry.path();
    std::error_code error;
    fs::permissions(restricted, fs::perms::none, error);
    if (error || std::ifstream(restricted / "input.cpp").good())
        GTEST_SKIP() << "host cannot enforce the unreadable-directory fixture";
    unsigned prefix = 0;
    bool traversalFailed = false;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(tree))
            if (entry.is_regular_file()) ++prefix;
    } catch (const fs::filesystem_error&) { traversalFailed = true; }
    ASSERT_TRUE(traversalFailed);
    ASSERT_GT(prefix, 0u) << "fixture must fail after a traversed source, not before it";
    SourceManager manager(root.string(), nullptr, true);
    manager.addSourceFile((root / "kept.cpp").string());
    const auto before = manager.files();
    codeskeptic::InputError inputError;
    EXPECT_FALSE(manager.scanDirectory(tree.string(), &inputError));
    EXPECT_EQ(inputError.reason, "read_error");
    EXPECT_EQ(manager.files(), before);
}

TEST_F(SourceManagerTargetTest, ValidScanAfterRejectedScanCommitsTogether) {
    SourceManager manager(root.string(), nullptr, true);
    codeskeptic::InputError error;
    EXPECT_FALSE(manager.scanDirectory((root / "missing").string(), &error));
    EXPECT_TRUE(manager.files().empty());
    ASSERT_TRUE(manager.scanDirectory(root.string(), &error));
    EXPECT_TRUE(error.reason.empty());
    EXPECT_EQ(manager.files(), std::vector<std::string>{fs::canonical(root / "kept.cpp").string()});
}

TEST_F(SourceManagerTargetTest, CanonicalAliasesAndRescanKeepOneSourceIdentity) {
    SourceManager manager(root.string(), nullptr, true);
    ASSERT_TRUE(manager.addSourceFile((root / "kept.cpp").string()));
    ASSERT_TRUE(manager.addSourceFile((root / "." / "kept.cpp").string()));
    ASSERT_TRUE(manager.scanDirectory(root.string()));
    EXPECT_EQ(manager.files(),
              std::vector<std::string>{fs::canonical(root / "kept.cpp").string()});
}

namespace {
codeskeptic::Config coverageConfig(const fs::path& root, bool warm) {
    std::vector<std::string> args = {"codeskeptic", root.string(),
                                   "--build-path", root.string()};
    std::vector<char*> argv;
    for (auto& arg : args) argv.push_back(arg.data());
    codeskeptic::Config config;
    EXPECT_TRUE(config.parseArgs(static_cast<int>(argv.size()), argv.data()));
    config.setWarmCache(warm);
    return config;
}

void coverageDatabase(const fs::path& root, bool missingAst) {
    llvm::json::Array commands;
    auto add = [&](const char* name, std::initializer_list<const char*> arguments) {
        llvm::json::Array args;
        for (const char* arg : arguments) args.push_back(arg);
        commands.push_back(llvm::json::Object{
            {"directory", root.string()}, {"file", name},
            {"arguments", std::move(args)}});
    };
    add("kept.cpp", {"clang++", "-DONE=1", "-c", "kept.cpp"});
    add("kept.cpp", {"clang++", "-DONE=2", "-c", "kept.cpp"});
    if (missingAst) {
        std::ofstream(root / "missing-ast.cpp") << "int other(){return 2;}\n";
        add("missing-ast.cpp", {"clang++", "-target", "invalid-cs-target",
                               "-c", "missing-ast.cpp"});
    }
    std::string text;
    llvm::raw_string_ostream out(text);
    out << llvm::json::Value(std::move(commands));
    std::ofstream(root / "compile_commands.json") << text;
}
} // namespace

TEST_F(SourceManagerTargetTest, CompileVariantsDoNotInflateAnalyzedSourceCount) {
    coverageDatabase(root, false);
    for (bool warm : {false, true}) {
        SCOPED_TRACE(warm ? "warm" : "cold");
        codeskeptic::StaticAnalyzer analyzer(coverageConfig(root, warm));
        analyzer.addRule<codeskeptic::DivByZeroRule>();
        const auto result = analyzer.run();
        EXPECT_EQ(result.attempted_tus, 1u);
        EXPECT_EQ(result.analyzed_tus, 1u);
        EXPECT_EQ(result.exitCode(), 0);
    }
    SourceManager::clearWarmCache();
}

TEST_F(SourceManagerTargetTest, DuplicateCallbacksCannotHideMissingAst) {
    coverageDatabase(root, true);
    for (bool warm : {false, true}) {
        SCOPED_TRACE(warm ? "warm" : "cold");
        codeskeptic::StaticAnalyzer analyzer(coverageConfig(root, warm));
        analyzer.addRule<codeskeptic::DivByZeroRule>();
        const auto result = analyzer.run();
        EXPECT_EQ(result.attempted_tus, 2u);
        EXPECT_EQ(result.analyzed_tus, 1u);
        EXPECT_TRUE(result.tool_failed);
        EXPECT_FALSE(result.complete());
        EXPECT_EQ(result.exitCode(), 2);
    }
    SourceManager::clearWarmCache();
}

TEST_F(SourceManagerTargetTest, WarmCachePreservesBrokenAstEvidenceAcrossOptInChanges) {
    std::ofstream(root / "kept.cpp") << "#error deliberate fixture error\nint kept(){return 1;}\n";
    auto database = std::make_unique<clang::tooling::FixedCompilationDatabase>(
        root.string(), std::vector<std::string>{"-std=c++17"});
    SourceManager manager(root.string(), std::move(database), true);
    ASSERT_TRUE(manager.addSourceFile((root / "kept.cpp").string()));
    manager.enableWarmCache(true);
    SourceManager::clearWarmCache();
    struct Restore {
        ~Restore() {
            SourceManager::setAnalyzeBrokenTUs(false);
            SourceManager::clearBrokenTUs();
            SourceManager::clearWarmCache();
        }
    } restore;
    for (bool accept : {false, true, false, true}) {
        SourceManager::setAnalyzeBrokenTUs(accept);
        unsigned visits = 0;
        EXPECT_EQ(manager.processAll([&](clang::ASTContext&) { ++visits; }), accept ? 0 : 1);
        EXPECT_EQ(visits, accept ? 1u : 0u);
        ASSERT_EQ(manager.coverage().size(), 1u);
        const auto& source = manager.coverage()[0];
        EXPECT_EQ(source.file, fs::canonical(root / "kept.cpp").string());
        EXPECT_EQ(source.commands, 1u);
        EXPECT_EQ(source.status, accept ? codeskeptic::SourceStatus::Analyzed : codeskeptic::SourceStatus::Skipped);
        EXPECT_EQ(source.analyzed_commands, accept ? 1u : 0u);
        EXPECT_EQ(source.skipped_commands, accept ? 0u : 1u);
        EXPECT_EQ(source.failed_commands, 0u);
        EXPECT_EQ(source.recovery_commands, accept ? 1u : 0u);
    }
    EXPECT_EQ(SourceManager::warmCacheMisses(), 1u);
    EXPECT_EQ(SourceManager::warmCacheHits(), 3u);
}

TEST_F(SourceManagerTargetTest, DiagnosticErrorGuardPreservesColdAndCachedOptInEvidence) {
    std::ofstream(root / "kept.cpp") <<
        "#if UNDEFINED_CONTROL\nint unused;\n#endif\nint kept(){return 1;}\n";
    struct Restore {
        ~Restore() {
            SourceManager::setAnalyzeBrokenTUs(false);
            SourceManager::clearBrokenTUs();
            SourceManager::clearWarmCache();
        }
    } restore;
    for (bool warm : {false, true}) {
        for (bool promoted : {false, true}) {
            SCOPED_TRACE(::testing::Message() << "warm=" << warm << " promoted=" << promoted);
            auto arguments = std::vector<std::string>{"-std=c++17", "-Wundef"};
            if (promoted) arguments.push_back("-Werror");
            auto database = std::make_unique<clang::tooling::FixedCompilationDatabase>(
                root.string(), arguments);
            SourceManager manager(root.string(), std::move(database), false);
            ASSERT_TRUE(manager.addSourceFile((root / "kept.cpp").string()));
            manager.enableWarmCache(warm);
            SourceManager::clearWarmCache();
            for (bool recover : {false, true, false, true}) {
                SCOPED_TRACE(recover ? "recovery" : "default");
                SourceManager::setAnalyzeBrokenTUs(recover);
                SourceManager::clearBrokenTUs();
                unsigned visits = 0;
                const bool skip = promoted && !recover;
                EXPECT_EQ(manager.processAll([&](clang::ASTContext& ctx) {
                    ++visits;
                    EXPECT_EQ(ctx.getDiagnostics().hasErrorOccurred(), promoted);
                    // This regression is specifically an error promoted from a
                    // warning, not a hard parse error already covered above.
                    EXPECT_FALSE(ctx.getDiagnostics().hasUncompilableErrorOccurred());
                }), skip ? 1 : 0);
                EXPECT_EQ(visits, skip ? 0u : 1u);
                ASSERT_EQ(manager.coverage().size(), 1u);
                const auto& source = manager.coverage()[0];
                EXPECT_EQ(source.file, fs::canonical(root / "kept.cpp").string());
                EXPECT_EQ(source.commands, 1u);
                EXPECT_EQ(source.status, skip ? codeskeptic::SourceStatus::Skipped
                                              : codeskeptic::SourceStatus::Analyzed);
                EXPECT_EQ(source.analyzed_commands, skip ? 0u : 1u);
                EXPECT_EQ(source.skipped_commands, skip ? 1u : 0u);
                EXPECT_EQ(source.failed_commands, 0u);
                EXPECT_EQ(source.recovery_commands, promoted && recover ? 1u : 0u);
                EXPECT_EQ(SourceManager::brokenTUs().size(), skip ? 1u : 0u);
            }
            EXPECT_EQ(SourceManager::warmCacheMisses(), warm ? 1u : 0u);
            EXPECT_EQ(SourceManager::warmCacheHits(), warm ? 3u : 0u);
        }
    }
}

TEST_F(SourceManagerTargetTest, NoAstFailureCannotBecomeCachedDiagnosticRecovery) {
    struct Restore {
        ~Restore() {
            SourceManager::setAnalyzeBrokenTUs(false);
            SourceManager::clearBrokenTUs();
            SourceManager::clearWarmCache();
        }
    } restore;
    for (bool warm : {false, true}) {
        auto database = std::make_unique<clang::tooling::FixedCompilationDatabase>(
            root.string(), std::vector<std::string>{"-target", "invalid-cs-target", "-Werror", "-Wundef"});
        SourceManager manager(root.string(), std::move(database), false);
        ASSERT_TRUE(manager.addSourceFile((root / "kept.cpp").string()));
        manager.enableWarmCache(warm);
        SourceManager::clearWarmCache();
        for (bool recover : {false, true, false, true}) {
            SourceManager::setAnalyzeBrokenTUs(recover);
            unsigned visits = 0;
            EXPECT_NE(manager.processAll([&](clang::ASTContext&) { ++visits; }), 0);
            EXPECT_EQ(visits, 0u);
            ASSERT_EQ(manager.coverage().size(), 1u);
            const auto& source = manager.coverage()[0];
            EXPECT_EQ(source.status, codeskeptic::SourceStatus::Failed);
            EXPECT_EQ(source.reason, "frontend_failed");
            EXPECT_EQ(source.failed_commands, 1u);
            EXPECT_EQ(source.skipped_commands, 0u);
            EXPECT_EQ(source.recovery_commands, 0u);
        }
        EXPECT_EQ(SourceManager::warmCacheHits(), 0u);
        EXPECT_EQ(SourceManager::warmCacheMisses(), warm ? 4u : 0u);
    }
}
