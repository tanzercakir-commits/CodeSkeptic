#include "source_manager/SourceManager.h"
#include "source_manager/InputIdentity.h"
#include "analyzer/StaticAnalyzer.h"
#include "rules/DivByZeroRule.h"
#include "rules/NullDerefRule.h"
#include <clang/AST/ASTContext.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <llvm/Support/JSON.h>
#include <gtest/gtest.h>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>

namespace fs = std::filesystem;
using codeskeptic::SourceManager;

namespace {
class ScopedIdentityEnvironment {
public:
    explicit ScopedIdentityEnvironment(const char* name) : name_(name) {
        if (const auto* value = std::getenv(name_)) previous_ = value;
    }
    ~ScopedIdentityEnvironment() {
        EXPECT_EQ(set(previous_ ? previous_->c_str() : nullptr), 0);
    }
    int set(const char* value) const {
#ifdef _WIN32
        return _putenv_s(name_, value ? value : "");
#else
        return value ? setenv(name_, value, 1) : unsetenv(name_);
#endif
    }
private:
    const char* name_;
    std::optional<std::string> previous_;
};
} // namespace

TEST(SourceInputIdentityTest, EnvironmentChangesAreCompleteStableAndRestored) {
    const auto original = codeskeptic::inputEnvironmentIdentity();
    ASSERT_FALSE(original.empty());
    EXPECT_EQ(codeskeptic::inputEnvironmentIdentity(), original);
    {
        ScopedIdentityEnvironment first("CODESKEPTIC_TEST_IDENTITY_FIRST");
        ScopedIdentityEnvironment second("CODESKEPTIC_TEST_IDENTITY_SECOND");
        ASSERT_EQ(first.set(nullptr), 0);
        ASSERT_EQ(second.set(nullptr), 0);
        const auto absent = codeskeptic::inputEnvironmentIdentity();
        ASSERT_FALSE(absent.empty());
        ASSERT_EQ(first.set("first=value with spaces"), 0);
        const auto added = codeskeptic::inputEnvironmentIdentity();
        ASSERT_FALSE(added.empty());
        EXPECT_NE(added, absent);
        EXPECT_EQ(codeskeptic::inputEnvironmentIdentity(), added);
        ASSERT_EQ(first.set("changed=value with spaces"), 0);
        const auto changed = codeskeptic::inputEnvironmentIdentity();
        ASSERT_FALSE(changed.empty());
        EXPECT_NE(changed, added);
        EXPECT_NE(changed, absent);
        ASSERT_EQ(second.set("another=value"), 0);
        const auto both = codeskeptic::inputEnvironmentIdentity();
        ASSERT_FALSE(both.empty());
        EXPECT_NE(both, changed);
        ASSERT_EQ(first.set(nullptr), 0);
        EXPECT_NE(codeskeptic::inputEnvironmentIdentity(), both);
        ASSERT_EQ(second.set(nullptr), 0);
        EXPECT_EQ(codeskeptic::inputEnvironmentIdentity(), absent);
        // The same complete environment has one identity regardless of the
        // order in which the two fixture variables entered the CRT table.
        ASSERT_EQ(second.set("another=value"), 0);
        ASSERT_EQ(first.set("changed=value with spaces"), 0);
        EXPECT_EQ(codeskeptic::inputEnvironmentIdentity(), both);
    }
    EXPECT_EQ(codeskeptic::inputEnvironmentIdentity(), original);
}

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

class SourceInputCacheTest : public SourceManagerTargetTest {
protected:
    void SetUp() override {
        SourceManagerTargetTest::SetUp();
        SourceManager::clearWarmCache();
        llvm::json::Array args{"clang++", "-std=c++17", "-c", "kept.cpp"};
        llvm::json::Array commands;
        commands.push_back(llvm::json::Object{{"directory", root.string()},
            {"file", "kept.cpp"}, {"arguments", std::move(args)}});
        std::string text;
        llvm::raw_string_ostream out(text);
        out << llvm::json::Value(std::move(commands));
        write(root / "compile_commands.json", text);
    }
    void TearDown() override {
        SourceManager::clearWarmCache();
        SourceManagerTargetTest::TearDown();
    }
    static void write(const fs::path& path, const std::string& text) {
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(stream);
        stream.write(text.data(), static_cast<std::streamsize>(text.size()));
        ASSERT_TRUE(stream);
    }
    codeskeptic::AnalysisResult scan(bool warm, bool null_rule = false) {
        std::vector<std::string> args{"codeskeptic", (root / "kept.cpp").string(),
                                      "--build-path", root.string()};
        std::vector<char*> argv;
        for (auto& arg : args) argv.push_back(arg.data());
        codeskeptic::Config config;
        EXPECT_TRUE(config.parseArgs(static_cast<int>(argv.size()), argv.data()));
        config.setWarmCache(warm);
        codeskeptic::StaticAnalyzer analyzer(config);
        if (null_rule) analyzer.addRule<codeskeptic::NullDerefRule>();
        else analyzer.addRule<codeskeptic::DivByZeroRule>();
        auto result = analyzer.run();
        EXPECT_TRUE(result.complete());
        EXPECT_EQ(result.failed_tus, 0u);
        return result;
    }
};

TEST_F(SourceInputCacheTest, ActualInputWitnessAllowsUnchangedHeaderBearingReuse) {
    write(root / "leaf.h", "#define VALUE 1\n");
    write(root / "kept.cpp", "#include \"leaf.h\"\nint kept(){return VALUE;}\n");
    std::string database_error;
    auto database = clang::tooling::CompilationDatabase::loadFromDirectory(root.string(), database_error);
    ASSERT_TRUE(database) << database_error;
    auto commands = database->getCompileCommands((root / "kept.cpp").string());
    ASSERT_EQ(commands.size(), 1u);
    ASSERT_TRUE(codeskeptic::cacheableCommand(commands.front().CommandLine))
        << ::testing::PrintToString(commands.front().CommandLine);
    SourceManager manager(root.string());
    manager.enableWarmCache(true);
    manager.recordInputs(codeskeptic::inputDigest("test-request"));
    ASSERT_TRUE(manager.addSourceFile((root / "kept.cpp").string()));
    ASSERT_EQ(manager.processAll([](clang::ASTContext&) {}), 0);
    const auto& identity = manager.inputIdentity();
    ASSERT_TRUE(identity.reusable) << identity.reason;
    ASSERT_TRUE(identity.hasBuffer((root / "kept.cpp").string()));
    ASSERT_TRUE(identity.hasBuffer((root / "leaf.h").string()));
    for (const auto& observation : identity.observations) {
        auto single = identity;
        single.observations = {observation};
        EXPECT_TRUE(single.matchesCurrent()) << static_cast<unsigned>(observation.kind) << ":" << observation.path;
    }
    ASSERT_TRUE(identity.matchesCurrent()) << identity.reason;
    ASSERT_EQ(manager.processAll([](clang::ASTContext&) {}), 0);
    EXPECT_EQ(SourceManager::warmCacheHits(), 1u);
}

TEST_F(SourceInputCacheTest, RelativeCompilationSidecarsUseCompilerDirectoryAndKeepWarmParity) {
    write(root / "kept.cpp", "int f(int *p); int kept(){return f(nullptr);}\n");
    write(root / "kept.cpp.csk", "f: requires p != null\n");
    const auto caller = root / "caller";
    ASSERT_TRUE(fs::create_directory(caller));
    write(caller / "kept.cpp.csk", "unrelated: requires q != null\n");
    struct RestoreDirectory {
        fs::path path = fs::current_path();
        ~RestoreDirectory() { fs::current_path(path); }
    } restore;
    fs::current_path(caller);
    ASSERT_EQ(scan(false, true).findings, 1u);
    EXPECT_EQ(scan(true, true).findings, 1u);
    EXPECT_EQ(scan(true, true).findings, 1u);
    EXPECT_EQ(SourceManager::warmCacheHits(), 1u);
    EXPECT_EQ(fs::current_path(), caller);
}

TEST_F(SourceInputCacheTest, RelativeHeaderSidecarCreationChangeAndRemovalInvalidateReuse) {
    write(root / "kept.cpp", "#include \"api.h\"\nint kept(){return f(nullptr);}\n");
    write(root / "api.h", "int f(int *p);\n");
    ASSERT_EQ(scan(true, true).findings, 0u);
    ASSERT_EQ(scan(true, true).findings, 0u);
    ASSERT_EQ(SourceManager::warmCacheHits(), 1u);
    write(root / "api.h.csk", "f: requires p != null\n");
    EXPECT_EQ(scan(true, true).findings, 1u);
    EXPECT_EQ(scan(false, true).findings, 1u);
    EXPECT_EQ(SourceManager::warmCacheHits(), 1u);
    const auto stamp = fs::last_write_time(root / "api.h.csk");
    write(root / "api.h.csk", "g: requires p != null\n");
    fs::last_write_time(root / "api.h.csk", stamp);
    EXPECT_EQ(scan(true, true).findings, 0u);
    EXPECT_EQ(SourceManager::warmCacheHits(), 1u);
    ASSERT_TRUE(fs::remove(root / "api.h.csk"));
    EXPECT_EQ(scan(true, true).findings, 0u);
    EXPECT_EQ(SourceManager::warmCacheMisses(), 4u);
}

TEST_F(SourceInputCacheTest, HeaderSymlinkKeepsAliasSpecificSidecarMeaning) {
    write(root / "real.h", "int f(int *p);\n");
    std::error_code error;
    fs::create_symlink(root / "real.h", root / "alias.h", error);
    if (error) GTEST_SKIP() << "host cannot create the symlink fixture";
    write(root / "kept.cpp", "#include \"alias.h\"\nint kept(){return f(nullptr);}\n");
    write(root / "alias.h.csk", "f: requires p != null\n");
    write(root / "real.h.csk", "unrelated: requires q != null\n");
    ASSERT_EQ(scan(false, true).findings, 1u);
    EXPECT_EQ(scan(true, true).findings, 1u);
    EXPECT_EQ(scan(true, true).findings, 1u);
    EXPECT_EQ(SourceManager::warmCacheHits(), 1u);
}

TEST_F(SourceInputCacheTest, CallbackFailureRestoresNativeAndRetainedVirtualDirectories) {
    const auto original = fs::current_path();
    struct RestoreDirectory {
        fs::path path;
        ~RestoreDirectory() { fs::current_path(path); }
    } restore{original}; // fixture cleanup even if restoration assertions fail
    for (bool warm : {false, true}) {
        SourceManager manager(root.string());
        manager.enableWarmCache(warm);
        ASSERT_TRUE(manager.addSourceFile((root / "kept.cpp").string()));
        ASSERT_EQ(manager.processAll([](clang::ASTContext&) {}), 0);
        EXPECT_THROW(manager.processAll([&](clang::ASTContext& context) {
            EXPECT_EQ(fs::current_path(), root);
            auto directory = context.getSourceManager().getFileManager().getVirtualFileSystem().getCurrentWorkingDirectory();
            ASSERT_TRUE(directory);
            EXPECT_EQ(fs::path(*directory), root);
            throw std::runtime_error("callback fixture");
        }), std::runtime_error);
        EXPECT_EQ(fs::current_path(), original);
        EXPECT_EQ(manager.processAll([&](clang::ASTContext&) { EXPECT_EQ(fs::current_path(), root); }), 0);
        EXPECT_EQ(fs::current_path(), original);
    }
}

TEST_F(SourceInputCacheTest, SameSizeAndRestoredMtimeSourceEditInvalidatesWarmAst) {
    write(root / "kept.cpp", "int kept(){return 12 / 0;}\n");
    ASSERT_EQ(scan(true).findings, 1u);
    const auto stamp = fs::last_write_time(root / "kept.cpp");
    const auto bytes = fs::file_size(root / "kept.cpp");
    write(root / "kept.cpp", "int kept(){return 12 / 1;}\n");
    fs::last_write_time(root / "kept.cpp", stamp);
    ASSERT_EQ(fs::file_size(root / "kept.cpp"), bytes);
    ASSERT_EQ(scan(false).findings, 0u);
    EXPECT_EQ(scan(true).findings, 0u);
    EXPECT_EQ(SourceManager::warmCacheMisses(), 2u);
}

TEST_F(SourceInputCacheTest, SameSizeAndRestoredMtimeTransitiveHeaderEditInvalidatesWarmAst) {
    write(root / "kept.cpp", "#include \"outer.h\"\nint kept(){return 12 / VALUE;}\n");
    write(root / "outer.h", "#include \"leaf.h\"\n");
    write(root / "leaf.h", "#define VALUE 0\n");
    ASSERT_EQ(scan(true).findings, 1u);
    ASSERT_EQ(scan(true).findings, 1u);
    ASSERT_EQ(SourceManager::warmCacheHits(), 1u); // a genuine header-bearing hit
    const auto stamp = fs::last_write_time(root / "leaf.h");
    const auto bytes = fs::file_size(root / "leaf.h");
    write(root / "leaf.h", "#define VALUE 1\n");
    fs::last_write_time(root / "leaf.h", stamp);
    ASSERT_EQ(fs::file_size(root / "leaf.h"), bytes);
    ASSERT_EQ(scan(false).findings, 0u);
    EXPECT_EQ(scan(true).findings, 0u);
    EXPECT_EQ(SourceManager::warmCacheMisses(), 2u);
}

TEST_F(SourceInputCacheTest, ExistenceOnlyHeaderAppearanceInvalidatesWarmAst) {
    write(root / "kept.cpp", "#if __has_include(\"optional.h\")\n#define VALUE 1\n"
          "#else\n#define VALUE 0\n#endif\nint kept(){return 12 / VALUE;}\n");
    ASSERT_EQ(scan(true).findings, 1u);
    write(root / "optional.h", "// queried but never included\n");
    ASSERT_EQ(scan(false).findings, 0u);
    EXPECT_EQ(scan(true).findings, 0u);
    EXPECT_EQ(SourceManager::warmCacheMisses(), 2u);
}

TEST_F(SourceInputCacheTest, WarmBackendPreservesOriginalAssertPreprocessingSemantics) {
    write(root / "kept.cpp", "typedef __SIZE_TYPE__ size_t; extern void* malloc(size_t);\n"
          "#define DEBUGASSERT(x)\nint kept(){int* p=(int*)malloc(4); DEBUGASSERT(p); return *p;}\n");
    ASSERT_EQ(scan(false, true).findings, 0u);
    EXPECT_EQ(scan(true, true).findings, 0u);
    // A different parse clears the process-global vanished-assert list.
    write(root / "other.cpp", "int other(){return 1;}\n");
    SourceManager other(root.string(), nullptr, true);
    ASSERT_TRUE(other.addSourceFile((root / "other.cpp").string()));
    ASSERT_EQ(other.processAll([](clang::ASTContext&) {}), 0);
    EXPECT_EQ(scan(true, true).findings, 0u);
}

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
