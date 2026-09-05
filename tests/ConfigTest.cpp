#include "config/Config.h"
#include "analyzer/StaticAnalyzer.h"
#include "rules/DivByZeroRule.h"

#include <gtest/gtest.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <vector>

using codeskeptic::Config;

namespace {

bool parse(Config& config, std::initializer_list<const char*> args) {
    std::vector<char*> argv;
    for (const char* arg : args)
        argv.push_back(const_cast<char*>(arg));
    return config.parseArgs(static_cast<int>(argv.size()), argv.data());
}

std::string writeConfig(const char* name, const char* content) {
    const auto path = std::filesystem::path(::testing::TempDir()) / name;
    std::ofstream file(path);
    file << content;
    return path.string();
}

} // anonymous namespace

TEST(ConfigTest, RejectsUnknownOptionAndMissingValue) {
    Config unknown;
    EXPECT_FALSE(parse(unknown, {"codeskeptic", "--severtiy", "error"}));

    Config missing;
    EXPECT_FALSE(parse(missing, {"codeskeptic", "--json", "--serve"}));
}

TEST(ConfigTest, RejectsInvalidEnumAndLineScope) {
    Config severity;
    EXPECT_FALSE(parse(severity,
                       {"codeskeptic", "--severity", "critical", "x.cpp"}));

    Config lang;
    EXPECT_FALSE(parse(lang, {"codeskeptic", "--lang", "de", "x.cpp"}));

    Config lines;
    EXPECT_FALSE(parse(lines, {"codeskeptic", "--lines", "10-x", "x.cpp"}));
}

TEST(ConfigTest, ConfigTrimsWhitespaceAndRejectsUnknownKeys) {
    Config valid;
    const auto validPath = writeConfig(
        "codeskeptic_valid.conf",
        "  # comment\nalloc_functions = my_alloc, other_alloc\n"
        "min_severity = warning\nlang = tr\n");
    ASSERT_TRUE(valid.loadFromFile(validPath));
    EXPECT_EQ(valid.allocFunctions().count("my_alloc"), 1u);
    EXPECT_EQ(valid.lang(), "tr");

    Config invalid;
    const auto invalidPath = writeConfig(
        "codeskeptic_invalid.conf", "min_severtiy=error\n");
    EXPECT_FALSE(invalid.loadFromFile(invalidPath));
}

TEST(ConfigTest, AllocatorPairsParseAtomicallyFromCliAndConfig) {
    Config cli;
    ASSERT_TRUE(parse(cli,
                      {"codeskeptic", "--allocator-pairs",
                       "pool_alloc=pool_free,pool_alloc=pool_release",
                       "x.cpp"}));
    ASSERT_EQ(cli.allocatorPairs().count("pool_alloc"), 1u);
    EXPECT_EQ(cli.allocatorPairs().at("pool_alloc").count("pool_free"), 1u);
    EXPECT_EQ(cli.allocatorPairs().at("pool_alloc").count("pool_release"),
              1u);

    Config file;
    const auto path = writeConfig(
        "codeskeptic_allocator_pairs.conf",
        "allocator_pairs = ns::make=ns::drop,ns::make=ns::release\n");
    ASSERT_TRUE(file.loadFromFile(path));
    ASSERT_EQ(file.allocatorPairs().count("ns::make"), 1u);
    EXPECT_EQ(file.allocatorPairs().at("ns::make").size(), 2u);
}

TEST(ConfigTest, AllocatorPairsRejectMalformedValueWithoutPartialState) {
    Config cli;
    EXPECT_FALSE(parse(cli,
                       {"codeskeptic", "--allocator-pairs",
                        "pool_alloc=pool_free,missing_separator", "x.cpp"}));
    EXPECT_TRUE(cli.allocatorPairs().empty());

    Config file;
    const auto path = writeConfig(
        "codeskeptic_bad_allocator_pairs.conf",
        "allocator_pairs = good_alloc=good_free,bad=entry=again\n");
    EXPECT_FALSE(file.loadFromFile(path));
    EXPECT_TRUE(file.allocatorPairs().empty());
}

TEST(ConfigTest, ConfigAndCliLayersCanCompleteOutputSelection) {
    Config config;
    const auto path = writeConfig("codeskeptic_layered.conf",
                                  "output_format = json\n");
    ASSERT_TRUE(config.loadFromFile(path));
    EXPECT_TRUE(parse(config,
                      {"codeskeptic", "--json", "findings.json", "x.cpp"}));
    EXPECT_EQ(config.jsonOutputPath(), "findings.json");
}

TEST(ConfigTest, HelpIsSuccessfulControlFlow) {
    Config config;
    EXPECT_TRUE(parse(config, {"codeskeptic", "--help"}));
    EXPECT_TRUE(config.helpRequested());
}

TEST(ConfigTest, PartialCoverageAcceptanceIsExplicit) {
    Config config;
    EXPECT_TRUE(parse(config,
                      {"codeskeptic", "--accept-partial-coverage", "x.cpp"}));
    EXPECT_TRUE(config.acceptPartialCoverage());
}

TEST(ConfigTest, ModelFileOptionsAreRepeatableAndLayered) {
    const auto path = writeConfig(
        "codeskeptic_models.conf",
        "model_file = platform.csk\n"
        "model_file = project.csk\n");
    Config layered;
    EXPECT_TRUE(layered.loadFromFile(path));
    EXPECT_TRUE(parse(layered, {"codeskeptic",
                                "--model-file", "vendor-base.csk",
                                "--model-file", "vendor-extra.csk",
                                "input.cpp"}));
    EXPECT_EQ(layered.modelFiles(),
              std::vector<std::string>({"platform.csk", "project.csk",
                                        "vendor-base.csk",
                                        "vendor-extra.csk"}));

    Config empty;
    const auto emptyPath = writeConfig("codeskeptic_empty_model.conf",
                                       "model_file =\n");
    EXPECT_FALSE(empty.loadFromFile(emptyPath));
    EXPECT_TRUE(empty.modelFiles().empty());

    Config missing;
    EXPECT_FALSE(parse(missing, {"codeskeptic", "--model-file"}));
}

TEST(ConfigTest, DiscoveryRetainsExplicitBuildAndFileListProvenance) {
    Config defaults;
    EXPECT_EQ(defaults.buildPath(), ".");
    EXPECT_FALSE(defaults.buildPathSpecified());
    EXPECT_FALSE(defaults.fileListSpecified());
    ASSERT_TRUE(parse(defaults, {"codeskeptic", "--doctor", "--build-path", "."}));
    EXPECT_TRUE(defaults.doctor());
    EXPECT_TRUE(defaults.buildPathSpecified());

    Config configured;
    ASSERT_TRUE(configured.loadFromFile(writeConfig("doctor_build.conf", "build_path=.\n")));
    EXPECT_TRUE(configured.buildPathSpecified());

    Config listed;
    const std::string list = writeConfig("doctor_empty_list.txt", "");
    ASSERT_TRUE(parse(listed, {"codeskeptic", "--doctor", "--files", list.c_str()}));
    EXPECT_TRUE(listed.fileListSpecified());
    EXPECT_TRUE(listed.sourceFiles().empty());
}

TEST(ConfigTest, ChangedCompilationCommandsInvalidateWarmAstCache) {
    namespace fs = std::filesystem;
    const auto root = fs::path(::testing::TempDir()) /
        ("codeskeptic-compdb-cache-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    ASSERT_TRUE(fs::create_directory(root));
    struct FixtureCleanup {
        fs::path root;
        ~FixtureCleanup() {
            codeskeptic::SourceManager::clearWarmCache();
            std::error_code error;
            fs::remove_all(root, error);
        }
    } cleanup{root};
    const auto source = root / "input.cpp";
    { std::ofstream file(source); file << "int divide() { return 12 / VALUE; }\n"; }
    auto writeDatabase = [&](std::initializer_list<int> divisors) {
        llvm::json::Array entries;
        for (int divisor : divisors) {
            entries.push_back(llvm::json::Object{
                {"directory", root.string()}, {"file", source.string()},
                {"arguments", llvm::json::Array{"clang++", "-std=c++17",
                    "-DVALUE=" + std::to_string(divisor), "-c", source.string()}}});
        }
        std::ofstream file(root / "compile_commands.json");
        file << llvm::formatv("{0}", llvm::json::Value(std::move(entries))).str();
    };
    auto analyze = [&]() {
        Config config;
        config.setBuildPath(root.string());
        config.setSourcePath(source.string());
        config.setWarmCache(true);
        codeskeptic::StaticAnalyzer analyzer(std::move(config));
        analyzer.addRule<codeskeptic::DivByZeroRule>();
        return analyzer.run();
    };
    codeskeptic::SourceManager::clearWarmCache();
    writeDatabase({1});
    EXPECT_EQ(analyze().exitCode(), 0);
    EXPECT_EQ(codeskeptic::SourceManager::warmCacheMisses(), 1u);
    writeDatabase({0});  // Source content/mtime are unchanged; only DB flags differ.
    const auto changed = analyze();
    EXPECT_EQ(changed.exitCode(), 1);
    EXPECT_EQ(changed.findings, 1u);
    EXPECT_EQ(codeskeptic::SourceManager::warmCacheMisses(), 2u);
    EXPECT_EQ(analyze().exitCode(), 1);
    EXPECT_GE(codeskeptic::SourceManager::warmCacheHits(), 1u);
    codeskeptic::SourceManager::clearWarmCache();
    writeDatabase({1, 0});  // The second compile configuration must not disappear.
    const auto multiple = analyze();
    EXPECT_EQ(multiple.exitCode(), 1);
    EXPECT_EQ(multiple.findings, 1u);
    EXPECT_EQ(multiple.analyzed_tus, 2u);
}
