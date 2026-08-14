#include "config/Config.h"

#include <gtest/gtest.h>

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

TEST(ConfigTest, RejectsEmptyFunctionScopeWithoutExpandingAnalysis) {
    Config empty;
    EXPECT_FALSE(parse(empty,
                       {"codeskeptic", "--function", "", "x.cpp"}));
    EXPECT_TRUE(empty.functions().empty());

    Config delimiters;
    EXPECT_FALSE(parse(delimiters,
                       {"codeskeptic", "--function", ",, ,", "x.cpp"}));
    EXPECT_TRUE(delimiters.functions().empty());

    Config file;
    const auto path = writeConfig("codeskeptic_empty_function.conf",
                                  "function = , ,\n");
    EXPECT_FALSE(file.loadFromFile(path));
    EXPECT_TRUE(file.functions().empty());
}

TEST(ConfigTest, FunctionAndLineScopesAreAtomicAndRepeatable) {
    Config functions;
    ASSERT_TRUE(parse(functions,
                      {"codeskeptic", "--function", "Parser::parse",
                       "--function", "emit, Worker::run", "x.cpp"}));
    EXPECT_EQ(functions.functions(),
              std::set<std::string>({"Parser::parse", "Worker::run",
                                     "emit"}));
    const auto acceptedFunctions = functions.functions();
    EXPECT_FALSE(functions.addFunctions(", ,"));
    EXPECT_EQ(functions.functions(), acceptedFunctions);

    Config lines;
    ASSERT_TRUE(lines.addLines("7"));
    EXPECT_FALSE(lines.addLines("10-20,bad"));
    EXPECT_EQ(lines.lines(),
              (std::vector<std::pair<unsigned, unsigned>>{{7, 7}}));
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

TEST(ConfigTest, InvalidConfigTextPreservesEntirePriorState) {
    Config config;
    config.setSourcePath("before.cpp");
    ASSERT_TRUE(config.addFunctions("before"));
    ASSERT_TRUE(config.addLines("7"));
    const Config before = config;

    EXPECT_FALSE(config.loadFromText(
        "source_path = after.cpp\n"
        "function = after\n"
        "unknown_key = rejected\n",
        "atomic-test"));

    EXPECT_EQ(config, before);

    std::string embeddedNul = "source_path = accepted.cpp";
    embeddedNul.push_back('\0');
    embeddedNul += "ignored.cpp\n";
    EXPECT_FALSE(config.loadFromText(embeddedNul, "nul-test"));
    EXPECT_EQ(config, before);
}

TEST(ConfigTest, MissingConfigIsOptionalButNonRegularEntriesFailClosed) {
    const auto root = std::filesystem::path(::testing::TempDir()) /
                      "codeskeptic_config_entry_kind";
    std::error_code ec;
    std::filesystem::remove_all(root, ec);
    std::filesystem::create_directories(root);
    const auto configPath = root / ".codeskeptic.conf";

    Config missing;
    EXPECT_TRUE(missing.loadFromFile(configPath.string()));

    std::filesystem::create_directory(configPath);
    Config directory;
    EXPECT_FALSE(directory.loadFromFile(configPath.string()));

    std::filesystem::remove_all(configPath, ec);
#ifndef _WIN32
    std::filesystem::create_symlink(root / "missing-target", configPath, ec);
    ASSERT_FALSE(ec) << ec.message();
    Config dangling;
    EXPECT_FALSE(dangling.loadFromFile(configPath.string()));
#endif
    std::filesystem::remove_all(root, ec);
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
