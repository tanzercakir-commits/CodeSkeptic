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
