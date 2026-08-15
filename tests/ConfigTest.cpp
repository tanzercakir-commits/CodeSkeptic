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

bool parse(Config& config, const std::vector<std::string>& args) {
    std::vector<char*> argv;
    argv.reserve(args.size());
    for (const auto& arg : args)
        argv.push_back(const_cast<char*>(arg.c_str()));
    return config.parseArgs(static_cast<int>(argv.size()), argv.data());
}

std::vector<std::string> withProgram(
    const std::string& program, const std::vector<std::string>& args) {
    std::vector<std::string> result{program};
    result.insert(result.end(), args.begin(), args.end());
    return result;
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

TEST(ConfigTest, PerTuBudgetsHaveExplicitSafeDefaults) {
    Config config;
    EXPECT_EQ(config.tuTimeoutSeconds(), 300u);
    EXPECT_EQ(config.tuMemoryMiB(), 4096u);
}

TEST(ConfigTest, PerTuBudgetsLayerFromConfigThenCli) {
    const auto path = writeConfig(
        "codeskeptic_resource_budgets.conf",
        "tu_timeout_seconds = 90\n"
        "tu_memory_mib = 3072\n");
    Config config;
    ASSERT_TRUE(config.loadFromFile(path));
    EXPECT_EQ(config.tuTimeoutSeconds(), 90u);
    EXPECT_EQ(config.tuMemoryMiB(), 3072u);

    ASSERT_TRUE(parse(config,
                      {"codeskeptic", "--tu-timeout-seconds", "45",
                       "--tu-memory-mib", "2048", "x.cpp"}));
    EXPECT_EQ(config.tuTimeoutSeconds(), 45u);
    EXPECT_EQ(config.tuMemoryMiB(), 2048u);
}

TEST(ConfigTest, CheckpointDirectoryLayersFromConfigThenCli) {
    const auto path = writeConfig(
        "codeskeptic_checkpoint.conf",
        "checkpoint_dir = configured-checkpoints\n");
    Config config;
    ASSERT_TRUE(config.loadFromFile(path));
    EXPECT_EQ(config.checkpointDir(), "configured-checkpoints");

    ASSERT_TRUE(parse(config,
                      {"codeskeptic", "--checkpoint-dir", "cli-checkpoints",
                       "x.cpp"}));
    EXPECT_EQ(config.checkpointDir(), "cli-checkpoints");
}

TEST(ConfigTest, CheckpointDirectoryRejectsEmptyValuesAtomically) {
    Config cli;
    const Config cli_before = cli;
    EXPECT_FALSE(parse(cli,
                       {"codeskeptic", "--checkpoint-dir", "", "x.cpp"}));
    EXPECT_EQ(cli, cli_before);

    Config file;
    const Config file_before = file;
    EXPECT_FALSE(file.loadFromText("checkpoint_dir =   \n",
                                   "checkpoint-test"));
    EXPECT_EQ(file, file_before);
}

TEST(ConfigTest, McpRequestConfigKeepsPolicyButClearsParentWork) {
    const auto files = writeConfig(
        "codeskeptic_mcp_parent_files.txt", "parent-a.cpp\nparent-b.cpp\n");
    Config base;
    ASSERT_TRUE(parse(base, {
        "codeskeptic", "--serve", "--whole-program",
        "--build-path", "configured-build", "--json", "parent.json",
        "--sarif", "parent.sarif", "--html", "parent.html",
        "--baseline", "parent.baseline", "--write-baseline",
        "write.baseline", "--function", "parent_only", "--lines",
        "10-20", "--summary-in", "parent.csk", "--summary-out",
        "parent-out.csk", "--summary-diff", "old.csk", "new.csk",
        "--model-file", "model.csk", "--tu-timeout-seconds", "17",
        "--tu-memory-mib", "768", "--checkpoint-dir", "checkpoints",
        "--files", files.c_str()}));
    base.setWorkerProgram("codeskeptic-worker");

    const Config scoped = base.mcpRequestConfig();
    EXPECT_TRUE(scoped.sourcePath().empty());
    EXPECT_TRUE(scoped.sourceFiles().empty());
    EXPECT_EQ(scoped.buildPath(), "configured-build");
    EXPECT_EQ(scoped.outputFormat(), "console");
    EXPECT_TRUE(scoped.jsonOutputPath().empty());
    EXPECT_TRUE(scoped.sarifOutputPath().empty());
    EXPECT_TRUE(scoped.htmlOutputPath().empty());
    EXPECT_TRUE(scoped.baselinePath().empty());
    EXPECT_TRUE(scoped.writeBaselinePath().empty());
    EXPECT_TRUE(scoped.functions().empty());
    EXPECT_TRUE(scoped.lines().empty());
    EXPECT_FALSE(scoped.serve());
    EXPECT_FALSE(scoped.wholeProgram());
    EXPECT_TRUE(scoped.summaryIn().empty());
    EXPECT_TRUE(scoped.summaryOut().empty());
    EXPECT_TRUE(scoped.summaryDiffOld().empty());
    EXPECT_TRUE(scoped.summaryDiffNew().empty());
    ASSERT_EQ(scoped.modelFiles().size(), 1u);
    EXPECT_EQ(scoped.modelFiles()[0], "model.csk");
    EXPECT_EQ(scoped.tuTimeoutSeconds(), 17u);
    EXPECT_EQ(scoped.tuMemoryMiB(), 768u);
    EXPECT_EQ(scoped.checkpointDir(), "checkpoints");
    EXPECT_TRUE(scoped.checkpointPerRunNamespace());
    EXPECT_EQ(scoped.workerProgram(), "codeskeptic-worker");
}

TEST(ConfigTest, PerTuBudgetsRejectZeroNegativeSuffixAndOverflowAtomically) {
    for (const char* option : {"--tu-timeout-seconds", "--tu-memory-mib"}) {
        for (const char* value : {"0", "-1", "1s", "12.5", "4294967296"}) {
            Config config;
            const Config before = config;
            EXPECT_FALSE(parse(config, {"codeskeptic", option, value,
                                        "x.cpp"}))
                << option << "=" << value;
            EXPECT_EQ(config, before) << option << "=" << value;
        }
    }

    for (const char* text : {
             "tu_timeout_seconds = 0\n",
             "tu_timeout_seconds = -1\n",
             "tu_timeout_seconds = 1s\n",
             "tu_memory_mib = 0\n",
             "tu_memory_mib = 12.5\n",
             "tu_memory_mib = 4294967296\n",
         }) {
        Config config;
        const Config before = config;
        EXPECT_FALSE(config.loadFromText(text, "budget-test")) << text;
        EXPECT_EQ(config, before) << text;
    }
}

TEST(ConfigTest, WorkerArgumentsPreserveAnalysisSettingsButNotParentControls) {
    Config config;
    ASSERT_FALSE(config.loadFromText(
        "lang = tr\n"
        "min_severity = warning\n"
        "function = alpha,beta\n"
        "fatal_asserts = die\n"
        "allocator_pairs = take=drop\n"
        "report_paths = /project/src\n"
        "policy = hardened\n"
        "enable_rule = null-deref\n"
        "summary_in = ignored-by-existing-parser\n",
        "worker.conf", false));

    // The failed atomic load above must not mutate the candidate. Apply a
    // valid layered configuration and parent-only controls separately.
    ASSERT_TRUE(config.loadFromText(
        "lang = tr\n"
        "min_severity = warning\n"
        "function = alpha,beta\n"
        "fatal_asserts = die\n"
        "allocator_pairs = take=drop\n"
        "report_paths = /project/src\n"
        "policy = hardened\n"
        "enable_rule = null-deref\n"));
    ASSERT_TRUE(parse(config, {
        "codeskeptic", "--whole-program", "--tu-timeout-seconds", "7",
        "--tu-memory-mib", "96", "--summary-in", "project.csk",
        "--model-file", "lib.csk", "--write-baseline", "baseline.txt",
        "source.cpp"}));

    const auto args = config.workerArguments({"null-deref", "bounds"});
    Config worker;
    ASSERT_TRUE(parse(worker, withProgram("codeskeptic-worker", args)));

    EXPECT_EQ(worker.lang(), "tr");
    EXPECT_EQ(worker.minSeverity(), codeskeptic::Severity::Warning);
    EXPECT_EQ(worker.functions(), config.functions());
    EXPECT_EQ(worker.fatalAsserts(), config.fatalAsserts());
    EXPECT_EQ(worker.allocatorPairs(), config.allocatorPairs());
    EXPECT_EQ(worker.reportPaths(), config.reportPaths());
    EXPECT_FALSE(worker.isRuleEnabled("bounds"));
    EXPECT_EQ(worker.summaryIn(), "project.csk");
    ASSERT_EQ(worker.modelFiles().size(), 1u);
    EXPECT_EQ(worker.modelFiles()[0], "lib.csk");

    EXPECT_FALSE(worker.wholeProgram());
    EXPECT_EQ(worker.tuTimeoutSeconds(), Config::kDefaultTuTimeoutSeconds);
    EXPECT_EQ(worker.tuMemoryMiB(), Config::kDefaultTuMemoryMiB);
    EXPECT_TRUE(worker.writeBaselinePath().empty());
    EXPECT_TRUE(worker.sourcePath().empty());

    const auto merged = config.workerArguments(
        {"null-deref", "bounds"}, "merged.csk", true);
    Config merged_worker;
    ASSERT_TRUE(parse(
        merged_worker, withProgram("codeskeptic-worker", merged)));
    EXPECT_EQ(merged_worker.summaryIn(), "merged.csk");
    EXPECT_TRUE(merged_worker.modelFiles().empty());
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
