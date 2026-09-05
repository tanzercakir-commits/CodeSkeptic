#include "config/Config.h"
#include "analyzer/StaticAnalyzer.h"
#include "rules/DivByZeroRule.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/FdResourceRule.h"

#include <gtest/gtest.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/Support/JSON.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <vector>
#include <algorithm>

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

std::string snapshot(const Config& c) {
    auto strings = [](const auto& source) {
        llvm::json::Array values;
        for (const auto& value : source) values.push_back(value);
        return values;
    };
    llvm::json::Array lines;
    for (auto range : c.lines()) lines.push_back(llvm::json::Array{range.first, range.second});
    llvm::json::Object pairs;
    for (const auto& entry : c.allocatorPairs()) pairs[entry.first] = strings(entry.second);
    llvm::json::Object state{
        {"source", c.sourcePath()}, {"files", strings(c.sourceFiles())},
        {"build", c.buildPath()}, {"explicit_build", c.buildPathSpecified()},
        {"explicit_files", c.fileListSpecified()}, {"doctor", c.doctor()},
        {"format", c.outputFormat()}, {"json", c.jsonOutputPath()},
        {"sarif", c.sarifOutputPath()}, {"html", c.htmlOutputPath()},
        {"baseline", c.baselinePath()}, {"write_baseline", c.writeBaselinePath()},
        {"lang", c.lang()}, {"severity", static_cast<int>(c.minSeverity())},
        {"functions", strings(c.functions())}, {"lines", std::move(lines)},
        {"fatal", strings(c.fatalAsserts())}, {"asserts", strings(c.assertMacros())},
        {"negative_asserts", strings(c.negativeAssertMacros())},
        {"alloc", strings(c.allocFunctions())}, {"free", strings(c.freeFunctions())},
        {"pairs", std::move(pairs)}, {"owners", strings(c.owningPointers())},
        {"untrusted", strings(c.untrustedIntSources())}, {"paths", strings(c.reportPaths())},
        {"policies", strings(c.policies())}, {"models", strings(c.modelFiles())},
        {"summary_in", c.summaryIn()}, {"summary_out", c.summaryOut()},
        {"diff_old", c.summaryDiffOld()}, {"diff_new", c.summaryDiffNew()},
        {"gate", c.summaryDiffGate()}, {"serve", c.serve()},
        {"whole", c.wholeProgram()}, {"broken", c.analyzeBrokenTUs()},
        {"partial", c.acceptPartialCoverage()}, {"assumptions", c.assumptions()},
        {"recovery", c.assertRecovery()}, {"cache", c.warmCache()},
        {"help", c.helpRequested()}, {"off_rule", c.isRuleEnabled("off-rule")},
        {"on_rule", c.isRuleEnabled("on-rule")}};
    return llvm::formatv("{0}", llvm::json::Value(std::move(state))).str();
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

TEST(ConfigTest, FailedCliUpdatePreservesCompleteObservableState) {
    Config c;
    ASSERT_TRUE(parse(c, {"codeskeptic", "--source", "kept.cpp", "--build-path", "kept-build",
                         "--function", "kept", "--lines", "5-9", "--lang", "tr",
                         "--disable-rule", "off-rule", "--json", "kept.json"}));
    c.setWarmCache(true);
    const auto before = snapshot(c);
    EXPECT_FALSE(parse(c, {"codeskeptic", "--source", "new.cpp", "--build-path", "new-build",
                          "--function", "new_function", "--json", "new.json", "--lang", "de"}));
    EXPECT_EQ(snapshot(c), before);
    EXPECT_FALSE(parse(c, {"codeskeptic", "--doctor", "--serve", "--whole-program",
                          "--no-assert-recovery", "--gate", "warn", "--model-file", "new.model",
                          "--accept-partial-coverage", "--lines", "10,4294967296"}));
    EXPECT_EQ(snapshot(c), before);
    EXPECT_FALSE(parse(c, {"codeskeptic", "--source", "new.cpp", "second.cpp"}));
    EXPECT_EQ(snapshot(c), before);
    ASSERT_TRUE(parse(c, {"codeskeptic", "--lang", "en"}));
    EXPECT_EQ(c.sourcePath(), "kept.cpp");
    EXPECT_EQ(c.lang(), "en");
}

TEST(ConfigTest, FailedConfigLoadPreservesStateAcrossAllLines) {
    Config c;
    ASSERT_TRUE(parse(c, {"codeskeptic", "--source", "kept.cpp", "--function", "kept"}));
    const auto before = snapshot(c);
    const auto path = writeConfig("transactional_config_bad.conf",
        "source_path=new.cpp\nbuild_path=new-build\nlang=tr\nfunction=new\n"
        "alloc_functions=new_alloc\nmodel_file=new.model\n"
        "min_severity=invalid\nfree_functions=new_free\n");
    EXPECT_FALSE(c.loadFromFile(path));
    EXPECT_EQ(snapshot(c), before);
}

TEST(ConfigTest, LineListFailureNeverPublishesValidPrefix) {
    Config c;
    ASSERT_TRUE(c.addLines("2-4"));
    const auto before = snapshot(c);
    for (const char* invalid : {"10,bad", "10,4294967296", "10,18446744073709551616",
                                "10,", "10,0", "10,9-2", "1 0", "1\t0", ",,", "+2"}) {
        SCOPED_TRACE(invalid);
        EXPECT_FALSE(c.addLines(invalid));
        EXPECT_EQ(snapshot(c), before);
    }
}

TEST(ConfigTest, InvalidNameListsDoNotBroadenScopeOrPartiallyApply) {
    for (const char* option : {"--function", "--fatal-asserts", "--assert-macros",
                              "--negative-assert-macros", "--alloc-functions", "--free-functions",
                              "--owning-pointers", "--untrusted-int-sources", "--policy"}) {
        for (const char* invalid : {",, ", "\t", "valid,,other", "valid,"}) {
            SCOPED_TRACE(std::string(option) + ":" + invalid);
            Config c;
            ASSERT_TRUE(parse(c, {"codeskeptic", "--function", "kept", "kept.cpp"}));
            const auto before = snapshot(c);
            EXPECT_FALSE(parse(c, {"codeskeptic", option, invalid}));
            EXPECT_EQ(snapshot(c), before);
        }
    }
}

TEST(ConfigTest, ConflictingOutputSelectorsDoNotSilentlyDiscardRequestedOutput) {
    Config c;
    const auto before = snapshot(c);
    EXPECT_FALSE(parse(c, {"codeskeptic", "--json", "one.json", "--sarif", "two.sarif", "x.cpp"}));
    EXPECT_EQ(snapshot(c), before);
}

TEST(ConfigTest, ProgrammaticListsAreAtomicAndReturnStructuredReasons) {
    using Setter = bool (Config::*)(const std::string&, codeskeptic::InputError*);
    const std::vector<Setter> setters{
        &Config::addFunctions, &Config::addFatalAsserts, &Config::addAssertMacros,
        &Config::addNegativeAssertMacros, &Config::addAllocFunctions,
        &Config::addFreeFunctions, &Config::addOwningPointers};
    for (auto setter : setters) {
        Config c;
        codeskeptic::InputError error;
        ASSERT_TRUE((c.*setter)("kept", &error));
        const auto before = snapshot(c);
        for (const auto& bad : {std::string("valid,,bad"), std::string("\t"),
                               std::string("good,bad\0suffix", 15)}) {
            EXPECT_FALSE((c.*setter)(bad, &error));
            EXPECT_EQ(error.reason, "invalid_list");
            EXPECT_FALSE(error.field.empty());
            EXPECT_EQ(snapshot(c), before);
        }
        EXPECT_TRUE((c.*setter)("ns::valid", &error));
        EXPECT_TRUE(error.reason.empty());
    }
    Config c;
    codeskeptic::InputError error;
    ASSERT_TRUE(c.addReportPaths(" kept path , other ", &error));
    const auto before = snapshot(c);
    for (const char* bad : {",,,", " \t\r\n"}) {
        EXPECT_FALSE(c.addReportPaths(bad, &error));
        EXPECT_EQ(error.field, "report_paths");
        EXPECT_EQ(snapshot(c), before);
    }
}

TEST(ConfigTest, ConfigConflictAndNulNeverPublishEarlierLines) {
    Config c;
    ASSERT_TRUE(c.addFunctions("kept"));
    const auto before = snapshot(c);
    codeskeptic::InputError error;
    auto path = writeConfig("config_output_conflict.conf",
        "function=new\njson_output=one.json\nsarif_output=two.sarif\n");
    EXPECT_FALSE(c.loadFromFile(path, &error));
    EXPECT_EQ(error.reason, "conflict");
    EXPECT_EQ(snapshot(c), before);
    path = writeConfig("config_nul.conf", "function=new\n");
    { std::ofstream file(path, std::ios::app | std::ios::binary);
      file << "source_path=prefix" << '\0' << "suffix\n"; }
    EXPECT_FALSE(c.loadFromFile(path, &error));
    EXPECT_EQ(error.reason, "invalid_value");
    EXPECT_EQ(snapshot(c), before);
}

TEST(ConfigTest, FileListReadFailureIsAtomicAndCrLfPathsStayExact) {
    Config c;
    ASSERT_TRUE(parse(c, {"codeskeptic", "--function", "kept"}));
    const auto before = snapshot(c);
    const auto path = writeConfig("config_files_nul.txt", "valid.cpp\n");
    { std::ofstream file(path, std::ios::app | std::ios::binary);
      file << "bad" << '\0' << ".cpp\n"; }
    EXPECT_FALSE(parse(c, {"codeskeptic", "--files", path.c_str()}));
    EXPECT_EQ(snapshot(c), before);
    { std::ofstream file(path, std::ios::binary);
      file << "first.cpp\r\nMy Project/second.cpp\r\n"; }
    ASSERT_TRUE(parse(c, {"codeskeptic", "--files", path.c_str()}));
    EXPECT_EQ(c.sourceFiles(), std::vector<std::string>({"first.cpp", "My Project/second.cpp"}));
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

TEST(ConfigTest, DiagnosticSelectionPreservesSiblingProducerFamilies) {
    const auto source = writeConfig("config_diagnostic_selection.cpp", R"(
        struct FILE; struct DIR;
        FILE* fopen(const char*, const char*); int fclose(FILE*);
        DIR* opendir(const char*); int closedir(DIR*);
        int open(const char*, int, ...); int close(int);
        void* malloc(unsigned long); void free(void*);
        int file_leak(const char* p) { FILE* f=fopen(p,"r"); if(!f) return 1; return 0; }
        int dir_leak(const char* p) { DIR* d=opendir(p); if(!d) return 1; return 0; }
        void fd_leak(const char* p) { int fd=open(p,0); (void)fd; }
        void heap_leak() { void* p=malloc(8); (void)p; }
        int file_safe(const char* p) { FILE* f=fopen(p,"r"); if(!f) return 1; fclose(f); return 0; }
    )");
    auto analyze = [&](Config config, unsigned resources, unsigned memory) {
        config.setSourcePath(source);
        codeskeptic::StaticAnalyzer analyzer(std::move(config));
        analyzer.addRule<codeskeptic::MemoryLeakRule_Ex>();
        analyzer.addRule<codeskeptic::FdResourceRule>();
        const auto result = analyzer.run();
        EXPECT_TRUE(result.complete());
        EXPECT_EQ(result.attempted_tus, 1u);
        EXPECT_EQ(result.analyzed_tus, 1u);
        EXPECT_EQ(result.findings, resources + memory);
        auto count = [&](const char* id) {
            return std::count_if(analyzer.diagnostics().begin(), analyzer.diagnostics().end(),
                                [&](const auto& d) { return d.rule_id == id; });
        };
        EXPECT_EQ(count("resource-leak"), resources);
        EXPECT_EQ(count("memory-leak"), memory);
        for (const auto& d : analyzer.diagnostics()) EXPECT_NE(d.function, "file_safe");
    };
    analyze(Config{}, 3, 1);
    Config noResource;
    ASSERT_TRUE(parse(noResource, {"codeskeptic", "--disable-rule", "resource-leak"}));
    analyze(noResource, 0, 1);
    Config noMemory;
    ASSERT_TRUE(parse(noMemory, {"codeskeptic", "--disable-rule", "memory-leak"}));
    analyze(noMemory, 3, 0);
    Config resourcesOnly;
    ASSERT_TRUE(resourcesOnly.loadFromFile(writeConfig("config_resource_only.conf",
                                                       "enable_rule=resource-leak\n")));
    analyze(resourcesOnly, 3, 0);
    analyze(Config{}, 3, 1);
    analyze(noResource, 0, 1);
}

TEST(ConfigTest, DisablingMemoryLeakDoesNotDisableUseAfterFree) {
    const auto source = writeConfig("config_sibling_uaf.cpp",
        "void f(){int* p=new int(1); delete p; int x=*p; (void)x;}\n");
    Config c;
    ASSERT_TRUE(parse(c, {"codeskeptic", "--disable-rule", "memory-leak"}));
    c.setSourcePath(source);
    codeskeptic::StaticAnalyzer analyzer(std::move(c));
    analyzer.addRule<codeskeptic::MemoryLeakRule_Ex>();
    const auto result = analyzer.run();
    EXPECT_FALSE(result.no_rules);
    EXPECT_EQ(result.exitCode(), 1);
    ASSERT_EQ(analyzer.diagnostics().size(), 1u);
    EXPECT_EQ(analyzer.diagnostics()[0].rule_id, "use-after-free");
}
