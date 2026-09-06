#include "analyzer/AnalysisCoordinator.h"
#include "analyzer/AnalysisState.h"
#include "analyzer/BuiltinRules.h"
#include "analyzer/StaticAnalyzer.h"
#include "analyzer/UnitEvidenceStore.h"
#include "source_manager/InputIdentity.h"
#include <gtest/gtest.h>
#include <llvm/ADT/SmallString.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/Program.h>
#include "engine/FunctionSummary.h"
#include <array>
#include <optional>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <future>
#include <thread>
#include <chrono>
#include <cstdlib>

namespace {
using namespace codeskeptic;
namespace fs = std::filesystem;

std::string readText(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

struct Scan {
    AnalysisResult result;
    DiagnosticList diagnostics;
    std::string report;
};

class AnalysisCoordinatorTest : public ::testing::Test {
protected:
    fs::path root;
    std::vector<fs::path> sources;
    std::string saved_executable;

    void SetUp() override {
        saved_executable = workerExecutable();
        clearAnalysisState();
        llvm::SmallString<256> directory;
        ASSERT_FALSE(llvm::sys::fs::createUniqueDirectory("codeskeptic-coordinator-test", directory));
        root = fs::path(directory.str().str());
        fs::create_directory(root / "src");
        fs::create_directory(root / "build");
    }
    void TearDown() override {
        setWorkerExecutable(saved_executable);
        clearAnalysisState();
        std::error_code error;
        if (!root.empty()) fs::remove_all(root, error); // Only this test's created fixture.
        EXPECT_FALSE(error);
    }
    fs::path file(const std::string& name, const std::string& text) {
        const auto path = root / "src" / fs::u8path(name);
        std::ofstream output(path, std::ios::binary);
        output << text;
        output.close();
        EXPECT_FALSE(output.fail());
        sources.push_back(path);
        return path;
    }
    void database(bool variants = false, const std::vector<std::string>& flags = {}) {
        llvm::json::Array entries;
        for (const auto& source : sources) {
            const int count = variants ? 2 : 1;
            for (int variant = 0; variant < count; ++variant) {
                llvm::json::Array arguments;
                arguments.push_back(source.extension() == ".c" ? "clang" : "clang++");
                arguments.push_back(source.extension() == ".c" ? "-std=gnu11" : "-std=c++17");
                arguments.push_back("-DVARIANT=" + std::to_string(variant));
                for (const auto& flag : flags) arguments.push_back(flag);
                arguments.push_back("-c");
                arguments.push_back(source.string());
                entries.push_back(llvm::json::Object{{"directory", root.string()},
                    {"file", source.string()}, {"arguments", std::move(arguments)}});
            }
        }
        std::string text;
        llvm::raw_string_ostream output(text);
        output << llvm::json::Value(std::move(entries));
        std::ofstream(root / "build/compile_commands.json") << text;
    }
    Scan scan(const std::string& executable, std::vector<std::string> extra = {}, bool synthetic = false,
              std::shared_ptr<ResourceCancellation> cancellation = {}) {
        setWorkerExecutable(executable);
        std::vector<std::string> arguments{"codeskeptic", "--source",
            synthetic ? sources.front().string() : (root / "src").string(),
            "--json", (root / "report.json").string()};
        if (!synthetic) arguments.insert(arguments.end(), {"--build-path", (root / "build").string()});
        arguments.insert(arguments.end(), extra.begin(), extra.end());
        std::vector<char*> raw;
        for (auto& argument : arguments) raw.push_back(argument.data());
        Config config;
        EXPECT_TRUE(config.parseArgs(static_cast<int>(raw.size()), raw.data()));
        config.setResourceCancellation(std::move(cancellation));
        StaticAnalyzer analyzer(config);
        addBuiltinRules(analyzer);
        Scan scan;
        scan.result = analyzer.run();
        scan.diagnostics = analyzer.diagnostics();
        scan.report = readText(root / "report.json");
        return scan;
    }
};

class AnalysisCacheTest : public AnalysisCoordinatorTest {
protected:
    void SetUp() override { AnalysisCoordinatorTest::SetUp(); processUnitEvidenceStore().clear(); }
    void TearDown() override { processUnitEvidenceStore().clear(); AnalysisCoordinatorTest::TearDown(); }
};

#ifdef __linux__
TEST_F(AnalysisCacheTest, RealHeaderBearingHitsPreserveReportAndInvalidateRestoredMetadata) {
    file("input.cpp", "#include \"value.h\"\nint result(){\n#if VALUE == 3\nint *p=nullptr; return *p;\n#else\nreturn 42;\n#endif\n}\n");
    const auto header = root / "src/value.h";
    { std::ofstream output(header, std::ios::binary); output << "#define VALUE 3\n"; }
    database();
    const auto fresh = scan(CODESKEPTIC_BINARY_PATH);
    ASSERT_EQ(fresh.result.exitCode(), 1);
    const auto inserted = scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"});
    EXPECT_EQ(inserted.report, fresh.report);
    ASSERT_GT(processUnitEvidenceStore().entries(), 0u);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 0u);
    const auto hit = scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"});
    EXPECT_EQ(hit.report, fresh.report);
    ASSERT_EQ(processUnitEvidenceStore().hits(), 1u);
    const auto modified = fs::last_write_time(header);
    { std::ofstream output(header, std::ios::binary); output << "#define VALUE 1\n"; }
    fs::last_write_time(header, modified);
    const auto changed = scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"});
    EXPECT_EQ(changed.result.exitCode(), 0);
    EXPECT_EQ(changed.report, scan(CODESKEPTIC_BINARY_PATH).report);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 1u);
}
#endif

TEST_F(AnalysisCacheTest, VolatileInputsRemainFreshWithIdenticalResults) {
    file("input.cpp", "#define VOLATILE_TIME __TIME__\nconst char *time_value=VOLATILE_TIME;\nint result(){return 42;}\n");
    database();
    const auto fresh = scan(CODESKEPTIC_BINARY_PATH);
    ASSERT_EQ(fresh.result.exitCode(), 0);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"}).report, fresh.report);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"}).report, fresh.report);
    EXPECT_EQ(processUnitEvidenceStore().entries(), 0u);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 0u);
}

TEST_F(AnalysisCacheTest, UnsupportedOptionsKeepFreshAnalysisAndReportParity) {
    file("input.cpp", "int result(){int *p=nullptr;return *p;}\n");
    const auto header = root / "forced.h";
    { std::ofstream output(header); output << "#define FORCED 1\n"; }
    for (const auto& flags : std::vector<std::vector<std::string>>{{"-fno-builtin"}, {"-include", header.string()}}) {
        database(false, flags);
        const auto fresh = scan(CODESKEPTIC_BINARY_PATH);
        ASSERT_EQ(fresh.result.exitCode(), 1);
        EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"}).report, fresh.report);
        EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"}).report, fresh.report);
        EXPECT_EQ(processUnitEvidenceStore().entries(), 0u);
        EXPECT_EQ(processUnitEvidenceStore().hits(), 0u);
    }
}

#ifndef __linux__
TEST_F(AnalysisCacheTest, UnqualifiedRuntimePlatformKeepsOrdinaryFreshResults) {
    file("input.cpp", "int result(){int *p=nullptr;return *p;}\n");
    database();
    const auto fresh = scan(CODESKEPTIC_BINARY_PATH);
    ASSERT_EQ(fresh.result.exitCode(), 1);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"}).report, fresh.report);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"}).report, fresh.report);
    EXPECT_EQ(processUnitEvidenceStore().entries(), 0u);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 0u);
}
#endif

TEST_F(AnalysisCacheTest, UnsolicitedReuseClaimIsNeverPublishedOrAdmitted) {
    file("input.cpp", "int result(){int *p=nullptr;return *p;}\n");
    database();
    const auto result = scan(CODESKEPTIC_CACHE_FIXTURE_PATH, {"--analysis-cache"});
    EXPECT_FALSE(result.result.complete());
    EXPECT_EQ(result.result.exitCode(), 2);
    ASSERT_EQ(result.result.sources.size(), 1u);
    EXPECT_EQ(result.result.sources.front().reason, "worker_result_invalid");
    EXPECT_TRUE(result.diagnostics.empty());
    EXPECT_EQ(processUnitEvidenceStore().entries(), 0u);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 0u);
}

#ifdef __linux__
class ScopedCacheEnvironment {
    std::string name_;
    std::optional<std::string> previous_;
public:
    ScopedCacheEnvironment(std::string name, const std::string& value) : name_(std::move(name)) {
        if (const auto* old = std::getenv(name_.c_str())) previous_ = old;
        EXPECT_EQ(::setenv(name_.c_str(), value.c_str(), 1), 0);
    }
    ~ScopedCacheEnvironment() {
        if (previous_) ::setenv(name_.c_str(), previous_->c_str(), 1);
        else ::unsetenv(name_.c_str());
    }
};

TEST_F(AnalysisCacheTest, ActualLoadedLibraryReplacementAndEarlierCandidateInvalidateReuse) {
    const auto source = file("input.cpp", "int result(){int *p=nullptr;return *p;}\n");
    const auto early = root / "runtime-early", late = root / "runtime-late";
    ASSERT_TRUE(fs::create_directory(early));
    ASSERT_TRUE(fs::create_directory(late));
    const auto first_module = root / "runtime-one.so", second_module = root / "runtime-two.so";
    ASSERT_TRUE(fs::copy_file(CODESKEPTIC_RUNTIME_FIXTURE_ONE, first_module));
    ASSERT_TRUE(fs::copy_file(CODESKEPTIC_RUNTIME_FIXTURE_TWO, second_module));
    // Recent module ctime deliberately refuses reuse. Age these owned copies
    // before starting a worker; never backdate timestamps or wait inside it.
    std::this_thread::sleep_for(std::chrono::seconds(3));
    const auto marker = root / "loaded-module";
    { std::ofstream output(marker); output << "0"; }
    const auto name = "libcodeskeptic_runtime_fixture.so";
    auto library_path = early.string() + ":" + late.string();
    if (const auto* prior = std::getenv("LD_LIBRARY_PATH")) library_path += ":" + std::string(prior);
    ScopedCacheEnvironment search("LD_LIBRARY_PATH", library_path);
    ScopedCacheEnvironment preload("LD_PRELOAD", name);
    ScopedCacheEnvironment marker_path("CS_CACHE_FIXTURE_MARKER", marker.string());
    WorkerRequest request;
    request.source = source.string(); request.build_directory = root.string();
    request.commands.emplace_back(root.string(), source.string(),
        std::vector<std::string>{"clang++", "-std=c++17", "-c", source.string()}, "");
    request.producers = {"null-deref"}; request.selected_families = {"null-deref"}; request.record_inputs = true;
    std::string summary_error;
    ASSERT_TRUE(exportWorkerSummaries(request.global_summaries, summary_error)) << summary_error;
    for (const bool earlier : {false, true}) {
        processUnitEvidenceStore().clear();
        std::error_code error;
        fs::remove(early / name, error); fs::remove(late / name, error);
        fs::create_symlink(first_module, late / name);
        const auto execute = [&] { return executeAnalysisWorker(CODESKEPTIC_BINARY_PATH, request); };
        const auto first = execute();
        ASSERT_TRUE(first.valid) << first.reason << first.detail;
        ASSERT_FALSE(first.response.runtime_digest.empty());
        EXPECT_FALSE(first.cache_hit); EXPECT_EQ(readText(marker), "1");
        const auto repeat = execute();
        ASSERT_TRUE(repeat.valid) << repeat.reason << repeat.detail;
        ASSERT_TRUE(repeat.cache_hit);
        ASSERT_EQ(processUnitEvidenceStore().hits(), 1u);
        ASSERT_EQ(repeat.response.runtime_digest, first.response.runtime_digest);
        const auto alias = earlier ? early / name : late / name;
        fs::create_symlink(second_module, late / "next-module-link");
        fs::rename(late / "next-module-link", alias);
        InputIdentity input;
        ASSERT_TRUE(decodeInputIdentity(first.response.input_witness, input));
        ASSERT_TRUE(input.matchesCurrent()) << "loader change must not be masked by frontend invalidation";
        const auto changed = execute();
        ASSERT_TRUE(changed.valid) << changed.reason << changed.detail;
        EXPECT_EQ(readText(marker), "2");
        ASSERT_FALSE(changed.response.runtime_digest.empty());
        EXPECT_NE(changed.response.runtime_digest, first.response.runtime_digest);
        EXPECT_FALSE(changed.cache_hit); EXPECT_EQ(processUnitEvidenceStore().hits(), 1u);
        auto normalized = changed.response;
        normalized.runtime_digest = first.response.runtime_digest;
        EXPECT_EQ(encodeWorkerResponse(normalized), encodeWorkerResponse(first.response));
        const auto repeat_changed = execute();
        ASSERT_TRUE(repeat_changed.valid) << repeat_changed.reason << repeat_changed.detail;
        EXPECT_TRUE(repeat_changed.cache_hit);
        EXPECT_EQ(repeat_changed.response.runtime_digest, changed.response.runtime_digest);
        EXPECT_EQ(processUnitEvidenceStore().hits(), 2u);
    }
}
#endif

#ifdef __linux__
TEST_F(AnalysisCacheTest, NewlySelectedRelocatableResourceDirectoryRejectsOldWorkerEntry) {
    file("input.cpp", "#include <stddef.h>\nint result(){\n#ifdef CS_ALTERNATE_RESOURCE\nint *p=nullptr;return *p;\n#else\nreturn 42;\n#endif\n}\n");
    database();
    ASSERT_TRUE(fs::create_directory(root / "bin"));
    const auto binary = root / "bin" / fs::path(CODESKEPTIC_BINARY_PATH).filename();
    ASSERT_TRUE(fs::copy_file(CODESKEPTIC_BINARY_PATH, binary));
    std::this_thread::sleep_for(std::chrono::seconds(3));
    ScopedCacheEnvironment no_override("CODESKEPTIC_RESOURCE_DIR", "");
    const auto first = scan(binary.string(), {"--analysis-cache"});
    ASSERT_EQ(first.result.exitCode(), 0);
    EXPECT_EQ(scan(binary.string(), {"--analysis-cache"}).report, first.report);
    ASSERT_EQ(processUnitEvidenceStore().hits(), 1u);
    const auto resource = root / "lib/clang/999/include";
    ASSERT_TRUE(fs::create_directories(resource));
    { std::ofstream output(resource / "stddef.h"); output << "#define CS_ALTERNATE_RESOURCE 1\n"; }
    const auto changed = scan(binary.string(), {"--analysis-cache"});
    EXPECT_EQ(changed.result.exitCode(), 1);
    EXPECT_EQ(changed.report, scan(binary.string()).report);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 1u);
}

TEST_F(AnalysisCacheTest, ChangedCompilerFlagsAndAnalysisProfileRejectPreviousEvidence) {
    file("input.cpp", "int result(){\n#if FLAG\nint *p=nullptr;return *p;\n#else\nreturn 42;\n#endif\n}\n");
    database(false, {"-DFLAG=0"});
    const auto first = scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"});
    ASSERT_EQ(first.result.exitCode(), 0);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"}).report, first.report);
    ASSERT_EQ(processUnitEvidenceStore().hits(), 1u);
    database(false, {"-DFLAG=1"});
    const auto changed = scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"});
    ASSERT_EQ(changed.result.exitCode(), 1);
    EXPECT_EQ(changed.report, scan(CODESKEPTIC_BINARY_PATH).report);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 1u);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache", "--no-assert-recovery"}).report,
              scan(CODESKEPTIC_BINARY_PATH, {"--no-assert-recovery"}).report);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 1u);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache", "--no-assert-recovery"}).report, changed.report);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 2u);
}

TEST_F(AnalysisCacheTest, EarlierIncludeCandidateAndChangedEnvironmentCannotUseOldHeader) {
    file("input.cpp", "#include <value.h>\nint result(){\n#if VALUE\nint *p=nullptr;return *p;\n#else\nreturn 42;\n#endif\n}\n");
    const auto early = root / "include-early", late = root / "include-late";
    ASSERT_TRUE(fs::create_directory(early)); ASSERT_TRUE(fs::create_directory(late));
    { std::ofstream output(late / "value.h"); output << "#define VALUE 0\n"; }
    database(false, {"-I", early.string(), "-I", late.string()});
    const auto first = scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"});
    ASSERT_EQ(first.result.exitCode(), 0);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"}).report, first.report);
    ASSERT_EQ(processUnitEvidenceStore().hits(), 1u);
    { std::ofstream output(early / "value.h"); output << "#define VALUE 1\n"; }
    const auto changed = scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"});
    ASSERT_EQ(changed.result.exitCode(), 1);
    EXPECT_EQ(changed.report, scan(CODESKEPTIC_BINARY_PATH).report);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 1u);

    processUnitEvidenceStore().clear();
    database();
    ScopedCacheEnvironment base("CPATH", late.string());
    const auto environmental = scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"});
    ASSERT_EQ(environmental.result.exitCode(), 0);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"}).report, environmental.report);
    ASSERT_EQ(processUnitEvidenceStore().hits(), 1u);
    ScopedCacheEnvironment changed_search("CPATH", early.string() + ":" + late.string());
    const auto environment_changed = scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"});
    ASSERT_EQ(environment_changed.result.exitCode(), 1);
    EXPECT_EQ(environment_changed.report, scan(CODESKEPTIC_BINARY_PATH).report);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 1u);
}

TEST_F(AnalysisCacheTest, CachedWorkNeverOverridesCancellationOrChangedLimits) {
    file("input.cpp", "int result(){int *p=nullptr;return *p;}\n");
    database();
    const auto first = scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"});
    ASSERT_TRUE(first.result.complete());
    ASSERT_GT(processUnitEvidenceStore().entries(), 0u);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache", "--worker-timeout-ms", "60000"}).report, first.report);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 0u);
    auto token = std::make_shared<ResourceCancellation>();
    token->request();
    const auto cancelled = scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"}, false, token);
    ASSERT_FALSE(cancelled.result.complete());
    EXPECT_EQ(cancelled.result.exitCode(), 2);
    ASSERT_EQ(cancelled.result.sources.size(), 1u);
    EXPECT_EQ(cancelled.result.sources[0].reason, "worker_cancelled");
    EXPECT_EQ(processUnitEvidenceStore().hits(), 0u);
}

TEST_F(AnalysisCacheTest, RuleSelectionAndVariantsKeepTheExactWorkerIdentity) {
    file("input.cpp", "int result(){int *p=nullptr;return *p;}\n");
    database(true);
    const auto fresh = scan(CODESKEPTIC_BINARY_PATH);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"}).report, fresh.report);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"}).report, fresh.report);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 1u);
    const auto filtered = scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache", "--disable-rule", "null-deref"});
    EXPECT_EQ(filtered.report, scan(CODESKEPTIC_BINARY_PATH, {"--disable-rule", "null-deref"}).report);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 1u);
}

TEST_F(AnalysisCacheTest, ReplacedToolBytesCannotReuseTheOldWorkerEntry) {
    file("input.cpp", "int result(){int *p=nullptr;return *p;}\n");
    database();
    const auto copy = root / fs::path(CODESKEPTIC_BINARY_PATH).filename();
    ASSERT_TRUE(fs::copy_file(CODESKEPTIC_BINARY_PATH, copy));
    std::this_thread::sleep_for(std::chrono::seconds(3)); // qualify newly installed executable before child startup
    const auto first = scan(copy.string(), {"--analysis-cache"});
    ASSERT_TRUE(first.result.complete());
    ASSERT_GT(processUnitEvidenceStore().entries(), 0u);
    EXPECT_EQ(scan(copy.string(), {"--analysis-cache"}).report, first.report);
    ASSERT_EQ(processUnitEvidenceStore().hits(), 1u);
    // A trailing non-loadable byte preserves this native executable's behavior
    // while changing its content identity. No repository binary is modified.
    { std::ofstream output(copy, std::ios::binary | std::ios::app); output.put('\0'); }
    EXPECT_EQ(scan(copy.string(), {"--analysis-cache"}).report, first.report);
    EXPECT_EQ(processUnitEvidenceStore().hits(), 1u);
}

TEST_F(AnalysisCacheTest, NonExecutableWorkerCannotBeRescuedByCachedEvidence) {
    file("input.cpp", "int result(){int *p=nullptr;return *p;}\n");
    database();
    const auto copy = root / fs::path(CODESKEPTIC_BINARY_PATH).filename();
    ASSERT_TRUE(fs::copy_file(CODESKEPTIC_BINARY_PATH, copy));
    std::this_thread::sleep_for(std::chrono::seconds(3));
    ASSERT_TRUE(scan(copy.string(), {"--analysis-cache"}).result.complete());
    ASSERT_TRUE(scan(copy.string(), {"--analysis-cache"}).result.complete());
    ASSERT_EQ(processUnitEvidenceStore().hits(), 1u);
    const auto permissions = fs::status(copy).permissions();
    fs::permissions(copy, fs::perms::owner_exec | fs::perms::group_exec | fs::perms::others_exec,
                    fs::perm_options::remove);
    const auto fresh = scan(copy.string());
    ASSERT_FALSE(fresh.result.complete());
    const auto cached = scan(copy.string(), {"--analysis-cache"});
    EXPECT_FALSE(cached.result.complete());
    EXPECT_EQ(cached.result.exitCode(), 2);
    EXPECT_EQ(cached.result.sources.front().reason, fresh.result.sources.front().reason);
    fs::permissions(copy, permissions);
    EXPECT_TRUE(scan(copy.string(), {"--analysis-cache"}).result.complete());
}
#endif

TEST_F(AnalysisCacheTest, OptInConfigurationIsExplicitValidatedAndInheritedSeparately) {
    Config defaults;
    EXPECT_FALSE(defaults.analysisCache());
    const auto path = root / "cache.conf";
    { std::ofstream output(path, std::ios::binary); output << "analysis_cache=true\n"; }
    ASSERT_TRUE(defaults.loadFromFile(path.string()));
    EXPECT_TRUE(defaults.analysisCache());
    EXPECT_FALSE(defaults.warmCache());
    Config request;
    request.setWarmCache(true);
    request.inheritAnalysisCache(defaults);
    EXPECT_TRUE(request.analysisCache());
    EXPECT_TRUE(request.warmCache());
    { std::ofstream output(path, std::ios::binary); output << "analysis_cache=perhaps\n"; }
    EXPECT_FALSE(defaults.loadFromFile(path.string()));
    EXPECT_TRUE(defaults.analysisCache()); // failed load remains transactional
    std::vector<std::string> args{"codeskeptic", "--no-analysis-cache"};
    std::vector<char*> raw;
    for (auto& arg : args) raw.push_back(arg.data());
    ASSERT_TRUE(defaults.parseArgs(raw.size(), raw.data()));
    EXPECT_FALSE(defaults.analysisCache());
}

TEST_F(AnalysisCoordinatorTest, ProductionWorkerMatchesInProcessForCAndCpp) {
    file("safe.c", "#include <stddef.h>\nint safe(void) { return (int)sizeof(size_t); }\n");
    file("finding.cpp", "int finding() { int* p = nullptr; return *p; }\n");
    database();
    const auto direct = scan("");
    ASSERT_EQ(direct.result.exitCode(), 1);
    ASSERT_FALSE(direct.diagnostics.empty());
    const auto isolated = scan(CODESKEPTIC_BINARY_PATH);
    EXPECT_EQ(isolated.report, direct.report);
    EXPECT_EQ(isolated.result.analyzed_tus, 2u);
    EXPECT_TRUE(isolated.result.coverageComplete());
}

TEST_F(AnalysisCoordinatorTest, SyntheticCAndCppUseFrozenDocumentedLanguageRecipes) {
    const auto c = file("input.c", "#include <stddef.h>\n_Static_assert(sizeof(int) >= 2, \"C11\");\n"
                                  "int safe(void) { return (int)sizeof(size_t); }\n");
    const auto direct_c = scan("", {}, true);
    ASSERT_EQ(direct_c.result.exitCode(), 0);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {}, true).report, direct_c.report);
    sources.clear();
    fs::remove(c);
    file("input.cpp", "template<class T> int answer(){ if constexpr(sizeof(T)>0) return 42; }\n"
                      "int safe(){ return answer<int>(); }\n");
    const auto direct_cpp = scan("", {}, true);
    ASSERT_EQ(direct_cpp.result.exitCode(), 0);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {}, true).report, direct_cpp.report);
}

TEST_F(AnalysisCoordinatorTest, CrashAtAnyPositionPreservesOtherFindingsAndFailsClosed) {
    for (unsigned crashed = 0; crashed < 3; ++crashed) {
        for (const auto& source : sources) fs::remove(source);
        sources.clear();
        for (unsigned index = 0; index < 3; ++index)
            file(std::to_string(index) + (index == crashed ? "-crash.cpp" : "-good.cpp"),
                 "int f" + std::to_string(index) + "() { int* p = nullptr; return *p; }\n");
        database();
        const auto isolated = scan(CODESKEPTIC_WORKER_FIXTURE_PATH,
            {"--accept-partial-coverage", "--analyze-broken-tus"});
        ASSERT_EQ(isolated.result.sources.size(), 3u);
        EXPECT_EQ(isolated.result.exitCode(), 2);
        EXPECT_FALSE(isolated.result.complete());
        EXPECT_EQ(isolated.result.failed_tus, 1u);
        EXPECT_EQ(isolated.result.analyzed_tus, 2u);
        EXPECT_EQ(isolated.result.sources[crashed].file, sources[crashed].string());
        EXPECT_EQ(isolated.result.sources[crashed].reason, "worker_crashed");
        EXPECT_EQ(isolated.diagnostics.size(), 2u);
        for (const auto& finding : isolated.diagnostics)
            EXPECT_NE(finding.file, sources[crashed].string());
    }
}

TEST_F(AnalysisCoordinatorTest, InvalidOrAbnormallyTerminatedChildCannotRescueItsReport) {
    for (const std::string fault : {"missing", "malformed", "oversized", "truncated", "version",
                                    "source", "reason", "after-crash", "after-nonzero"}) {
        for (const auto& source : sources) fs::remove(source);
        sources.clear();
        file("a-" + fault + ".cpp", "int bad(){ int* p=nullptr; return *p; }\n");
        file("z-survivor.cpp", "int survivor(){ int* q=nullptr; return *q; }\n");
        database();
        const auto isolated = scan(CODESKEPTIC_WORKER_FIXTURE_PATH);
        EXPECT_EQ(isolated.result.exitCode(), 2) << fault;
        EXPECT_EQ(isolated.result.failed_tus, 1u) << fault;
        EXPECT_EQ(isolated.result.analyzed_tus, 1u) << fault;
        ASSERT_EQ(isolated.diagnostics.size(), 1u) << fault;
        EXPECT_EQ(isolated.diagnostics.front().function, "survivor") << fault;
    }
}

TEST_F(AnalysisCoordinatorTest, LaunchFailureDoesNotFallBackToAnInProcessCleanVerdict) {
    file("safe.cpp", "int safe(){ return 42; }\n");
    database();
    const auto isolated = scan((root / "no-such-worker").string());
    ASSERT_EQ(isolated.result.sources.size(), 1u);
    EXPECT_EQ(isolated.result.sources.front().reason, "worker_launch_failed");
    EXPECT_EQ(isolated.result.exitCode(), 2);
    EXPECT_EQ(isolated.result.analyzed_tus, 0u);
}

TEST_F(AnalysisCoordinatorTest, ContradictoryChildCoverageCannotProduceACleanParent) {
    file("a-reason.cpp", "int first(){ return 42; }\n");
    file("z-clean.cpp", "int second(){ return 42; }\n");
    database();
    const auto isolated = scan(CODESKEPTIC_WORKER_FIXTURE_PATH);
    EXPECT_EQ(isolated.result.exitCode(), 2);
    EXPECT_EQ(isolated.result.failed_tus, 1u);
    EXPECT_EQ(isolated.result.analyzed_tus, 1u);
    EXPECT_TRUE(isolated.diagnostics.empty());
}

TEST_F(AnalysisCoordinatorTest, RealCompileVariantsAndSuppressionAuditRemainEquivalent) {
    file("variants.cpp", "int bound(){\n#if VARIANT == 0\nint* p=nullptr; return *p;\n#else\nreturn 42;\n#endif\n}\n"
         "int suppressed(){ int* p=nullptr; return *p; } // codeskeptic-disable-line null-deref -- test decision\n");
    database(true);
    const auto direct = scan("");
    ASSERT_EQ(direct.result.exitCode(), 1);
    ASSERT_FALSE(direct.result.suppressions.empty());
    const auto isolated = scan(CODESKEPTIC_BINARY_PATH);
    EXPECT_EQ(isolated.report, direct.report);
    ASSERT_EQ(isolated.result.sources.size(), 1u);
    EXPECT_EQ(isolated.result.sources.front().analyzed_commands, 2u);
}

TEST_F(AnalysisCoordinatorTest, RollingGlobalSummariesMatchWithAndWithoutPrepass) {
    file("a.cpp", "int* give(){ return nullptr; }\n");
    file("b.cpp", "int* give(); int* middle(){ return give(); }\n");
    file("c.cpp", "int* middle(); int use(){ int* p=middle(); return *p; }\n");
    database();
    for (bool whole : {false, true}) {
        std::vector<std::string> extra{"--summary-out", (root / "summary.txt").string()};
        if (whole) extra.push_back("--whole-program");
        const auto direct = scan("", extra);
        const auto expected_summary = readText(root / "summary.txt");
        ASSERT_FALSE(expected_summary.empty());
        ASSERT_FALSE(direct.diagnostics.empty());
        const auto isolated = scan(CODESKEPTIC_BINARY_PATH, extra);
        EXPECT_EQ(isolated.report, direct.report) << "whole=" << whole;
        EXPECT_EQ(readText(root / "summary.txt"), expected_summary) << "whole=" << whole;
    }
}

TEST_F(AnalysisCoordinatorTest, FailedPrepassIsNotErasedByAnotherSuccessfulSource) {
    file("a-crash.cpp", "int* give(){ return nullptr; }\n");
    file("z.cpp", "int survivor(){ int* p=nullptr; return *p; }\n");
    database();
    const auto isolated = scan(CODESKEPTIC_WORKER_FIXTURE_PATH, {"--whole-program"});
    EXPECT_EQ(isolated.result.exitCode(), 2);
    ASSERT_EQ(isolated.result.sources.size(), 2u);
    EXPECT_EQ(isolated.result.sources.front().prepass_status, "failed");
    EXPECT_EQ(isolated.result.analyzed_tus, 1u);
    ASSERT_EQ(isolated.diagnostics.size(), 1u);
    EXPECT_EQ(isolated.diagnostics.front().function, "survivor");
}

TEST_F(AnalysisCoordinatorTest, SpacesAndUnicodePathsAndRepeatedOrderingAreStable) {
    file(u8"z boş-資料.cpp", "int last(){ int* p=nullptr; return *p; }\n");
    file("a first.c", "int first(void){ int* p=0; return *p; }\n");
    database();
    const auto first = scan(CODESKEPTIC_BINARY_PATH);
    ASSERT_EQ(first.result.exitCode(), 1);
    ASSERT_EQ(first.result.sources.size(), 2u);
    EXPECT_LT(first.result.sources[0].file, first.result.sources[1].file);
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH).report, first.report);
    EXPECT_EQ(scan("").report, first.report);
}

TEST_F(AnalysisCoordinatorTest, BrokenSourceCoverageMatchesWithoutInventedCleanResults) {
    file("a.cpp", "int broken(){ return missing_symbol; }\n");
    file("b.cpp", "int safe(){ return 42; }\n");
    database();
    for (const std::vector<std::string> extra : {std::vector<std::string>{},
                                               {"--accept-partial-coverage"}, {"--analyze-broken-tus"}}) {
        const auto direct = scan("", extra);
        const auto isolated = scan(CODESKEPTIC_BINARY_PATH, extra);
        EXPECT_EQ(isolated.report, direct.report);
        EXPECT_FALSE(isolated.result.coverageComplete());
    }
}

TEST_F(AnalysisCoordinatorTest, InvalidSummaryImportPreservesExistingRollingState) {
    file("input.cpp", "int* give(){ return nullptr; }\n");
    database();
    const auto result = scan("", {"--summary-out", (root / "summary.txt").string()});
    ASSERT_EQ(result.result.exitCode(), 0);
    const auto snapshot = readText(root / "summary.txt");
    std::string error, before, after;
    ASSERT_TRUE(importWorkerSummaries(snapshot, error)) << error;
    ASSERT_GT(SummaryRegistry::instance().globalSize(), 0u);
    ASSERT_TRUE(exportWorkerSummaries(before, error)) << error;
    EXPECT_FALSE(importWorkerSummaries(snapshot + "\ncorrupt record\n", error));
    ASSERT_TRUE(exportWorkerSummaries(after, error)) << error;
    EXPECT_EQ(after, before);
}

TEST_F(AnalysisCoordinatorTest, AnalysisOptionsAndFamilySelectionSurviveWorkerTransfer) {
    file("scoped.cpp", "int first(){ int* p=nullptr; return *p; }\n"
                       "int second(){ int* q=nullptr; return *q; }\n");
    database();
    for (const std::vector<std::string> extra : {
        std::vector<std::string>{"--function", "second", "--lines", "2", "--lang", "tr"},
        {"--disable-rule", "null-deref"},
        {"--function", "first", "--function", "second", "--lines", "1", "--lines", "2"}}) {
        const auto direct = scan("", extra);
        EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, extra).report, direct.report);
    }
}

TEST_F(AnalysisCoordinatorTest, ProductionMcpStdioUsesWorkersWithoutPollutingFramesOrLeakingSelection) {
    const auto source = file("mcp.cpp", "int finding(){ int* p=nullptr; return *p; }\n");
    database();
    std::string frames;
    llvm::raw_string_ostream stream(frames);
    for (int id = 1; id <= 2; ++id) {
        llvm::json::Object arguments{{"path", source.string()}, {"build_path", (root / "build").string()}};
        if (id == 1) arguments["disable_rules"] = "null-deref";
        stream << llvm::json::Value(llvm::json::Object{{"jsonrpc", "2.0"}, {"id", id},
            {"method", "tools/call"}, {"params", llvm::json::Object{{"name", "analyze"},
                {"arguments", std::move(arguments)}}}}) << '\n';
    }
    stream << "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n";
    const auto input = (root / "mcp-input.jsonl").string();
    const auto output = (root / "mcp-output.jsonl").string();
    const auto errors = (root / "mcp-stderr.log").string();
    std::ofstream(input) << frames;
    const std::array<llvm::StringRef, 2> arguments{{CODESKEPTIC_BINARY_PATH, "--serve"}};
    const std::array<std::optional<llvm::StringRef>, 3> redirects{{input, output, errors}};
    std::string error;
    ASSERT_EQ(llvm::sys::ExecuteAndWait(CODESKEPTIC_BINARY_PATH, arguments, std::nullopt,
                                      redirects, 30, 0, &error), 0) << error << readText(errors);
    std::istringstream lines(readText(output));
    std::string line;
    for (int id = 1; id <= 3; ++id) {
        ASSERT_TRUE(static_cast<bool>(std::getline(lines, line)));
        auto value = llvm::json::parse(line);
        ASSERT_TRUE(static_cast<bool>(value)) << line;
        const auto* envelope = value->getAsObject();
        ASSERT_NE(envelope, nullptr);
        EXPECT_EQ(envelope->getInteger("id"), id);
        const auto* result = envelope->getObject("result");
        ASSERT_NE(result, nullptr) << line;
        if (id == 3) continue;
        const auto* content = result->getArray("content");
        ASSERT_NE(content, nullptr);
        ASSERT_EQ(content->size(), 1u);
        const auto* block = content->front().getAsObject();
        ASSERT_NE(block, nullptr);
        const auto text = block->getString("text");
        ASSERT_TRUE(text.has_value());
        auto payload = llvm::json::parse(*text);
        ASSERT_TRUE(static_cast<bool>(payload));
        const auto* report = payload->getAsObject();
        ASSERT_NE(report, nullptr);
        EXPECT_EQ(report->getInteger("exit_code"), id == 1 ? 0 : 1);
        EXPECT_EQ(report->getBoolean("complete"), true);
        const auto* coverage = report->getObject("coverage");
        ASSERT_NE(coverage, nullptr);
        EXPECT_EQ(coverage->getInteger("analyzed_tus"), 1);
    }
    EXPECT_FALSE(static_cast<bool>(std::getline(lines, line)));
}

TEST_F(AnalysisCoordinatorTest, ResourceFailurePreservesSurvivorsAndCannotBeAcceptedAsClean) {
    for (const std::string failure : {"sleep", "memory", "no-ack", "wrong-ack"}) {
        for (const auto& source : sources) fs::remove(source);
        sources.clear();
        file("a-good.cpp", "int before(){ int* p=nullptr; return *p; }\n");
        file("b-budget-" + failure + ".cpp", "int failed(){ return 0; }\n");
        file("c-good.cpp", "int after(){ int* p=nullptr; return *p; }\n");
        database();
        const auto result = scan(CODESKEPTIC_RESOURCE_FIXTURE_PATH,
            {"--worker-timeout-ms", failure == "sleep" ? "300" : "5000", "--worker-memory-mb", "512",
             "--accept-partial-coverage", "--analyze-broken-tus"});
        EXPECT_EQ(result.result.exitCode(), 2);
        EXPECT_FALSE(result.result.complete());
        EXPECT_EQ(result.result.failed_tus, 1u);
        EXPECT_EQ(result.result.analyzed_tus, 2u);
        ASSERT_EQ(result.result.sources.size(), 3u);
        EXPECT_EQ(result.result.sources[1].reason, failure == "sleep" ? "worker_timeout" :
                  failure == "memory" ? "worker_memory_exhausted" : "worker_result_invalid");
        ASSERT_EQ(result.diagnostics.size(), 2u);
        EXPECT_EQ(result.diagnostics[0].function, "before");
        EXPECT_EQ(result.diagnostics[1].function, "after");
    }
}

TEST_F(AnalysisCoordinatorTest, CancellationKeepsCompletedFindingAndAccountsForUnstartedSources) {
    file("a-good.cpp", "int before(){ int* p=nullptr; return *p; }\n");
    const auto sleeping = file("b-budget-sleep.cpp", "int middle(){ return 0; }\n");
    file("c-budget-sleep.cpp", "int tail(){ return 0; }\n");
    database();
    const auto token = std::make_shared<ResourceCancellation>();
    auto canceller = std::async(std::launch::async, [&] {
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (!fs::exists(sleeping.string() + ".started") && std::chrono::steady_clock::now() < until)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        const bool started = fs::exists(sleeping.string() + ".started");
        token->request();
        return started;
    });
    const auto result = scan(CODESKEPTIC_RESOURCE_FIXTURE_PATH, {}, false, token);
    EXPECT_TRUE(canceller.get());
    EXPECT_EQ(result.result.exitCode(), 2);
    EXPECT_EQ(result.result.failed_tus, 2u);
    EXPECT_EQ(result.result.analyzed_tus, 1u);
    ASSERT_EQ(result.diagnostics.size(), 1u);
    EXPECT_EQ(result.diagnostics.front().function, "before");
    ASSERT_EQ(result.result.sources.size(), 3u);
    EXPECT_EQ(result.result.sources[1].reason, "worker_cancelled");
    EXPECT_EQ(result.result.sources[2].reason, "worker_cancelled");
    EXPECT_FALSE(fs::exists(sources[2].string() + ".started"));
}

} // namespace
