#include "analyzer/AnalysisCoordinator.h"
#include "analyzer/AnalysisState.h"
#include "core/Capabilities.h"
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
#include <atomic>
#ifdef __linux__
#include <cerrno>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

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
    DiskCacheStatus disk_cache;
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
              std::shared_ptr<ResourceCancellation> cancellation = {}, const fs::path& config_path = {}) {
        setWorkerExecutable(executable);
        std::vector<std::string> arguments{"codeskeptic", "--source",
            synthetic ? sources.front().string() : (root / "src").string(),
            "--json", (root / "report.json").string()};
        if (!synthetic) arguments.insert(arguments.end(), {"--build-path", (root / "build").string()});
        arguments.insert(arguments.end(), extra.begin(), extra.end());
        std::vector<char*> raw;
        for (auto& argument : arguments) raw.push_back(argument.data());
        Config config;
        if (!config_path.empty()) EXPECT_TRUE(config.loadFromFile(config_path.string()));
        EXPECT_TRUE(config.parseArgs(static_cast<int>(raw.size()), raw.data()));
        config.setResourceCancellation(std::move(cancellation));
        StaticAnalyzer analyzer(config);
        addBuiltinRules(analyzer);
        Scan scan;
        scan.result = analyzer.run();
        scan.diagnostics = analyzer.diagnostics();
        scan.report = readText(root / "report.json");
        scan.disk_cache = analyzer.diskCacheStatus();
        return scan;
    }
};

class AnalysisCacheTest : public AnalysisCoordinatorTest {
protected:
    void SetUp() override { AnalysisCoordinatorTest::SetUp(); processUnitEvidenceStore().clear(); }
    void TearDown() override { processUnitEvidenceStore().clear(); AnalysisCoordinatorTest::TearDown(); }
};

#ifdef __linux__
TEST_F(AnalysisCacheTest, CheckpointSnapshotBindsPendingHeaderAndSidecarWithoutPublishingFindings) {
    const auto source = file("snapshot.cpp", "#include \"snapshot.h\"\nint finding(){int *p=nullptr; return *p;}\n");
    const auto header = root / "src/snapshot.h";
    { std::ofstream out(header, std::ios::binary); out << "int pending(int *p);\n"; }
    const auto tool = root / "checkpoint-worker";
    fs::copy_file(CODESKEPTIC_BINARY_PATH, tool);
    // The private copied tool must predate the new worker's startup identity.
    std::this_thread::sleep_for(std::chrono::seconds(3));
    WorkerRequest request;
    request.source = source.string(); request.build_directory = root.string();
    request.commands.emplace_back(root.string(), source.string(),
        std::vector<std::string>{"clang++", "-std=c++17", "-c", source.string()}, "");
    request.phase = WorkerPhase::Snapshot; request.record_inputs = true;
    request.global_summaries = "# codeskeptic-summaries-v1\n";
    std::string error;
    ASSERT_TRUE(exportWorkerSummaries(request.global_summaries, error));
    const auto initial = executeAnalysisWorker(tool.string(), request, {}, nullptr, nullptr, nullptr, true);
    ASSERT_TRUE(initial.valid) << initial.reason << initial.detail;
    EXPECT_TRUE(initial.response.diagnostics.empty());
    ASSERT_TRUE(reusableWorkerResponse(request, initial.response));
    const auto packet = encodeWorkerResponse(initial.response);
    EXPECT_EQ(processUnitEvidenceStore().entries(), 0u);
    const auto resume = executeAnalysisWorker(tool.string(), request, {}, nullptr, nullptr, &packet, true);
    ASSERT_TRUE(resume.valid) << resume.reason << resume.detail;
    EXPECT_TRUE(resume.cache_hit);
    EXPECT_EQ(processUnitEvidenceStore().entries(), 0u);
    const auto sidecar = root / "src/snapshot.h.csk";
    { std::ofstream out(sidecar, std::ios::binary); out << "pending: requires p != null\n"; }
    const auto changed_sidecar = executeAnalysisWorker(tool.string(), request, {}, nullptr, nullptr, &packet, true);
    EXPECT_FALSE(changed_sidecar.valid);
    EXPECT_FALSE(changed_sidecar.cache_hit);
    fs::remove(sidecar); // Only this fixture's newly created sidecar.
    const auto timestamp = fs::last_write_time(header);
    { std::ofstream out(header, std::ios::binary); out << "int changed(int *p);\n"; }
    fs::last_write_time(header, timestamp);
    const auto changed_header = executeAnalysisWorker(tool.string(), request, {}, nullptr, nullptr, &packet, true);
    EXPECT_FALSE(changed_header.valid);
    EXPECT_FALSE(changed_header.cache_hit);
}

TEST_F(AnalysisCacheTest, CheckpointReplaysReportsAndRollingSummariesForBothExecutionModes) {
    file("a.cpp", "int *make_pointer(){return nullptr;}\n");
    file("b.cpp", "int *make_pointer(); int finding(){return *make_pointer();}\n");
    database(true);
    const auto tool = root / "checkpoint-worker";
    fs::copy_file(CODESKEPTIC_BINARY_PATH, tool);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    for (const bool whole : {false, true}) {
        std::vector<std::string> settings{"--summary-out", (root / "summaries.txt").string()};
        if (whole) settings.push_back("--whole-program");
        const auto fresh = scan(tool.string(), settings);
        ASSERT_TRUE(fresh.result.complete());
        const auto summaries = readText(root / "summaries.txt");
        settings.insert(settings.end(), {"--checkpoint-dir", (root / (whole ? "whole-checkpoint" : "plain-checkpoint")).string()});
        const auto recorded = scan(tool.string(), settings);
        ASSERT_TRUE(recorded.result.complete());
        EXPECT_EQ(recorded.report, fresh.report);
        EXPECT_EQ(readText(root / "summaries.txt"), summaries);
        settings.push_back("--resume");
        const auto resumed = scan(tool.string(), settings);
        ASSERT_TRUE(resumed.result.complete());
        EXPECT_EQ(resumed.report, fresh.report);
        EXPECT_EQ(readText(root / "summaries.txt"), summaries);
        EXPECT_EQ(processUnitEvidenceStore().entries(), 0u);
    }
}

TEST_F(AnalysisCacheTest, CheckpointRejectsChangedInputsAndCorruptManifestWithoutOverwritingReport) {
    file("a.cpp", "#include \"value.h\"\nint first(){return VALUE;}\n");
    file("b.cpp", "#include \"value.h\"\nint second(){int *p=nullptr;return *p+VALUE;}\n");
    const auto header = root / "src/value.h";
    { std::ofstream out(header, std::ios::binary); out << "#define VALUE 1\n"; }
    database();
    const auto tool = root / "checkpoint-worker";
    fs::copy_file(CODESKEPTIC_BINARY_PATH, tool);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    const auto directory = root / "checkpoint";
    const std::vector<std::string> fresh{"--checkpoint-dir", directory.string()};
    const auto recorded = scan(tool.string(), fresh);
    ASSERT_TRUE(recorded.result.complete());
    const std::vector<std::string> resume{"--checkpoint-dir", directory.string(), "--resume"};
    auto changed_settings = resume;
    changed_settings.insert(changed_settings.end(), {"--severity", "error"});
    EXPECT_EQ(scan(tool.string(), changed_settings).result.exitCode(), 2);
    EXPECT_EQ(readText(root / "report.json"), recorded.report);
    const auto modified = fs::last_write_time(header);
    { std::ofstream out(header, std::ios::binary); out << "#define VALUE 2\n"; }
    fs::last_write_time(header, modified);
    EXPECT_EQ(scan(tool.string(), resume).result.exitCode(), 2);
    EXPECT_EQ(readText(root / "report.json"), recorded.report);
    { std::ofstream out(header, std::ios::binary); out << "#define VALUE 1\n"; }
    fs::last_write_time(header, modified);
    // Input identity also binds file metadata: a restored byte/mtime pair may
    // still be refused. Corruption is independently exercised without replay.
    const auto manifest = directory / "manifest.csk-checkpoint";
    auto bytes = readText(manifest);
    ASSERT_GT(bytes.size(), 100u);
    bytes[90] ^= 1;
    { std::ofstream out(manifest, std::ios::binary | std::ios::trunc); out << bytes; }
    EXPECT_EQ(scan(tool.string(), resume).result.exitCode(), 2);
    EXPECT_EQ(readText(root / "report.json"), recorded.report);
}

class CheckpointInterruptTest : public AnalysisCacheTest, public ::testing::WithParamInterface<bool> {};

TEST_P(CheckpointInterruptTest, RealInterruptedCliResumesInAnotherProcessAndMatchesFresh) {
    for (unsigned i = 0; i < 3; ++i)
        file(std::to_string(i) + ".cpp", "int finding" + std::to_string(i) + "(){int *p=nullptr;return *p;}\n");
    database();
    const auto tool = root / "checkpoint-cli";
    fs::copy_file(CODESKEPTIC_BINARY_PATH, tool);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    const auto report = root / "cli-report.json";
    const auto errors = root / "cli-errors.log";
    std::vector<std::string> arguments{tool.string(), "--source", (root / "src").string(),
        "--build-path", (root / "build").string(), "--json", report.string()};
    if (GetParam()) arguments.push_back("--whole-program");
    const std::string total = GetParam() ? "6" : "3";
    const std::array<std::string, 3> redirects{{"", (root / "cli-stdout.log").string(), errors.string()}};
    WorkerLimits limits; limits.timeout_ms = 90000;
    const auto fresh = runResourceWorker(tool.string(), arguments, redirects, limits);
    ASSERT_EQ(fresh.stop, ResourceStop::Exited);
    ASSERT_EQ(fresh.exit_code, 1);
    const auto expected = readText(report);
    arguments.insert(arguments.end(), {"--checkpoint-dir", (root / "cli-checkpoint").string()});
    std::vector<llvm::StringRef> raw(arguments.begin(), arguments.end());
    const std::array<std::optional<llvm::StringRef>, 3> streams{{redirects[0], redirects[1], redirects[2]}};
    std::string launch_error;
    bool launch_failed = false;
    const auto child = llvm::sys::ExecuteNoWait(tool.string(), raw, std::nullopt, streams, 0, &launch_error, &launch_failed);
    ASSERT_FALSE(launch_failed) << launch_error;
    ASSERT_GT(child.Pid, 0);
    // Gracefully interrupt the actual CLI, allowing its existing owner to
    // terminate/reap the active worker. Never use a second owner for that PID.
    bool interrupted = false;
    int status = 0;
    pid_t waited = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);
    while (std::chrono::steady_clock::now() < deadline) {
        waited = ::waitpid(child.Pid, &status, WNOHANG);
        if (waited < 0 && errno == EINTR) continue;
        if (waited != 0) break;
        if (!interrupted && readText(errors).find("checkpoint: saved worker=1/" + total) != std::string::npos) {
            EXPECT_EQ(::kill(child.Pid, SIGTERM), 0);
            interrupted = true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    if (waited == 0) {
        ::kill(child.Pid, SIGKILL);
        do { waited = ::waitpid(child.Pid, &status, 0); } while (waited < 0 && errno == EINTR);
        ADD_FAILURE() << "checkpoint CLI did not stop before the bounded deadline";
    }
    ASSERT_EQ(waited, child.Pid);
    ASSERT_TRUE(interrupted) << readText(errors);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(WEXITSTATUS(status), 2);
    ASSERT_TRUE(fs::exists(root / "cli-checkpoint/manifest.csk-checkpoint"));
    arguments.push_back("--resume");
    const auto resumed = runResourceWorker(tool.string(), arguments, redirects, limits);
    ASSERT_EQ(resumed.stop, ResourceStop::Exited) << resumed.detail << readText(errors);
    ASSERT_EQ(resumed.exit_code, 1) << readText(errors);
    EXPECT_EQ(readText(report), expected);
    EXPECT_NE(readText(errors).find("checkpoint: replayed worker=1/" + total), std::string::npos);
    EXPECT_NE(readText(errors).find("checkpoint: saved worker=" + total + '/' + total), std::string::npos);
}

INSTANTIATE_TEST_SUITE_P(PlainAndWholeProgramPrepass, CheckpointInterruptTest, ::testing::Values(false, true));

TEST_F(AnalysisCacheTest, CheckpointParentFilesBindConsumedBytesAbsenceAndSummaryFreshness) {
    const auto source = file("a.cpp", "int finding(){int *p=nullptr;return *p;}\n");
    database();
    const auto config_file = root / "settings.conf";
    const auto list = root / "files.txt", model = root / "model.txt";
    const auto summary = root / "summary.txt", baseline = root / "baseline.txt";
    { std::ofstream out(config_file, std::ios::binary); out << "min_severity=warning\n"; }
    { std::ofstream out(list, std::ios::binary); out << source.string() << '\n'; }
    for (const auto& path : {model, summary}) {
        std::ofstream out(path, std::ios::binary); out << "codeskeptic-summaries v2\nkeep/1\tN\tR\tU\n";
    }
    { std::ofstream out(baseline, std::ios::binary); out << "# codeskeptic-baseline v3\n"; }
    fs::last_write_time(summary, fs::last_write_time(source) + std::chrono::hours(1));
    const auto tool = root / "checkpoint-worker";
    fs::copy_file(CODESKEPTIC_BINARY_PATH, tool);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    std::vector<std::string> settings{"--files", list.string(), "--model-file", model.string(),
        "--summary-in", summary.string(), "--baseline", baseline.string(),
        "--checkpoint-dir", (root / "checkpoint").string()};
    const auto fresh = scan(tool.string(), settings, false, {}, config_file);
    ASSERT_TRUE(fresh.result.complete());
    settings.push_back("--resume");
    const auto control = scan(tool.string(), settings, false, {}, config_file);
    ASSERT_TRUE(control.result.complete()); EXPECT_EQ(control.report, fresh.report);
    // Every mutated file remains parseable and retains its timestamp. Exact
    // consumed bytes, not effective options or worker-request equivalence alone,
    // must invalidate the run before any saved worker is replayed.
    for (const auto& path : {config_file, list, model, summary, baseline, root / "build/compile_commands.json"}) {
        SCOPED_TRACE(path.string());
        const auto original = readText(path);
        const auto stamp = fs::last_write_time(path);
        std::string changed;
        for (const char c : original) { if (c == '\n') changed += '\r'; changed += c; }
        if (changed == original) changed += ' '; // compact JSON: valid trailing whitespace
        { std::ofstream out(path, std::ios::binary); out << changed; }
        fs::last_write_time(path, stamp);
        ::testing::internal::CaptureStderr();
        const auto rejected = scan(tool.string(), settings, false, {}, config_file);
        const auto errors = ::testing::internal::GetCapturedStderr();
        EXPECT_EQ(rejected.result.exitCode(), 2) << errors;
        EXPECT_EQ(rejected.result.analyzed_tus, 0u);
        EXPECT_EQ(rejected.report, fresh.report);
        EXPECT_NE(errors.find("checkpoint_run_identity_changed"), std::string::npos) << errors;
        { std::ofstream out(path, std::ios::binary); out << original; }
        fs::last_write_time(path, stamp);
    }
    const auto stamp = fs::last_write_time(summary);
    fs::last_write_time(summary, fs::last_write_time(source) - std::chrono::hours(1));
    EXPECT_EQ(scan(tool.string(), settings, false, {}, config_file).result.exitCode(), 2);
    EXPECT_EQ(readText(root / "report.json"), fresh.report);
    fs::last_write_time(summary, stamp);
    // Optional missing configuration becoming present is a change even if the
    // new empty file leaves every effective option identical.
    const auto absent = root / "optional.conf";
    const std::vector<std::string> empty_settings{"--checkpoint-dir", (root / "absence-checkpoint").string()};
    const auto absent_run = scan(tool.string(), empty_settings, false, {}, absent);
    ASSERT_TRUE(absent_run.result.complete());
    { std::ofstream out(absent, std::ios::binary); }
    auto resume_absent = empty_settings; resume_absent.push_back("--resume");
    EXPECT_EQ(scan(tool.string(), resume_absent, false, {}, absent).result.exitCode(), 2);
    EXPECT_EQ(readText(root / "report.json"), absent_run.report);
}

TEST_F(AnalysisCacheTest, CheckpointInnerRecordsAreStrictAndMissingWorkersMustExecute) {
    file("a.cpp", "int first(){int *p=nullptr;return *p;}\n");
    const auto pending = file("b.cpp", "int second(){int *p=nullptr;return *p;}\n");
    database();
    const auto tool = root / "checkpoint-worker";
    fs::copy_file(CODESKEPTIC_BINARY_PATH, tool);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    const auto directory = root / "checkpoint";
    const std::vector<std::string> settings{"--checkpoint-dir", directory.string()};
    const auto fresh = scan(tool.string(), settings);
    ASSERT_TRUE(fresh.result.complete());
    std::string payload;
    {
        CheckpointStore store(directory.string(), 268435456);
        ASSERT_TRUE(store.open(true, payload)) << store.state();
    }
    // Independently split the length-prefixed run fields. Re-publish mutations
    // through the real store so the outer checksum remains valid: these must
    // fail the inner run/worker contract, not merely the disk checksum.
    std::vector<std::string> fields;
    for (std::size_t at = 0; at < payload.size();) {
        ASSERT_GE(payload.size() - at, 4u);
        std::uint32_t size = 0;
        for (unsigned i = 0; i < 4; ++i)
            size |= std::uint32_t(static_cast<unsigned char>(payload[at++])) << (8 * i);
        ASSERT_LE(size, payload.size() - at);
        fields.push_back(payload.substr(at, size)); at += size;
    }
    ASSERT_EQ(fields.size(), 12u); ASSERT_EQ(fields[2], "2"); ASSERT_EQ(fields[7], "2");
    auto encode = [](const std::vector<std::string>& values) {
        std::string result;
        for (const auto& value : values) {
            for (unsigned i = 0; i < 4; ++i)
                result += static_cast<char>((value.size() >> (8 * i)) & 255);
            result += value;
        }
        return result;
    };
    auto publish = [&](const std::string& bytes) {
        CheckpointStore store(directory.string(), 268435456);
        std::string old;
        ASSERT_TRUE(store.open(true, old)) << store.state();
        ASSERT_EQ(store.save(bytes), DiskWriteResult::Committed) << store.state();
    };
    const std::vector<std::string> resume{"--checkpoint-dir", directory.string(), "--resume"};
    for (unsigned mutation = 0; mutation < 9; ++mutation) {
        SCOPED_TRACE(mutation);
        auto changed = fields;
        switch (mutation) {
        case 0: changed[9].clear(); break;
        case 1: changed[9] = "not a worker response"; break;
        case 2: std::swap(changed[8], changed[10]); std::swap(changed[9], changed[11]); break;
        case 3: changed[10] = changed[8]; changed[11] = changed[9]; break;
        case 4: changed.pop_back(); break;
        case 5: changed.push_back("trailing field"); break;
        case 6: changed[2] = "02"; break;
        case 7: changed[2] = "1"; break;
        case 8: changed[7] = "3"; break;
        }
        const auto bytes = encode(changed);
        publish(bytes);
        ::testing::internal::CaptureStderr();
        const auto rejected = scan(tool.string(), resume);
        const auto errors = ::testing::internal::GetCapturedStderr();
        EXPECT_EQ(rejected.result.exitCode(), 2) << errors;
        EXPECT_EQ(rejected.report, fresh.report);
        EXPECT_EQ(rejected.result.analyzed_tus, 0u);
        EXPECT_NE(errors.find("checkpoint rejected:"), std::string::npos);
    }
    auto prefix = fields;
    prefix[7] = "1"; prefix.resize(10);
    publish(encode(prefix));
    ::testing::internal::CaptureStderr();
    const auto resumed = scan(tool.string(), resume);
    const auto errors = ::testing::internal::GetCapturedStderr();
    ASSERT_TRUE(resumed.result.complete()) << errors;
    EXPECT_EQ(resumed.report, fresh.report);
    EXPECT_NE(errors.find("checkpoint: replayed worker=1/2"), std::string::npos);
    EXPECT_NE(errors.find("checkpoint: saved worker=2/2"), std::string::npos);
    // A pending TU has no completed response in this manifest. Its initial
    // inventory must still reject edits before replaying the saved first TU.
    publish(encode(prefix));
    const auto stamp = fs::last_write_time(pending);
    { std::ofstream out(pending, std::ios::binary); out << "int second(){return 42;}\n"; }
    fs::last_write_time(pending, stamp);
    const auto changed = scan(tool.string(), resume);
    EXPECT_EQ(changed.result.exitCode(), 2);
    EXPECT_EQ(changed.result.analyzed_tus, 0u);
    EXPECT_EQ(changed.report, fresh.report);
}

TEST_F(AnalysisCacheTest, CheckpointInvalidCompilationMustNotOpenAnyReportDestination) {
    const auto source = file("preserve.cpp", "int preserve(){return 42;}\n");
    database();
    const auto checkpoint = root / "checkpoint";
    fs::create_directory(checkpoint);
    const auto manifest = checkpoint / "manifest.csk-checkpoint";
    { std::ofstream out(manifest); out << "preserve manifest"; }
    const auto safe = root / "report-sentinel.json";
    { std::ofstream out(safe); out << "preserve report"; }
    for (const auto& path : {source, manifest, safe}) {
        const auto before = readText(path);
        const auto result = scan(CODESKEPTIC_BINARY_PATH,
            {"--build-path", (root / "missing-build").string(), "--checkpoint-dir", checkpoint.string(),
             "--resume", "--json", path.string()});
        EXPECT_EQ(result.result.exitCode(), 2);
        EXPECT_EQ(readText(path), before);
    }
}

TEST_F(AnalysisCacheTest, CheckpointProtectsSelectedCompilationDatabaseAndHardlinkOutputAlias) {
    file("source.cpp", "int value(){return 42;}\n");
    const auto tool = root / "checkpoint-worker";
    fs::copy_file(CODESKEPTIC_BINARY_PATH, tool);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    const auto database_path = root / "build/compile_commands.json";
    for (const bool hardlink : {false, true}) {
        SCOPED_TRACE(hardlink);
        database();
        const auto before = readText(database_path);
        const auto output = hardlink ? root / "database-alias.json" : database_path;
        if (hardlink) fs::create_hard_link(database_path, output);
        const auto result = scan(tool.string(), {"--checkpoint-dir",
            (root / (hardlink ? "link-checkpoint" : "direct-checkpoint")).string(), "--json", output.string()});
        EXPECT_EQ(result.result.exitCode(), 2);
        EXPECT_EQ(readText(database_path), before);
        EXPECT_EQ(readText(output), before);
    }
}

TEST_F(AnalysisCacheTest, CheckpointEmptyInputOrDisabledRulesPreservesExistingReport) {
    file("source.cpp", "int value(){return 42;}\n");
    database();
    const auto empty_list = root / "empty-files.txt";
    { std::ofstream out(empty_list); }
    const auto checkpoint = (root / "checkpoint").string();
    const auto report = root / "report.json";
    { std::ofstream out(report); out << "preserve previous output"; }
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--files", empty_list.string(),
        "--checkpoint-dir", checkpoint, "--resume"}).result.exitCode(), 2);
    EXPECT_EQ(readText(report), "preserve previous output");
    std::string disabled;
    for (const auto& capability : ruleCapabilities()) {
        if (!disabled.empty()) disabled += ',';
        disabled += capability.id;
    }
    EXPECT_EQ(scan(CODESKEPTIC_BINARY_PATH, {"--disable-rule", disabled,
        "--checkpoint-dir", checkpoint, "--resume"}).result.exitCode(), 2);
    EXPECT_EQ(readText(report), "preserve previous output");
}

TEST_F(AnalysisCacheTest, CheckpointBudgetsNeverPublishPartialWorkAsComplete) {
    file("a.cpp", "int first(){return 42;}\n");
    file("b.cpp", "int second(){return 43;}\n");
    database();
    const auto tool = root / "checkpoint-worker";
    fs::copy_file(CODESKEPTIC_BINARY_PATH, tool);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    const auto report = root / "report.json";
    { std::ofstream out(report); out << "prior complete report"; }
    const std::vector<std::pair<std::string, std::string>> limits{
        {"--checkpoint-units", "1"}, {"--checkpoint-bytes", "1"}, {"--worker-timeout-ms", "1"}};
    unsigned index = 0;
    for (const auto& limit : limits) {
        SCOPED_TRACE(limit.first);
        const auto directory = root / ("checkpoint-" + std::to_string(index++));
        const auto result = scan(tool.string(), {"--checkpoint-dir", directory.string(),
            limit.first, limit.second, "--accept-partial-coverage"});
        EXPECT_EQ(result.result.exitCode(), 2);
        EXPECT_FALSE(result.result.complete());
        EXPECT_EQ(result.result.analyzed_tus, 0u);
        EXPECT_EQ(readText(report), "prior complete report");
        EXPECT_FALSE(fs::exists(directory / "manifest.csk-checkpoint"));
        EXPECT_FALSE(fs::exists(directory / ".pending"));
    }
}

TEST_F(AnalysisCacheTest, DiskPreferencesCannotReuseHiddenMemoryOrAnotherDirectory) {
    file("persistent.cpp", "int finding(){ int* p=nullptr; return *p; }\n");
    database();
    const auto fresh = scan(CODESKEPTIC_BINARY_PATH);
    ASSERT_TRUE(fresh.result.complete());
    const auto memory = scan(CODESKEPTIC_BINARY_PATH, {"--analysis-cache"});
    EXPECT_EQ(memory.report, fresh.report);
    const auto directory = (root / "disk").string();
    const std::vector<std::string> settings{"--analysis-cache", "--analysis-cache-dir", directory};
    const auto first = scan(CODESKEPTIC_BINARY_PATH, settings);
    EXPECT_EQ(first.report, fresh.report);
    EXPECT_EQ(first.disk_cache.hits, 0u);
    ASSERT_EQ(first.disk_cache.writes, 1u);
    const auto second = scan(CODESKEPTIC_BINARY_PATH, settings);
    EXPECT_EQ(second.report, fresh.report);
    EXPECT_EQ(second.disk_cache.hits, 1u);
    EXPECT_EQ(second.disk_cache.writes, 0u);
    const auto elsewhere = scan(CODESKEPTIC_BINARY_PATH,
        {"--analysis-cache", "--analysis-cache-dir", (root / "other").string()});
    EXPECT_EQ(elsewhere.report, fresh.report);
    EXPECT_EQ(elsewhere.disk_cache.hits, 0u);
    EXPECT_EQ(elsewhere.disk_cache.writes, 1u);
    const auto tight = scan(CODESKEPTIC_BINARY_PATH,
        {"--analysis-cache", "--analysis-cache-dir", directory, "--analysis-cache-bytes", "1"});
    EXPECT_EQ(tight.report, fresh.report);
    EXPECT_EQ(tight.disk_cache.hits, 0u);
    EXPECT_GT(tight.disk_cache.capacity, 0u);
    EXPECT_TRUE(fs::is_empty(directory));
    const auto disabled = scan(CODESKEPTIC_BINARY_PATH,
        {"--analysis-cache-dir", (root / "never-created").string(), "--no-analysis-cache"});
    EXPECT_EQ(disabled.report, fresh.report);
    EXPECT_FALSE(fs::exists(root / "never-created"));
}

TEST_F(AnalysisCacheTest, SeparateCliProcessesPersistAndCorruptionFallsBackToFreshAnalysis) {
    file("cli-cache.cpp", "int finding(){ int* p=nullptr; return *p; }\n");
    database();
    const auto report = (root / "cli-report.json").string();
    const auto output = (root / "cli-out.log").string();
    const auto errors = (root / "cli-errors.log").string();
    const auto directory = (root / "disk-cli").string();
    auto cli = [&](const std::vector<std::string>& options) {
        std::vector<std::string> args{CODESKEPTIC_BINARY_PATH, "--source", sources.front().string(),
            "--build-path", (root / "build").string(), "--json", report};
        args.insert(args.end(), options.begin(), options.end());
        std::vector<llvm::StringRef> refs(args.begin(), args.end());
        const std::array<std::optional<llvm::StringRef>, 3> redirects{{llvm::StringRef(""), output, errors}};
        std::string error;
        EXPECT_EQ(llvm::sys::ExecuteAndWait(CODESKEPTIC_BINARY_PATH, refs, std::nullopt, redirects, 30, 0, &error), 1)
            << error << readText(errors);
        return readText(report);
    };
    const auto fresh = cli({});
    ASSERT_FALSE(fresh.empty());
    const std::vector<std::string> settings{"--analysis-cache", "--analysis-cache-dir", directory};
    EXPECT_EQ(cli(settings), fresh);
    EXPECT_NE(readText(errors).find("writes=1"), std::string::npos) << readText(errors);
    EXPECT_EQ(cli(settings), fresh);
    EXPECT_NE(readText(errors).find("hits=1"), std::string::npos) << readText(errors);
    std::size_t entries = 0;
    for (const auto& entry : fs::directory_iterator(directory)) {
        ASSERT_EQ(entry.path().extension(), ".entry");
        std::ofstream(entry.path(), std::ios::binary | std::ios::trunc) << "corrupt";
        ++entries;
    }
    ASSERT_EQ(entries, 1u);
    EXPECT_EQ(cli(settings), fresh);
    EXPECT_NE(readText(errors).find("rejected=1"), std::string::npos) << readText(errors);
    EXPECT_NE(readText(errors).find("hits=0"), std::string::npos) << readText(errors);
    EXPECT_EQ(cli(settings), fresh);
    EXPECT_NE(readText(errors).find("hits=1"), std::string::npos) << readText(errors);
}

TEST_F(AnalysisCacheTest, SeparateMcpProcessesInheritDiskSettingsWithoutChangingRpcFrames) {
    const auto source = file("mcp-cache.cpp", "int finding(){ int* p=nullptr; return *p; }\n");
    database();
    const auto input = (root / "disk-mcp-input.jsonl").string();
    const auto output = (root / "disk-mcp-output.jsonl").string();
    const auto errors = (root / "disk-mcp-errors.log").string();
    std::string frames;
    llvm::raw_string_ostream stream(frames);
    stream << llvm::json::Value(llvm::json::Object{{"jsonrpc", "2.0"}, {"id", 1},
        {"method", "tools/call"}, {"params", llvm::json::Object{{"name", "analyze"},
            {"arguments", llvm::json::Object{{"path", source.string()}, {"build_path", (root / "build").string()}}}}}}) << '\n';
    stream << "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n";
    { std::ofstream file(input, std::ios::binary); file << frames; }
    auto mcp = [&](bool enabled) {
        std::vector<std::string> args{CODESKEPTIC_BINARY_PATH, "--serve"};
        if (enabled) args.insert(args.end(), {"--analysis-cache", "--analysis-cache-dir", (root / "disk-mcp").string()});
        std::vector<llvm::StringRef> refs(args.begin(), args.end());
        const std::array<std::optional<llvm::StringRef>, 3> redirects{{input, output, errors}};
        std::string error;
        EXPECT_EQ(llvm::sys::ExecuteAndWait(CODESKEPTIC_BINARY_PATH, refs, std::nullopt, redirects, 30, 0, &error), 0)
            << error << readText(errors);
        return readText(output);
    };
    const auto fresh = mcp(false);
    ASSERT_FALSE(fresh.empty());
    EXPECT_EQ(mcp(true), fresh);
    EXPECT_NE(readText(errors).find("writes=1"), std::string::npos) << readText(errors);
    EXPECT_EQ(mcp(true), fresh);
    EXPECT_NE(readText(errors).find("hits=1"), std::string::npos) << readText(errors);
    std::istringstream lines(fresh);
    std::string line;
    for (int id : {1, 2}) {
        ASSERT_TRUE(static_cast<bool>(std::getline(lines, line)));
        auto parsed = llvm::json::parse(line);
        ASSERT_TRUE(static_cast<bool>(parsed));
        ASSERT_NE(parsed->getAsObject(), nullptr);
        EXPECT_EQ(parsed->getAsObject()->getInteger("id"), id);
    }
    EXPECT_FALSE(static_cast<bool>(std::getline(lines, line)));
}

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

TEST_F(AnalysisCacheTest, RealSyscallFailuresPreservePrecommitTargetAndExposePostcommitUncertainty) {
    const auto source = file("disk-fault.cpp", "int finding(){ int* p=nullptr; return *p; }\n");
    database();
    const auto directory = (root / "disk-fault").string();
    const auto control = root / "fault-control";
    const auto report = (root / "fault-report.json").string();
    const auto output = (root / "fault-out.log").string();
    const auto errors = (root / "fault-errors.log").string();
    const auto module = root / "disk-fault-runtime.so";
    ASSERT_TRUE(fs::copy_file(CODESKEPTIC_RUNTIME_FIXTURE_ONE, module));
    // Like the existing loader fixtures: /tmp's coherent native identity and
    // an aged module are prerequisites, not a relaxation of runtime validation.
    std::this_thread::sleep_for(std::chrono::seconds(3));
    ScopedCacheEnvironment preload("LD_PRELOAD", module.string());
    ScopedCacheEnvironment target("CS_DISK_FAULT_DIR", directory);
    ScopedCacheEnvironment mode("CS_DISK_FAULT_CONTROL", control.string());
    auto invoke = [&](char fault, bool caching = true) {
        { std::ofstream file(control, std::ios::binary); file << fault; }
        std::vector<std::string> args{CODESKEPTIC_BINARY_PATH, "--source", source.string(),
            "--build-path", (root / "build").string(), "--json", report};
        if (caching) args.insert(args.end(), {"--analysis-cache", "--analysis-cache-dir", directory});
        std::vector<llvm::StringRef> refs(args.begin(), args.end());
        const std::array<std::optional<llvm::StringRef>, 3> redirects{{llvm::StringRef(""), output, errors}};
        std::string error;
        EXPECT_EQ(llvm::sys::ExecuteAndWait(CODESKEPTIC_BINARY_PATH, refs, std::nullopt, redirects, 30, 0, &error), 1)
            << error << readText(errors);
        return readText(report);
    };
    const auto initial = invoke('0');
    ASSERT_NE(readText(errors).find("writes=1"), std::string::npos) << readText(errors);
    const auto first = fs::directory_iterator(directory);
    ASSERT_NE(first, fs::directory_iterator{});
    const auto entry = first->path();
    const auto old = readText(entry);
    // Source content changes, not the request/key/environment. An old candidate
    // must be rejected by the child, so this genuinely attempts replacement.
    { std::ofstream file(source, std::ios::binary | std::ios::app); file << "// changed\n"; }
    const auto changed_fresh = invoke('0', false);
    ASSERT_FALSE(changed_fresh.empty());
    for (char fault : {'f', 'r'}) {
        EXPECT_EQ(invoke(fault), changed_fresh);
        EXPECT_NE(readText(errors).find("state=write_failed"), std::string::npos) << readText(errors);
        EXPECT_NE(readText(errors).find("writes=0"), std::string::npos) << readText(errors);
        EXPECT_EQ(readText(entry), old);
        EXPECT_FALSE(fs::exists(fs::path(directory) / ".pending"));
    }
    EXPECT_EQ(invoke('d'), changed_fresh);
    EXPECT_NE(readText(errors).find("state=committed_durability_uncertain"), std::string::npos) << readText(errors);
    EXPECT_NE(readText(errors).find("writes=1"), std::string::npos) << readText(errors);
    EXPECT_NE(readText(entry), old); // committed; do not claim the old bytes survived
    EXPECT_FALSE(fs::exists(fs::path(directory) / ".pending"));
    EXPECT_EQ(invoke('0'), changed_fresh);
    EXPECT_NE(readText(errors).find("hits=1"), std::string::npos) << readText(errors);
}

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
        const auto crashed_source = fs::canonical(sources[crashed]).string();
        EXPECT_EQ(isolated.result.sources[crashed].file, crashed_source);
        EXPECT_EQ(isolated.result.sources[crashed].reason, "worker_crashed");
        EXPECT_EQ(isolated.diagnostics.size(), 2u);
        for (const auto& finding : isolated.diagnostics)
            EXPECT_NE(finding.file, crashed_source);
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
        // This correctness test gives all three children the same deadline,
        // including process startup. 300ms also timed out a healthy survivor
        // in the retained Windows run. Keep 5s below the fixture's
        // 30s sleep. The independent 150ms timeout/kill/reap regression remains.
        const auto result = scan(CODESKEPTIC_RESOURCE_FIXTURE_PATH,
            {"--worker-timeout-ms", "5000", "--worker-memory-mb", "512",
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
