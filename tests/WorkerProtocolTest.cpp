#include "analyzer/WorkerProtocol.h"
#include "analyzer/WorkerRuntime.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

using namespace codeskeptic;

namespace {

std::filesystem::path tempPath(const char* name) {
    return std::filesystem::path(::testing::TempDir()) / name;
}

WorkerRequest sampleRequest(const std::filesystem::path& response) {
    WorkerRequest request;
    request.request_id = "request-1";
    request.unit.canonical_path = "/project/a file.cpp";
    request.unit.working_directory = "/project/build";
    request.unit.command_line = {
        "clang++", "-DVALUE=a b", "../a file.cpp"};
    request.unit.output = "a.o";
    request.unit.compile_command_sha256 =
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef";
    request.unit.command_ordinal = 2;
    request.phase = TranslationUnitPhase::Analysis;
    request.config_arguments = {"--lang", "tr", "--severity", "warning"};
    request.response_path = response.string();
    request.summary_fragment_path = response.string() + ".summary";
    return request;
}

} // anonymous namespace

TEST(WorkerProtocolTest, RequestRoundTripPreservesExactCommandIdentity) {
    const auto path = tempPath("codeskeptic-worker-request.json");
    const auto response = tempPath("codeskeptic-worker-response.json");
    const WorkerRequest expected = sampleRequest(response);
    std::string error;

    ASSERT_TRUE(writeWorkerRequest(path.string(), expected, error)) << error;
    WorkerRequest actual;
    ASSERT_TRUE(readWorkerRequest(path.string(), actual, error)) << error;

    EXPECT_EQ(actual.request_id, expected.request_id);
    EXPECT_EQ(actual.phase, expected.phase);
    EXPECT_EQ(actual.unit.canonical_path, expected.unit.canonical_path);
    EXPECT_EQ(actual.unit.working_directory, expected.unit.working_directory);
    EXPECT_EQ(actual.unit.command_line, expected.unit.command_line);
    EXPECT_EQ(actual.unit.output, expected.unit.output);
    EXPECT_EQ(actual.unit.compile_command_sha256,
              expected.unit.compile_command_sha256);
    EXPECT_EQ(actual.unit.command_ordinal, expected.unit.command_ordinal);
    EXPECT_EQ(actual.config_arguments, expected.config_arguments);
    EXPECT_EQ(actual.response_path, expected.response_path);
    EXPECT_EQ(actual.summary_fragment_path,
              expected.summary_fragment_path);
}

TEST(WorkerProtocolTest, ResponseRejectsIdentityDriftBeforeAggregation) {
    const auto path = tempPath("codeskeptic-worker-identity-response.json");
    const WorkerRequest expected = sampleRequest(path);
    WorkerResponse response;
    response.request_id = expected.request_id;
    response.canonical_path = expected.unit.canonical_path;
    response.compile_command_sha256 = expected.unit.compile_command_sha256;
    response.command_ordinal = expected.unit.command_ordinal;
    response.phase = expected.phase;
    response.analysis.attempted_tus = 1;
    response.analysis.analyzed_tus = 1;
    response.analysis.findings = 1;
    response.diagnostics.push_back(Diagnostic{
        Severity::Warning, expected.unit.canonical_path, 7, 3,
        "null-deref", "possible null dereference", "f", {}, "csf1:test"});
    std::string error;

    ASSERT_TRUE(writeWorkerResponse(path.string(), response, error)) << error;
    WorkerResponse accepted;
    ASSERT_TRUE(readWorkerResponse(path.string(), expected, accepted, error))
        << error;
    ASSERT_EQ(accepted.diagnostics.size(), 1u);
    EXPECT_EQ(accepted.diagnostics[0].fingerprint, "csf1:test");

    response.command_ordinal += 1;
    ASSERT_TRUE(writeWorkerResponse(path.string(), response, error)) << error;
    EXPECT_FALSE(readWorkerResponse(path.string(), expected, accepted, error));
    EXPECT_NE(error.find("identity"), std::string::npos);
}

TEST(WorkerProtocolTest, ResponseRejectsFindingCountDrift) {
    const auto path = tempPath("codeskeptic-worker-count-response.json");
    const WorkerRequest expected = sampleRequest(path);
    WorkerResponse response;
    response.request_id = expected.request_id;
    response.canonical_path = expected.unit.canonical_path;
    response.compile_command_sha256 = expected.unit.compile_command_sha256;
    response.command_ordinal = expected.unit.command_ordinal;
    response.phase = expected.phase;
    response.analysis.attempted_tus = 1;
    response.analysis.analyzed_tus = 1;
    response.analysis.findings = 2;
    response.diagnostics.push_back(Diagnostic{
        Severity::Warning, expected.unit.canonical_path, 7, 3,
        "null-deref", "possible null dereference", "f", {}, "csf1:test"});
    std::string error;

    ASSERT_TRUE(writeWorkerResponse(path.string(), response, error)) << error;
    WorkerResponse accepted;
    EXPECT_FALSE(readWorkerResponse(path.string(), expected, accepted, error));
    EXPECT_NE(error.find("count"), std::string::npos) << error;
}

TEST(WorkerProtocolTest, ResponseRejectsManufacturedExactTuCoverage) {
    const auto path = tempPath("codeskeptic-worker-coverage-response.json");
    const WorkerRequest expected = sampleRequest(path);
    WorkerResponse response;
    response.request_id = expected.request_id;
    response.canonical_path = expected.unit.canonical_path;
    response.compile_command_sha256 = expected.unit.compile_command_sha256;
    response.command_ordinal = expected.unit.command_ordinal;
    response.phase = expected.phase;
    response.analysis.attempted_tus = 2;
    response.analysis.analyzed_tus = 2;
    std::string error;

    ASSERT_TRUE(writeWorkerResponse(path.string(), response, error)) << error;
    WorkerResponse accepted;
    EXPECT_FALSE(readWorkerResponse(path.string(), expected, accepted, error));
    EXPECT_NE(error.find("exact-TU"), std::string::npos) << error;

    response.analysis.attempted_tus = 1;
    response.analysis.analyzed_tus = 1;
    response.analysis.no_inputs = true;
    ASSERT_TRUE(writeWorkerResponse(path.string(), response, error)) << error;
    EXPECT_FALSE(readWorkerResponse(path.string(), expected, accepted, error));
    EXPECT_NE(error.find("exact-TU"), std::string::npos) << error;
}

TEST(WorkerProtocolTest, ResponseAllowsAnalyzedBrokenRecoveryOverlap) {
    const auto path = tempPath("codeskeptic-worker-recovery-response.json");
    const WorkerRequest expected = sampleRequest(path);
    WorkerResponse response;
    response.request_id = expected.request_id;
    response.canonical_path = expected.unit.canonical_path;
    response.compile_command_sha256 = expected.unit.compile_command_sha256;
    response.command_ordinal = expected.unit.command_ordinal;
    response.phase = expected.phase;
    response.analysis.attempted_tus = 1;
    response.analysis.analyzed_tus = 1;
    response.analysis.broken_tus = 1;
    std::string error;

    ASSERT_TRUE(writeWorkerResponse(path.string(), response, error)) << error;
    WorkerResponse accepted;
    ASSERT_TRUE(readWorkerResponse(path.string(), expected, accepted, error))
        << error;
    EXPECT_EQ(accepted.analysis.analyzed_tus, 1u);
    EXPECT_EQ(accepted.analysis.broken_tus, 1u);
    EXPECT_EQ(accepted.analysis.exitCode(), 2);
}

TEST(WorkerProtocolTest, UnknownOrWrongTypedFieldsFailClosed) {
    const auto path = tempPath("codeskeptic-worker-invalid-request.json");
    std::ofstream output(path, std::ios::binary);
    output << R"({"protocol":1,"request_id":"x","phase":"analysis",)"
              R"("unit":{},"config_arguments":[],"response_path":"x",)"
              R"("summary_fragment_path":"","unexpected":true})";
    output.close();

    WorkerRequest request;
    std::string error;
    EXPECT_FALSE(readWorkerRequest(path.string(), request, error));
    EXPECT_FALSE(error.empty());
}

TEST(WorkerProtocolTest, RuntimeAnalyzesExactlyTheBoundCommand) {
    const auto root = tempPath("codeskeptic-worker-runtime");
    std::filesystem::create_directories(root);
    const auto source = root / "clean.cpp";
    const auto request_path = root / "request.json";
    const auto response_path = root / "response.json";
    {
        std::ofstream output(source, std::ios::binary | std::ios::trunc);
        output << "int clean(int value) { return value + 1; }\n";
    }
    WorkerRequest request = sampleRequest(response_path);
    request.request_id = "runtime-clean";
    request.unit.canonical_path =
        std::filesystem::weakly_canonical(source).string();
    request.unit.working_directory = root.string();
    request.unit.command_line = {
        "clang++", "-std=c++17", "-fsyntax-only",
        request.unit.canonical_path};
    request.unit.output.clear();
    request.unit.command_ordinal = 0;
    request.unit.compile_command_sha256 =
        translationUnitCommandSha256(request.unit);
    request.summary_fragment_path.clear();
    std::string error;
    ASSERT_TRUE(writeWorkerRequest(request_path.string(), request, error))
        << error;

    ASSERT_EQ(runTranslationUnitWorker(request_path.string()), 0);
    WorkerResponse response;
    ASSERT_TRUE(readWorkerResponse(
        response_path.string(), request, response, error)) << error;
    EXPECT_EQ(response.analysis.attempted_tus, 1u);
    EXPECT_EQ(response.analysis.analyzed_tus, 1u);
    EXPECT_EQ(response.analysis.exitCode(), 0);
}

TEST(WorkerProtocolTest, RuntimeRejectsCommandHashDrift) {
    const auto root = tempPath("codeskeptic-worker-runtime-hash");
    std::filesystem::create_directories(root);
    const auto source = root / "clean.cpp";
    const auto request_path = root / "request.json";
    const auto response_path = root / "response.json";
    {
        std::ofstream output(source, std::ios::binary | std::ios::trunc);
        output << "int clean() { return 0; }\n";
    }
    WorkerRequest request = sampleRequest(response_path);
    request.unit.canonical_path =
        std::filesystem::weakly_canonical(source).string();
    request.unit.working_directory = root.string();
    request.unit.command_line = {
        "clang++", "-std=c++17", "-fsyntax-only",
        request.unit.canonical_path};
    request.unit.command_ordinal = 0;
    request.unit.compile_command_sha256 = std::string(64, '0');
    request.summary_fragment_path.clear();
    std::string error;
    ASSERT_TRUE(writeWorkerRequest(request_path.string(), request, error))
        << error;

    EXPECT_NE(runTranslationUnitWorker(request_path.string()), 0);
    EXPECT_FALSE(std::filesystem::exists(response_path));
}
