#include "analyzer/WorkerProtocol.h"
#include "analyzer/AnalysisCoordinator.h"
#include <filesystem>
#include <fstream>
#include <cstdlib>
#include <stdexcept>

#ifdef CODESKEPTIC_WORKER_TEST_CHILD

// Faults exist ONLY in this separately built test executable, never production
// flags/environment or analyzer rules. Normal requests still execute real code.
int main(int argc, char** argv) {
    using namespace codeskeptic;
    if (argc != 4 || std::string(argv[1]) != "--codeskeptic-worker-v1") return 2;
    std::string packet, error;
    WorkerRequest request;
    if (!readWorkerPacket(argv[2], packet, error) || !decodeWorkerRequest(packet, request, error)) return 2;
    const auto name = std::filesystem::path(request.source).filename().string();
    if (name.find("crash.") != std::string::npos && name.find("after-") == std::string::npos) std::abort();
    if (name.find("missing.") != std::string::npos) return 0;
    if (name.find("malformed.") != std::string::npos) {
        return writeWorkerPacket(argv[3], "not a worker packet", error) ? 0 : 2;
    }
    if (name.find("oversized.") != std::string::npos) {
        std::ofstream output(argv[3], std::ios::binary);
        output.seekp(kWorkerPacketLimit);
        output.put('x');
        output.close();
        return output.fail() ? 2 : 0;
    }
    const auto status = runAnalysisWorker(argv[2], argv[3]);
    if (status) return status;
    if (name.find("after-crash.") != std::string::npos) std::abort();
    if (name.find("after-nonzero.") != std::string::npos) return 7;
    if (name.find("truncated.") != std::string::npos || name.find("version.") != std::string::npos ||
        name.find("source.") != std::string::npos || name.find("reason.") != std::string::npos) {
        std::string result;
        if (!readWorkerPacket(argv[3], result, error)) return 2;
        if (name.find("truncated.") != std::string::npos) result.pop_back();
        else if (name.find("version.") != std::string::npos) result[7] = '2';
        else {
            WorkerResponse response;
            if (!decodeWorkerResponse(result, request, workerRequestDigest(packet), response, error)) return 2;
            if (name.find("reason.") != std::string::npos) response.coverage.reason = "frontend_failed";
            else response.coverage.file += ".wrong";
            result = encodeWorkerResponse(response);
        }
        return writeWorkerPacket(argv[3], result, error) ? 0 : 2;
    }
    return 0;
}

#else

#include <gtest/gtest.h>
#include <llvm/ADT/SmallString.h>
#include <llvm/Support/FileSystem.h>
#include <limits>

namespace {
using namespace codeskeptic;

WorkerRequest sampleRequest() {
    WorkerRequest request;
    request.ordinal = 7;
    request.source = (std::filesystem::temp_directory_path() / "worker path" / "source.cpp").string();
    request.build_directory = std::filesystem::temp_directory_path().string();
    request.commands.emplace_back(request.build_directory, request.source,
        std::vector<std::string>{"clang++", "-DVARIANT=1", "-c", request.source}, "one.o");
    request.commands.emplace_back(request.build_directory, request.source,
        std::vector<std::string>{"clang++", "-DVARIANT=2", "-c", request.source}, "two.o");
    request.arguments = {"--lang", "tr", "--function", "space::function"};
    request.producers = {"bounds", "div-by-zero"};
    request.selected_families = {"bounds", "div-by-zero"};
    request.global_summaries = "opaque test snapshot";
    request.harvest = true;
    return request;
}

WorkerResponse sampleResponse(const WorkerRequest& request) {
    WorkerResponse response;
    response.request_digest = workerRequestDigest(encodeWorkerRequest(request));
    response.ordinal = request.ordinal;
    response.phase = request.phase;
    response.coverage.file = request.source;
    response.coverage.status = SourceStatus::Analyzed;
    response.coverage.reason = "analyzed";
    response.coverage.commands = response.coverage.analyzed_commands = request.commands.size();
    Diagnostic diagnostic{};
    diagnostic.severity = Severity::Error;
    diagnostic.file = "header with space.h";
    diagnostic.line = 15;
    diagnostic.column = 7;
    diagnostic.rule_id = "out-of-bounds";
    diagnostic.message = std::string("bytes\0\xff", 7);
    diagnostic.function = "ns::function";
    diagnostic.notes = {{"other header.h", 2, 9, "origin"}, {"input.cpp", 4, 1, "use"}};
    diagnostic.kind = FindingKind::BoundsRead;
    diagnostic.additional_kinds = {FindingKind::BoundsWrite, FindingKind::BoundsAddress};
    diagnostic.fingerprint = "site identity";
    diagnostic.baseline_function = "csb-fn1:test signature";
    response.diagnostics.push_back(diagnostic);
    response.gaps = {{"first", CoverageGap::CfgUnavailable}, {"second", CoverageGap::NonConvergence}};
    response.global_summaries = request.global_summaries;
    return response;
}

TEST(WorkerProtocolTest, RequestRoundTripPreservesFrozenVariantsAndSettings) {
    auto expected = sampleRequest();
    WorkerRequest decoded;
    std::string error;
    ASSERT_TRUE(decodeWorkerRequest(encodeWorkerRequest(expected), decoded, error)) << error;
    EXPECT_EQ(decoded.ordinal, expected.ordinal);
    EXPECT_EQ(decoded.source, expected.source);
    EXPECT_EQ(decoded.build_directory, expected.build_directory);
    EXPECT_EQ(decoded.phase, expected.phase);
    EXPECT_EQ(decoded.synthetic, expected.synthetic);
    EXPECT_EQ(decoded.arguments, expected.arguments);
    EXPECT_EQ(decoded.producers, expected.producers);
    EXPECT_EQ(decoded.selected_families, expected.selected_families);
    EXPECT_EQ(decoded.global_summaries, expected.global_summaries);
    EXPECT_TRUE(decoded.harvest);
    ASSERT_EQ(decoded.commands.size(), 2u);
    for (std::size_t i = 0; i < decoded.commands.size(); ++i) {
        EXPECT_EQ(decoded.commands[i].Directory, expected.commands[i].Directory);
        EXPECT_EQ(decoded.commands[i].Filename, expected.commands[i].Filename);
        EXPECT_EQ(decoded.commands[i].Output, expected.commands[i].Output);
        EXPECT_EQ(decoded.commands[i].CommandLine, expected.commands[i].CommandLine);
    }
}

TEST(WorkerProtocolTest, ResponsePreservesEveryFindingFieldAndCoverageGap) {
    const auto request = sampleRequest();
    const auto expected = sampleResponse(request);
    WorkerResponse decoded;
    std::string error;
    ASSERT_TRUE(decodeWorkerResponse(encodeWorkerResponse(expected), request,
                                    expected.request_digest, decoded, error)) << error;
    ASSERT_EQ(decoded.diagnostics.size(), 1u);
    const auto& actual = decoded.diagnostics.front();
    const auto& wanted = expected.diagnostics.front();
    EXPECT_EQ(actual, wanted);
    EXPECT_EQ(actual.function, wanted.function);
    EXPECT_EQ(actual.fingerprint, wanted.fingerprint);
    EXPECT_EQ(actual.kind, wanted.kind);
    EXPECT_EQ(actual.additional_kinds, wanted.additional_kinds);
    EXPECT_EQ(actual.baseline_function, wanted.baseline_function);
    ASSERT_EQ(actual.notes.size(), wanted.notes.size());
    for (std::size_t i = 0; i < actual.notes.size(); ++i) {
        EXPECT_EQ(actual.notes[i].file, wanted.notes[i].file);
        EXPECT_EQ(actual.notes[i].line, wanted.notes[i].line);
        EXPECT_EQ(actual.notes[i].column, wanted.notes[i].column);
        EXPECT_EQ(actual.notes[i].message, wanted.notes[i].message);
    }
    EXPECT_EQ(decoded.coverage.analyzed_commands, 2u);
    ASSERT_EQ(decoded.gaps.size(), 2u);
    EXPECT_EQ(decoded.gaps[0].function, "first");
    EXPECT_EQ(decoded.gaps[0].gap, CoverageGap::CfgUnavailable);
    EXPECT_EQ(decoded.gaps[1].gap, CoverageGap::NonConvergence);
}

TEST(WorkerProtocolTest, EveryTruncatedRequestOrResultFailsTransactionally) {
    const auto request = sampleRequest();
    const auto response = sampleResponse(request);
    const auto input = encodeWorkerRequest(request), output = encodeWorkerResponse(response);
    std::string error;
    for (std::size_t size = 0; size < input.size(); ++size) {
        WorkerRequest untouched;
        untouched.source = "sentinel";
        ASSERT_FALSE(decodeWorkerRequest(input.substr(0, size), untouched, error)) << size;
        ASSERT_EQ(untouched.source, "sentinel");
    }
    for (std::size_t size = 0; size < output.size(); ++size) {
        WorkerResponse untouched;
        untouched.ordinal = 999;
        ASSERT_FALSE(decodeWorkerResponse(output.substr(0, size), request,
                                         response.request_digest, untouched, error)) << size;
        ASSERT_EQ(untouched.ordinal, 999u);
    }
}

TEST(WorkerProtocolTest, UnknownVersionsBuildIdentityAndTrailingBytesFail) {
    const auto request = sampleRequest();
    const auto response = sampleResponse(request);
    for (int mutation = 0; mutation < 3; ++mutation) {
        auto input = encodeWorkerRequest(request), output = encodeWorkerResponse(response);
        if (mutation == 0) input[7] = output[7] = '9';
        if (mutation == 1) input[12] = output[12] = '?';
        if (mutation == 2) { input += '\0'; output += '\0'; }
        WorkerRequest decoded_request;
        WorkerResponse decoded_response;
        std::string error;
        EXPECT_FALSE(decodeWorkerRequest(input, decoded_request, error));
        EXPECT_FALSE(decodeWorkerResponse(output, request, response.request_digest, decoded_response, error));
    }
}

TEST(WorkerProtocolTest, EmptyInputsNulArgumentsAndSyntheticVariantsFail) {
    for (int mutation = 0; mutation < 5; ++mutation) {
        auto request = sampleRequest();
        if (mutation == 0) request.source.clear();
        if (mutation == 1) request.commands.clear();
        if (mutation == 2) request.commands.front().CommandLine.clear();
        if (mutation == 3) request.commands.front().CommandLine.push_back(std::string("bad\0arg", 7));
        if (mutation == 4) request.synthetic = true;
        WorkerRequest decoded;
        std::string error;
        EXPECT_FALSE(decodeWorkerRequest(encodeWorkerRequest(request), decoded, error)) << mutation;
    }
}

TEST(WorkerProtocolTest, IdentityAndCoverageContradictionsCannotProduceSuccess) {
    const auto request = sampleRequest();
    for (int mutation = 0; mutation < 10; ++mutation) {
        auto response = sampleResponse(request);
        const auto digest = response.request_digest;
        if (mutation == 0) response.request_digest = "different";
        if (mutation == 1) ++response.ordinal;
        if (mutation == 2) response.phase = WorkerPhase::Harvest;
        if (mutation == 3) response.coverage.file += ".different";
        if (mutation == 4) ++response.coverage.commands;
        if (mutation == 5) --response.coverage.analyzed_commands;
        if (mutation == 6) response.coverage.status = SourceStatus::Failed;
        if (mutation == 7) response.coverage.recovery_commands = 3;
        if (mutation == 8) response.coverage.prepass_status = "analyzed";
        if (mutation == 9) response.coverage.reason.clear();
        WorkerResponse decoded;
        std::string error;
        EXPECT_FALSE(decodeWorkerResponse(encodeWorkerResponse(response), request, digest, decoded, error)) << mutation;
    }
}

TEST(WorkerProtocolTest, InvalidEnumsAndOversizedFieldsAreNotEncoded) {
    auto request = sampleRequest();
    request.phase = static_cast<WorkerPhase>(99);
    EXPECT_THROW(encodeWorkerRequest(request), std::runtime_error);
    request = sampleRequest();
    auto response = sampleResponse(request);
    response.diagnostics.front().kind = static_cast<FindingKind>(99);
    EXPECT_THROW(encodeWorkerResponse(response), std::runtime_error);
    request.global_summaries.assign(kWorkerFieldLimit + 1, 'x');
    EXPECT_THROW(encodeWorkerRequest(request), std::runtime_error);
}

TEST(WorkerProtocolTest, ContradictoryFailureReasonsCannotClaimAnalyzedCoverage) {
    const auto request = sampleRequest();
    for (const std::string reason : {"frontend_failed", "worker_crashed", "error_recovery_ast"}) {
        auto response = sampleResponse(request);
        response.coverage.reason = reason;
        WorkerResponse decoded;
        std::string error;
        EXPECT_FALSE(decodeWorkerResponse(encodeWorkerResponse(response), request,
                                         response.request_digest, decoded, error)) << reason;
    }
}

TEST(WorkerProtocolTest, DigestBindsCommandOrderFlagsAndSummaryState) {
    auto request = sampleRequest();
    const auto first = workerRequestDigest(encodeWorkerRequest(request));
    EXPECT_EQ(first.size(), 64u);
    std::swap(request.commands[0], request.commands[1]);
    EXPECT_NE(first, workerRequestDigest(encodeWorkerRequest(request)));
    request = sampleRequest();
    request.commands[0].CommandLine.push_back("-DCHANGED=1");
    EXPECT_NE(first, workerRequestDigest(encodeWorkerRequest(request)));
    request = sampleRequest();
    request.global_summaries += "changed";
    EXPECT_NE(first, workerRequestDigest(encodeWorkerRequest(request)));
}

TEST(WorkerProtocolTest, RecoveryRequiresExactRequestOptInAndConsistentSkippedState) {
    auto request = sampleRequest();
    auto response = sampleResponse(request);
    response.coverage.recovery_commands = 1;
    response.coverage.reason = "error_recovery_ast";
    WorkerResponse decoded;
    std::string error;
    EXPECT_FALSE(decodeWorkerResponse(encodeWorkerResponse(response), request,
                                     response.request_digest, decoded, error));
    request.arguments.push_back("--analyze-broken-tus");
    response.request_digest = workerRequestDigest(encodeWorkerRequest(request));
    EXPECT_TRUE(decodeWorkerResponse(encodeWorkerResponse(response), request,
                                    response.request_digest, decoded, error)) << error;
    response.coverage.status = SourceStatus::Skipped;
    response.coverage.reason = "broken_translation_unit";
    response.coverage.recovery_commands = 0;
    response.coverage.analyzed_commands = 1;
    response.coverage.skipped_commands = 1;
    EXPECT_FALSE(decodeWorkerResponse(encodeWorkerResponse(response), request,
                                     response.request_digest, decoded, error));
}

} // namespace
#endif
