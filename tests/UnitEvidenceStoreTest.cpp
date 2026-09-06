#ifdef CODESKEPTIC_RUNTIME_TEST_MODULE
#include <cstdio>
#include <cstdlib>

// Private Linux loader fixture; no hooks or fault flags in the production tool.
__attribute__((constructor)) static void markRuntimeLoaded() {
    const auto* path = std::getenv("CS_CACHE_FIXTURE_MARKER");
    if (path) if (auto* output = std::fopen(path, "wb")) {
        std::fprintf(output, "%d", CODESKEPTIC_RUNTIME_TEST_MODULE);
        std::fclose(output);
    }
}

#elif defined(CODESKEPTIC_CACHE_TEST_CHILD)
#include "analyzer/AnalysisCoordinator.h"

int main(int argc, char** argv) {
    using namespace codeskeptic;
    if (argc != 4 || std::string(argv[1]) != "--codeskeptic-worker-v1") return 2;
    const auto status = runAnalysisWorker(argv[2], argv[3]);
    if (status) return status;
    std::string request_packet, response_packet, error;
    WorkerRequest request;
    WorkerResponse response;
    if (!readWorkerPacket(argv[2], request_packet, error) || !decodeWorkerRequest(request_packet, request, error) ||
        !readWorkerPacket(argv[3], response_packet, error) ||
        !decodeWorkerResponse(response_packet, request, workerRequestDigest(request_packet), response, error)) return 2;
    // An otherwise ordinary result lies about reuse even on unqualified hosts.
    // This separate fault executable must never make it past parent validation.
    response.cache_hit = true;
    if (response.input_witness.empty()) response.input_witness = "unqualified-test-witness";
    if (response.runtime_digest.empty()) response.runtime_digest = std::string(64, 'a');
    return writeWorkerPacket(argv[3], encodeWorkerResponse(response), error) ? 0 : 2;
}

#else
#include "source_manager/InputIdentity.h"
#include "analyzer/UnitEvidenceStore.h"
#include "analyzer/RuntimeIdentity.h"
#include <gtest/gtest.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#ifndef _WIN32
#include <sys/resource.h>
#endif

namespace fs = std::filesystem;
using namespace codeskeptic;

class InputIdentityTest : public ::testing::Test {
protected:
    fs::path root;
    void SetUp() override {
        root = fs::path(::testing::TempDir()) / ("codeskeptic-input-identity-" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        ASSERT_TRUE(fs::create_directory(root));
    }
    void TearDown() override { std::error_code error; fs::remove_all(root, error); }
    void write(const std::string& bytes) {
        std::ofstream file(root / "input.cpp", std::ios::binary);
        file << bytes;
        ASSERT_TRUE(file.good());
    }
    InputIdentity witness() {
        InputRecording recording(inputDigest("request"));
        auto buffer = recording.filesystem()->getBufferForFile((root / "input.cpp").string());
        EXPECT_TRUE(buffer);
        auto result = recording.finish();
        // Codec/store fixture: actual filesystem observations plus a synthetic
        // frontend identity. Production frontend collection is separately tested
        // by SourceManager and real subprocess integration tests.
        result.observations.push_back({InputObservationKind::Frontend, "fixture", inputDigest("frontend")});
        return result;
    }
};

TEST_F(InputIdentityTest, RefusedRecordingNeverSubstitutesAnEarlierRead) {
    write("AAAA");
    InputRecording recording(inputDigest("request"));
    auto vfs = recording.filesystem();
    auto first = vfs->getBufferForFile((root / "input.cpp").string());
    ASSERT_TRUE(first);
    ASSERT_EQ((*first)->getBuffer(), "AAAA");
    recording.refuse("unsupported_fixture");
    write("BBBB");
    auto second = vfs->getBufferForFile((root / "input.cpp").string());
    ASSERT_TRUE(second);
    EXPECT_EQ((*second)->getBuffer(), "BBBB");
    EXPECT_FALSE(recording.finish().reusable);
}

TEST_F(InputIdentityTest, VolatileRereadConsumesCurrentBytes) {
    write("AAAA");
    InputRecording recording(inputDigest("request"));
    auto vfs = recording.filesystem();
    auto first = vfs->getBufferForFile((root / "input.cpp").string());
    ASSERT_TRUE(first);
    write("BBBB");
    auto second = vfs->getBufferForFile((root / "input.cpp").string(), -1, true, true);
    ASSERT_TRUE(second);
    EXPECT_EQ((*second)->getBuffer(), "BBBB");
    EXPECT_FALSE(recording.finish().reusable);
}

TEST_F(InputIdentityTest, ContradictoryReadReturnsNewBytesButRefusesReuse) {
    write("AAAA");
    InputRecording recording(inputDigest("request"));
    auto vfs = recording.filesystem();
    const auto stamp = fs::last_write_time(root / "input.cpp");
    auto first = vfs->getBufferForFile((root / "input.cpp").string());
    ASSERT_TRUE(first);
    write("BBBB");
    fs::last_write_time(root / "input.cpp", stamp);
    auto second = vfs->getBufferForFile((root / "input.cpp").string());
    ASSERT_TRUE(second);
    EXPECT_EQ((*second)->getBuffer(), "BBBB");
    EXPECT_EQ((*first)->getBuffer(), "AAAA"); // owned bytes cannot change under the AST
    EXPECT_FALSE(recording.finish().reusable);
}

#ifndef _WIN32
TEST_F(InputIdentityTest, TransientOpenFailureCannotBecomeReusableStatusOnlyEvidence) {
    write("AAAA");
    InputRecording recording(inputDigest("request"));
    const auto path = (root / "input.cpp").string();
    ASSERT_TRUE(recording.filesystem()->status(path));
    struct rlimit original{};
    ASSERT_EQ(::getrlimit(RLIMIT_NOFILE, &original), 0);
    struct RestoreLimit {
        struct rlimit original;
        ~RestoreLimit() { ::setrlimit(RLIMIT_NOFILE, &original); }
    } restore{original};
    auto limited = original;
    limited.rlim_cur = 0;
    ASSERT_EQ(::setrlimit(RLIMIT_NOFILE, &limited), 0);
    // stat still works with no free descriptors. Restore the exact old soft
    // limit before assertions/teardown; the hard limit is never lowered.
    auto failed = recording.filesystem()->openFileForRead(path);
    const auto restored = ::setrlimit(RLIMIT_NOFILE, &original);
    ASSERT_EQ(restored, 0);
    ASSERT_FALSE(failed);
    EXPECT_EQ(failed.getError(), std::errc::too_many_files_open);
    EXPECT_FALSE(recording.finish().reusable);
    auto recovered = recording.filesystem()->getBufferForFile(path);
    ASSERT_TRUE(recovered);
    EXPECT_EQ((*recovered)->getBuffer(), "AAAA");
    EXPECT_FALSE(recording.finish().reusable);
}
#endif

TEST_F(InputIdentityTest, DirectoryFramingOverflowRefusesReuseWithoutTruncatingIteration) {
    const auto directory = root / "many";
    ASSERT_TRUE(fs::create_directory(directory));
    constexpr auto count = kInputObservationLimit - 1;
    constexpr auto path_bytes = kInputIdentityLimit / count - 4;
    ASSERT_LT(directory.string().size() + 10, path_bytes);
    const auto name_bytes = path_bytes - directory.string().size() - 1;
    ASSERT_LE(name_bytes, 255u);
    for (std::size_t i = 0; i < count; ++i) {
        auto name = std::to_string(i);
        name.resize(name_bytes, 'x');
        std::ofstream output(directory / name, std::ios::binary);
        ASSERT_TRUE(output.good());
    }
    InputRecording recording(inputDigest("request"));
    std::size_t seen = 0;
    std::error_code error;
    EXPECT_NO_THROW({
        auto iterator = recording.filesystem()->dir_begin(directory.string(), error);
        for (; !error && iterator != llvm::vfs::directory_iterator{}; iterator.increment(error)) ++seen;
    });
    EXPECT_FALSE(error);
    EXPECT_EQ(seen, count);
    EXPECT_FALSE(recording.finish().reusable);
}

TEST_F(InputIdentityTest, WitnessCodecRejectsTruncationDuplicatesAndUnknownKindsTransactionally) {
    write("int f(){return 42;}\n");
    auto identity = witness();
    ASSERT_TRUE(identity.matchesCurrent());
    auto bytes = encodeInputIdentity(identity);
    ASSERT_FALSE(bytes.empty());
    InputIdentity decoded;
    ASSERT_TRUE(decodeInputIdentity(bytes, decoded));
    EXPECT_TRUE(decoded.matchesCurrent());
    for (std::size_t length = 0; length < bytes.size(); ++length) {
        // A truncation exactly between observations could be a shorter witness,
        // but cannot discard the final required frontend field in this fixture.
        InputIdentity unchanged;
        unchanged.reason = "sentinel";
        EXPECT_FALSE(decodeInputIdentity(bytes.substr(0, length), unchanged)) << length;
        EXPECT_EQ(unchanged.reason, "sentinel");
    }
    auto duplicated = identity;
    duplicated.observations.push_back(duplicated.observations.front());
    EXPECT_FALSE(decodeInputIdentity(encodeInputIdentity(duplicated), decoded));
    auto unknown = identity;
    unknown.observations.front().kind = static_cast<InputObservationKind>(999);
    EXPECT_FALSE(decodeInputIdentity(encodeInputIdentity(unknown), decoded));
    EXPECT_FALSE(decodeInputIdentity(bytes + "trailing", decoded));
    EXPECT_FALSE(decodeInputIdentity(std::string(kInputIdentityLimit + 1, 'x'), decoded));
}

TEST_F(InputIdentityTest, StoreRejectsStaleWrongBoundAndUnwitnessedInputs) {
    write("AAAA");
    const auto identity = witness();
    const auto bytes = encodeInputIdentity(identity);
    UnitEvidenceStore store;
    EXPECT_FALSE(store.remember("key", identity.context, "packet", ""));
    EXPECT_FALSE(store.remember("key", inputDigest("different"), "packet", bytes));
    ASSERT_TRUE(store.remember("key", identity.context, "packet", bytes));
    EXPECT_EQ(store.lookup("key", identity.context), std::optional<std::string>("packet"));
    EXPECT_EQ(store.hits(), 1u);
    write("BBBB");
    EXPECT_FALSE(store.lookup("key", identity.context));
    EXPECT_EQ(store.entries(), 0u);
    EXPECT_FALSE(store.remember("key", identity.context, "packet", bytes));
}

TEST_F(InputIdentityTest, StoreBoundEvictionAndCancellationCannotInventHits) {
    write("AAAA");
    const auto identity = witness();
    const auto bytes = encodeInputIdentity(identity);
    UnitEvidenceStore store(4096, 1);
    ASSERT_TRUE(store.remember("one", identity.context, "first", bytes));
    EXPECT_FALSE(store.remember("huge", identity.context, std::string(4096, 'x'), bytes));
    ASSERT_EQ(store.entries(), 1u);
    EXPECT_FALSE(store.lookup("one", identity.context, [] { return true; }));
    EXPECT_EQ(store.hits(), 0u);
    EXPECT_EQ(store.entries(), 1u);
    ASSERT_TRUE(store.remember("two", identity.context, "second", bytes));
    EXPECT_FALSE(store.lookup("one", identity.context));
    EXPECT_EQ(store.lookup("two", identity.context), std::optional<std::string>("second"));
    EXPECT_LE(store.bytes(), 4096u);
}

TEST_F(InputIdentityTest, CancellationDuringAdmissionNeverPublishesAnEntry) {
    write("AAAA");
    const auto identity = witness();
    UnitEvidenceStore store;
    unsigned checks = 0;
    EXPECT_FALSE(store.remember("key", identity.context, "packet", encodeInputIdentity(identity),
                               [&] { return ++checks >= 2; }));
    EXPECT_GE(checks, 2u);
    EXPECT_EQ(store.entries(), 0u);
    EXPECT_EQ(store.hits(), 0u);
}

TEST(InputCommandIdentityTest, UnsupportedDriverAndForwardedInputsCannotClaimEligibility) {
    EXPECT_FALSE(cacheableCommand({"clang++", "-include", "@hidden.rsp", "input.cpp"}));
    EXPECT_FALSE(cacheableCommand({"clang-cl", "/Yuheader.h", "/Fpinput.pch", "input.cpp"}));
    EXPECT_FALSE(cacheableCommand({"cl.exe", "/clang:-fmodules", "input.cpp"}));
    EXPECT_FALSE(cacheableCommand({"clang++", "-Wp,-include,hidden.h", "input.cpp"}));
    EXPECT_FALSE(cacheableCommand({"clang++", "-ivfsoverlay", "overlay.yaml", "input.cpp"}));
    EXPECT_FALSE(cacheableCommand({"clang++", "-include-pch", "input.pch", "input.cpp"}));
    EXPECT_FALSE(cacheableCommand({"clang++", "-fmodules", "input.cpp"}));
    EXPECT_TRUE(cacheableCommand({"clang++", "-std=c++17", "-I", "include", "-DVALUE=1", "input.cpp"}));
}

TEST(InputCommandIdentityTest, OnlyPlainCAndCxxSourcesCanClaimEligibility) {
    for (const auto* language : {"ast", "ir", "assembler", "assembler-with-cpp", "c++-header"})
        EXPECT_FALSE(cacheableCommand({"clang++", "-x", language, "input.cpp"})) << language;
    EXPECT_FALSE(cacheableCommand({"CLANG-CL.EXE", "input.cpp"}));
    EXPECT_FALSE(cacheableCommand({"CL.EXE", "input.cpp"}));
    EXPECT_FALSE(cacheableCommand({"clang++", "-include", "header.h", "input.cpp"}));
    EXPECT_TRUE(cacheableCommand({"clang", "-x", "c", "input.c"}));
    EXPECT_TRUE(cacheableCommand({"clang++", "-x", "c++", "input.cpp"}));
}

TEST(RuntimeIdentityTest, MappingsAreBoundByFileIdentityNotAddressOrPermissionSegment) {
    std::vector<RuntimeMapping> mappings;
    std::string error;
    ASSERT_TRUE(parseRuntimeMappings(
        "1000-2000 r--p 0000 08:01 123 /lib/example.so\n"
        "2000-3000 r-xp 1000 08:01 123 /lib/example.so\n"
        "4000-5000 rw-p 0000 00:00 0 [heap]\n"
        "6000-7000 r-xp 0000 00:00 0 [vdso]\n"
        "8000-9000 r--p 0000 08:01 456 /lib/data only.bin\n", mappings, error)) << error;
    ASSERT_EQ(mappings.size(), 2u);
    EXPECT_EQ(mappings[0].path, "/lib/data only.bin");
    EXPECT_EQ(mappings[1].path, "/lib/example.so");
    EXPECT_EQ(mappings[1].device_major, 8u);
    EXPECT_EQ(mappings[1].device_minor, 1u);
    EXPECT_EQ(mappings[1].inode, 123u);
}

TEST(RuntimeIdentityTest, AmbiguousOrUnsupportedMappingsRefuseTransactionally) {
    const std::string valid = "1000-2000 r-xp 0000 08:01 123 /lib/example.so\n";
    for (const auto& bad : std::vector<std::string>{
            "", "truncated\n", "2000-1000 r-xp 0000 08:01 123 /lib/x.so\n",
            "2000-3000 rwxp 0000 08:01 123 /lib/x.so\n",
            "2000-3000 r-xp 0000 00:00 0\n",
            "2000-3000 r-xp 0000 08:01 123 /lib/x.so (deleted)\n",
            "2000-3000 r-xp 0000 08:01 123 /lib/x\\012.so\n",
            valid + "2000-3000 r--p 0000 08:01 999 /lib/example.so\n",
            std::string(1024 * 1024 + 1, 'x')}) {
        std::vector<RuntimeMapping> mappings{{"sentinel", 1, 2, 3}};
        std::string error;
        EXPECT_FALSE(parseRuntimeMappings(bad, mappings, error));
        ASSERT_EQ(mappings.size(), 1u);
        EXPECT_EQ(mappings.front().path, "sentinel");
        EXPECT_FALSE(error.empty());
    }
}

TEST(RuntimeIdentityTest, ActualRuntimeIsStableOrExplicitlyUnsupportedAndCancellationRefuses) {
    const auto first = observeRuntimeIdentity();
    if (!runtimeIdentitySupported()) {
        EXPECT_FALSE(first);
        EXPECT_EQ(first.reason, "runtime_profile_unqualified");
        return;
    }
    ASSERT_TRUE(first) << first.reason;
    const auto second = observeRuntimeIdentity();
    ASSERT_TRUE(second) << second.reason;
    EXPECT_EQ(first.digest.size(), 64u);
    EXPECT_EQ(second.digest, first.digest);
    const auto cancelled = observeRuntimeIdentity([] { return true; });
    EXPECT_FALSE(cancelled);
    EXPECT_EQ(cancelled.reason, "runtime_validation_cancelled");
}

TEST_F(InputIdentityTest, CandidateTransportDoesNotCountAsConfirmedReuse) {
    write("AAAA");
    const auto identity = witness();
    UnitEvidenceStore store;
    ASSERT_TRUE(store.rememberCandidate("key", identity.context, "packet", encodeInputIdentity(identity)));
    write("BBBB");
    // A candidate is only transported; the actual supervised child must reject
    // these stale inputs. Retrieving it must never claim a validated cache hit.
    EXPECT_EQ(store.candidate("key", identity.context), std::optional<std::string>("packet"));
    EXPECT_EQ(store.hits(), 0u);
    EXPECT_FALSE(store.candidate("key", inputDigest("wrong")));
    EXPECT_FALSE(store.candidate("key", identity.context, [] { return true; }));
    EXPECT_EQ(store.hits(), 0u);
}
#endif
