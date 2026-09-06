#ifdef CODESKEPTIC_RUNTIME_TEST_MODULE
#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <sys/syscall.h>
#include <unistd.h>

// Fault injection belongs only to this separately built private fixture DSO.
// No production environment flag or storage hook is introduced. The control
// file changes without changing the child's environment/runtime identity.
static bool diskFault(int fd, char mode, bool pending) {
    const auto* directory = std::getenv("CS_DISK_FAULT_DIR");
    const auto* control = std::getenv("CS_DISK_FAULT_CONTROL");
    if (!directory || !control) return false;
    auto* file = std::fopen(control, "rb");
    if (!file) return false;
    const int selected = std::fgetc(file);
    std::fclose(file);
    if (selected != mode) return false;
    char proc[64], path[8192];
    std::snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    const auto size = ::readlink(proc, path, sizeof(path) - 1);
    if (size < 0) return false;
    path[size] = '\0';
    const auto length = std::strlen(directory);
    return std::strncmp(path, directory, length) == 0 &&
        std::strcmp(path + length, pending ? "/.pending" : "") == 0;
}
extern "C" int fsync(int fd) {
    if (diskFault(fd, 'f', true) || diskFault(fd, 'd', false)) { errno = EIO; return -1; }
    return static_cast<int>(::syscall(SYS_fsync, fd));
}
extern "C" int renameat(int old_fd, const char* old_name, int new_fd, const char* new_name) noexcept {
    if (std::strcmp(old_name, ".pending") == 0 && diskFault(old_fd, 'r', false)) { errno = EIO; return -1; }
#ifdef SYS_renameat
    return static_cast<int>(::syscall(SYS_renameat, old_fd, old_name, new_fd, new_name));
#else
    return static_cast<int>(::syscall(SYS_renameat2, old_fd, old_name, new_fd, new_name, 0));
#endif
}

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
#include "analyzer/WorkerProtocol.h"
#include <gtest/gtest.h>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>
#ifdef __linux__
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
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

#ifdef __linux__
class DiskEvidenceStoreTest : public InputIdentityTest {
protected:
    std::string proof, digest = inputDigest("request"), key = inputDigest("key");
    fs::path directory;
    void SetUp() override {
        InputIdentityTest::SetUp();
        write("int f(){return 42;}\n");
        proof = encodeInputIdentity(witness());
        ASSERT_FALSE(proof.empty());
        directory = root / "disk";
    }
    fs::path entry() const { return directory / (key + ".entry"); }
    std::string read(const fs::path& path) {
        std::ifstream input(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
    }
    void replace(const fs::path& path, const std::string& bytes) {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        file << bytes;
        ASSERT_TRUE(file.good());
    }
};

TEST_F(DiskEvidenceStoreTest, SeparateStoresRoundtripOnlyBoundedValidatedEnvelopes) {
    DiskEvidenceStore writer(directory.string(), 1024 * 1024, 8);
    EXPECT_EQ(writer.rememberCandidate(key, digest, "original", proof), DiskWriteResult::Committed);
    const auto envelope = read(entry());
    ASSERT_FALSE(envelope.empty());
    DiskEvidenceStore reader(directory.string(), 1024 * 1024, 8);
    EXPECT_EQ(reader.candidate(key, digest), "original");
    EXPECT_EQ(reader.status().hits, 0u); // Only the actual child can confirm reuse.
    EXPECT_FALSE(reader.candidate(key, inputDigest("wrong-request")));
    EXPECT_EQ(reader.status().rejected, 1u);
    for (std::size_t length : {0u, 7u, 151u, static_cast<unsigned>(envelope.size() - 1)}) {
        replace(entry(), envelope.substr(0, length));
        EXPECT_FALSE(reader.candidate(key, digest));
    }
    auto tampered = envelope;
    tampered[152] ^= 1;
    replace(entry(), tampered);
    EXPECT_FALSE(reader.candidate(key, digest));
    replace(entry(), envelope + "trailing");
    EXPECT_FALSE(reader.candidate(key, digest));
    replace(entry(), envelope);
    EXPECT_EQ(reader.candidate(key, digest), "original");
}

TEST_F(DiskEvidenceStoreTest, ExactByteCeilingIncludesOldAndPendingAndPreservesFailedReplacement) {
    DiskEvidenceStore writer(directory.string(), 1024 * 1024, 8);
    ASSERT_EQ(writer.rememberCandidate(key, digest, "original", proof), DiskWriteResult::Committed);
    const auto old = read(entry());
    DiskEvidenceStore tight(directory.string(), old.size() * 2 - 1, 8);
    EXPECT_EQ(tight.rememberCandidate(key, digest, "replaced", proof), DiskWriteResult::NotStored);
    EXPECT_EQ(tight.status().capacity, 1u);
    EXPECT_EQ(read(entry()), old);
    EXPECT_FALSE(fs::exists(directory / ".pending"));
    DiskEvidenceStore exact(directory.string(), old.size() * 2, 8);
    EXPECT_EQ(exact.rememberCandidate(key, digest, "replaced", proof), DiskWriteResult::Committed);
    EXPECT_EQ(exact.status().bytes, old.size());
    EXPECT_EQ(exact.candidate(key, digest), "replaced");
    DiskEvidenceStore one(directory.string(), 1024 * 1024, 1);
    EXPECT_EQ(one.rememberCandidate(key, digest, "original", proof), DiskWriteResult::NotStored);
    EXPECT_EQ(one.status().capacity, 1u);
    EXPECT_EQ(one.candidate(key, digest), "replaced");
}

TEST_F(DiskEvidenceStoreTest, CancellationDuringPartialWritePreservesOldAndRemovesTemporary) {
    DiskEvidenceStore store(directory.string(), 1024 * 1024, 8);
    ASSERT_EQ(store.rememberCandidate(key, digest, "original", proof), DiskWriteResult::Committed);
    const auto old = read(entry());
    bool observed_partial = false;
    const auto cancel = [&] {
        std::error_code error;
        const auto size = fs::file_size(directory / ".pending", error);
        if (!error && size > 0) observed_partial = true;
        return observed_partial;
    };
    EXPECT_EQ(store.rememberCandidate(key, digest, std::string(180000, 'x'), proof, cancel), DiskWriteResult::NotStored);
    EXPECT_TRUE(observed_partial);
    EXPECT_EQ(store.status().state, "cancelled");
    EXPECT_EQ(read(entry()), old);
    EXPECT_FALSE(fs::exists(directory / ".pending"));
    EXPECT_EQ(store.candidate(key, digest), "original");
}

TEST_F(DiskEvidenceStoreTest, CrashLeftTemporaryIsNeverACandidateAndRetentionStaysFinite) {
    DiskEvidenceStore store(directory.string(), 1024 * 1024, 3);
    ASSERT_EQ(store.rememberCandidate(key, digest, "original", proof), DiskWriteResult::Committed);
    replace(directory / ".pending", "interrupted write");
    ASSERT_EQ(::chmod((directory / ".pending").c_str(), 0600), 0);
    EXPECT_EQ(store.candidate(key, digest), "original");
    EXPECT_EQ(store.status().recovered, 1u);
    EXPECT_FALSE(fs::exists(directory / ".pending"));
    for (int i = 0; i < 8; ++i)
        EXPECT_EQ(store.rememberCandidate(inputDigest(std::to_string(i)), digest, "other", proof), DiskWriteResult::Committed);
    EXPECT_LE(store.status().entries, 3u);
    EXPECT_GT(store.status().evictions, 0u);
    std::uint64_t actual = 0;
    std::size_t count = 0;
    for (const auto& file : fs::directory_iterator(directory)) { actual += file.file_size(); ++count; }
    EXPECT_EQ(actual, store.status().bytes);
    EXPECT_EQ(count, store.status().entries);
    DiskEvidenceStore tiny(directory.string(), 1, 1);
    EXPECT_FALSE(tiny.candidate(key, digest));
    EXPECT_TRUE(fs::is_empty(directory));
    EXPECT_EQ(tiny.rememberCandidate(key, digest, "new", proof), DiskWriteResult::NotStored);
    EXPECT_EQ(tiny.status().capacity, 1u);
}

TEST_F(DiskEvidenceStoreTest, ActualProcessExitMidWriteLeavesOnlyRecoverableTemporaryAndOldTarget) {
    DiskEvidenceStore store(directory.string(), 1024 * 1024, 8);
    ASSERT_EQ(store.rememberCandidate(key, digest, "original", proof), DiskWriteResult::Committed);
    const auto old = read(entry());
    const auto child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        DiskEvidenceStore writer(directory.string(), 1024 * 1024, 8);
        writer.rememberCandidate(key, digest, std::string(180000, 'x'), proof, [&] {
            std::error_code error;
            const auto size = fs::file_size(directory / ".pending", error);
            if (!error && size > 0) ::_exit(73); // no C++ destructor/cleanup
            return false;
        });
        ::_exit(4);
    }
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status)); ASSERT_EQ(WEXITSTATUS(status), 73);
    ASSERT_TRUE(fs::exists(directory / ".pending"));
    EXPECT_EQ(read(entry()), old);
    EXPECT_EQ(store.candidate(key, digest), "original");
    EXPECT_EQ(store.status().recovered, 1u);
    EXPECT_FALSE(fs::exists(directory / ".pending"));
}

TEST_F(DiskEvidenceStoreTest, SymlinksHardlinksAndUnrelatedNamesAreNotFollowedOrDeleted) {
    DiskEvidenceStore store(directory.string(), 1024 * 1024, 8);
    ASSERT_EQ(store.rememberCandidate(key, digest, "original", proof), DiskWriteResult::Committed);
    const auto external = root / "external";
    fs::rename(entry(), external);
    fs::create_symlink(external, entry());
    const auto original = read(external);
    EXPECT_FALSE(store.candidate(key, digest));
    EXPECT_EQ(store.rememberCandidate(key, digest, "replacement", proof), DiskWriteResult::NotStored);
    EXPECT_EQ(read(external), original);
    EXPECT_TRUE(fs::is_symlink(entry()));
    fs::remove(entry());
    fs::create_hard_link(external, entry());
    EXPECT_FALSE(store.candidate(key, digest));
    EXPECT_EQ(store.rememberCandidate(key, digest, "replacement", proof), DiskWriteResult::NotStored);
    EXPECT_EQ(read(external), original);
    fs::remove(entry());
    fs::rename(external, entry());
    replace(directory / "user-file", "do not delete");
    EXPECT_FALSE(store.candidate(key, digest));
    EXPECT_EQ(store.rememberCandidate(key, digest, "replacement", proof), DiskWriteResult::NotStored);
    EXPECT_EQ(read(directory / "user-file"), "do not delete");
    fs::remove(directory / "user-file");
    fs::create_symlink(entry(), directory / ".pending");
    EXPECT_FALSE(store.candidate(key, digest));
    EXPECT_TRUE(fs::is_symlink(directory / ".pending"));
    EXPECT_EQ(read(entry()), original);
}

TEST_F(DiskEvidenceStoreTest, DirectoryPermissionsAndAncestorSymlinksRefuseStorage) {
    ASSERT_TRUE(fs::create_directory(directory));
    ASSERT_EQ(::chmod(directory.c_str(), 0755), 0);
    DiskEvidenceStore store(directory.string(), 1024 * 1024, 8);
    EXPECT_EQ(store.rememberCandidate(key, digest, "original", proof), DiskWriteResult::NotStored);
    EXPECT_TRUE(fs::is_empty(directory));
    ASSERT_EQ(::chmod(directory.c_str(), 0700), 0);
    const auto alias = root / "alias";
    fs::create_directory_symlink(directory, alias);
    DiskEvidenceStore linked(alias.string(), 1024 * 1024, 8);
    EXPECT_EQ(linked.rememberCandidate(key, digest, "original", proof), DiskWriteResult::NotStored);
    DiskEvidenceStore ancestor((alias / "nested").string(), 1024 * 1024, 8);
    EXPECT_EQ(ancestor.rememberCandidate(key, digest, "original", proof), DiskWriteResult::NotStored);
    EXPECT_TRUE(fs::is_empty(directory));
}

TEST_F(DiskEvidenceStoreTest, ConcurrentWritersAndReadersPublishOnlyWholePacketsWithinCaps) {
    DiskEvidenceStore store(directory.string(), 1024 * 1024, 8);
    ASSERT_EQ(store.rememberCandidate(key, digest, "original", proof), DiskWriteResult::Committed);
    const auto child = ::fork();
    ASSERT_GE(child, 0);
    if (child == 0) {
        DiskEvidenceStore writer(directory.string(), 1024 * 1024, 8);
        unsigned committed = 0;
        for (int i = 0; i < 120; ++i) {
            const auto result = writer.rememberCandidate(key, digest, std::string(70000, i % 2 ? 'a' : 'b'), proof);
            if (result == DiskWriteResult::NotStored && writer.status().state != "busy") ::_exit(3);
            if (result == DiskWriteResult::Committed) ++committed;
            ::usleep(1000);
        }
        ::_exit(committed ? 0 : 5);
    }
    unsigned same_commits = 0, other_commits = 0;
    for (int i = 0; i < 120; ++i) {
        const bool same = i % 2 == 0;
        const auto result = store.rememberCandidate(same ? key : inputDigest(std::to_string(i)), digest,
                                                    std::string(70000, 'c'), proof);
        if (result == DiskWriteResult::Committed) { if (same) ++same_commits; else ++other_commits; }
        else EXPECT_EQ(store.status().state, "busy");
        const auto packet = store.candidate(key, digest);
        if (packet) EXPECT_TRUE(*packet == "original" || *packet == std::string(70000, 'a') ||
                              *packet == std::string(70000, 'b') || *packet == std::string(70000, 'c'));
        else EXPECT_TRUE(store.status().state == "busy" || store.status().state == "miss");
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    int status = 0;
    ASSERT_EQ(::waitpid(child, &status, 0), child);
    ASSERT_TRUE(WIFEXITED(status)); EXPECT_EQ(WEXITSTATUS(status), 0);
    EXPECT_GT(same_commits, 0u); EXPECT_GT(other_commits, 0u);
    EXPECT_GT(store.status().evictions, 0u);
    EXPECT_FALSE(fs::exists(directory / ".pending"));
    store.candidate(key, digest);
    EXPECT_LE(store.status().bytes, 1024 * 1024u);
    EXPECT_LE(store.status().entries, 8u);
}

TEST_F(DiskEvidenceStoreTest, HeldDirectoryLockReturnsBusyWithoutWaitingOrWriting) {
    DiskEvidenceStore store(directory.string(), 1024 * 1024, 8);
    ASSERT_EQ(store.rememberCandidate(key, digest, "original", proof), DiskWriteResult::Committed);
    const int fd = ::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(::flock(fd, LOCK_EX | LOCK_NB), 0);
    EXPECT_FALSE(store.candidate(key, digest));
    EXPECT_EQ(store.status().state, "busy");
    EXPECT_EQ(store.rememberCandidate(key, digest, "replacement", proof), DiskWriteResult::NotStored);
    EXPECT_EQ(store.status().state, "busy");
    ::close(fd);
    EXPECT_EQ(store.candidate(key, digest), "original");
}

TEST_F(DiskEvidenceStoreTest, InvalidLimitsNamesAndCancellationNeverCreateStorage) {
    for (const auto& limits : std::vector<std::pair<std::uint64_t, std::size_t>>{
             {0, 1}, {1, 0}, {1073741825ULL, 8}, {1024, 4097}}) {
        DiskEvidenceStore store(directory.string(), limits.first, limits.second);
        EXPECT_FALSE(store.candidate(key, digest));
        EXPECT_EQ(store.rememberCandidate(key, digest, "original", proof), DiskWriteResult::NotStored);
        EXPECT_EQ(store.status().state, "invalid_limits");
        EXPECT_FALSE(fs::exists(directory));
    }
    DiskEvidenceStore store(directory.string(), 1024 * 1024, 8);
    EXPECT_FALSE(store.candidate("../outside", digest));
    EXPECT_EQ(store.rememberCandidate("../outside", digest, "original", proof), DiskWriteResult::NotStored);
    EXPECT_EQ(store.status().state, "rejected");
    EXPECT_FALSE(fs::exists(directory));
    EXPECT_FALSE(store.candidate(key, digest, [] { return true; }));
    EXPECT_EQ(store.rememberCandidate(key, digest, "original", proof, [] { return true; }), DiskWriteResult::NotStored);
    EXPECT_EQ(store.status().state, "cancelled");
    EXPECT_FALSE(fs::exists(directory));
}
#else
TEST(DiskEvidenceStoreTest, UnsupportedPlatformNeverTouchesDisk) {
    const auto directory = fs::path(::testing::TempDir()) / ("codeskeptic-unsupported-disk-" +
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    DiskEvidenceStore store(directory.string(), 1024, 8);
    EXPECT_EQ(store.status().state, "unsupported");
    EXPECT_FALSE(store.candidate(inputDigest("key"), inputDigest("request")));
    EXPECT_EQ(store.rememberCandidate(inputDigest("key"), inputDigest("request"), "packet", "proof"),
              DiskWriteResult::NotStored);
    EXPECT_EQ(store.status().state, "unsupported");
    EXPECT_FALSE(fs::exists(directory));
}
#endif

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

TEST_F(InputIdentityTest, OptionalProofCompositionNeverBreaksAnOtherwiseValidResponse) {
    WorkerRequest request;
    request.source = (root / "input.cpp").string();
    request.build_directory = root.string();
    request.commands.emplace_back(root.string(), request.source,
        std::vector<std::string>{"clang++", "-c", request.source}, "");
    request.producers = {"null-deref"}; request.selected_families = {"null-deref"};
    request.record_inputs = true;
    WorkerResponse response;
    response.request_digest = workerRequestDigest(encodeWorkerRequest(request));
    response.coverage.file = request.source;
    response.coverage.status = SourceStatus::Analyzed; response.coverage.reason = "analyzed";
    response.coverage.commands = response.coverage.analyzed_commands = 1;
    for (unsigned i = 0; i < 4; ++i) {
        Diagnostic diagnostic{};
        diagnostic.severity = Severity::Error; diagnostic.file = request.source;
        diagnostic.line = diagnostic.column = 1; diagnostic.rule_id = "null-deref";
        diagnostic.message.assign(kWorkerFieldLimit - 4096, 'x');
        response.diagnostics.push_back(std::move(diagnostic));
    }
    const auto ordinary = encodeWorkerResponse(response);
    WorkerResponse decoded;
    std::string error;
    ASSERT_TRUE(decodeWorkerResponse(ordinary, request, response.request_digest, decoded, error)) << error;
    const auto room = kWorkerPacketLimit - ordinary.size();
    ASSERT_GT(room, 64u); ASSERT_LT(room, kInputIdentityLimit);
    // This is a wire-capacity fixture, not an actual frontend proof. Exact fit
    // must preserve both fields; exceeding that by one byte must drop only
    // optional proof, with every ordinary response byte unchanged.
    response.runtime_digest = std::string(64, 'a');
    response.input_witness.assign(room - response.runtime_digest.size(), 'w');
    {
        const auto exact_fit = encodeWorkerResponse(response);
        EXPECT_EQ(exact_fit.size(), kWorkerPacketLimit);
        ASSERT_TRUE(decodeWorkerResponse(exact_fit, request, response.request_digest, decoded, error)) << error;
        EXPECT_EQ(decoded.input_witness, response.input_witness);
        EXPECT_EQ(decoded.runtime_digest, response.runtime_digest);
    }
    response.input_witness.push_back('w');
    std::string fallback;
    EXPECT_NO_THROW(fallback = encodeWorkerResponse(response));
    ASSERT_FALSE(fallback.empty());
    EXPECT_EQ(inputDigest(fallback), inputDigest(ordinary));
    ASSERT_TRUE(decodeWorkerResponse(fallback, request, response.request_digest, decoded, error)) << error;
    EXPECT_TRUE(decoded.input_witness.empty()); EXPECT_TRUE(decoded.runtime_digest.empty());
    EXPECT_FALSE(decoded.cache_hit);
    response.cache_hit = true;
    EXPECT_THROW(encodeWorkerResponse(response), std::runtime_error);
    response.cache_hit = false;
    response.input_witness.assign(kWorkerFieldLimit + 1, 'w');
    EXPECT_THROW(encodeWorkerResponse(response), std::runtime_error);
    response.input_witness.clear(); response.runtime_digest.clear();
    for (auto& diagnostic : response.diagnostics) diagnostic.message.resize(kWorkerFieldLimit, 'x');
    EXPECT_THROW(encodeWorkerResponse(response), std::runtime_error);
}
#endif
