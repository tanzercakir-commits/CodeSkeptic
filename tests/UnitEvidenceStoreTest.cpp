#include "analyzer/UnitEvidenceStore.h"

#include <gtest/gtest.h>
#include <llvm/ADT/SmallString.h>
#include <llvm/Support/FileSystem.h>

#include <filesystem>
#include <fstream>
#include <chrono>

#ifndef CODESKEPTIC_BINARY
#error "CODESKEPTIC_BINARY must name the production executable"
#endif

using namespace codeskeptic;

namespace {

class TemporaryEvidenceDirectory {
public:
    TemporaryEvidenceDirectory() {
        llvm::SmallString<256> path;
        if (!llvm::sys::fs::createUniqueDirectory(
                "codeskeptic-unit-evidence", path))
            path_ = std::filesystem::path(path.str().str());
    }
    ~TemporaryEvidenceDirectory() {
        std::error_code ec;
        if (!path_.empty()) std::filesystem::remove_all(path_, ec);
    }
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

TranslationUnitExecution sampleUnit() {
    TranslationUnitExecution unit;
    unit.canonical_path = "/project/unit.cpp";
    unit.working_directory = "/project";
    unit.command_line = {"clang++", "-std=c++17", unit.canonical_path};
    unit.command_ordinal = 0;
    unit.compile_command_sha256 = translationUnitCommandSha256(unit);
    return unit;
}

DependencyManifest sampleDependencies(char content = 'a') {
    DependencyManifest manifest;
    manifest.toolchain_identity_sha256 = std::string(64, '1');
    manifest.files = {
        DependencyEvidence{"/project/unit.cpp", std::string(64, content),
                           false, {}},
    };
    manifest.sha256 = dependencyManifestSha256(manifest);
    return manifest;
}

WorkerResponse sampleResponse(const TranslationUnitExecution& unit,
                              const DependencyManifest& dependencies) {
    WorkerResponse response;
    response.request_id = "cold-request";
    response.canonical_path = unit.canonical_path;
    response.compile_command_sha256 = unit.compile_command_sha256;
    response.command_ordinal = unit.command_ordinal;
    response.phase = TranslationUnitPhase::Analysis;
    response.analysis.attempted_tus = 1;
    response.analysis.analyzed_tus = 1;
    response.dependency_manifest = dependencies;
    return response;
}

std::unique_ptr<UnitEvidenceStore> openStore(
    const std::filesystem::path& root,
    const std::vector<TranslationUnitExecution>& units,
    std::string& error,
    std::vector<std::string> config = {"--lang", "en"},
    bool namespace_by_run_identity = false) {
    return UnitEvidenceStore::open(
        root.string(), units, false, CODESKEPTIC_BINARY, config,
        {"null-deref", "div-by-zero"}, ResourceLimits{30, 1024}, error,
        namespace_by_run_identity);
}

} // anonymous namespace

#ifndef _WIN32
TEST(UnitEvidenceStoreTest, LegacyManifestTemporarySymlinkCannotEscapeRoot) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    ASSERT_TRUE(std::filesystem::create_directory(root));
    const auto outside = temporary.path() / "outside.txt";
    {
        std::ofstream output(outside, std::ios::binary | std::ios::trunc);
        output << "sentinel\n";
    }
    std::error_code ec;
    std::filesystem::create_symlink(
        outside, root / "manifest.json.tmp.1", ec);
    ASSERT_FALSE(ec) << ec.message();
    const auto unit = sampleUnit();
    std::string error;

    auto store = openStore(root, {unit}, error);

    ASSERT_NE(store, nullptr) << error;
    EXPECT_TRUE(std::filesystem::is_regular_file(root / "manifest.json"));
    std::ifstream input(outside, std::ios::binary);
    const std::string contents((std::istreambuf_iterator<char>(input)),
                               std::istreambuf_iterator<char>());
    EXPECT_EQ(contents, "sentinel\n");
}

TEST(UnitEvidenceStoreTest, CurrentManifestTemporarySymlinkFailsClosed) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    ASSERT_TRUE(std::filesystem::create_directory(root));
    const auto outside = temporary.path() / "outside.txt";
    {
        std::ofstream output(outside, std::ios::binary | std::ios::trunc);
        output << "sentinel\n";
    }
    std::error_code ec;
    std::filesystem::create_symlink(
        outside, root / "manifest.json.tmp", ec);
    ASSERT_FALSE(ec) << ec.message();
    const auto unit = sampleUnit();
    std::string error;

    auto store = openStore(root, {unit}, error);

    EXPECT_EQ(store, nullptr);
    EXPECT_NE(error.find("staging path is not a regular file"),
              std::string::npos)
        << error;
    std::ifstream input(outside, std::ios::binary);
    const std::string contents((std::istreambuf_iterator<char>(input)),
                               std::istreambuf_iterator<char>());
    EXPECT_EQ(contents, "sentinel\n");
}

TEST(UnitEvidenceStoreTest, RegularManifestStagingRemainderResumes) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    ASSERT_TRUE(std::filesystem::create_directory(root));
    {
        std::ofstream remainder(root / "manifest.json.tmp",
                                std::ios::binary | std::ios::trunc);
        remainder << "{interrupted";
    }
    const auto unit = sampleUnit();
    std::string error;

    auto store = openStore(root, {unit}, error);

    ASSERT_NE(store, nullptr) << error;
    EXPECT_TRUE(std::filesystem::is_regular_file(root / "manifest.json"));
    EXPECT_FALSE(std::filesystem::exists(root / "manifest.json.tmp"));
}
#endif

TEST(UnitEvidenceStoreTest, ExistingEmptyCheckpointDirectoryInitializes) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    ASSERT_TRUE(std::filesystem::create_directory(root));
    const auto unit = sampleUnit();
    std::string error;

    auto store = openStore(root, {unit}, error);

    ASSERT_NE(store, nullptr) << error;
    EXPECT_TRUE(std::filesystem::is_regular_file(root / "manifest.json"));
    EXPECT_TRUE(std::filesystem::is_directory(root / "entries"));
}

TEST(UnitEvidenceStoreTest, NamespacedStorePartitionsExactRunIdentities) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    const auto unit = sampleUnit();
    auto other_unit = unit;
    other_unit.canonical_path = "/project/other.cpp";
    other_unit.command_line.back() = other_unit.canonical_path;
    other_unit.compile_command_sha256 =
        translationUnitCommandSha256(other_unit);
    std::string error;

    ASSERT_NE(openStore(root, {unit}, error, {"--lang", "en"}, true),
              nullptr) << error;
    ASSERT_NE(openStore(root, {unit}, error, {"--lang", "tr"}, true),
              nullptr) << error;
    ASSERT_NE(openStore(root, {other_unit}, error, {"--lang", "en"}, true),
              nullptr) << error;
    ASSERT_NE(openStore(root, {unit}, error, {"--lang", "en"}, true),
              nullptr) << error;

    const auto requests = root / "requests";
    ASSERT_TRUE(std::filesystem::is_directory(requests));
    std::size_t namespaces = 0;
    for (const auto& entry : std::filesystem::directory_iterator(requests)) {
        ASSERT_TRUE(entry.is_directory());
        EXPECT_EQ(entry.path().filename().string().size(), 32u);
        EXPECT_TRUE(std::filesystem::is_regular_file(
            entry.path() / "manifest.json"));
        ++namespaces;
    }
    EXPECT_EQ(namespaces, 3u);
    EXPECT_FALSE(std::filesystem::exists(root / "manifest.json"));
}

TEST(UnitEvidenceStoreTest, ExactEntryRoundTripsAndDependencyChangeMisses) {
    TemporaryEvidenceDirectory temporary;
    ASSERT_FALSE(temporary.path().empty());
    const auto root = temporary.path() / "checkpoint";
    const auto unit = sampleUnit();
    std::string error;
    auto store = openStore(root, {unit}, error);
    ASSERT_NE(store, nullptr) << error;

    const auto dependencies = sampleDependencies();
    const auto response = sampleResponse(unit, dependencies);
    std::string key;
    std::string payload;
    ASSERT_TRUE(store->store(unit, TranslationUnitPhase::Analysis,
                             dependencies, std::string(64, '2'), response,
                             {}, key, payload, error)) << error;
    EXPECT_EQ(key.size(), 64u);
    EXPECT_EQ(payload.size(), 64u);

    CachedUnitEvidence cached;
    EXPECT_EQ(store->lookup(unit, TranslationUnitPhase::Analysis,
                            dependencies, std::string(64, '2'), cached,
                            error), EvidenceLookupStatus::Hit) << error;
    EXPECT_EQ(cached.response.analysis.analyzed_tus, 1u);
    EXPECT_EQ(cached.checkpoint_key_sha256, key);
    EXPECT_EQ(cached.payload_sha256, payload);

    const auto changed = sampleDependencies('b');
    EXPECT_EQ(store->lookup(unit, TranslationUnitPhase::Analysis, changed,
                            std::string(64, '2'), cached, error),
              EvidenceLookupStatus::Miss) << error;
}

TEST(UnitEvidenceStoreTest, UnplannedDependencyProbeCannotEnterCheckpoint) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    const auto unit = sampleUnit();
    const auto dependencies = sampleDependencies();
    auto response = sampleResponse(unit, dependencies);
    response.phase = TranslationUnitPhase::DependencyProbe;
    std::string error;
    auto store = openStore(root, {unit}, error);
    ASSERT_NE(store, nullptr) << error;
    std::string key;
    std::string payload;
    EXPECT_FALSE(store->store(
        unit, TranslationUnitPhase::DependencyProbe, dependencies,
        std::string(64, '2'), response, {}, key, payload, error));
    EXPECT_NE(error.find("plan"), std::string::npos) << error;
}

TEST(UnitEvidenceStoreTest, ExpectedEntryCorruptionFailsClosed) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    const auto unit = sampleUnit();
    const auto dependencies = sampleDependencies();
    const auto response = sampleResponse(unit, dependencies);
    std::string error;
    auto store = openStore(root, {unit}, error);
    ASSERT_NE(store, nullptr) << error;
    std::string key;
    std::string payload;
    ASSERT_TRUE(store->store(unit, TranslationUnitPhase::Analysis,
                             dependencies, std::string(64, '2'), response,
                             {}, key, payload, error)) << error;
    {
        std::ofstream corrupt(root / "entries" / key / "response.json",
                              std::ios::binary | std::ios::trunc);
        corrupt << "{truncated";
    }

    CachedUnitEvidence cached;
    EXPECT_EQ(store->lookup(unit, TranslationUnitPhase::Analysis,
                            dependencies, std::string(64, '2'), cached,
                            error), EvidenceLookupStatus::Failed);
    EXPECT_NE(error.find("corrupt"), std::string::npos) << error;
}

TEST(UnitEvidenceStoreTest, CorruptOrphanCannotBeRepublished) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    const auto unit = sampleUnit();
    const auto dependencies = sampleDependencies();
    const auto response = sampleResponse(unit, dependencies);
    std::string error;
    auto first = openStore(root, {unit}, error);
    ASSERT_NE(first, nullptr) << error;
    std::string key;
    std::string payload;
    ASSERT_TRUE(first->store(unit, TranslationUnitPhase::Analysis,
                             dependencies, std::string(64, '2'), response,
                             {}, key, payload, error)) << error;
    first.reset();

    ASSERT_TRUE(std::filesystem::remove(root / "manifest.json"));
    auto resumed = openStore(root, {unit}, error);
    ASSERT_NE(resumed, nullptr) << error;
    {
        std::ofstream corrupt(root / "entries" / key / "response.json",
                              std::ios::binary | std::ios::trunc);
        corrupt << "{truncated";
    }
    std::string resumed_key;
    std::string resumed_payload;
    EXPECT_FALSE(resumed->store(
        unit, TranslationUnitPhase::Analysis, dependencies,
        std::string(64, '2'), response, {}, resumed_key, resumed_payload,
        error));
    EXPECT_NE(error.find("corrupt"), std::string::npos) << error;
}

TEST(UnitEvidenceStoreTest, NonRegularOrExtraEntryPayloadFailsClosed) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    const auto unit = sampleUnit();
    const auto dependencies = sampleDependencies();
    const auto response = sampleResponse(unit, dependencies);
    std::string error;
    auto store = openStore(root, {unit}, error);
    ASSERT_NE(store, nullptr) << error;
    std::string key;
    std::string payload;
    ASSERT_TRUE(store->store(unit, TranslationUnitPhase::Analysis,
                             dependencies, std::string(64, '2'), response,
                             {}, key, payload, error)) << error;

    const auto entry = root / "entries" / key;
    ASSERT_TRUE(std::filesystem::create_directory(entry / "extra"));
    CachedUnitEvidence cached;
    EXPECT_EQ(store->lookup(unit, TranslationUnitPhase::Analysis,
                            dependencies, std::string(64, '2'), cached,
                            error), EvidenceLookupStatus::Failed);
    EXPECT_NE(error.find("non-regular"), std::string::npos) << error;

    ASSERT_TRUE(std::filesystem::remove(entry / "extra"));
    ASSERT_TRUE(std::filesystem::remove(entry / "response.json"));
    ASSERT_TRUE(std::filesystem::create_directory(entry / "response.json"));
    error.clear();
    EXPECT_EQ(store->lookup(unit, TranslationUnitPhase::Analysis,
                            dependencies, std::string(64, '2'), cached,
                            error), EvidenceLookupStatus::Failed);
    EXPECT_NE(error.find("non-regular"), std::string::npos) << error;

#ifndef _WIN32
    ASSERT_TRUE(std::filesystem::remove(entry / "response.json"));
    std::error_code symlink_error;
    std::filesystem::create_symlink(
        entry / "request.json", entry / "response.json", symlink_error);
    ASSERT_FALSE(symlink_error) << symlink_error.message();
    error.clear();
    EXPECT_EQ(store->lookup(unit, TranslationUnitPhase::Analysis,
                            dependencies, std::string(64, '2'), cached,
                            error), EvidenceLookupStatus::Failed);
    EXPECT_NE(error.find("non-regular"), std::string::npos) << error;
#endif
}

TEST(UnitEvidenceStoreTest, CorruptSummaryFragmentFailsClosed) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    const auto unit = sampleUnit();
    const auto dependencies = sampleDependencies();
    const auto response = sampleResponse(unit, dependencies);
    std::string error;
    auto store = openStore(root, {unit}, error);
    ASSERT_NE(store, nullptr) << error;
    std::string key;
    std::string payload;
    ASSERT_TRUE(store->store(unit, TranslationUnitPhase::Analysis,
                             dependencies, std::string(64, '2'), response,
                             "codeskeptic-summaries v10\n", key, payload,
                             error)) << error;
    {
        std::ofstream corrupt(root / "entries" / key / "summary.csk",
                              std::ios::binary | std::ios::trunc);
        corrupt << "forged\n";
    }

    CachedUnitEvidence cached;
    EXPECT_EQ(store->lookup(unit, TranslationUnitPhase::Analysis,
                            dependencies, std::string(64, '2'), cached,
                            error), EvidenceLookupStatus::Failed);
    EXPECT_NE(error.find("corrupt"), std::string::npos) << error;
}

TEST(UnitEvidenceStoreTest, ExplicitCheckpointIdentityMismatchFailsClosed) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    auto unit = sampleUnit();
    std::string error;
    ASSERT_NE(openStore(root, {unit}, error), nullptr) << error;

    auto incompatible_config = openStore(
        root, {unit}, error, {"--lang", "tr"});
    EXPECT_EQ(incompatible_config, nullptr);
    EXPECT_NE(error.find("incompatible"), std::string::npos) << error;

    auto command_changed = sampleUnit();
    command_changed.command_line.insert(command_changed.command_line.begin() + 1,
                                        "-DVALUE=2");
    command_changed.compile_command_sha256 =
        translationUnitCommandSha256(command_changed);
    auto incompatible_command = openStore(root, {command_changed}, error);
    EXPECT_EQ(incompatible_command, nullptr);
    EXPECT_NE(error.find("incompatible"), std::string::npos) << error;

    unit.command_ordinal = 1;
    unit.compile_command_sha256 = translationUnitCommandSha256(unit);
    auto incompatible_plan = openStore(root, {unit}, error);
    EXPECT_EQ(incompatible_plan, nullptr);
    EXPECT_NE(error.find("incompatible"), std::string::npos) << error;
}

TEST(UnitEvidenceStoreTest, ManifestSchemaChecksumAndSizeFailClosed) {
    TemporaryEvidenceDirectory temporary;
    const auto unit = sampleUnit();
    std::string error;

    const auto checksum_root = temporary.path() / "checksum";
    ASSERT_NE(openStore(checksum_root, {unit}, error), nullptr) << error;
    const auto checksum_manifest = checksum_root / "manifest.json";
    std::string manifest;
    {
        std::ifstream input(checksum_manifest, std::ios::binary);
        manifest.assign(std::istreambuf_iterator<char>(input),
                        std::istreambuf_iterator<char>());
    }
    const auto field = manifest.find("\"manifest_sha256\"");
    ASSERT_NE(field, std::string::npos);
    const auto colon = manifest.find(':', field);
    const auto quote = manifest.find('"', colon);
    ASSERT_NE(quote, std::string::npos);
    ASSERT_LT(quote + 1, manifest.size());
    manifest[quote + 1] = manifest[quote + 1] == '0' ? '1' : '0';
    {
        std::ofstream output(checksum_manifest,
                             std::ios::binary | std::ios::trunc);
        output << manifest;
    }
    EXPECT_EQ(openStore(checksum_root, {unit}, error), nullptr);
    EXPECT_NE(error.find("checksum"), std::string::npos) << error;

    const auto schema_root = temporary.path() / "schema";
    ASSERT_NE(openStore(schema_root, {unit}, error), nullptr) << error;
    {
        std::ofstream output(schema_root / "manifest.json",
                             std::ios::binary | std::ios::trunc);
        output << "{\"schema\":999}\n";
    }
    EXPECT_EQ(openStore(schema_root, {unit}, error), nullptr);
    EXPECT_NE(error.find("schema"), std::string::npos) << error;

    const auto oversized_root = temporary.path() / "oversized";
    ASSERT_NE(openStore(oversized_root, {unit}, error), nullptr) << error;
    std::error_code ec;
    std::filesystem::resize_file(oversized_root / "manifest.json",
                                 (16u << 20) + 1u, ec);
    ASSERT_FALSE(ec) << ec.message();
    EXPECT_EQ(openStore(oversized_root, {unit}, error), nullptr);
    EXPECT_NE(error.find("size limit"), std::string::npos) << error;
}

TEST(UnitEvidenceStoreTest, AnalyzerAndRuleSetChangesAreIncompatible) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    const auto analyzer_one = temporary.path() / "analyzer-one";
    const auto analyzer_two = temporary.path() / "analyzer-two";
    {
        std::ofstream first(analyzer_one, std::ios::binary);
        first << "analyzer-v1";
        std::ofstream second(analyzer_two, std::ios::binary);
        second << "analyzer-v2";
    }
    const auto unit = sampleUnit();
    std::string error;
    auto first = UnitEvidenceStore::open(
        root.string(), {unit}, false, analyzer_one.string(),
        {"--lang", "en"}, {"null-deref"}, ResourceLimits{30, 1024},
        error);
    ASSERT_NE(first, nullptr) << error;

    auto analyzer_changed = UnitEvidenceStore::open(
        root.string(), {unit}, false, analyzer_two.string(),
        {"--lang", "en"}, {"null-deref"}, ResourceLimits{30, 1024},
        error);
    EXPECT_EQ(analyzer_changed, nullptr);
    EXPECT_NE(error.find("incompatible"), std::string::npos) << error;

    auto rules_changed = UnitEvidenceStore::open(
        root.string(), {unit}, false, analyzer_one.string(),
        {"--lang", "en"}, {"div-by-zero", "null-deref"},
        ResourceLimits{30, 1024}, error);
    EXPECT_EQ(rules_changed, nullptr);
    EXPECT_NE(error.find("incompatible"), std::string::npos) << error;
}

TEST(UnitEvidenceStoreTest, AnalyzerMutationAfterOpenFailsVerification) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    const auto analyzer = temporary.path() / "analyzer";
    {
        std::ofstream output(analyzer, std::ios::binary);
        output << "analyzer-v1";
    }
    const auto unit = sampleUnit();
    std::string error;
    auto store = UnitEvidenceStore::open(
        root.string(), {unit}, false, analyzer.string(),
        {"--lang", "en"}, {"null-deref"}, ResourceLimits{30, 1024},
        error);
    ASSERT_NE(store, nullptr) << error;
    EXPECT_TRUE(store->verifyAnalyzerIdentity(error)) << error;
    std::error_code ec;
    const auto original_time = std::filesystem::last_write_time(analyzer, ec);
    ASSERT_FALSE(ec) << ec.message();

    {
        std::ofstream output(analyzer,
                             std::ios::binary | std::ios::trunc);
        output << "analyzer-v2";
    }
    std::filesystem::last_write_time(analyzer, original_time, ec);
    ASSERT_FALSE(ec) << ec.message();
    EXPECT_FALSE(store->verifyAnalyzerIdentity(error));
    EXPECT_NE(error.find("analyzer"), std::string::npos) << error;

    {
        std::ofstream output(analyzer,
                             std::ios::binary | std::ios::trunc);
        output << "analyzer-v1";
    }
    std::filesystem::last_write_time(analyzer, original_time, ec);
    ASSERT_FALSE(ec) << ec.message();
    EXPECT_TRUE(store->verifyAnalyzerIdentity(error)) << error;
}

TEST(UnitEvidenceStoreTest, AnalyzerMutationCannotPublishCompletedEvidence) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    const auto analyzer = temporary.path() / "analyzer";
    {
        std::ofstream output(analyzer, std::ios::binary);
        output << "analyzer-v1";
    }
    const auto unit = sampleUnit();
    const auto dependencies = sampleDependencies();
    const auto response = sampleResponse(unit, dependencies);
    std::string error;
    auto store = UnitEvidenceStore::open(
        root.string(), {unit}, false, analyzer.string(),
        {"--lang", "en"}, {"null-deref"}, ResourceLimits{30, 1024},
        error);
    ASSERT_NE(store, nullptr) << error;
    std::error_code ec;
    const auto original_time = std::filesystem::last_write_time(analyzer, ec);
    ASSERT_FALSE(ec) << ec.message();
    {
        std::ofstream output(analyzer,
                             std::ios::binary | std::ios::trunc);
        output << "analyzer-v2";
    }
    std::filesystem::last_write_time(analyzer, original_time, ec);
    ASSERT_FALSE(ec) << ec.message();
    std::string key;
    std::string payload;

    EXPECT_FALSE(store->store(
        unit, TranslationUnitPhase::Analysis, dependencies,
        std::string(64, '2'), response, {}, key, payload, error));
    EXPECT_NE(error.find("analyzer identity"), std::string::npos) << error;

    {
        std::ofstream output(analyzer,
                             std::ios::binary | std::ios::trunc);
        output << "analyzer-v1";
    }
    std::filesystem::last_write_time(analyzer, original_time, ec);
    ASSERT_FALSE(ec) << ec.message();
    CachedUnitEvidence cached;
    EXPECT_EQ(store->lookup(
                  unit, TranslationUnitPhase::Analysis, dependencies,
                  std::string(64, '2'), cached, error),
              EvidenceLookupStatus::Miss) << error;
}

TEST(UnitEvidenceStoreTest, EntryStagingRemainderRecoversButSymlinkFails) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    const auto unit = sampleUnit();
    const auto dependencies = sampleDependencies();
    const auto response = sampleResponse(unit, dependencies);
    std::string error;
    auto store = openStore(root, {unit}, error);
    ASSERT_NE(store, nullptr) << error;
    std::string key;
    std::string payload;
    ASSERT_TRUE(store->store(
        unit, TranslationUnitPhase::Analysis, dependencies,
        std::string(64, '2'), response, {}, key, payload, error)) << error;
    const auto staging = root / "entries" / (key + ".tmp");
    ASSERT_TRUE(std::filesystem::create_directory(staging));
    {
        std::ofstream partial(staging / "partial.json",
                              std::ios::binary | std::ios::trunc);
        partial << "{interrupted";
    }
    std::string resumed_key;
    std::string resumed_payload;
    EXPECT_TRUE(store->store(
        unit, TranslationUnitPhase::Analysis, dependencies,
        std::string(64, '2'), response, {}, resumed_key, resumed_payload,
        error)) << error;
    EXPECT_FALSE(std::filesystem::exists(staging));

#ifndef _WIN32
    const auto outside = temporary.path() / "outside.txt";
    {
        std::ofstream output(outside, std::ios::binary | std::ios::trunc);
        output << "sentinel\n";
    }
    std::error_code ec;
    std::filesystem::create_symlink(outside, staging, ec);
    ASSERT_FALSE(ec) << ec.message();
    EXPECT_FALSE(store->store(
        unit, TranslationUnitPhase::Analysis, dependencies,
        std::string(64, '2'), response, {}, resumed_key, resumed_payload,
        error));
    EXPECT_NE(error.find("staging"), std::string::npos) << error;
    std::ifstream input(outside, std::ios::binary);
    const std::string contents((std::istreambuf_iterator<char>(input)),
                               std::istreambuf_iterator<char>());
    EXPECT_EQ(contents, "sentinel\n");
#endif
}

TEST(UnitEvidenceStoreTest, ExpiredDeadlineCannotPublishCompletedEvidence) {
    TemporaryEvidenceDirectory temporary;
    const auto root = temporary.path() / "checkpoint";
    const auto unit = sampleUnit();
    const auto dependencies = sampleDependencies();
    const auto response = sampleResponse(unit, dependencies);
    std::string error;
    auto store = openStore(root, {unit}, error);
    ASSERT_NE(store, nullptr) << error;
    std::string key;
    std::string payload;

    EXPECT_FALSE(store->store(
        unit, TranslationUnitPhase::Analysis, dependencies,
        std::string(64, '2'), response, {}, key, payload, error,
        std::chrono::steady_clock::now()));
    EXPECT_NE(error.find("deadline exhausted"), std::string::npos) << error;
    CachedUnitEvidence cached;
    EXPECT_EQ(store->lookup(
                  unit, TranslationUnitPhase::Analysis, dependencies,
                  std::string(64, '2'), cached, error),
              EvidenceLookupStatus::Miss) << error;
}

TEST(UnitEvidenceStoreTest, StreamingInputHashStopsAtDeadline) {
    TemporaryEvidenceDirectory temporary;
    const auto large = temporary.path() / "large-input.bin";
    {
        std::ofstream output(large, std::ios::binary | std::ios::trunc);
        output << 'x';
    }
    std::error_code ec;
    std::filesystem::resize_file(large, 256u << 20, ec);
    ASSERT_FALSE(ec) << ec.message();
    std::string error;
    const auto started = std::chrono::steady_clock::now();

    const std::string digest = orderedInputFilesSha256(
        {large.string()}, error,
        started + std::chrono::milliseconds(2));
    const auto elapsed_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count());

    EXPECT_TRUE(digest.empty());
    EXPECT_NE(error.find("deadline exhausted"), std::string::npos) << error;
    EXPECT_LT(elapsed_ms, 2000u);
}
