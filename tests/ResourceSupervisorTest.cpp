#include "core/ResourceSupervisor.h"
#include "core/ResourceWorkerControl.h"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

#ifndef CODESKEPTIC_RESOURCE_PROBE
#error "CODESKEPTIC_RESOURCE_PROBE must name the resource-budget probe"
#endif

using codeskeptic::ResourceLimits;
using codeskeptic::ResourceRunStatus;
using codeskeptic::ResourceSupervisor;

namespace codeskeptic {

struct ResourceSupervisorTestAccess {
    static ResourceRunResult failSecondMemorySample(
        const std::string& program,
        const std::vector<std::string>& arguments,
        ResourceLimits limits) {
        unsigned samples = 0;
        return ResourceSupervisor::runWithMemorySampler(
            program, arguments, limits, [&samples]() -> std::uint64_t {
                ++samples;
                return samples == 1 ? 1024u : 0u;
            });
    }
};

} // namespace codeskeptic

TEST(ResourceSupervisorTest, CompletedChildCarriesBoundedStatistics) {
    const auto result = ResourceSupervisor::run(
        CODESKEPTIC_RESOURCE_PROBE, {"complete"}, ResourceLimits{5, 512});

    EXPECT_EQ(result.status, ResourceRunStatus::Completed) << result.error;
    EXPECT_EQ(result.exit_code, 0);
    EXPECT_LT(result.duration_ms, 5000u);
    EXPECT_GT(result.peak_memory_kib, 0u);
}

TEST(ResourceSupervisorTest, SuccessfulExitWithoutCompletionMarkerFailsClosed) {
    const auto result = ResourceSupervisor::run(
        CODESKEPTIC_RESOURCE_PROBE, {"exit-without-done"},
        ResourceLimits{5, 512});

    EXPECT_EQ(result.status, ResourceRunStatus::Crashed);
    EXPECT_TRUE(
        result.error.find("completion handshake") != std::string::npos ||
        result.error.find("cannot sample running worker") != std::string::npos)
        << result.error;
}

TEST(ResourceSupervisorTest, PostReadySamplingFailureFailsClosed) {
    const auto result =
        codeskeptic::ResourceSupervisorTestAccess::failSecondMemorySample(
            CODESKEPTIC_RESOURCE_PROBE, {"complete"},
            ResourceLimits{5, 512});

    EXPECT_EQ(result.status, ResourceRunStatus::Crashed);
    EXPECT_EQ(result.exit_code, -2);
    EXPECT_NE(result.error.find("cannot sample running worker"),
              std::string::npos) << result.error;
}

TEST(ResourceSupervisorTest, ParentPeakDoesNotPolluteCompletedChild) {
    std::vector<std::unique_ptr<unsigned char[]>> parent_blocks;
    parent_blocks.reserve(600);
    for (unsigned i = 0; i < 600; ++i) {
        auto block = std::make_unique<unsigned char[]>(1u << 20);
        for (std::size_t offset = 0; offset < (1u << 20); offset += 4096)
            block[offset] = static_cast<unsigned char>(i);
        parent_blocks.push_back(std::move(block));
    }

    const auto result = ResourceSupervisor::run(
        CODESKEPTIC_RESOURCE_PROBE, {"complete"}, ResourceLimits{5, 512});

    EXPECT_EQ(result.status, ResourceRunStatus::Completed)
        << "parent RSS must not be charged to the exec'd child: "
        << result.peak_memory_kib << " KiB; " << result.error;
    EXPECT_EQ(result.exit_code, 0);
    EXPECT_GT(result.peak_memory_kib, 0u);
    EXPECT_LT(result.peak_memory_kib, 512u * 1024u);
}

TEST(ResourceSupervisorTest, TimeoutKillsChildWithinBound) {
    const auto started = std::chrono::steady_clock::now();
    const auto result = ResourceSupervisor::run(
        CODESKEPTIC_RESOURCE_PROBE, {"sleep", "10"},
        ResourceLimits{1, 512});
    const auto observed_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count());

    EXPECT_EQ(result.status, ResourceRunStatus::TimedOut);
    EXPECT_GE(result.duration_ms, 900u);
    EXPECT_LT(result.duration_ms, 5000u);
    EXPECT_LT(observed_ms, 5000u);
}

TEST(ResourceSupervisorTest, MemoryCeilingIsIndependentlyTriggerable) {
    const auto result = ResourceSupervisor::run(
        CODESKEPTIC_RESOURCE_PROBE, {"allocate", "512"},
        ResourceLimits{10, 64});

    EXPECT_EQ(result.status, ResourceRunStatus::MemoryExceeded)
        << result.error;
    EXPECT_LT(result.duration_ms, 5000u);
    EXPECT_NE(result.status, ResourceRunStatus::TimedOut);
}

TEST(ResourceSupervisorTest, FreedTransientPeakStillExceedsMemoryCeiling) {
    const auto result = ResourceSupervisor::run(
        CODESKEPTIC_RESOURCE_PROBE, {"allocate", "96"},
        ResourceLimits{10, 64});

    EXPECT_EQ(result.status, ResourceRunStatus::MemoryExceeded)
        << "a freed peak must remain observable: "
        << result.peak_memory_kib << " KiB; " << result.error;
    EXPECT_NE(result.status, ResourceRunStatus::TimedOut);
}

TEST(ResourceSupervisorTest, MissingProgramFailsWithoutVerdict) {
    const auto result = ResourceSupervisor::run(
        "definitely-missing-codeskeptic-worker", {},
        ResourceLimits{1, 64});
    EXPECT_EQ(result.status, ResourceRunStatus::LaunchFailed);
    EXPECT_NE(result.error.find("missing"), std::string::npos);
}

TEST(ResourceSupervisorTest, ChildHandshakeStopsWhenSupervisorIsGone) {
    const std::filesystem::path directory =
        std::filesystem::path(::testing::TempDir()) /
        "codeskeptic-dead-supervisor";
    std::filesystem::remove_all(directory);
    std::filesystem::create_directories(directory);
    std::vector<std::string> storage{
        "probe",
        std::string(codeskeptic::kResourceControlArgument) +
            directory.string(),
        std::string(codeskeptic::kResourceParentArgument) +
            "18446744073709551615",
    };
    std::vector<char*> argv;
    for (auto& value : storage) argv.push_back(value.data());
    argv.push_back(nullptr);
    int argc = static_cast<int>(storage.size());
    std::string error;

    EXPECT_EQ(codeskeptic::initializeResourceWorker(
                  argc, argv.data(), error),
              codeskeptic::ResourceWorkerInitialization::Failed);
    EXPECT_NE(error.find("supervisor exited"), std::string::npos) << error;
    std::filesystem::remove_all(directory);
}
