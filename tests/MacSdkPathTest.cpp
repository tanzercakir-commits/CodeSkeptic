#include "source_manager/ResourceDir.h"
#include "core/ExitPolicy.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using codeskeptic::analysisExitCode;
using codeskeptic::resolveMacSdkPath;

namespace {

// Temp dir helper mirroring ResourceDirTest's style.
struct TempDir {
    fs::path path;
    TempDir() {
        path = fs::temp_directory_path() /
               ("cs_sdk_test_" + std::to_string(::getpid()) + "_" +
                std::to_string(counter()++));
        fs::create_directories(path);
    }
    ~TempDir() { std::error_code ec; fs::remove_all(path, ec); }
    static int& counter() { static int c = 0; return c; }
};

} // namespace

// --- resolveMacSdkPath: the v0.4.5 P1 (baked CI Xcode path) ---

TEST(MacSdkPathTest, EnvSdkrootWinsVerbatim) {
    TempDir t;
    // Even over an existing xcrun path: SDKROOT is explicit intent.
    EXPECT_EQ(resolveMacSdkPath("/env/sdk", t.path.string(),
                                t.path.string()),
              "/env/sdk");
}

TEST(MacSdkPathTest, EnvHonoredEvenWhenMissing) {
    // A wrong SDKROOT must fail LOUDLY downstream (exit-2), not be
    // silently second-guessed into a different SDK.
    EXPECT_EQ(resolveMacSdkPath("/definitely/missing/sdk", "", ""),
              "/definitely/missing/sdk");
}

TEST(MacSdkPathTest, XcrunUsedWhenItExists) {
    TempDir t;
    EXPECT_EQ(resolveMacSdkPath("", t.path.string(), "/baked/missing"),
              t.path.string());
}

TEST(MacSdkPathTest, MissingXcrunFallsThroughToBaked) {
    TempDir t;
    EXPECT_EQ(resolveMacSdkPath("", "/xcrun/missing", t.path.string()),
              t.path.string());
}

TEST(MacSdkPathTest, BakedOnlyIfItExists) {
    // The P1 itself: the CI runner's versioned Xcode path, absent on
    // the user's machine, must NOT be injected.
    EXPECT_EQ(resolveMacSdkPath("", "", "/Applications/Xcode_15.4.app/x"),
              "");
}

TEST(MacSdkPathTest, AllMissingYieldsEmpty) {
    EXPECT_EQ(resolveMacSdkPath("", "", ""), "");
}

// --- analysisExitCode: the fail-loud half ---

TEST(ExitPolicyTest, CleanRunIsZero) {
    EXPECT_EQ(analysisExitCode(0, 5, 0, false), 0);
}

TEST(ExitPolicyTest, FindingsAreOne) {
    EXPECT_EQ(analysisExitCode(3, 5, 0, false), 1);
}

TEST(ExitPolicyTest, AllBrokenIsTwo) {
    // "Clean! + exit 0" with zero coverage was the worst failure mode
    // an analyzer can have in CI (external macOS evaluation, P1).
    EXPECT_EQ(analysisExitCode(0, 3, 3, false), 2);
}

TEST(ExitPolicyTest, PartialBreakageKeepsFindingsSemantics) {
    EXPECT_EQ(analysisExitCode(0, 3, 2, false), 0);
    EXPECT_EQ(analysisExitCode(1, 3, 2, false), 1);
}

TEST(ExitPolicyTest, ForcedAnalysisKeepsOldBehavior) {
    EXPECT_EQ(analysisExitCode(0, 3, 3, true), 0);
}

TEST(ExitPolicyTest, NoInputsIsZeroNotTwo) {
    // An empty run (no files matched) is not "analysis failed".
    EXPECT_EQ(analysisExitCode(0, 0, 0, false), 0);
}
