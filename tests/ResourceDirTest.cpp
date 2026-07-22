#include "source_manager/ResourceDir.h"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>

using codeskeptic::resolveResourceDir;
namespace fs = std::filesystem;

namespace {

// Fresh scratch root per test case.
fs::path scratch(const std::string& name) {
    fs::path root = fs::path(::testing::TempDir()) / ("resdir_" + name);
    fs::remove_all(root);
    fs::create_directories(root);
    return root;
}

// Lay down <base>/<version>/include/stddef.h — a qualifying resource dir.
void makeResourceDir(const fs::path& versionDir) {
    fs::create_directories(versionDir / "include");
    std::ofstream(versionDir / "include" / "stddef.h") << "// stub\n";
}

} // anonymous namespace

TEST(ResourceDirTest, OverrideWinsWhenItExists) {
    auto root = scratch("override");
    fs::create_directories(root / "custom");
    EXPECT_EQ(resolveResourceDir((root / "custom").string(), "", ""),
              (root / "custom").string());
}

TEST(ResourceDirTest, MissingOverrideFallsThrough) {
    auto root = scratch("missing_override");
    fs::create_directories(root / "baked");
    // Override points nowhere -> ignored; baked (existing) wins.
    EXPECT_EQ(resolveResourceDir((root / "nope").string(), "",
                                 (root / "baked").string()),
              (root / "baked").string());
}

TEST(ResourceDirTest, ExeRelativeLayoutIsFound) {
    auto root = scratch("layout");
    fs::create_directories(root / "bin");
    makeResourceDir(root / "lib" / "clang" / "20");
    EXPECT_EQ(resolveResourceDir("", (root / "bin").string(), ""),
              (root / "lib" / "clang" / "20").string());
}

TEST(ResourceDirTest, HighestVersionWins) {
    auto root = scratch("versions");
    fs::create_directories(root / "bin");
    makeResourceDir(root / "lib" / "clang" / "18");
    makeResourceDir(root / "lib" / "clang" / "20");
    fs::create_directories(root / "lib" / "clang" / "not-a-version");
    EXPECT_EQ(resolveResourceDir("", (root / "bin").string(), ""),
              (root / "lib" / "clang" / "20").string());
}

TEST(ResourceDirTest, VersionDirWithoutHeadersIsSkipped) {
    auto root = scratch("empty_shell");
    fs::create_directories(root / "bin");
    makeResourceDir(root / "lib" / "clang" / "18");
    // 20 exists but carries no intrinsic headers -> must not win.
    fs::create_directories(root / "lib" / "clang" / "20");
    EXPECT_EQ(resolveResourceDir("", (root / "bin").string(), ""),
              (root / "lib" / "clang" / "18").string());
}

TEST(ResourceDirTest, ExeRelativeBeatsBaked) {
    auto root = scratch("precedence");
    fs::create_directories(root / "bin");
    makeResourceDir(root / "lib" / "clang" / "20");
    fs::create_directories(root / "baked");
    EXPECT_EQ(resolveResourceDir("", (root / "bin").string(),
                                 (root / "baked").string()),
              (root / "lib" / "clang" / "20").string());
}

TEST(ResourceDirTest, BakedIsLastResortOnlyIfItExists) {
    auto root = scratch("baked");
    fs::create_directories(root / "baked");
    EXPECT_EQ(resolveResourceDir("", (root / "bin").string(), // no layout
                                 (root / "baked").string()),
              (root / "baked").string());
    // A baked path that no longer exists must never be handed to Clang.
    EXPECT_EQ(resolveResourceDir("", "", (root / "gone").string()), "");
}

TEST(ResourceDirTest, AllMissingYieldsEmpty) {
    EXPECT_EQ(resolveResourceDir("", "", ""), "");
}
