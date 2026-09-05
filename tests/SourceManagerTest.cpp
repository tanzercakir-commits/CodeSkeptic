#include "source_manager/SourceManager.h"
#include <clang/Tooling/CompilationDatabase.h>
#include <gtest/gtest.h>
#include <chrono>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;
using codeskeptic::SourceManager;

class SourceManagerTargetTest : public ::testing::Test {
protected:
    fs::path root;
    fs::path restricted;
    void SetUp() override {
        root = fs::path(::testing::TempDir()) / ("codeskeptic-targets-" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        ASSERT_TRUE(fs::create_directory(root));
        std::ofstream(root / "kept.cpp") << "int kept(){return 1;}\n";
    }
    void TearDown() override {
        std::error_code error;
        if (!restricted.empty()) fs::permissions(restricted, fs::perms::owner_all, error);
        fs::remove_all(root, error);
    }
};

TEST_F(SourceManagerTargetTest, InvalidFileTargetsPreserveAcceptedState) {
    SourceManager manager(root.string(), nullptr, true);
    manager.addSourceFile((root / "kept.cpp").string());
    const auto before = manager.files();
    manager.addSourceFile(root.string());
    EXPECT_EQ(manager.files(), before);
    std::ofstream(root / "not-source.txt") << "not a source";
    manager.addSourceFile((root / "not-source.txt").string());
    EXPECT_EQ(manager.files(), before);
    manager.addSourceFile((root / "missing.cpp").string());
    EXPECT_EQ(manager.files(), before);
}

TEST_F(SourceManagerTargetTest, FailedDirectoryScanNeverPublishesTraversedPrefix) {
    const auto tree = root / "tree";
    fs::create_directory(tree);
    for (const char* name : {"first", "second"}) {
        fs::create_directory(tree / name);
        std::ofstream(tree / name / "input.cpp") << "int f(){return 2;}\n";
    }
    // Choose the last existing child in this host's traversal order. Changing
    // its permissions does not create/remove/reorder directory entries.
    for (const auto& entry : fs::directory_iterator(tree)) restricted = entry.path();
    std::error_code error;
    fs::permissions(restricted, fs::perms::none, error);
    if (error || std::ifstream(restricted / "input.cpp").good())
        GTEST_SKIP() << "host cannot enforce the unreadable-directory fixture";
    unsigned prefix = 0;
    bool traversalFailed = false;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(tree))
            if (entry.is_regular_file()) ++prefix;
    } catch (const fs::filesystem_error&) { traversalFailed = true; }
    ASSERT_TRUE(traversalFailed);
    ASSERT_GT(prefix, 0u) << "fixture must fail after a traversed source, not before it";
    SourceManager manager(root.string(), nullptr, true);
    manager.addSourceFile((root / "kept.cpp").string());
    const auto before = manager.files();
    manager.scanDirectory(tree.string());
    EXPECT_EQ(manager.files(), before);
}
