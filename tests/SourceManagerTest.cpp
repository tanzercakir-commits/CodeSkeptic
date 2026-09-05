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
    ASSERT_TRUE(manager.addSourceFile((root / "kept.cpp").string()));
    const auto before = manager.files();
    codeskeptic::InputError error;
    EXPECT_FALSE(manager.addSourceFile(root.string(), &error));
    EXPECT_EQ(error.reason, "invalid_target");
    EXPECT_EQ(error.field, "path");
    EXPECT_EQ(manager.files(), before);
    std::ofstream(root / "not-source.txt") << "not a source";
    EXPECT_FALSE(manager.addSourceFile((root / "not-source.txt").string(), &error));
    EXPECT_EQ(manager.files(), before);
    EXPECT_FALSE(manager.addSourceFile((root / "missing.cpp").string(), &error));
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
    codeskeptic::InputError inputError;
    EXPECT_FALSE(manager.scanDirectory(tree.string(), &inputError));
    EXPECT_EQ(inputError.reason, "read_error");
    EXPECT_EQ(manager.files(), before);
}

TEST_F(SourceManagerTargetTest, ValidScanAfterRejectedScanCommitsTogether) {
    SourceManager manager(root.string(), nullptr, true);
    codeskeptic::InputError error;
    EXPECT_FALSE(manager.scanDirectory((root / "missing").string(), &error));
    EXPECT_TRUE(manager.files().empty());
    ASSERT_TRUE(manager.scanDirectory(root.string(), &error));
    EXPECT_TRUE(error.reason.empty());
    EXPECT_EQ(manager.files(), std::vector<std::string>{(root / "kept.cpp").string()});
}
