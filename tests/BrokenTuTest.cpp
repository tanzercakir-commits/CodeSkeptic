#include "config/Config.h"
#include "source_manager/SourceManager.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>

using namespace codeskeptic;
namespace fs = std::filesystem;

// Broken-TU guard (#86): a TU whose parse ends in an uncompilable
// error is SKIPPED by default — clang's error recovery eats
// initializers and declarations, and rules then report confidently
// about code that does not exist (measured on Godot: a single missing
// generated header turned into 298 spurious uninit-ptr ERRORS across
// 176 TUs). --analyze-broken-tus restores the old behavior.

namespace {

struct TempTu {
    fs::path dir;
    TempTu(const char* name, const char* source) {
        dir = fs::temp_directory_path() / name;
        fs::create_directories(dir);
        {
            std::ofstream f(dir / "bad.cpp");
            f << source;
        }
        {
            std::ofstream db(dir / "compile_commands.json");
            // generic_string(): forward slashes. A native Windows path
            // ("C:\Users\...") embedded raw is invalid JSON — "\U" is
            // not an escape — and the whole DB fails to parse.
            db << "[{\"directory\": \"" << dir.generic_string()
               << "\", \"command\": \"c++ -c bad.cpp\", \"file\": "
                  "\"bad.cpp\"}]";
        }
    }
    ~TempTu() { std::error_code ec; fs::remove_all(dir, ec); }
};

constexpr const char* kBrokenSource =
    "#include \"no_such_header_cs_test.h\"\n"
    "int f() { int *p = make(); return *p; }\n";

} // namespace

TEST(BrokenTuTest, BrokenTuIsSkippedAndRecorded) {
    TempTu tu("cs_broken_tu_skip", kBrokenSource);
    SourceManager::setAnalyzeBrokenTUs(false);
    SourceManager::clearBrokenTUs();

    SourceManager sm(tu.dir.string());
    sm.addSourceFile((tu.dir / "bad.cpp").string());
    int callbacks = 0;
    sm.processAll([&](clang::ASTContext&) { ++callbacks; });

    EXPECT_EQ(callbacks, 0);
    ASSERT_EQ(SourceManager::brokenTUs().size(), 1u);
    SourceManager::clearBrokenTUs();
}

TEST(BrokenTuTest, AnalyzeBrokenTUsOverride) {
    TempTu tu("cs_broken_tu_force", kBrokenSource);
    SourceManager::setAnalyzeBrokenTUs(true);
    SourceManager::clearBrokenTUs();

    SourceManager sm(tu.dir.string());
    sm.addSourceFile((tu.dir / "bad.cpp").string());
    int callbacks = 0;
    sm.processAll([&](clang::ASTContext&) { ++callbacks; });

    EXPECT_EQ(callbacks, 1);
    EXPECT_TRUE(SourceManager::brokenTUs().empty());
    SourceManager::setAnalyzeBrokenTUs(false);
}

TEST(BrokenTuTest, CleanTuStillAnalyzed) {
    TempTu tu("cs_broken_tu_clean", "int f() { return 0; }\n");
    SourceManager::setAnalyzeBrokenTUs(false);
    SourceManager::clearBrokenTUs();

    SourceManager sm(tu.dir.string());
    sm.addSourceFile((tu.dir / "bad.cpp").string());
    int callbacks = 0;
    sm.processAll([&](clang::ASTContext&) { ++callbacks; });

    EXPECT_EQ(callbacks, 1);
    EXPECT_TRUE(SourceManager::brokenTUs().empty());
}

TEST(BrokenTuTest, ConfigFlagParsed) {
    Config config;
    const char* argv[] = {"codeskeptic", "--analyze-broken-tus", "d.cpp"};
    ASSERT_TRUE(config.parseArgs(3, const_cast<char**>(argv)));
    EXPECT_TRUE(config.analyzeBrokenTUs());
}
