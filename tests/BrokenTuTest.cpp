#include "config/Config.h"
#include "source_manager/SourceManager.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <set>
#include <thread>

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

TEST(BrokenTuTest, MissingCompileDatabaseKeepsFallbackAvailable) {
    const fs::path dir = fs::temp_directory_path() / "cs_missing_compdb";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);

    SourceManager sm(dir.string());

    EXPECT_TRUE(sm.compilationDatabaseValid());
    fs::remove_all(dir, ec);
}

TEST(BrokenTuTest, ExistingMalformedCompileDatabaseIsInvalidInput) {
    const fs::path dir = fs::temp_directory_path() / "cs_malformed_compdb";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);
    {
        std::ofstream db(dir / "compile_commands.json");
        db << "[{\"directory\":\"unterminated";
    }

    SourceManager sm(dir.string());

    EXPECT_FALSE(sm.compilationDatabaseValid());
    EXPECT_FALSE(sm.compilationDatabaseError().empty());
    fs::remove_all(dir, ec);
}

TEST(BrokenTuTest, NonRegularCompileDatabaseEntriesFailClosed) {
    const fs::path dir = fs::temp_directory_path() / "cs_nonregular_compdb";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);

    const fs::path database = dir / "compile_commands.json";
    fs::create_directory(database);
    {
        SourceManager sm(dir.string());
        EXPECT_FALSE(sm.compilationDatabaseValid());
        EXPECT_NE(sm.compilationDatabaseError().find("regular file"),
                  std::string::npos);
    }

    fs::remove_all(database, ec);
#ifndef _WIN32
    fs::create_symlink(dir / "missing-target.json", database, ec);
    ASSERT_FALSE(ec) << ec.message();
    {
        SourceManager sm(dir.string());
        EXPECT_FALSE(sm.compilationDatabaseValid());
        EXPECT_FALSE(sm.compilationDatabaseError().empty());
    }
#endif
    fs::remove_all(dir, ec);
}

TEST(BrokenTuTest, BufferValidationUsesProductionClangParser) {
    std::string error;
    EXPECT_TRUE(validateCompilationDatabaseText(
        R"([{"directory":".","arguments":["clang++","-c","x.cpp"],"file":"x.cpp"}])",
        error));
    EXPECT_TRUE(error.empty());

    EXPECT_FALSE(validateCompilationDatabaseText(
        "[{\"directory\":\"unterminated", error));
    EXPECT_FALSE(error.empty());

    std::string embeddedNul =
        "[{\"directory\":\".\",\"arguments\":[\"clang++\",\"-c\","
        "\"x.cpp\"],\"file\":\"x.cpp";
    embeddedNul.push_back('\0');
    embeddedNul += "suffix\"}]";
    EXPECT_FALSE(validateCompilationDatabaseText(embeddedNul, error));
    EXPECT_NE(error.find("NUL"), std::string::npos);

    EXPECT_FALSE(validateCompilationDatabaseText(
        R"([{"directory":".","arguments":["clang++","-c","x.cpp"],"file":"x.cpp\u0000file-suffix"}])",
        error));
    EXPECT_NE(error.find("NUL"), std::string::npos);

    EXPECT_FALSE(validateCompilationDatabaseText(
        R"([{"directory":".","arguments":["clang++","-c","x.cpp\u0000argument-suffix"],"file":"x.cpp"}])",
        error));
    EXPECT_NE(error.find("NUL"), std::string::npos);
}

TEST(BrokenTuTest, AnalysisWorkerIsSerialAndJoinedBeforeReturn) {
    const fs::path dir =
        fs::temp_directory_path() / "cs_serial_analysis_worker";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);
    for (const char* name : {"first.cpp", "second.cpp"}) {
        std::ofstream source(dir / name);
        source << "int " << name[0] << "() { return 0; }\n";
    }
    {
        std::ofstream database(dir / "compile_commands.json");
        database
            << "[{\"directory\":\"" << dir.generic_string()
            << "\",\"arguments\":[\"clang++\",\"-c\",\"first.cpp\"],"
               "\"file\":\"first.cpp\"},"
            << "{\"directory\":\"" << dir.generic_string()
            << "\",\"arguments\":[\"clang++\",\"-c\",\"second.cpp\"],"
               "\"file\":\"second.cpp\"}]";
    }

    SourceManager manager(dir.string());
    manager.addSourceFile((dir / "first.cpp").string());
    manager.addSourceFile((dir / "second.cpp").string());
    ASSERT_TRUE(manager.compilationDatabaseValid());

    const auto caller = std::this_thread::get_id();
    std::atomic<int> active{0};
    std::atomic<int> maximum{0};
    std::atomic<int> callbacks{0};
    std::mutex id_mutex;
    std::set<std::thread::id> worker_ids;
    const int result = manager.processAll([&](clang::ASTContext&) {
        const int now = active.fetch_add(1) + 1;
        int observed = maximum.load();
        while (observed < now &&
               !maximum.compare_exchange_weak(observed, now)) {}
        {
            std::lock_guard<std::mutex> lock(id_mutex);
            worker_ids.insert(std::this_thread::get_id());
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        callbacks.fetch_add(1);
        active.fetch_sub(1);
    });

    EXPECT_EQ(result, 0);
    EXPECT_EQ(callbacks.load(), 2);
    EXPECT_EQ(active.load(), 0);
    EXPECT_EQ(maximum.load(), 1);
    ASSERT_EQ(worker_ids.size(), 1u);
    EXPECT_NE(*worker_ids.begin(), caller);
    std::cout << "SERIAL_WORKER_EVIDENCE callbacks=" << callbacks.load()
              << " max_active=" << maximum.load()
              << " worker_threads=" << worker_ids.size()
              << " joined=" << (active.load() == 0 ? 1 : 0) << "\n";
    fs::remove_all(dir, ec);
}
