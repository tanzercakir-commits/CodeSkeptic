#include "core/Diagnostic.h"

#include <algorithm>
#include <gtest/gtest.h>

using namespace zerodefect;

TEST(DiagnosticTest, SeverityToString) {
    Diagnostic info{Severity::Info, "f.cpp", 1, 1, "r", "m"};
    Diagnostic warn{Severity::Warning, "f.cpp", 1, 1, "r", "m"};
    Diagnostic err{Severity::Error, "f.cpp", 1, 1, "r", "m"};

    EXPECT_EQ(info.severityToString(), "info");
    EXPECT_EQ(warn.severityToString(), "warning");
    EXPECT_EQ(err.severityToString(), "error");
}

TEST(DiagnosticTest, Location) {
    Diagnostic d{Severity::Warning, "/src/main.cpp", 42, 10, "rule", "msg"};
    EXPECT_EQ(d.location(), "/src/main.cpp:42:10");
}

TEST(DiagnosticTest, SortBySeverity) {
    Diagnostic info{Severity::Info, "a.cpp", 1, 1, "r", "m"};
    Diagnostic warn{Severity::Warning, "a.cpp", 1, 1, "r", "m"};
    Diagnostic err{Severity::Error, "a.cpp", 1, 1, "r", "m"};

    DiagnosticList list = {info, warn, err};
    std::sort(list.begin(), list.end());

    // Error > Warning > Info (severity büyük olan önce)
    EXPECT_EQ(list[0].severity, Severity::Error);
    EXPECT_EQ(list[1].severity, Severity::Warning);
    EXPECT_EQ(list[2].severity, Severity::Info);
}

TEST(DiagnosticTest, SortByFileThenLine) {
    Diagnostic d1{Severity::Error, "b.cpp", 10, 1, "r", "m"};
    Diagnostic d2{Severity::Error, "a.cpp", 20, 1, "r", "m"};
    Diagnostic d3{Severity::Error, "a.cpp", 5, 1, "r", "m"};

    DiagnosticList list = {d1, d2, d3};
    std::sort(list.begin(), list.end());

    // Aynı severity → dosya alfabetik → satır küçükten büyüğe
    EXPECT_EQ(list[0].file, "a.cpp");
    EXPECT_EQ(list[0].line, 5u);
    EXPECT_EQ(list[1].file, "a.cpp");
    EXPECT_EQ(list[1].line, 20u);
    EXPECT_EQ(list[2].file, "b.cpp");
}
