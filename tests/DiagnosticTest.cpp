#include "core/Diagnostic.h"
#include "core/Messages.h"

#include <algorithm>
#include <gtest/gtest.h>

using namespace codeskeptic;

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

    // Error > Warning > Info (higher severity first)
    EXPECT_EQ(list[0].severity, Severity::Error);
    EXPECT_EQ(list[1].severity, Severity::Warning);
    EXPECT_EQ(list[2].severity, Severity::Info);
}

TEST(MessagesTest, LangSwitchAndSubstitution) {
    setLang(Lang::EN);
    std::string en = msg(MsgId::DoubleFree, "ptr");
    EXPECT_NE(en.find("Double free"), std::string::npos);
    EXPECT_NE(en.find("ptr"), std::string::npos);

    setLang(Lang::TR);
    std::string tr = msg(MsgId::DoubleFree, "ptr");
    EXPECT_NE(tr.find("Cift serbest birakma"), std::string::npos);
    EXPECT_NE(tr.find("ptr"), std::string::npos);

    setLang(Lang::EN);  // return to the default for other tests

    EXPECT_EQ(parseLang("tr"), Lang::TR);
    EXPECT_EQ(parseLang("en"), Lang::EN);
    EXPECT_EQ(parseLang("de"), Lang::EN);  // unknown -> default
}

TEST(DiagnosticTest, EqualityAndDedup) {
    Diagnostic d1{Severity::Warning, "a.cpp", 10, 5, "memory-leak", "msg"};
    Diagnostic dup = d1;
    Diagnostic other{Severity::Warning, "a.cpp", 10, 5, "uninit-ptr", "msg"};

    EXPECT_EQ(d1, dup);
    EXPECT_FALSE(d1 == other);

    // Equal records must be adjacent after sorting → unique deduplicates
    DiagnosticList list = {d1, other, dup};
    std::sort(list.begin(), list.end());
    list.erase(std::unique(list.begin(), list.end()), list.end());
    EXPECT_EQ(list.size(), 2u);
}

TEST(DiagnosticTest, SortByFileThenLine) {
    Diagnostic d1{Severity::Error, "b.cpp", 10, 1, "r", "m"};
    Diagnostic d2{Severity::Error, "a.cpp", 20, 1, "r", "m"};
    Diagnostic d3{Severity::Error, "a.cpp", 5, 1, "r", "m"};

    DiagnosticList list = {d1, d2, d3};
    std::sort(list.begin(), list.end());

    // Same severity → file alphabetical → line ascending
    EXPECT_EQ(list[0].file, "a.cpp");
    EXPECT_EQ(list[0].line, 5u);
    EXPECT_EQ(list[1].file, "a.cpp");
    EXPECT_EQ(list[1].line, 20u);
    EXPECT_EQ(list[2].file, "b.cpp");
}
