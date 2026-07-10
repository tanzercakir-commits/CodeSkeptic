// HTML rapor: tek kendine-yeten dosya. Degismezler: (1) her kullanici
// verisi HTML-escape'lidir (kaynak koddaki <script> rapora sizamaz),
// (2) izler kaynak baglamiyla gomulur (rapor tasinabilir), (3) ozet
// kartlari/filtre iskeleti ve bos-rapor hali dogru uretilir.

#include "reporter/HtmlReporter.h"

#include <fstream>
#include <gtest/gtest.h>

using namespace zerodefect;

namespace {

std::string readWhole(const std::string& path) {
    std::ifstream file(path);
    return {std::istreambuf_iterator<char>(file),
            std::istreambuf_iterator<char>()};
}

Diagnostic makeDiag(const std::string& file, unsigned line,
                    const std::string& rule, const std::string& message,
                    Severity sev = Severity::Warning) {
    Diagnostic d{sev, file, line, 1, rule, message};
    d.function = "f";
    return d;
}

} // anonymous namespace

TEST(HtmlReporterTest, BasicStructure_CardsFiltersFindings) {
    std::string out = ::testing::TempDir() + "report_basic.html";
    DiagnosticList diags = {
        makeDiag("a.cpp", 3, "null-deref", "maybe null", Severity::Warning),
        makeDiag("b.cpp", 7, "memory-leak", "leaked", Severity::Error),
    };
    HtmlReporter reporter(out);
    reporter.report(diags);

    std::string html = readWhole(out);
    EXPECT_NE(html.find("<!DOCTYPE html>"), std::string::npos);
    // Ozet kartlari (ayni zamanda filtre): severity + kural
    EXPECT_NE(html.find("data-sev=\"error\""), std::string::npos);
    EXPECT_NE(html.find("data-rule=\"memory-leak\""), std::string::npos);
    // Bulgu govdesi ve konum
    EXPECT_NE(html.find("a.cpp:3:1"), std::string::npos);
    EXPECT_NE(html.find("maybe null"), std::string::npos);
    // Filtre iskeleti: metin kutusu + script
    EXPECT_NE(html.find("id=\"q\""), std::string::npos);
    EXPECT_NE(html.find("<script>"), std::string::npos);
    // Dis kaynak yok (kendine yeten dosya)
    EXPECT_EQ(html.find("http://"), std::string::npos);
    EXPECT_EQ(html.find("https://"), std::string::npos);
}

TEST(HtmlReporterTest, UserData_IsHtmlEscaped) {
    std::string out = ::testing::TempDir() + "report_escape.html";
    DiagnosticList diags = {
        makeDiag("evil<script>.cpp", 1, "null-deref",
                 "deref of 'p' where a<b & c>\"d\""),
    };
    HtmlReporter reporter(out);
    reporter.report(diags);

    std::string html = readWhole(out);
    EXPECT_EQ(html.find("evil<script>"), std::string::npos);
    EXPECT_NE(html.find("evil&lt;script&gt;"), std::string::npos);
    EXPECT_NE(html.find("a&lt;b &amp; c&gt;&quot;d&quot;"),
              std::string::npos);
}

TEST(HtmlReporterTest, Trace_EmbedsSourceContext) {
    // Gercek bir kaynak dosya: iz notu ve bulgu, ±2 satir baglamla ve
    // hedef satir isaretli gomulmeli — rapor tasindiginda baglam kalir
    std::string src = ::testing::TempDir() + "ctx_demo.cpp";
    {
        std::ofstream f(src);
        f << "int line_one;\n"
          << "int* p = 0;\n"
          << "int x = *p;\n"
          << "int line_four;\n";
    }
    Diagnostic d = makeDiag(src, 3, "null-deref", "p is null",
                            Severity::Error);
    d.notes.push_back({src, 2, 1, "p assigned null here"});

    std::string out = ::testing::TempDir() + "report_ctx.html";
    HtmlReporter reporter(out);
    reporter.report({d});

    std::string html = readWhole(out);
    EXPECT_NE(html.find("Dataflow trace"), std::string::npos);
    EXPECT_NE(html.find("p assigned null here"), std::string::npos);
    // Kaynak satirlari gomulu (escape'li)
    EXPECT_NE(html.find("int* p = 0;"), std::string::npos);
    EXPECT_NE(html.find("int x = *p;"), std::string::npos);
    // Hedef satir isaretli
    EXPECT_NE(html.find("cl hit"), std::string::npos);
}

TEST(HtmlReporterTest, EmptyReport_ShowsClean) {
    std::string out = ::testing::TempDir() + "report_empty.html";
    HtmlReporter reporter(out);
    reporter.report({});

    std::string html = readWhole(out);
    EXPECT_NE(html.find("Clean! No issues found."), std::string::npos);
}

TEST(HtmlReporterTest, MissingSourceFile_NoContextButNoCrash) {
    // Kaynak yoksa (tasima/silme) baglam atlanir, rapor yine uretilir
    std::string out = ::testing::TempDir() + "report_nosrc.html";
    Diagnostic d = makeDiag("/no/such/file.cpp", 10, "memory-leak", "leak");
    d.notes.push_back({"/no/such/file.cpp", 5, 1, "allocated here"});
    HtmlReporter reporter(out);
    reporter.report({d});

    std::string html = readWhole(out);
    EXPECT_NE(html.find("allocated here"), std::string::npos);
    EXPECT_EQ(html.find("cl hit"), std::string::npos);
}
