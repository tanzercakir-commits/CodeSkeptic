#include "analyzer/Baseline.h"

#include <fstream>
#include <gtest/gtest.h>

using namespace zerodefect;

namespace {

Diagnostic makeDiag(const std::string& file, unsigned line,
                    const std::string& rule, const std::string& message) {
    return {Severity::Warning, file, line, 1, rule, message};
}

std::string writeSource(const std::string& name,
                        const std::string& content) {
    std::string path = ::testing::TempDir() + name;
    std::ofstream file(path);
    file << content;
    return path;
}

} // anonymous namespace

TEST(BaselineTest, WriteLoadFilterRoundtrip) {
    std::string path = ::testing::TempDir() + "baseline1.txt";

    DiagnosticList original = {
        makeDiag("a.cpp", 10, "memory-leak", "leak of p"),
        makeDiag("b.cpp", 20, "div-by-zero", "z is zero"),
    };
    ASSERT_TRUE(Baseline::write(path, original));

    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));

    // Ayni bulgular + bir yeni bulgu
    DiagnosticList current = original;
    current.push_back(makeDiag("c.cpp", 5, "uninit-ptr", "new finding"));

    size_t filtered = baseline.filter(current);
    EXPECT_EQ(filtered, 2u);
    ASSERT_EQ(current.size(), 1u);
    EXPECT_EQ(current[0].rule_id, "uninit-ptr");
}

TEST(BaselineTest, KeyV1IncludesLineAndMessage) {
    auto d1 = makeDiag("a.cpp", 10, "memory-leak", "leak of p");
    auto d2 = makeDiag("a.cpp", 11, "memory-leak", "leak of p");
    auto d3 = makeDiag("a.cpp", 10, "memory-leak", "leak of q");

    EXPECT_NE(Baseline::keyV1(d1), Baseline::keyV1(d2));
    EXPECT_NE(Baseline::keyV1(d1), Baseline::keyV1(d3));
}

TEST(BaselineTest, MissingFile_LoadFailsButFilterIsNoop) {
    Baseline baseline;
    EXPECT_FALSE(baseline.load("/nonexistent/baseline.txt"));

    DiagnosticList diags = { makeDiag("a.cpp", 1, "r", "m") };
    EXPECT_EQ(baseline.filter(diags), 0u);
    EXPECT_EQ(diags.size(), 1u);
}

TEST(BaselineTest, EmptyDiagnostics_WritesEmptyFile) {
    std::string path = ::testing::TempDir() + "baseline2.txt";
    ASSERT_TRUE(Baseline::write(path, {}));

    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    DiagnosticList diags = { makeDiag("a.cpp", 1, "r", "m") };
    EXPECT_EQ(baseline.filter(diags), 0u);
}

// ===================================================================
// Baseline v2: satir-bagimsiz anahtar (satir icerigi hash'i)
// Degismezler: (1) kod kaydiginca baseline gecerli kalir, (2) satirin
// KENDISI degisince bulgu yeniden gorunur, (3) ozdes satirlar sayiyla
// izlenir — birini baseline'a almak digerini gizlemez, (4) eski v1
// dosyalari eski anlamiyla calismaya devam eder.
// ===================================================================

TEST(BaselineV2Test, LineShift_StillSuppressed) {
    // Bulgu satirinin USTUNE kod eklenir: satir numarasi kayar ama
    // icerik ayni — v1'in bilinen sinirlamasi, v2'de cozuldu
    auto src = writeSource("blv2_shift.cpp",
        "void f() {\n"
        "    int* p = new int(1);\n"
        "}\n");
    std::string path = ::testing::TempDir() + "blv2_shift.txt";
    ASSERT_TRUE(Baseline::write(path,
        { makeDiag(src, 2, "memory-leak", "leak of p") }));

    // Ustune iki satir eklendi: bulgu artik 4. satirda
    writeSource("blv2_shift.cpp",
        "// yeni aciklama\n"
        "// bir satir daha\n"
        "void f() {\n"
        "    int* p = new int(1);\n"
        "}\n");
    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    DiagnosticList current = { makeDiag(src, 4, "memory-leak", "leak of p") };
    EXPECT_EQ(baseline.filter(current), 1u);
    EXPECT_TRUE(current.empty());
}

TEST(BaselineV2Test, ReindentedLine_StillSuppressed) {
    // Yalniz girinti degisti (ornegin blok bir if icine alindi ama
    // bulgu satiri ayni): kirpilmis icerik ayni -> bastirilmis kalir
    auto src = writeSource("blv2_indent.cpp",
        "int* p = new int(1);\n");
    std::string path = ::testing::TempDir() + "blv2_indent.txt";
    ASSERT_TRUE(Baseline::write(path,
        { makeDiag(src, 1, "memory-leak", "leak of p") }));

    writeSource("blv2_indent.cpp",
        "        int* p = new int(1);\n");
    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    DiagnosticList current = { makeDiag(src, 1, "memory-leak", "leak of p") };
    EXPECT_EQ(baseline.filter(current), 1u);
}

TEST(BaselineV2Test, ChangedLine_ResurfacesAsNew) {
    // Satirin KENDISI degisti: bulgu yeniden gorunmeli — degisen satir
    // yeniden gozden gecirilmeli (bilincli davranis)
    auto src = writeSource("blv2_changed.cpp",
        "int* p = new int(1);\n");
    std::string path = ::testing::TempDir() + "blv2_changed.txt";
    ASSERT_TRUE(Baseline::write(path,
        { makeDiag(src, 1, "memory-leak", "leak of p") }));

    writeSource("blv2_changed.cpp",
        "int* p = new int(42);\n");
    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    DiagnosticList current = { makeDiag(src, 1, "memory-leak", "leak of p") };
    EXPECT_EQ(baseline.filter(current), 0u);
    EXPECT_EQ(current.size(), 1u);
}

TEST(BaselineV2Test, IdenticalLines_CountedSeparately) {
    // Iki ayri konumda OZDES satir + ozdes mesaj: baseline'da BIR kayit
    // varsa yalniz BIR bulgu bastirilir — ikincisi yeni sayilir
    // (set semantigi olsaydi ikisi de sessizce yutulurdu)
    auto src = writeSource("blv2_dup.cpp",
        "void f() { delete p; }\n"
        "void g() { delete p; }\n");
    std::string path = ::testing::TempDir() + "blv2_dup.txt";
    ASSERT_TRUE(Baseline::write(path,
        { makeDiag(src, 1, "double-free", "double free of p") }));

    // Kirpilmis satir icerikleri farkli (f vs g) — bu test ayni ICERIGI
    // zorlamali: iki satir birebir ayni olsun
    src = writeSource("blv2_dup2.cpp",
        "    delete p;\n"
        "    delete p;\n");
    path = ::testing::TempDir() + "blv2_dup2.txt";
    ASSERT_TRUE(Baseline::write(path,
        { makeDiag(src, 1, "double-free", "double free of p") }));

    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));
    DiagnosticList current = {
        makeDiag(src, 1, "double-free", "double free of p"),
        makeDiag(src, 2, "double-free", "double free of p"),
    };
    EXPECT_EQ(baseline.filter(current), 1u);
    ASSERT_EQ(current.size(), 1u);

    // Iki kayitli baseline ikisini de bastirir
    ASSERT_TRUE(Baseline::write(path, {
        makeDiag(src, 1, "double-free", "double free of p"),
        makeDiag(src, 2, "double-free", "double free of p"),
    }));
    Baseline full;
    ASSERT_TRUE(full.load(path));
    DiagnosticList both = {
        makeDiag(src, 1, "double-free", "double free of p"),
        makeDiag(src, 2, "double-free", "double free of p"),
    };
    EXPECT_EQ(full.filter(both), 2u);
    EXPECT_TRUE(both.empty());
}

TEST(BaselineV2Test, OldV1File_StillMatchesByLine) {
    // Elle yazilmis v1 dosyasi (basliksiz, satir numarali anahtar):
    // ayni satirdaki bulgu bastirilir, kayan bulgu bastirilMAZ (eski
    // davranis korunur — tazeleyince v2'ye gecilir)
    std::string path = ::testing::TempDir() + "blv2_v1compat.txt";
    {
        std::ofstream file(path);
        file << "memory-leak|old.cpp|10|leak of p\n";
    }
    Baseline baseline;
    ASSERT_TRUE(baseline.load(path));

    DiagnosticList same = { makeDiag("old.cpp", 10, "memory-leak", "leak of p") };
    EXPECT_EQ(baseline.filter(same), 1u);

    DiagnosticList shifted = { makeDiag("old.cpp", 11, "memory-leak", "leak of p") };
    EXPECT_EQ(baseline.filter(shifted), 0u);
}

TEST(BaselineV2Test, FileHeaderWritten) {
    // v2 dosyasi surumlu basliyor — ileride format degisirse ayirt
    // edilebilir; '#' satirlari yuklemede yorumdur
    std::string path = ::testing::TempDir() + "blv2_header.txt";
    ASSERT_TRUE(Baseline::write(path, {}));
    std::ifstream file(path);
    std::string first;
    std::getline(file, first);
    EXPECT_EQ(first, "# zerodefect-baseline v2");
}
