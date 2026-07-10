#include "server/McpServer.h"

#include "core/FunctionFilter.h"
#include "source_manager/SourceManager.h"

#include <fstream>
#include <string>
#include <gtest/gtest.h>

using namespace zerodefect;

namespace {

std::string writeTempSource(const std::string& name,
                            const std::string& content) {
    std::string path = ::testing::TempDir() + name;
    std::ofstream file(path);
    file << content;
    return path;
}

} // anonymous namespace

TEST(McpServerTest, Initialize) {
    auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}})");
    EXPECT_NE(response.find("\"protocolVersion\""), std::string::npos);
    EXPECT_NE(response.find("zerodefect"), std::string::npos);
    EXPECT_NE(response.find("\"tools\""), std::string::npos);
}

TEST(McpServerTest, NotificationGetsNoResponse) {
    auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","method":"notifications/initialized"})");
    EXPECT_TRUE(response.empty());
}

TEST(McpServerTest, Ping) {
    auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":7,"method":"ping"})");
    EXPECT_NE(response.find("\"result\""), std::string::npos);
    EXPECT_NE(response.find("\"id\":7"), std::string::npos);
}

TEST(McpServerTest, ToolsListContainsAnalyze) {
    auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":2,"method":"tools/list"})");
    EXPECT_NE(response.find("\"analyze\""), std::string::npos);
    EXPECT_NE(response.find("\"inputSchema\""), std::string::npos);
    EXPECT_NE(response.find("dataflow traces"), std::string::npos);
}

TEST(McpServerTest, UnknownMethod_Error) {
    auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":3,"method":"no/such"})");
    EXPECT_NE(response.find("-32601"), std::string::npos);
}

TEST(McpServerTest, ParseError) {
    auto response = handleMcpMessage("this is not json");
    EXPECT_NE(response.find("-32700"), std::string::npos);
}

TEST(McpServerTest, AnalyzeCallReturnsFindingsWithTrace) {
    auto path = writeTempSource("mcp_uaf.cpp", R"(
        void f() {
            int* p = new int(1);
            delete p;
            int x = *p;
            (void)x;
        }
    )");

    std::string request =
        R"({"jsonrpc":"2.0","id":4,"method":"tools/call,)";
    request =
        std::string(R"({"jsonrpc":"2.0","id":4,"method":"tools/call",)") +
        R"("params":{"name":"analyze","arguments":{"path":")" + path +
        R"("}}})";
    auto response = handleMcpMessage(request);

    EXPECT_NE(response.find("use-after-free"), std::string::npos);
    EXPECT_NE(response.find("allocated here"), std::string::npos);
    EXPECT_NE(response.find("freed here"), std::string::npos);
    // Ic JSON, text alaninda kacirilmis tirnakla tasinir: \"count\":
    EXPECT_NE(response.find("\\\"count\\\":"), std::string::npos);
}

TEST(McpServerTest, AnalyzeWithFunctionScope) {
    auto path = writeTempSource("mcp_two.cpp", R"(
        void first() { int* a; int x = *a; (void)x; }
        void second() { int* b; int y = *b; (void)y; }
    )");

    std::string request =
        std::string(R"({"jsonrpc":"2.0","id":5,"method":"tools/call",)") +
        R"("params":{"name":"analyze","arguments":{"path":")" + path +
        R"(","functions":"second"}}})";
    auto response = handleMcpMessage(request);

    EXPECT_EQ(response.find("'a'"), std::string::npos);
    EXPECT_NE(response.find("'b'"), std::string::npos);
    EXPECT_NE(response.find("\\\"count\\\":1"), std::string::npos);
}

TEST(McpServerTest, FilterStateResetAfterScopedAnalyze) {
    // Regresyon: filtreli analyze cagrisi global fonksiyon/satir
    // filtresini set edip birakirsa, ayni surecteki SONRAKI analizler
    // sessizce budanir (uzun omurlu MCP server + tek-surec test kosumu).
    // Bulgu kaybi olarak yasandi: InterproceduralTest'in 11 testi
    // tek-surec kosumda dusuyordu, ctest izolasyonu gizliyordu.
    auto path = writeTempSource("mcp_scope_reset.cpp", R"(
        void first() { int* a; int x = *a; (void)x; }
        void second() { int* b; int y = *b; (void)y; }
    )");

    std::string request =
        std::string(R"({"jsonrpc":"2.0","id":9,"method":"tools/call",)") +
        R"("params":{"name":"analyze","arguments":{"path":")" + path +
        R"(","functions":"second","lines":"1-2"}}})";
    handleMcpMessage(request);

    EXPECT_TRUE(zerodefect::functionFilter().empty());
    EXPECT_TRUE(zerodefect::lineRanges().empty());
}

namespace {

std::string analyzeRequest(int id, const std::string& path) {
    return std::string(R"({"jsonrpc":"2.0","id":)") + std::to_string(id) +
           R"(,"method":"tools/call",)" +
           R"("params":{"name":"analyze","arguments":{"path":")" + path +
           R"("}}})";
}

} // anonymous namespace

TEST(McpServerTest, WarmCache_SecondCallHits) {
    // MCP uzun omurlu surec: ayni dosyaya ikinci analyze cagrisi parse
    // maliyeti odememeli — ve onbellekten gelen AST AYNI bulgulari
    // uretmeli (onbellek davranis degistirmez, sadece hizlandirir).
    SourceManager::clearWarmCache();
    auto path = writeTempSource("mcp_warm_hit.cpp", R"(
        void f() {
            int* p = new int(1);
            delete p;
            int x = *p;
            (void)x;
        }
    )");

    auto first = handleMcpMessage(analyzeRequest(20, path));
    EXPECT_GE(SourceManager::warmCacheMisses(), 1u);
    EXPECT_EQ(SourceManager::warmCacheHits(), 0u);

    auto second = handleMcpMessage(analyzeRequest(21, path));
    EXPECT_GE(SourceManager::warmCacheHits(), 1u);

    EXPECT_NE(first.find("use-after-free"), std::string::npos);
    EXPECT_NE(second.find("use-after-free"), std::string::npos);
    EXPECT_NE(second.find("\\\"count\\\":1"), std::string::npos);
}

TEST(McpServerTest, WarmCache_InvalidatedOnChange) {
    // Tasarim degismezi: BAYAT AST ASLA SERVIS EDILMEZ. Dosya degisince
    // (farkli boyut -> farkli parmak izi) ikinci cagri YENI icerigin
    // bulgularini vermeli — eski use-after-free kaybolur, yeni
    // div-by-zero gorunur.
    SourceManager::clearWarmCache();
    auto path = writeTempSource("mcp_warm_inval.cpp", R"(
        void f() {
            int* p = new int(1);
            delete p;
            int x = *p;
            (void)x;
        }
    )");

    auto first = handleMcpMessage(analyzeRequest(22, path));
    EXPECT_NE(first.find("use-after-free"), std::string::npos);

    // Ayni yol, farkli boyutta yeni icerik: UAF yok, sifira bolme var
    writeTempSource("mcp_warm_inval.cpp", R"(
        int g(int n) {
            if (n == 0) {
                return 100 / n;
            }
            return 0;
        }
    )");

    auto second = handleMcpMessage(analyzeRequest(23, path));
    EXPECT_EQ(second.find("use-after-free"), std::string::npos);
    EXPECT_NE(second.find("div-by-zero"), std::string::npos);
}

TEST(McpServerTest, AnalyzeWithSummaries_CrossFileKnowledge) {
    // "summaries" argumani: --summary-out ile yazilmis dosya MCP analyze
    // cagrisina verilir — tek dosya, tum-proje bilgisiyle analiz edilir.
    // Ayni cagri ozetsiz sessiz (kontrol grubu; bilgi dosyadan geliyor).
    auto caller = writeTempSource("mcp_sum_caller.cpp", R"(
        int* find(int c);
        void f(int c) {
            int* p = find(c);
            int x = *p;
            (void)x;
        }
    )");
    auto sumPath = writeTempSource("mcp_sum_store.txt",
        "zerodefect-summaries v2\nfind/1\tM\t-\tU\n");

    auto without = handleMcpMessage(
        std::string(R"({"jsonrpc":"2.0","id":30,"method":"tools/call",)") +
        R"("params":{"name":"analyze","arguments":{"path":")" + caller +
        R"("}}})");
    EXPECT_EQ(without.find("null-deref"), std::string::npos);

    auto with = handleMcpMessage(
        std::string(R"({"jsonrpc":"2.0","id":31,"method":"tools/call",)") +
        R"("params":{"name":"analyze","arguments":{"path":")" + caller +
        R"(","summaries":")" + sumPath + R"("}}})");
    EXPECT_NE(with.find("null-deref"), std::string::npos);
}

TEST(McpServerTest, ToolsListMentionsSummaries) {
    auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":32,"method":"tools/list"})");
    EXPECT_NE(response.find("\"summaries\""), std::string::npos);
}

TEST(McpServerTest, AnalyzeMissingPath_Error) {
    auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":6,"method":"tools/call",)"
        R"("params":{"name":"analyze","arguments":{}}})");
    EXPECT_NE(response.find("-32602"), std::string::npos);
}

TEST(McpServerTest, UnknownTool_Error) {
    auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":8,"method":"tools/call",)"
        R"("params":{"name":"no_such_tool","arguments":{}}})");
    EXPECT_NE(response.find("-32602"), std::string::npos);
}
