#include "server/McpServer.h"

#include "core/FunctionFilter.h"
#include "source_manager/SourceManager.h"

#include <fstream>
#include <string>
#include <gtest/gtest.h>

using namespace codeskeptic;

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
    EXPECT_NE(response.find("codeskeptic"), std::string::npos);
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
    // The inner JSON travels in the text field with escaped quotes: \"count\":
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
    // Regression: if a scoped analyze call sets the global function/line
    // filter and leaves it behind, SUBSEQUENT analyses in the same
    // process are silently pruned (long-lived MCP server + single-process
    // test run). Seen in the wild as lost findings: 11 tests of
    // InterproceduralTest failed in a single-process run, while ctest
    // isolation was hiding it.
    auto path = writeTempSource("mcp_scope_reset.cpp", R"(
        void first() { int* a; int x = *a; (void)x; }
        void second() { int* b; int y = *b; (void)y; }
    )");

    std::string request =
        std::string(R"({"jsonrpc":"2.0","id":9,"method":"tools/call",)") +
        R"("params":{"name":"analyze","arguments":{"path":")" + path +
        R"(","functions":"second","lines":"1-2"}}})";
    handleMcpMessage(request);

    EXPECT_TRUE(codeskeptic::functionFilter().empty());
    EXPECT_TRUE(codeskeptic::lineRanges().empty());
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
    // MCP is a long-lived process: a second analyze call on the same
    // file must not pay the parse cost — and the AST served from the
    // cache must produce the SAME findings (the cache does not change
    // behavior, it only speeds things up).
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
    // Design invariant: a STALE AST IS NEVER SERVED. When the file
    // changes (different size -> different fingerprint) the second call
    // must report the NEW content's findings — the old use-after-free
    // disappears, the new div-by-zero shows up.
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

    // Same path, new content with a different size: no UAF, has div-by-zero
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
    // The "summaries" argument: a file written with --summary-out is
    // handed to the MCP analyze call — a single file is analyzed with
    // whole-project knowledge. The same call without summaries is silent
    // (control group; the knowledge comes from the file).
    auto caller = writeTempSource("mcp_sum_caller.cpp", R"(
        int* find(int c);
        void f(int c) {
            int* p = find(c);
            int x = *p;
            (void)x;
        }
    )");
    auto sumPath = writeTempSource("mcp_sum_store.txt",
        "codeskeptic-summaries v2\nfind/1\tM\t-\tU\n");

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

// --- Project-idiom parameters (fatal_asserts / alloc/free_functions) ---

TEST(McpServerTest, ToolsListContainsIdiomParams) {
    auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":11,"method":"tools/list"})");
    EXPECT_NE(response.find("fatal_asserts"), std::string::npos);
    EXPECT_NE(response.find("alloc_functions"), std::string::npos);
    EXPECT_NE(response.find("free_functions"), std::string::npos);
}

TEST(McpServerTest, FatalAsserts_KillsPath_AndDoesNotLeakToNextCall) {
    auto path = writeTempSource("mcp_fatal.cpp", R"(
        void my_check_fail(const char*);
        int f(int* p) {
            if (!p) my_check_fail("p");
            return *p;
        }
    )");

    // With the handler registered the !p path dies at the call and the
    // dereference is clean.
    std::string withParam =
        std::string(R"({"jsonrpc":"2.0","id":12,"method":"tools/call",)") +
        R"("params":{"name":"analyze","arguments":{"path":")" + path +
        R"(","fatal_asserts":"my_check_fail"}}})";
    auto response = handleMcpMessage(withParam);
    EXPECT_NE(response.find("\\\"count\\\":0"), std::string::npos);

    // Long-lived process: the registration must NOT survive into the
    // next call — without the parameter the possible-null path is back.
    std::string withoutParam =
        std::string(R"({"jsonrpc":"2.0","id":13,"method":"tools/call",)") +
        R"("params":{"name":"analyze","arguments":{"path":")" + path +
        R"("}}})";
    response = handleMcpMessage(withoutParam);
    EXPECT_NE(response.find("null-deref"), std::string::npos);
}

TEST(McpServerTest, AllocFunctions_ExtendLeakTracking) {
    auto path = writeTempSource("mcp_alloc.cpp", R"(
        void* my_pool_alloc(unsigned long);
        void my_pool_free(void*);
        void leaky(int c) {
            void* p = my_pool_alloc(64);
            if (c) my_pool_free(p);
        }
    )");

    std::string request =
        std::string(R"({"jsonrpc":"2.0","id":14,"method":"tools/call",)") +
        R"("params":{"name":"analyze","arguments":{"path":")" + path +
        R"(","alloc_functions":"my_pool_alloc",)" +
        R"("free_functions":"my_pool_free"}}})";
    auto response = handleMcpMessage(request);
    EXPECT_NE(response.find("memory-leak"), std::string::npos);
}
