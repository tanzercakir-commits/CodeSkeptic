#include "server/McpServer.h"

#include "config/Config.h"
#include "core/FunctionFilter.h"

#include <fstream>
#include <filesystem>
#include <string>
#include <gtest/gtest.h>

using namespace codeskeptic;

namespace {

std::string writeTempSource(const std::string& name,
                            const std::string& content) {
    std::string path = ::testing::TempDir() + name;
    std::ofstream file(path);
    file << content;
    // Generic (forward-slash) form: the tests splice this path into a
    // hand-built JSON request, where raw Windows backslashes would be
    // invalid escape sequences.
    return std::filesystem::path(path).generic_string();
}

std::string testMcpMessage(const std::string& line) {
    Config base;
    base.setWorkerProgram(CODESKEPTIC_BINARY);
    return codeskeptic::handleMcpMessage(line, base);
}

std::string testMcpMessage(const std::string& line,
                           const Config& base) {
    return codeskeptic::handleMcpMessage(line, base);
}

std::string unconfiguredMcpMessage(const std::string& line) {
    return codeskeptic::handleMcpMessage(line);
}

} // anonymous namespace

#define handleMcpMessage testMcpMessage

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
    EXPECT_NE(response.find("\"tu_timeout_seconds\""), std::string::npos);
    EXPECT_NE(response.find("\"tu_memory_mib\""), std::string::npos);
    EXPECT_NE(response.find("\"default\":300"), std::string::npos);
    EXPECT_NE(response.find("\"default\":4096"), std::string::npos);
}

TEST(McpServerTest, ToolsListPublishesResolvedServerBudgetDefaults) {
    Config base;
    ASSERT_TRUE(base.setTuTimeoutSeconds(77));
    ASSERT_TRUE(base.setTuMemoryMiB(3072));

    const auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":79,"method":"tools/list"})", base);

    EXPECT_NE(response.find("\"default\":77"), std::string::npos)
        << response;
    EXPECT_NE(response.find("\"default\":3072"), std::string::npos)
        << response;
}

TEST(McpServerTest, AnalyzeWithoutBoundWorkerFailsClosed) {
    const auto response = unconfiguredMcpMessage(
        R"({"jsonrpc":"2.0","id":80,"method":"tools/call","params":{"name":"analyze","arguments":{"path":"x.cpp"}}})");
    EXPECT_NE(response.find("-32603"), std::string::npos) << response;
    EXPECT_NE(response.find("resource-isolated"), std::string::npos)
        << response;
}

TEST(McpServerTest, AnalyzeValidatesTypedPerTuBudgets) {
    const auto valid = validateMcpMessage(
        R"({"jsonrpc":"2.0","id":71,"method":"tools/call","params":{"name":"analyze","arguments":{"path":"x.cpp","tu_timeout_seconds":45,"tu_memory_mib":2048}}})");
    EXPECT_NE(valid.find("\"validated\":true"), std::string::npos);

    for (const char* request : {
             R"({"jsonrpc":"2.0","id":72,"method":"tools/call","params":{"name":"analyze","arguments":{"path":"x.cpp","tu_timeout_seconds":"45"}}})",
             R"({"jsonrpc":"2.0","id":73,"method":"tools/call","params":{"name":"analyze","arguments":{"path":"x.cpp","tu_timeout_seconds":1.5}}})",
             R"({"jsonrpc":"2.0","id":74,"method":"tools/call","params":{"name":"analyze","arguments":{"path":"x.cpp","tu_timeout_seconds":0}}})",
             R"({"jsonrpc":"2.0","id":75,"method":"tools/call","params":{"name":"analyze","arguments":{"path":"x.cpp","tu_memory_mib":-1}}})",
             R"({"jsonrpc":"2.0","id":76,"method":"tools/call","params":{"name":"analyze","arguments":{"path":"x.cpp","tu_memory_mib":4294967296}}})",
         }) {
        const auto response = validateMcpMessage(request);
        EXPECT_NE(response.find("-32602"), std::string::npos) << request;
    }
}

TEST(McpServerTest, AnalyzeInheritsServerBudgetsUnlessRequestOverrides) {
    Config base;
    ASSERT_TRUE(base.setTuTimeoutSeconds(77));
    ASSERT_TRUE(base.setTuMemoryMiB(3072));
    const std::string request =
        R"({"jsonrpc":"2.0","id":77,"method":"tools/call","params":{"name":"analyze","arguments":{"path":"x.cpp"}}})";
    const auto inherited = validateMcpMessage(request, base);
    EXPECT_NE(inherited.find("\"tu_timeout_seconds\":77"),
              std::string::npos);
    EXPECT_NE(inherited.find("\"tu_memory_mib\":3072"),
              std::string::npos);

    const auto overridden = validateMcpMessage(
        R"({"jsonrpc":"2.0","id":78,"method":"tools/call","params":{"name":"analyze","arguments":{"path":"x.cpp","tu_timeout_seconds":9,"tu_memory_mib":128}}})",
        base);
    EXPECT_NE(overridden.find("\"tu_timeout_seconds\":9"),
              std::string::npos);
    EXPECT_NE(overridden.find("\"tu_memory_mib\":128"),
              std::string::npos);
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

TEST(McpServerTest, InvalidJsonRpcEnvelopeFailsClosed) {
    for (const char* request : {
             R"({"id":1,"method":"ping"})",
             R"({"jsonrpc":"1.0","id":1,"method":"ping"})",
             R"({"jsonrpc":"2.0"})",
             R"({"jsonrpc":"2.0","method":7})",
             R"({"jsonrpc":"2.0","id":true,"method":"ping"})",
             R"({"jsonrpc":"2.0","id":{},"method":"ping"})",
         }) {
        const auto response = validateMcpMessage(request);
        EXPECT_NE(response.find("-32600"), std::string::npos) << request;
    }

    EXPECT_TRUE(validateMcpMessage(
        R"({"jsonrpc":"2.0","method":"notifications/initialized"})")
                    .empty());
}

TEST(McpServerTest, ValidationOnlyNeverStartsAnalyzeSideEffects) {
    const std::string request =
        R"({"jsonrpc":"2.0","id":44,"method":"tools/call","params":{"name":"analyze","arguments":{"path":"definitely-missing.cpp","functions":"f"}}})";

    ::testing::internal::CaptureStderr();
    const auto first = validateMcpMessage(request);
    const auto second = validateMcpMessage(request);
    const std::string stderr_text =
        ::testing::internal::GetCapturedStderr();

    EXPECT_EQ(first, second);
    EXPECT_NE(first.find("\"validated\":true"), std::string::npos);
    EXPECT_TRUE(stderr_text.empty());
}

TEST(McpServerTest, AnalyzeRejectsEmbeddedNulFields) {
    for (const char* field : {"path", "build_path", "summaries", "functions",
                              "lines", "fatal_asserts", "alloc_functions",
                              "free_functions", "allocator_pairs"}) {
        const std::string request =
            std::string(R"({"jsonrpc":"2.0","id":45,"method":"tools/call","params":{"name":"analyze","arguments":{"path":"x.cpp",")") +
            field + R"(":"x\u0000suffix"}}})";
        const auto response = validateMcpMessage(request);
        EXPECT_NE(response.find("-32602"), std::string::npos) << field;
        EXPECT_NE(response.find("must not contain NUL"), std::string::npos)
            << field;
    }
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
    EXPECT_NE(response.find("\\\"capability_tier\\\":\\\"supported\\\""),
              std::string::npos);
    EXPECT_NE(response.find("\\\"blocks_verdict\\\":true"),
              std::string::npos);
    EXPECT_NE(response.find("\\\"fingerprint\\\":\\\"csf1-"),
              std::string::npos);
    EXPECT_NE(response.find("\\\"blocking_count\\\":1"),
              std::string::npos);
    EXPECT_NE(response.find("\\\"report_only_count\\\":0"),
              std::string::npos);
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

TEST(McpServerTest, RepeatedProductionRequestPreservesFindings) {
    // Per-TU resource isolation uses fresh worker processes. Repeating an MCP
    // request must preserve the finding without sharing an AST cache.
    auto path = writeTempSource("mcp_warm_hit.cpp", R"(
        void f() {
            int* p = new int(1);
            delete p;
            int x = *p;
            (void)x;
        }
    )");

    auto first = handleMcpMessage(analyzeRequest(20, path));
    auto second = handleMcpMessage(analyzeRequest(21, path));

    EXPECT_NE(first.find("use-after-free"), std::string::npos);
    EXPECT_NE(second.find("use-after-free"), std::string::npos);
    EXPECT_NE(second.find("\\\"count\\\":1"), std::string::npos);
}

TEST(McpServerTest, ProductionWorkerReanalyzesChangedSource) {
    // A fresh worker must report new content on the same path: the old
    // use-after-free disappears and the new div-by-zero appears.
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
        "codeskeptic-summaries v2\nfind/1\tM\tO\tU\n");

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

TEST(McpServerTest, AnalyzeRejectsUnknownOrWrongTypedFields) {
    auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":60,"method":"tools/call",)"
        R"("params":{"name":"analyze","arguments":{"path":"x.cpp",)"
        R"("severtiy":"error"}}})");
    EXPECT_NE(response.find("unknown analyze field"), std::string::npos);

    response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":601,"method":"tools/call",)"
        R"("params":{"name":"analyze","arguments":{"path":"x.cpp",)"
        R"("checkpoint_dir":"/tmp/forged"}}})");
    EXPECT_NE(response.find("unknown analyze field: checkpoint_dir"),
              std::string::npos);

    response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":61,"method":"tools/call",)"
        R"("params":{"name":"analyze","arguments":{"path":"x.cpp",)"
        R"("functions":7}}})");
    EXPECT_NE(response.find("field must be a string"), std::string::npos);

    response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":62,"method":"tools/call",)"
        R"("params":{"name":"analyze","arguments":{"path":"x.cpp",)"
        R"("lines":"10-x"}}})");
    EXPECT_NE(response.find("invalid lines scope"), std::string::npos);
}

TEST(McpServerTest, AnalyzeRejectsEmptyFunctionScope) {
    for (const char* functions : {"", ",, ,"}) {
        const std::string request =
            std::string(R"({"jsonrpc":"2.0","id":65,"method":"tools/call",)") +
            R"("params":{"name":"analyze","arguments":{"path":"x.cpp",)" +
            R"("functions":")" + functions + R"("}}})";
        const auto response = handleMcpMessage(request);
        EXPECT_NE(response.find("-32602"), std::string::npos);
        EXPECT_NE(response.find("invalid functions scope"),
                  std::string::npos);
    }
}

TEST(McpServerTest, BrokenTuReturnsFailedVerdictAndCoverage) {
    auto path = writeTempSource(
        "mcp_broken_verdict.cpp",
        "#include \"definitely_missing_codeskeptic_header.h\"\n"
        "int f() { return 0; }\n");
    auto response = handleMcpMessage(analyzeRequest(63, path));

    EXPECT_NE(response.find("\\\"status\\\":\\\"failed\\\""),
              std::string::npos);
    EXPECT_NE(response.find("\\\"complete\\\":false"), std::string::npos);
    EXPECT_NE(response.find("\\\"attempted_tus\\\":1"), std::string::npos);
    EXPECT_NE(response.find("\\\"analyzed_tus\\\":0"), std::string::npos);
    EXPECT_NE(response.find("\\\"broken_tus\\\":1"), std::string::npos);
    EXPECT_NE(response.find("\"isError\":true"), std::string::npos);
}

TEST(McpServerTest, MissingSummaryReturnsIncompleteEvidence) {
    auto path = writeTempSource("mcp_missing_summary.cpp",
                                "int f() { return 0; }\n");
    const auto missing = std::filesystem::path(::testing::TempDir()) /
                         "definitely_missing_summary.csk";
    std::string request =
        std::string(R"({"jsonrpc":"2.0","id":64,"method":"tools/call",)") +
        R"("params":{"name":"analyze","arguments":{"path":")" + path +
        R"(","summaries":")" + missing.generic_string() + R"("}}})";
    auto response = handleMcpMessage(request);

    EXPECT_NE(response.find("\\\"status\\\":\\\"incomplete\\\""),
              std::string::npos);
    EXPECT_NE(response.find("\\\"summary_load_failed\\\":true"),
              std::string::npos);
    EXPECT_NE(response.find("\"isError\":true"), std::string::npos);
}

TEST(McpServerTest, UnknownTool_Error) {
    auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":8,"method":"tools/call",)"
        R"("params":{"name":"no_such_tool","arguments":{}}})");
    EXPECT_NE(response.find("-32602"), std::string::npos);
}

// --- Project-idiom parameters (fatal_asserts / allocator families) ---

TEST(McpServerTest, ToolsListContainsIdiomParams) {
    auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":11,"method":"tools/list"})");
    EXPECT_NE(response.find("fatal_asserts"), std::string::npos);
    EXPECT_NE(response.find("alloc_functions"), std::string::npos);
    EXPECT_NE(response.find("free_functions"), std::string::npos);
    EXPECT_NE(response.find("allocator_pairs"), std::string::npos);
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

TEST(McpServerTest, AllocatorPairsAreExactFailClosedAndRequestScoped) {
    auto path = writeTempSource("mcp_allocator_pairs.cpp", R"(
        void* pool_alloc(unsigned long);
        void pool_free(void*);
        void* arena_alloc(unsigned long);
        void arena_free(void*);
        void mismatch() {
            void* p = pool_alloc(64);
            arena_free(p);
        }
    )");

    std::string withPairs =
        std::string(R"({"jsonrpc":"2.0","id":15,"method":"tools/call",)") +
        R"("params":{"name":"analyze","arguments":{"path":")" + path +
        R"(","allocator_pairs":"pool_alloc=pool_free,arena_alloc=arena_free"}}})";
    auto response = handleMcpMessage(withPairs);
    EXPECT_NE(response.find("memory-leak"), std::string::npos);

    std::string malformed =
        std::string(R"({"jsonrpc":"2.0","id":16,"method":"tools/call",)") +
        R"("params":{"name":"analyze","arguments":{"path":")" + path +
        R"(","allocator_pairs":"pool_alloc=pool_free,bad"}}})";
    response = handleMcpMessage(malformed);
    EXPECT_NE(response.find("-32602"), std::string::npos);

    std::string withoutPairs =
        std::string(R"({"jsonrpc":"2.0","id":17,"method":"tools/call",)") +
        R"("params":{"name":"analyze","arguments":{"path":")" + path +
        R"("}}})";
    response = handleMcpMessage(withoutPairs);
    EXPECT_EQ(response.find("memory-leak"), std::string::npos);
}
