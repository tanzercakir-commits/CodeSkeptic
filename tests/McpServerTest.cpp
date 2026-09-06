#include "server/McpServer.h"
#include "config/Config.h"
#include "analyzer/StaticAnalyzer.h"

#include "core/FunctionFilter.h"
#include "engine/FatalCalls.h"
#include "engine/AllocFunctions.h"
#include "engine/FunctionSummary.h"
#include "engine/ImmutableFlags.h"
#include "engine/ParamIntervals.h"
#include "source_manager/SourceManager.h"
#include <llvm/Support/JSON.h>
#include <llvm/Support/FormatVariadic.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <clang/Tooling/Tooling.h>

#include <fstream>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>
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

} // anonymous namespace

namespace {

constexpr std::size_t requestByteLimit = 1024 * 1024;

void expectRpcError(const std::string& response, int code,
                    const std::string& expectedId = "null") {
    auto parsed = llvm::json::parse(response);
    ASSERT_TRUE(static_cast<bool>(parsed)) << response.substr(0, 250);
    const auto* object = parsed->getAsObject();
    ASSERT_NE(object, nullptr);
    EXPECT_EQ(object->getString("jsonrpc"), "2.0");
    EXPECT_EQ(object->get("result"), nullptr);
    const auto* error = object->getObject("error");
    ASSERT_NE(error, nullptr) << response.substr(0, 250);
    EXPECT_EQ(error->getInteger("code"), code);
    ASSERT_NE(error->getString("message"), std::nullopt);
    const auto* id = object->get("id");
    ASSERT_NE(id, nullptr);
    EXPECT_EQ(llvm::formatv("{0}", *id).str(), expectedId);
}

// Exercise the actual stdio entry point without a new testing-only server API.
// CTest uses separate processes; within one process this scope restores streams.
class ServerStreams {
public:
    explicit ServerStreams(const std::string& input) : input_(input),
        inMask_(std::cin.exceptions()), outMask_(std::cout.exceptions()),
        inState_(std::cin.rdstate()), outState_(std::cout.rdstate()) {
        std::cin.exceptions(std::ios::goodbit);
        std::cout.exceptions(std::ios::goodbit);
        inBuf_ = std::cin.rdbuf(input_.rdbuf());
        outBuf_ = std::cout.rdbuf(output_.rdbuf());
    }
    ~ServerStreams() {
        std::cin.exceptions(std::ios::goodbit);
        std::cout.exceptions(std::ios::goodbit);
        std::cin.rdbuf(inBuf_);
        std::cout.rdbuf(outBuf_);
        std::cin.clear(inState_);
        std::cout.clear(outState_);
        std::cin.exceptions(inMask_);
        std::cout.exceptions(outMask_);
    }
    std::string output() const { return output_.str(); }
    std::istringstream input_;
private:
    std::ostringstream output_;
    std::ios::iostate inMask_, outMask_, inState_, outState_;
    std::streambuf *inBuf_, *outBuf_;
};

class ThrowingReadBuffer : public std::streambuf {
    int_type underflow() override { throw std::runtime_error("injected read failure"); }
};

class ThrowingWriteBuffer : public std::streambuf {
    int_type overflow(int_type) override { throw std::runtime_error("injected write failure"); }
    std::streamsize xsputn(const char*, std::streamsize) override {
        throw std::runtime_error("injected write failure");
    }
};

} // namespace

TEST(McpServerTest, EnvelopeRequiresVersionAndMethodBeforeNotificationHandling) {
    for (const char* request : {
        R"({"id":3,"method":"ping"})", R"({"jsonrpc":2,"id":3,"method":"ping"})",
        R"({"jsonrpc":"1.0","id":3,"method":"ping"})", "{}",
        R"({"jsonrpc":"2.0"})", R"({"jsonrpc":"2.0","method":false})",
        R"({"jsonrpc":"2.0","method":""})",
        R"({"jsonrpc":"2.0","id":3,"method":"pi\u0000ng"})",
        R"({"method":"notifications/initialized"})"}) {
        SCOPED_TRACE(request);
        expectRpcError(handleMcpMessage(request), -32600);
    }
}

TEST(McpServerTest, EnvelopeRejectsNonMcpIdsWithoutReflectingThem) {
    for (const char* id : {"null", "true", "false", "[]", "{}", "1.5", "1e100",
                           "1.8446744073709551616e19", "-9223372036854775809",
                           "18446744073709551616", "1.0000000000000000001", "1e-999"}) {
        SCOPED_TRACE(id);
        expectRpcError(handleMcpMessage(std::string(
            R"({"jsonrpc":"2.0","method":"ping","id":)") + id + "}"), -32600);
    }
    for (const char* id : {"0", "-1", "9223372036854775807", "-9223372036854775808",
                           "18446744073709551615", R"("")", R"("request-α")"}) {
        SCOPED_TRACE(id);
        auto response = llvm::json::parse(handleMcpMessage(std::string(
            R"({"jsonrpc":"2.0","method":"ping","id":)") + id + "}"));
        ASSERT_TRUE(static_cast<bool>(response));
        ASSERT_NE(response->getAsObject(), nullptr);
        ASSERT_NE(response->getAsObject()->get("result"), nullptr);
        ASSERT_NE(response->getAsObject()->get("id"), nullptr);
        EXPECT_EQ(llvm::formatv("{0}", *response->getAsObject()->get("id")).str(), id);
    }
}

TEST(McpServerTest, EnvelopeIntegralDecimalIdsPreserveExactValueAndRejectDuplicates) {
    for (const auto& item : std::vector<std::pair<std::string, std::string>>{
        {"1.0", "1"}, {"10e-1", "1"}, {"1E+2", "100"}, {"0.000e-99", "0"},
        {"9.223372036854776e18", "9223372036854776000"},
        {"1.8446744073709551615e19", "18446744073709551615"},
        {"-9.223372036854775808e18", "-9223372036854775808"},
        {"100000000000000000000000000e-26", "1"}}) {
        auto response = llvm::json::parse(handleMcpMessage(std::string(
            R"({"jsonrpc":"2.0","\u0069d":)") + item.first +
            R"(,"method":"ping","params":{"id":3}})"));
        ASSERT_TRUE(static_cast<bool>(response));
        const auto* object = response->getAsObject();
        ASSERT_NE(object, nullptr);
        ASSERT_NE(object->get("result"), nullptr) << item.first;
        EXPECT_EQ(llvm::formatv("{0}", *object->get("id")).str(), item.second);
    }
    expectRpcError(handleMcpMessage(
        R"({"jsonrpc":"2.0","id":1,"\u0069d":2,"method":"ping"})"), -32600);
    expectRpcError(handleMcpMessage(
        R"({"jsonrpc":"2.0","id":"a","id":"b","method":"ping"})"), -32600);
}

TEST(McpServerTest, EnvelopeValidNotificationsNeverAnalyzeOrReply) {
    const auto misses = SourceManager::warmCacheMisses();
    const auto hits = SourceManager::warmCacheHits();
    for (const char* request : {
        R"({"jsonrpc":"2.0","method":"notifications/initialized"})",
        R"({"jsonrpc":"2.0","method":"unknown"})",
        R"({"jsonrpc":"2.0","method":"tools/call","params":{"name":"analyze","arguments":{"path":"unused.cpp"}}})"})
        EXPECT_TRUE(handleMcpMessage(request).empty());
    EXPECT_EQ(SourceManager::warmCacheMisses(), misses);
    EXPECT_EQ(SourceManager::warmCacheHits(), hits);
}

TEST(McpServerTest, EnvelopeRejectsInvalidParamsBeforeDispatch) {
    for (const char* method : {"ping", "initialize", "tools/list", "tools/call"}) {
        for (const char* params : {"null", "false", "3", "[]", R"("text")"}) {
            SCOPED_TRACE(method);
            SCOPED_TRACE(params);
            expectRpcError(handleMcpMessage(std::string(
                R"({"jsonrpc":"2.0","id":8,"method":")") + method +
                R"(","params":)" + params + "}"), -32602, "8");
        }
    }
}

TEST(McpServerTest, EnvelopeBoundsBytesAndNestingWithoutRejectingValidBoundary) {
    std::string ping = R"({"jsonrpc":"2.0","id":9,"method":"ping"})";
    ping.resize(requestByteLimit, ' ');
    EXPECT_NE(handleMcpMessage(ping).find("\"result\""), std::string::npos);
    ping.push_back(' ');
    expectRpcError(handleMcpMessage(ping), -32600);
    // Root + params + 62 arrays = exactly 64 containers.
    const std::string prefix = R"({"jsonrpc":"2.0","id":10,"method":"ping","params":{"nested":)";
    EXPECT_NE(handleMcpMessage(prefix + std::string(62, '[') + "0" +
        std::string(62, ']') + "}}").find("\"result\""), std::string::npos);
    expectRpcError(handleMcpMessage(prefix + std::string(63, '[') + "0" +
        std::string(63, ']') + "}}"), -32600);
    // Delimiters and escaped quotes inside strings are not structural depth.
    const std::string quoted = R"({"jsonrpc":"2.0","id":11,"method":"ping","params":{"text":"\"\\)" +
        std::string(128, '[') + R"("}})";
    EXPECT_NE(handleMcpMessage(quoted).find("\"result\""), std::string::npos);
}

TEST(McpServerTest, EnvelopeBoundedStdioDrainsFrameAndResumesIncludingCrlfAndEof) {
    std::string exact = R"({"jsonrpc":"2.0","id":12,"method":"ping"})";
    exact.resize(requestByteLimit, ' ');
    std::string output;
    int result = -1;
    {
        ServerStreams streams(exact + "\r\n" + exact + " \n" +
            R"({"jsonrpc":"2.0","method":"notifications/initialized"})" + "\n" +
            "{broken\n" + R"({"jsonrpc":"2.0","id":13,"method":"ping"})");
        result = runMcpServer();
        output = streams.output();
    }
    EXPECT_EQ(result, 0);
    std::istringstream lines(output);
    std::string line;
    ASSERT_TRUE(static_cast<bool>(std::getline(lines, line)));
    EXPECT_NE(line.find("\"id\":12"), std::string::npos);
    ASSERT_TRUE(static_cast<bool>(std::getline(lines, line)));
    expectRpcError(line, -32600);
    ASSERT_TRUE(static_cast<bool>(std::getline(lines, line)));
    expectRpcError(line, -32700);
    ASSERT_TRUE(static_cast<bool>(std::getline(lines, line)));
    EXPECT_NE(line.find("\"id\":13"), std::string::npos);
    EXPECT_FALSE(static_cast<bool>(std::getline(lines, line)));
}

TEST(McpServerTest, LifecycleStreamFailuresAreTerminalNotCleanEof) {
    int readResult = -1, writeResult = -1, throwingResult = -1;
    bool noReadAfterWriteFailure = false;
    {
        ServerStreams streams("");
        std::cin.setstate(std::ios::badbit);
        readResult = runMcpServer();
    }
    {
        ServerStreams streams(R"({"jsonrpc":"2.0","id":14,"method":"ping"})" "\nnext\n");
        std::cout.setstate(std::ios::badbit);
        writeResult = runMcpServer();
        noReadAfterWriteFailure = streams.input_.peek() == 'n';
    }
    {
        ServerStreams streams("");
        ThrowingReadBuffer buffer;
        std::cin.rdbuf(&buffer);
        std::cin.exceptions(std::ios::badbit);
        EXPECT_NO_THROW(throwingResult = runMcpServer());
        std::cin.exceptions(std::ios::goodbit);
        std::cin.rdbuf(streams.input_.rdbuf());
    }
    EXPECT_EQ(readResult, 2);
    EXPECT_EQ(writeResult, 2);
    EXPECT_TRUE(noReadAfterWriteFailure);
    EXPECT_EQ(throwingResult, 2);
}

TEST(McpServerTest, LifecycleConstructorFailureReturnsErrorAndClearsPublishedScope) {
    const auto path = writeTempSource("mcp_constructor_failure.cpp",
        "void first(){int* a;int x=*a;(void)x;}\n"
        "void second(){int* b;int y=*b;(void)y;}\n");
    const std::string request = std::string(
        R"({"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"analyze","arguments":{"path":")") +
        path + R"(","functions":"second","fatal_asserts":"my_fatal","allocator_pairs":"my_alloc=my_free"}}})";
    const auto oldMask = std::cerr.exceptions();
    const auto oldState = std::cerr.rdstate();
    std::cerr.exceptions(std::ios::goodbit);
    ThrowingWriteBuffer buffer;
    auto* oldBuffer = std::cerr.rdbuf(&buffer);
    std::cerr.exceptions(std::ios::badbit | std::ios::failbit);
    std::string response;
    bool escaped = false;
    try { response = handleMcpMessage(request); } catch (...) { escaped = true; }
    std::cerr.exceptions(std::ios::goodbit);
    std::cerr.rdbuf(oldBuffer);
    std::cerr.clear(oldState);
    std::cerr.exceptions(oldMask);
    EXPECT_FALSE(escaped);
    if (!escaped) expectRpcError(response, -32603, "15");
    EXPECT_TRUE(functionFilter().empty());
    EXPECT_TRUE(fatalCallNames().empty());
    EXPECT_TRUE(allocatorPairs().empty());
    // The following real request must work without the failed call's filter.
    const auto next = handleMcpMessage(std::string(
        R"({"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"analyze","arguments":{"path":")") + path + R"("}}})");
    EXPECT_NE(next.find("'a'"), std::string::npos);
    EXPECT_NE(next.find("'b'"), std::string::npos);
}

#if GTEST_HAS_DEATH_TEST
TEST(McpServerTest, LifecycleWorkerExceptionReachesCallerAndNextAnalysisWorks) {
    const auto path = writeTempSource("mcp_worker_failure.cpp", "int f(){return 0;}\n");
    for (bool warm : {false, true}) {
        SCOPED_TRACE(warm);
        // Catch the baseline's std::terminate in a child, not the whole runner.
        EXPECT_EXIT({
            SourceManager manager(::testing::TempDir(), nullptr, true);
            manager.enableWarmCache(warm);
            manager.addSourceFile(path);
            if (warm && manager.processAll([](clang::ASTContext&) {}) != 0) std::_Exit(3);
            bool caught = false;
            try {
                manager.processAll([](clang::ASTContext&) {
                    throw std::runtime_error("injected worker exception");
                });
            } catch (const std::runtime_error&) { caught = true; }
            unsigned visited = 0;
            const int next = manager.processAll([&](clang::ASTContext&) { ++visited; });
            std::_Exit(caught && next == 0 && visited == 1 ? 0 : 4);
        }, ::testing::ExitedWithCode(0), "");
    }
}
#endif

TEST(McpServerTest, LifecycleExceptionalOwnerExitClearsAllTuCaches) {
    const auto path = writeTempSource("mcp_owner_failure.cpp", "int f(){return 0;}\n");
    auto ast = clang::tooling::buildASTFromCodeWithArgs(
        "static const int flag=1; static int inner(int x){return x;} "
        "int outer(){return inner(3);}", {"-std=c++17"}, "owner.cpp");
    ASSERT_NE(ast, nullptr);
    const clang::FunctionDecl* inner = nullptr;
    for (const auto* decl : ast->getASTContext().getTranslationUnitDecl()->decls())
        if (const auto* function = llvm::dyn_cast<clang::FunctionDecl>(decl))
            if (function->getNameAsString() == "inner") inner = function;
    ASSERT_NE(inner, nullptr);
    Config config;
    config.setSourcePath(path);
    try {
        StaticAnalyzer analyzer(config);
        SummaryRegistry::instance().rebuild(ast->getASTContext());
        EXPECT_NE(SummaryRegistry::instance().lookup(inner), nullptr);
        EXPECT_FALSE(ParamIntervalCache::instance().get(ast->getASTContext()).empty());
        EXPECT_FALSE(ImmutableFlagCache::instance().get(ast->getASTContext()).empty());
        throw std::runtime_error("injected owner exit after cache population");
    } catch (const std::runtime_error&) {}
    // Keep old AST alive while probing keys; this test never dereferences a
    // dangling pointer even on the failing baseline.
    EXPECT_EQ(SummaryRegistry::instance().lookup(inner), nullptr);
    auto next = clang::tooling::buildASTFromCodeWithArgs(
        "int fresh(){return 0;}", {"-std=c++17"}, "fresh.cpp");
    ASSERT_NE(next, nullptr);
    EXPECT_TRUE(ParamIntervalCache::instance().get(next->getASTContext()).empty());
    EXPECT_TRUE(ImmutableFlagCache::instance().get(next->getASTContext()).empty());
    SummaryRegistry::instance().clear();
    ParamIntervalCache::instance().clear();
    ImmutableFlagCache::instance().clear();
}

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
    EXPECT_NE(response.find("disable_rules"), std::string::npos);
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

TEST(McpServerTest, InvalidTextScopeFailsBeforePublishingGlobalsOrCache) {
    const auto path = writeTempSource("mcp_atomic_input.cpp",
        "void first(){int* a;int x=*a;(void)x;}\n"
        "void second(){int* b;int y=*b;(void)y;}\n");
    for (const char* value : {",, ", "\t", "second,,first"}) {
        SCOPED_TRACE(value);
        llvm::json::Object request{
            {"jsonrpc", "2.0"}, {"id", 77}, {"method", "tools/call"},
            {"params", llvm::json::Object{{"name", "analyze"},
                {"arguments", llvm::json::Object{{"path", path}, {"functions", value}}}}}};
        const auto functions = functionFilter();
        const auto ranges = lineRanges();
        const auto hits = SourceManager::warmCacheHits();
        const auto misses = SourceManager::warmCacheMisses();
        const auto response = handleMcpMessage(llvm::formatv("{0}", llvm::json::Value(std::move(request))).str());
        auto parsed = llvm::json::parse(response);
        ASSERT_TRUE(static_cast<bool>(parsed));
        const auto* object = parsed->getAsObject();
        ASSERT_NE(object, nullptr);
        EXPECT_EQ(object->get("result"), nullptr);
        const auto* error = object->getObject("error");
        EXPECT_NE(error, nullptr) << response;
        if (error) {
            EXPECT_EQ(error->getInteger("code"), -32602);
            const auto* data = error->getObject("data");
            ASSERT_NE(data, nullptr);
            EXPECT_EQ(data->getString("schema"), "codeskeptic-input-error/v1");
            EXPECT_EQ(data->getString("reason"), "invalid_list");
            EXPECT_EQ(data->getString("field"), "functions");
        }
        EXPECT_EQ(functionFilter(), functions);
        EXPECT_EQ(lineRanges(), ranges);
        EXPECT_EQ(SourceManager::warmCacheHits(), hits);
        EXPECT_EQ(SourceManager::warmCacheMisses(), misses);
    }
}

TEST(McpServerTest, LateInputFailurePreservesAllPublishedRegistries) {
    const auto functions = functionFilter();
    const auto ranges = lineRanges();
    const auto fatal = fatalCallNames();
    const auto alloc = allocFunctionNames();
    const auto free = freeFunctionNames();
    const auto pairs = allocatorPairs();
    const auto hits = SourceManager::warmCacheHits();
    const auto misses = SourceManager::warmCacheMisses();
    auto response = handleMcpMessage(
        R"({"jsonrpc":"2.0","id":78,"method":"tools/call","params":{"name":"analyze","arguments":{"path":"unused.cpp","functions":"new_function","lines":"2-5","fatal_asserts":"new_fatal","alloc_functions":"new_alloc","free_functions":"new_free","allocator_pairs":"valid=pair,bad"}}})");
    auto parsed = llvm::json::parse(response);
    ASSERT_TRUE(static_cast<bool>(parsed));
    const auto* object = parsed->getAsObject();
    ASSERT_NE(object, nullptr);
    EXPECT_EQ(object->get("result"), nullptr);
    const auto* error = object->getObject("error");
    ASSERT_NE(error, nullptr);
    EXPECT_EQ(error->getInteger("code"), -32602);
    const auto* data = error->getObject("data");
    ASSERT_NE(data, nullptr);
    EXPECT_EQ(data->getString("field"), "allocator_pairs");
    EXPECT_EQ(data->getString("reason"), "invalid_list");
    EXPECT_EQ(functionFilter(), functions);
    EXPECT_EQ(lineRanges(), ranges);
    EXPECT_EQ(fatalCallNames(), fatal);
    EXPECT_EQ(allocFunctionNames(), alloc);
    EXPECT_EQ(freeFunctionNames(), free);
    EXPECT_EQ(allocatorPairs(), pairs);
    EXPECT_EQ(SourceManager::warmCacheHits(), hits);
    EXPECT_EQ(SourceManager::warmCacheMisses(), misses);
}

TEST(McpServerTest, InvalidRuleSelectionPreservesDefaultsRegistriesAndCache) {
    Config defaults;
    ASSERT_TRUE(defaults.addDisabledRules("resource-leak"));
    for (const char* value : {R"("")", R"("memory-leak,,bounds")",
                              R"("memory-leak,zz-unknown")", "[]", "null", "false"}) {
        SCOPED_TRACE(value);
        auto selection = llvm::json::parse(value);
        ASSERT_TRUE(static_cast<bool>(selection));
        const bool wrongType = !selection->getAsString();
        llvm::json::Object request{
            {"jsonrpc", "2.0"}, {"id", 79}, {"method", "tools/call"},
            {"params", llvm::json::Object{{"name", "analyze"},
                {"arguments", llvm::json::Object{{"path", "unused.cpp"},
                    {"functions", "new_function"}, {"fatal_asserts", "new_fatal"},
                    {"alloc_functions", "new_alloc"},
                    {"disable_rules", std::move(*selection)}}}}}};
        const auto functions = functionFilter();
        const auto ranges = lineRanges();
        const auto fatal = fatalCallNames();
        const auto alloc = allocFunctionNames();
        const auto free = freeFunctionNames();
        const auto pairs = allocatorPairs();
        const auto hits = SourceManager::warmCacheHits();
        const auto misses = SourceManager::warmCacheMisses();
        const auto response = handleMcpMessage(
            llvm::formatv("{0}", llvm::json::Value(std::move(request))).str(), defaults);
        auto parsed = llvm::json::parse(response);
        ASSERT_TRUE(static_cast<bool>(parsed));
        const auto* object = parsed->getAsObject();
        ASSERT_NE(object, nullptr);
        EXPECT_EQ(object->get("result"), nullptr);
        const auto* error = object->getObject("error");
        ASSERT_NE(error, nullptr) << response;
        EXPECT_EQ(error->getInteger("code"), -32602);
        const auto* data = error->getObject("data");
        ASSERT_NE(data, nullptr);
        EXPECT_EQ(data->getString("schema"), "codeskeptic-input-error/v1");
        EXPECT_EQ(data->getString("field"), "disable_rules");
        EXPECT_EQ(data->getString("reason"), wrongType ? "invalid_type" :
            (std::string(value).find("zz-unknown") != std::string::npos
                ? "unknown_rule" : "invalid_list"));
        EXPECT_FALSE(defaults.isRuleEnabled("resource-leak"));
        EXPECT_TRUE(defaults.isRuleEnabled("memory-leak"));
        EXPECT_EQ(functionFilter(), functions);
        EXPECT_EQ(lineRanges(), ranges);
        EXPECT_EQ(fatalCallNames(), fatal);
        EXPECT_EQ(allocFunctionNames(), alloc);
        EXPECT_EQ(freeFunctionNames(), free);
        EXPECT_EQ(allocatorPairs(), pairs);
        EXPECT_EQ(SourceManager::warmCacheHits(), hits);
        EXPECT_EQ(SourceManager::warmCacheMisses(), misses);
    }
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
    EXPECT_NE(with.find("\"isError\":false"), std::string::npos);
    EXPECT_NE(with.find("\\\"complete\\\":true"), std::string::npos);
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
