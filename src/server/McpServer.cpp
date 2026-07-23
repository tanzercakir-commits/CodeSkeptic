#include "server/McpServer.h"

#include "analyzer/StaticAnalyzer.h"
#include "config/Config.h"
#include "rules/DivByZeroRule.h"
#include "rules/IntOverflowRule.h"
#include "rules/BoundsRule.h"
#include "rules/AssumptionRule.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/NullDerefRule.h"
#include "rules/ContractRule.h"
#include "rules/PolicyRule.h"
#include "rules/UninitPointerRule_Ex.h"

#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>

#include <iostream>
#include <optional>
#include <string>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

namespace json = llvm::json;

namespace {

const char kProtocolVersion[] = "2024-11-05";
const char kServerName[] = "codeskeptic";
#ifndef CODESKEPTIC_VERSION
#define CODESKEPTIC_VERSION "0.0.0-dev"
#endif
const char kServerVersion[] = CODESKEPTIC_VERSION;

std::string serialize(const json::Value& value) {
    std::string out;
    llvm::raw_string_ostream os(out);
    os << value;
    return out;
}

json::Object makeResponse(const json::Value& id, json::Value result) {
    return json::Object{
        {"jsonrpc", "2.0"},
        {"id", id},
        {"result", std::move(result)},
    };
}

json::Object makeError(const json::Value& id, int code,
                       const std::string& message) {
    return json::Object{
        {"jsonrpc", "2.0"},
        {"id", id},
        {"error", json::Object{{"code", code}, {"message", message}}},
    };
}

json::Value handleInitialize(const json::Value& id) {
    return makeResponse(id, json::Object{
        {"protocolVersion", kProtocolVersion},
        {"capabilities", json::Object{{"tools", json::Object{}}}},
        {"serverInfo", json::Object{
            {"name", kServerName},
            {"version", kServerVersion},
        }},
    });
}

json::Value handleToolsList(const json::Value& id) {
    json::Object analyzeSchema{
        {"type", "object"},
        {"properties", json::Object{
            {"path", json::Object{
                {"type", "string"},
                {"description", "Source file or directory to analyze"},
            }},
            {"build_path", json::Object{
                {"type", "string"},
                {"description", "Directory containing compile_commands.json"},
            }},
            {"functions", json::Object{
                {"type", "string"},
                {"description",
                 "Comma-separated function names to analyze (plain or "
                 "qualified) — targeted re-check of edited functions"},
            }},
            {"lines", json::Object{
                {"type", "string"},
                {"description",
                 "Comma-separated line ranges (e.g. \"10-40,55\") of the "
                 "analyzed file; only overlapping functions are analyzed"},
            }},
            {"summaries", json::Object{
                {"type", "string"},
                {"description",
                 "Path to a summary file written by --summary-out; single-"
                 "file analysis then sees cross-file function knowledge "
                 "(e.g. a callee in another file that may return null/zero)"},
            }},
            {"fatal_asserts", json::Object{
                {"type", "string"},
                {"description",
                 "Comma-separated names of project assert handlers that "
                 "never return (e.g. \"assert_fail_impl\"); dataflow "
                 "paths die at calls to them, so assert-guarded code "
                 "stops producing impossible-path findings"},
            }},
            {"alloc_functions", json::Object{
                {"type", "string"},
                {"description",
                 "Comma-separated project allocator wrappers (e.g. "
                 "\"git__malloc,git__strdup\"); extends leak/double-free/"
                 "use-after-free tracking to them"},
            }},
            {"free_functions", json::Object{
                {"type", "string"},
                {"description",
                 "Comma-separated project deallocator wrappers (e.g. "
                 "\"git__free\") paired with alloc_functions"},
            }},
        }},
        {"required", json::Array{"path"}},
    };

    return makeResponse(id, json::Object{
        {"tools", json::Array{json::Object{
            {"name", "analyze"},
            {"description",
             "Run CodeSkeptic static analysis (uninitialized pointers, "
             "memory leaks, double free, use-after-free, division by "
             "zero, null dereference). Findings include dataflow traces "
             "explaining the event chain that leads to each bug."},
            {"inputSchema", std::move(analyzeSchema)},
        }}},
    });
}

json::Value runAnalyze(const json::Value& id, const json::Object* args) {
    if (!args) return makeError(id, -32602, "missing arguments");
    auto path = args->getString("path");
    if (!path) return makeError(id, -32602, "missing required field: path");

    codeskeptic::Config config;
    config.setSourcePath(path->str());
    if (auto buildPath = args->getString("build_path"))
        config.setBuildPath(buildPath->str());
    if (auto functions = args->getString("functions"))
        config.addFunctions(functions->str());
    if (auto lines = args->getString("lines"))
        config.addLines(lines->str());
    if (auto summaries = args->getString("summaries"))
        config.setSummaryIn(summaries->str());
    if (auto fatalAsserts = args->getString("fatal_asserts"))
        config.addFatalAsserts(fatalAsserts->str());
    if (auto allocFns = args->getString("alloc_functions"))
        config.addAllocFunctions(allocFns->str());
    if (auto freeFns = args->getString("free_functions"))
        config.addFreeFunctions(freeFns->str());
    // Long-lived process: parsed ASTs are kept warm between calls (the
    // fingerprint catches staleness — a stale AST is NEVER served)
    config.setWarmCache(true);

    codeskeptic::StaticAnalyzer analyzer(std::move(config));
    analyzer.addRule<codeskeptic::UninitPointerRule_Ex>();
    analyzer.addRule<codeskeptic::MemoryLeakRule_Ex>();
    analyzer.addRule<codeskeptic::DivByZeroRule>();
    analyzer.addRule<codeskeptic::IntOverflowRule>();
    analyzer.addRule<codeskeptic::BoundsRule>();
    analyzer.addRule<codeskeptic::AssumptionRule>();
    analyzer.addRule<codeskeptic::NullDerefRule>();
    analyzer.addRule<codeskeptic::ContractRule>();
    analyzer.addRule<codeskeptic::PolicyRule>();
    analyzer.run();

    json::Array findings;
    for (const auto& diag : analyzer.diagnostics()) {
        json::Array notes;
        for (const auto& note : diag.notes) {
            notes.push_back(json::Object{
                {"file", note.file},
                {"line", static_cast<int64_t>(note.line)},
                {"column", static_cast<int64_t>(note.column)},
                {"message", note.message},
            });
        }
        findings.push_back(json::Object{
            {"file", diag.file},
            {"line", static_cast<int64_t>(diag.line)},
            {"column", static_cast<int64_t>(diag.column)},
            {"severity", diag.severityToString()},
            {"rule", diag.rule_id},
            {"message", diag.message},
            {"trace", std::move(notes)},
        });
    }

    json::Object payload{
        {"count", static_cast<int64_t>(findings.size())},
        {"findings", std::move(findings)},
    };

    // MCP tool result: JSON as text content (agents parse it directly);
    // findings do not mean isError — the analysis SUCCEEDED, the result
    // is the findings
    return makeResponse(id, json::Object{
        {"content", json::Array{json::Object{
            {"type", "text"},
            {"text", serialize(json::Value(std::move(payload)))},
        }}},
    });
}

json::Value handleToolsCall(const json::Value& id,
                            const json::Object* params) {
    if (!params) return makeError(id, -32602, "missing params");
    auto name = params->getString("name");
    if (!name) return makeError(id, -32602, "missing tool name");
    if (*name != "analyze")
        return makeError(id, -32602, "unknown tool: " + name->str());
    return runAnalyze(id, params->getObject("arguments"));
}

} // anonymous namespace

namespace codeskeptic {

std::string handleMcpMessage(const std::string& line) {
    auto parsed = json::parse(line);
    if (!parsed) {
        llvm::consumeError(parsed.takeError());
        return serialize(json::Value(
            makeError(nullptr, -32700, "parse error")));
    }

    const json::Object* msg = parsed->getAsObject();
    if (!msg) {
        return serialize(json::Value(
            makeError(nullptr, -32600, "invalid request")));
    }

    auto method = msg->getString("method");
    const json::Value* idPtr = msg->get("id");
    bool isNotification = (idPtr == nullptr);
    json::Value id = idPtr ? *idPtr : json::Value(nullptr);

    if (!method) {
        if (isNotification) return "";
        return serialize(json::Value(
            makeError(id, -32600, "missing method")));
    }

    // Notifications (notifications/*) get no response
    if (isNotification) return "";

    json::Value response(nullptr);
    if (*method == "initialize") {
        response = handleInitialize(id);
    } else if (*method == "ping") {
        response = makeResponse(id, json::Object{});
    } else if (*method == "tools/list") {
        response = handleToolsList(id);
    } else if (*method == "tools/call") {
        response = handleToolsCall(id, msg->getObject("params"));
    } else {
        response = makeError(id, -32601,
                             "method not found: " + method->str());
    }
    return serialize(response);
}

int runMcpServer() {
#ifdef _WIN32
    // Newline-delimited JSON-RPC framing: Windows text-mode stdio
    // would expand "\n" to "\r\n" on write and leave stray '\r's in
    // reads. Binary mode keeps the frames byte-exact
    // (docs/windows-support.md §5).
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    std::string line;
    while (std::getline(std::cin, line)) {
        // Tolerate CRLF-framing clients on every platform: getline
        // splits at '\n', so a client's "\r\n" leaves a trailing '\r'.
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        std::string response = handleMcpMessage(line);
        if (!response.empty()) {
            std::cout << response << "\n" << std::flush;
        }
    }
    return 0;
}

} // namespace codeskeptic
