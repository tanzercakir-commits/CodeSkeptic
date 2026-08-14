#include "server/McpServer.h"

#include "analyzer/StaticAnalyzer.h"
#include "analyzer/DefaultRules.h"
#include "core/Capabilities.h"
#include "core/FindingFingerprint.h"
#include "config/Config.h"

#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>

#include <iostream>
#include <optional>
#include <set>
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

json::Value handleToolsList(const json::Value& id,
                            const codeskeptic::Config& base_config) {
    json::Object analyzeSchema{
        {"type", "object"},
        {"additionalProperties", false},
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
            {"allocator_pairs", json::Object{
                {"type", "string"},
                {"description",
                 "Comma-separated exact custom allocation families "
                 "(e.g. \"pool_alloc=pool_free\"); malformed values "
                 "are rejected without partial registration"},
            }},
            {"tu_timeout_seconds", json::Object{
                {"type", "integer"},
                {"minimum", static_cast<int64_t>(1)},
                {"maximum", static_cast<int64_t>(
                    codeskeptic::Config::kMaxTuTimeoutSeconds)},
                {"default", static_cast<int64_t>(
                    base_config.tuTimeoutSeconds())},
                {"description",
                 "Per-translation-unit wall timeout in seconds"},
            }},
            {"tu_memory_mib", json::Object{
                {"type", "integer"},
                {"minimum", static_cast<int64_t>(1)},
                {"maximum", static_cast<int64_t>(
                    codeskeptic::Config::kMaxTuMemoryMiB)},
                {"default", static_cast<int64_t>(
                    base_config.tuMemoryMiB())},
                {"description",
                 "Per-translation-unit memory ceiling in MiB"},
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

std::optional<std::string> configureAnalyze(
    const json::Object* args, codeskeptic::Config& config) {
    if (!args) return "missing arguments";

    static const std::set<std::string> stringFields = {
        "path", "build_path", "functions", "lines", "summaries",
        "fatal_asserts", "alloc_functions", "free_functions",
        "allocator_pairs"
    };
    static const std::set<std::string> integerFields = {
        "tu_timeout_seconds", "tu_memory_mib"
    };
    for (const auto& field : *args) {
        const std::string name = field.first.str();
        if (!stringFields.count(name) && !integerFields.count(name))
            return "unknown analyze field: " + name;
    }

    for (const auto& name : stringFields) {
        if (args->get(name) && !args->getString(name))
            return "field must be a string: " + name;
        if (auto value = args->getString(name); value && value->contains('\0'))
            return "field must not contain NUL: " + name;
    }
    for (const auto& name : integerFields) {
        if (args->get(name) && !args->getInteger(name))
            return "field must be an integer: " + name;
    }

    auto path = args->getString("path");
    if (!path) return "missing required field: path";
    if (path->empty())
        return "field must not be empty: path";

    config.setSourcePath(path->str());
    if (auto buildPath = args->getString("build_path"))
        config.setBuildPath(buildPath->str());
    if (auto functions = args->getString("functions")) {
        if (!config.addFunctions(functions->str()))
            return "invalid functions scope; expected at least one name";
    }
    if (auto lines = args->getString("lines")) {
        if (!config.addLines(lines->str()))
            return "invalid lines scope; expected e.g. 10-40,55";
    }
    if (auto summaries = args->getString("summaries"))
        config.setSummaryIn(summaries->str());
    if (auto fatalAsserts = args->getString("fatal_asserts"))
        config.addFatalAsserts(fatalAsserts->str());
    if (auto allocFns = args->getString("alloc_functions"))
        config.addAllocFunctions(allocFns->str());
    if (auto freeFns = args->getString("free_functions"))
        config.addFreeFunctions(freeFns->str());
    if (auto pairs = args->getString("allocator_pairs")) {
        if (!config.addAllocatorPairs(pairs->str()))
            return "invalid allocator_pairs; expected allocator=deallocator "
                   "entries separated by commas";
    }
    if (auto timeout = args->getInteger("tu_timeout_seconds")) {
        if (*timeout <= 0 ||
            !config.setTuTimeoutSeconds(static_cast<std::uint64_t>(*timeout)))
            return "tu_timeout_seconds is outside the supported range";
    }
    if (auto memory = args->getInteger("tu_memory_mib")) {
        if (*memory <= 0 ||
            !config.setTuMemoryMiB(static_cast<std::uint64_t>(*memory)))
            return "tu_memory_mib is outside the supported range";
    }
    return std::nullopt;
}

json::Value runAnalyze(const json::Value& id, const json::Object* args,
                       const codeskeptic::Config& base_config) {
    if (base_config.workerProgram().empty())
        return makeError(id, -32603,
                         "resource-isolated worker is unavailable");
    codeskeptic::Config config = base_config.mcpRequestConfig();
    if (auto error = configureAnalyze(args, config))
        return makeError(id, -32602, *error);

    codeskeptic::StaticAnalyzer analyzer(std::move(config));
    codeskeptic::registerDefaultRules(analyzer);
    const codeskeptic::AnalysisResult result = analyzer.run();

    json::Array findings;
    for (const auto& diag : analyzer.diagnostics()) {
        const std::string fingerprint = diag.fingerprint.empty()
            ? codeskeptic::findingFingerprint(diag)
            : diag.fingerprint;
        const codeskeptic::RuleCapability* capability =
            codeskeptic::findRuleCapability(diag.rule_id);
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
            {"capability_tier",
             capability
                 ? codeskeptic::capabilityTierName(capability->tier)
                 : "unclassified"},
            {"blocks_verdict",
             codeskeptic::findingBlocksVerdict(diag.rule_id)},
            {"fingerprint", fingerprint},
            {"message", diag.message},
            {"trace", std::move(notes)},
        });
    }

    json::Array translation_units;
    for (const auto& receipt : result.tu_receipts) {
        translation_units.push_back(json::Object{
            {"path", receipt.canonical_path},
            {"compile_command_sha256", receipt.compile_command_sha256},
            {"command_ordinal",
             static_cast<int64_t>(receipt.command_ordinal)},
            {"phase", receipt.phase},
            {"status", translationUnitStatusName(receipt.status)},
            {"duration_ms", static_cast<int64_t>(receipt.duration_ms)},
            {"peak_memory_kib",
             static_cast<int64_t>(receipt.peak_memory_kib)},
            {"timeout_seconds",
             static_cast<int64_t>(receipt.timeout_seconds)},
            {"memory_mib", static_cast<int64_t>(receipt.memory_mib)},
        });
    }

    json::Object payload{
        {"status", result.statusName()},
        {"complete", result.complete()},
        {"exit_code", static_cast<int64_t>(result.exitCode())},
        {"coverage", json::Object{
            {"attempted_tus", static_cast<int64_t>(result.attempted_tus)},
            {"analyzed_tus", static_cast<int64_t>(result.analyzed_tus)},
            {"broken_tus", static_cast<int64_t>(result.broken_tus)},
            {"incomplete_functions",
             static_cast<int64_t>(result.incomplete_functions)},
        }},
        {"evidence", json::Object{
            {"compile_database_failed", result.compile_database_failed},
            {"tool_failed", result.tool_failed},
            {"summary_load_failed", result.summary_load_failed},
            {"summary_stale", result.summary_stale},
        }},
        {"count", static_cast<int64_t>(findings.size())},
        {"blocking_count",
         static_cast<int64_t>(result.blockingFindings())},
        {"report_only_count",
         static_cast<int64_t>(result.report_only_findings)},
        {"translation_units", std::move(translation_units)},
        {"findings", std::move(findings)},
    };

    // Findings are a successful tool result. isError is reserved for a
    // missing trustworthy verdict (coverage/evidence/I/O failure).
    return makeResponse(id, json::Object{
        {"isError", result.exitCode() > 1},
        {"content", json::Array{json::Object{
            {"type", "text"},
            {"text", serialize(json::Value(std::move(payload)))},
        }}},
    });
}

json::Value handleToolsCall(const json::Value& id,
                            const json::Object* params,
                            bool executeAnalysis,
                            const codeskeptic::Config& base_config) {
    if (!params) return makeError(id, -32602, "missing params");
    auto name = params->getString("name");
    if (!name) return makeError(id, -32602, "missing tool name");
    if (*name != "analyze")
        return makeError(id, -32602, "unknown tool: " + name->str());
    const json::Object* arguments = params->getObject("arguments");
    if (executeAnalysis) return runAnalyze(id, arguments, base_config);

    codeskeptic::Config config = base_config.mcpRequestConfig();
    if (auto error = configureAnalyze(arguments, config))
        return makeError(id, -32602, *error);
    return makeResponse(id, json::Object{
        {"validated", true},
        {"tu_timeout_seconds",
         static_cast<int64_t>(config.tuTimeoutSeconds())},
        {"tu_memory_mib", static_cast<int64_t>(config.tuMemoryMiB())},
    });
}

std::string handleMcpMessageImpl(const std::string& line,
                                 bool executeAnalysis,
                                 const codeskeptic::Config& base_config) {
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

    auto jsonrpc = msg->getString("jsonrpc");
    auto method = msg->getString("method");
    const json::Value* idPtr = msg->get("id");
    bool isNotification = (idPtr == nullptr);
    json::Value id = idPtr ? *idPtr : json::Value(nullptr);

    if (!jsonrpc || *jsonrpc != "2.0") {
        return serialize(json::Value(
            makeError(id, -32600, "jsonrpc must be 2.0")));
    }
    if (idPtr && idPtr->kind() != json::Value::Null &&
        idPtr->kind() != json::Value::String &&
        idPtr->kind() != json::Value::Number) {
        return serialize(json::Value(
            makeError(nullptr, -32600, "invalid id")));
    }
    if (!method) {
        return serialize(json::Value(
            makeError(id, -32600, "missing method")));
    }

    if (isNotification) return "";

    json::Value response(nullptr);
    if (*method == "initialize") {
        response = handleInitialize(id);
    } else if (*method == "ping") {
        response = makeResponse(id, json::Object{});
    } else if (*method == "tools/list") {
        response = handleToolsList(id, base_config);
    } else if (*method == "tools/call") {
        response = handleToolsCall(
            id, msg->getObject("params"), executeAnalysis, base_config);
    } else {
        response = makeError(id, -32601,
                             "method not found: " + method->str());
    }
    return serialize(response);
}

} // anonymous namespace

namespace codeskeptic {

std::string handleMcpMessage(const std::string& line) {
    Config base_config;
    return handleMcpMessageImpl(line, true, base_config);
}

std::string handleMcpMessage(const std::string& line,
                             const Config& base_config) {
    return handleMcpMessageImpl(line, true, base_config);
}

std::string validateMcpMessage(const std::string& line) {
    Config base_config;
    return handleMcpMessageImpl(line, false, base_config);
}

std::string validateMcpMessage(const std::string& line,
                               const Config& base_config) {
    return handleMcpMessageImpl(line, false, base_config);
}

int runMcpServer() {
    Config base_config;
    return runMcpServer(base_config);
}

int runMcpServer(const Config& base_config) {
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
        std::string response = handleMcpMessage(line, base_config);
        if (!response.empty()) {
            std::cout << response << "\n" << std::flush;
        }
    }
    return 0;
}

} // namespace codeskeptic
