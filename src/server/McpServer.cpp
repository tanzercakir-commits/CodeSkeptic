#include "server/McpServer.h"

#include "analyzer/StaticAnalyzer.h"
#include "core/Capabilities.h"
#include "core/FindingFingerprint.h"
#include "config/Config.h"
#include "reporter/Coverage.h"
#include "rules/DivByZeroRule.h"
#include "rules/IntOverflowRule.h"
#include "rules/SignConversionRule.h"
#include "rules/AllocSizeOverflowRule.h"
#include "rules/BoundsRule.h"
#include "rules/AssumptionRule.h"
#include "rules/MemoryLeakRule_Ex.h"
#include "rules/FdResourceRule.h"
#include "rules/NullDerefRule.h"
#include "rules/ContractRule.h"
#include "rules/PolicyRule.h"
#include "rules/UninitPointerRule_Ex.h"
#include "rules/UninitScalarRule.h"

#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>

#include <iostream>
#include <charconv>
#include <cstdint>
#include <exception>
#include <optional>
#include <set>
#include <sstream>
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
constexpr std::size_t kMaxMessageBytes = 1024 * 1024;
constexpr unsigned kMaxMessageDepth = 64;

std::string serialize(const json::Value& value) {
    std::string out;
    llvm::raw_string_ostream os(out);
    os << value;
    return out;
}

// Bound recursion before LLVM constructs or destroys a nested JSON tree.
// This is only a budget check; LLVM still validates the complete JSON grammar.
bool withinDepthBudget(const std::string& line) {
    unsigned depth = 0;
    bool quoted = false, escaped = false;
    for (char ch : line) {
        if (quoted) {
            if (escaped) escaped = false;
            else if (ch == '\\') escaped = true;
            else if (ch == '"') quoted = false;
        } else if (ch == '"') {
            quoted = true;
        } else if (ch == '{' || ch == '[') {
            if (++depth > kMaxMessageDepth) return false;
        } else if ((ch == '}' || ch == ']') && depth) {
            --depth;
        }
    }
    return true;
}

bool jsonSpace(char ch) {
    return ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n';
}

// The complete JSON grammar has already been checked by LLVM. Locate the
// original top-level ID spelling before floating-point coercion loses bits.
// Decode escaped key names as well; duplicate IDs are ambiguous and rejected.
std::optional<llvm::StringRef> rawRequestId(const std::string& line) {
    std::optional<llvm::StringRef> found;
    unsigned depth = 0;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char ch = line[i];
        if (ch == '{' || ch == '[') ++depth;
        else if (ch == '}' || ch == ']') --depth;
        else if (ch == '"') {
            const auto start = i++;
            while (i < line.size() && line[i] != '"') {
                if (line[i] == '\\') ++i;
                ++i;
            }
            auto colon = i + 1;
            while (colon < line.size() && jsonSpace(line[colon])) ++colon;
            if (depth != 1 || colon == line.size() || line[colon] != ':') continue;
            const auto spelling = llvm::StringRef(line).slice(start, i + 1);
            bool isId = spelling == "\"id\"";
            if (!isId && spelling.contains('\\')) {
                auto key = json::parse(spelling);
                if (!key) { llvm::consumeError(key.takeError()); return std::nullopt; }
                isId = key->getAsString() == "id";
            }
            if (!isId) continue;
            if (found) return std::nullopt;
            auto first = colon + 1;
            while (first < line.size() && jsonSpace(line[first])) ++first;
            auto last = first;
            while (last < line.size() && !jsonSpace(line[last]) &&
                   line[last] != ',' && line[last] != '}') ++last;
            found = llvm::StringRef(line).slice(first, last);
        }
    }
    return found;
}

bool parseRequestId(const json::Value& candidate, const std::string& line,
                    json::Value& id) {
    const auto raw = rawRequestId(line);
    if (!raw) return false;
    if (candidate.getAsString()) { id = candidate; return true; }
    if (!candidate.getAsNumber()) return false;

    // Parse decimal arithmetic exactly, including integral 1.0 / 10e-1 forms.
    // No float-to-integer conversion, precision loss or unbounded bigint.
    const auto token = *raw;
    const bool negative = token.starts_with("-");
    std::size_t i = negative ? 1 : 0, fractional = 0;
    bool afterPoint = false;
    std::string digits;
    for (; i < token.size() && token[i] != 'e' && token[i] != 'E'; ++i) {
        if (token[i] == '.') { afterPoint = true; continue; }
        digits.push_back(token[i]);
        if (afterPoint) ++fractional;
    }
    const auto nonzero = digits.find_first_not_of('0');
    if (nonzero == std::string::npos) { id = std::int64_t(0); return true; }
    digits.erase(0, nonzero);
    std::int64_t exponent = 0;
    if (i < token.size()) {
        ++i;
        if (token[i] == '+') ++i;
        const auto parsed = std::from_chars(token.data() + i, token.end(), exponent);
        if (parsed.ec != std::errc{} || parsed.ptr != token.end() ||
            exponent > static_cast<std::int64_t>(kMaxMessageBytes) ||
            exponent < -static_cast<std::int64_t>(kMaxMessageBytes)) return false;
    }
    const auto shift = exponent - static_cast<std::int64_t>(fractional);
    if (shift < 0) {
        const auto remove = static_cast<std::size_t>(-shift);
        if (remove >= digits.size()) return false;
        if (digits.find_first_not_of('0', digits.size() - remove) != std::string::npos)
            return false;
        digits.resize(digits.size() - remove);
    } else {
        if (digits.size() > 20 || static_cast<std::uint64_t>(shift) > 20 - digits.size())
            return false;
        digits.append(static_cast<std::size_t>(shift), '0');
    }
    if (digits.size() > 20) return false;
    if (negative) {
        digits.insert(digits.begin(), '-');
        std::int64_t value = 0;
        const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), value);
        if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size()) return false;
        id = value;
    } else {
        std::uint64_t value = 0;
        const auto parsed = std::from_chars(digits.data(), digits.data() + digits.size(), value);
        if (parsed.ec != std::errc{} || parsed.ptr != digits.data() + digits.size()) return false;
        id = value;
    }
    return true;
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

json::Object makeInputError(const json::Value& id, const codeskeptic::InputError& error) {
    auto data = json::parse(codeskeptic::inputErrorJson(error));
    if (!data) {
        llvm::consumeError(data.takeError());
        return makeError(id, -32603, "cannot serialize input failure");
    }
    auto response = makeError(id, -32602, error.message);
    (*response.getObject("error"))["data"] = std::move(*data);
    return response;
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
            {"disable_rules", json::Object{
                {"type", "string"},
                {"description", "Comma-separated diagnostic family IDs to exclude for this request; adds to server defaults. Omit to add no exclusions. Empty or unknown IDs are rejected."},
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

json::Value runAnalyze(const json::Value& id, const json::Object* args,
                      const codeskeptic::Config& defaults, bool* analysis_cancelled) {
    if (!args) return makeError(id, -32602, "missing arguments");

    static const std::set<std::string> allowedFields = {
        "path", "build_path", "functions", "lines", "summaries",
        "fatal_asserts", "alloc_functions", "free_functions",
        "allocator_pairs", "disable_rules"
    };
    for (const auto& field : *args) {
        const std::string name = field.first.str();
        if (!allowedFields.count(name))
            return makeError(id, -32602, "unknown analyze field: " + name);
    }

    for (const auto& name : allowedFields) {
        if (name == "disable_rules" && args->get(name) && !args->getString(name))
            return makeInputError(id, {"invalid_type", name, "Expected a comma-separated diagnostic ID string"});
        if (args->get(name) && !args->getString(name))
            return makeError(id, -32602,
                             "field must be a string: " + name);
        if (auto value = args->getString(name)) {
            if (value->contains('\0'))
                return makeInputError(id, {"invalid_value", name, "Input contains NUL"});
        }
    }

    auto path = args->getString("path");
    if (!path) return makeError(id, -32602, "missing required field: path");
    if (path->empty())
        return makeError(id, -32602, "field must not be empty: path");

    codeskeptic::Config config;
    config.inheritRuleSelection(defaults);
    config.inheritWorkerLimits(defaults);
    codeskeptic::InputError inputError;
    if (auto disabled = args->getString("disable_rules")) {
        if (!config.addDisabledRules(disabled->str(), &inputError))
            return makeInputError(id, inputError);
    }
    config.setSourcePath(path->str());
    if (auto buildPath = args->getString("build_path"))
        config.setBuildPath(buildPath->str());
    if (auto functions = args->getString("functions")) {
        if (!config.addFunctions(functions->str(), &inputError))
            return makeInputError(id, inputError);
    }
    if (auto lines = args->getString("lines")) {
        if (!config.addLines(lines->str(), &inputError))
            return makeInputError(id, inputError);
    }
    if (auto summaries = args->getString("summaries"))
        config.setSummaryIn(summaries->str());
    if (auto fatalAsserts = args->getString("fatal_asserts")) {
        if (!config.addFatalAsserts(fatalAsserts->str(), &inputError))
            return makeInputError(id, inputError);
    }
    if (auto allocFns = args->getString("alloc_functions")) {
        if (!config.addAllocFunctions(allocFns->str(), &inputError))
            return makeInputError(id, inputError);
    }
    if (auto freeFns = args->getString("free_functions")) {
        if (!config.addFreeFunctions(freeFns->str(), &inputError))
            return makeInputError(id, inputError);
    }
    if (auto pairs = args->getString("allocator_pairs")) {
        if (!config.addAllocatorPairs(pairs->str(), &inputError))
            return makeInputError(id, inputError);
    }
    // Long-lived process: parsed ASTs are kept warm between calls (the
    // fingerprint catches staleness — a stale AST is NEVER served)
    config.setWarmCache(true);

    codeskeptic::StaticAnalyzer analyzer(std::move(config));
    analyzer.addRule<codeskeptic::UninitPointerRule_Ex>();
    analyzer.addRule<codeskeptic::UninitScalarRule>();
    analyzer.addRule<codeskeptic::MemoryLeakRule_Ex>();
    analyzer.addRule<codeskeptic::FdResourceRule>();
    analyzer.addRule<codeskeptic::DivByZeroRule>();
    analyzer.addRule<codeskeptic::IntOverflowRule>();
    analyzer.addRule<codeskeptic::SignConversionRule>();
    analyzer.addRule<codeskeptic::AllocSizeOverflowRule>();
    analyzer.addRule<codeskeptic::BoundsRule>();
    analyzer.addRule<codeskeptic::AssumptionRule>();
    analyzer.addRule<codeskeptic::NullDerefRule>();
    analyzer.addRule<codeskeptic::ContractRule>();
    analyzer.addRule<codeskeptic::PolicyRule>();
    const codeskeptic::AnalysisResult result = analyzer.run();
    if (analysis_cancelled) {
        for (const auto& source : result.sources)
            if (source.reason == "worker_cancelled") *analysis_cancelled = true;
    }

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

    // Use exactly the CLI/JSON/SARIF representation, including source identities
    // and failed command evidence. Do not reconstruct a second coverage schema.
    std::ostringstream coverageText;
    codeskeptic::writeCoverageJson(coverageText, result);
    auto coverage = json::parse(coverageText.str());
    if (!coverage) {
        llvm::consumeError(coverage.takeError());
        return makeError(id, -32603, "unable to serialize source coverage");
    }
    json::Object payload{
        {"status", result.statusName()},
        {"complete", result.complete()},
        {"exit_code", static_cast<int64_t>(result.exitCode())},
        {"coverage", std::move(*coverage)},
        {"evidence", json::Object{
            {"tool_failed", result.tool_failed},
            {"summary_load_failed", result.summary_load_failed},
            {"summary_stale", result.summary_stale},
        }},
        {"count", static_cast<int64_t>(findings.size())},
        {"blocking_count",
         static_cast<int64_t>(result.blockingFindings())},
        {"report_only_count",
         static_cast<int64_t>(result.report_only_findings)},
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
                            const codeskeptic::Config& defaults, bool* analysis_cancelled) {
    if (!params) return makeError(id, -32602, "missing params");
    auto name = params->getString("name");
    if (!name) return makeError(id, -32602, "missing tool name");
    if (*name != "analyze")
        return makeError(id, -32602, "unknown tool: " + name->str());
    return runAnalyze(id, params->getObject("arguments"), defaults, analysis_cancelled);
}

} // anonymous namespace

namespace codeskeptic {

static std::string handleMcpMessageWithCancellation(const std::string& line,
    const Config& defaults, bool* analysis_cancelled);

std::string handleMcpMessage(const std::string& line) {
    return handleMcpMessage(line, Config{});
}

std::string handleMcpMessage(const std::string& line, const Config& defaults) {
    return handleMcpMessageWithCancellation(line, defaults, nullptr);
}

static std::string handleMcpMessageWithCancellation(const std::string& line,
    const Config& defaults, bool* analysis_cancelled) {
    json::Value id(nullptr);
    try {
        if (line.size() > kMaxMessageBytes || !withinDepthBudget(line))
            return serialize(json::Value(makeError(nullptr, -32600, "request exceeds input budget")));
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

        const auto version = msg->getString("jsonrpc");
        const auto method = msg->getString("method");
        const json::Value* idPtr = msg->get("id");
        json::Value requestId(nullptr);
        if (!version || *version != "2.0" || !method || method->empty() ||
            method->contains('\0') || (idPtr && !parseRequestId(*idPtr, line, requestId)))
            return serialize(json::Value(makeError(nullptr, -32600, "invalid request")));

        // Absence of an ID is valid for notifications, not for an invalid envelope.
        // This server has no analysis side effects for any notification method.
        if (!idPtr) return "";
        id = std::move(requestId);
        if (msg->get("params") && !msg->getObject("params"))
            return serialize(json::Value(makeError(id, -32602, "params must be an object")));

        json::Value response(nullptr);
        if (*method == "initialize") {
            response = handleInitialize(id);
        } else if (*method == "ping") {
            response = makeResponse(id, json::Object{});
        } else if (*method == "tools/list") {
            response = handleToolsList(id);
        } else if (*method == "tools/call") {
            response = handleToolsCall(id, msg->getObject("params"), defaults, analysis_cancelled);
        } else {
            response = makeError(id, -32601, "method not found");
        }
        return serialize(response);
    } catch (...) {
        // Analyzer lifetime cleanup has already run, including constructor
        // failures and exceptions transferred from the joined worker. Never
        // expose exception text or an incomplete payload as a successful result.
        return serialize(json::Value(makeError(id, -32603, "internal error")));
    }
}

int runMcpServer() {
    return runMcpServer(Config{});
}

int runMcpServer(const Config& defaults) {
#ifdef _WIN32
    // Newline-delimited JSON-RPC framing: Windows text-mode stdio
    // would expand "\n" to "\r\n" on write and leave stray '\r's in
    // reads. Binary mode keeps the frames byte-exact
    // (docs/windows-support.md §5).
    _setmode(_fileno(stdin), _O_BINARY);
    _setmode(_fileno(stdout), _O_BINARY);
#endif
    try {
        std::string line;
        bool oversized = false;
        for (;;) {
            const auto ch = std::cin.get();
            const bool eof = ch == std::char_traits<char>::eof();
            if (eof && (std::cin.bad() || !std::cin.eof())) return 2;
            if (!eof && ch != '\n') {
                // One additional byte allows a CRLF client's trailing CR.
                if (line.size() <= kMaxMessageBytes) line.push_back(static_cast<char>(ch));
                else oversized = true;
                continue;
            }
            if (!line.empty() && line.back() == '\r') line.pop_back();
            oversized = oversized || line.size() > kMaxMessageBytes;
            if (oversized || !line.empty()) {
                bool analysis_cancelled = false;
                const std::string response = oversized
                    ? serialize(json::Value(makeError(nullptr, -32600, "request exceeds input budget")))
                    : handleMcpMessageWithCancellation(line, defaults, &analysis_cancelled);
                if (!response.empty()) {
                    std::cout << response << '\n' << std::flush;
                    if (!std::cout) return 2;
                    // An active analysis has already reaped its cancelled
                    // child. Deliver its complete frame before stopping; do
                    // not block for a second request/EOF. Ordinary resource
                    // failures do not mark this request cancelled. No state
                    // from an earlier or unrelated call can stop this server.
                    if (analysis_cancelled) return 2;
                }
            }
            if (eof) return 0;
            line.clear();
            oversized = false;
        }
    } catch (...) {
        // A broken input/output channel cannot deliver a reliable RPC reply.
        return 2;
    }
}

} // namespace codeskeptic
