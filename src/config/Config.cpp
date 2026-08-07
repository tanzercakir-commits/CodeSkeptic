#include "config/Config.h"

#include "core/Messages.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <set>
#include <stdexcept>

namespace {

std::string trim(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

bool parseBool(const std::string& value, bool& out) {
    if (value == "true" || value == "1") {
        out = true;
        return true;
    }
    if (value == "false" || value == "0") {
        out = false;
        return true;
    }
    return false;
}

bool isOutputFormat(const std::string& value) {
    return value == "console" || value == "json" ||
           value == "sarif" || value == "html";
}

const std::set<std::string>& singleValueOptions() {
    static const std::set<std::string> options = {
        "--source", "--build-path", "--json", "--sarif", "--html",
        "--severity", "--disable-rule", "--lang", "--baseline",
        "--function", "--fatal-asserts", "--assert-macros",
        "--negative-assert-macros", "--alloc-functions",
        "--free-functions", "--untrusted-int-sources",
        "--owning-pointers", "--report-paths", "--policy", "--gate",
        "--lines", "--summary-in", "--summary-out", "--files",
        "--write-baseline"
    };
    return options;
}

bool looksLikeOption(const char* value) {
    return value && value[0] == '-' && value[1] == '-';
}

void configError(const std::string& path, std::size_t line,
                 const std::string& message) {
    std::cerr << "[CodeSkeptic] invalid config " << path << ":" << line
              << ": " << message << "\n";
}

} // anonymous namespace

namespace codeskeptic {

Config::Config()
    : build_path_(".")
    , output_format_("console")
    , lang_("en")
    , min_severity_(Severity::Info) {}

bool Config::loadFromFile(const std::string& path) {
    std::ifstream file(path);
    // The default project config is optional. Once the file exists, every
    // non-comment line is a contract and is validated strictly.
    if (!file.is_open()) {
        std::error_code ec;
        if (std::filesystem::exists(path, ec) && !ec) {
            std::cerr << "[CodeSkeptic] cannot read config: " << path << "\n";
            return false;
        }
        return true;
    }

    std::string line;
    std::size_t lineNumber = 0;
    bool ok = true;
    while (std::getline(file, line)) {
        ++lineNumber;
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        auto pos = line.find('=');
        if (pos == std::string::npos) {
            configError(path, lineNumber, "expected key=value");
            ok = false;
            continue;
        }

        std::string key = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1));
        if (key.empty()) {
            configError(path, lineNumber, "empty key");
            ok = false;
            continue;
        }

        if (key == "source_path")        source_path_ = value;
        else if (key == "build_path")    build_path_ = value;
        else if (key == "output_format") {
            if (!isOutputFormat(value)) {
                configError(path, lineNumber,
                            "output_format expects console/json/sarif/html");
                ok = false;
            } else {
                output_format_ = value;
            }
        }
        else if (key == "json_output") {
            output_format_ = "json";
            json_output_path_ = value;
        }
        else if (key == "sarif_output") {
            output_format_ = "sarif";
            sarif_output_path_ = value;
        }
        else if (key == "html_output") {
            output_format_ = "html";
            html_output_path_ = value;
        }
        else if (key == "min_severity") {
            Severity parsed;
            if (!parseSeverity(value, parsed)) {
                configError(path, lineNumber,
                            "min_severity expects info/warning/error");
                ok = false;
            } else {
                min_severity_ = parsed;
            }
        }
        else if (key == "lang") {
            if (value != "en" && value != "tr") {
                configError(path, lineNumber, "lang expects en or tr");
                ok = false;
            } else {
                lang_ = value;
            }
        }
        else if (key == "baseline")      baseline_path_ = value;
        else if (key == "function")      addFunctions(value);
        else if (key == "fatal_asserts") addFatalAsserts(value);
        else if (key == "assert_macros") addAssertMacros(value);
        else if (key == "negative_assert_macros") addNegativeAssertMacros(value);
        else if (key == "assert_recovery") {
            if (!parseBool(value, assert_recovery_)) {
                configError(path, lineNumber,
                            "assert_recovery expects true/false/1/0");
                ok = false;
            }
        }
        else if (key == "alloc_functions") addNamesTo(alloc_functions_, value);
        else if (key == "free_functions")  addNamesTo(free_functions_, value);
        else if (key == "owning_pointers") addNamesTo(owning_pointers_, value);
        else if (key == "untrusted_int_sources") addNamesTo(untrusted_int_sources_, value);
        else if (key == "report_paths")    addReportPaths(value);
        else if (key == "policy")          addNamesTo(policies_, value);
        else if (key == "summary_diff_gate") {
            if (value != "error" && value != "warn") {
                configError(path, lineNumber,
                            "summary_diff_gate expects error or warn");
                ok = false;
            } else {
                summary_diff_gate_ = value;
            }
        }
        else if (key == "analyze_broken_tus") {
            if (!parseBool(value, analyze_broken_tus_)) {
                configError(path, lineNumber,
                            "analyze_broken_tus expects true/false/1/0");
                ok = false;
            }
        }
        else if (key == "accept_partial_coverage") {
            if (!parseBool(value, accept_partial_coverage_)) {
                configError(path, lineNumber,
                            "accept_partial_coverage expects true/false/1/0");
                ok = false;
            }
        }
        else if (key == "enable_rule")   enabled_rules_.insert(value);
        else if (key == "disable_rule")  disabled_rules_.insert(value);
        else {
            configError(path, lineNumber, "unknown key '" + key + "'");
            ok = false;
        }
    }

    if (file.bad()) {
        std::cerr << "[CodeSkeptic] failed while reading config: " << path
                  << "\n";
        ok = false;
    }
    return ok;
}

bool Config::parseArgs(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (singleValueOptions().count(arg) &&
            (i + 1 >= argc || looksLikeOption(argv[i + 1]))) {
            std::cerr << "[CodeSkeptic] missing value for " << arg << "\n";
            return false;
        }
        if (arg == "--summary-diff" &&
            (i + 2 >= argc || looksLikeOption(argv[i + 1]) ||
             looksLikeOption(argv[i + 2]))) {
            std::cerr << "[CodeSkeptic] --summary-diff expects two files\n";
            return false;
        }

        if (arg == "--source" && i + 1 < argc) {
            source_path_ = argv[++i];
        } else if (arg == "--build-path" && i + 1 < argc) {
            build_path_ = argv[++i];
        } else if (arg == "--json" && i + 1 < argc) {
            output_format_ = "json";
            json_output_path_ = argv[++i];
        } else if (arg == "--sarif" && i + 1 < argc) {
            output_format_ = "sarif";
            sarif_output_path_ = argv[++i];
        } else if (arg == "--html" && i + 1 < argc) {
            output_format_ = "html";
            html_output_path_ = argv[++i];
        } else if (arg == "--severity" && i + 1 < argc) {
            const std::string value = argv[++i];
            if (!parseSeverity(value, min_severity_)) {
                std::cerr << "[CodeSkeptic] --severity expects "
                             "info/warning/error, got: " << value << "\n";
                return false;
            }
        } else if (arg == "--disable-rule" && i + 1 < argc) {
            disabled_rules_.insert(argv[++i]);
        } else if (arg == "--lang" && i + 1 < argc) {
            lang_ = argv[++i];
            if (lang_ != "en" && lang_ != "tr") {
                std::cerr << "[CodeSkeptic] --lang expects en or tr, got: "
                          << lang_ << "\n";
                return false;
            }
        } else if (arg == "--baseline" && i + 1 < argc) {
            baseline_path_ = argv[++i];
        } else if (arg == "--function" && i + 1 < argc) {
            addFunctions(argv[++i]);
        } else if (arg == "--fatal-asserts" && i + 1 < argc) {
            addFatalAsserts(argv[++i]);
        } else if (arg == "--assert-macros" && i + 1 < argc) {
            addAssertMacros(argv[++i]);
        } else if (arg == "--negative-assert-macros" && i + 1 < argc) {
            addNegativeAssertMacros(argv[++i]);
        } else if (arg == "--no-assert-recovery") {
            assert_recovery_ = false;
        } else if (arg == "--alloc-functions" && i + 1 < argc) {
            addNamesTo(alloc_functions_, argv[++i]);
        } else if (arg == "--free-functions" && i + 1 < argc) {
            addNamesTo(free_functions_, argv[++i]);
        } else if (arg == "--untrusted-int-sources" && i + 1 < argc) {
            addNamesTo(untrusted_int_sources_, argv[++i]);
        } else if (arg == "--owning-pointers" && i + 1 < argc) {
            addNamesTo(owning_pointers_, argv[++i]);
        } else if (arg == "--report-paths" && i + 1 < argc) {
            addReportPaths(argv[++i]);
        } else if (arg == "--policy" && i + 1 < argc) {
            addNamesTo(policies_, argv[++i]);
        } else if (arg == "--gate" && i + 1 < argc) {
            summary_diff_gate_ = argv[++i];
            if (summary_diff_gate_ != "error" &&
                summary_diff_gate_ != "warn") {
                std::cerr << "[CodeSkeptic] --gate expects 'error' or "
                             "'warn', got: " << summary_diff_gate_
                          << "\n";
                return false;
            }
        } else if (arg == "--lines" && i + 1 < argc) {
            const std::string value = argv[++i];
            if (!addLines(value)) {
                std::cerr << "[CodeSkeptic] --lines expects positive line "
                             "numbers/ranges (e.g. 10-40,55), got: "
                          << value << "\n";
                return false;
            }
        } else if (arg == "--serve") {
            serve_ = true;
        } else if (arg == "--whole-program") {
            whole_program_ = true;
        } else if (arg == "--analyze-broken-tus") {
            analyze_broken_tus_ = true;
        } else if (arg == "--accept-partial-coverage") {
            accept_partial_coverage_ = true;
        } else if (arg == "--assumptions") {
            assumptions_ = true;
        } else if (arg == "--summary-in" && i + 1 < argc) {
            summary_in_path_ = argv[++i];
        } else if (arg == "--summary-out" && i + 1 < argc) {
            summary_out_path_ = argv[++i];
        } else if (arg == "--summary-diff" && i + 2 < argc) {
            summary_diff_old_ = argv[++i];
            summary_diff_new_ = argv[++i];
        } else if (arg == "--files" && i + 1 < argc) {
            // List file: one source file path per line.
            // For large/hand-picked sets (benchmarks, agent batch requests).
            const char* listPath = argv[++i];
            std::ifstream listFile(listPath);
            // A missing LIST file must say so — silently leaving the
            // set empty surfaced as the generic "no source path"
            // usage message and cost a 20-minute scan-diff hunt
            // (2026-07-12).
            if (!listFile) {
                std::cerr << "[CodeSkeptic] --files list not found: "
                          << listPath << "\n";
                return false;
            }
            std::string fileLine;
            while (std::getline(listFile, fileLine)) {
                if (!fileLine.empty()) source_files_.push_back(fileLine);
            }
        } else if (arg == "--write-baseline" && i + 1 < argc) {
            write_baseline_path_ = argv[++i];
        } else if (arg == "--help") {
            std::cout << "Usage: codeskeptic [options] [source_path]\n"
                      << "\n"
                      << "Options:\n"
                      << "  --source <path>        Directory/file to analyze\n"
                      << "  --build-path <path>    compile_commands.json directory\n"
                      << "  --json <file>          JSON output file\n"
                      << "  --sarif <file>         SARIF 2.1.0 output file\n"
                      << "  --html <file>          Self-contained HTML report (filters,\n"
                      << "                         dataflow traces with source context)\n"
                      << "  --severity <level>     Minimum severity (info/warning/error)\n"
                      << "  --disable-rule <id>    Disable a rule\n"
                      << "  --baseline <file>      Suppress findings recorded in baseline\n"
                      << "  --write-baseline <file> Record current findings as baseline\n"
                      << "  --function <names>     Analyze only these functions (comma list,\n"
                      << "                         plain or qualified; repeatable)\n"
                      << "  --lines <N-M,K>        Analyze only functions overlapping these\n"
                      << "                         line ranges of the analyzed file\n"
                      << "  --fatal-asserts <names> Treat these functions as never returning\n"
                      << "                         (comma list; kills dataflow paths after\n"
                      << "                         custom assert-failure handlers that lack\n"
                      << "                         [[noreturn]])\n"
                      << "  --assert-macros <names> Extra macro names that are assertions\n"
                      << "                         (comma list). Anything containing\n"
                      << "                         \"assert\" is recognized already; use this\n"
                      << "                         for CHECK/VERIFY-style spellings. Single-\n"
                      << "                         argument macros only. Never list one that\n"
                      << "                         asserts a NEGATIVE (assert_null and\n"
                      << "                         friends) - it would be believed backwards\n"
                      << "  --negative-assert-macros <names> Macro names that assert a\n"
                      << "                         pointer IS null/empty/unset (comma list).\n"
                      << "                         The spelling heuristic vetoes a null-ness\n"
                      << "                         vocabulary already; list here any negative\n"
                      << "                         macro whose name uses none of those words\n"
                      << "                         (wins over --assert-macros on conflict)\n"
                      << "  --no-assert-recovery   Do not recover assert conditions that\n"
                      << "                         NDEBUG compiled out. On by default: a\n"
                      << "                         release-build assert() leaves no trace in\n"
                      << "                         the AST, so without recovery every\n"
                      << "                         pointer it guards reads as unchecked\n"
                      << "  --alloc-functions <names> Treat these functions as heap\n"
                      << "                         allocators (comma list; extends the\n"
                      << "                         leak/double-free/UAF analysis to project\n"
                      << "                         wrappers like git__malloc, zmalloc)\n"
                      << "  --untrusted-int-sources <names> Treat these functions'\n"
                      << "                         return AND integer out-params as a\n"
                      << "                         full-range untrusted length (comma list;\n"
                      << "                         same discipline as atoi — for wire/packet\n"
                      << "                         length fields in parsers; also drives the\n"
                      << "                         sign-conversion rule)\n"
                      << "  --free-functions <names> Treat these functions as deallocators\n"
                      << "                         (first argument is freed)\n"
                      << "  --owning-pointers <names> Treat these class templates as\n"
                      << "                         owning smart pointers (comma list;\n"
                      << "                         a raw pointer adopted by constructing\n"
                      << "                         one — Ref, RefPtr, scoped_refptr — is\n"
                      << "                         no longer leaked; std::unique_ptr/\n"
                      << "                         shared_ptr are built in)\n"
                      << "  --report-paths <paths> Report only findings under these\n"
                      << "                         path prefixes (comma list). Filters\n"
                      << "                         out findings in dependency headers\n"
                      << "                         pulled into your TUs; analysis is\n"
                      << "                         unaffected\n"
                      << "  --serve                Run as an MCP server (JSON-RPC on stdio)\n"
                      << "  --whole-program        Two-pass mode: collect function summaries\n"
                      << "                         across all files first, then analyze\n"
                      << "  --accept-partial-coverage  Allow a verdict over successfully\n"
                      << "                         analyzed TUs while still reporting skips\n"
                      << "  --summary-out <file>   Save harvested cross-file function\n"
                      << "                         summaries to a file after analysis\n"
                      << "  --summary-in <file>    Load function summaries saved earlier;\n"
                      << "                         analyze single files with whole-project\n"
                      << "                         knowledge (incremental whole-program)\n"
                      << "  --summary-diff <old> <new>  Report contract changes between two\n"
                      << "                         summary files instead of analyzing;\n"
                      << "                         exits 1 if any contract weakened\n"
                      << "  --files <list>         Analyze files listed (one path per line)\n"
                      << "  --lang <en|tr>         Diagnostic message language (default: en)\n"
                      << "  --version              Print version and exit\n"
                      << "  --help                 Show this message\n";
            help_requested_ = true;
            return true;
        } else if (arg[0] != '-' && source_path_.empty()) {
            source_path_ = arg;
        } else if (arg[0] != '-') {
            // A second positional used to be SILENTLY ignored — the
            // caller believed both files were analyzed (v0.4.5,
            // caught while testing the exit-2 policy). Fail loudly:
            // one path (file or directory) or --files <list>.
            std::cerr << msg(MsgId::MultipleSourcePaths, source_path_, arg)
                      << "\n";
            return false;
        } else {
            if (singleValueOptions().count(arg) || arg == "--summary-diff")
                std::cerr << "[CodeSkeptic] missing value for " << arg << "\n";
            else
                std::cerr << "[CodeSkeptic] unknown option: " << arg << "\n";
            return false;
        }
    }

    if (output_format_ == "json" && json_output_path_.empty()) {
        std::cerr << "[CodeSkeptic] json output requires a file path\n";
        return false;
    }
    if (output_format_ == "sarif" && sarif_output_path_.empty()) {
        std::cerr << "[CodeSkeptic] sarif output requires a file path\n";
        return false;
    }
    if (output_format_ == "html" && html_output_path_.empty()) {
        std::cerr << "[CodeSkeptic] html output requires a file path\n";
        return false;
    }
    return true;
}

bool Config::isRuleEnabled(const std::string& rule_id) const {
    if (disabled_rules_.count(rule_id)) return false;
    if (enabled_rules_.empty()) return true;
    return enabled_rules_.count(rule_id) > 0;
}

void Config::addFunctions(const std::string& list) {
    std::string token;
    for (size_t i = 0; i <= list.size(); ++i) {
        char c = (i < list.size()) ? list[i] : ',';
        if (c == ',') {
            if (!token.empty()) functions_.insert(token);
            token.clear();
        } else if (c != ' ') {
            token += c;
        }
    }
}

void Config::addFatalAsserts(const std::string& list) {
    addNamesTo(fatal_asserts_, list);
}

void Config::addNegativeAssertMacros(const std::string& list) {
    addNamesTo(negative_assert_macros_, list);
}

void Config::addAssertMacros(const std::string& list) {
    addNamesTo(assert_macros_, list);
}

void Config::addAllocFunctions(const std::string& list) {
    addNamesTo(alloc_functions_, list);
}

void Config::addFreeFunctions(const std::string& list) {
    addNamesTo(free_functions_, list);
}

void Config::addOwningPointers(const std::string& list) {
    addNamesTo(owning_pointers_, list);
}

void Config::addReportPaths(const std::string& list) {
    // Comma-split with edge-trim only: unlike identifier lists, paths
    // may legally contain interior spaces.
    std::string token;
    auto flush = [&] {
        size_t b = token.find_first_not_of(" \t");
        size_t e = token.find_last_not_of(" \t");
        if (b != std::string::npos)
            report_paths_.push_back(token.substr(b, e - b + 1));
        token.clear();
    };
    for (char c : list) {
        if (c == ',') flush();
        else token += c;
    }
    flush();
}

void Config::addNamesTo(std::set<std::string>& target,
                        const std::string& list) {
    std::string token;
    for (size_t i = 0; i <= list.size(); ++i) {
        char c = (i < list.size()) ? list[i] : ',';
        if (c == ',') {
            if (!token.empty()) target.insert(token);
            token.clear();
        } else if (c != ' ') {
            token += c;
        }
    }
}

bool Config::addLines(const std::string& list) {
    // "12-40,55" -> {12,40}, {55,55}. Invalid scope is a caller error:
    // silently dropping it would expand a targeted analysis to all functions.
    std::string token;
    bool ok = true;
    auto flush = [this, &ok](const std::string& t) {
        if (t.empty()) {
            ok = false;
            return;
        }
        auto dash = t.find('-');
        unsigned from = 0, to = 0;
        try {
            std::size_t used = 0;
            if (dash == std::string::npos) {
                const auto parsed = std::stoul(t, &used);
                if (used != t.size()) throw std::invalid_argument("line");
                if (parsed > std::numeric_limits<unsigned>::max())
                    throw std::out_of_range("line");
                from = to = static_cast<unsigned>(parsed);
            } else {
                if (dash == 0 || dash + 1 >= t.size() ||
                    t.find('-', dash + 1) != std::string::npos)
                    throw std::invalid_argument("range");
                const std::string first = t.substr(0, dash);
                const std::string last = t.substr(dash + 1);
                const auto parsedFrom = std::stoul(first, &used);
                if (used != first.size()) throw std::invalid_argument("line");
                if (parsedFrom > std::numeric_limits<unsigned>::max())
                    throw std::out_of_range("line");
                from = static_cast<unsigned>(parsedFrom);
                const auto parsedTo = std::stoul(last, &used);
                if (used != last.size()) throw std::invalid_argument("line");
                if (parsedTo > std::numeric_limits<unsigned>::max())
                    throw std::out_of_range("line");
                to = static_cast<unsigned>(parsedTo);
            }
        } catch (...) {
            ok = false;
            return;
        }
        if (from == 0 || to < from) {
            ok = false;
            return;
        }
        lines_.emplace_back(from, to);
    };
    for (size_t i = 0; i <= list.size(); ++i) {
        char c = (i < list.size()) ? list[i] : ',';
        if (c == ',') {
            flush(token);
            token.clear();
        } else if (c != ' ') {
            token += c;
        }
    }
    return ok;
}

bool Config::parseSeverity(const std::string& str, Severity& severity) const {
    if (str == "info") {
        severity = Severity::Info;
        return true;
    }
    if (str == "warning") {
        severity = Severity::Warning;
        return true;
    }
    if (str == "error") {
        severity = Severity::Error;
        return true;
    }
    return false;
}

} // namespace codeskeptic
