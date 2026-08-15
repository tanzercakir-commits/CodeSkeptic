#include "config/Config.h"

#include "core/Messages.h"

#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <set>
#include <sstream>
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

bool parseBoundedUnsigned(const std::string& value,
                          unsigned maximum,
                          unsigned& out) {
    if (value.empty()) return false;
    std::uint64_t parsed = 0;
    const char* first = value.data();
    const char* last = first + value.size();
    const auto result = std::from_chars(first, last, parsed, 10);
    if (result.ec != std::errc{} || result.ptr != last || parsed == 0 ||
        parsed > maximum)
        return false;
    out = static_cast<unsigned>(parsed);
    return true;
}

const std::set<std::string>& singleValueOptions() {
    static const std::set<std::string> options = {
        "--source", "--build-path", "--json", "--sarif", "--html",
        "--severity", "--disable-rule", "--lang", "--baseline",
        "--function", "--fatal-asserts", "--assert-macros",
        "--negative-assert-macros", "--alloc-functions",
        "--free-functions", "--allocator-pairs", "--untrusted-int-sources",
        "--owning-pointers", "--report-paths", "--policy", "--gate",
        "--lines", "--summary-in", "--summary-out", "--model-file",
        "--files", "--tu-timeout-seconds", "--tu-memory-mib",
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

bool Config::operator==(const Config& other) const {
    return source_path_ == other.source_path_ &&
           source_files_ == other.source_files_ &&
           build_path_ == other.build_path_ &&
           output_format_ == other.output_format_ &&
           json_output_path_ == other.json_output_path_ &&
           sarif_output_path_ == other.sarif_output_path_ &&
           html_output_path_ == other.html_output_path_ &&
           baseline_path_ == other.baseline_path_ &&
           write_baseline_path_ == other.write_baseline_path_ &&
           lang_ == other.lang_ && functions_ == other.functions_ &&
           fatal_asserts_ == other.fatal_asserts_ &&
           assert_macros_ == other.assert_macros_ &&
           negative_assert_macros_ == other.negative_assert_macros_ &&
           alloc_functions_ == other.alloc_functions_ &&
           allocator_pairs_ == other.allocator_pairs_ &&
           untrusted_int_sources_ == other.untrusted_int_sources_ &&
           free_functions_ == other.free_functions_ &&
           owning_pointers_ == other.owning_pointers_ &&
           report_paths_ == other.report_paths_ &&
           policies_ == other.policies_ &&
           summary_diff_gate_ == other.summary_diff_gate_ &&
           lines_ == other.lines_ && serve_ == other.serve_ &&
           whole_program_ == other.whole_program_ &&
           analyze_broken_tus_ == other.analyze_broken_tus_ &&
           accept_partial_coverage_ == other.accept_partial_coverage_ &&
           tu_timeout_seconds_ == other.tu_timeout_seconds_ &&
           tu_memory_mib_ == other.tu_memory_mib_ &&
           assert_recovery_ == other.assert_recovery_ &&
           assumptions_ == other.assumptions_ &&
           warm_cache_ == other.warm_cache_ &&
           help_requested_ == other.help_requested_ &&
           summary_in_path_ == other.summary_in_path_ &&
           summary_out_path_ == other.summary_out_path_ &&
           model_files_ == other.model_files_ &&
           summary_diff_old_ == other.summary_diff_old_ &&
           summary_diff_new_ == other.summary_diff_new_ &&
           min_severity_ == other.min_severity_ &&
           enabled_rules_ == other.enabled_rules_ &&
           disabled_rules_ == other.disabled_rules_;
}

Config Config::mcpRequestConfig() const {
    Config scoped = *this;
    scoped.source_path_.clear();
    scoped.source_files_.clear();
    scoped.output_format_ = "console";
    scoped.json_output_path_.clear();
    scoped.sarif_output_path_.clear();
    scoped.html_output_path_.clear();
    scoped.baseline_path_.clear();
    scoped.write_baseline_path_.clear();
    scoped.functions_.clear();
    scoped.lines_.clear();
    scoped.serve_ = false;
    scoped.whole_program_ = false;
    scoped.warm_cache_ = false;
    scoped.help_requested_ = false;
    scoped.summary_in_path_.clear();
    scoped.summary_out_path_.clear();
    scoped.summary_diff_old_.clear();
    scoped.summary_diff_new_.clear();
    return scoped;
}

bool Config::loadFromFile(const std::string& path) {
    // The default project config is optional. Once the file exists, every
    // non-comment line is a contract and is validated strictly.
    std::error_code ec;
    const auto entryStatus = std::filesystem::symlink_status(path, ec);
    if (ec == std::errc::no_such_file_or_directory &&
        entryStatus.type() == std::filesystem::file_type::not_found)
        return true;
    if (ec) {
        std::cerr << "[CodeSkeptic] cannot inspect config: " << path
                  << ": " << ec.message() << "\n";
        return false;
    }
    if (entryStatus.type() == std::filesystem::file_type::not_found) return true;

    const auto resolvedStatus = std::filesystem::status(path, ec);
    if (ec || !std::filesystem::is_regular_file(resolvedStatus)) {
        std::cerr << "[CodeSkeptic] cannot read config: " << path;
        if (ec) std::cerr << ": " << ec.message();
        else std::cerr << ": path is not a regular file";
        std::cerr << "\n";
        return false;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[CodeSkeptic] cannot read config: " << path << "\n";
        return false;
    }

    std::ostringstream content;
    content << file.rdbuf();
    if (file.bad()) {
        std::cerr << "[CodeSkeptic] failed while reading config: " << path
                  << "\n";
        return false;
    }
    return loadFromText(content.str(), path);
}

bool Config::loadFromText(const std::string& text,
                          const std::string& source,
                          bool reportErrors) {
    if (text.find('\0') != std::string::npos) {
        if (reportErrors) configError(source, 0, "embedded NUL byte");
        return false;
    }
    Config candidate = *this;
    if (!candidate.loadFromTextInPlace(text, source, reportErrors)) return false;
    *this = std::move(candidate);
    return true;
}

bool Config::loadFromTextInPlace(const std::string& text,
                                 const std::string& source,
                                 bool reportErrors) {
    std::istringstream file(text);
    auto report = [&](std::size_t line, const std::string& message) {
        if (reportErrors) configError(source, line, message);
    };

    std::string line;
    std::size_t lineNumber = 0;
    bool ok = true;
    while (std::getline(file, line)) {
        ++lineNumber;
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        auto pos = line.find('=');
        if (pos == std::string::npos) {
            report(lineNumber, "expected key=value");
            ok = false;
            continue;
        }

        std::string key = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1));
        if (key.empty()) {
            report(lineNumber, "empty key");
            ok = false;
            continue;
        }

        if (key == "source_path")        source_path_ = value;
        else if (key == "build_path")    build_path_ = value;
        else if (key == "output_format") {
            if (!isOutputFormat(value)) {
                report(lineNumber,
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
                report(lineNumber,
                       "min_severity expects info/warning/error");
                ok = false;
            } else {
                min_severity_ = parsed;
            }
        }
        else if (key == "lang") {
            if (value != "en" && value != "tr") {
                report(lineNumber, "lang expects en or tr");
                ok = false;
            } else {
                lang_ = value;
            }
        }
        else if (key == "baseline")      baseline_path_ = value;
        else if (key == "function") {
            if (!addFunctions(value)) {
                report(lineNumber, "function expects at least one name");
                ok = false;
            }
        }
        else if (key == "fatal_asserts") addFatalAsserts(value);
        else if (key == "assert_macros") addAssertMacros(value);
        else if (key == "negative_assert_macros") addNegativeAssertMacros(value);
        else if (key == "assert_recovery") {
            if (!parseBool(value, assert_recovery_)) {
                report(lineNumber,
                       "assert_recovery expects true/false/1/0");
                ok = false;
            }
        }
        else if (key == "alloc_functions") addNamesTo(alloc_functions_, value);
        else if (key == "free_functions")  addNamesTo(free_functions_, value);
        else if (key == "allocator_pairs") {
            if (!addAllocatorPairs(value)) {
                report(lineNumber,
                       "allocator_pairs expects allocator=deallocator"
                       " entries separated by commas");
                ok = false;
            }
        }
        else if (key == "owning_pointers") addNamesTo(owning_pointers_, value);
        else if (key == "untrusted_int_sources") addNamesTo(untrusted_int_sources_, value);
        else if (key == "report_paths")    addReportPaths(value);
        else if (key == "policy")          addNamesTo(policies_, value);
        else if (key == "model_file") {
            if (value.empty()) {
                report(lineNumber, "model_file expects a non-empty path");
                ok = false;
            } else {
                model_files_.push_back(value);
            }
        }
        else if (key == "summary_diff_gate") {
            if (value != "error" && value != "warn") {
                report(lineNumber,
                       "summary_diff_gate expects error or warn");
                ok = false;
            } else {
                summary_diff_gate_ = value;
            }
        }
        else if (key == "analyze_broken_tus") {
            if (!parseBool(value, analyze_broken_tus_)) {
                report(lineNumber,
                       "analyze_broken_tus expects true/false/1/0");
                ok = false;
            }
        }
        else if (key == "accept_partial_coverage") {
            if (!parseBool(value, accept_partial_coverage_)) {
                report(lineNumber,
                       "accept_partial_coverage expects true/false/1/0");
                ok = false;
            }
        }
        else if (key == "tu_timeout_seconds") {
            if (!parseBoundedUnsigned(value, kMaxTuTimeoutSeconds,
                                      tu_timeout_seconds_)) {
                report(lineNumber,
                       "tu_timeout_seconds expects an integer from 1 to " +
                           std::to_string(kMaxTuTimeoutSeconds));
                ok = false;
            }
        }
        else if (key == "tu_memory_mib") {
            if (!parseBoundedUnsigned(value, kMaxTuMemoryMiB,
                                      tu_memory_mib_)) {
                report(lineNumber,
                       "tu_memory_mib expects an integer from 1 to " +
                           std::to_string(kMaxTuMemoryMiB));
                ok = false;
            }
        }
        else if (key == "enable_rule")   enabled_rules_.insert(value);
        else if (key == "disable_rule")  disabled_rules_.insert(value);
        else {
            report(lineNumber, "unknown key '" + key + "'");
            ok = false;
        }
    }

    if (file.bad()) {
        if (reportErrors)
            std::cerr << "[CodeSkeptic] failed while reading config: "
                      << source << "\n";
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
            const std::string value = argv[++i];
            if (!addFunctions(value)) {
                std::cerr << "[CodeSkeptic] --function expects at least "
                             "one function name\n";
                return false;
            }
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
        } else if (arg == "--allocator-pairs" && i + 1 < argc) {
            if (!addAllocatorPairs(argv[++i])) {
                std::cerr << "[CodeSkeptic] --allocator-pairs expects "
                             "allocator=deallocator entries separated by "
                             "commas\n";
                return false;
            }
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
        } else if (arg == "--tu-timeout-seconds" && i + 1 < argc) {
            const std::string value = argv[++i];
            unsigned parsed = 0;
            if (!parseBoundedUnsigned(value, kMaxTuTimeoutSeconds, parsed)) {
                std::cerr << "[CodeSkeptic] --tu-timeout-seconds expects an "
                             "integer from 1 to "
                          << kMaxTuTimeoutSeconds << ", got: " << value
                          << "\n";
                return false;
            }
            tu_timeout_seconds_ = parsed;
        } else if (arg == "--tu-memory-mib" && i + 1 < argc) {
            const std::string value = argv[++i];
            unsigned parsed = 0;
            if (!parseBoundedUnsigned(value, kMaxTuMemoryMiB, parsed)) {
                std::cerr << "[CodeSkeptic] --tu-memory-mib expects an "
                             "integer from 1 to "
                          << kMaxTuMemoryMiB << ", got: " << value << "\n";
                return false;
            }
            tu_memory_mib_ = parsed;
        } else if (arg == "--assumptions") {
            assumptions_ = true;
        } else if (arg == "--summary-in" && i + 1 < argc) {
            summary_in_path_ = argv[++i];
        } else if (arg == "--summary-out" && i + 1 < argc) {
            summary_out_path_ = argv[++i];
        } else if (arg == "--model-file" && i + 1 < argc) {
            model_files_.push_back(argv[++i]);
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
                      << "  --allocator-pairs <pairs> Exact custom allocation families\n"
                      << "                         (allocator=deallocator, comma list;\n"
                      << "                         malformed values are rejected)\n"
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
                      << "  --accept-partial-coverage  Legacy acknowledgement flag; partial\n"
                      << "                         TU coverage still has no verdict (exit 2)\n"
                      << "  --tu-timeout-seconds <N> Per-translation-unit wall timeout\n"
                      << "                         (default: 300; range: 1-86400)\n"
                      << "  --tu-memory-mib <N>   Per-translation-unit memory ceiling in MiB\n"
                      << "                         (default: 4096; range: 1-131072)\n"
                      << "  --summary-out <file>   Save harvested cross-file function\n"
                      << "                         summaries to a file after analysis\n"
                      << "  --summary-in <file>    Load function summaries saved earlier;\n"
                      << "                         analyze single files with whole-project\n"
                      << "                         knowledge (incremental whole-program)\n"
                      << "  --model-file <file>    Load an opt-in library model using the\n"
                      << "                         strict summary schema (repeatable;\n"
                      << "                         malformed or missing files exit 2)\n"
                      << "  --summary-diff <old> <new>  Report contract changes between two\n"
                      << "                         summary files instead of analyzing;\n"
                      << "                         exits 1 if any contract weakened\n"
                      << "  --files <list>         Analyze files listed (one path per line)\n"
                      << "  --lang <en|tr>         Diagnostic message language (default: en)\n"
                      << "  --capabilities [--json] Print the tiered product scope and exit\n"
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

bool Config::setTuTimeoutSeconds(std::uint64_t value) {
    if (value == 0 || value > kMaxTuTimeoutSeconds) return false;
    tu_timeout_seconds_ = static_cast<unsigned>(value);
    return true;
}

bool Config::setTuMemoryMiB(std::uint64_t value) {
    if (value == 0 || value > kMaxTuMemoryMiB) return false;
    tu_memory_mib_ = static_cast<unsigned>(value);
    return true;
}

std::vector<std::string> Config::workerArguments(
    const std::vector<std::string>& available_rule_ids,
    const std::string& summary_override,
    bool replace_configured_summaries) const {
    std::vector<std::string> args;
    auto add = [&args](const std::string& option, const std::string& value) {
        args.push_back(option);
        args.push_back(value);
    };
    auto join = [](const auto& values) {
        std::string joined;
        for (const auto& value : values) {
            if (!joined.empty()) joined += ',';
            joined += value;
        }
        return joined;
    };

    add("--lang", lang_);
    switch (min_severity_) {
        case Severity::Info: add("--severity", "info"); break;
        case Severity::Warning: add("--severity", "warning"); break;
        case Severity::Error: add("--severity", "error"); break;
    }
    if (!functions_.empty()) add("--function", join(functions_));
    if (!lines_.empty()) {
        std::vector<std::string> ranges;
        ranges.reserve(lines_.size());
        for (const auto& [first, last] : lines_) {
            ranges.push_back(first == last
                                 ? std::to_string(first)
                                 : std::to_string(first) + "-" +
                                       std::to_string(last));
        }
        add("--lines", join(ranges));
    }
    if (!fatal_asserts_.empty()) add("--fatal-asserts", join(fatal_asserts_));
    if (!assert_macros_.empty()) add("--assert-macros", join(assert_macros_));
    if (!negative_assert_macros_.empty())
        add("--negative-assert-macros", join(negative_assert_macros_));
    if (!assert_recovery_) args.push_back("--no-assert-recovery");
    if (!alloc_functions_.empty())
        add("--alloc-functions", join(alloc_functions_));
    if (!free_functions_.empty())
        add("--free-functions", join(free_functions_));
    if (!allocator_pairs_.empty()) {
        std::vector<std::string> pairs;
        for (const auto& [allocator, deallocators] : allocator_pairs_)
            for (const auto& deallocator : deallocators)
                pairs.push_back(allocator + "=" + deallocator);
        add("--allocator-pairs", join(pairs));
    }
    if (!untrusted_int_sources_.empty())
        add("--untrusted-int-sources", join(untrusted_int_sources_));
    if (!owning_pointers_.empty())
        add("--owning-pointers", join(owning_pointers_));
    if (!report_paths_.empty()) add("--report-paths", join(report_paths_));
    if (!policies_.empty()) add("--policy", join(policies_));
    if (analyze_broken_tus_) args.push_back("--analyze-broken-tus");
    if (accept_partial_coverage_) args.push_back("--accept-partial-coverage");
    if (assumptions_) args.push_back("--assumptions");

    for (const auto& rule_id : available_rule_ids) {
        if (!isRuleEnabled(rule_id)) add("--disable-rule", rule_id);
    }

    if (replace_configured_summaries) {
        if (!summary_override.empty()) add("--summary-in", summary_override);
    } else {
        if (!summary_in_path_.empty()) add("--summary-in", summary_in_path_);
        for (const auto& model : model_files_) add("--model-file", model);
    }
    return args;
}

bool Config::isRuleEnabled(const std::string& rule_id) const {
    if (disabled_rules_.count(rule_id)) return false;
    if (enabled_rules_.empty()) return true;
    return enabled_rules_.count(rule_id) > 0;
}

bool Config::addFunctions(const std::string& list) {
    auto parsed = functions_;
    bool found = false;
    std::string token;
    for (size_t i = 0; i <= list.size(); ++i) {
        char c = (i < list.size()) ? list[i] : ',';
        if (c == ',') {
            if (!token.empty()) {
                parsed.insert(token);
                found = true;
            }
            token.clear();
        } else if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
            token += c;
        }
    }
    if (!found) return false;
    functions_ = std::move(parsed);
    return true;
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

bool Config::addAllocatorPairs(const std::string& list) {
    auto parsed = allocator_pairs_;
    std::size_t begin = 0;
    while (begin <= list.size()) {
        const std::size_t comma = list.find(',', begin);
        const std::string entry = trim(list.substr(
            begin, comma == std::string::npos ? std::string::npos
                                               : comma - begin));
        const std::size_t separator = entry.find('=');
        if (entry.empty() || separator == std::string::npos ||
            entry.find('=', separator + 1) != std::string::npos) {
            return false;
        }
        const std::string allocator = trim(entry.substr(0, separator));
        const std::string deallocator = trim(entry.substr(separator + 1));
        if (allocator.empty() || deallocator.empty()) return false;
        parsed[allocator].insert(deallocator);
        if (comma == std::string::npos) break;
        begin = comma + 1;
    }
    allocator_pairs_ = std::move(parsed);
    return true;
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
    auto parsed = lines_;
    std::string token;
    bool ok = true;
    auto flush = [&parsed, &ok](const std::string& t) {
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
        parsed.emplace_back(from, to);
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
    if (!ok) return false;
    lines_ = std::move(parsed);
    return true;
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
