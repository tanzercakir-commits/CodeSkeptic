#include "config/Config.h"

#include "core/Messages.h"
#include "core/Capabilities.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <set>
#include <stdexcept>
#include <algorithm>
#include <charconv>
#include <sstream>
#include <llvm/Support/SHA256.h>
#include <llvm/ADT/StringRef.h>

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

bool parseResourceNumber(const std::string& value, unsigned minimum, unsigned maximum,
                         unsigned& result) {
    unsigned parsed = 0;
    if (value.empty() || value.find_first_not_of("0123456789") != std::string::npos) return false;
    const auto converted = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (converted.ec != std::errc{} || converted.ptr != value.data() + value.size() ||
        parsed < minimum || parsed > maximum) return false;
    result = parsed;
    return true;
}

bool cacheDirectory(const std::string& value) {
    if (value.empty() || value.size() > 4096 || value.find('\0') != std::string::npos) return false;
    const std::filesystem::path path(value);
    if (!path.is_absolute() || path == path.root_path()) return false;
    for (const auto& component : path.relative_path())
        if (component.empty() || component == "." || component == "..") return false;
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
        "--files", "--worker-timeout-ms", "--worker-memory-mb",
        "--write-baseline", "--analysis-cache-dir", "--analysis-cache-bytes", "--analysis-cache-entries",
        "--checkpoint-dir", "--checkpoint-bytes", "--checkpoint-units"
    };
    return options;
}

bool looksLikeOption(const char* value) {
    return value && value[0] == '-' && value[1] == '-';
}

std::string consumedDigest(llvm::SHA256& hash) {
    const auto digest = hash.final();
    std::string encoded;
    const char* hex = "0123456789abcdef";
    for (const auto byte : digest) { encoded += hex[byte >> 4]; encoded += hex[byte & 15]; }
    return encoded;
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

bool Config::loadFromFile(const std::string& path, InputError* error) {
    Config staged = *this;
    InputError failure{"invalid_value", "config", "Invalid configuration input"};
    if (!staged.loadFromFileInPlace(path, &failure)) {
        if (failure.reason.empty())
            failure = {"invalid_value", "config", "Invalid configuration input"};
        if (error) *error = failure;
        reportInputError(failure);
        return false;
    }
    *this = std::move(staged);
    if (error) *error = {};
    return true;
}

bool Config::loadFromFileInPlace(const std::string& path, InputError* error) {
    if (path.find('\0') != std::string::npos)
        return rejectInput(error, "invalid_path", "config", "Path contains NUL");
    const auto input_path = std::filesystem::absolute(path).lexically_normal().string();
    std::ifstream file(path, std::ios::binary);
    // The default project config is optional. Once the file exists, every
    // non-comment line is a contract and is validated strictly.
    if (!file.is_open()) {
        std::error_code ec;
        const bool exists = std::filesystem::exists(path, ec);
        if (exists || ec) {
            std::cerr << "[CodeSkeptic] cannot read config: " << path << "\n";
            return rejectInput(error, "read_error", "config", "Cannot read configuration file");
        }
        configuration_inputs_[input_path] = "absent";
        return true;
    }

    llvm::SHA256 consumed;
    std::string line;
    std::size_t lineNumber = 0;
    bool ok = true;
    std::string selectedOutput;
    while (std::getline(file, line)) {
        consumed.update(line);
        if (!file.eof()) consumed.update("\n");
        ++lineNumber;
        if (line.find('\0') != std::string::npos)
            return rejectInput(error, "invalid_value", "config", "Configuration contains NUL");
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

        std::string output;
        if (key == "output_format") output = value;
        else if (key == "json_output") output = "json";
        else if (key == "sarif_output") output = "sarif";
        else if (key == "html_output") output = "html";
        if (!output.empty()) {
            if (!selectedOutput.empty() && selectedOutput != output)
                return rejectInput(error, "conflict", "output", "Conflicting output selectors");
            selectedOutput = output;
        }

        if (key == "source_path")        source_path_ = value;
        else if (key == "build_path")    setBuildPath(value);
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
        else if (key == "function") { if (!addFunctions(value, error)) return false; }
        else if (key == "fatal_asserts") { if (!addFatalAsserts(value, error)) return false; }
        else if (key == "assert_macros") { if (!addAssertMacros(value, error)) return false; }
        else if (key == "negative_assert_macros") { if (!addNegativeAssertMacros(value, error)) return false; }
        else if (key == "assert_recovery") {
            if (!parseBool(value, assert_recovery_)) {
                configError(path, lineNumber,
                            "assert_recovery expects true/false/1/0");
                ok = false;
            }
        }
        else if (key == "alloc_functions") { if (!addAllocFunctions(value, error)) return false; }
        else if (key == "free_functions") { if (!addFreeFunctions(value, error)) return false; }
        else if (key == "allocator_pairs") {
            if (!addAllocatorPairs(value, error)) {
                configError(path, lineNumber,
                            "allocator_pairs expects allocator=deallocator"
                            " entries separated by commas");
                return false;
            }
        }
        else if (key == "owning_pointers") { if (!addOwningPointers(value, error)) return false; }
        else if (key == "untrusted_int_sources") { if (!addNamesTo(untrusted_int_sources_, value, "untrusted_int_sources", error)) return false; }
        else if (key == "report_paths") { if (!addReportPaths(value, error)) return false; }
        else if (key == "policy") { if (!addNamesTo(policies_, value, "policy", error)) return false; }
        else if (key == "model_file") {
            if (value.empty()) {
                configError(path, lineNumber,
                            "model_file expects a non-empty path");
                ok = false;
            } else {
                model_files_.push_back(value);
            }
        }
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
        else if (key == "checkpoint_dir") {
            if (!cacheDirectory(value))
                return rejectInput(error, "invalid_path", key, "Checkpoint directory requires an absolute non-root path without dot components");
            checkpoint_directory_ = value;
        }
        else if (key == "checkpoint_bytes" || key == "checkpoint_units") {
            const bool bytes = key == "checkpoint_bytes";
            auto& target = bytes ? checkpoint_bytes_ : checkpoint_units_;
            if (!parseResourceNumber(value, 1, bytes ? 1073741824 : 4096, target))
                return rejectInput(error, "invalid_value", key, "Checkpoint limit is outside its integer range");
        }
        else if (key == "analysis_cache") {
            if (!parseBool(value, analysis_cache_))
                return rejectInput(error, "invalid_value", key, "analysis_cache expects true/false/1/0");
        }
        else if (key == "analysis_cache_dir") {
            if (!cacheDirectory(value))
                return rejectInput(error, "invalid_path", key, "Cache directory requires an absolute non-root path without dot components");
            analysis_cache_directory_ = value;
        }
        else if (key == "analysis_cache_bytes" || key == "analysis_cache_entries") {
            const bool bytes = key == "analysis_cache_bytes";
            auto& target = bytes ? analysis_cache_bytes_ : analysis_cache_entries_;
            if (!parseResourceNumber(value, 1, bytes ? 1073741824 : 4096, target))
                return rejectInput(error, "invalid_value", key, "Cache storage limit is outside its integer range");
        }
        else if (key == "worker_timeout_ms" || key == "worker_memory_mb") {
            const bool timeout = key == "worker_timeout_ms";
            unsigned& target = timeout ? worker_limits_.timeout_ms : worker_limits_.memory_mb;
            if (!parseResourceNumber(value, timeout ? 1 : 16, timeout ? 3600000 : 65536, target))
                return rejectInput(error, "invalid_value", key, "Worker resource limit is outside its integer range");
        }
        else if (key == "enable_rule") { if (!addEnabledRules(value, error)) return false; }
        else if (key == "disable_rule") { if (!addDisabledRules(value, error)) return false; }
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
    if (ok) {
        configuration_inputs_[input_path] = consumedDigest(consumed);
    }
    return ok;
}

bool Config::parseArgs(int argc, char* argv[], InputError* error) {
    Config staged = *this;
    InputError failure{"invalid_value", "arguments", "Invalid command line input"};
    if (!staged.parseArgsInPlace(argc, argv, &failure)) {
        if (failure.reason.empty())
            failure = {"invalid_value", "arguments", "Invalid command line input"};
        if (error) *error = failure;
        reportInputError(failure);
        return false;
    }
    *this = std::move(staged);
    if (error) *error = {};
    return true;
}

bool Config::parseArgsInPlace(int argc, char* argv[], InputError* error) {
    if (argc < 1 || !argv)
        return rejectInput(error, "invalid_value", "arguments", "Missing argument vector");
    for (int i = 0; i < argc; ++i)
        if (!argv[i])
            return rejectInput(error, "invalid_value", "arguments", "Null argument");
    std::string selectedOutput;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.empty())
            return rejectInput(error, "invalid_value", "arguments", "Empty argument");

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

        if (arg == "--json" || arg == "--sarif" || arg == "--html") {
            if (!selectedOutput.empty() && selectedOutput != arg)
                return rejectInput(error, "conflict", "output", "Conflicting output selectors");
            selectedOutput = arg;
        }

        if (arg == "--source" && i + 1 < argc) {
            source_path_ = argv[++i];
        } else if (arg == "--build-path" && i + 1 < argc) {
            setBuildPath(argv[++i]);
        } else if (arg == "--doctor") {
            doctor_ = true;
        } else if (arg == "--checkpoint-dir") {
            const std::string value(argv[++i]);
            if (!cacheDirectory(value))
                return rejectInput(error, "invalid_path", arg, "Checkpoint directory requires an absolute non-root path without dot components");
            checkpoint_directory_ = value;
        } else if (arg == "--checkpoint-bytes" || arg == "--checkpoint-units") {
            const bool bytes = arg == "--checkpoint-bytes";
            auto& target = bytes ? checkpoint_bytes_ : checkpoint_units_;
            if (!parseResourceNumber(argv[++i], 1, bytes ? 1073741824 : 4096, target))
                return rejectInput(error, "invalid_value", arg, "Checkpoint limit is outside its integer range");
        } else if (arg == "--resume") {
            resume_checkpoint_ = true;
        } else if (arg == "--analysis-cache") {
            analysis_cache_ = true;
        } else if (arg == "--no-analysis-cache") {
            analysis_cache_ = false;
        } else if (arg == "--analysis-cache-dir") {
            const std::string value(argv[++i]);
            if (!cacheDirectory(value))
                return rejectInput(error, "invalid_path", arg, "Cache directory requires an absolute non-root path without dot components");
            analysis_cache_directory_ = value;
        } else if (arg == "--analysis-cache-bytes" || arg == "--analysis-cache-entries") {
            const bool bytes = arg == "--analysis-cache-bytes";
            auto& target = bytes ? analysis_cache_bytes_ : analysis_cache_entries_;
            if (!parseResourceNumber(argv[++i], 1, bytes ? 1073741824 : 4096, target))
                return rejectInput(error, "invalid_value", arg, "Cache storage limit is outside its integer range");
        } else if (arg == "--worker-timeout-ms" || arg == "--worker-memory-mb") {
            const bool timeout = arg == "--worker-timeout-ms";
            unsigned& target = timeout ? worker_limits_.timeout_ms : worker_limits_.memory_mb;
            if (!parseResourceNumber(argv[++i], timeout ? 1 : 16, timeout ? 3600000 : 65536, target))
                return rejectInput(error, "invalid_value", arg, "Worker resource limit is outside its integer range");
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
            if (!addDisabledRules(argv[++i], error)) return false;
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
            if (!addFunctions(argv[++i], error)) return false;
        } else if (arg == "--fatal-asserts" && i + 1 < argc) {
            if (!addFatalAsserts(argv[++i], error)) return false;
        } else if (arg == "--assert-macros" && i + 1 < argc) {
            if (!addAssertMacros(argv[++i], error)) return false;
        } else if (arg == "--negative-assert-macros" && i + 1 < argc) {
            if (!addNegativeAssertMacros(argv[++i], error)) return false;
        } else if (arg == "--no-assert-recovery") {
            assert_recovery_ = false;
        } else if (arg == "--alloc-functions" && i + 1 < argc) {
            if (!addAllocFunctions(argv[++i], error)) return false;
        } else if (arg == "--free-functions" && i + 1 < argc) {
            if (!addFreeFunctions(argv[++i], error)) return false;
        } else if (arg == "--allocator-pairs" && i + 1 < argc) {
            if (!addAllocatorPairs(argv[++i], error)) {
                std::cerr << "[CodeSkeptic] --allocator-pairs expects "
                             "allocator=deallocator entries separated by "
                             "commas\n";
                return false;
            }
        } else if (arg == "--untrusted-int-sources" && i + 1 < argc) {
            if (!addNamesTo(untrusted_int_sources_, argv[++i], "untrusted_int_sources", error)) return false;
        } else if (arg == "--owning-pointers" && i + 1 < argc) {
            if (!addOwningPointers(argv[++i], error)) return false;
        } else if (arg == "--report-paths" && i + 1 < argc) {
            if (!addReportPaths(argv[++i], error)) return false;
        } else if (arg == "--policy" && i + 1 < argc) {
            if (!addNamesTo(policies_, argv[++i], "policy", error)) return false;
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
            if (!addLines(value, error)) {
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
        } else if (arg == "--model-file" && i + 1 < argc) {
            model_files_.push_back(argv[++i]);
        } else if (arg == "--summary-diff" && i + 2 < argc) {
            summary_diff_old_ = argv[++i];
            summary_diff_new_ = argv[++i];
        } else if (arg == "--files" && i + 1 < argc) {
            file_list_specified_ = true;
            // List file: one source file path per line.
            // For large/hand-picked sets (benchmarks, agent batch requests).
            const char* listPath = argv[++i];
            std::ifstream listFile(listPath, std::ios::binary);
            // A missing LIST file must say so — silently leaving the
            // set empty surfaced as the generic "no source path"
            // usage message and cost a 20-minute scan-diff hunt
            // (2026-07-12).
            if (!listFile) {
                std::cerr << "[CodeSkeptic] --files list not found: "
                          << listPath << "\n";
                return false;
            }
            llvm::SHA256 consumed;
            std::string fileLine;
            while (std::getline(listFile, fileLine)) {
                consumed.update(fileLine);
                if (!listFile.eof()) consumed.update("\n");
                if (!fileLine.empty() && fileLine.back() == '\r') fileLine.pop_back();
                if (fileLine.find('\0') != std::string::npos)
                    return rejectInput(error, "invalid_path", "files", "File list contains NUL");
                if (!fileLine.empty()) source_files_.push_back(fileLine);
            }
            if (listFile.bad())
                return rejectInput(error, "read_error", "files", "Cannot read source file list");
            configuration_inputs_[std::filesystem::absolute(listPath).lexically_normal().string()] = consumedDigest(consumed);
        } else if (arg == "--write-baseline" && i + 1 < argc) {
            write_baseline_path_ = argv[++i];
        } else if (arg == "--help") {
            std::cout << "Usage: codeskeptic [options] [source_path]\n"
                      << "\n"
                      << "Options:\n"
                      << "  --source <path>        Directory/file to analyze\n"
                      << "  --build-path <path>    compile_commands.json directory\n"
                      << "  --doctor              Explain compilation-database selection;\n"
                      << "                         does not build or run analysis\n"
                      << "  --checkpoint-dir <path> Explicit private directory for one resumable CLI run\n"
                      << "  --resume              Resume that checkpoint; changed inputs are rejected\n"
                      << "  --checkpoint-bytes <N> Byte ceiling including old+temporary manifest, 1..1073741824\n"
                      << "  --checkpoint-units <N> Maximum source units, 1..4096 (default 128)\n"
                      << "  --analysis-cache       Opt in to bounded process-local worker reuse\n"
                      << "  --no-analysis-cache    Disable worker reuse (default)\n"
                      << "  --analysis-cache-dir <path> Explicit absolute private disk directory\n"
                      << "  --analysis-cache-bytes <N> Disk byte cap including temp files, 1..1073741824\n"
                      << "                         (default 268435456; requires cache enablement and directory)\n"
                      << "  --analysis-cache-entries <N> Disk entry cap including temp files, 1..4096 (default 128)\n"
                      << "  --worker-timeout-ms <N> Per-worker deadline, 1..3600000 ms\n"
                      << "                         (default 120000); includes startup\n"
                      << "  --worker-memory-mb <N> Per-worker native memory cap, 16..65536\n"
                      << "                         MiB (default 2048); see usage for platform semantics\n"
                      << "  --json <file>          JSON output file\n"
                      << "  --sarif <file>         SARIF 2.1.0 output file\n"
                      << "  --html <file>          Self-contained HTML report (filters,\n"
                      << "                         dataflow traces with source context)\n"
                      << "  --severity <level>     Minimum severity (info/warning/error)\n"
                      << "  --disable-rule <ids>   Disable diagnostic families (comma list; repeatable)\n"
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
                      << "  --accept-partial-coverage  Allow a verdict over successfully\n"
                      << "                         analyzed TUs while still reporting skips\n"
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

    if (resume_checkpoint_ && checkpoint_directory_.empty())
        return rejectInput(error, "missing_value", "--resume", "Resume requires --checkpoint-dir");
    if (!checkpoint_directory_.empty() &&
        (serve_ || doctor_ || !summary_diff_old_.empty() || analysis_cache_))
        return rejectInput(error, "conflict", "--checkpoint-dir", "Checkpoint is a CLI analysis mode and cannot combine with server, doctor, summary-diff or analysis-cache");
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

std::string Config::checkpointSettings() const {
    std::ostringstream out;
    auto text = [&](const std::string& value) { out << value.size() << ':' << value; };
    auto number = [&](auto value) { text(std::to_string(value)); };
    auto strings = [&](const auto& values) {
        number(values.size());
        for (const auto& value : values) text(value);
    };
    text("codeskeptic-checkpoint-settings/v1");
    text(source_path_); strings(source_files_); text(build_path_);
    number(build_path_specified_); number(file_list_specified_);
    text(output_format_); text(json_output_path_); text(sarif_output_path_); text(html_output_path_);
    text(baseline_path_); text(write_baseline_path_); text(lang_);
    number(static_cast<unsigned>(min_severity_)); strings(enabled_rules_); strings(disabled_rules_);
    strings(functions_); number(lines_.size());
    for (const auto& range : lines_) { number(range.first); number(range.second); }
    strings(fatal_asserts_); strings(assert_macros_); strings(negative_assert_macros_);
    strings(alloc_functions_); strings(free_functions_); strings(owning_pointers_);
    strings(untrusted_int_sources_); number(allocator_pairs_.size());
    for (const auto& pair : allocator_pairs_) { text(pair.first); strings(pair.second); }
    strings(report_paths_); strings(policies_); text(summary_diff_gate_);
    number(whole_program_); number(analyze_broken_tus_); number(accept_partial_coverage_);
    number(assert_recovery_); number(assumptions_); number(warm_cache_);
    number(worker_limits_.timeout_ms); number(worker_limits_.memory_mb);
    text(summary_in_path_); text(summary_out_path_); strings(model_files_);
    number(analysis_cache_); text(analysis_cache_directory_);
    number(analysis_cache_bytes_); number(analysis_cache_entries_);
    text(checkpoint_directory_); number(checkpoint_bytes_); number(checkpoint_units_);
    number(configuration_inputs_.size());
    for (const auto& entry : configuration_inputs_) { text(entry.first); text(entry.second); }
    return out.str();
}

bool Config::isRuleEnabled(const std::string& rule_id) const {
    const auto* capability = findRuleCapability(rule_id);
    // A new/unclassified diagnostic cannot disappear and manufacture clean.
    if (!capability) return true;
    const std::string family(capability->id);
    if (disabled_rules_.count(family)) return false;
    if (enabled_rules_.empty()) return true;
    return enabled_rules_.count(family) > 0;
}

bool Config::addRuleIds(std::set<std::string>& target, const std::string& list,
                        const char* field, InputError* error) {
    std::set<std::string> names;
    if (!addNamesTo(names, list, field, error)) return false;
    auto staged = target;
    for (const auto& name : names) {
        const auto* capability = findRuleCapability(name);
        if (!capability)
            return rejectInput(error, "unknown_rule", field, "Unknown diagnostic family");
        // The two internal contract aliases select their public family; they
        // are not independently advertised or independently enabled rules.
        staged.insert(std::string(capability->id));
    }
    target = std::move(staged);
    if (error) *error = {};
    return true;
}

bool Config::addDisabledRules(const std::string& list, InputError* error) {
    return addRuleIds(disabled_rules_, list, "disable_rules", error);
}

bool Config::addEnabledRules(const std::string& list, InputError* error) {
    return addRuleIds(enabled_rules_, list, "enable_rules", error);
}

bool Config::addFunctions(const std::string& list, InputError* error) {
    return addNamesTo(functions_, list, "functions", error);
}

bool Config::addFatalAsserts(const std::string& list, InputError* error) {
    return addNamesTo(fatal_asserts_, list, "fatal_asserts", error);
}

bool Config::addNegativeAssertMacros(const std::string& list, InputError* error) {
    return addNamesTo(negative_assert_macros_, list, "negative_assert_macros", error);
}

bool Config::addAssertMacros(const std::string& list, InputError* error) {
    return addNamesTo(assert_macros_, list, "assert_macros", error);
}

bool Config::addAllocFunctions(const std::string& list, InputError* error) {
    return addNamesTo(alloc_functions_, list, "alloc_functions", error);
}

bool Config::addFreeFunctions(const std::string& list, InputError* error) {
    return addNamesTo(free_functions_, list, "free_functions", error);
}

bool Config::addAllocatorPairs(const std::string& list, InputError* error) {
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
            return rejectInput(error, "invalid_list", "allocator_pairs", "Expected allocator=deallocator entries");
        }
        const std::string allocator = trim(entry.substr(0, separator));
        const std::string deallocator = trim(entry.substr(separator + 1));
        if (allocator.empty() || deallocator.empty() ||
            std::any_of(entry.begin(), entry.end(),
                [](unsigned char ch) { return ch < 32 || ch == 127; }))
            return rejectInput(error, "invalid_list", "allocator_pairs", "Expected allocator=deallocator entries");
        parsed[allocator].insert(deallocator);
        if (comma == std::string::npos) break;
        begin = comma + 1;
    }
    allocator_pairs_ = std::move(parsed);
    if (error) *error = {};
    return true;
}

bool Config::addOwningPointers(const std::string& list, InputError* error) {
    return addNamesTo(owning_pointers_, list, "owning_pointers", error);
}

bool Config::addReportPaths(const std::string& list, InputError* error) {
    // Comma-split with edge-trim only: unlike identifier lists, paths
    // may legally contain interior spaces.
    std::string token;
    auto parsed = report_paths_;
    if (list.find('\0') != std::string::npos)
        return rejectInput(error, "invalid_path", "report_paths", "Path contains NUL");
    auto flush = [&] {
        token = trim(token);
        if (!token.empty()) parsed.push_back(token);
        token.clear();
    };
    for (char c : list) {
        if (c == ',') flush();
        else token += c;
    }
    flush();
    if (parsed.size() == report_paths_.size())
        return rejectInput(error, "invalid_list", "report_paths", "Expected at least one report path");
    report_paths_ = std::move(parsed);
    if (error) *error = {};
    return true;
}

bool Config::addNamesTo(std::set<std::string>& target,
                        const std::string& list, const char* field, InputError* error) {
    auto parsed = target;
    std::string token;
    for (size_t i = 0; i <= list.size(); ++i) {
        char c = (i < list.size()) ? list[i] : ',';
        if (c == ',') {
            token = trim(token);
            if (token.empty() || std::any_of(token.begin(), token.end(),
                    [](unsigned char ch) { return ch < 32 || ch == 127; }))
                return rejectInput(error, "invalid_list", field, "Expected a non-empty comma-separated name list");
            parsed.insert(token);
            token.clear();
        } else {
            token += c;
        }
    }
    target = std::move(parsed);
    if (error) *error = {};
    return true;
}

bool Config::addLines(const std::string& list, InputError* error) {
    // "12-40,55" -> {12,40}, {55,55}. Invalid scope is a caller error:
    // silently dropping it would expand a targeted analysis to all functions.
    std::string token;
    auto parsedLines = lines_;
    bool ok = true;
    bool overflow = false;
    auto number = [&overflow](const std::string& text, unsigned& value) {
        if (text.empty() || !std::all_of(text.begin(), text.end(),
                [](char ch) { return ch >= '0' && ch <= '9'; })) return false;
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
        if (parsed.ec == std::errc::result_out_of_range) overflow = true;
        return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size();
    };
    auto flush = [&parsedLines, &ok, &number](const std::string& raw) {
        const std::string t = trim(raw);
        if (t.empty()) {
            ok = false;
            return;
        }
        auto dash = t.find('-');
        unsigned from = 0, to = 0;
        if (dash == std::string::npos) {
            if (!number(t, from)) { ok = false; return; }
            to = from;
        } else if (!number(trim(t.substr(0, dash)), from) ||
                   !number(trim(t.substr(dash + 1)), to)) {
            ok = false;
            return;
        }
        if (from == 0 || to < from) {
            ok = false;
            return;
        }
        parsedLines.emplace_back(from, to);
    };
    for (size_t i = 0; i <= list.size(); ++i) {
        char c = (i < list.size()) ? list[i] : ',';
        if (c == ',') {
            flush(token);
            token.clear();
        } else {
            token += c;
        }
    }
    if (!ok)
        return rejectInput(error, overflow ? "overflow" : "invalid_range", "lines",
                           "invalid lines scope; expected positive unsigned line numbers or ascending ranges");
    lines_ = std::move(parsedLines);
    if (error) *error = {};
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
