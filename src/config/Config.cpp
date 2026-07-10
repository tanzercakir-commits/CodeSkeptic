#include "config/Config.h"

#include <fstream>
#include <iostream>

namespace zerodefect {

Config::Config()
    : build_path_(".")
    , output_format_("console")
    , lang_("en")
    , min_severity_(Severity::Info) {}

bool Config::loadFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;

        auto pos = line.find('=');
        if (pos == std::string::npos) continue;

        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);

        if (key == "source_path")        source_path_ = value;
        else if (key == "build_path")    build_path_ = value;
        else if (key == "output_format") output_format_ = value;
        else if (key == "json_output")   json_output_path_ = value;
        else if (key == "sarif_output") {
            output_format_ = "sarif";
            sarif_output_path_ = value;
        }
        else if (key == "html_output") {
            output_format_ = "html";
            html_output_path_ = value;
        }
        else if (key == "min_severity")  min_severity_ = parseSeverity(value);
        else if (key == "lang")          lang_ = value;
        else if (key == "baseline")      baseline_path_ = value;
        else if (key == "function")      addFunctions(value);
        else if (key == "enable_rule")   enabled_rules_.insert(value);
        else if (key == "disable_rule")  disabled_rules_.insert(value);
    }

    return true;
}

bool Config::parseArgs(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

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
            min_severity_ = parseSeverity(argv[++i]);
        } else if (arg == "--disable-rule" && i + 1 < argc) {
            disabled_rules_.insert(argv[++i]);
        } else if (arg == "--lang" && i + 1 < argc) {
            lang_ = argv[++i];
        } else if (arg == "--baseline" && i + 1 < argc) {
            baseline_path_ = argv[++i];
        } else if (arg == "--function" && i + 1 < argc) {
            addFunctions(argv[++i]);
        } else if (arg == "--lines" && i + 1 < argc) {
            addLines(argv[++i]);
        } else if (arg == "--serve") {
            serve_ = true;
        } else if (arg == "--whole-program") {
            whole_program_ = true;
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
            std::ifstream listFile(argv[++i]);
            std::string fileLine;
            while (std::getline(listFile, fileLine)) {
                if (!fileLine.empty()) source_files_.push_back(fileLine);
            }
        } else if (arg == "--write-baseline" && i + 1 < argc) {
            write_baseline_path_ = argv[++i];
        } else if (arg == "--help") {
            std::cerr << "Usage: zerodefect [options] [source_path]\n"
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
                      << "  --serve                Run as an MCP server (JSON-RPC on stdio)\n"
                      << "  --whole-program        Two-pass mode: collect function summaries\n"
                      << "                         across all files first, then analyze\n"
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
            return false;
        } else if (arg[0] != '-' && source_path_.empty()) {
            source_path_ = arg;
        }
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

void Config::addLines(const std::string& list) {
    // "12-40,55" -> {12,40}, {55,55}. Invalid tokens are silently skipped.
    std::string token;
    auto flush = [this](const std::string& t) {
        if (t.empty()) return;
        auto dash = t.find('-');
        unsigned from = 0, to = 0;
        try {
            if (dash == std::string::npos) {
                from = to = static_cast<unsigned>(std::stoul(t));
            } else {
                from = static_cast<unsigned>(std::stoul(t.substr(0, dash)));
                to = static_cast<unsigned>(std::stoul(t.substr(dash + 1)));
            }
        } catch (...) {
            return;
        }
        if (from == 0 || to < from) return;
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
}

Severity Config::parseSeverity(const std::string& str) const {
    if (str == "warning") return Severity::Warning;
    if (str == "error")   return Severity::Error;
    return Severity::Info;
}

} // namespace zerodefect
