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
        else if (key == "min_severity")  min_severity_ = parseSeverity(value);
        else if (key == "lang")          lang_ = value;
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
        } else if (arg == "--severity" && i + 1 < argc) {
            min_severity_ = parseSeverity(argv[++i]);
        } else if (arg == "--disable-rule" && i + 1 < argc) {
            disabled_rules_.insert(argv[++i]);
        } else if (arg == "--lang" && i + 1 < argc) {
            lang_ = argv[++i];
        } else if (arg == "--help") {
            std::cerr << "Usage: zerodefect [options] [source_path]\n"
                      << "\n"
                      << "Options:\n"
                      << "  --source <path>        Directory/file to analyze\n"
                      << "  --build-path <path>    compile_commands.json directory\n"
                      << "  --json <file>          JSON output file\n"
                      << "  --sarif <file>         SARIF 2.1.0 output file\n"
                      << "  --severity <level>     Minimum severity (info/warning/error)\n"
                      << "  --disable-rule <id>    Disable a rule\n"
                      << "  --lang <en|tr>         Diagnostic message language (default: en)\n"
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

Severity Config::parseSeverity(const std::string& str) const {
    if (str == "warning") return Severity::Warning;
    if (str == "error")   return Severity::Error;
    return Severity::Info;
}

} // namespace zerodefect
