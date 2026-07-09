#ifndef ZERODEFECT_CONFIG_H
#define ZERODEFECT_CONFIG_H

#include "core/Diagnostic.h"

#include <set>
#include <string>

namespace zerodefect {

class Config {
public:
    Config();

    bool loadFromFile(const std::string& path);
    bool parseArgs(int argc, char* argv[]);

    const std::string& sourcePath() const { return source_path_; }
    const std::string& buildPath() const { return build_path_; }
    const std::string& outputFormat() const { return output_format_; }
    const std::string& jsonOutputPath() const { return json_output_path_; }
    const std::string& sarifOutputPath() const { return sarif_output_path_; }
    const std::string& lang() const { return lang_; }
    Severity minSeverity() const { return min_severity_; }
    bool isRuleEnabled(const std::string& rule_id) const;

    void setSourcePath(const std::string& path) { source_path_ = path; }
    void setBuildPath(const std::string& path) { build_path_ = path; }
    void setOutputFormat(const std::string& format) { output_format_ = format; }
    void setMinSeverity(Severity severity) { min_severity_ = severity; }

private:
    Severity parseSeverity(const std::string& str) const;

    std::string source_path_;
    std::string build_path_;
    std::string output_format_;
    std::string json_output_path_;
    std::string sarif_output_path_;
    std::string lang_;
    Severity min_severity_;
    std::set<std::string> enabled_rules_;
    std::set<std::string> disabled_rules_;
};

} // namespace zerodefect

#endif // ZERODEFECT_CONFIG_H
