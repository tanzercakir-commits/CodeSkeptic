#ifndef ZERODEFECT_CONFIG_H
#define ZERODEFECT_CONFIG_H

#include "core/Diagnostic.h"

#include <set>
#include <string>
#include <utility>
#include <vector>

namespace zerodefect {

class Config {
public:
    Config();

    bool loadFromFile(const std::string& path);
    bool parseArgs(int argc, char* argv[]);

    const std::string& sourcePath() const { return source_path_; }
    const std::vector<std::string>& sourceFiles() const {
        return source_files_;
    }
    const std::string& buildPath() const { return build_path_; }
    const std::string& outputFormat() const { return output_format_; }
    const std::string& jsonOutputPath() const { return json_output_path_; }
    const std::string& sarifOutputPath() const { return sarif_output_path_; }
    const std::string& htmlOutputPath() const { return html_output_path_; }
    const std::string& baselinePath() const { return baseline_path_; }
    const std::string& writeBaselinePath() const { return write_baseline_path_; }
    const std::string& lang() const { return lang_; }
    const std::set<std::string>& functions() const { return functions_; }
    const std::vector<std::pair<unsigned, unsigned>>& lines() const {
        return lines_;
    }
    Severity minSeverity() const { return min_severity_; }
    bool isRuleEnabled(const std::string& rule_id) const;

    void setSourcePath(const std::string& path) { source_path_ = path; }
    void setBuildPath(const std::string& path) { build_path_ = path; }
    void setOutputFormat(const std::string& format) { output_format_ = format; }
    void setMinSeverity(Severity severity) { min_severity_ = severity; }
    bool serve() const { return serve_; }
    bool wholeProgram() const { return whole_program_; }

    // Summary persistence (Cross-TU v2): --summary-out writes the
    // harvested store to disk; --summary-in loads it into the store
    // before analysis. Together they give incremental whole-program:
    // harvest the whole project once, then analyze the changed file on
    // its own but with project knowledge.
    const std::string& summaryIn() const { return summary_in_path_; }
    const std::string& summaryOut() const { return summary_out_path_; }
    // --summary-diff <old> <new>: contract-diff report instead of analysis
    const std::string& summaryDiffOld() const { return summary_diff_old_; }
    const std::string& summaryDiffNew() const { return summary_diff_new_; }
    void setSummaryIn(const std::string& path) { summary_in_path_ = path; }
    void setSummaryOut(const std::string& path) { summary_out_path_ = path; }

    // Warm AST cache: a programmatic switch for long-lived processes
    // (MCP server). Not enabled in the CLI — keeping all ASTs alive for
    // the process lifetime during a large directory scan is wrong
    // memory-wise.
    void setWarmCache(bool enabled) { warm_cache_ = enabled; }
    bool warmCache() const { return warm_cache_; }

    // Programmatic scope settings (the MCP server uses these directly)
    void addFunctions(const std::string& list);
    void addLines(const std::string& list);

private:
    Severity parseSeverity(const std::string& str) const;

    std::string source_path_;
    std::vector<std::string> source_files_;
    std::string build_path_;
    std::string output_format_;
    std::string json_output_path_;
    std::string sarif_output_path_;
    std::string html_output_path_;
    std::string baseline_path_;
    std::string write_baseline_path_;
    std::string lang_;
    std::set<std::string> functions_;
    std::vector<std::pair<unsigned, unsigned>> lines_;
    bool serve_ = false;
    bool whole_program_ = false;
    bool warm_cache_ = false;
    std::string summary_in_path_;
    std::string summary_out_path_;
    std::string summary_diff_old_;
    std::string summary_diff_new_;
    Severity min_severity_;
    std::set<std::string> enabled_rules_;
    std::set<std::string> disabled_rules_;
};

} // namespace zerodefect

#endif // ZERODEFECT_CONFIG_H
