#ifndef CODESKEPTIC_CONFIG_H
#define CODESKEPTIC_CONFIG_H

#include "core/Diagnostic.h"
#include "core/Messages.h"
#include "core/ResourceBudget.h"

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace codeskeptic {

class Config {
public:
    Config();

    bool loadFromFile(const std::string& path, InputError* error = nullptr);
    bool parseArgs(int argc, char* argv[], InputError* error = nullptr);
    bool helpRequested() const { return help_requested_; }

    const std::string& sourcePath() const { return source_path_; }
    const std::vector<std::string>& sourceFiles() const {
        return source_files_;
    }
    const std::string& buildPath() const { return build_path_; }
    bool buildPathSpecified() const { return build_path_specified_; }
    bool fileListSpecified() const { return file_list_specified_; }
    bool doctor() const { return doctor_; }
    const WorkerLimits& workerLimits() const { return worker_limits_; }
    void inheritWorkerLimits(const Config& defaults) { worker_limits_ = defaults.worker_limits_; }
    void setResourceCancellation(std::shared_ptr<ResourceCancellation> cancellation) {
        resource_cancellation_ = std::move(cancellation);
    }
    const ResourceCancellation* resourceCancellation() const { return resource_cancellation_.get(); }
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
    bool addDisabledRules(const std::string& list, InputError* error = nullptr);
    bool addEnabledRules(const std::string& list, InputError* error = nullptr);
    // Only selection defaults are inherited by an MCP request. Source/scope,
    // report paths, model files and other launch settings remain request-local.
    void inheritRuleSelection(const Config& defaults) {
        auto enabled = defaults.enabled_rules_;
        auto disabled = defaults.disabled_rules_;
        enabled_rules_ = std::move(enabled);
        disabled_rules_ = std::move(disabled);
        assumptions_ = defaults.assumptions_; // Explicit family activation only.
    }

    void setSourcePath(const std::string& path) { source_path_ = path; }
    void setBuildPath(const std::string& path) {
        build_path_ = path;
        build_path_specified_ = true;
    }
    void setOutputFormat(const std::string& format) { output_format_ = format; }
    void setMinSeverity(Severity severity) { min_severity_ = severity; }
    bool serve() const { return serve_; }
    bool wholeProgram() const { return whole_program_; }
    // #86: analyze TUs whose parse ended in errors (default: skip them
    // with an honest coverage note — error recovery eats declarations
    // and rules would report confidently about code that isn't there).
    bool analyzeBrokenTUs() const { return analyze_broken_tus_; }
    // Explicit adoption escape hatch: preserve coverage counts/warnings but
    // allow a verdict over the successfully analyzed subset. Default is
    // fail-closed; integrations must opt in deliberately.
    bool acceptPartialCoverage() const { return accept_partial_coverage_; }
    // --assumptions: opt-in intent-debt report of inferred, undeclared
    // preconditions (AssumptionRule). Off by default — it is high-volume
    // by nature and must not perturb the normal finding stream.
    bool assumptions() const { return assumptions_; }

    // Summary persistence (Cross-TU v2): --summary-out writes the
    // harvested store to disk; --summary-in loads it into the store
    // before analysis. Together they give incremental whole-program:
    // harvest the whole project once, then analyze the changed file on
    // its own but with project knowledge.
    const std::string& summaryIn() const { return summary_in_path_; }
    const std::string& summaryOut() const { return summary_out_path_; }
    // Opt-in library models use the same strict summary schema but are
    // declarative inputs, not source harvests. Repeatable paths are loaded
    // in order and merged conservatively without freshness checks.
    const std::vector<std::string>& modelFiles() const {
        return model_files_;
    }
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
    void setAnalysisCache(bool enabled) { analysis_cache_ = enabled; }
    bool analysisCache() const { return analysis_cache_; }
    const std::string& analysisCacheDirectory() const { return analysis_cache_directory_; }
    unsigned analysisCacheBytes() const { return analysis_cache_bytes_; }
    unsigned analysisCacheEntries() const { return analysis_cache_entries_; }
    void inheritAnalysisCache(const Config& defaults) {
        analysis_cache_directory_ = defaults.analysis_cache_directory_;
        analysis_cache_bytes_ = defaults.analysis_cache_bytes_;
        analysis_cache_entries_ = defaults.analysis_cache_entries_;
        analysis_cache_ = defaults.analysis_cache_;
    }

    const std::string& checkpointDirectory() const { return checkpoint_directory_; }
    bool resumeCheckpoint() const { return resume_checkpoint_; }
    unsigned checkpointBytes() const { return checkpoint_bytes_; }
    unsigned checkpointUnits() const { return checkpoint_units_; }
    // Effective invocation identity; excludes only resume/new selection and the
    // cancellation handle. It is not a substitute for consumed file identities.
    std::string checkpointSettings() const;
    const std::map<std::string, std::string>& configurationInputs() const { return configuration_inputs_; }

    // Programmatic scope settings (the MCP server uses these directly)
    bool addFunctions(const std::string& list, InputError* error = nullptr);
    bool addLines(const std::string& list, InputError* error = nullptr);

    // Fatal-assert handlers (--fatal-asserts): user-declared noreturn
    // functions; the engine kills dataflow paths at calls to them.
    bool addFatalAsserts(const std::string& list, InputError* error = nullptr);
    const std::set<std::string>& fatalAsserts() const {
        return fatal_asserts_;
    }

    // Vanished-assert recovery (AR.3). Under NDEBUG an assert's
    // condition never reaches the parser; the engine recovers it from
    // the preprocessor. On by default — --no-assert-recovery turns it
    // off, --assert-macros names macros that are assertions but are
    // not spelled "assert" (see engine/AssertGuards.h).
    void setAssertRecovery(bool on) { assert_recovery_ = on; }
    bool assertRecovery() const { return assert_recovery_; }
    bool addAssertMacros(const std::string& list, InputError* error = nullptr);
    const std::set<std::string>& assertMacros() const {
        return assert_macros_;
    }
    // --negative-assert-macros: names that assert a pointer IS null and
    // must be vetoed even when the spelling heuristic misses them.
    bool addNegativeAssertMacros(const std::string& list, InputError* error = nullptr);
    const std::set<std::string>& negativeAssertMacros() const {
        return negative_assert_macros_;
    }

    // Custom allocator wrappers (--alloc-functions / --free-functions):
    // extend the leak/double-free/UAF domain to project-specific heap
    // wrappers (git__malloc, zmalloc, ...).
    bool addAllocFunctions(const std::string& list, InputError* error = nullptr);
    bool addFreeFunctions(const std::string& list, InputError* error = nullptr);
    const std::set<std::string>& allocFunctions() const {
        return alloc_functions_;
    }
    const std::set<std::string>& freeFunctions() const {
        return free_functions_;
    }
    bool addAllocatorPairs(const std::string& list, InputError* error = nullptr);
    const std::map<std::string, std::set<std::string>>& allocatorPairs() const {
        return allocator_pairs_;
    }

    // Project untrusted-length sources (--untrusted-int-sources): the
    // RETURN of these functions is treated as a full-range untrusted
    // integer (a length/count decoded off the wire), the same discipline
    // as atoi/strtol. Default empty — no effect unless a project opts in.
    const std::set<std::string>& untrustedIntSources() const {
        return untrusted_int_sources_;
    }

    // Project owning-smart-pointer wrappers (--owning-pointers): raw
    // pointers adopted by construction into these types escape the leak
    // domain (Ref<T>, RefPtr<T>, scoped_refptr<T>, ...).
    bool addOwningPointers(const std::string& list, InputError* error = nullptr);
    const std::set<std::string>& owningPointers() const {
        return owning_pointers_;
    }

    // Report-path filter (--report-paths): only findings under these
    // path prefixes are reported. The Carbon scan lesson (2026-07-16):
    // 15 of 16 findings were in LLVM DEPENDENCY headers pulled into the
    // TUs — noise for the project being scanned. Unset = report all
    // (analysis itself is unaffected; this filters reporting only).
    bool addReportPaths(const std::string& list, InputError* error = nullptr);
    const std::vector<std::string>& reportPaths() const {
        return report_paths_;
    }

    // Project-wide policies (CONTRACTS.md Round E): `policy = <name>`
    // in .codeskeptic.conf or --policy on the CLI; file-scoped
    // activation stays in `// cs:policy` comments.
    const std::set<std::string>& policies() const { return policies_; }

    // Summary-diff gate (CONTRACTS.md §5): "error" (default) exits 1
    // on WEAKENED; "warn" reports but exits 0 (adoption ramp).
    const std::string& summaryDiffGate() const { return summary_diff_gate_; }

private:
    bool parseSeverity(const std::string& str, Severity& severity) const;
    bool loadFromFileInPlace(const std::string& path, InputError* error);
    bool parseArgsInPlace(int argc, char* argv[], InputError* error);
    bool addNamesTo(std::set<std::string>& target, const std::string& list,
                    const char* field, InputError* error);
    bool addRuleIds(std::set<std::string>& target, const std::string& list,
                    const char* field, InputError* error);

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
    std::set<std::string> fatal_asserts_;
    std::set<std::string> assert_macros_;
    std::set<std::string> negative_assert_macros_;
    std::set<std::string> alloc_functions_;
    std::map<std::string, std::set<std::string>> allocator_pairs_;
    std::set<std::string> untrusted_int_sources_;
    std::set<std::string> free_functions_;
    std::set<std::string> owning_pointers_;
    std::vector<std::string> report_paths_;
    std::set<std::string> policies_;
    std::string summary_diff_gate_ = "error";
    std::vector<std::pair<unsigned, unsigned>> lines_;
    bool serve_ = false;
    bool whole_program_ = false;
    bool analyze_broken_tus_ = false;
    bool accept_partial_coverage_ = false;
    bool assert_recovery_ = true;
    bool assumptions_ = false;
    bool warm_cache_ = false;
    bool analysis_cache_ = false;
    std::string analysis_cache_directory_;
    unsigned analysis_cache_bytes_ = 256 * 1024 * 1024;
    unsigned analysis_cache_entries_ = 128;
    std::string checkpoint_directory_;
    bool resume_checkpoint_ = false;
    unsigned checkpoint_bytes_ = 256 * 1024 * 1024;
    unsigned checkpoint_units_ = 128;
    std::map<std::string, std::string> configuration_inputs_;
    bool help_requested_ = false;
    bool build_path_specified_ = false;
    bool file_list_specified_ = false;
    bool doctor_ = false;
    WorkerLimits worker_limits_;
    std::shared_ptr<ResourceCancellation> resource_cancellation_;
    std::string summary_in_path_;
    std::string summary_out_path_;
    std::vector<std::string> model_files_;
    std::string summary_diff_old_;
    std::string summary_diff_new_;
    Severity min_severity_;
    std::set<std::string> enabled_rules_;
    std::set<std::string> disabled_rules_;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_CONFIG_H
