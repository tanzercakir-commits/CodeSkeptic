#ifndef CODESKEPTIC_CONFIG_H
#define CODESKEPTIC_CONFIG_H

#include "core/Diagnostic.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace codeskeptic {

class Config {
public:
    static constexpr unsigned kDefaultTuTimeoutSeconds = 300;
    static constexpr unsigned kDefaultTuMemoryMiB = 4096;
    static constexpr unsigned kMaxTuTimeoutSeconds = 86400;
    static constexpr unsigned kMaxTuMemoryMiB = 131072;

    Config();

    bool loadFromFile(const std::string& path);
    bool loadFromText(const std::string& text,
                      const std::string& source = "<memory>",
                      bool reportErrors = true);
    bool parseArgs(int argc, char* argv[]);
    bool helpRequested() const { return help_requested_; }
    bool operator==(const Config& other) const;
    bool operator!=(const Config& other) const { return !(*this == other); }

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
    // #86: analyze TUs whose parse ended in errors (default: skip them
    // with an honest coverage note — error recovery eats declarations
    // and rules would report confidently about code that isn't there).
    bool analyzeBrokenTUs() const { return analyze_broken_tus_; }
    // Explicit adoption escape hatch: preserve coverage counts/warnings but
    // allow a verdict over the successfully analyzed subset. Default is
    // fail-closed; integrations must opt in deliberately.
    bool acceptPartialCoverage() const { return accept_partial_coverage_; }
    unsigned tuTimeoutSeconds() const { return tu_timeout_seconds_; }
    unsigned tuMemoryMiB() const { return tu_memory_mib_; }
    const std::string& checkpointDir() const { return checkpoint_dir_; }
    bool checkpointPerRunNamespace() const {
        return checkpoint_per_run_namespace_;
    }
    bool setTuTimeoutSeconds(std::uint64_t value);
    bool setTuMemoryMiB(std::uint64_t value);
    // Exact analysis settings forwarded to an isolated translation-unit
    // worker. Parent-only inputs/outputs, resource limits, and control modes
    // are deliberately excluded: the coordinator supplies one exact source
    // command and owns the final project artifact/verdict.
    std::vector<std::string> workerArguments(
        const std::vector<std::string>& available_rule_ids,
        const std::string& summary_override = {},
        bool replace_configured_summaries = false) const;
    void setWorkerProgram(std::string path) {
        worker_program_ = std::move(path);
    }
    const std::string& workerProgram() const { return worker_program_; }
    // Derive one isolated MCP call from the long-lived server policy. Runtime
    // budgets, rules, models, language, and project idioms are inherited;
    // request inputs, scopes, output side effects, baselines, summaries, and
    // control modes are cleared so one server invocation cannot smuggle CLI
    // work into every tool call.
    Config mcpRequestConfig() const;
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

    // Legacy programmatic compatibility switch. AST reuse is disabled; the
    // exact process-isolated checkpoint store owns safe persistent reuse.
    void setWarmCache(bool enabled) { warm_cache_ = enabled; }
    bool warmCache() const { return warm_cache_; }

    // Programmatic scope settings (the MCP server uses these directly)
    bool addFunctions(const std::string& list);
    bool addLines(const std::string& list);

    // Fatal-assert handlers (--fatal-asserts): user-declared noreturn
    // functions; the engine kills dataflow paths at calls to them.
    void addFatalAsserts(const std::string& list);
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
    void addAssertMacros(const std::string& list);
    const std::set<std::string>& assertMacros() const {
        return assert_macros_;
    }
    // --negative-assert-macros: names that assert a pointer IS null and
    // must be vetoed even when the spelling heuristic misses them.
    void addNegativeAssertMacros(const std::string& list);
    const std::set<std::string>& negativeAssertMacros() const {
        return negative_assert_macros_;
    }

    // Custom allocator wrappers (--alloc-functions / --free-functions):
    // extend the leak/double-free/UAF domain to project-specific heap
    // wrappers (git__malloc, zmalloc, ...).
    void addAllocFunctions(const std::string& list);
    void addFreeFunctions(const std::string& list);
    const std::set<std::string>& allocFunctions() const {
        return alloc_functions_;
    }
    const std::set<std::string>& freeFunctions() const {
        return free_functions_;
    }
    bool addAllocatorPairs(const std::string& list);
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
    void addOwningPointers(const std::string& list);
    const std::set<std::string>& owningPointers() const {
        return owning_pointers_;
    }

    // Report-path filter (--report-paths): only findings under these
    // path prefixes are reported. The Carbon scan lesson (2026-07-16):
    // 15 of 16 findings were in LLVM DEPENDENCY headers pulled into the
    // TUs — noise for the project being scanned. Unset = report all
    // (analysis itself is unaffected; this filters reporting only).
    void addReportPaths(const std::string& list);
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
    bool loadFromTextInPlace(const std::string& text,
                             const std::string& source,
                             bool reportErrors);
    bool parseSeverity(const std::string& str, Severity& severity) const;
    void addNamesTo(std::set<std::string>& target, const std::string& list);

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
    unsigned tu_timeout_seconds_ = kDefaultTuTimeoutSeconds;
    unsigned tu_memory_mib_ = kDefaultTuMemoryMiB;
    std::string checkpoint_dir_;
    bool checkpoint_per_run_namespace_ = false;
    bool assert_recovery_ = true;
    bool assumptions_ = false;
    bool warm_cache_ = false;
    bool help_requested_ = false;
    std::string summary_in_path_;
    std::string summary_out_path_;
    std::vector<std::string> model_files_;
    std::string summary_diff_old_;
    std::string summary_diff_new_;
    Severity min_severity_;
    std::set<std::string> enabled_rules_;
    std::set<std::string> disabled_rules_;
    // Runtime-only coordinator state; it is not user configuration and is
    // intentionally excluded from operator== and config-file parsing.
    std::string worker_program_;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_CONFIG_H
