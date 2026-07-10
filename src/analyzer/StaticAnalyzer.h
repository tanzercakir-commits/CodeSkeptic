#ifndef ZERODEFECT_STATIC_ANALYZER_H
#define ZERODEFECT_STATIC_ANALYZER_H

#include "config/Config.h"
#include "core/Diagnostic.h"
#include "engine/RuleEngine.h"
#include "reporter/Reporter.h"
#include "source_manager/SourceManager.h"

#include <memory>
#include <utility>

namespace zerodefect {

class StaticAnalyzer {
public:
    explicit StaticAnalyzer(Config config);

    // Reverts the global filter state set by the ctor. In long-lived
    // processes (MCP server, tests) this prevents a filtered run from
    // silently pruning subsequent runs.
    ~StaticAnalyzer();

    template <typename T, typename... Args>
    void addRule(Args&&... args) {
        engine_.addRule<T>(std::forward<Args>(args)...);
    }

    int run();

    const DiagnosticList& diagnostics() const { return diagnostics_; }
    const Config& config() const { return config_; }

private:
    Config config_;
    std::unique_ptr<SourceManager> source_mgr_;
    RuleEngine engine_;
    std::unique_ptr<Reporter> reporter_;
    DiagnosticList diagnostics_;
};

} // namespace zerodefect

#endif // ZERODEFECT_STATIC_ANALYZER_H
