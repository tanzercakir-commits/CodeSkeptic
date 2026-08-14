#ifndef CODESKEPTIC_ANALYSIS_COORDINATOR_H
#define CODESKEPTIC_ANALYSIS_COORDINATOR_H

#include "core/AnalysisResult.h"
#include "core/Diagnostic.h"
#include "core/ResourceSupervisor.h"
#include "source_manager/SourceManager.h"

#include <functional>
#include <vector>

namespace codeskeptic {

enum class TranslationUnitPhase {
    SummaryHarvest,
    Analysis,
};

const char* translationUnitPhaseName(TranslationUnitPhase phase);

struct UnitExecutionResult {
    ResourceRunResult resource;
    AnalysisResult analysis;
    DiagnosticList diagnostics;
};

struct CoordinatedAnalysisResult {
    AnalysisResult analysis;
    DiagnosticList diagnostics;
};

using UnitExecutor = std::function<UnitExecutionResult(
    const TranslationUnitExecution&, TranslationUnitPhase)>;

class AnalysisCoordinator {
public:
    static CoordinatedAnalysisResult run(
        const std::vector<TranslationUnitExecution>& units,
        ResourceLimits limits,
        bool whole_program,
        const UnitExecutor& executor);
};

} // namespace codeskeptic

#endif // CODESKEPTIC_ANALYSIS_COORDINATOR_H
