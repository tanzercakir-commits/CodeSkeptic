#ifndef CODESKEPTIC_WORKER_PROTOCOL_H
#define CODESKEPTIC_WORKER_PROTOCOL_H

#include "analyzer/AnalysisCoordinator.h"
#include "core/AnalysisResult.h"
#include "core/Diagnostic.h"
#include "source_manager/SourceManager.h"

#include <string>
#include <vector>

namespace codeskeptic {

inline constexpr int kWorkerProtocolVersion = 1;

struct WorkerRequest {
    std::string request_id;
    TranslationUnitExecution unit;
    TranslationUnitPhase phase = TranslationUnitPhase::Analysis;
    std::vector<std::string> config_arguments;
    std::string response_path;
    std::string summary_fragment_path;
};

struct WorkerResponse {
    std::string request_id;
    std::string canonical_path;
    std::string compile_command_sha256;
    std::size_t command_ordinal = 0;
    TranslationUnitPhase phase = TranslationUnitPhase::Analysis;
    AnalysisResult analysis;
    DiagnosticList diagnostics;
    std::string summary_fragment_sha256;
};

bool writeWorkerRequest(const std::string& path,
                        const WorkerRequest& request,
                        std::string& error);
bool readWorkerRequest(const std::string& path,
                       WorkerRequest& request,
                       std::string& error);
bool writeWorkerResponse(const std::string& path,
                         const WorkerResponse& response,
                         std::string& error);
bool readWorkerResponse(const std::string& path,
                        const WorkerRequest& expected,
                        WorkerResponse& response,
                        std::string& error);

std::string sha256File(const std::string& path, std::string& error);

} // namespace codeskeptic

#endif // CODESKEPTIC_WORKER_PROTOCOL_H
