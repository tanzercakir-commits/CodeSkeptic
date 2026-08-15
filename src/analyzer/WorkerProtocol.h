#ifndef CODESKEPTIC_WORKER_PROTOCOL_H
#define CODESKEPTIC_WORKER_PROTOCOL_H

#include "analyzer/AnalysisCoordinator.h"
#include "core/AnalysisResult.h"
#include "core/Diagnostic.h"
#include "source_manager/SourceManager.h"

#include <string>
#include <vector>

namespace codeskeptic {

inline constexpr int kWorkerProtocolVersion = 3;

struct DependencyEvidence {
    std::string canonical_path;
    std::string content_sha256;
    bool sidecar_exists = false;
    std::string sidecar_sha256;

    bool operator==(const DependencyEvidence& other) const {
        return canonical_path == other.canonical_path &&
               content_sha256 == other.content_sha256 &&
               sidecar_exists == other.sidecar_exists &&
               sidecar_sha256 == other.sidecar_sha256;
    }
};

struct DependencyManifest {
    std::string toolchain_identity_sha256;
    std::vector<DependencyEvidence> files;
    bool cacheable = true;
    std::string sha256;

    bool operator==(const DependencyManifest& other) const {
        return toolchain_identity_sha256 ==
                   other.toolchain_identity_sha256 &&
               files == other.files && cacheable == other.cacheable &&
               sha256 == other.sha256;
    }
};

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
    DependencyManifest dependency_manifest;
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
std::string dependencyManifestSha256(const DependencyManifest& manifest);

} // namespace codeskeptic

#endif // CODESKEPTIC_WORKER_PROTOCOL_H
