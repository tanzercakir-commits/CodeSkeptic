#ifndef CODESKEPTIC_WORKER_PROTOCOL_H
#define CODESKEPTIC_WORKER_PROTOCOL_H

#include "core/AnalysisResult.h"
#include "core/ResourceBudget.h"
#include "engine/CoverageReport.h"
#include <clang/Tooling/CompilationDatabase.h>
#include <cstdint>
#include <string>
#include <vector>

namespace codeskeptic {

// Private, same-build protocol, not a public report or a persisted cache format.
// Fixed field order and length-prefixed byte strings avoid duplicate JSON keys,
// text-mode path corruption, delimiter ambiguity and recursive parser inputs.
// Every packet binds its schema AND exact tool build; unknown/trailing fields
// fail closed. Child process success is checked separately from packet validity.
constexpr std::size_t kWorkerPacketLimit = 64 * 1024 * 1024;
constexpr std::size_t kWorkerFieldLimit = 16 * 1024 * 1024;
constexpr std::size_t kWorkerCollectionLimit = 100000;

enum class WorkerPhase : std::uint32_t { Harvest, Analyze };

struct WorkerRequest {
    std::uint32_t ordinal = 0;
    WorkerPhase phase = WorkerPhase::Analyze;
    std::string source;
    std::string build_directory;
    bool synthetic = false;
    std::vector<clang::tooling::CompileCommand> commands;
    // Resolved analysis-only settings: no project-config reload, discovery,
    // output files, parent filters or per-child baseline budgets.
    std::vector<std::string> arguments;
    std::vector<std::string> producers;
    std::vector<std::string> selected_families;
    std::string global_summaries;
    bool harvest = false;
    unsigned memory_mb = WorkerLimits{}.memory_mb;
};

struct WorkerResponse {
    std::string request_digest;
    std::uint32_t ordinal = 0;
    WorkerPhase phase = WorkerPhase::Analyze;
    SourceCoverage coverage;
    DiagnosticList diagnostics;
    std::vector<CoverageEntry> gaps;
    std::string global_summaries;
};

// Encoding throws on limits/invalid values. Decoding is transactional: an
// invalid packet cannot publish a partial replacement into the caller's result.
std::string encodeWorkerRequest(const WorkerRequest& request);
bool decodeWorkerRequest(const std::string& packet, WorkerRequest& request,
                         std::string& error);
std::string encodeWorkerResponse(const WorkerResponse& response);
bool decodeWorkerResponse(const std::string& packet, const WorkerRequest& request,
                          const std::string& request_digest,
                          WorkerResponse& response, std::string& error);
std::string workerRequestDigest(const std::string& packet);

// File transport is binary on all hosts; reject non-regular, symlink, oversized,
// truncated or growing input. It is not an attestation against a hostile owner.
bool readWorkerPacket(const std::string& path, std::string& packet, std::string& error);
bool writeWorkerPacket(const std::string& path, const std::string& packet, std::string& error);

} // namespace codeskeptic
#endif
