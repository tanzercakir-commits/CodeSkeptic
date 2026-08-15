#ifndef CODESKEPTIC_UNIT_EVIDENCE_STORE_H
#define CODESKEPTIC_UNIT_EVIDENCE_STORE_H

#include "analyzer/WorkerProtocol.h"
#include "core/ResourceSupervisor.h"

#include <chrono>
#include <memory>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace codeskeptic {

using EvidenceDeadline = std::chrono::steady_clock::time_point;

enum class EvidenceLookupStatus {
    Hit,
    Miss,
    Failed,
};

struct CachedUnitEvidence {
    WorkerResponse response;
    std::string summary_fragment;
    std::string checkpoint_key_sha256;
    std::string payload_sha256;
};

class UnitEvidenceStore {
public:
    static std::unique_ptr<UnitEvidenceStore> open(
        const std::string& directory,
        const std::vector<TranslationUnitExecution>& units,
        bool whole_program,
        const std::string& analyzer_program,
        const std::vector<std::string>& configuration_arguments,
        const std::vector<std::string>& rule_ids,
        ResourceLimits limits,
        std::string& error,
        bool namespace_by_run_identity = false);

    bool verifyAnalyzerIdentity(
        std::string& error,
        EvidenceDeadline deadline = EvidenceDeadline::max()) const;

    EvidenceLookupStatus lookup(
        const TranslationUnitExecution& unit,
        TranslationUnitPhase phase,
        const DependencyManifest& dependencies,
        const std::string& input_sha256,
        CachedUnitEvidence& cached,
        std::string& error,
        EvidenceDeadline deadline = EvidenceDeadline::max()) const;

    bool store(const TranslationUnitExecution& unit,
               TranslationUnitPhase phase,
               const DependencyManifest& dependencies,
               const std::string& input_sha256,
               const WorkerResponse& response,
               const std::string& summary_fragment,
               std::string& checkpoint_key_sha256,
               std::string& payload_sha256,
               std::string& error,
               EvidenceDeadline deadline = EvidenceDeadline::max());

private:
    struct CompletedEntry {
        std::string checkpoint_key_sha256;
        std::string payload_sha256;
    };

    UnitEvidenceStore() = default;
    bool writeRunManifest(
        std::string& error,
        EvidenceDeadline deadline = EvidenceDeadline::max()) const;

    std::string directory_;
    std::string analyzer_program_;
    std::string analyzer_sha256_;
    mutable std::string analyzer_metadata_identity_;
    std::string configuration_sha256_;
    std::string plan_sha256_;
    std::set<std::string> planned_unit_ids_;
    std::map<std::string, CompletedEntry> completed_;
};

// Stable content digests used by the cache key. They are exposed for focused
// contract tests and for StaticAnalyzer's ordered model/summary inputs.
std::string sha256RegularFileStreaming(const std::string& path,
                                       std::string& error,
                                       EvidenceDeadline deadline =
                                           EvidenceDeadline::max());
std::string orderedInputFilesSha256(const std::vector<std::string>& paths,
                                    std::string& error,
                                    EvidenceDeadline deadline =
                                        EvidenceDeadline::max());

} // namespace codeskeptic

#endif // CODESKEPTIC_UNIT_EVIDENCE_STORE_H
