#ifndef CODESKEPTIC_ANALYSIS_COORDINATOR_H
#define CODESKEPTIC_ANALYSIS_COORDINATOR_H

#include "analyzer/WorkerProtocol.h"
#include "config/Config.h"

namespace codeskeptic {

// Production main resolves its own executable and opts in once (including
// --serve). Library embedders retain an explicit in-process backend when this
// path is empty; arbitrary custom rule objects cannot be serialized as IDs.
// A configured worker failure NEVER falls back to in-process analysis.
void setWorkerExecutable(std::string executable);
const std::string& workerExecutable();

struct WorkerExecution {
    bool valid = false;
    bool cache_hit = false;
    std::string reason;
    std::string detail;
    WorkerResponse response;
};

std::vector<std::string> workerAnalysisArguments(const Config& config);
WorkerExecution executeAnalysisWorker(const std::string& executable, const WorkerRequest& request,
    const WorkerLimits& limits = {}, const ResourceCancellation* cancellation = nullptr);
// Private main dispatch; no normal argument scanning or config-file load.
int runAnalysisWorker(const std::string& request_path, const std::string& response_path);

// Bounded, checked rolling summary transfer. Failed imports leave the existing
// registry untouched; callers must mark missing evidence as failure.
bool exportWorkerSummaries(std::string& bytes, std::string& error);
bool importWorkerSummaries(const std::string& bytes, std::string& error);

} // namespace codeskeptic
#endif
