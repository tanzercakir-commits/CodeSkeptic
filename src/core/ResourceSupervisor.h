#ifndef CODESKEPTIC_RESOURCE_SUPERVISOR_H
#define CODESKEPTIC_RESOURCE_SUPERVISOR_H

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace codeskeptic {

struct ResourceSupervisorTestAccess;

struct ResourceLimits {
    unsigned timeout_seconds = 0;
    unsigned memory_mib = 0;
};

enum class ResourceRunStatus {
    Completed,
    TimedOut,
    MemoryExceeded,
    Crashed,
    LaunchFailed,
};

struct ResourceRunResult {
    ResourceRunStatus status = ResourceRunStatus::LaunchFailed;
    int exit_code = -1;
    std::uint64_t duration_ms = 0;
    std::uint64_t peak_memory_kib = 0;
    std::string error;
};

class ResourceSupervisor {
public:
    // The worker is a separate OS process. Post-exec start/completion
    // handshakes bracket parent-side resident-set and wall-clock polling; the
    // parent terminates and reaps the exact worker at either ceiling. This is
    // compatible with sanitizer runtimes whose large virtual shadow mappings
    // cannot start under a pre-exec RLIMIT_DATA ceiling. Linux VmHWM, Windows
    // PeakWorkingSetSize, and a child-reset Darwin footprint interval retain
    // post-exec allocation/free peaks for deterministic classification.
    static ResourceRunResult run(const std::string& program,
                                 const std::vector<std::string>& arguments,
                                 ResourceLimits limits);
    static ResourceRunResult runUntil(
        const std::string& program,
        const std::vector<std::string>& arguments,
        ResourceLimits limits,
        std::chrono::steady_clock::time_point deadline);

private:
    using MemorySampler = std::function<std::uint64_t()>;
    static ResourceRunResult runWithMemorySampler(
        const std::string& program,
        const std::vector<std::string>& arguments,
        ResourceLimits limits,
        const MemorySampler& memory_sampler);
    static ResourceRunResult runWithMemorySamplerUntil(
        const std::string& program,
        const std::vector<std::string>& arguments,
        ResourceLimits limits,
        const MemorySampler& memory_sampler,
        std::chrono::steady_clock::time_point deadline);
    friend struct ResourceSupervisorTestAccess;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_RESOURCE_SUPERVISOR_H
