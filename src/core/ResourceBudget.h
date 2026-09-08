#ifndef CODESKEPTIC_RESOURCE_BUDGET_H
#define CODESKEPTIC_RESOURCE_BUDGET_H

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace codeskeptic {

struct WorkerLimits {
    unsigned timeout_ms = 120000;
    unsigned memory_mb = 2048;
};

bool validWorkerLimits(const WorkerLimits& limits);

class ResourceCancellation {
public:
    void request() noexcept { requested_.store(true, std::memory_order_relaxed); }
    bool requested() const noexcept { return requested_.load(std::memory_order_relaxed); }
private:
    std::atomic<bool> requested_{false};
};

// Process signal handlers record only a flag. Killing/reaping happens in normal
// coordinator control flow, never in a handler. Library callers can additionally
// provide a run-owned cancellation token without changing signal dispositions.
bool workerSignalCancellationRequested() noexcept;
class WorkerSignalScope {
public:
    WorkerSignalScope();
    ~WorkerSignalScope();
    WorkerSignalScope(const WorkerSignalScope&) = delete;
    WorkerSignalScope& operator=(const WorkerSignalScope&) = delete;
private:
    struct State;
    std::unique_ptr<State> state_;
};

enum class ResourceStop { Exited, Crashed, LaunchFailed, Timeout, Cancelled, SupervisionFailed };
struct ResourceProcessResult {
    ResourceStop stop = ResourceStop::LaunchFailed;
    int exit_code = -1;
    std::string detail;
};

// Exact owned PID/HANDLE only; no process group, wait-any, host-wide enumeration,
// privilege, alarm, or LLVM timed/polling Wait. Limits cover each launch+wait;
// memory is applied explicitly inside the same-build child before AST work.
ResourceProcessResult runResourceWorker(const std::string& executable,
    const std::vector<std::string>& arguments, const std::array<std::string, 3>& redirects,
    const WorkerLimits& limits, const ResourceCancellation* cancellation = nullptr);

// Worker-only: changes this process's limits, never the parent's. A successful
// Windows application retains its private Job handle for this object's lifetime.
// POSIX address-space and Windows committed-memory caps are NOT equal RSS limits.
// On macOS only, MiB is added to ONE startup MACH_TASK_BASIC_INFO.virtual_size
// snapshot. The finite absolute RLIMIT_AS ceiling is clamped to inherited limits,
// installed once and read back exactly. It does not bound resident/committed
// memory or reuse/touching of existing mappings. Later unmapping does not lower
// the ceiling, so remaining headroom can then exceed the original allowance.
class WorkerMemoryLimit {
public:
    WorkerMemoryLimit() = default;
    ~WorkerMemoryLimit();
    bool apply(unsigned memory_mb, std::string& error);
    WorkerMemoryLimit(const WorkerMemoryLimit&) = delete;
    WorkerMemoryLimit& operator=(const WorkerMemoryLimit&) = delete;
private:
    void* job_ = nullptr;
};

} // namespace codeskeptic
#endif
