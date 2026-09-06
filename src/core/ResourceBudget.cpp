#include "core/ResourceBudget.h"

#include <llvm/Support/Program.h>
#include <algorithm>
#include <chrono>
#include <csignal>
#include <iostream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <cerrno>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace codeskeptic {
namespace {
static_assert(std::atomic<std::sig_atomic_t>::is_always_lock_free,
              "signal cancellation requires a lock-free flag");
std::atomic<std::sig_atomic_t> signal_cancelled{0};
void recordCancellation(int) { signal_cancelled.store(1, std::memory_order_relaxed); }

bool cancelled(const ResourceCancellation* token) {
    return workerSignalCancellationRequested() || (token && token->requested());
}

class OwnedChild {
public:
    explicit OwnedChild(llvm::sys::ProcessInfo info) : info_(info) {}
    ~OwnedChild() {
        if (active_ && !terminate())
            std::cerr << "[CodeSkeptic] cannot finish owned worker cleanup\n";
    }
    // -1 is a supervision failure, 0 still running, 1 reaped/handle closed.
    int poll(ResourceProcessResult& result) {
#ifdef _WIN32
        const auto handle = static_cast<HANDLE>(info_.Process);
        const DWORD state = WaitForSingleObject(handle, 0);
        if (state == WAIT_TIMEOUT) return 0;
        if (state != WAIT_OBJECT_0) {
            result.detail = "worker wait failed";
            return -1;
        }
        DWORD code = 0;
        const bool queried = GetExitCodeProcess(handle, &code) != 0;
        CloseHandle(handle);
        active_ = false;
        if (!queried) { result.detail = "worker exit query failed"; return -1; }
        result.exit_code = static_cast<int>(code);
        result.stop = result.exit_code < 0 ? ResourceStop::Crashed : ResourceStop::Exited;
#else
        int status = 0;
        pid_t waited;
        do { waited = ::waitpid(info_.Pid, &status, WNOHANG); } while (waited < 0 && errno == EINTR);
        if (waited == 0) return 0;
        if (waited < 0) {
            const auto error = errno;
            // A missing waitable child must never turn into a kill of a reused
            // PID. Embedders must not independently reap this owner's child.
            if (error == ECHILD) active_ = false;
            result.detail = std::error_code(error, std::generic_category()).message();
            return -1;
        }
        active_ = false;
        result.stop = WIFEXITED(status) ? ResourceStop::Exited : ResourceStop::Crashed;
        result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
#endif
        return 1;
    }
    bool terminate() {
        if (!active_) return true;
        ResourceProcessResult ignored;
        const int state = poll(ignored);
        if (state == 1 || !active_) return true;
#ifdef _WIN32
        const auto handle = static_cast<HANDLE>(info_.Process);
        if (!TerminateProcess(handle, 2) && WaitForSingleObject(handle, 0) != WAIT_OBJECT_0)
            return false;
        if (WaitForSingleObject(handle, INFINITE) != WAIT_OBJECT_0) return false;
        CloseHandle(handle);
#else
        if (::kill(info_.Pid, SIGKILL) != 0 && errno != ESRCH) return false;
        int status;
        pid_t waited;
        do { waited = ::waitpid(info_.Pid, &status, 0); } while (waited < 0 && errno == EINTR);
        if (waited < 0 && errno != ECHILD) return false;
#endif
        active_ = false;
        return true;
    }
    OwnedChild(const OwnedChild&) = delete;
    OwnedChild& operator=(const OwnedChild&) = delete;
private:
    llvm::sys::ProcessInfo info_;
    bool active_ = true;
};
} // namespace

bool validWorkerLimits(const WorkerLimits& limits) {
    return limits.timeout_ms >= 1 && limits.timeout_ms <= 3600000 &&
           limits.memory_mb >= 16 && limits.memory_mb <= 65536;
}

bool workerSignalCancellationRequested() noexcept {
    return signal_cancelled.load(std::memory_order_relaxed) != 0;
}

struct WorkerSignalScope::State {
#ifdef _WIN32
    using Handler = void (*)(int);
    Handler interrupt = SIG_DFL;
    Handler terminate = SIG_DFL;
#else
    struct sigaction interrupt{};
    struct sigaction terminate{};
#endif
    std::sig_atomic_t previous = 0;
};

WorkerSignalScope::WorkerSignalScope() : state_(std::make_unique<State>()) {
    state_->previous = signal_cancelled.exchange(0, std::memory_order_relaxed);
#ifdef _WIN32
    state_->interrupt = std::signal(SIGINT, recordCancellation);
    state_->terminate = std::signal(SIGTERM, recordCancellation);
    if (state_->interrupt == SIG_ERR || state_->terminate == SIG_ERR) {
        if (state_->interrupt != SIG_ERR) std::signal(SIGINT, state_->interrupt);
        if (state_->terminate != SIG_ERR) std::signal(SIGTERM, state_->terminate);
        signal_cancelled.store(state_->previous, std::memory_order_relaxed);
        throw std::runtime_error("cannot install worker cancellation handlers");
    }
#else
    struct sigaction handler{};
    handler.sa_handler = recordCancellation;
    sigemptyset(&handler.sa_mask);
    // No SA_RESTART: an idle input read can return after the owner's signal.
    if (sigaction(SIGINT, &handler, &state_->interrupt) != 0) {
        signal_cancelled.store(state_->previous, std::memory_order_relaxed);
        throw std::runtime_error("cannot install worker interrupt handler");
    }
    if (sigaction(SIGTERM, &handler, &state_->terminate) != 0) {
        sigaction(SIGINT, &state_->interrupt, nullptr);
        signal_cancelled.store(state_->previous, std::memory_order_relaxed);
        throw std::runtime_error("cannot install worker termination handler");
    }
#endif
}

WorkerSignalScope::~WorkerSignalScope() {
#ifdef _WIN32
    std::signal(SIGINT, state_->interrupt);
    std::signal(SIGTERM, state_->terminate);
#else
    sigaction(SIGINT, &state_->interrupt, nullptr);
    sigaction(SIGTERM, &state_->terminate, nullptr);
#endif
    signal_cancelled.store(state_->previous, std::memory_order_relaxed);
}

ResourceProcessResult runResourceWorker(const std::string& executable,
    const std::vector<std::string>& arguments, const std::array<std::string, 3>& redirects,
    const WorkerLimits& limits, const ResourceCancellation* cancellation) {
    ResourceProcessResult result;
    if (!validWorkerLimits(limits) || executable.empty() || arguments.empty()) {
        result.detail = "invalid worker launch or limits";
        return result;
    }
    if (cancelled(cancellation)) {
        result.stop = ResourceStop::Cancelled;
        return result;
    }
#ifndef _WIN32
    struct sigaction child_action{};
    if (sigaction(SIGCHLD, nullptr, &child_action) != 0 || child_action.sa_handler == SIG_IGN ||
        (child_action.sa_flags & SA_NOCLDWAIT)) {
        result.detail = "worker requires exclusive waitable child ownership";
        return result;
    }
#endif
    std::vector<llvm::StringRef> raw;
    for (const auto& argument : arguments) raw.push_back(argument);
    const std::array<std::optional<llvm::StringRef>, 3> streams{{redirects[0], redirects[1], redirects[2]}};
    bool launch_failed = false;
    const auto started = std::chrono::steady_clock::now();
    const auto process = llvm::sys::ExecuteNoWait(executable, raw, std::nullopt, streams,
                                                 0, &result.detail, &launch_failed);
    if (launch_failed || process.Pid <= 0) return result;
    OwnedChild child(process);
    while (true) {
        const bool stopping = cancelled(cancellation);
        const bool timeout = std::chrono::steady_clock::now() - started >=
                             std::chrono::milliseconds(limits.timeout_ms);
        if (stopping || timeout) {
            result.stop = stopping ? ResourceStop::Cancelled : ResourceStop::Timeout;
            if (!child.terminate()) {
                result.stop = ResourceStop::SupervisionFailed;
                result.detail = "cannot terminate/reap owned worker";
            }
            return result;
        }
        const int state = child.poll(result);
        if (state > 0) return result;
        if (state < 0) { result.stop = ResourceStop::SupervisionFailed; return result; }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

WorkerMemoryLimit::~WorkerMemoryLimit() {
#ifdef _WIN32
    if (job_) CloseHandle(static_cast<HANDLE>(job_));
#endif
}

bool WorkerMemoryLimit::apply(unsigned memory_mb, std::string& error) {
    if (!validWorkerLimits({1, memory_mb})) { error = "invalid worker memory limit"; return false; }
    const std::uint64_t bytes = static_cast<std::uint64_t>(memory_mb) * 1024 * 1024;
#ifdef _WIN32
    if (job_ || bytes > std::numeric_limits<SIZE_T>::max()) {
        error = "worker memory limit cannot be represented or was already applied"; return false;
    }
    const auto job = CreateJobObjectW(nullptr, nullptr);
    if (!job) { error = "cannot create private worker memory job"; return false; }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    limits.ProcessMemoryLimit = static_cast<SIZE_T>(bytes);
    if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)) ||
        !AssignProcessToJobObject(job, GetCurrentProcess())) {
        CloseHandle(job);
        error = "cannot apply worker process-memory job";
        return false;
    }
    job_ = job;
#else
    struct rlimit previous{};
    if (bytes > std::numeric_limits<rlim_t>::max() || getrlimit(RLIMIT_AS, &previous) != 0) {
        error = "cannot read worker address-space limit"; return false;
    }
    rlim_t target = static_cast<rlim_t>(bytes);
    if (previous.rlim_cur != RLIM_INFINITY) target = std::min(target, previous.rlim_cur);
    if (previous.rlim_max != RLIM_INFINITY) target = std::min(target, previous.rlim_max);
    const struct rlimit limits{target, target};
    if (setrlimit(RLIMIT_AS, &limits) != 0) {
        error = "cannot apply worker address-space limit"; return false;
    }
#endif
    error.clear();
    return true;
}

} // namespace codeskeptic
