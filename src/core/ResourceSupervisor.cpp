#include "core/ResourceSupervisor.h"
#include "core/ResourceWorkerControl.h"

#include <llvm/ADT/SmallString.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Program.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#define PSAPI_VERSION 1
#include <windows.h>
#include <psapi.h>
#elif defined(__APPLE__)
#include <libproc.h>
#include <signal.h>
#else
#include <signal.h>
#include <unistd.h>
#endif

namespace codeskeptic {

namespace {

constexpr int kMemoryLimitExitCode = 86;
constexpr auto kPollInterval = std::chrono::milliseconds(1);

std::uint64_t residentMemoryKiB(const llvm::sys::ProcessInfo& process) {
#ifdef _WIN32
    PROCESS_MEMORY_COUNTERS counters{};
    counters.cb = sizeof(counters);
    if (!GetProcessMemoryInfo(
            static_cast<HANDLE>(process.Process), &counters,
            sizeof(counters)))
        return 0;
    return static_cast<std::uint64_t>(counters.PeakWorkingSetSize) / 1024u;
#elif defined(__APPLE__)
    rusage_info_v4 usage{};
    if (proc_pid_rusage(process.Pid, RUSAGE_INFO_V4,
                        reinterpret_cast<rusage_info_t*>(&usage)) != 0)
        return 0;
    // The child resets this interval after exec and before publishing ready.
    // Unlike lifetime ru_maxrss, the interval peak excludes the spawning
    // parent's vfork image and remains monotonic across allocation/free.
    return static_cast<std::uint64_t>(
               usage.ri_interval_max_phys_footprint) / 1024u;
#else
    std::ifstream input("/proc/" + std::to_string(process.Pid) + "/status");
    std::string key;
    while (input >> key) {
        if (key != "VmHWM:") {
            std::string ignored;
            std::getline(input, ignored);
            continue;
        }
        std::uint64_t peak_kib = 0;
        std::string unit;
        if (input >> peak_kib >> unit && unit == "kB") return peak_kib;
        return 0;
    }
    return 0;
#endif
}

bool publishParentMarker(const std::filesystem::path& path,
                         std::string& error) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        error = "cannot create resource-control acknowledgement";
        return false;
    }
    output << "1\n";
    output.flush();
    if (!output.good()) {
        error = "cannot write resource-control acknowledgement";
        return false;
    }
    return true;
}

bool terminateProcess(const llvm::sys::ProcessInfo& process) {
#ifdef _WIN32
    return TerminateProcess(static_cast<HANDLE>(process.Process),
                            static_cast<UINT>(-2)) != 0 ||
           GetLastError() == ERROR_ACCESS_DENIED;
#else
    return ::kill(process.Pid, SIGKILL) == 0 || errno == ESRCH;
#endif
}

} // anonymous namespace

ResourceRunResult ResourceSupervisor::run(
    const std::string& program,
    const std::vector<std::string>& arguments,
    ResourceLimits limits) {
    ResourceRunResult result;
    llvm::SmallString<128> unique_directory;
    const std::error_code directory_error =
        llvm::sys::fs::createUniqueDirectory("codeskeptic-resource-worker",
                                             unique_directory);
    if (directory_error) {
        result.error = "cannot create resource-control directory: " +
                       directory_error.message();
        result.status = ResourceRunStatus::LaunchFailed;
        return result;
    }
    const std::filesystem::path control_directory(
        unique_directory.str().str());
    const auto cleanup_control = [&control_directory]() {
        std::error_code ignored;
        std::filesystem::remove_all(control_directory, ignored);
    };

    std::vector<std::string> storage;
    storage.reserve(arguments.size() + 3);
    storage.push_back(program);
    storage.insert(storage.end(), arguments.begin(), arguments.end());
    storage.push_back(std::string(kResourceControlArgument) +
                      control_directory.string());
#ifdef _WIN32
    const std::uint64_t supervisor_pid = GetCurrentProcessId();
#else
    const std::uint64_t supervisor_pid = static_cast<std::uint64_t>(getpid());
#endif
    storage.push_back(std::string(kResourceParentArgument) +
                      std::to_string(supervisor_pid));

    std::vector<llvm::StringRef> args;
    args.reserve(storage.size());
    for (const auto& value : storage) args.emplace_back(value);

    std::string error;
    bool execution_failed = false;
    const auto started = std::chrono::steady_clock::now();
    const llvm::sys::ProcessInfo process = llvm::sys::ExecuteNoWait(
        program, args, std::nullopt, {}, 0, &error, &execution_failed);
    if (execution_failed || process.Pid == llvm::sys::ProcessInfo::InvalidPid) {
        result.error = error.empty()
            ? "missing or unexecutable worker: " + program
            : "missing or unexecutable worker: " + program + ": " + error;
        result.status = ResourceRunStatus::LaunchFailed;
        cleanup_control();
        return result;
    }

    const auto deadline = started +
        std::chrono::seconds(limits.timeout_seconds);
    const std::uint64_t memory_limit_kib =
        static_cast<std::uint64_t>(limits.memory_mib) * 1024u;
    bool timed_out = false;
    bool memory_exceeded = false;
    bool handshake_ready = false;
    bool completion_seen = false;
    bool handshake_failed = false;
    llvm::sys::ProcessInfo completed;
    for (;;) {
        const auto observed_at = std::chrono::steady_clock::now();
        if (limits.timeout_seconds > 0 && observed_at >= deadline) {
            timed_out = true;
            if (!terminateProcess(process))
                error = "failed to terminate timed-out worker";
            break;
        }

        if (!handshake_ready) {
            std::error_code marker_error;
            const bool ready = std::filesystem::exists(
                control_directory / "ready", marker_error);
            if (marker_error) {
                handshake_failed = true;
                error = "cannot observe resource-control marker: " +
                        marker_error.message();
                if (!terminateProcess(process) && error.empty())
                    error = "failed to terminate unobservable worker";
                break;
            }
            if (ready) {
                const std::uint64_t memory = residentMemoryKiB(process);
                if (memory == 0) {
                    handshake_failed = true;
                    error = "cannot sample ready worker resident memory";
                    if (!terminateProcess(process) && error.empty())
                        error = "failed to terminate unsampled worker";
                    break;
                }
                result.peak_memory_kib = memory;
                if (memory_limit_kib > 0 && memory > memory_limit_kib) {
                    memory_exceeded = true;
                    if (!terminateProcess(process))
                        error = "failed to terminate memory-exceeded worker";
                    break;
                }
                if (!publishParentMarker(control_directory / "go", error)) {
                    handshake_failed = true;
                    if (!terminateProcess(process) && error.empty())
                        error = "failed to terminate unacknowledged worker";
                    break;
                }
                handshake_ready = true;
            }
        } else {
            const std::uint64_t memory = residentMemoryKiB(process);
            if (memory > 0)
                result.peak_memory_kib =
                    std::max(result.peak_memory_kib, memory);
            if (memory_limit_kib > 0 && memory > memory_limit_kib) {
                memory_exceeded = true;
                if (!terminateProcess(process))
                    error = "failed to terminate memory-exceeded worker";
                break;
            }
            std::error_code marker_error;
            const bool done = std::filesystem::exists(
                control_directory / "done", marker_error);
            if (marker_error) {
                handshake_failed = true;
                error = "cannot observe worker completion marker: " +
                        marker_error.message();
                if (!terminateProcess(process))
                    error += "; failed to terminate unobservable worker";
                break;
            }
            if (done &&
                !std::filesystem::exists(control_directory / "finish")) {
                completion_seen = true;
                if (!publishParentMarker(control_directory / "finish", error)) {
                    handshake_failed = true;
                    if (!terminateProcess(process))
                        error += "; failed to terminate unacknowledged worker";
                    break;
                }
            }
        }

        std::string wait_error;
        completed = llvm::sys::Wait(process, 0u, &wait_error, nullptr, true);
        if (completed.Pid != llvm::sys::ProcessInfo::InvalidPid) {
            if (!wait_error.empty()) error = std::move(wait_error);
            if (!handshake_ready) {
                handshake_failed = true;
                if (error.empty())
                    error = "worker exited before resource-control handshake";
            } else if (!completion_seen) {
                handshake_failed = true;
                if (error.empty())
                    error = "worker exited before completion handshake";
            }
            if (limits.timeout_seconds > 0 &&
                std::chrono::steady_clock::now() >= deadline)
                timed_out = true;
            break;
        }
        std::this_thread::sleep_for(kPollInterval);
    }

    if (timed_out || memory_exceeded || handshake_failed) {
        if (completed.Pid == llvm::sys::ProcessInfo::InvalidPid) {
            std::string wait_error;
            completed = llvm::sys::Wait(process, 1u, &wait_error, nullptr);
            if (!wait_error.empty()) {
                if (!error.empty()) error += "; ";
                error += wait_error;
            }
        }
        result.exit_code = -2;
    } else {
        result.exit_code = completed.ReturnCode;
    }
    result.duration_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started).count());
    result.error = std::move(error);
    cleanup_control();

    if (timed_out) {
        result.status = ResourceRunStatus::TimedOut;
    } else if (memory_exceeded ||
               result.exit_code == kMemoryLimitExitCode) {
        result.status = ResourceRunStatus::MemoryExceeded;
    } else if (handshake_failed) {
        result.status = ResourceRunStatus::Crashed;
    } else if (result.exit_code < 0) {
        result.status = ResourceRunStatus::Crashed;
    } else {
        result.status = ResourceRunStatus::Completed;
    }
    return result;
}

} // namespace codeskeptic
