#include "core/ResourceWorkerControl.h"

#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef __APPLE__
#include <dlfcn.h>
#endif

namespace codeskeptic {

namespace {

constexpr auto kHandshakePollInterval = std::chrono::milliseconds(1);

bool resetPostExecMemoryPeak(std::string& error) {
#ifdef __APPLE__
    using ResetFootprintInterval = int (*)(pid_t);
    void* symbol = dlsym(RTLD_DEFAULT, "proc_reset_footprint_interval");
    if (symbol == nullptr) {
        error = "Darwin post-exec footprint reset is unavailable";
        return false;
    }
    const auto reset = reinterpret_cast<ResetFootprintInterval>(symbol);
    if (reset(getpid()) != 0) {
        error = "cannot reset Darwin post-exec footprint peak: " +
                std::string(std::strerror(errno));
        return false;
    }
#else
    (void)error;
#endif
    return true;
}

bool publishMarker(const std::filesystem::path& path, std::string& error) {
    const std::filesystem::path temporary = path.string() + ".tmp";
    std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
    if (!output) {
        error = "cannot create resource-control marker";
        return false;
    }
    output << "1\n";
    output.flush();
    if (!output.good()) {
        error = "cannot write resource-control marker";
        return false;
    }
    output.close();
    std::error_code ec;
    std::filesystem::rename(temporary, path, ec);
    if (ec) {
        error = "cannot publish resource-control marker: " + ec.message();
        return false;
    }
    return true;
}

std::filesystem::path& activeControlDirectory() {
    static std::filesystem::path directory;
    return directory;
}

std::uint64_t& activeParentPid() {
    static std::uint64_t pid = 0;
    return pid;
}

bool parentIsAlive(std::uint64_t pid) {
    if (pid == 0) return false;
#ifdef _WIN32
    if (pid > static_cast<std::uint64_t>(MAXDWORD)) return false;
    HANDLE parent = OpenProcess(SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
    if (parent == nullptr) return false;
    const DWORD state = WaitForSingleObject(parent, 0);
    CloseHandle(parent);
    return state == WAIT_TIMEOUT;
#else
    if (pid > static_cast<std::uint64_t>(
                  std::numeric_limits<pid_t>::max()))
        return false;
    const int result = ::kill(static_cast<pid_t>(pid), 0);
    return result == 0 || errno == EPERM;
#endif
}

void announceCompletion() {
    const std::filesystem::path& directory = activeControlDirectory();
    if (directory.empty()) return;
    std::string ignored;
    if (!publishMarker(directory / "done", ignored)) return;

    const std::filesystem::path finish = directory / "finish";
    for (;;) {
        std::error_code ec;
        if (std::filesystem::exists(finish, ec) || ec) return;
        if (!parentIsAlive(activeParentPid())) return;
        std::this_thread::sleep_for(kHandshakePollInterval);
    }
}

void watchSupervisor() {
    for (;;) {
        if (!parentIsAlive(activeParentPid())) std::_Exit(72);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

} // anonymous namespace

ResourceWorkerInitialization initializeResourceWorker(
    int& argc, char** argv, std::string& error) {
    std::string control_directory;
    std::uint64_t parent_pid = 0;
    int write_index = 1;
    const std::string control_prefix = kResourceControlArgument;
    const std::string parent_prefix = kResourceParentArgument;
    for (int read_index = 1; read_index < argc; ++read_index) {
        const std::string argument = argv[read_index];
        if (argument.rfind(control_prefix, 0) == 0) {
            if (!control_directory.empty()) {
                error = "duplicate resource-control argument";
                return ResourceWorkerInitialization::Failed;
            }
            control_directory = argument.substr(control_prefix.size());
            if (control_directory.empty()) {
                error = "empty resource-control directory";
                return ResourceWorkerInitialization::Failed;
            }
            continue;
        }
        if (argument.rfind(parent_prefix, 0) == 0) {
            if (parent_pid != 0) {
                error = "duplicate resource-parent argument";
                return ResourceWorkerInitialization::Failed;
            }
            const std::string value = argument.substr(parent_prefix.size());
            char* end = nullptr;
            errno = 0;
            const unsigned long long parsed = std::strtoull(
                value.c_str(), &end, 10);
            if (value.empty() || errno != 0 || end == value.c_str() ||
                *end != '\0' || parsed == 0) {
                error = "invalid resource-parent process id";
                return ResourceWorkerInitialization::Failed;
            }
            parent_pid = static_cast<std::uint64_t>(parsed);
            continue;
        }
        {
            argv[write_index++] = argv[read_index];
        }
    }
    if (control_directory.empty() && parent_pid == 0)
        return ResourceWorkerInitialization::Unsupervised;
    if (control_directory.empty() || parent_pid == 0) {
        error = "incomplete resource-control arguments";
        return ResourceWorkerInitialization::Failed;
    }

    argc = write_index;
    argv[write_index] = nullptr;
    const std::filesystem::path directory(control_directory);
    std::error_code ec;
    if (!std::filesystem::is_directory(directory, ec) || ec) {
        error = "invalid resource-control directory";
        return ResourceWorkerInitialization::Failed;
    }
    if (!resetPostExecMemoryPeak(error))
        return ResourceWorkerInitialization::Failed;
    if (!publishMarker(directory / "ready", error))
        return ResourceWorkerInitialization::Failed;

    const std::filesystem::path go = directory / "go";
    for (;;) {
        ec.clear();
        if (std::filesystem::exists(go, ec)) {
            activeControlDirectory() = directory;
            activeParentPid() = parent_pid;
            if (std::atexit(announceCompletion) != 0) {
                error = "cannot register resource-control completion marker";
                return ResourceWorkerInitialization::Failed;
            }
            try {
                std::thread(watchSupervisor).detach();
            } catch (const std::exception& exception) {
                error = "cannot start resource supervisor watcher: " +
                        std::string(exception.what());
                return ResourceWorkerInitialization::Failed;
            }
            return ResourceWorkerInitialization::Ready;
        }
        if (ec) {
            error = "cannot observe resource-control acknowledgement: " +
                    ec.message();
            return ResourceWorkerInitialization::Failed;
        }
        if (!parentIsAlive(parent_pid)) {
            error = "resource supervisor exited before acknowledgement";
            return ResourceWorkerInitialization::Failed;
        }
        std::this_thread::sleep_for(kHandshakePollInterval);
    }
}

} // namespace codeskeptic
