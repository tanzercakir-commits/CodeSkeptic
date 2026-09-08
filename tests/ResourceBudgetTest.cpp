#include "core/ResourceBudget.h"
#include "analyzer/AnalysisCoordinator.h"
#include <chrono>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <csignal>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifdef __APPLE__
#include <cerrno>
#include <cstdio>
#include <limits>
#include <mach/mach.h>
#include <sys/mman.h>
#include <sys/resource.h>
#endif

#ifdef CODESKEPTIC_RESOURCE_TEST_CHILD

#ifdef __APPLE__
bool darwinSnapshot(std::uint64_t& bytes) {
    mach_task_basic_info_data_t value{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    const auto status = task_info(mach_task_self(), MACH_TASK_BASIC_INFO,
        reinterpret_cast<task_info_t>(&value), &count);
    bytes = value.virtual_size;
    return status == KERN_SUCCESS && count == MACH_TASK_BASIC_INFO_COUNT && bytes != 0;
}

int darwinMappingLimit(const std::string& inherited_mode) {
    constexpr std::uint64_t mib = 1024 * 1024;
    constexpr std::size_t large = 192 * mib, small = 8 * mib;
    constexpr int protection = PROT_READ | PROT_WRITE, flags = MAP_PRIVATE | MAP_ANON;
    auto fail = [](int stage) {
        std::fprintf(stderr, "darwin-native-budget failure_stage=%d errno=%d\n", stage, errno);
        return stage;
    };
    // Same-request positive control BEFORE lowering any cap. Reserve address
    // space only: do not touch 192 MiB of physical pages. Missing control fails.
    void* control = mmap(nullptr, large, protection, flags, -1, 0);
    if (control == MAP_FAILED) return fail(70);
    if (munmap(control, large) != 0) return fail(71);
    std::fprintf(stdout, "darwin-native-budget precontrol_bytes=%zu passed=1\n", large);
    struct rlimit inherited{};
    if (getrlimit(RLIMIT_AS, &inherited) != 0) return fail(72);
    if (inherited_mode != "none") {
        std::uint64_t baseline = 0;
        if (!darwinSnapshot(baseline) || baseline >= RLIM_INFINITY - 96*mib) return fail(73);
        const bool soft_only = inherited_mode == "soft";
        if (!soft_only && inherited_mode != "hard") return fail(74);
        rlim_t soft = static_cast<rlim_t>(baseline + (soft_only ? 32 : 64)*mib);
        rlim_t hard = static_cast<rlim_t>(baseline + (soft_only ? 96 : 64)*mib);
        // Never raise either inherited host limit, even in the test child.
        if (inherited.rlim_max != RLIM_INFINITY) hard = std::min(hard, inherited.rlim_max);
        if (inherited.rlim_cur != RLIM_INFINITY) soft = std::min(soft, inherited.rlim_cur);
        soft = std::min(soft, hard);
        inherited = {soft, hard};
        if (setrlimit(RLIMIT_AS, &inherited) != 0) return fail(75);
    }
    codeskeptic::WorkerMemoryLimit cap;
    std::string error;
    if (!cap.apply(128, error)) {
        std::fprintf(stderr, "%s\n", error.c_str());
        return fail(76);
    }
    struct rlimit installed{};
    if (getrlimit(RLIMIT_AS, &installed) != 0 || installed.rlim_cur == RLIM_INFINITY ||
        installed.rlim_cur != installed.rlim_max || installed.rlim_cur == 0) return fail(77);
    if ((inherited.rlim_cur != RLIM_INFINITY && installed.rlim_cur > inherited.rlim_cur) ||
        (inherited.rlim_max != RLIM_INFINITY && installed.rlim_max > inherited.rlim_max)) return fail(78);
    if (inherited_mode != "none" && installed.rlim_cur != inherited.rlim_cur) return fail(79);
    void* positive = mmap(nullptr, small, protection, flags, -1, 0);
    if (positive == MAP_FAILED) return fail(80);
    struct ReleasePositive {
        void* address;
        ~ReleasePositive() { munmap(address, small); }
    } release{positive};
    const long page = sysconf(_SC_PAGESIZE);
    if (page <= 0 || static_cast<std::size_t>(page) > small) return fail(81);
    auto* touched = static_cast<volatile unsigned char*>(positive);
    for (std::size_t offset = 0; offset < small; offset += static_cast<std::size_t>(page))
        touched[offset] = 0x5a; // Volatile: an optimizing build must perform touches.
    std::uint64_t current = 0;
    if (!darwinSnapshot(current) || current > installed.rlim_cur ||
        large <= installed.rlim_cur - current) return fail(82);
    errno = 0;
    void* rejected = mmap(nullptr, large, protection, flags, -1, 0);
    const int denial_errno = errno;
    if (rejected != MAP_FAILED) {
        munmap(rejected, large); // Unexpected success must not touch host RAM.
        return fail(83);
    }
    if (denial_errno != ENOMEM) return fail(84);
    std::fprintf(stdout, "darwin-native-budget target_bytes=%llu observed_bytes=%llu "
        "positive_bytes=%zu refused_bytes=%zu denial_errno=%d\n",
        static_cast<unsigned long long>(installed.rlim_cur),
        static_cast<unsigned long long>(current), small, large, denial_errno);
    return 0;
}
#endif

int consumeMemory(unsigned memory_mb) {
    codeskeptic::WorkerMemoryLimit cap;
    std::string error;
    if (!cap.apply(memory_mb, error)) return 90;
    try {
        std::vector<std::unique_ptr<char[]>> blocks;
        for (unsigned i = 0; i < 1024; ++i) {
            auto block = std::make_unique<char[]>(1024 * 1024);
            std::memset(block.get(), static_cast<int>(i), 1024 * 1024);
            blocks.push_back(std::move(block));
        }
    } catch (const std::bad_alloc&) { return 91; }
    return 0;
}

// These synthetic workloads live only in a separately built test executable.
// The production executable contains no filename-based fault injection.
int main(int argc, char** argv) {
    using namespace codeskeptic;
    if (argc == 4 && std::string(argv[1]) == "--codeskeptic-worker-v1") {
        std::string packet, error;
        WorkerRequest request;
        if (!readWorkerPacket(argv[2], packet, error) || !decodeWorkerRequest(packet, request, error)) return 2;
        const auto name = std::filesystem::path(request.source).filename().string();
        if (name.find("budget-sleep.") != std::string::npos) {
            std::ofstream(request.source + ".started") << "started\n";
            std::this_thread::sleep_for(std::chrono::seconds(30));
            return 0;
        }
        if (name.find("budget-memory.") != std::string::npos) return consumeMemory(request.memory_mb);
        const auto status = runAnalysisWorker(argv[2], argv[3]);
        if (status != 0) return status;
        if (name.find("budget-no-ack.") != std::string::npos)
            std::filesystem::remove(std::string(argv[3]) + ".limits");
        if (name.find("budget-wrong-ack.") != std::string::npos)
            std::ofstream(std::string(argv[3]) + ".limits") << "codeskeptic-worker-memory/v1 16\n";
        return 0;
    }
    if (argc != 4) return 2;
    const std::string mode(argv[1]);
    std::ofstream(argv[3]) << "started\n";
#ifdef __APPLE__
    if (mode == "darwin-mapping") return darwinMappingLimit(argv[2]);
#endif
    if (mode == "sleep") {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        return 0;
    }
    if (mode == "exit") return std::atoi(argv[2]);
    if (mode == "crash") std::abort();
    if (mode != "memory") return 2;
    // Actual allocation AND touches, not just a synthetic return code. The
    // tested low cap prevents these allocations from approaching host limits.
    return consumeMemory(static_cast<unsigned>(std::strtoul(argv[2], nullptr, 10)));
}

#else

#include "config/Config.h"
#include "server/McpServer.h"
#include <gtest/gtest.h>
#include <llvm/ADT/SmallString.h>
#include <llvm/Support/FileSystem.h>
#include <future>
#include <iostream>
#include <sstream>
#include <llvm/Support/JSON.h>
#include <llvm/Support/raw_ostream.h>
#ifdef __linux__
#include <fcntl.h>
#include <poll.h>
#include <sys/syscall.h>
#endif

namespace {
using namespace codeskeptic;
namespace fs = std::filesystem;

class ResourceBudgetTest : public ::testing::Test {
protected:
    fs::path root;
    std::unique_ptr<WorkerSignalScope> signals;
    void SetUp() override {
        signals = std::make_unique<WorkerSignalScope>();
        llvm::SmallString<256> path;
        ASSERT_FALSE(llvm::sys::fs::createUniqueDirectory("codeskeptic-resource-test", path));
        root = path.str().str();
    }
    void TearDown() override {
        std::error_code error;
        if (!root.empty()) fs::remove_all(root, error);
        EXPECT_FALSE(error);
    }
    ResourceProcessResult child(const std::string& mode, const std::string& value,
                               WorkerLimits limits = {}, const ResourceCancellation* token = nullptr) {
        const std::string binary = CODESKEPTIC_RESOURCE_FIXTURE_PATH;
        return runResourceWorker(binary, {binary, mode, value, (root / "started").string()},
            {{"", (root / "stdout").string(), (root / "stderr").string()}}, limits, token);
    }
};

TEST_F(ResourceBudgetTest, TimeoutStopsAndReapsAnActualSleepingChild) {
    const auto start = std::chrono::steady_clock::now();
    const auto result = child("sleep", "0", {150, 2048});
    EXPECT_EQ(result.stop, ResourceStop::Timeout);
    EXPECT_TRUE(fs::exists(root / "started"));
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));
}

TEST_F(ResourceBudgetTest, TokenCancellationStopsAChildThatHasActuallyStarted) {
    ResourceCancellation token;
    auto canceller = std::async(std::launch::async, [&] {
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (!fs::exists(root / "started") && std::chrono::steady_clock::now() < until)
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        const bool started = fs::exists(root / "started");
        token.request();
        return started;
    });
    const auto result = child("sleep", "0", {5000, 2048}, &token);
    EXPECT_TRUE(canceller.get());
    EXPECT_EQ(result.stop, ResourceStop::Cancelled);
}

TEST_F(ResourceBudgetTest, AlreadyCancelledTokenDoesNotLaunch) {
    ResourceCancellation token;
    token.request();
    EXPECT_EQ(child("exit", "0", {}, &token).stop, ResourceStop::Cancelled);
    EXPECT_FALSE(fs::exists(root / "started"));
}

TEST_F(ResourceBudgetTest, UnrelatedPriorCancellationDoesNotTerminateAFreshMcpSession) {
    ResourceCancellation token;
    token.request();
    ASSERT_EQ(child("exit", "0", {}, &token).stop, ResourceStop::Cancelled);
    std::istringstream input("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n"
                             "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n");
    std::ostringstream output;
    struct RestoreStreams {
        std::streambuf* input;
        std::streambuf* output;
        ~RestoreStreams() {
            std::cin.rdbuf(input); std::cin.clear();
            std::cout.rdbuf(output); std::cout.clear();
        }
    } restore{std::cin.rdbuf(input.rdbuf()), std::cout.rdbuf(output.rdbuf())};
    EXPECT_EQ(runMcpServer(), 0);
    const auto frames = output.str();
    EXPECT_NE(frames.find("\"id\":1"), std::string::npos);
    EXPECT_NE(frames.find("\"id\":2"), std::string::npos);
    EXPECT_EQ(std::count(frames.begin(), frames.end(), '\n'), 2);
}

TEST_F(ResourceBudgetTest, RealNativeMemoryCapRejectsTouchedAllocations) {
    const auto result = child("memory", "128", {5000, 128});
    ASSERT_EQ(result.stop, ResourceStop::Exited) << result.detail;
    EXPECT_EQ(result.exit_code, 91);
    EXPECT_TRUE(fs::exists(root / "started"));
    const auto setup = child("memory", "0");
    ASSERT_EQ(setup.stop, ResourceStop::Exited);
    EXPECT_EQ(setup.exit_code, 90);
}

#ifdef __APPLE__
TEST_F(ResourceBudgetTest, DarwinFiniteCeilingHasPositiveControlAndKernelMappingDenial) {
    struct rlimit before{}, after{};
    ASSERT_EQ(getrlimit(RLIMIT_AS, &before), 0);
    const auto result = child("darwin-mapping", "none", {5000, 128});
    std::ifstream errors(root / "stderr"), output(root / "stdout");
    const std::string detail{std::istreambuf_iterator<char>(errors), {}};
    std::cout << std::string(std::istreambuf_iterator<char>(output), {});
    EXPECT_EQ(result.stop, ResourceStop::Exited) << result.detail << detail;
    EXPECT_EQ(result.exit_code, 0) << detail;
    ASSERT_EQ(getrlimit(RLIMIT_AS, &after), 0);
    EXPECT_EQ(after.rlim_cur, before.rlim_cur);
    EXPECT_EQ(after.rlim_max, before.rlim_max);
}

TEST_F(ResourceBudgetTest, DarwinRetainsStricterInheritedSoftAndHardCeilings) {
    struct rlimit before{}, after{};
    ASSERT_EQ(getrlimit(RLIMIT_AS, &before), 0);
    for (const std::string mode : {"soft", "hard"}) {
        SCOPED_TRACE(mode);
        const auto result = child("darwin-mapping", mode, {5000, 128});
        std::ifstream errors(root / "stderr"), output(root / "stdout");
        const std::string detail{std::istreambuf_iterator<char>(errors), {}};
        std::cout << std::string(std::istreambuf_iterator<char>(output), {});
        EXPECT_EQ(result.stop, ResourceStop::Exited) << result.detail << detail;
        EXPECT_EQ(result.exit_code, 0) << detail;
        ASSERT_EQ(getrlimit(RLIMIT_AS, &after), 0);
        EXPECT_EQ(after.rlim_cur, before.rlim_cur);
        EXPECT_EQ(after.rlim_max, before.rlim_max);
    }
}
#endif

TEST_F(ResourceBudgetTest, SuccessNonzeroCrashAndLaunchFailureRemainDistinct) {
    for (int code : {0, 7}) {
        const auto result = child("exit", std::to_string(code));
        EXPECT_EQ(result.stop, ResourceStop::Exited);
        EXPECT_EQ(result.exit_code, code);
    }
    EXPECT_EQ(child("crash", "0").stop, ResourceStop::Crashed);
    const auto missing = (root / "does-not-exist").string();
    EXPECT_EQ(runResourceWorker(missing, {missing}, {{"", "", ""}}, {}).stop,
              ResourceStop::LaunchFailed);
}

TEST_F(ResourceBudgetTest, LimitsAreStrictAndConfigurationUpdatesAreTransactional) {
    auto parse = [](Config& config, std::vector<std::string> values) {
        std::vector<char*> raw;
        for (auto& value : values) raw.push_back(value.data());
        return config.parseArgs(static_cast<int>(raw.size()), raw.data());
    };
    Config config;
    EXPECT_EQ(config.workerLimits().timeout_ms, 120000u);
    EXPECT_EQ(config.workerLimits().memory_mb, 2048u);
    ASSERT_TRUE(parse(config, {"codeskeptic", "source.cpp", "--worker-timeout-ms", "250",
                              "--worker-memory-mb", "512"}));
    for (const std::string value : {"0", "-1", "+1", "1.5", "1ms", "3600001", "999999999999999999"}) {
        EXPECT_FALSE(parse(config, {"codeskeptic", "--worker-memory-mb", "1024", "--worker-timeout-ms", value}));
        EXPECT_EQ(config.workerLimits().timeout_ms, 250u);
        EXPECT_EQ(config.workerLimits().memory_mb, 512u);
    }
    for (const std::string value : {"0", "15", "65537", " 128", "128 ", "nan"})
        EXPECT_FALSE(parse(config, {"codeskeptic", "--worker-memory-mb", value}));
    EXPECT_FALSE(parse(config, {"codeskeptic", "--worker-timeout-ms"}));
    const auto path = root / "settings.conf";
    std::ofstream(path) << "worker_timeout_ms=333\nworker_memory_mb=768\n";
    ASSERT_TRUE(config.loadFromFile(path.string()));
    Config request;
    request.inheritWorkerLimits(config);
    EXPECT_EQ(request.workerLimits().timeout_ms, 333u);
    EXPECT_EQ(request.workerLimits().memory_mb, 768u);
    EXPECT_TRUE(request.sourcePath().empty());
    std::ofstream(path) << "worker_timeout_ms=444\nworker_memory_mb=0\n";
    EXPECT_FALSE(config.loadFromFile(path.string()));
    EXPECT_EQ(config.workerLimits().timeout_ms, 333u);
}

TEST_F(ResourceBudgetTest, MemoryLimitIsValidatedAndBoundToTheExactWorkerRequest) {
    WorkerRequest request;
    request.source = (root / "input.cpp").string();
    request.build_directory = root.string();
    request.commands.emplace_back(root.string(), request.source,
        std::vector<std::string>{"clang++", "-c", request.source}, "");
    const auto original = workerRequestDigest(encodeWorkerRequest(request));
    request.memory_mb = 512;
    EXPECT_NE(workerRequestDigest(encodeWorkerRequest(request)), original);
    WorkerRequest decoded;
    std::string error;
    ASSERT_TRUE(decodeWorkerRequest(encodeWorkerRequest(request), decoded, error));
    EXPECT_EQ(decoded.memory_mb, 512u);
    request.memory_mb = 15;
    decoded.source = "preserve";
    EXPECT_FALSE(decodeWorkerRequest(encodeWorkerRequest(request), decoded, error));
    EXPECT_EQ(decoded.source, "preserve");
}

#ifndef _WIN32
TEST_F(ResourceBudgetTest, TimeoutDoesNotReapAnUnrelatedSibling) {
    const pid_t sibling = ::fork();
    ASSERT_GE(sibling, 0);
    if (sibling == 0) { ::usleep(50000); ::_exit(42); }
    const auto result = child("sleep", "0", {200, 2048});
    int status = 0;
    const auto waited = ::waitpid(sibling, &status, 0);
    EXPECT_EQ(result.stop, ResourceStop::Timeout);
    ASSERT_EQ(waited, sibling);
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(WEXITSTATUS(status), 42);
}

void alarmMarker(int) {}
TEST_F(ResourceBudgetTest, PollingPreservesExistingAlarmHandlerAndTimer) {
    struct Restore {
        struct sigaction saved{};
        Restore() { sigaction(SIGALRM, nullptr, &saved); }
        ~Restore() { alarm(0); sigaction(SIGALRM, &saved, nullptr); }
    } restore;
    struct sigaction action{};
    action.sa_handler = alarmMarker;
    sigemptyset(&action.sa_mask);
    ASSERT_EQ(sigaction(SIGALRM, &action, nullptr), 0);
    alarm(10);
    EXPECT_EQ(child("sleep", "0", {50, 2048}).stop, ResourceStop::Timeout);
    struct sigaction observed{};
    ASSERT_EQ(sigaction(SIGALRM, nullptr, &observed), 0);
    EXPECT_EQ(observed.sa_handler, alarmMarker);
    EXPECT_GT(alarm(0), 0u);
}
#endif

#if defined(__linux__) || defined(_WIN32)
TEST_F(ResourceBudgetTest, RepeatedTerminationsDoNotLeakDescriptorsOrHandles) {
    auto count = []() -> std::size_t {
#ifdef _WIN32
        DWORD value = 0;
        EXPECT_TRUE(GetProcessHandleCount(GetCurrentProcess(), &value));
        return value;
#else
        return static_cast<std::size_t>(std::distance(fs::directory_iterator("/proc/self/fd"),
                                                       fs::directory_iterator{}));
#endif
    };
    // Initialize dynamic-library/runtime machinery before taking the baseline.
    EXPECT_EQ(child("exit", "0").exit_code, 0);
    const auto before = count();
    for (int repeat = 0; repeat < 8; ++repeat)
        EXPECT_EQ(child("sleep", "0", {50, 2048}).stop, ResourceStop::Timeout);
    EXPECT_EQ(count(), before);
}
#endif

#ifdef __linux__
// Linux-only end-to-end control, not a native Windows qualification claim.
// Pipes stay open while testing active cancellation; EOF cannot hide a server
// that incorrectly waits for another request after completing cancellation.
class McpPipe {
public:
    explicit McpPipe(const fs::path& errors, std::vector<std::string> options = {}) {
        int input[2], output[2];
        if (pipe2(input, O_CLOEXEC) != 0) throw std::runtime_error("input pipe");
        if (pipe2(output, O_CLOEXEC) != 0) {
            close(input[0]); close(input[1]); throw std::runtime_error("output pipe");
        }
        const int log = open(errors.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (log < 0) {
            for (int fd : {input[0], input[1], output[0], output[1]}) close(fd);
            throw std::runtime_error("error log");
        }
        std::vector<std::string> storage{CODESKEPTIC_BINARY_PATH, "--serve"};
        storage.insert(storage.end(), options.begin(), options.end());
        std::vector<char*> argv;
        for (auto& value : storage) argv.push_back(value.data());
        argv.push_back(nullptr);
        pid_ = fork();
        if (pid_ == 0) {
            if (dup2(input[0], STDIN_FILENO) < 0 || dup2(output[1], STDOUT_FILENO) < 0 ||
                dup2(log, STDERR_FILENO) < 0) _exit(126);
            for (int fd : {input[0], input[1], output[0], output[1], log}) close(fd);
            execv(argv[0], argv.data());
            _exit(127);
        }
        close(input[0]); close(output[1]); close(log);
        if (pid_ < 0) { close(input[1]); close(output[0]); throw std::runtime_error("server fork"); }
        input_ = input[1]; output_ = output[0];
    }
    ~McpPipe() {
        if (input_ >= 0) close(input_);
        if (pid_ > 0) {
            kill(pid_, SIGTERM);
            const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(2);
            int status;
            pid_t result = 0;
            while ((result = waitpid(pid_, &status, WNOHANG)) == 0 && std::chrono::steady_clock::now() < until)
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            if (result == 0) { kill(pid_, SIGKILL); while (waitpid(pid_, &status, 0) < 0 && errno == EINTR) {} }
        }
        // Descriptor pins the exact observed descendant, never a recycled PID.
        // Normal successful cancellation has already killed/reaped it.
        if (worker_fd_ >= 0) {
            syscall(SYS_pidfd_send_signal, worker_fd_, SIGKILL, nullptr, 0);
            close(worker_fd_);
        }
        if (output_ >= 0) close(output_);
    }
    void send(const std::string& text) {
        std::size_t offset = 0;
        while (offset < text.size()) {
            const auto count = write(input_, text.data() + offset, text.size() - offset);
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) throw std::runtime_error("server input write");
            offset += static_cast<std::size_t>(count);
        }
    }
    std::string line() {
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        while (buffer_.find('\n') == std::string::npos && std::chrono::steady_clock::now() < until) {
            struct pollfd event{output_, POLLIN, 0};
            if (poll(&event, 1, 50) <= 0) continue;
            char bytes[4096];
            const auto count = read(output_, bytes, sizeof(bytes));
            if (count <= 0) break;
            buffer_.append(bytes, static_cast<std::size_t>(count));
        }
        const auto end = buffer_.find('\n');
        if (end == std::string::npos) throw std::runtime_error("missing complete server frame");
        const auto result = buffer_.substr(0, end);
        buffer_.erase(0, end + 1);
        return result;
    }
    pid_t observeWorker() {
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < until) {
            pid_t child = 0;
            std::ifstream("/proc/" + std::to_string(pid_) + "/task/" + std::to_string(pid_) + "/children") >> child;
            if (child > 0) {
                worker_fd_ = static_cast<int>(syscall(SYS_pidfd_open, child, 0));
                if (worker_fd_ >= 0) return child;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
        throw std::runtime_error("no owned worker observed");
    }
    void interrupt() { if (kill(pid_, SIGINT) != 0) throw std::runtime_error("server interrupt"); }
    void eof() { close(input_); input_ = -1; }
    int finish() {
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
        int status = 0;
        while (std::chrono::steady_clock::now() < until) {
            const auto result = waitpid(pid_, &status, WNOHANG);
            if (result == pid_) { pid_ = 0; return WIFEXITED(status) ? WEXITSTATUS(status) : -1; }
            if (result < 0 && errno != EINTR) throw std::runtime_error("server wait");
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        throw std::runtime_error("server did not exit with input still open");
    }
private:
    pid_t pid_ = 0;
    int input_ = -1, output_ = -1, worker_fd_ = -1;
    std::string buffer_;
};

std::string analyzeFrame(const fs::path& source, int id = 1) {
    std::string text;
    llvm::raw_string_ostream stream(text);
    stream << llvm::json::Value(llvm::json::Object{{"jsonrpc", "2.0"}, {"id", id},
        {"method", "tools/call"}, {"params", llvm::json::Object{{"name", "analyze"},
            {"arguments", llvm::json::Object{{"path", source.string()}}}}}}) << '\n';
    return text;
}

void checkFailedMcpAnalysis(const std::string& frame, const std::string& reason = {}) {
    auto envelope = llvm::json::parse(frame);
    ASSERT_TRUE(static_cast<bool>(envelope));
    ASSERT_NE(envelope->getAsObject(), nullptr);
    const auto* result = envelope->getAsObject()->getObject("result");
    ASSERT_NE(result, nullptr) << frame;
    const auto* content = result->getArray("content");
    ASSERT_NE(content, nullptr);
    ASSERT_EQ(content->size(), 1u);
    ASSERT_NE(content->front().getAsObject(), nullptr);
    const auto text = content->front().getAsObject()->getString("text");
    ASSERT_TRUE(text.has_value());
    auto payload = llvm::json::parse(*text);
    ASSERT_TRUE(static_cast<bool>(payload));
    ASSERT_NE(payload->getAsObject(), nullptr);
    EXPECT_EQ(payload->getAsObject()->getInteger("exit_code"), 2);
    EXPECT_EQ(payload->getAsObject()->getBoolean("complete"), false);
    const auto* coverage = payload->getAsObject()->getObject("coverage");
    ASSERT_NE(coverage, nullptr);
    EXPECT_EQ(coverage->getInteger("failed_tus"), 1);
    if (!reason.empty()) EXPECT_NE(text->find(reason), llvm::StringRef::npos);
}

TEST_F(ResourceBudgetTest, ProductionMcpInheritsLimitsAndContinuesAfterResourceFailure) {
    const auto source = root / "safe.cpp";
    std::ofstream(source) << "int safe(){ return 42; }\n";
    for (const std::string option : {"--worker-timeout-ms", "--worker-memory-mb"}) {
        McpPipe server(root / (option + ".log"), {option, option == "--worker-timeout-ms" ? "1" : "16"});
        server.send(analyzeFrame(source, 1));
        ASSERT_NO_FATAL_FAILURE(checkFailedMcpAnalysis(server.line(),
            option == "--worker-timeout-ms" ? "worker_timeout" : ""));
        server.send(analyzeFrame(source, 2));
        ASSERT_NO_FATAL_FAILURE(checkFailedMcpAnalysis(server.line()));
        server.send("{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n");
        EXPECT_NE(server.line().find("\"id\":3"), std::string::npos);
        server.eof();
        EXPECT_EQ(server.finish(), 0);
    }
}

TEST_F(ResourceBudgetTest, ProductionMcpActiveCancellationFlushesFailureAndExitsWithoutEof) {
    const auto source = root / "many.cpp";
    {
        std::ofstream output(source);
        for (unsigned i = 0; i < 20000; ++i)
            output << "int function" << i << "(){ return " << i << "; }\n";
    }
    McpPipe server(root / "cancel.log");
    server.send(analyzeFrame(source));
    const auto worker = server.observeWorker();
    server.interrupt();
    ASSERT_NO_FATAL_FAILURE(checkFailedMcpAnalysis(server.line(), "worker_cancelled"));
    // Intentionally leave stdin open: the cancellation response, not EOF,
    // must finish this session only after its child has been reaped.
    EXPECT_EQ(server.finish(), 2);
    EXPECT_FALSE(fs::exists("/proc/" + std::to_string(worker)));
}
#endif

} // namespace
#endif
