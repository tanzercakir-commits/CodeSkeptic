#include "analyzer/RuntimeIdentity.h"
#include "source_manager/InputIdentity.h"
#include "source_manager/SourceManager.h"
#include <llvm/Support/SHA256.h>
#include <array>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <limits>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <tuple>

#ifdef __linux__
#include <cerrno>
#include <fcntl.h>
#include <sys/auxv.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <unistd.h>
#endif

namespace codeskeptic {
namespace {
constexpr std::size_t kMapsLimit = 1024 * 1024;
constexpr std::size_t kModuleLimit = 256;
constexpr std::uint64_t kModuleByteLimit = 512ull * 1024 * 1024;
constexpr std::uint64_t kRuntimeByteLimit = 1024ull * 1024 * 1024;

void require(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
}
std::uint64_t number(const std::string& value, int base = 10) {
    require(!value.empty(), "empty_runtime_number");
    std::uint64_t result = 0;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result, base);
    require(parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size(), "invalid_runtime_number");
    return result;
}
void bind(std::string& output, const std::string& value) {
    output += std::to_string(value.size()) + ":" + value;
}

#ifdef __linux__
class Descriptor {
public:
    explicit Descriptor(const std::string& path)
        : value_(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK)) {
        require(value_ >= 0, "runtime_file_unavailable");
    }
    ~Descriptor() { ::close(value_); }
    int get() const { return value_; }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
private:
    int value_;
};
struct Budget {
    std::function<bool()> cancelled;
    std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
    void check() const {
        require(!(cancelled && cancelled()), "runtime_validation_cancelled");
        require(std::chrono::steady_clock::now() - start <= std::chrono::seconds(5), "runtime_validation_deadline");
    }
};
std::size_t readChunk(int descriptor, char* data, std::size_t size, const Budget& budget) {
    for (;;) {
        budget.check();
        const auto count = ::read(descriptor, data, size);
        if (count < 0 && errno == EINTR) continue;
        require(count >= 0, "runtime_read_failed");
        return static_cast<std::size_t>(count);
    }
}
std::string readProc(const std::string& path, std::size_t limit, const Budget& budget) {
    Descriptor descriptor(path);
    std::array<char, 16384> chunk;
    std::string result;
    for (;;) {
        const auto count = readChunk(descriptor.get(), chunk.data(), chunk.size(), budget);
        if (!count) break;
        require(count <= limit - result.size(), "runtime_proc_bound");
        result.append(chunk.data(), count);
    }
    return result;
}
std::uint64_t startupCutoff(const Budget& budget) {
    const auto process = readProc("/proc/self/stat", 65536, budget);
    const auto close = process.rfind(')');
    require(close != std::string::npos, "runtime_process_stat_invalid");
    std::istringstream fields(process.substr(close + 1));
    std::string token;
    for (unsigned field = 3; field <= 22; ++field)
        require(static_cast<bool>(fields >> token), "runtime_process_stat_truncated");
    const auto ticks = number(token);
    const auto frequency = ::sysconf(_SC_CLK_TCK);
    require(frequency > 0, "runtime_clock_frequency_unavailable");
    std::istringstream system(readProc("/proc/stat", kMapsLimit, budget));
    std::string line;
    std::uint64_t boot = 0;
    while (std::getline(system, line)) if (line.rfind("btime ", 0) == 0) {
        require(!boot, "runtime_boot_time_duplicate");
        boot = number(line.substr(6));
    }
    require(boot > 0 && ticks / frequency < std::numeric_limits<std::uint64_t>::max() - boot,
            "runtime_start_time_unavailable");
    // Both btime and start ticks are rounded down, then an extra second is
    // subtracted. Recent installations conservatively stay fresh-only. This is
    // not historical-clock or privileged in-place-write attestation.
    return boot + ticks / frequency - 1;
}
std::string metadata(const struct stat& status) {
    std::string result;
    for (const auto value : {static_cast<std::uint64_t>(status.st_dev),
                            static_cast<std::uint64_t>(status.st_ino),
                            static_cast<std::uint64_t>(status.st_mode),
                            static_cast<std::uint64_t>(status.st_nlink),
                            static_cast<std::uint64_t>(status.st_size),
                            static_cast<std::uint64_t>(status.st_mtim.tv_sec),
                            static_cast<std::uint64_t>(status.st_mtim.tv_nsec),
                            static_cast<std::uint64_t>(status.st_ctim.tv_sec),
                            static_cast<std::uint64_t>(status.st_ctim.tv_nsec)}) bind(result, std::to_string(value));
    return result;
}
std::string hashMapping(const RuntimeMapping& mapping, std::uint64_t cutoff,
                        std::uint64_t& total, const Budget& budget) {
    Descriptor descriptor(mapping.path);
    struct stat before{}, after{};
    require(::fstat(descriptor.get(), &before) == 0, "runtime_stat_failed");
    require(S_ISREG(before.st_mode) && before.st_nlink > 0 && before.st_size >= 0,
            "runtime_not_regular");
    std::unique_ptr<Descriptor> executable;
    if (major(before.st_dev) != mapping.device_major || minor(before.st_dev) != mapping.device_minor ||
            before.st_ino != mapping.inode) {
        // Btrfs can expose a subvolume-specific st_dev while maps reports the
        // superblock device. Never accept inode-only equality. The kernel's exe
        // handle can independently bind the main executable; other ambiguous
        // mappings remain fresh-only (map_files handles may require privileges).
        const auto phdr = ::getauxval(AT_PHDR);
        require(phdr && std::any_of(mapping.ranges.begin(), mapping.ranges.end(),
            [&](const auto& range) { return range.first <= phdr && phdr < range.second; }),
            "runtime_mapping_replaced");
        std::array<char, 4097> target{};
        const auto length = ::readlink("/proc/self/exe", target.data(), target.size());
        require(length > 0 && static_cast<std::size_t>(length) < target.size() &&
                std::string(target.data(), length) == mapping.path, "runtime_mapping_replaced");
        executable = std::make_unique<Descriptor>("/proc/self/exe");
        struct stat actual{};
        require(::fstat(executable->get(), &actual) == 0 && actual.st_dev == before.st_dev &&
                actual.st_ino == before.st_ino && actual.st_ino == mapping.inode &&
                metadata(actual) == metadata(before), "runtime_mapping_replaced");
    }
    require(before.st_ctim.tv_sec >= 0 && static_cast<std::uint64_t>(before.st_ctim.tv_sec) < cutoff &&
            before.st_ctim.tv_nsec >= 0 && before.st_ctim.tv_nsec < 1000000000,
            "runtime_recent_or_changed_module");
    const auto size = static_cast<std::uint64_t>(before.st_size);
    require(size <= kModuleByteLimit && size <= kRuntimeByteLimit - total, "runtime_byte_bound");
    total += size;
    llvm::SHA256 hash;
    std::array<char, 65536> chunk;
    std::uint64_t consumed = 0;
    const auto actual_descriptor = executable ? executable->get() : descriptor.get();
    for (;;) {
        const auto count = readChunk(actual_descriptor, chunk.data(), chunk.size(), budget);
        if (!count) break;
        require(count <= size - consumed, "runtime_file_grew");
        consumed += count;
        hash.update(llvm::StringRef(chunk.data(), count));
    }
    require(consumed == size && ::fstat(actual_descriptor, &after) == 0 && metadata(before) == metadata(after),
            "runtime_changed_during_hash");
    const auto digest = hash.final();
    std::string result = metadata(before);
    bind(result, std::to_string(mapping.device_major));
    bind(result, std::to_string(mapping.device_minor));
    bind(result, std::to_string(mapping.inode));
    bind(result, std::string(reinterpret_cast<const char*>(digest.data()), digest.size()));
    return result;
}
#endif
} // namespace

bool parseRuntimeMappings(const std::string& text, std::vector<RuntimeMapping>& mappings, std::string& error) {
    try {
        require(!text.empty() && text.size() <= kMapsLimit && text.find('\0') == std::string::npos,
                "runtime_maps_bound_or_invalid");
        std::istringstream lines(text);
        std::string line;
        std::map<std::string, RuntimeMapping> staged;
        while (std::getline(lines, line)) {
            require(line.size() <= 4352, "runtime_mapping_path_bound");
            std::istringstream fields(line);
            std::string range, permissions, offset, device, inode, path;
            require(static_cast<bool>(fields >> range >> permissions >> offset >> device >> inode),
                    "runtime_mapping_truncated");
            const auto dash = range.find('-'), colon = device.find(':');
            require(dash != std::string::npos && colon != std::string::npos &&
                    number(range.substr(0, dash), 16) < number(range.substr(dash + 1), 16), "runtime_range_invalid");
            number(offset, 16);
            const auto major = number(device.substr(0, colon), 16), minor = number(device.substr(colon + 1), 16);
            const auto file = number(inode);
            require(permissions.size() == 4 && (permissions[0] == 'r' || permissions[0] == '-') &&
                    (permissions[1] == 'w' || permissions[1] == '-') &&
                    (permissions[2] == 'x' || permissions[2] == '-') &&
                    (permissions[3] == 'p' || permissions[3] == 's'), "runtime_permissions_invalid");
            std::getline(fields >> std::ws, path);
            const bool executable = permissions[2] == 'x';
            require(!(executable && permissions[1] == 'w'), "runtime_writable_executable_mapping");
            if (!file) {
                require(!executable || path == "[vdso]" || path == "[vsyscall]", "runtime_unknown_executable_mapping");
                continue;
            }
            require(!path.empty() && path.front() == '/' && path.size() <= 4096 &&
                    path.find('\\') == std::string::npos && path.find(" (deleted)") == std::string::npos,
                    "runtime_mapping_path_ambiguous");
            auto [position, inserted] = staged.emplace(path, RuntimeMapping{path, major, minor, file});
            require(inserted || (position->second.device_major == major && position->second.device_minor == minor &&
                                 position->second.inode == file), "runtime_mapping_identity_conflict");
            position->second.ranges.emplace_back(number(range.substr(0, dash), 16), number(range.substr(dash + 1), 16));
            require(staged.size() <= kModuleLimit, "runtime_module_bound");
        }
        require(!staged.empty(), "runtime_no_file_mappings");
        std::vector<RuntimeMapping> result;
        for (auto& entry : staged) result.push_back(std::move(entry.second));
        mappings = std::move(result); error.clear(); return true;
    } catch (const std::exception& failure) { error = failure.what(); return false; }
}

bool runtimeIdentitySupported() {
#ifdef __linux__
    return true;
#else
    return false;
#endif
}
RuntimeIdentity observeRuntimeIdentity(const std::function<bool()>& cancelled) {
#ifdef __linux__
    try {
        Budget budget{cancelled};
        const auto cutoff = startupCutoff(budget);
        const auto maps = readProc("/proc/self/maps", kMapsLimit, budget);
        std::vector<RuntimeMapping> modules;
        std::string error;
        require(parseRuntimeMappings(maps, modules, error), error.c_str());
        struct utsname kernel{};
        require(::uname(&kernel) == 0, "runtime_kernel_identity_unavailable");
        std::string manifest = "codeskeptic-linux-runtime/v1";
        bind(manifest, kernel.release); bind(manifest, kernel.version); bind(manifest, kernel.machine);
        // Resource-dir selection probes the relocatable installation using
        // native filesystem APIs outside Clang's observed VFS. Bind the actual
        // process-frozen choice used by this worker's ordinary frontend too.
        budget.check();
        const auto arguments = platformExtraArgs();
        budget.check();
        bind(manifest, "platform-arguments/v1"); bind(manifest, std::to_string(arguments.size()));
        for (const auto& argument : arguments) bind(manifest, argument);
        std::uint64_t total = 0;
        for (const auto& module : modules) {
            budget.check();
            bind(manifest, module.path);
            bind(manifest, hashMapping(module, cutoff, total, budget));
        }
        // Comparing parsed file identities avoids harmless stack/heap/ASLR map
        // changes while refusing modules added, removed, or replaced mid-capture.
        std::vector<RuntimeMapping> after;
        require(parseRuntimeMappings(readProc("/proc/self/maps", kMapsLimit, budget), after, error), error.c_str());
        require(after.size() == modules.size(), "runtime_mapping_set_changed");
        for (std::size_t i = 0; i < modules.size(); ++i)
            require(std::tie(after[i].path, after[i].device_major, after[i].device_minor, after[i].inode) ==
                    std::tie(modules[i].path, modules[i].device_major, modules[i].device_minor, modules[i].inode),
                    "runtime_mapping_set_changed");
        budget.check();
        return {inputDigest(manifest), {}};
    } catch (const std::exception& failure) { return {{}, failure.what()}; }
#else
    (void)cancelled;
    return {{}, "runtime_profile_unqualified"};
#endif
}
} // namespace codeskeptic
