#ifndef CODESKEPTIC_RUNTIME_IDENTITY_H
#define CODESKEPTIC_RUNTIME_IDENTITY_H

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace codeskeptic {
struct RuntimeMapping {
    std::string path;
    std::uint64_t device_major = 0, device_minor = 0, inode = 0;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
};
// Diagnostic detection points, not claims about which operation spent time.
enum class RuntimeObservationStage {
    Starting, Startup, MapsBefore, Kernel, PlatformArguments, ModuleIdentity,
    ModuleRead, ModuleHash, ModuleValidation, MapsAfter, Manifest
};
struct RuntimeObservationFailure {
    RuntimeObservationStage detection_stage = RuntimeObservationStage::Starting;
    // Completed means whole-module hash, identity recheck and manifest binding.
    std::uint64_t modules_completed = 0;
    // Actual positive module reads / completed hash updates; excludes proc data.
    std::uint64_t module_read_bytes = 0, module_hashed_bytes = 0;
    std::uint64_t wall_us = 0;
    std::optional<std::uint64_t> thread_cpu_us;
};
struct RuntimeIdentity {
    std::string digest;
    std::string reason;
    std::optional<RuntimeObservationFailure> observation_failure = std::nullopt;
    explicit operator bool() const { return !digest.empty(); }
};

// Currently a qualified Linux /proc profile only. Other platforms keep ordinary
// fresh analysis; an unavailable identity never means an empty-runtime hit.
bool runtimeIdentitySupported();
RuntimeIdentity observeRuntimeIdentity(const std::function<bool()>& cancelled = {});

// Fixed labels and bounded decimal fields only. Does not log or affect identity.
std::string formatRuntimeObservationFailure(const RuntimeObservationFailure& failure);

// Strict, bounded parser shared by the actual Linux collector and its tests.
// All file-backed mappings matter, including non-executable data-only modules.
bool parseRuntimeMappings(const std::string& text, std::vector<RuntimeMapping>& mappings,
                          std::string& error);
} // namespace codeskeptic
#endif
