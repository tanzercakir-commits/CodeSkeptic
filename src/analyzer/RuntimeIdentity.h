#ifndef CODESKEPTIC_RUNTIME_IDENTITY_H
#define CODESKEPTIC_RUNTIME_IDENTITY_H

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace codeskeptic {
struct RuntimeMapping {
    std::string path;
    std::uint64_t device_major = 0, device_minor = 0, inode = 0;
    std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;
};
struct RuntimeIdentity {
    std::string digest;
    std::string reason;
    explicit operator bool() const { return !digest.empty(); }
};

// Currently a qualified Linux /proc profile only. Other platforms keep ordinary
// fresh analysis; an unavailable identity never means an empty-runtime hit.
bool runtimeIdentitySupported();
RuntimeIdentity observeRuntimeIdentity(const std::function<bool()>& cancelled = {});

// Strict, bounded parser shared by the actual Linux collector and its tests.
// All file-backed mappings matter, including non-executable data-only modules.
bool parseRuntimeMappings(const std::string& text, std::vector<RuntimeMapping>& mappings,
                          std::string& error);
} // namespace codeskeptic
#endif
