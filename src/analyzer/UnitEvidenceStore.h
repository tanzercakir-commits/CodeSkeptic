#ifndef CODESKEPTIC_UNIT_EVIDENCE_STORE_H
#define CODESKEPTIC_UNIT_EVIDENCE_STORE_H

#include <cstddef>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <cstdint>

namespace codeskeptic {

// Process-local, immutable completed worker packets. This is not disk storage
// or a checkpoint. Admission remains the coordinator's successful-child gate.
class UnitEvidenceStore {
public:
    explicit UnitEvidenceStore(std::size_t byte_limit = 64 * 1024 * 1024,
                               std::size_t entry_limit = 128)
        : byte_limit_(byte_limit), entry_limit_(entry_limit) {}
    bool remember(const std::string& key, const std::string& request_digest,
                  std::string packet, std::string witness,
                  const std::function<bool()>& cancelled = {});
    // Coordinator path: a structurally bound candidate, NOT reusable evidence
    // until the newly launched supervised worker validates its runtime/inputs.
    bool rememberCandidate(const std::string& key, const std::string& request_digest,
                           std::string packet, std::string witness,
                           const std::function<bool()>& cancelled = {});
    std::optional<std::string> candidate(const std::string& key, const std::string& request_digest,
                                        const std::function<bool()>& cancelled = {});
    void confirmHit();
    std::optional<std::string> lookup(const std::string& key,
        const std::string& request_digest, const std::function<bool()>& cancelled = {});
    void clear();
    std::size_t hits() const;
    std::size_t entries() const;
    std::size_t bytes() const;
private:
    struct Entry { std::string packet, witness; std::size_t size; };
    mutable std::mutex mutex_;
    std::map<std::string, Entry> entries_;
    std::size_t byte_limit_, entry_limit_, bytes_ = 0, hits_ = 0;
};
UnitEvidenceStore& processUnitEvidenceStore();

// Persistence never bypasses the coordinator/child qualification gates. Each
// analysis owns one store with frozen preferences; persistent mode does not use
// the process-local map, even if a previous analysis populated that map.
struct DiskCacheStatus {
    std::string state = "ready";
    std::size_t candidates = 0, hits = 0, writes = 0, evictions = 0, recovered = 0;
    std::size_t rejected = 0, errors = 0, capacity = 0, busy = 0;
    std::uint64_t bytes = 0;
    std::size_t entries = 0;
};
enum class DiskWriteResult { NotStored, Committed, CommittedDurabilityUncertain };
class DiskEvidenceStore {
public:
    DiskEvidenceStore(std::string directory, std::uint64_t byte_limit,
                      std::size_t entry_limit);
    std::optional<std::string> candidate(const std::string& key,
        const std::string& request_digest, const std::function<bool()>& cancelled = {});
    DiskWriteResult rememberCandidate(const std::string& key, const std::string& request_digest,
        const std::string& packet, const std::string& witness,
        const std::function<bool()>& cancelled = {});
    void confirmHit();
    DiskCacheStatus status() const;
private:
    const std::string directory_;
    const std::uint64_t byte_limit_;
    const std::size_t entry_limit_;
    mutable std::mutex mutex_;
    DiskCacheStatus status_;
};
} // namespace codeskeptic
#endif
