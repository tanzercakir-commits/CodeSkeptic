#include "analyzer/UnitEvidenceStore.h"
#include "source_manager/InputIdentity.h"

namespace codeskeptic {
bool UnitEvidenceStore::remember(const std::string& key, const std::string& request_digest,
                                std::string packet, std::string witness,
                                const std::function<bool()>& cancelled) {
    InputIdentity identity;
    if (key.empty() || !decodeInputIdentity(witness, identity) ||
        identity.context != request_digest || !identity.matchesCurrent(cancelled)) return false;
    return rememberCandidate(key, request_digest, std::move(packet), std::move(witness), cancelled);
}
bool UnitEvidenceStore::rememberCandidate(const std::string& key, const std::string& request_digest,
    std::string packet, std::string witness, const std::function<bool()>& cancelled) {
    InputIdentity identity;
    if (key.empty() || !decodeInputIdentity(witness, identity) || identity.context != request_digest) return false;
    if (key.size() > byte_limit_ || packet.size() > byte_limit_ - key.size() ||
        witness.size() > byte_limit_ - key.size() - packet.size() || !entry_limit_) return false;
    const auto size = key.size() + packet.size() + witness.size();
    std::lock_guard<std::mutex> lock(mutex_);
    if (cancelled && cancelled()) return false;
    auto old = entries_.find(key);
    if (old != entries_.end()) { bytes_ -= old->second.size; entries_.erase(old); }
    // Deterministic bounded eviction affects work saved, never evidence validity.
    while (!entries_.empty() && (entries_.size() >= entry_limit_ || bytes_ > byte_limit_ - size)) {
        bytes_ -= entries_.begin()->second.size;
        entries_.erase(entries_.begin());
    }
    entries_.emplace(key, Entry{std::move(packet), std::move(witness), size});
    bytes_ += size;
    return true;
}
std::optional<std::string> UnitEvidenceStore::candidate(const std::string& key,
    const std::string& request_digest, const std::function<bool()>& cancelled) {
    if (cancelled && cancelled()) return {};
    std::lock_guard<std::mutex> lock(mutex_);
    const auto found = entries_.find(key);
    if (found == entries_.end()) return {};
    InputIdentity identity;
    if (!decodeInputIdentity(found->second.witness, identity) || identity.context != request_digest) return {};
    return found->second.packet;
}
void UnitEvidenceStore::confirmHit() { std::lock_guard<std::mutex> lock(mutex_); ++hits_; }
std::optional<std::string> UnitEvidenceStore::lookup(const std::string& key,
    const std::string& request_digest, const std::function<bool()>& cancelled) {
    if (cancelled && cancelled()) return {};
    std::lock_guard<std::mutex> lock(mutex_);
    auto found = entries_.find(key);
    if (found == entries_.end()) return {};
    InputIdentity identity;
    if (!decodeInputIdentity(found->second.witness, identity) || identity.context != request_digest ||
        !identity.matchesCurrent(cancelled)) {
        bytes_ -= found->second.size;
        entries_.erase(found);
        return {};
    }
    if (cancelled && cancelled()) return {};
    ++hits_;
    return found->second.packet;
}
void UnitEvidenceStore::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear(); bytes_ = hits_ = 0;
}
std::size_t UnitEvidenceStore::hits() const { std::lock_guard<std::mutex> lock(mutex_); return hits_; }
std::size_t UnitEvidenceStore::entries() const { std::lock_guard<std::mutex> lock(mutex_); return entries_.size(); }
std::size_t UnitEvidenceStore::bytes() const { std::lock_guard<std::mutex> lock(mutex_); return bytes_; }
UnitEvidenceStore& processUnitEvidenceStore() { static UnitEvidenceStore store; return store; }
} // namespace codeskeptic
