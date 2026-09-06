#include "analyzer/UnitEvidenceStore.h"
#include "source_manager/InputIdentity.h"
#include "analyzer/WorkerProtocol.h"
#include <algorithm>
#include <filesystem>
#include <limits>
#include <stdexcept>
#include <vector>
#ifdef __linux__
#include <cerrno>
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

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

namespace {
constexpr std::uint64_t diskEnvelopeBytes = 8 + 64 + 64 + 8 + 8 + 64;
constexpr std::uint64_t diskRecordLimit = kWorkerPacketLimit + kInputIdentityLimit + diskEnvelopeBytes;
bool digestName(const std::string& text) {
    return text.size() == 64 && text.find_first_not_of("0123456789abcdef") == std::string::npos;
}
struct DiskFailure { const char* state; };
void diskCheck(bool condition, const char* state) { if (!condition) throw DiskFailure{state}; }
void checkCancellation(const std::function<bool()>& cancelled) {
    diskCheck(!cancelled || !cancelled(), "cancelled");
}
void diskFailure(DiskCacheStatus& status, const char* state) {
    status.state = state;
    const std::string reason(state);
    if (reason == "capacity") ++status.capacity;
    else if (reason == "busy") ++status.busy;
    else if (reason == "rejected") ++status.rejected;
    else if (reason != "cancelled" && reason != "unsupported") ++status.errors;
}
void appendSize(std::string& bytes, std::uint64_t size) {
    for (unsigned i = 0; i < 8; ++i) bytes.push_back(static_cast<char>((size >> (i * 8)) & 255));
}
std::uint64_t readSize(const std::string& bytes, std::size_t at) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= std::uint64_t(static_cast<unsigned char>(bytes[at + i])) << (8 * i);
    return value;
}
std::string diskEnvelope(const std::string& key, const std::string& digest,
                         const std::string& packet, const std::string& witness) {
    InputIdentity identity;
    diskCheck(digestName(key) && digestName(digest) && packet.size() <= kWorkerPacketLimit &&
              witness.size() <= kInputIdentityLimit && decodeInputIdentity(witness, identity) &&
              identity.context == digest, "rejected");
    std::string bytes("CSKDISK1");
    bytes += key; bytes += digest;
    appendSize(bytes, packet.size()); appendSize(bytes, witness.size());
    bytes += packet; bytes += witness;
    bytes += inputDigest(bytes);
    return bytes;
}
std::string decodeDiskEnvelope(const std::string& bytes, const std::string& key,
                               const std::string& digest) {
    diskCheck(bytes.size() >= diskEnvelopeBytes && bytes.size() <= diskRecordLimit &&
              bytes.compare(0, 8, "CSKDISK1") == 0 && bytes.compare(8, 64, key) == 0 &&
              bytes.compare(72, 64, digest) == 0, "rejected");
    const auto packet_size = readSize(bytes, 136), witness_size = readSize(bytes, 144);
    diskCheck(packet_size <= kWorkerPacketLimit && witness_size <= kInputIdentityLimit &&
              packet_size + witness_size + diskEnvelopeBytes == bytes.size(), "rejected");
    diskCheck(inputDigest(bytes.substr(0, bytes.size() - 64)) == bytes.substr(bytes.size() - 64), "rejected");
    InputIdentity identity;
    diskCheck(decodeInputIdentity(bytes.substr(152 + packet_size, witness_size), identity) &&
              identity.context == digest, "rejected");
    return bytes.substr(152, packet_size);
}

#ifdef __linux__
struct DiskFd {
    int fd = -1;
    explicit DiskFd(int value = -1) : fd(value) {}
    ~DiskFd() { if (fd >= 0) ::close(fd); }
    DiskFd(const DiskFd&) = delete;
    DiskFd& operator=(const DiskFd&) = delete;
};
bool privateRegular(const struct stat& info) {
    return S_ISREG(info.st_mode) && info.st_uid == ::geteuid() &&
           (info.st_mode & 07777) == 0600 && info.st_nlink == 1 && info.st_size >= 0;
}
bool sameFile(const struct stat& a, const struct stat& b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size &&
           a.st_mode == b.st_mode && a.st_nlink == b.st_nlink && a.st_uid == b.st_uid &&
           a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec &&
           a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
// Never canonicalize through symlinks, and never recursively create parents.
// Descriptor-relative operations pin the selected private directory throughout
// this transaction. Cooperating clients must not rename/remove that directory.
int openDiskDirectory(const std::string& path, bool create = true) {
    diskCheck(!path.empty() && path.size() <= 4096 && path.front() == '/' &&
              path.find('\0') == std::string::npos, "rejected");
    std::vector<std::string> components;
    for (const auto& part : std::filesystem::path(path).relative_path()) {
        const auto name = part.string();
        diskCheck(!name.empty() && name != "." && name != "..", "rejected");
        components.push_back(name);
    }
    diskCheck(!components.empty(), "rejected");
    DiskFd directory(::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    diskCheck(directory.fd >= 0, "unavailable");
    for (std::size_t i = 0; i < components.size(); ++i) {
        const auto& name = components[i];
        int next = ::openat(directory.fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 && errno == ENOENT && create && i + 1 == components.size()) {
            diskCheck(::mkdirat(directory.fd, name.c_str(), 0700) == 0 || errno == EEXIST, "unavailable");
            next = ::openat(directory.fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        diskCheck(next >= 0, "unavailable");
        ::close(directory.fd); directory.fd = next;
    }
    struct stat info{};
    diskCheck(::fstat(directory.fd, &info) == 0 && S_ISDIR(info.st_mode) &&
              info.st_uid == ::geteuid() && (info.st_mode & 07777) == 0700, "rejected");
    if (::flock(directory.fd, LOCK_EX | LOCK_NB) != 0)
        throw DiskFailure{errno == EWOULDBLOCK ? "busy" : "unavailable"};
    const int result = directory.fd; directory.fd = -1;
    return result;
}
struct DiskEntry { std::string name; struct stat info; };
struct Inventory {
    std::vector<DiskEntry> files;
    std::uint64_t bytes = 0;
};
Inventory inventory(int directory, DiskCacheStatus& status,
                    const std::function<bool()>& cancelled,
                    const std::string& only_name = {}) {
    // Reopen rather than dup: directory streams must not share an offset.
    const int scan_fd = ::openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    diskCheck(scan_fd >= 0, "unavailable");
    DIR* scan = ::fdopendir(scan_fd);
    if (!scan) { ::close(scan_fd); throw DiskFailure{"unavailable"}; }
    struct CloseDir { DIR* ptr; ~CloseDir() { ::closedir(ptr); } } close{scan};
    Inventory result;
    std::optional<DiskEntry> pending;
    for (;;) {
        checkCancellation(cancelled);
        errno = 0;
        const auto* entry = ::readdir(scan);
        if (!entry) { diskCheck(errno == 0, "unavailable"); break; }
        const std::string name(entry->d_name);
        if (name == "." || name == "..") continue;
        diskCheck(only_name.empty() || name == ".pending" || name == only_name, "rejected");
        diskCheck(result.files.size() < 4096, "capacity");
        diskCheck(name == ".pending" || (!only_name.empty() && name == only_name) || (name.size() == 70 &&
                  name.substr(64) == ".entry" && digestName(name.substr(0, 64))), "rejected");
        struct stat info{};
        diskCheck(::fstatat(directory, name.c_str(), &info, AT_SYMLINK_NOFOLLOW) == 0 &&
                  privateRegular(info), "rejected");
        diskCheck(static_cast<std::uint64_t>(info.st_size) <= std::numeric_limits<std::uint64_t>::max() - result.bytes,
                  "capacity");
        result.bytes += info.st_size;
        if (name == ".pending") pending = DiskEntry{name, info};
        else result.files.push_back({name, info});
    }
    // No namespace mutation until the entire bounded inventory was validated.
    if (pending) {
        diskCheck(::unlinkat(directory, ".pending", 0) == 0, "unavailable");
        result.bytes -= pending->info.st_size;
        ++status.recovered;
    }
    std::sort(result.files.begin(), result.files.end(), [](const auto& a, const auto& b) { return a.name < b.name; });
    status.bytes = result.bytes; status.entries = result.files.size();
    return result;
}
void retain(int directory, Inventory& files, std::uint64_t limit, std::size_t count_limit,
            std::uint64_t reserve, std::size_t reserved_entries, const std::string& preserve,
            DiskCacheStatus& status, const std::function<bool()>& cancelled) {
    diskCheck(reserve <= limit && reserved_entries <= count_limit, "capacity");
    for (auto it = files.files.begin(); files.bytes > limit - reserve ||
         files.files.size() > count_limit - reserved_entries;) {
        checkCancellation(cancelled);
        if (it == files.files.end()) throw DiskFailure{"capacity"};
        if (it->name == preserve) { ++it; continue; }
        diskCheck(::unlinkat(directory, it->name.c_str(), 0) == 0, "unavailable");
        files.bytes -= it->info.st_size;
        it = files.files.erase(it);
        ++status.evictions;
        status.bytes = files.bytes; status.entries = files.files.size();
    }
}
std::string readDiskEntry(int directory, const DiskEntry& entry,
                          const std::function<bool()>& cancelled) {
    diskCheck(static_cast<std::uint64_t>(entry.info.st_size) <= diskRecordLimit, "rejected");
    DiskFd file(::openat(directory, entry.name.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
    struct stat before{}, after{};
    diskCheck(file.fd >= 0 && ::fstat(file.fd, &before) == 0 && privateRegular(before) &&
              sameFile(entry.info, before), "rejected");
    std::string bytes(static_cast<std::size_t>(before.st_size), '\0');
    for (std::size_t offset = 0; offset < bytes.size();) {
        checkCancellation(cancelled);
        const auto n = ::read(file.fd, bytes.data() + offset, std::min<std::size_t>(65536, bytes.size() - offset));
        if (n < 0 && errno == EINTR) continue;
        diskCheck(n > 0, "rejected");
        offset += n;
    }
    char tail;
    diskCheck(::read(file.fd, &tail, 1) == 0 && ::fstat(file.fd, &after) == 0 &&
              sameFile(before, after), "rejected");
    checkCancellation(cancelled);
    return bytes;
}
#endif
} // namespace

DiskEvidenceStore::DiskEvidenceStore(std::string directory, std::uint64_t bytes, std::size_t entries)
    : directory_(std::move(directory)), byte_limit_(bytes), entry_limit_(entries) {
    if (!bytes || bytes > 1024ULL * 1024 * 1024 || !entries || entries > 4096)
        status_.state = "invalid_limits";
#ifndef __linux__
    else status_.state = "unsupported";
#endif
}
std::optional<std::string> DiskEvidenceStore::candidate(const std::string& key,
    const std::string& digest, const std::function<bool()>& cancelled) {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        diskCheck(byte_limit_ && byte_limit_ <= 1024ULL * 1024 * 1024 && entry_limit_ && entry_limit_ <= 4096,
                  "invalid_limits");
        diskCheck(digestName(key) && digestName(digest), "rejected");
        checkCancellation(cancelled);
#ifdef __linux__
        DiskFd directory(openDiskDirectory(directory_));
        auto files = inventory(directory.fd, status_, cancelled);
        retain(directory.fd, files, byte_limit_, entry_limit_, 0, 0, "", status_, cancelled);
        const auto name = key + ".entry";
        const auto found = std::find_if(files.files.begin(), files.files.end(), [&](const auto& entry) { return entry.name == name; });
        if (found == files.files.end()) { status_.state = "miss"; return {}; }
        auto packet = decodeDiskEnvelope(readDiskEntry(directory.fd, *found, cancelled), key, digest);
        ++status_.candidates; status_.state = "candidate";
        return packet;
#else
        throw DiskFailure{"unsupported"};
#endif
    } catch (const DiskFailure& error) { diskFailure(status_, error.state); }
      catch (...) { diskFailure(status_, "unavailable"); }
    return {};
}
DiskWriteResult DiskEvidenceStore::rememberCandidate(const std::string& key, const std::string& digest,
    const std::string& packet, const std::string& witness, const std::function<bool()>& cancelled) {
    std::lock_guard<std::mutex> lock(mutex_);
    try {
        diskCheck(byte_limit_ && byte_limit_ <= 1024ULL * 1024 * 1024 && entry_limit_ && entry_limit_ <= 4096,
                  "invalid_limits");
        checkCancellation(cancelled);
#ifdef __linux__
        const auto bytes = diskEnvelope(key, digest, packet, witness);
        DiskFd directory(openDiskDirectory(directory_));
        auto files = inventory(directory.fd, status_, cancelled);
        const auto name = key + ".entry";
        retain(directory.fd, files, byte_limit_, entry_limit_, bytes.size(), 1, name, status_, cancelled);
        const auto old = std::find_if(files.files.begin(), files.files.end(), [&](const auto& entry) { return entry.name == name; });
        const auto old_size = old == files.files.end() ? 0 : old->info.st_size;
        DiskFd pending(::openat(directory.fd, ".pending", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        diskCheck(pending.fd >= 0, "write_failed");
        struct RemovePending {
            int directory;
            ~RemovePending() { ::unlinkat(directory, ".pending", 0); }
        } cleanup{directory.fd};
        // A restrictive umask may only remove permissions; restore this newly
        // created private regular file's exact mode before publication.
        diskCheck(::fchmod(pending.fd, 0600) == 0, "write_failed");
        for (std::size_t offset = 0; offset < bytes.size();) {
            checkCancellation(cancelled);
            const auto n = ::write(pending.fd, bytes.data() + offset, std::min<std::size_t>(65536, bytes.size() - offset));
            if (n < 0 && errno == EINTR) continue;
            diskCheck(n > 0, "write_failed");
            offset += n;
        }
        diskCheck(::fsync(pending.fd) == 0, "write_failed");
        checkCancellation(cancelled);
        diskCheck(::renameat(directory.fd, ".pending", directory.fd, name.c_str()) == 0, "write_failed");
        // Rename is the visibility commit point. After it, neither cancellation
        // nor a directory-sync failure may be reported as an uncommitted write.
        ++status_.writes;
        status_.bytes = files.bytes - old_size + bytes.size();
        status_.entries = files.files.size() + (old == files.files.end() ? 1 : 0);
        if (::fsync(directory.fd) != 0) {
            diskFailure(status_, "committed_durability_uncertain");
            return DiskWriteResult::CommittedDurabilityUncertain;
        }
        status_.state = "stored";
        return DiskWriteResult::Committed;
#else
        throw DiskFailure{"unsupported"};
#endif
    } catch (const DiskFailure& error) { diskFailure(status_, error.state); }
      catch (...) { diskFailure(status_, "write_failed"); }
    return DiskWriteResult::NotStored;
}
void DiskEvidenceStore::confirmHit() { std::lock_guard<std::mutex> lock(mutex_); ++status_.hits; }
DiskCacheStatus DiskEvidenceStore::status() const { std::lock_guard<std::mutex> lock(mutex_); return status_; }

namespace {
const std::string& checkpointName() {
    // Intentionally outside DiskEvidenceStore's digest.entry namespace so
    // cache retention can never adopt or delete a closed checkpoint's manifest.
    static const std::string name = "manifest.csk-checkpoint";
    return name;
}
#ifdef __linux__
Inventory checkpointInventory(int directory, const std::function<bool()>& cancelled) {
    DiskCacheStatus status;
    auto files = inventory(directory, status, cancelled, checkpointName());
    diskCheck(files.files.empty() || (files.files.size() == 1 &&
              files.files.front().name == checkpointName()), "rejected");
    return files;
}
#endif
}

CheckpointStore::CheckpointStore(std::string directory, std::uint64_t byte_limit)
    : directory_(std::move(directory)), byte_limit_(byte_limit) {}
CheckpointStore::~CheckpointStore() {
#ifdef __linux__
    if (descriptor_ >= 0) ::close(descriptor_);
#endif
}
bool CheckpointStore::open(bool resume, std::string& payload,
                           const std::function<bool()>& cancelled) {
    if (descriptor_ >= 0) { state_ = "already_open"; return false; }
    try {
        diskCheck(state_ == "closed", "already_open");
        diskCheck(byte_limit_ > 0 && byte_limit_ <= 1024ULL * 1024 * 1024, "invalid_limits");
        checkCancellation(cancelled);
#ifdef __linux__
        descriptor_ = openDiskDirectory(directory_, !resume);
        auto files = checkpointInventory(descriptor_, cancelled);
        diskCheck(files.bytes <= byte_limit_, "capacity");
        if (resume) {
            diskCheck(files.files.size() == 1, "missing");
            const auto bytes = readDiskEntry(descriptor_, files.files.front(), cancelled);
            diskCheck(bytes.size() >= 80 && bytes.size() <= kWorkerPacketLimit &&
                      bytes.compare(0, 8, "CSKCP001") == 0 && readSize(bytes, 8) == bytes.size() - 80 &&
                      inputDigest(bytes.substr(0, bytes.size() - 64)) == bytes.substr(bytes.size() - 64), "rejected");
            auto decoded = bytes.substr(16, bytes.size() - 80);
            checkCancellation(cancelled);
            payload = std::move(decoded);
        } else {
            diskCheck(files.files.empty(), "exists");
            payload.clear();
        }
        state_ = "ready";
        return true;
#else
        throw DiskFailure{"unsupported"};
#endif
    } catch (const DiskFailure& error) { state_ = error.state; }
      catch (...) { state_ = "unavailable"; }
#ifdef __linux__
    if (descriptor_ >= 0) { ::close(descriptor_); descriptor_ = -1; }
#endif
    return false;
}
DiskWriteResult CheckpointStore::save(const std::string& payload,
                                     const std::function<bool()>& cancelled) {
    try {
        checkCancellation(cancelled);
        diskCheck(descriptor_ >= 0, "not_open");
        diskCheck(payload.size() <= kWorkerPacketLimit - 80, "capacity");
#ifdef __linux__
        const auto files = checkpointInventory(descriptor_, cancelled);
        const auto size = payload.size() + 80;
        // Reserve the whole next record while preserving the previous one.
        // No retention/eviction is permitted to turn a failed save into data loss.
        diskCheck(size <= byte_limit_ && files.bytes <= byte_limit_ - size, "capacity");
        std::string bytes("CSKCP001");
        appendSize(bytes, payload.size()); bytes += payload; bytes += inputDigest(bytes);
        DiskFd pending(::openat(descriptor_, ".pending", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
        diskCheck(pending.fd >= 0, "write_failed");
        struct RemovePending {
            int directory;
            ~RemovePending() { ::unlinkat(directory, ".pending", 0); }
        } cleanup{descriptor_};
        diskCheck(::fchmod(pending.fd, 0600) == 0, "write_failed");
        for (std::size_t offset = 0; offset < bytes.size();) {
            checkCancellation(cancelled);
            const auto n = ::write(pending.fd, bytes.data() + offset,
                                  std::min<std::size_t>(65536, bytes.size() - offset));
            if (n < 0 && errno == EINTR) continue;
            diskCheck(n > 0, "write_failed");
            offset += n;
        }
        diskCheck(::fsync(pending.fd) == 0, "write_failed");
        checkCancellation(cancelled);
        diskCheck(::renameat(descriptor_, ".pending", descriptor_, checkpointName().c_str()) == 0, "write_failed");
        if (::fsync(descriptor_) != 0) {
            state_ = "committed_durability_uncertain";
            return DiskWriteResult::CommittedDurabilityUncertain;
        }
        state_ = "stored";
        return DiskWriteResult::Committed;
#else
        throw DiskFailure{"unsupported"};
#endif
    } catch (const DiskFailure& error) { state_ = error.state; }
      catch (...) { state_ = "write_failed"; }
    return DiskWriteResult::NotStored;
}
} // namespace codeskeptic
