#include "analyzer/UnitEvidenceStore.h"

#include <llvm/ADT/StringExtras.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/raw_ostream.h>

#include <cctype>
#include <filesystem>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <system_error>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#endif

namespace codeskeptic {

namespace json = llvm::json;
namespace fs = std::filesystem;

namespace {

constexpr int kEvidenceSchema = 1;
constexpr std::uintmax_t kMaxManifestBytes = 16u << 20;
constexpr std::uintmax_t kMaxPayloadBytes = 64u << 20;
constexpr std::uintmax_t kMaxHashedFileBytes = 16ull << 30;

struct EntryMetadata {
    std::string unit_id_sha256;
    std::string checkpoint_key_sha256;
    std::string payload_sha256;
    std::string analyzer_sha256;
    std::string configuration_sha256;
    std::string dependency_sha256;
    std::string input_sha256;
    std::string request_sha256;
    std::string response_sha256;
    std::string summary_sha256;
    bool summary_exists = false;
    std::string entry_sha256;
};

bool validSha256(const std::string& value) {
    if (value.size() != 64) return false;
    for (const unsigned char c : value) {
        if (!std::isdigit(c) && !(c >= 'a' && c <= 'f')) return false;
    }
    return true;
}

std::string fileMetadataIdentity(const std::string& path,
                                 std::string& error) {
#ifdef _WIN32
    const HANDLE file = CreateFileW(
        fs::path(path).c_str(), FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = "cannot inspect analyzer identity: " +
                std::to_string(GetLastError());
        return {};
    }
    BY_HANDLE_FILE_INFORMATION identity{};
    FILE_BASIC_INFO basic{};
    const bool identity_ok = GetFileInformationByHandle(file, &identity) != 0;
    const bool basic_ok = GetFileInformationByHandleEx(
        file, FileBasicInfo, &basic, sizeof(basic)) != 0;
    CloseHandle(file);
    if (!identity_ok || !basic_ok ||
        (identity.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        error = "cannot inspect analyzer identity";
        return {};
    }
    std::ostringstream value;
    value << identity.dwVolumeSerialNumber << ':'
          << identity.nFileIndexHigh << ':' << identity.nFileIndexLow << ':'
          << identity.nFileSizeHigh << ':' << identity.nFileSizeLow << ':'
          << basic.LastWriteTime.QuadPart << ':' << basic.ChangeTime.QuadPart;
    return value.str();
#else
    struct stat identity {};
    if (::stat(path.c_str(), &identity) != 0 ||
        !S_ISREG(identity.st_mode)) {
        error = "cannot inspect analyzer identity: " + path;
        return {};
    }
    std::ostringstream value;
    value << static_cast<unsigned long long>(identity.st_dev) << ':'
          << static_cast<unsigned long long>(identity.st_ino) << ':'
          << static_cast<unsigned long long>(identity.st_size) << ':';
#ifdef __APPLE__
    value << identity.st_mtimespec.tv_sec << ':'
          << identity.st_mtimespec.tv_nsec << ':'
          << identity.st_ctimespec.tv_sec << ':'
          << identity.st_ctimespec.tv_nsec;
#else
    value << identity.st_mtim.tv_sec << ':' << identity.st_mtim.tv_nsec << ':'
          << identity.st_ctim.tv_sec << ':' << identity.st_ctim.tv_nsec;
#endif
    return value.str();
#endif
}

void appendLengthPrefixed(std::ostringstream& output,
                          const std::string& value) {
    output << value.size() << ':' << value << '\n';
}

std::string hashText(const std::string& text) {
    const auto digest = llvm::SHA256::hash(
        llvm::ArrayRef<std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
    return llvm::toHex(digest, true);
}

std::string unitId(const TranslationUnitExecution& unit,
                   TranslationUnitPhase phase) {
    std::ostringstream identity;
    appendLengthPrefixed(identity, unit.canonical_path);
    appendLengthPrefixed(identity, unit.compile_command_sha256);
    identity << unit.command_ordinal << '\n';
    appendLengthPrefixed(identity, translationUnitPhaseName(phase));
    return hashText(identity.str());
}

std::string planDigest(
    const std::vector<TranslationUnitExecution>& units,
    bool whole_program) {
    std::ostringstream plan;
    plan << kEvidenceSchema << '\n';
    const auto append_phase = [&](TranslationUnitPhase phase) {
        for (const auto& unit : units)
            appendLengthPrefixed(plan, unitId(unit, phase));
    };
    if (whole_program) append_phase(TranslationUnitPhase::SummaryHarvest);
    append_phase(TranslationUnitPhase::Analysis);
    return hashText(plan.str());
}

std::string configurationDigest(
    const std::vector<std::string>& arguments,
    const std::vector<std::string>& rule_ids,
    ResourceLimits limits,
    bool whole_program) {
    std::ostringstream identity;
    identity << kEvidenceSchema << '\n' << limits.timeout_seconds << '\n'
             << limits.memory_mib << '\n' << (whole_program ? 1 : 0) << '\n';
    identity << arguments.size() << '\n';
    for (const auto& argument : arguments)
        appendLengthPrefixed(identity, argument);
    identity << rule_ids.size() << '\n';
    for (const auto& rule_id : rule_ids)
        appendLengthPrefixed(identity, rule_id);
    return hashText(identity.str());
}

std::string cacheKey(const std::string& analyzer_sha256,
                     const std::string& configuration_sha256,
                     const TranslationUnitExecution& unit,
                     TranslationUnitPhase phase,
                     const DependencyManifest& dependencies,
                     const std::string& input_sha256) {
    std::ostringstream identity;
    identity << kEvidenceSchema << '\n';
    appendLengthPrefixed(identity, analyzer_sha256);
    appendLengthPrefixed(identity, configuration_sha256);
    appendLengthPrefixed(identity, unitId(unit, phase));
    appendLengthPrefixed(identity, dependencies.sha256);
    appendLengthPrefixed(identity, input_sha256);
    return hashText(identity.str());
}

std::string payloadDigest(const EntryMetadata& metadata) {
    std::ostringstream payload;
    appendLengthPrefixed(payload, metadata.unit_id_sha256);
    appendLengthPrefixed(payload, metadata.checkpoint_key_sha256);
    appendLengthPrefixed(payload, metadata.analyzer_sha256);
    appendLengthPrefixed(payload, metadata.configuration_sha256);
    appendLengthPrefixed(payload, metadata.dependency_sha256);
    appendLengthPrefixed(payload, metadata.input_sha256);
    appendLengthPrefixed(payload, metadata.request_sha256);
    appendLengthPrefixed(payload, metadata.response_sha256);
    appendLengthPrefixed(payload, metadata.summary_sha256);
    payload << (metadata.summary_exists ? 1 : 0) << '\n';
    return hashText(payload.str());
}

std::string entryDigest(const EntryMetadata& metadata) {
    std::ostringstream entry;
    appendLengthPrefixed(entry, metadata.payload_sha256);
    appendLengthPrefixed(entry, metadata.checkpoint_key_sha256);
    return hashText(entry.str());
}

template <typename CompletedMap>
std::string runManifestDigest(
    const std::string& analyzer_sha256,
    const std::string& configuration_sha256,
    const std::string& plan_sha256,
    const CompletedMap& completed) {
    std::ostringstream manifest;
    manifest << kEvidenceSchema << '\n';
    appendLengthPrefixed(manifest, analyzer_sha256);
    appendLengthPrefixed(manifest, configuration_sha256);
    appendLengthPrefixed(manifest, plan_sha256);
    manifest << completed.size() << '\n';
    for (const auto& [unit_id, entry] : completed) {
        appendLengthPrefixed(manifest, unit_id);
        appendLengthPrefixed(manifest, entry.checkpoint_key_sha256);
        appendLengthPrefixed(manifest, entry.payload_sha256);
    }
    return hashText(manifest.str());
}

bool onlyFields(const json::Object& object,
                std::initializer_list<const char*> names,
                const char* context,
                std::string& error) {
    std::set<std::string> allowed;
    for (const char* name : names) allowed.insert(name);
    for (const auto& entry : object) {
        if (!allowed.count(entry.first.str())) {
            error = std::string(context) + " contains unknown field: " +
                    entry.first.str();
            return false;
        }
    }
    return true;
}

bool stringField(const json::Object& object, const char* name,
                 std::string& value, std::string& error,
                 bool allow_empty = false) {
    const auto field = object.getString(name);
    if (!field || (!allow_empty && field->empty()) ||
        field->find('\0') != llvm::StringRef::npos) {
        error = std::string("invalid evidence string field: ") + name;
        return false;
    }
    value = field->str();
    return true;
}

bool deadlineExpired(EvidenceDeadline deadline, std::string& error) {
    if (deadline != EvidenceDeadline::max() &&
        std::chrono::steady_clock::now() >= deadline) {
        error = "translation-unit deadline exhausted during checkpoint evidence";
        return true;
    }
    return false;
}

bool readBounded(const fs::path& path, std::uintmax_t maximum,
                 std::string& text, std::string& error,
                 EvidenceDeadline deadline = EvidenceDeadline::max()) {
    if (deadlineExpired(deadline, error)) return false;
    std::error_code ec;
    const auto status = fs::symlink_status(path, ec);
    if (ec || !fs::is_regular_file(status)) {
        error = "evidence path is not a regular file: " + path.string();
        return false;
    }
    const auto size = fs::file_size(path, ec);
    if (ec || size > maximum) {
        error = "evidence file exceeds size limit: " + path.string();
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "cannot read evidence file: " + path.string();
        return false;
    }
    text.clear();
    text.reserve(static_cast<std::size_t>(size));
    std::vector<char> buffer(64u << 10);
    while (input) {
        if (deadlineExpired(deadline, error)) return false;
        input.read(buffer.data(),
                   static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) text.append(buffer.data(),
                                   static_cast<std::size_t>(count));
    }
    if (input.bad()) {
        error = "failed while reading evidence file: " + path.string();
        return false;
    }
    if (deadlineExpired(deadline, error)) return false;
    return true;
}

bool replaceFile(const fs::path& temporary, const fs::path& destination,
                 std::string& error) {
#ifdef _WIN32
    if (!MoveFileExW(temporary.c_str(), destination.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        error = "cannot atomically publish evidence file: " +
                std::to_string(GetLastError());
        return false;
    }
    return true;
#else
    std::error_code ec;
    fs::rename(temporary, destination, ec);
    if (ec) {
        error = "cannot atomically publish evidence file: " + ec.message();
        return false;
    }
    return true;
#endif
}

bool writeAtomicJson(const fs::path& path, json::Value value,
                     std::string& error,
                     EvidenceDeadline deadline = EvidenceDeadline::max()) {
    if (deadlineExpired(deadline, error)) return false;
    std::string text;
    llvm::raw_string_ostream stream(text);
    stream << value;
    stream.flush();
    text.push_back('\n');
    if (text.size() > kMaxManifestBytes) {
        error = "evidence JSON exceeds size limit: " + path.string();
        return false;
    }
    // A checkpoint directory is untrusted persisted input. Open the staging
    // path with create-new semantics so a pre-existing symlink or other node
    // cannot be followed and used to truncate a file outside the store.
    const fs::path temporary = path.string() + ".tmp";
    std::error_code staging_error;
    const auto staging_status = fs::symlink_status(temporary, staging_error);
    const bool staging_missing =
        staging_error == std::errc::no_such_file_or_directory ||
        (!staging_error &&
         staging_status.type() == fs::file_type::not_found);
    if (!staging_missing) {
        if (staging_error || !fs::is_regular_file(staging_status)) {
            error = "evidence staging path is not a regular file: " +
                    temporary.string();
            return false;
        }
        staging_error.clear();
        if (!fs::remove(temporary, staging_error) || staging_error) {
            error = "cannot recover stale evidence staging file: " +
                    temporary.string() + ": " +
                    staging_error.message();
            return false;
        }
    }
    int descriptor = -1;
    const std::error_code open_error = llvm::sys::fs::openFileForWrite(
        temporary.string(), descriptor, llvm::sys::fs::CD_CreateNew,
        llvm::sys::fs::OF_None);
    if (open_error) {
        error = "cannot create evidence file: " + temporary.string() +
                ": " + open_error.message();
        return false;
    }
    bool write_failed = false;
    {
        llvm::raw_fd_ostream output(descriptor, true);
        output.write(text.data(), static_cast<std::streamsize>(text.size()));
        output.flush();
        if (output.has_error()) {
            error = "failed while writing evidence file: " +
                    temporary.string();
            write_failed = true;
        }
    }
    if (write_failed) {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        return false;
    }
    if (deadlineExpired(deadline, error)) {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        return false;
    }
    std::error_code status_error;
    const auto temporary_status = fs::symlink_status(temporary, status_error);
    if (status_error || !fs::is_regular_file(temporary_status)) {
        error = "evidence staging path is not a regular file: " +
                temporary.string();
        return false;
    }
    if (deadlineExpired(deadline, error)) {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        return false;
    }
    if (!replaceFile(temporary, path, error)) {
        std::error_code ignored;
        fs::remove(temporary, ignored);
        return false;
    }
    return true;
}

bool parseJsonObject(const fs::path& path, std::uintmax_t maximum,
                     json::Value& storage, json::Object*& object,
                     std::string& error,
                     EvidenceDeadline deadline = EvidenceDeadline::max()) {
    std::string text;
    if (!readBounded(path, maximum, text, error, deadline)) return false;
    if (deadlineExpired(deadline, error)) return false;
    auto parsed = json::parse(text);
    if (!parsed) {
        llvm::consumeError(parsed.takeError());
        error = "invalid evidence JSON: " + path.string();
        return false;
    }
    if (deadlineExpired(deadline, error)) return false;
    storage = std::move(*parsed);
    object = storage.getAsObject();
    if (!object) {
        error = "evidence root is not an object: " + path.string();
        return false;
    }
    return true;
}

bool sameUnit(const TranslationUnitExecution& left,
              const TranslationUnitExecution& right) {
    return left.canonical_path == right.canonical_path &&
           left.working_directory == right.working_directory &&
           left.command_line == right.command_line &&
           left.output == right.output &&
           left.compile_command_sha256 == right.compile_command_sha256 &&
           left.command_ordinal == right.command_ordinal;
}

json::Object entryObject(const EntryMetadata& metadata) {
    return json::Object{
        {"schema", kEvidenceSchema},
        {"unit_id_sha256", metadata.unit_id_sha256},
        {"checkpoint_key_sha256", metadata.checkpoint_key_sha256},
        {"payload_sha256", metadata.payload_sha256},
        {"analyzer_sha256", metadata.analyzer_sha256},
        {"configuration_sha256", metadata.configuration_sha256},
        {"dependency_sha256", metadata.dependency_sha256},
        {"input_sha256", metadata.input_sha256},
        {"request_sha256", metadata.request_sha256},
        {"response_sha256", metadata.response_sha256},
        {"summary_sha256", metadata.summary_sha256},
        {"summary_exists", metadata.summary_exists},
        {"entry_sha256", metadata.entry_sha256},
    };
}

bool parseEntryMetadata(const fs::path& path, EntryMetadata& metadata,
                        std::string& error,
                        EvidenceDeadline deadline = EvidenceDeadline::max()) {
    json::Value storage(nullptr);
    json::Object* object = nullptr;
    if (!parseJsonObject(path, kMaxManifestBytes, storage, object, error,
                         deadline) ||
        !onlyFields(*object,
                    {"schema", "unit_id_sha256",
                     "checkpoint_key_sha256", "payload_sha256",
                     "analyzer_sha256", "configuration_sha256",
                     "dependency_sha256", "input_sha256", "request_sha256",
                     "response_sha256", "summary_sha256", "summary_exists",
                     "entry_sha256"},
                    "evidence entry", error) ||
        object->getInteger("schema") != kEvidenceSchema ||
        !stringField(*object, "unit_id_sha256",
                     metadata.unit_id_sha256, error) ||
        !stringField(*object, "checkpoint_key_sha256",
                     metadata.checkpoint_key_sha256, error) ||
        !stringField(*object, "payload_sha256",
                     metadata.payload_sha256, error) ||
        !stringField(*object, "analyzer_sha256",
                     metadata.analyzer_sha256, error) ||
        !stringField(*object, "configuration_sha256",
                     metadata.configuration_sha256, error) ||
        !stringField(*object, "dependency_sha256",
                     metadata.dependency_sha256, error) ||
        !stringField(*object, "input_sha256", metadata.input_sha256, error) ||
        !stringField(*object, "request_sha256",
                     metadata.request_sha256, error) ||
        !stringField(*object, "response_sha256",
                     metadata.response_sha256, error) ||
        !stringField(*object, "summary_sha256",
                     metadata.summary_sha256, error, true) ||
        !stringField(*object, "entry_sha256",
                     metadata.entry_sha256, error))
        return false;
    const auto summary_exists = object->getBoolean("summary_exists");
    if (!summary_exists) {
        error = "invalid evidence boolean field: summary_exists";
        return false;
    }
    metadata.summary_exists = *summary_exists;
    for (const auto* digest : {
             &metadata.unit_id_sha256, &metadata.checkpoint_key_sha256,
             &metadata.payload_sha256, &metadata.analyzer_sha256,
             &metadata.configuration_sha256, &metadata.dependency_sha256,
             &metadata.input_sha256, &metadata.request_sha256,
             &metadata.response_sha256, &metadata.entry_sha256}) {
        if (!validSha256(*digest)) {
            error = "invalid checksum in evidence entry";
            return false;
        }
    }
    if (metadata.summary_exists != validSha256(metadata.summary_sha256) ||
        payloadDigest(metadata) != metadata.payload_sha256 ||
        entryDigest(metadata) != metadata.entry_sha256) {
        error = "evidence entry checksum mismatch";
        return false;
    }
    return true;
}

bool sameEntryMetadata(const EntryMetadata& left,
                       const EntryMetadata& right) {
    return left.unit_id_sha256 == right.unit_id_sha256 &&
           left.checkpoint_key_sha256 == right.checkpoint_key_sha256 &&
           left.payload_sha256 == right.payload_sha256 &&
           left.analyzer_sha256 == right.analyzer_sha256 &&
           left.configuration_sha256 == right.configuration_sha256 &&
           left.dependency_sha256 == right.dependency_sha256 &&
           left.input_sha256 == right.input_sha256 &&
           left.request_sha256 == right.request_sha256 &&
           left.response_sha256 == right.response_sha256 &&
           left.summary_sha256 == right.summary_sha256 &&
           left.summary_exists == right.summary_exists &&
           left.entry_sha256 == right.entry_sha256;
}

bool validateEntryPayloadFiles(const fs::path& directory,
                               const EntryMetadata& metadata,
                               std::string& error,
                               EvidenceDeadline deadline =
                                   EvidenceDeadline::max()) {
    std::set<std::string> expected{
        "entry.json", "request.json", "response.json"};
    if (metadata.summary_exists) expected.insert("summary.csk");
    std::set<std::string> actual;
    std::error_code ec;
    for (fs::directory_iterator iterator(directory, ec), end;
         !ec && iterator != end; iterator.increment(ec)) {
        if (deadlineExpired(deadline, error)) return false;
        const auto status = iterator->symlink_status(ec);
        if (ec || !fs::is_regular_file(status)) {
            error = "evidence entry contains a non-regular payload";
            return false;
        }
        actual.insert(iterator->path().filename().string());
    }
    if (ec || actual != expected) {
        error = "evidence entry file set is inconsistent";
        return false;
    }

    std::string request;
    std::string response;
    if (!readBounded(directory / "request.json", kMaxPayloadBytes,
                     request, error, deadline) ||
        !readBounded(directory / "response.json", kMaxPayloadBytes,
                     response, error, deadline) ||
        hashText(request) != metadata.request_sha256 ||
        hashText(response) != metadata.response_sha256) {
        if (error.empty()) error = "evidence payload checksum mismatch";
        return false;
    }
    if (!metadata.summary_exists) return true;
    std::string summary;
    if (!readBounded(directory / "summary.csk", kMaxPayloadBytes,
                     summary, error, deadline) ||
        hashText(summary) != metadata.summary_sha256) {
        if (error.empty()) error = "evidence summary checksum mismatch";
        return false;
    }
    return true;
}

} // anonymous namespace

std::string sha256RegularFileStreaming(const std::string& path,
                                       std::string& error,
                                       EvidenceDeadline deadline) {
    if (deadlineExpired(deadline, error)) return {};
    std::error_code ec;
    const auto status = fs::status(path, ec);
    if (ec || !fs::is_regular_file(status)) {
        error = "path is not a regular file: " + path;
        return {};
    }
    const auto size = fs::file_size(path, ec);
    if (ec || size > kMaxHashedFileBytes) {
        error = "file exceeds evidence hash limit: " + path;
        return {};
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "cannot read file for evidence hash: " + path;
        return {};
    }
    llvm::SHA256 hasher;
    std::vector<char> buffer(64u << 10);
    while (input) {
        if (deadlineExpired(deadline, error)) return {};
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0) {
            hasher.update(llvm::ArrayRef<std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(buffer.data()),
                static_cast<std::size_t>(count)));
        }
    }
    if (input.bad()) {
        error = "failed while hashing evidence file: " + path;
        return {};
    }
    if (deadlineExpired(deadline, error)) return {};
    const auto digest = hasher.final();
    return llvm::toHex(llvm::ArrayRef<std::uint8_t>(digest), true);
}

std::string orderedInputFilesSha256(const std::vector<std::string>& paths,
                                    std::string& error,
                                    EvidenceDeadline deadline) {
    if (deadlineExpired(deadline, error)) return {};
    std::ostringstream identity;
    identity << paths.size() << '\n';
    for (const auto& path : paths) {
        const std::string digest =
            sha256RegularFileStreaming(path, error, deadline);
        if (digest.empty()) return {};
        appendLengthPrefixed(identity, digest);
    }
    return hashText(identity.str());
}

std::unique_ptr<UnitEvidenceStore> UnitEvidenceStore::open(
    const std::string& directory,
    const std::vector<TranslationUnitExecution>& units,
    bool whole_program,
    const std::string& analyzer_program,
    const std::vector<std::string>& configuration_arguments,
    const std::vector<std::string>& rule_ids,
    ResourceLimits limits,
    std::string& error,
    bool namespace_by_run_identity) {
    error.clear();
    if (directory.empty()) {
        error = "checkpoint directory is empty";
        return nullptr;
    }
    auto store = std::unique_ptr<UnitEvidenceStore>(new UnitEvidenceStore());
    store->analyzer_program_ = analyzer_program;
    store->analyzer_sha256_ =
        sha256RegularFileStreaming(analyzer_program, error);
    if (store->analyzer_sha256_.empty()) return nullptr;
    store->analyzer_metadata_identity_ =
        fileMetadataIdentity(analyzer_program, error);
    if (store->analyzer_metadata_identity_.empty()) return nullptr;
    store->configuration_sha256_ = configurationDigest(
        configuration_arguments, rule_ids, limits, whole_program);
    store->plan_sha256_ = planDigest(units, whole_program);
    for (const auto& unit : units) {
        if (whole_program) {
            store->planned_unit_ids_.insert(
                unitId(unit, TranslationUnitPhase::SummaryHarvest));
        }
        store->planned_unit_ids_.insert(
            unitId(unit, TranslationUnitPhase::Analysis));
    }

    fs::path root(directory);
    std::error_code ec;
    if (namespace_by_run_identity) {
        const auto ensure_real_directory = [&](const fs::path& path,
                                               const char* description) {
            ec.clear();
            const auto path_status = fs::symlink_status(path, ec);
            const bool path_missing =
                ec == std::errc::no_such_file_or_directory ||
                (!ec && path_status.type() == fs::file_type::not_found);
            if (path_missing) {
                ec.clear();
                fs::create_directories(path, ec);
                if (ec) {
                    error = std::string("cannot create ") + description +
                            ": " + ec.message();
                    return false;
                }
                return true;
            }
            if (ec || !fs::is_directory(path_status)) {
                error = std::string(description) +
                        " is not a real directory";
                return false;
            }
            return true;
        };
        if (!ensure_real_directory(root, "checkpoint namespace root"))
            return nullptr;
        const fs::path requests = root / "requests";
        if (!ensure_real_directory(requests,
                                   "checkpoint requests path"))
            return nullptr;
        std::ostringstream identity;
        identity << kEvidenceSchema << '\n';
        appendLengthPrefixed(identity, store->analyzer_sha256_);
        appendLengthPrefixed(identity, store->configuration_sha256_);
        appendLengthPrefixed(identity, store->plan_sha256_);
        // The manifest still binds the full analyzer/configuration/plan
        // digests. A 128-bit directory discriminator keeps ordinary Windows
        // checkpoint paths below MAX_PATH; a collision remains fail-closed
        // because the full manifest identity is validated on open.
        root = requests / hashText(identity.str()).substr(0, 32);
    }
    store->directory_ = root.string();
    ec.clear();
    const auto status = fs::symlink_status(root, ec);
    const bool missing =
        ec == std::errc::no_such_file_or_directory ||
        (!ec && status.type() == fs::file_type::not_found);
    if (missing) {
        ec.clear();
        fs::create_directories(root / "entries", ec);
        if (ec) {
            error = "cannot create checkpoint directory: " + ec.message();
            return nullptr;
        }
    } else if (ec || !fs::is_directory(status)) {
        error = "checkpoint path is not a real directory";
        return nullptr;
    }

    const fs::path manifest_path = root / "manifest.json";
    ec.clear();
    const auto manifest_status = fs::symlink_status(manifest_path, ec);
    const bool manifest_missing =
        ec == std::errc::no_such_file_or_directory ||
        (!ec && manifest_status.type() == fs::file_type::not_found);
    if (manifest_missing) {
        ec.clear();
        const fs::path entries_path = root / "entries";
        const auto entries_status = fs::symlink_status(entries_path, ec);
        const bool entries_missing =
            ec == std::errc::no_such_file_or_directory ||
            (!ec && entries_status.type() == fs::file_type::not_found);
        if (entries_missing) {
            ec.clear();
            fs::create_directories(entries_path, ec);
            if (ec) {
                error = "cannot create checkpoint entries directory: " +
                        ec.message();
                return nullptr;
            }
        } else if (ec || !fs::is_directory(entries_status)) {
            error = "checkpoint entries path is not a real directory";
            return nullptr;
        }
        if (!store->writeRunManifest(error)) return nullptr;
        return store;
    }
    if (ec || !fs::is_regular_file(manifest_status)) {
        error = "checkpoint manifest is not a real file";
        return nullptr;
    }
    ec.clear();
    const auto entries_status = fs::symlink_status(root / "entries", ec);
    if (ec || !fs::is_directory(entries_status)) {
        error = "checkpoint entries path is not a real directory";
        return nullptr;
    }

    json::Value storage(nullptr);
    json::Object* object = nullptr;
    if (!parseJsonObject(manifest_path, kMaxManifestBytes,
                         storage, object, error) ||
        !onlyFields(*object,
                    {"schema", "analyzer_sha256", "configuration_sha256",
                     "plan_sha256", "completed", "manifest_sha256"},
                    "checkpoint manifest", error) ||
        object->getInteger("schema") != kEvidenceSchema) {
        if (error.empty()) error = "checkpoint manifest schema is incompatible";
        return nullptr;
    }
    std::string analyzer;
    std::string configuration;
    std::string plan;
    std::string manifest_sha;
    if (!stringField(*object, "analyzer_sha256", analyzer, error) ||
        !stringField(*object, "configuration_sha256", configuration, error) ||
        !stringField(*object, "plan_sha256", plan, error) ||
        !stringField(*object, "manifest_sha256", manifest_sha, error))
        return nullptr;
    const auto* completed = object->getArray("completed");
    if (!completed || completed->size() > 200000) {
        error = "checkpoint manifest has invalid completed set";
        return nullptr;
    }
    std::string previous;
    for (const auto& item : *completed) {
        const auto* entry = item.getAsObject();
        std::string unit_id;
        CompletedEntry completed_entry;
        if (!entry ||
            !onlyFields(*entry,
                        {"unit_id_sha256", "checkpoint_key_sha256",
                         "payload_sha256"},
                        "checkpoint completion", error) ||
            !stringField(*entry, "unit_id_sha256", unit_id, error) ||
            !stringField(*entry, "checkpoint_key_sha256",
                         completed_entry.checkpoint_key_sha256, error) ||
            !stringField(*entry, "payload_sha256",
                         completed_entry.payload_sha256, error) ||
            !validSha256(unit_id) ||
            !validSha256(completed_entry.checkpoint_key_sha256) ||
            !validSha256(completed_entry.payload_sha256) ||
            (!previous.empty() && previous >= unit_id) ||
            !store->planned_unit_ids_.count(unit_id)) {
            if (error.empty()) error = "checkpoint completion is corrupt";
            return nullptr;
        }
        previous = unit_id;
        store->completed_.emplace(unit_id, std::move(completed_entry));
    }
    if (!validSha256(analyzer) || !validSha256(configuration) ||
        !validSha256(plan) || !validSha256(manifest_sha) ||
        runManifestDigest(analyzer, configuration, plan,
                          store->completed_) != manifest_sha) {
        error = "checkpoint manifest checksum is corrupt";
        return nullptr;
    }
    if (analyzer != store->analyzer_sha256_ ||
        configuration != store->configuration_sha256_ ||
        plan != store->plan_sha256_) {
        error = "checkpoint manifest is incompatible with this exact run";
        return nullptr;
    }
    return store;
}

bool UnitEvidenceStore::verifyAnalyzerIdentity(
    std::string& error, EvidenceDeadline deadline) const {
    error.clear();
    if (deadlineExpired(deadline, error)) return false;
    const std::string metadata =
        fileMetadataIdentity(analyzer_program_, error);
    if (metadata.empty()) {
        error = "cannot verify analyzer identity: " + error;
        return false;
    }
    if (metadata == analyzer_metadata_identity_) return true;
    const std::string current =
        sha256RegularFileStreaming(analyzer_program_, error, deadline);
    if (current.empty()) {
        error = "cannot verify analyzer identity: " + error;
        return false;
    }
    if (current != analyzer_sha256_) {
        error = "analyzer identity changed during checkpointed run";
        return false;
    }
    analyzer_metadata_identity_ = metadata;
    return true;
}

bool UnitEvidenceStore::writeRunManifest(
    std::string& error, EvidenceDeadline deadline) const {
    if (deadlineExpired(deadline, error)) return false;
    json::Array completed;
    for (const auto& [unit_id, entry] : completed_) {
        completed.push_back(json::Object{
            {"unit_id_sha256", unit_id},
            {"checkpoint_key_sha256", entry.checkpoint_key_sha256},
            {"payload_sha256", entry.payload_sha256},
        });
    }
    json::Object manifest{
        {"schema", kEvidenceSchema},
        {"analyzer_sha256", analyzer_sha256_},
        {"configuration_sha256", configuration_sha256_},
        {"plan_sha256", plan_sha256_},
        {"completed", std::move(completed)},
        {"manifest_sha256",
         runManifestDigest(analyzer_sha256_, configuration_sha256_,
                           plan_sha256_, completed_)},
    };
    return writeAtomicJson(fs::path(directory_) / "manifest.json",
                           json::Value(std::move(manifest)), error, deadline);
}

EvidenceLookupStatus UnitEvidenceStore::lookup(
    const TranslationUnitExecution& unit,
    TranslationUnitPhase phase,
    const DependencyManifest& dependencies,
    const std::string& input_sha256,
    CachedUnitEvidence& cached,
    std::string& error,
    EvidenceDeadline deadline) const {
    cached = {};
    error.clear();
    if (!verifyAnalyzerIdentity(error, deadline))
        return EvidenceLookupStatus::Failed;
    if (!validSha256(dependencies.sha256) ||
        dependencyManifestSha256(dependencies) != dependencies.sha256 ||
        !validSha256(input_sha256)) {
        error = "current cache identity evidence is invalid";
        return EvidenceLookupStatus::Failed;
    }
    if (!dependencies.cacheable) return EvidenceLookupStatus::Miss;
    const std::string unit_id = unitId(unit, phase);
    if (!planned_unit_ids_.count(unit_id)) {
        error = "cache lookup unit is outside the exact run plan";
        return EvidenceLookupStatus::Failed;
    }
    const std::string key = cacheKey(
        analyzer_sha256_, configuration_sha256_, unit, phase,
        dependencies, input_sha256);
    const auto completed = completed_.find(unit_id);
    if (completed == completed_.end() ||
        completed->second.checkpoint_key_sha256 != key)
        return EvidenceLookupStatus::Miss;

    const fs::path entry_directory =
        fs::path(directory_) / "entries" / key;
    std::error_code ec;
    const auto status = fs::symlink_status(entry_directory, ec);
    if (ec || !fs::is_directory(status)) {
        error = "expected cache entry is corrupt: missing directory";
        return EvidenceLookupStatus::Failed;
    }
    EntryMetadata metadata;
    if (!parseEntryMetadata(entry_directory / "entry.json", metadata, error,
                            deadline)) {
        error = "expected cache entry is corrupt: " + error;
        return EvidenceLookupStatus::Failed;
    }
    if (metadata.unit_id_sha256 != unit_id ||
        metadata.checkpoint_key_sha256 != key ||
        metadata.payload_sha256 != completed->second.payload_sha256 ||
        metadata.analyzer_sha256 != analyzer_sha256_ ||
        metadata.configuration_sha256 != configuration_sha256_ ||
        metadata.dependency_sha256 != dependencies.sha256 ||
        metadata.input_sha256 != input_sha256) {
        error = "expected cache entry is corrupt: identity mismatch";
        return EvidenceLookupStatus::Failed;
    }
    std::string hash_error;
    if (!validateEntryPayloadFiles(entry_directory, metadata, hash_error,
                                   deadline)) {
        error = "expected cache entry is corrupt: " + hash_error;
        return EvidenceLookupStatus::Failed;
    }
    WorkerRequest request;
    const bool request_valid = readWorkerRequest(
        (entry_directory / "request.json").string(), request, hash_error);
    if (!request_valid || !sameUnit(request.unit, unit) ||
        request.phase != phase) {
        if (deadlineExpired(deadline, error))
            return EvidenceLookupStatus::Failed;
        error = "expected cache entry is corrupt: invalid stored request";
        return EvidenceLookupStatus::Failed;
    }
    if (deadlineExpired(deadline, error))
        return EvidenceLookupStatus::Failed;
    WorkerResponse response;
    const bool response_valid = readWorkerResponse(
        (entry_directory / "response.json").string(), request, response,
        hash_error);
    if (!response_valid ||
        !(response.dependency_manifest == dependencies) ||
        response.analysis.hasHardFailure() ||
        response.analysis.hasIncompleteEvidence()) {
        if (deadlineExpired(deadline, error))
            return EvidenceLookupStatus::Failed;
        error = "expected cache entry is corrupt: invalid stored response";
        return EvidenceLookupStatus::Failed;
    }
    if (deadlineExpired(deadline, error))
        return EvidenceLookupStatus::Failed;
    std::string summary;
    if (metadata.summary_exists) {
        if (!readBounded(entry_directory / "summary.csk", kMaxPayloadBytes,
                         summary, hash_error, deadline) ||
            hashText(summary) != metadata.summary_sha256 ||
            response.summary_fragment_sha256 != metadata.summary_sha256) {
            error = hash_error.find("deadline exhausted") !=
                            std::string::npos
                ? hash_error
                : "expected cache entry is corrupt: summary checksum mismatch";
            return EvidenceLookupStatus::Failed;
        }
    } else if (!response.summary_fragment_sha256.empty()) {
        error = "expected cache entry is corrupt: missing summary fragment";
        return EvidenceLookupStatus::Failed;
    }

    cached.response = std::move(response);
    cached.summary_fragment = std::move(summary);
    cached.checkpoint_key_sha256 = key;
    cached.payload_sha256 = metadata.payload_sha256;
    if (deadlineExpired(deadline, error)) {
        cached = {};
        return EvidenceLookupStatus::Failed;
    }
    return EvidenceLookupStatus::Hit;
}

bool UnitEvidenceStore::store(
    const TranslationUnitExecution& unit,
    TranslationUnitPhase phase,
    const DependencyManifest& dependencies,
    const std::string& input_sha256,
    const WorkerResponse& response,
    const std::string& summary_fragment,
    std::string& checkpoint_key_sha256,
    std::string& payload_sha256,
    std::string& error,
    EvidenceDeadline deadline) {
    error.clear();
    checkpoint_key_sha256.clear();
    payload_sha256.clear();
    if (!verifyAnalyzerIdentity(error, deadline)) return false;
    if (!validSha256(dependencies.sha256) ||
        dependencyManifestSha256(dependencies) != dependencies.sha256 ||
        !validSha256(input_sha256) || !dependencies.cacheable ||
        response.canonical_path != unit.canonical_path ||
        response.compile_command_sha256 != unit.compile_command_sha256 ||
        response.command_ordinal != unit.command_ordinal ||
        response.phase != phase ||
        !(response.dependency_manifest == dependencies) ||
        response.analysis.hasHardFailure() ||
        response.analysis.hasIncompleteEvidence()) {
        error = "refusing to cache incomplete or inconsistent worker evidence";
        return false;
    }

    const std::string unit_id = unitId(unit, phase);
    if (!planned_unit_ids_.count(unit_id)) {
        error = "refusing to cache a unit outside the exact run plan";
        return false;
    }
    const std::string key = cacheKey(
        analyzer_sha256_, configuration_sha256_, unit, phase,
        dependencies, input_sha256);
    const fs::path entries = fs::path(directory_) / "entries";
    const fs::path final_directory = entries / key;
    const fs::path temporary = entries / (key + ".tmp");
    std::error_code ec;
    const auto staging_status = fs::symlink_status(temporary, ec);
    const bool staging_missing =
        ec == std::errc::no_such_file_or_directory ||
        (!ec && staging_status.type() == fs::file_type::not_found);
    if (!staging_missing) {
        if (ec || !fs::is_directory(staging_status)) {
            error = "cache entry staging path is not a real directory";
            return false;
        }
        ec.clear();
        fs::remove_all(temporary, ec);
        if (ec) {
            error = "cannot recover stale cache entry staging directory: " +
                    ec.message();
            return false;
        }
    }
    ec.clear();
    fs::create_directory(temporary, ec);
    if (ec) {
        error = "cannot create cache entry staging directory: " + ec.message();
        return false;
    }
    const auto cleanup = [&] {
        std::error_code ignored;
        fs::remove_all(temporary, ignored);
    };

    WorkerRequest request;
    request.request_id = "checkpoint:" + key;
    request.unit = unit;
    request.phase = phase;
    request.response_path = "response.json";
    if (!summary_fragment.empty()) request.summary_fragment_path = "summary.csk";
    WorkerResponse stored_response = response;
    stored_response.request_id = request.request_id;
    stored_response.summary_fragment_sha256 =
        summary_fragment.empty() ? std::string{} : hashText(summary_fragment);

    if (!writeWorkerRequest((temporary / "request.json").string(),
                            request, error) ||
        !writeWorkerResponse((temporary / "response.json").string(),
                             stored_response, error)) {
        cleanup();
        return false;
    }
    if (deadlineExpired(deadline, error)) {
        cleanup();
        return false;
    }
    if (!summary_fragment.empty()) {
        std::ofstream summary(temporary / "summary.csk",
                              std::ios::binary | std::ios::trunc);
        summary.write(summary_fragment.data(),
                      static_cast<std::streamsize>(summary_fragment.size()));
        summary.flush();
        if (!summary.good()) {
            cleanup();
            error = "cannot stage cache summary fragment";
            return false;
        }
        if (deadlineExpired(deadline, error)) {
            cleanup();
            return false;
        }
    }

    EntryMetadata metadata;
    metadata.unit_id_sha256 = unit_id;
    metadata.checkpoint_key_sha256 = key;
    metadata.analyzer_sha256 = analyzer_sha256_;
    metadata.configuration_sha256 = configuration_sha256_;
    metadata.dependency_sha256 = dependencies.sha256;
    metadata.input_sha256 = input_sha256;
    metadata.request_sha256 = sha256RegularFileStreaming(
        (temporary / "request.json").string(), error, deadline);
    metadata.response_sha256 = sha256RegularFileStreaming(
        (temporary / "response.json").string(), error, deadline);
    metadata.summary_exists = !summary_fragment.empty();
    if (metadata.summary_exists)
        metadata.summary_sha256 = hashText(summary_fragment);
    if (metadata.request_sha256.empty() || metadata.response_sha256.empty()) {
        cleanup();
        return false;
    }
    metadata.payload_sha256 = payloadDigest(metadata);
    metadata.entry_sha256 = entryDigest(metadata);
    if (!writeAtomicJson(temporary / "entry.json",
                         json::Value(entryObject(metadata)), error,
                         deadline)) {
        cleanup();
        return false;
    }

    const auto final_status = fs::symlink_status(final_directory, ec);
    const bool final_missing =
        ec == std::errc::no_such_file_or_directory ||
        (!ec && final_status.type() == fs::file_type::not_found);
    if (final_missing) {
        if (deadlineExpired(deadline, error)) {
            cleanup();
            return false;
        }
        ec.clear();
        fs::rename(temporary, final_directory, ec);
        if (ec) {
            cleanup();
            error = "cannot atomically publish cache entry: " + ec.message();
            return false;
        }
    } else {
        EntryMetadata existing;
        std::string existing_error;
        if (ec || !fs::is_directory(final_status) ||
            !parseEntryMetadata(final_directory / "entry.json", existing,
                                existing_error, deadline) ||
            !sameEntryMetadata(existing, metadata) ||
            !validateEntryPayloadFiles(final_directory, existing,
                                       existing_error, deadline)) {
            cleanup();
            error = existing_error.find("deadline exhausted") !=
                            std::string::npos
                ? existing_error
                : "existing content-addressed cache entry is corrupt";
            return false;
        }
        cleanup();
    }

    // Content-addressed payloads may remain as harmless orphans, but an
    // analyzer that changed while staging must never enter the authoritative
    // completed manifest.
    if (!verifyAnalyzerIdentity(error, deadline)) return false;

    const auto previous = completed_.find(unit_id);
    const bool had_previous = previous != completed_.end();
    CompletedEntry previous_value;
    if (had_previous) previous_value = previous->second;
    completed_[unit_id] = {key, metadata.payload_sha256};
    if (!writeRunManifest(error, deadline)) {
        if (had_previous) completed_[unit_id] = std::move(previous_value);
        else completed_.erase(unit_id);
        return false;
    }
    if (deadlineExpired(deadline, error)) {
        if (had_previous) completed_[unit_id] = std::move(previous_value);
        else completed_.erase(unit_id);
        std::string rollback_error;
        if (!writeRunManifest(rollback_error))
            error += "; cannot roll back timed-out checkpoint manifest: " +
                     rollback_error;
        return false;
    }
    checkpoint_key_sha256 = key;
    payload_sha256 = metadata.payload_sha256;
    return true;
}

} // namespace codeskeptic
