#include "source_manager/InputIdentity.h"
#include "contracts/ModelInput.h"
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Lex/PPCallbacks.h>
#include <clang/Lex/Preprocessor.h>
#include <llvm/ADT/SmallString.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/Path.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <map>
#include <set>
#include <stdexcept>

#ifdef __APPLE__
#include <crt_externs.h>
#elif !defined(_WIN32)
extern char** environ;
#endif

namespace codeskeptic {
namespace {
using Kind = InputObservationKind;
namespace vfs = llvm::vfs;
thread_local std::weak_ptr<InputRecordingState> active_recording;

void field(std::string& output, const std::string& value) {
    if (value.size() > kInputIdentityLimit || output.size() > kInputIdentityLimit - 4 ||
        value.size() > kInputIdentityLimit - output.size() - 4)
        throw std::runtime_error("input identity bound exceeded");
    const auto length = static_cast<std::uint32_t>(value.size());
    for (unsigned i = 0; i != 4; ++i) output.push_back(static_cast<char>(length >> (8 * i)));
    output += value;
}
std::string statusValue(const llvm::ErrorOr<vfs::Status>& status) {
    if (!status) return "error:" + std::to_string(status.getError().value());
    const auto& s = *status;
    std::string result;
    // PhysicalFileSystem echoes the query spelling in Status::Name (relative
    // versus absolute, './'). The observation already binds the absolute query;
    // that presentation spelling is not an independently changing input.
    field(result, std::to_string(static_cast<unsigned>(s.getType())));
    field(result, std::to_string(static_cast<unsigned>(s.getPermissions())));
    field(result, std::to_string(s.getUniqueID().getDevice()));
    field(result, std::to_string(s.getUniqueID().getFile()));
    field(result, std::to_string(s.getUser()));
    field(result, std::to_string(s.getGroup()));
    field(result, std::to_string(s.getSize()));
    field(result, std::to_string(s.getLastModificationTime().time_since_epoch().count()));
    return result;
}
bool ordinaryStatus(const llvm::ErrorOr<vfs::Status>& status) {
    if (status) return status->isRegularFile() || status->isDirectory();
    return status.getError() == std::errc::no_such_file_or_directory ||
           status.getError() == std::errc::not_a_directory;
}
std::string absolutePath(vfs::FileSystem& fs, const llvm::Twine& path) {
    llvm::SmallString<256> full(path.str());
    if (fs.makeAbsolute(full)) return {};
    // Do not lexically remove '..': it can have different meaning after a
    // symlink component. Keep the actual absolute query spelling.
    llvm::sys::path::remove_dots(full, /*remove_dot_dot=*/false);
    return full.str().str();
}
std::string bufferValue(llvm::StringRef bytes) {
    return std::to_string(bytes.size()) + ":" + inputDigest(bytes.str());
}
struct DirectorySnapshot {
    std::vector<vfs::directory_entry> entries;
    std::error_code error;
    bool bounded = true;
};
bool ordinaryDirectory(const DirectorySnapshot& snapshot) {
    return snapshot.bounded && (!snapshot.error ||
        (snapshot.entries.empty() && (snapshot.error == std::errc::no_such_file_or_directory ||
                                     snapshot.error == std::errc::not_a_directory)));
}
DirectorySnapshot readDirectory(vfs::FileSystem& fs, const std::string& path) {
    DirectorySnapshot result;
    auto cursor = fs.dir_begin(path, result.error);
    std::size_t bytes = 0;
    while (!result.error && cursor != vfs::directory_iterator{}) {
        bytes += cursor->path().size();
        if (result.entries.size() >= kInputObservationLimit || bytes > kInputIdentityLimit) {
            result.bounded = false;
            break;
        }
        result.entries.push_back(*cursor);
        cursor.increment(result.error);
    }
    return result;
}
std::string directoryValue(const DirectorySnapshot& directory) {
    std::string result;
    field(result, std::to_string(directory.error.value()));
    for (const auto& entry : directory.entries) {
        field(result, entry.path().str());
        field(result, std::to_string(static_cast<unsigned>(entry.type())));
    }
    return inputDigest(result);
}
bool absoluteObservationPath(const std::string& path) {
    return !path.empty() && path.find('\0') == std::string::npos &&
           std::filesystem::path(path).is_absolute();
}
} // namespace

struct InputRecordingState {
    InputIdentity identity;
    std::map<std::pair<unsigned, std::string>, std::string> seen;
    std::size_t bytes = 0, buffer_bytes = 0;
    void refuse(const std::string& reason) {
        if (identity.reusable) identity.reason = reason;
        identity.reusable = false;
    }
    void add(Kind kind, const std::string& path, const std::string& value) {
        if (!identity.reusable) return;
        if (kind != Kind::Frontend && !absoluteObservationPath(path)) {
            refuse("unresolved_input_path"); return;
        }
        const auto key = std::make_pair(static_cast<unsigned>(kind), path);
        auto found = seen.find(key);
        if (found != seen.end()) {
            if (found->second != value) refuse("input_changed_during_consumption");
            return;
        }
        const std::size_t added = path.size() + value.size() + 16;
        if (seen.size() >= kInputObservationLimit || added > kInputIdentityLimit ||
            bytes > kInputIdentityLimit - added) { refuse("input_evidence_bound"); return; }
        bytes += added;
        seen.emplace(key, value);
        identity.observations.push_back({kind, path, value});
    }
};

namespace {
class SnapshotIterator : public vfs::detail::DirIterImpl {
public:
    explicit SnapshotIterator(std::vector<vfs::directory_entry> entries)
        : entries_(std::move(entries)) {
        if (!entries_.empty()) CurrentEntry = entries_.front();
    }
    std::error_code increment() override {
        CurrentEntry = ++position_ < entries_.size() ? entries_[position_] : vfs::directory_entry{};
        return {};
    }
private:
    std::vector<vfs::directory_entry> entries_;
    std::size_t position_ = 0;
};
class ObservedFile : public vfs::File {
public:
    ObservedFile(std::unique_ptr<vfs::File> file, std::string path, bool binary,
                 std::shared_ptr<InputRecordingState> state)
        : file_(std::move(file)), path_(std::move(path)), binary_(binary), state_(std::move(state)) {}
    ~ObservedFile() override { if (file_) file_->close(); }
    llvm::ErrorOr<vfs::Status> status() override {
        auto result = file_->status();
        if (!ordinaryStatus(result)) state_->refuse("unsupported_file_status");
        state_->add(Kind::Status, path_, statusValue(result));
        return result;
    }
    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> getBuffer(const llvm::Twine& name,
        int64_t size, bool terminated, bool volatile_file) override {
        if (volatile_file) state_->refuse("volatile_file_read");
        if (!state_->identity.reusable)
            return file_->getBuffer(name, size, terminated, volatile_file);
        status();
        auto result = file_->getBuffer(name, size, terminated, volatile_file);
        if (!result) { state_->refuse("input_buffer_unavailable"); return result; }
        status();
        const auto bytes = (*result)->getBuffer();
        if (bytes.size() > kInputBufferLimit ||
            state_->buffer_bytes > kInputTotalBufferLimit - std::min(bytes.size(), kInputTotalBufferLimit)) {
            state_->refuse("input_buffer_bound"); return result;
        }
        if (state_->identity.reusable) {
            // Own the bytes returned by THIS read. Never replay an earlier
            // buffer: a contradictory second read must be observed and refuse
            // reuse, not silently change ordinary frontend consumption.
            auto owned = llvm::MemoryBuffer::getMemBufferCopy(bytes, name.str());
            state_->buffer_bytes += bytes.size();
            state_->add(binary_ ? Kind::BinaryBuffer : Kind::TextBuffer, path_, bufferValue(owned->getBuffer()));
            return owned;
        }
        return result;
    }
    std::error_code close() override {
        if (!file_) return {};
        auto error = file_->close(); file_.reset(); return error;
    }
private:
    std::unique_ptr<vfs::File> file_;
    std::string path_;
    bool binary_;
    std::shared_ptr<InputRecordingState> state_;
};
class ObservedFileSystem : public vfs::ProxyFileSystem {
public:
    explicit ObservedFileSystem(std::shared_ptr<InputRecordingState> state)
        : ProxyFileSystem(llvm::IntrusiveRefCntPtr<vfs::FileSystem>(vfs::createPhysicalFileSystem().release())),
          state_(std::move(state)) {}
    llvm::ErrorOr<vfs::Status> status(const llvm::Twine& path) override {
        auto result = getUnderlyingFS().status(path);
        if (!ordinaryStatus(result)) state_->refuse("unsupported_file_status");
        state_->add(Kind::Status, absolutePath(getUnderlyingFS(), path), statusValue(result));
        return result;
    }
    bool exists(const llvm::Twine& path) override {
        // ProxyFileSystem forwards exists directly; status alone cannot record
        // this query (notably __has_include without a subsequent include).
        const bool result = getUnderlyingFS().exists(path);
        status(path);
        state_->add(Kind::Exists, absolutePath(getUnderlyingFS(), path), result ? "1" : "0");
        return result;
    }
    llvm::ErrorOr<std::unique_ptr<vfs::File>> openFileForRead(const llvm::Twine& path) override {
        return open(path, false);
    }
    llvm::ErrorOr<std::unique_ptr<vfs::File>> openFileForReadBinary(const llvm::Twine& path) override {
        return open(path, true);
    }
    vfs::directory_iterator dir_begin(const llvm::Twine& path, std::error_code& error) override {
        if (!state_->identity.reusable) return getUnderlyingFS().dir_begin(path, error);
        const auto full = absolutePath(getUnderlyingFS(), path);
        const auto snapshot = readDirectory(getUnderlyingFS(), full);
        if (!ordinaryDirectory(snapshot)) {
            state_->refuse("directory_observation_unavailable");
            return getUnderlyingFS().dir_begin(path, error);
        }
        try { state_->add(Kind::Directory, full, directoryValue(snapshot)); }
        catch (const std::runtime_error&) {
            state_->refuse("directory_evidence_bound");
            return getUnderlyingFS().dir_begin(path, error);
        }
        error = snapshot.error;
        return vfs::directory_iterator(std::make_shared<SnapshotIterator>(snapshot.entries));
    }
    std::error_code getRealPath(const llvm::Twine& path, llvm::SmallVectorImpl<char>& output) override {
        auto error = getUnderlyingFS().getRealPath(path, output);
        if (error) state_->refuse("real_path_unavailable");
        else state_->add(Kind::RealPath, absolutePath(getUnderlyingFS(), path),
                         std::string(output.begin(), output.end()));
        return error;
    }
    std::error_code isLocal(const llvm::Twine& path, bool& local) override {
        auto error = getUnderlyingFS().isLocal(path, local);
        if (error) state_->refuse("filesystem_locality_unavailable");
        else state_->add(Kind::Local, absolutePath(getUnderlyingFS(), path), local ? "1" : "0");
        return error;
    }
private:
    llvm::ErrorOr<std::unique_ptr<vfs::File>> open(const llvm::Twine& path, bool binary) {
        const auto full = absolutePath(getUnderlyingFS(), path);
        auto file = binary ? getUnderlyingFS().openFileForReadBinary(path) : getUnderlyingFS().openFileForRead(path);
        if (!file) {
            const auto metadata = status(path);
            // Missing path observations can be revalidated. A successful stat
            // cannot witness a failed open (EMFILE, ACLs, I/O errors, races).
            if ((file.getError() != std::errc::no_such_file_or_directory &&
                 file.getError() != std::errc::not_a_directory) ||
                metadata || metadata.getError() != file.getError()) state_->refuse("input_open_unavailable");
            return file.getError();
        }
        return std::unique_ptr<vfs::File>(new ObservedFile(std::move(*file), full, binary, state_));
    }
    std::shared_ptr<InputRecordingState> state_;
};
class VolatileCallbacks : public clang::PPCallbacks {
public:
    explicit VolatileCallbacks(std::weak_ptr<InputRecordingState> state) : state_(std::move(state)) {}
    void MacroExpands(const clang::Token& token, const clang::MacroDefinition&,
                      clang::SourceRange, const clang::MacroArgs*) override {
        const auto* id = token.getIdentifierInfo();
        if (id && (id->getName() == "__DATE__" || id->getName() == "__TIME__" || id->getName() == "__TIMESTAMP__"))
            if (auto state = state_.lock()) state->refuse("volatile_builtin");
    }
private:
    std::weak_ptr<InputRecordingState> state_;
};
} // namespace

std::string inputDigest(const std::string& bytes) {
    const auto digest = llvm::SHA256::hash(llvm::ArrayRef<std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size()));
    static const char* hex = "0123456789abcdef";
    std::string result;
    for (auto byte : digest) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}
std::string inputEnvironmentIdentity() {
#ifdef _WIN32
    // Enumerate the same complete CRT table consumed by getenv. The secure
    // per-name getters cannot discover unknown names; _get_environ is not an
    // MSVC CRT API. main() initializes _environ; an unavailable table refuses
    // reuse rather than being fingerprinted as an empty environment.
    char** environment = _environ;
    if (!environment) return {};
#elif defined(__APPLE__)
    char** environment = *_NSGetEnviron();
#else
    char** environment = environ;
#endif
    std::vector<std::string> values;
    std::size_t bytes = 0;
    if (environment) for (auto entry = environment; *entry; ++entry) {
        std::string value(*entry);
        bytes += value.size();
        if (bytes > kInputIdentityLimit || values.size() >= kInputObservationLimit) return {};
        values.push_back(std::move(value));
    }
    std::sort(values.begin(), values.end());
    std::string encoded;
    try { for (const auto& value : values) field(encoded, value); }
    catch (...) { return {}; }
    return inputDigest(encoded);
}

bool cacheableCommand(const std::vector<std::string>& arguments) {
    if (arguments.empty()) return false;
    auto driver = std::filesystem::path(arguments.front()).filename().string();
    for (auto& character : driver)
        if (character >= 'A' && character <= 'Z') character = static_cast<char>(character - 'A' + 'a');
    if (driver == "cl" || driver == "cl.exe" || driver == "clang-cl" || driver == "clang-cl.exe") return false;
    const std::set<std::string> pairs{"-x", "-std", "-I", "-iquote", "-isystem", "-idirafter",
        "-D", "-U", "-o", "-target", "--target", "--sysroot", "-isysroot", "-resource-dir"};
    const std::set<std::string> flags{"-c", "-fsyntax-only", "-w", "-g", "-g0", "-g1", "-g2", "-g3",
        "-O0", "-O1", "-O2", "-O3", "-Os", "-Oz", "-Og", "-fPIC", "-fpic", "-fPIE", "-fpie",
        "-pthread", "-nostdinc", "-nostdinc++", "-nobuiltininc", "-fno-exceptions", "-fno-rtti",
        "--driver-mode=g++", "--driver-mode=gcc"};
    for (std::size_t i = 1; i < arguments.size(); ++i) {
        const auto& arg = arguments[i];
        if (arg.empty() || arg.find('\0') != std::string::npos || arg[0] == '@') return false;
        if (pairs.count(arg)) {
            if (++i == arguments.size() || arguments[i].empty() ||
                arguments[i].find('\0') != std::string::npos || arguments[i][0] == '@') return false;
            if (arg == "-x" && arguments[i] != "c" && arguments[i] != "c++") return false;
            continue;
        }
        if (flags.count(arg)) continue;
        if (arg[0] != '-') {
            const auto extension = std::filesystem::path(arg).extension().string();
            if (extension != ".c" && extension != ".cpp" && extension != ".cc" && extension != ".cxx") return false;
            continue;
        }
        if (arg.rfind("-D", 0) == 0 || arg.rfind("-U", 0) == 0 || arg.rfind("-I", 0) == 0 ||
            arg.rfind("-std=", 0) == 0 || arg.rfind("--target=", 0) == 0 ||
            arg.rfind("--sysroot=", 0) == 0 || arg.rfind("-resource-dir=", 0) == 0 ||
            (arg.rfind("-W", 0) == 0 && arg.find(',') == std::string::npos)) continue;
        return false;
    }
    return true;
}

InputRecording::InputRecording(std::string context) : state_(std::make_shared<InputRecordingState>()) {
    state_->identity.reusable = true;
    state_->identity.reason.clear();
    state_->identity.context = std::move(context);
    state_->identity.environment = inputEnvironmentIdentity();
    if (state_->identity.environment.empty()) state_->refuse("environment_unavailable");
    previous_ = active_recording;
    active_recording = state_;
    filesystem_ = llvm::IntrusiveRefCntPtr<vfs::FileSystem>(new ObservedFileSystem(state_));
}
InputRecording::~InputRecording() { active_recording = previous_; }
void InputRecording::refuse(const std::string& reason) { state_->refuse(reason); }
InputIdentity InputRecording::finish() const {
    return snapshotter()();
}
std::function<InputIdentity()> InputRecording::snapshotter() const {
    return [state = state_]() {
        auto result = state->identity;
        if (result.environment != inputEnvironmentIdentity()) {
            result.reusable = false; result.reason = "environment_changed_during_analysis";
        }
        return result;
    };
}
void refuseInputReuse(const std::string& reason) {
    if (auto state = active_recording.lock()) state->refuse(reason);
}
void observeCompilerInputs(clang::CompilerInstance& compiler) {
    if (auto state = active_recording.lock()) {
        std::string options;
        try {
            for (const auto& option : compiler.getInvocation().getCC1CommandLine()) field(options, option);
            field(options, compiler.getPreprocessor().getPredefines());
            state->add(Kind::Frontend, state->identity.context + ":" +
                       std::to_string(state->identity.observations.size()), inputDigest(options));
        } catch (...) { state->refuse("frontend_identity_bound"); }
        compiler.getPreprocessor().addPPCallbacks(std::make_unique<VolatileCallbacks>(state));
    }
}
void observeSidecarAbsence(const std::string& path) {
    if (auto state = active_recording.lock()) {
        std::error_code error;
        auto full = std::filesystem::absolute(path, error);
        if (error) state->refuse("sidecar_path_unavailable");
        else state->add(Kind::SidecarAbsent, full.string(), "absent");
    }
}
void observeSidecarText(const std::string& path, const std::string& text) {
    if (auto state = active_recording.lock()) {
        std::error_code error;
        auto full = std::filesystem::absolute(path, error);
        if (error) state->refuse("sidecar_path_unavailable");
        else state->add(Kind::SidecarText, full.string(), bufferValue(text));
    }
}

bool InputIdentity::hasBuffer(const std::string& path) const {
    return std::any_of(observations.begin(), observations.end(), [&](const auto& observation) {
        return (observation.kind == Kind::TextBuffer || observation.kind == Kind::BinaryBuffer) && observation.path == path;
    });
}
bool InputIdentity::matchesCurrent(const std::function<bool()>& cancelled) const {
    if (!reusable || observations.empty() || environment.empty() || environment != inputEnvironmentIdentity()) return false;
    auto fs = vfs::createPhysicalFileSystem();
    const auto started = std::chrono::steady_clock::now();
    std::size_t bytes = 0;
    try {
        for (const auto& o : observations) {
            if ((cancelled && cancelled()) || std::chrono::steady_clock::now() - started > std::chrono::seconds(5)) return false;
            if (o.kind == Kind::Frontend) continue; // separately bound request/tool/environment key
            if (!absoluteObservationPath(o.path)) return false;
            std::string actual;
            switch (o.kind) {
            case Kind::Status: actual = statusValue(fs->status(o.path)); break;
            case Kind::Exists: actual = fs->exists(o.path) ? "1" : "0"; break;
            case Kind::TextBuffer: case Kind::BinaryBuffer: {
                auto status = fs->status(o.path);
                if (!status || !status->isRegularFile() || status->getSize() > kInputBufferLimit) return false;
                auto buffer = fs->getBufferForFile(o.path, -1, true, false, o.kind == Kind::TextBuffer);
                if (!buffer || (*buffer)->getBufferSize() > kInputBufferLimit) return false;
                bytes += (*buffer)->getBufferSize();
                if (bytes > kInputTotalBufferLimit) return false;
                actual = bufferValue((*buffer)->getBuffer()); break;
            }
            case Kind::Directory: {
                auto directory = readDirectory(*fs, o.path);
                if (!ordinaryDirectory(directory)) return false;
                actual = directoryValue(directory); break;
            }
            case Kind::RealPath: {
                llvm::SmallString<256> path;
                if (fs->getRealPath(o.path, path)) return false;
                actual = path.str().str(); break;
            }
            case Kind::Local: {
                bool local;
                if (fs->isLocal(o.path, local)) return false;
                actual = local ? "1" : "0"; break;
            }
            case Kind::SidecarAbsent: {
                std::error_code error;
                if (std::filesystem::symlink_status(o.path, error).type() != std::filesystem::file_type::not_found ||
                    (error && error != std::errc::no_such_file_or_directory && error != std::errc::not_a_directory)) return false;
                actual = "absent"; break;
            }
            case Kind::SidecarText: {
                std::string text;
                if (!model_input::readTextFile(o.path, 1024 * 1024, text)) return false;
                actual = bufferValue(text); break;
            }
            default: return false;
            }
            if (actual != o.value) return false;
        }
    } catch (...) { return false; }
    return !(cancelled && cancelled());
}
void InputIdentity::append(const InputIdentity& other) {
    if (!other.reusable || !reusable || environment != other.environment) {
        reusable = false; reason = other.reason.empty() ? "incompatible_input_evidence" : other.reason; return;
    }
    if (observations.size() + other.observations.size() > kInputObservationLimit) {
        reusable = false; reason = "input_evidence_bound"; return;
    }
    std::map<std::pair<unsigned, std::string>, std::string> seen;
    for (const auto& o : observations) seen[{static_cast<unsigned>(o.kind), o.path}] = o.value;
    for (const auto& o : other.observations) {
        auto [found, inserted] = seen.emplace(std::make_pair(static_cast<unsigned>(o.kind), o.path), o.value);
        if (inserted) observations.push_back(o);
        else if (found->second != o.value) {
            reusable = false; reason = "input_changed_between_commands"; return;
        }
    }
}

std::string encodeInputIdentity(const InputIdentity& identity) {
    if (!identity.reusable) return {};
    try {
        std::string result = "CSINPUT1";
        field(result, identity.context); field(result, identity.environment);
        for (const auto& observation : identity.observations) {
            field(result, std::to_string(static_cast<unsigned>(observation.kind)));
            field(result, observation.path); field(result, observation.value);
        }
        return result;
    } catch (...) { return {}; }
}
bool decodeInputIdentity(const std::string& bytes, InputIdentity& identity) {
    try {
        if (bytes.size() > kInputIdentityLimit || bytes.size() < 8 || bytes.compare(0, 8, "CSINPUT1")) return false;
        std::size_t offset = 8;
        auto read = [&]() {
            if (bytes.size() - offset < 4) throw std::runtime_error("truncated input field");
            std::uint32_t size = 0;
            for (unsigned i = 0; i < 4; ++i) size |= static_cast<std::uint32_t>(static_cast<unsigned char>(bytes[offset++])) << (8 * i);
            if (size > bytes.size() - offset) throw std::runtime_error("truncated input bytes");
            auto value = bytes.substr(offset, size); offset += size; return value;
        };
        InputIdentity staged;
        staged.context = read(); staged.environment = read();
        auto digest = [](const std::string& value) {
            return value.size() == 64 && value.find_first_not_of("0123456789abcdef") == std::string::npos;
        };
        if (!digest(staged.context) || !digest(staged.environment)) return false;
        std::set<std::pair<unsigned, std::string>> seen;
        bool has_buffer = false, has_frontend = false;
        while (offset < bytes.size()) {
            const auto tag = read();
            unsigned type = 0;
            for (unsigned i = 1; i <= static_cast<unsigned>(Kind::Frontend); ++i)
                if (tag == std::to_string(i)) type = i;
            if (!type || staged.observations.size() >= kInputObservationLimit) return false;
            auto path = read(), value = read();
            const auto kind = static_cast<Kind>(type);
            if (kind == Kind::Frontend) { if (!digest(value) || path.empty()) return false; has_frontend = true; }
            else if (!absoluteObservationPath(path)) return false;
            if (!seen.emplace(type, path).second) return false;
            if (kind == Kind::TextBuffer || kind == Kind::BinaryBuffer) has_buffer = true;
            staged.observations.push_back({kind, std::move(path), std::move(value)});
        }
        if (!has_buffer || !has_frontend) return false;
        staged.reusable = true; staged.reason.clear(); identity = std::move(staged); return true;
    } catch (...) { return false; }
}
} // namespace codeskeptic
