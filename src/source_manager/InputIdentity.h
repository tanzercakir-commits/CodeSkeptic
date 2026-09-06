#ifndef CODESKEPTIC_INPUT_IDENTITY_H
#define CODESKEPTIC_INPUT_IDENTITY_H

#include <llvm/ADT/IntrusiveRefCntPtr.h>
#include <llvm/Support/VirtualFileSystem.h>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace clang { class CompilerInstance; }
namespace codeskeptic {

// Evidence bounds are refusal thresholds, not truncation thresholds. An input
// that cannot be witnessed still receives ordinary fresh analysis.
constexpr std::size_t kInputIdentityLimit = 4 * 1024 * 1024;
constexpr std::size_t kInputObservationLimit = 16384;
constexpr std::size_t kInputBufferLimit = 16 * 1024 * 1024;
constexpr std::size_t kInputTotalBufferLimit = 64 * 1024 * 1024;

enum class InputObservationKind : unsigned {
    Status = 1, Exists, TextBuffer, BinaryBuffer, Directory, RealPath,
    Local, SidecarAbsent, SidecarText, Frontend
};
struct InputObservation {
    InputObservationKind kind;
    std::string path;
    std::string value;
};

struct InputIdentity {
    bool reusable = false;
    std::string context;
    std::string environment;
    std::string reason = "not_recorded";
    std::vector<InputObservation> observations;

    // Validation checks the observations of the actual compiler/consumer, not
    // a guessed include list. The caller separately binds the request/tool key.
    bool matchesCurrent(const std::function<bool()>& cancelled = {}) const;
    bool hasBuffer(const std::string& path) const;
    void append(const InputIdentity& other);
};

std::string inputDigest(const std::string& bytes);
std::string inputEnvironmentIdentity();
bool cacheableCommand(const std::vector<std::string>& arguments);
std::string encodeInputIdentity(const InputIdentity& identity);
bool decodeInputIdentity(const std::string& bytes, InputIdentity& identity);

struct InputRecordingState;
class InputRecording {
public:
    explicit InputRecording(std::string context);
    ~InputRecording();
    llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> filesystem() const { return filesystem_; }
    InputIdentity finish() const;
    std::function<InputIdentity()> snapshotter() const;
    void refuse(const std::string& reason);
    InputRecording(const InputRecording&) = delete;
    InputRecording& operator=(const InputRecording&) = delete;
private:
    std::shared_ptr<InputRecordingState> state_;
    std::weak_ptr<InputRecordingState> previous_;
    llvm::IntrusiveRefCntPtr<llvm::vfs::FileSystem> filesystem_;
};

// Hooks apply only to the current analysis thread. A retained AST callback
// holds a weak owner, never a reference to an expired stack frame.
void observeCompilerInputs(clang::CompilerInstance& compiler);
void observeSidecarAbsence(const std::string& path);
void observeSidecarText(const std::string& path, const std::string& consumed_text);
void refuseInputReuse(const std::string& reason);

} // namespace codeskeptic
#endif
