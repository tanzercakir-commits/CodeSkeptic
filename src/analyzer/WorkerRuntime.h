#ifndef CODESKEPTIC_WORKER_RUNTIME_H
#define CODESKEPTIC_WORKER_RUNTIME_H

#include <string>
#include <vector>

namespace codeskeptic {

struct DependencyEvidence;
struct TranslationUnitExecution;

// Collects and hashes non-AST file inputs named by the exact compile command
// (response files, PCH/module artifacts, module maps, and VFS overlays).
// Response files are followed recursively. Missing or unreadable explicit
// inputs fail closed instead of permitting a stale checkpoint hit.
bool collectCompileCommandDependencyEvidence(
    const TranslationUnitExecution& unit,
    std::vector<DependencyEvidence>& evidence, std::string& error,
    bool* volatile_preprocessor_input = nullptr);

// Hidden same-binary entry point used only by the parent coordinator. A valid
// analysis result is always written through WorkerProtocol and returns zero;
// protocol/setup failures return non-zero without manufacturing a response.
// Exit 86 is reserved for a caught allocation failure so ResourceSupervisor
// can distinguish the configured memory ceiling from an arbitrary crash.
int runTranslationUnitWorker(const std::string& request_path);

} // namespace codeskeptic

#endif // CODESKEPTIC_WORKER_RUNTIME_H
