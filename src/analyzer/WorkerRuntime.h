#ifndef CODESKEPTIC_WORKER_RUNTIME_H
#define CODESKEPTIC_WORKER_RUNTIME_H

#include <string>

namespace codeskeptic {

// Hidden same-binary entry point used only by the parent coordinator. A valid
// analysis result is always written through WorkerProtocol and returns zero;
// protocol/setup failures return non-zero without manufacturing a response.
// Exit 86 is reserved for a caught allocation failure so ResourceSupervisor
// can distinguish the configured memory ceiling from an arbitrary crash.
int runTranslationUnitWorker(const std::string& request_path);

} // namespace codeskeptic

#endif // CODESKEPTIC_WORKER_RUNTIME_H
