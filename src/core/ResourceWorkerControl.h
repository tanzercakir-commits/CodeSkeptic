#ifndef CODESKEPTIC_RESOURCE_WORKER_CONTROL_H
#define CODESKEPTIC_RESOURCE_WORKER_CONTROL_H

#include <string>

namespace codeskeptic {

inline constexpr char kResourceControlArgument[] =
    "--codeskeptic-resource-control=";
inline constexpr char kResourceParentArgument[] =
    "--codeskeptic-resource-parent=";

enum class ResourceWorkerInitialization {
    Unsupervised,
    Ready,
    Failed,
};

// Removes the supervisor-only control argument from argv. A supervised child
// announces that its executable/runtime image is ready, then waits until the
// parent has taken the first post-exec memory sample. At normal process exit,
// a second marker keeps the child observable until the parent records its
// post-work peak. These boundaries prevent fork/vfork state from being charged
// to the worker and make even very short worker executions observable.
ResourceWorkerInitialization initializeResourceWorker(
    int& argc, char** argv, std::string& error);

} // namespace codeskeptic

#endif // CODESKEPTIC_RESOURCE_WORKER_CONTROL_H
