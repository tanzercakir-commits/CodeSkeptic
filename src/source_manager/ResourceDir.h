#ifndef CODESKEPTIC_RESOURCE_DIR_H
#define CODESKEPTIC_RESOURCE_DIR_H

#include <string>

namespace codeskeptic {

// Picks the Clang resource directory (intrinsic headers: stddef.h,
// stdarg.h, ...) for the synthesized/adjusted compile commands.
//
// Resolution order (first hit wins):
//   1. override_dir  — explicit user override, trusted when it exists
//                      (comes from the CODESKEPTIC_RESOURCE_DIR env var)
//   2. exe-relative  — <exe_dir>/../lib/clang/<N>, the release-tarball
//                      layout; the numerically-highest <N> that actually
//                      carries include/stddef.h wins
//   3. baked_dir     — the build machine's path compiled in at build
//                      time (dev builds), used only if it still exists
// Returns "" when nothing usable is found (no -resource-dir injected —
// the pre-v0.4 behavior for builds without the baked macro).
//
// Pure function of its inputs — unit-tested in ResourceDirTest.cpp.
std::string resolveResourceDir(const std::string& override_dir,
                               const std::string& exe_dir,
                               const std::string& baked_dir);

// Process-level entry point: env override + real executable location +
// the baked CLANG_RESOURCE_DIR macro, resolved once and cached.
const std::string& resourceDir();

} // namespace codeskeptic

#endif // CODESKEPTIC_RESOURCE_DIR_H
