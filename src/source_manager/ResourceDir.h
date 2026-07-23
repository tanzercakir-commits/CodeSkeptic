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

// Picks the macOS SDK sysroot for synthesized/adjusted compile
// commands — the exact same disease resource-dir had in v0.4 applied
// to -isysroot (found by the first external evaluation on real user
// hardware, 2026-07-23): release binaries carried the CI runner's
// versioned Xcode path baked at build time, which exists on almost no
// user machine, so the no-compile-db quickstart silently analyzed
// nothing.
//
// Resolution order (first hit wins):
//   1. env_sdkroot   — the standard SDKROOT env var; honored VERBATIM
//                      even if the path is missing (explicit user
//                      intent; a bad value now fails loudly downstream
//                      instead of being silently overridden)
//   2. xcrun_sdk     — `xcrun --show-sdk-path` output, used when the
//                      path exists (the every-Mac-with-CLT case)
//   3. baked_sdk     — the build machine's path compiled in at build
//                      time, used only if it still exists (dev builds)
// Returns "" when nothing usable is found (no -isysroot injected —
// clang's own defaults apply, and a hopeless TU fails LOUDLY via the
// all-TUs-broken exit-2 policy instead of reporting a false clean).
//
// Deterministic given the filesystem — unit-tested in MacSdkPathTest.
std::string resolveMacSdkPath(const std::string& env_sdkroot,
                              const std::string& xcrun_sdk,
                              const std::string& baked_sdk);

// Process-level entry point (meaningful on macOS; "" elsewhere):
// SDKROOT env + one cached `xcrun --show-sdk-path` probe + the baked
// MACOS_SDK_PATH macro.
const std::string& macSdkPath();

} // namespace codeskeptic

#endif // CODESKEPTIC_RESOURCE_DIR_H
