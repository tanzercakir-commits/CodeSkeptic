#include "source_manager/ResourceDir.h"

#include <cstdlib>
#include <filesystem>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#include <vector>
#elif defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace codeskeptic {

namespace {

// A directory qualifies as a resource dir only if it actually carries
// the intrinsic headers — an empty version-numbered shell must not win.
bool looksLikeResourceDir(const fs::path& p) {
    std::error_code ec;
    return fs::exists(p / "include" / "stddef.h", ec);
}

std::string exeDir() {
#ifdef __APPLE__
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    std::vector<char> buf(size + 1, '\0');
    if (_NSGetExecutablePath(buf.data(), &size) != 0) return {};
    std::error_code ec;
    fs::path p = fs::canonical(fs::path(buf.data()), ec);
    if (ec) return {};
    return p.parent_path().string();
#elif defined(_WIN32)
    // GetModuleFileNameW(nullptr, ...): the Win32 "where is this very
    // executable" API. On truncation (n >= MAX_PATH) fall through to
    // the baked build path rather than trusting a clipped string.
    wchar_t buf[MAX_PATH];
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    std::error_code ec;
    fs::path p = fs::canonical(fs::path(buf), ec);
    if (ec) return {};
    return p.parent_path().string();
#else
    std::error_code ec;
    // Not a hard-coded install path: /proc/self/exe is the kernel's
    // stable API for "where is this very executable".
    fs::path p = fs::read_symlink("/proc/self/exe", ec);  // codeskeptic-disable-line policy
    if (ec) return {};
    return p.parent_path().string();
#endif
}

} // anonymous namespace

std::string resolveResourceDir(const std::string& override_dir,
                               const std::string& exe_dir,
                               const std::string& baked_dir) {
    std::error_code ec;

    // 1. Explicit override: the user said so; trusted as long as the
    // path exists (a missing override falls through rather than
    // silently producing broken TUs with a dead -resource-dir).
    if (!override_dir.empty() && fs::exists(override_dir, ec))
        return override_dir;

    // 2. Relocatable layout: <exe>/../lib/clang/<version> — how the
    // release tarball ships the headers next to the binary.
    if (!exe_dir.empty()) {
        fs::path base = fs::path(exe_dir).parent_path() / "lib" / "clang";
        if (fs::is_directory(base, ec)) {
            long best = -1;
            fs::path best_path;
            try {
                for (const auto& entry : fs::directory_iterator(base, ec)) {
                    std::error_code entry_ec;
                    if (!entry.is_directory(entry_ec)) continue;
                    const std::string name =
                        entry.path().filename().string();
                    char* end = nullptr;
                    long v = std::strtol(name.c_str(), &end, 10);
                    if (end == name.c_str()) continue; // not version-shaped
                    if (v > best && looksLikeResourceDir(entry.path())) {
                        best = v;
                        best_path = entry.path();
                    }
                }
            } catch (const fs::filesystem_error&) {
                // unreadable layout -> fall through to the baked path
            }
            if (best >= 0) return best_path.string();
        }
    }

    // 3. The build machine's baked path (dev builds), only while it
    // still exists — never handed to Clang as a dead directory.
    if (!baked_dir.empty() && fs::exists(baked_dir, ec))
        return baked_dir;

    return {};
}

const std::string& resourceDir() {
    static const std::string resolved = [] {
        const char* env = std::getenv("CODESKEPTIC_RESOURCE_DIR");
#ifdef CLANG_RESOURCE_DIR
        const std::string baked = CLANG_RESOURCE_DIR;
#else
        const std::string baked;
#endif
        return resolveResourceDir(env ? env : "", exeDir(), baked);
    }();
    return resolved;
}

} // namespace codeskeptic
