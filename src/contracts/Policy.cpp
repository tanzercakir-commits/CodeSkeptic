#include "contracts/Policy.h"

namespace zerodefect {

namespace {
std::set<std::string>& profilePoliciesStorage() {
    static std::set<std::string> policies;
    return policies;
}
} // anonymous namespace

bool isKnownPolicy(const std::string& name) {
    return name == "no-absolute-paths";
}

void setProfilePolicies(const std::set<std::string>& names) {
    profilePoliciesStorage() = names;
}

const std::set<std::string>& profilePolicies() {
    return profilePoliciesStorage();
}

bool looksLikeAbsolutePath(const std::string& text) {
    if (text.size() < 3) return false;

    // Windows drive root: C:\... or C:/...
    const bool winDrive =
        ((text[0] >= 'A' && text[0] <= 'Z') ||
         (text[0] >= 'a' && text[0] <= 'z')) &&
        text[1] == ':' && (text[2] == '\\' || text[2] == '/');

    if (!winDrive) {
        if (text[0] != '/') return false;
        // At least two segments: a second '/' with content around it.
        // "/", "/tmp", "//" fail; "/etc/app.conf" passes.
        auto second = text.find('/', 1);
        if (second == std::string::npos || second == 1 ||
            second + 1 >= text.size())
            return false;
    }

    // Prose with slashes ("either/or use / here") is not a path.
    for (char c : text)
        if (c == ' ' || c == '\t' || c == '\n') return false;
    return true;
}

} // namespace zerodefect
