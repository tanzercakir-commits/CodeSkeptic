#ifndef CODESKEPTIC_CAPABILITIES_H
#define CODESKEPTIC_CAPABILITIES_H

#include <iosfwd>

namespace codeskeptic {

// Stable discovery surface for CI, wrappers, and AI agents. The JSON form is
// intentionally dependency-free so it is available before analysis starts.
void writeCapabilities(std::ostream& out, bool json);

} // namespace codeskeptic

#endif // CODESKEPTIC_CAPABILITIES_H
