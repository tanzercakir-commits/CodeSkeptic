#include "engine/AssumptionMode.h"

namespace codeskeptic {

namespace {
bool g_assumptionMode = false;
} // namespace

void setAssumptionMode(bool enabled) { g_assumptionMode = enabled; }

bool assumptionMode() { return g_assumptionMode; }

} // namespace codeskeptic
