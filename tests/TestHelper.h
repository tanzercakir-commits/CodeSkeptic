#ifndef ZERODEFECT_TEST_HELPER_H
#define ZERODEFECT_TEST_HELPER_H

#include "core/Diagnostic.h"
#include "core/Rule.h"

#include <string>

namespace zerodefect {
namespace testing {

DiagnosticList runRule(Rule& rule, const std::string& code,
                       const std::string& filename = "test.cpp");

// Whole-program modunun test karsiligi: once calleeTU'dan ozetler
// hasat edilir (cross-TU deposuna), sonra kural callerTU uzerinde
// kosulur. Depo cikista temizlenir (test izolasyonu).
DiagnosticList runRuleCrossTU(Rule& rule, const std::string& calleeTU,
                              const std::string& callerTU);

} // namespace testing
} // namespace zerodefect

#endif // ZERODEFECT_TEST_HELPER_H
