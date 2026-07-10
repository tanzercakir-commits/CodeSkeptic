#ifndef ZERODEFECT_TEST_HELPER_H
#define ZERODEFECT_TEST_HELPER_H

#include "core/Diagnostic.h"
#include "core/Rule.h"

#include <string>

namespace zerodefect {
namespace testing {

DiagnosticList runRule(Rule& rule, const std::string& code,
                       const std::string& filename = "test.cpp");

// Test counterpart of whole-program mode: summaries are first
// harvested from calleeTU (into the cross-TU store), then the rule is
// run on callerTU. The store is cleared on exit (test isolation).
DiagnosticList runRuleCrossTU(Rule& rule, const std::string& calleeTU,
                              const std::string& callerTU);

} // namespace testing
} // namespace zerodefect

#endif // ZERODEFECT_TEST_HELPER_H
