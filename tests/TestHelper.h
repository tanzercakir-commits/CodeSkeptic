#ifndef ZERODEFECT_TEST_HELPER_H
#define ZERODEFECT_TEST_HELPER_H

#include "core/Diagnostic.h"
#include "core/Rule.h"

#include <string>

namespace zerodefect {
namespace testing {

DiagnosticList runRule(Rule& rule, const std::string& code,
                       const std::string& filename = "test.cpp");

} // namespace testing
} // namespace zerodefect

#endif // ZERODEFECT_TEST_HELPER_H
