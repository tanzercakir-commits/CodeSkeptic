#ifndef ZERODEFECT_REPORTER_H
#define ZERODEFECT_REPORTER_H

#include "core/Diagnostic.h"

#include <string>

namespace zerodefect {

class Reporter {
public:
    virtual ~Reporter() = default;

    virtual void report(const DiagnosticList& diagnostics) = 0;
    virtual std::string format() const = 0;
};

} // namespace zerodefect

#endif // ZERODEFECT_REPORTER_H
