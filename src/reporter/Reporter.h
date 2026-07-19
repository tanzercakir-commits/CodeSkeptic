#ifndef CODESKEPTIC_REPORTER_H
#define CODESKEPTIC_REPORTER_H

#include "core/Diagnostic.h"

#include <string>

namespace codeskeptic {

class Reporter {
public:
    virtual ~Reporter() = default;

    virtual void report(const DiagnosticList& diagnostics) = 0;
    virtual std::string format() const = 0;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_REPORTER_H
