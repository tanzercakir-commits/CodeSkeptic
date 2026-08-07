#ifndef CODESKEPTIC_REPORTER_H
#define CODESKEPTIC_REPORTER_H

#include "core/Diagnostic.h"
#include "core/AnalysisResult.h"

#include <string>

namespace codeskeptic {

class Reporter {
public:
    virtual ~Reporter() = default;

    // False means the requested artifact was not fully written. Report I/O is
    // part of the verdict: a missing SARIF/JSON file must fail CI loudly.
    virtual bool report(const DiagnosticList& diagnostics,
                        const AnalysisResult* result = nullptr) = 0;
    virtual std::string format() const = 0;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_REPORTER_H
