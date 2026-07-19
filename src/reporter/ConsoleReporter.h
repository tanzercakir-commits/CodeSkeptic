#ifndef CODESKEPTIC_CONSOLE_REPORTER_H
#define CODESKEPTIC_CONSOLE_REPORTER_H

#include "reporter/Reporter.h"

namespace codeskeptic {

class ConsoleReporter : public Reporter {
public:
    void report(const DiagnosticList& diagnostics) override;
    std::string format() const override;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_CONSOLE_REPORTER_H
