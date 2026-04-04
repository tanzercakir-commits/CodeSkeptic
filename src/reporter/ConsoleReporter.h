#ifndef ZERODEFECT_CONSOLE_REPORTER_H
#define ZERODEFECT_CONSOLE_REPORTER_H

#include "reporter/Reporter.h"

namespace zerodefect {

class ConsoleReporter : public Reporter {
public:
    void report(const DiagnosticList& diagnostics) override;
    std::string format() const override;
};

} // namespace zerodefect

#endif // ZERODEFECT_CONSOLE_REPORTER_H
