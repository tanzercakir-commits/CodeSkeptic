#ifndef ZERODEFECT_SARIF_REPORTER_H
#define ZERODEFECT_SARIF_REPORTER_H

#include "reporter/Reporter.h"

#include <string>

namespace zerodefect {

// SARIF 2.1.0 cikti — GitHub code scanning ve modern CI araclarinin
// ortak dili. Minimal ama gecerli sema: tool.driver + rules + results.
class SarifReporter : public Reporter {
public:
    explicit SarifReporter(const std::string& output_path);

    void report(const DiagnosticList& diagnostics) override;
    std::string format() const override;

private:
    std::string output_path_;
};

} // namespace zerodefect

#endif // ZERODEFECT_SARIF_REPORTER_H
