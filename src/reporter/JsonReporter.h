#ifndef CODESKEPTIC_JSON_REPORTER_H
#define CODESKEPTIC_JSON_REPORTER_H

#include "reporter/Reporter.h"

namespace codeskeptic {

class JsonReporter : public Reporter {
public:
    explicit JsonReporter(const std::string& output_path);

    void report(const DiagnosticList& diagnostics) override;
    std::string format() const override;

private:
    std::string output_path_;
};

} // namespace codeskeptic

#endif // CODESKEPTIC_JSON_REPORTER_H
