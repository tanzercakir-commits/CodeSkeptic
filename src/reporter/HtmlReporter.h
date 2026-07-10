#ifndef ZERODEFECT_HTML_REPORTER_H
#define ZERODEFECT_HTML_REPORTER_H

#include "reporter/Reporter.h"

namespace zerodefect {

// A single, self-contained HTML report: no dependencies, opens offline,
// as easy to share as an email/PR attachment. The summary cards double
// as filters (severity/rule), the text box filters by file/message;
// each finding's dataflow trace expands on click with source context
// (source lines are carried along when the report is generated — the
// context is not lost when the report is moved).
class HtmlReporter : public Reporter {
public:
    explicit HtmlReporter(const std::string& output_path);

    void report(const DiagnosticList& diagnostics) override;
    std::string format() const override;

private:
    std::string output_path_;
};

} // namespace zerodefect

#endif // ZERODEFECT_HTML_REPORTER_H
