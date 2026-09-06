#include "reporter/JsonReporter.h"
#include "reporter/ReportContract.h"
#include "core/Messages.h"

#include <fstream>
#include <iostream>

namespace codeskeptic {

JsonReporter::JsonReporter(const std::string& output_path)
    : output_path_(output_path) {}

bool JsonReporter::report(const DiagnosticList& diagnostics,
                          const AnalysisResult* result) {
    std::ofstream file(output_path_);
    if (!file.is_open()) {
        std::cerr << msg(MsgId::OutputFileOpenError, output_path_) << "\n";
        return false;
    }

    writeReportJson(file, diagnostics, result);
    file.flush();
    if (!file.good()) {
        std::cerr << msg(MsgId::OutputFileOpenError, output_path_) << "\n";
        return false;
    }
    return true;
}

std::string JsonReporter::format() const {
    return "json";
}

} // namespace codeskeptic
