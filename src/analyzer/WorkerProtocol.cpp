#include "analyzer/WorkerProtocol.h"

#include <llvm/ADT/StringExtras.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/SHA256.h>
#include <llvm/Support/raw_ostream.h>

#include <filesystem>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>

namespace codeskeptic {

namespace json = llvm::json;

namespace {

constexpr std::uintmax_t kMaxRequestBytes = 16u << 20;
constexpr std::uintmax_t kMaxResponseBytes = 64u << 20;

bool readBounded(const std::string& path, std::uintmax_t maximum,
                 std::string& text, std::string& error) {
    std::error_code ec;
    const auto status = std::filesystem::status(path, ec);
    if (ec || !std::filesystem::is_regular_file(status)) {
        error = "worker protocol path is not a regular file: " + path;
        return false;
    }
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size > maximum) {
        error = "worker protocol file exceeds size limit: " + path;
        return false;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        error = "cannot read worker protocol file: " + path;
        return false;
    }
    text.assign(std::istreambuf_iterator<char>(input),
                std::istreambuf_iterator<char>());
    if (input.bad()) {
        error = "failed while reading worker protocol file: " + path;
        return false;
    }
    return true;
}

bool writeAtomic(const std::string& path, const json::Value& value,
                 std::string& error) {
    std::string text;
    llvm::raw_string_ostream stream(text);
    stream << value;
    stream.flush();
    text.push_back('\n');

    const std::string temporary = path + ".tmp";
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        if (!output) {
            error = "cannot create worker protocol file: " + temporary;
            return false;
        }
        output.write(text.data(), static_cast<std::streamsize>(text.size()));
        output.flush();
        if (!output.good()) {
            error = "failed while writing worker protocol file: " + temporary;
            return false;
        }
    }
    std::error_code ec;
    std::filesystem::rename(temporary, path, ec);
    if (ec) {
        std::filesystem::remove(temporary);
        error = "cannot publish worker protocol file: " + ec.message();
        return false;
    }
    return true;
}

bool onlyFields(const json::Object& object,
                std::initializer_list<const char*> names,
                const char* context, std::string& error) {
    std::set<std::string> allowed;
    for (const char* name : names) allowed.insert(name);
    for (const auto& entry : object) {
        if (!allowed.count(entry.first.str())) {
            error = std::string(context) + " contains unknown field: " +
                    entry.first.str();
            return false;
        }
    }
    return true;
}

bool stringField(const json::Object& object, const char* name,
                 std::string& value, std::string& error,
                 bool allow_empty = true) {
    const auto field = object.getString(name);
    if (!field || (!allow_empty && field->empty()) ||
        field->find('\0') != llvm::StringRef::npos) {
        error = std::string("invalid worker protocol string field: ") + name;
        return false;
    }
    value = field->str();
    return true;
}

template <typename T>
bool unsignedField(const json::Object& object, const char* name,
                   T& value, std::string& error) {
    const auto field = object.getInteger(name);
    if (!field || *field < 0 ||
        static_cast<std::uint64_t>(*field) >
            static_cast<std::uint64_t>(std::numeric_limits<T>::max())) {
        error = std::string("invalid worker protocol integer field: ") + name;
        return false;
    }
    value = static_cast<T>(*field);
    return true;
}

bool boolField(const json::Object& object, const char* name,
               bool& value, std::string& error) {
    const auto field = object.getBoolean(name);
    if (!field) {
        error = std::string("invalid worker protocol boolean field: ") + name;
        return false;
    }
    value = *field;
    return true;
}

bool stringArray(const json::Object& object, const char* name,
                 std::vector<std::string>& values, std::string& error) {
    const auto* array = object.getArray(name);
    if (!array || array->size() > 100000) {
        error = std::string("invalid worker protocol array field: ") + name;
        return false;
    }
    values.clear();
    values.reserve(array->size());
    for (const auto& item : *array) {
        const auto text = item.getAsString();
        if (!text || text->find('\0') != llvm::StringRef::npos) {
            error = std::string("invalid string in worker protocol array: ") +
                    name;
            return false;
        }
        values.push_back(text->str());
    }
    return true;
}

json::Array toArray(const std::vector<std::string>& values) {
    json::Array result;
    for (const auto& value : values) result.push_back(value);
    return result;
}

bool validSha256(const std::string& value) {
    if (value.size() != 64) return false;
    for (const unsigned char c : value) {
        if (!std::isdigit(c) && !(c >= 'a' && c <= 'f')) return false;
    }
    return true;
}

bool parsePhase(llvm::StringRef value, TranslationUnitPhase& phase) {
    if (value == "analysis") {
        phase = TranslationUnitPhase::Analysis;
        return true;
    }
    if (value == "summary-harvest") {
        phase = TranslationUnitPhase::SummaryHarvest;
        return true;
    }
    return false;
}

json::Object unitObject(const TranslationUnitExecution& unit) {
    return json::Object{
        {"canonical_path", unit.canonical_path},
        {"working_directory", unit.working_directory},
        {"command_line", toArray(unit.command_line)},
        {"output", unit.output},
        {"compile_command_sha256", unit.compile_command_sha256},
        {"command_ordinal", static_cast<std::int64_t>(unit.command_ordinal)},
    };
}

bool parseUnit(const json::Object& object, TranslationUnitExecution& unit,
               std::string& error) {
    if (!onlyFields(object,
                    {"canonical_path", "working_directory", "command_line",
                     "output", "compile_command_sha256", "command_ordinal"},
                    "worker unit", error) ||
        !stringField(object, "canonical_path", unit.canonical_path, error,
                     false) ||
        !stringField(object, "working_directory", unit.working_directory,
                     error) ||
        !stringArray(object, "command_line", unit.command_line, error) ||
        !stringField(object, "output", unit.output, error) ||
        !stringField(object, "compile_command_sha256",
                     unit.compile_command_sha256, error, false) ||
        !unsignedField(object, "command_ordinal", unit.command_ordinal,
                       error))
        return false;
    if (unit.command_line.empty() || !validSha256(unit.compile_command_sha256)) {
        error = "invalid worker unit identity";
        return false;
    }
    return true;
}

json::Object analysisObject(const AnalysisResult& result) {
    return json::Object{
        {"attempted_tus", static_cast<std::int64_t>(result.attempted_tus)},
        {"analyzed_tus", static_cast<std::int64_t>(result.analyzed_tus)},
        {"broken_tus", static_cast<std::int64_t>(result.broken_tus)},
        {"incomplete_functions",
         static_cast<std::int64_t>(result.incomplete_functions)},
        {"findings", static_cast<std::int64_t>(result.findings)},
        {"report_only_findings",
         static_cast<std::int64_t>(result.report_only_findings)},
        {"analyze_broken_tus", result.analyze_broken_tus},
        {"accept_partial_coverage", result.accept_partial_coverage},
        {"no_inputs", result.no_inputs},
        {"no_rules", result.no_rules},
        {"compile_database_failed", result.compile_database_failed},
        {"tool_failed", result.tool_failed},
        {"summary_load_failed", result.summary_load_failed},
        {"summary_stale", result.summary_stale},
        {"summary_save_failed", result.summary_save_failed},
        {"baseline_load_failed", result.baseline_load_failed},
        {"baseline_write_failed", result.baseline_write_failed},
        {"baseline_recorded", result.baseline_recorded},
        {"report_write_failed", result.report_write_failed},
    };
}

bool parseAnalysis(const json::Object& object, AnalysisResult& result,
                   std::string& error) {
    if (!onlyFields(
            object,
            {"attempted_tus", "analyzed_tus", "broken_tus",
             "incomplete_functions", "findings", "report_only_findings",
             "analyze_broken_tus", "accept_partial_coverage", "no_inputs",
             "no_rules", "compile_database_failed", "tool_failed",
             "summary_load_failed", "summary_stale", "summary_save_failed",
             "baseline_load_failed", "baseline_write_failed",
             "baseline_recorded", "report_write_failed"},
            "worker analysis", error) ||
        !unsignedField(object, "attempted_tus", result.attempted_tus, error) ||
        !unsignedField(object, "analyzed_tus", result.analyzed_tus, error) ||
        !unsignedField(object, "broken_tus", result.broken_tus, error) ||
        !unsignedField(object, "incomplete_functions",
                       result.incomplete_functions, error) ||
        !unsignedField(object, "findings", result.findings, error) ||
        !unsignedField(object, "report_only_findings",
                       result.report_only_findings, error) ||
        !boolField(object, "analyze_broken_tus", result.analyze_broken_tus,
                   error) ||
        !boolField(object, "accept_partial_coverage",
                   result.accept_partial_coverage, error) ||
        !boolField(object, "no_inputs", result.no_inputs, error) ||
        !boolField(object, "no_rules", result.no_rules, error) ||
        !boolField(object, "compile_database_failed",
                   result.compile_database_failed, error) ||
        !boolField(object, "tool_failed", result.tool_failed, error) ||
        !boolField(object, "summary_load_failed", result.summary_load_failed,
                   error) ||
        !boolField(object, "summary_stale", result.summary_stale, error) ||
        !boolField(object, "summary_save_failed", result.summary_save_failed,
                   error) ||
        !boolField(object, "baseline_load_failed",
                   result.baseline_load_failed, error) ||
        !boolField(object, "baseline_write_failed",
                   result.baseline_write_failed, error) ||
        !boolField(object, "baseline_recorded", result.baseline_recorded,
                   error) ||
        !boolField(object, "report_write_failed", result.report_write_failed,
                   error))
        return false;
    // Every worker request binds exactly one compile command/TU. Recovery
    // mode may analyze that TU while preserving its broken evidence, so the
    // analyzed and broken bits may overlap, but neither the denominator nor
    // no-input identity is controlled by the child.
    if (result.attempted_tus != 1 || result.no_inputs ||
        result.analyzed_tus > result.attempted_tus ||
        result.broken_tus > result.attempted_tus ||
        result.report_only_findings > result.findings) {
        error = "inconsistent exact-TU worker analysis";
        return false;
    }
    return true;
}

json::Object noteObject(const TraceNote& note) {
    return json::Object{
        {"file", note.file},
        {"line", static_cast<std::int64_t>(note.line)},
        {"column", static_cast<std::int64_t>(note.column)},
        {"message", note.message},
    };
}

json::Object diagnosticObject(const Diagnostic& diagnostic) {
    json::Array notes;
    for (const auto& note : diagnostic.notes) notes.push_back(noteObject(note));
    return json::Object{
        {"severity", diagnostic.severityToString()},
        {"file", diagnostic.file},
        {"line", static_cast<std::int64_t>(diagnostic.line)},
        {"column", static_cast<std::int64_t>(diagnostic.column)},
        {"rule_id", diagnostic.rule_id},
        {"message", diagnostic.message},
        {"function", diagnostic.function},
        {"notes", std::move(notes)},
        {"fingerprint", diagnostic.fingerprint},
    };
}

bool parseNote(const json::Object& object, TraceNote& note,
               std::string& error) {
    return onlyFields(object, {"file", "line", "column", "message"},
                      "worker trace note", error) &&
           stringField(object, "file", note.file, error) &&
           unsignedField(object, "line", note.line, error) &&
           unsignedField(object, "column", note.column, error) &&
           stringField(object, "message", note.message, error);
}

bool parseDiagnostic(const json::Object& object, Diagnostic& diagnostic,
                     std::string& error) {
    if (!onlyFields(object,
                    {"severity", "file", "line", "column", "rule_id",
                     "message", "function", "notes", "fingerprint"},
                    "worker diagnostic", error))
        return false;
    std::string severity;
    if (!stringField(object, "severity", severity, error, false) ||
        !stringField(object, "file", diagnostic.file, error) ||
        !unsignedField(object, "line", diagnostic.line, error) ||
        !unsignedField(object, "column", diagnostic.column, error) ||
        !stringField(object, "rule_id", diagnostic.rule_id, error, false) ||
        !stringField(object, "message", diagnostic.message, error) ||
        !stringField(object, "function", diagnostic.function, error) ||
        !stringField(object, "fingerprint", diagnostic.fingerprint, error))
        return false;
    if (severity == "info") diagnostic.severity = Severity::Info;
    else if (severity == "warning") diagnostic.severity = Severity::Warning;
    else if (severity == "error") diagnostic.severity = Severity::Error;
    else {
        error = "invalid worker diagnostic severity";
        return false;
    }
    const auto* notes = object.getArray("notes");
    if (!notes || notes->size() > 100000) {
        error = "invalid worker diagnostic notes";
        return false;
    }
    diagnostic.notes.clear();
    for (const auto& item : *notes) {
        const auto* note_object = item.getAsObject();
        TraceNote note;
        if (!note_object || !parseNote(*note_object, note, error)) return false;
        diagnostic.notes.push_back(std::move(note));
    }
    return true;
}

bool parseProtocolRoot(const std::string& text, json::Object*& object,
                       json::Value& storage, std::string& error) {
    auto parsed = json::parse(text);
    if (!parsed) {
        llvm::consumeError(parsed.takeError());
        error = "invalid worker protocol JSON";
        return false;
    }
    storage = std::move(*parsed);
    object = storage.getAsObject();
    if (!object || object->getInteger("protocol") != kWorkerProtocolVersion) {
        error = "unsupported worker protocol version";
        return false;
    }
    return true;
}

} // anonymous namespace

bool writeWorkerRequest(const std::string& path,
                        const WorkerRequest& request,
                        std::string& error) {
    json::Object root{
        {"protocol", kWorkerProtocolVersion},
        {"request_id", request.request_id},
        {"phase", translationUnitPhaseName(request.phase)},
        {"unit", unitObject(request.unit)},
        {"config_arguments", toArray(request.config_arguments)},
        {"response_path", request.response_path},
        {"summary_fragment_path", request.summary_fragment_path},
    };
    return writeAtomic(path, json::Value(std::move(root)), error);
}

bool readWorkerRequest(const std::string& path,
                       WorkerRequest& request,
                       std::string& error) {
    std::string text;
    if (!readBounded(path, kMaxRequestBytes, text, error)) return false;
    json::Value storage(nullptr);
    json::Object* root = nullptr;
    if (!parseProtocolRoot(text, root, storage, error) ||
        !onlyFields(*root,
                    {"protocol", "request_id", "phase", "unit",
                     "config_arguments", "response_path",
                     "summary_fragment_path"},
                    "worker request", error) ||
        !stringField(*root, "request_id", request.request_id, error, false) ||
        !stringArray(*root, "config_arguments", request.config_arguments,
                     error) ||
        !stringField(*root, "response_path", request.response_path, error,
                     false) ||
        !stringField(*root, "summary_fragment_path",
                     request.summary_fragment_path, error))
        return false;
    const auto phase = root->getString("phase");
    const auto* unit = root->getObject("unit");
    if (!phase || !parsePhase(*phase, request.phase) || !unit ||
        !parseUnit(*unit, request.unit, error)) {
        if (error.empty()) error = "invalid worker request phase or unit";
        return false;
    }
    return true;
}

bool writeWorkerResponse(const std::string& path,
                         const WorkerResponse& response,
                         std::string& error) {
    json::Array diagnostics;
    for (const auto& diagnostic : response.diagnostics)
        diagnostics.push_back(diagnosticObject(diagnostic));
    json::Object root{
        {"protocol", kWorkerProtocolVersion},
        {"request_id", response.request_id},
        {"phase", translationUnitPhaseName(response.phase)},
        {"canonical_path", response.canonical_path},
        {"compile_command_sha256", response.compile_command_sha256},
        {"command_ordinal", static_cast<std::int64_t>(response.command_ordinal)},
        {"analysis", analysisObject(response.analysis)},
        {"diagnostics", std::move(diagnostics)},
        {"summary_fragment_sha256", response.summary_fragment_sha256},
    };
    return writeAtomic(path, json::Value(std::move(root)), error);
}

bool readWorkerResponse(const std::string& path,
                        const WorkerRequest& expected,
                        WorkerResponse& response,
                        std::string& error) {
    std::string text;
    if (!readBounded(path, kMaxResponseBytes, text, error)) return false;
    json::Value storage(nullptr);
    json::Object* root = nullptr;
    if (!parseProtocolRoot(text, root, storage, error) ||
        !onlyFields(*root,
                    {"protocol", "request_id", "phase", "canonical_path",
                     "compile_command_sha256", "command_ordinal", "analysis",
                     "diagnostics", "summary_fragment_sha256"},
                    "worker response", error) ||
        !stringField(*root, "request_id", response.request_id, error, false) ||
        !stringField(*root, "canonical_path", response.canonical_path, error,
                     false) ||
        !stringField(*root, "compile_command_sha256",
                     response.compile_command_sha256, error, false) ||
        !unsignedField(*root, "command_ordinal", response.command_ordinal,
                       error) ||
        !stringField(*root, "summary_fragment_sha256",
                     response.summary_fragment_sha256, error))
        return false;
    const auto phase = root->getString("phase");
    const auto* analysis = root->getObject("analysis");
    const auto* diagnostics = root->getArray("diagnostics");
    if (!phase || !parsePhase(*phase, response.phase) || !analysis ||
        !parseAnalysis(*analysis, response.analysis, error) || !diagnostics ||
        diagnostics->size() > 100000) {
        if (error.empty()) error = "invalid worker response payload";
        return false;
    }
    response.diagnostics.clear();
    for (const auto& item : *diagnostics) {
        const auto* object = item.getAsObject();
        Diagnostic diagnostic{Severity::Info, {}, 0, 0, {}, {}, {}, {}, {}};
        if (!object || !parseDiagnostic(*object, diagnostic, error)) return false;
        response.diagnostics.push_back(std::move(diagnostic));
    }
    if (response.analysis.findings != response.diagnostics.size()) {
        error = "worker response finding count does not match diagnostics";
        return false;
    }
    if ((!response.summary_fragment_sha256.empty() &&
         !validSha256(response.summary_fragment_sha256)) ||
        response.request_id != expected.request_id ||
        response.phase != expected.phase ||
        response.canonical_path != expected.unit.canonical_path ||
        response.compile_command_sha256 !=
            expected.unit.compile_command_sha256 ||
        response.command_ordinal != expected.unit.command_ordinal) {
        error = "worker response identity does not match request";
        return false;
    }
    return true;
}

std::string sha256File(const std::string& path, std::string& error) {
    std::string content;
    if (!readBounded(path, kMaxResponseBytes, content, error)) return {};
    const auto digest = llvm::SHA256::hash(
        llvm::ArrayRef<std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(content.data()),
            content.size()));
    return llvm::toHex(digest, true);
}

} // namespace codeskeptic
