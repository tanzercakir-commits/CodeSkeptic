#include "analyzer/WorkerProtocol.h"
#include "core/Capabilities.h"
#include <llvm/ADT/ArrayRef.h>
#include <llvm/Support/SHA256.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <limits>
#include <stdexcept>

namespace codeskeptic {
namespace {

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

class Writer {
public:
    std::string bytes;
    void raw(const char* data, std::size_t size) {
        require(size <= kWorkerPacketLimit - bytes.size(), "worker packet exceeds limit");
        bytes.append(data, size);
    }
    void number(std::uint32_t value) {
        char encoded[4];
        for (unsigned i = 0; i < 4; ++i) encoded[i] = static_cast<char>((value >> (8 * i)) & 255);
        raw(encoded, 4);
    }
    void count(std::size_t value) {
        require(value <= kWorkerCollectionLimit, "worker collection exceeds limit");
        number(static_cast<std::uint32_t>(value));
    }
    void flag(bool value) { number(value ? 1 : 0); }
    void text(const std::string& value) {
        require(value.size() <= kWorkerFieldLimit, "worker field exceeds limit");
        number(static_cast<std::uint32_t>(value.size()));
        raw(value.data(), value.size());
    }
    void strings(const std::vector<std::string>& values) {
        count(values.size());
        for (const auto& value : values) text(value);
    }
    void header(const char* magic) {
        raw(magic, 8);
        text(toolVersion());
    }
};

class Reader {
public:
    explicit Reader(const std::string& bytes) : bytes_(bytes) {
        require(bytes.size() <= kWorkerPacketLimit, "worker packet exceeds limit");
    }
    std::string raw(std::size_t size) {
        require(size <= bytes_.size() - position_, "truncated worker packet");
        auto value = bytes_.substr(position_, size);
        position_ += size;
        return value;
    }
    std::uint32_t number() {
        const auto value = raw(4);
        std::uint32_t result = 0;
        for (unsigned i = 0; i < 4; ++i)
            result |= static_cast<std::uint32_t>(static_cast<unsigned char>(value[i])) << (8 * i);
        return result;
    }
    std::size_t count() {
        const auto value = number();
        require(value <= kWorkerCollectionLimit, "worker collection exceeds limit");
        return value;
    }
    bool flag() {
        const auto value = number();
        require(value <= 1, "invalid worker boolean");
        return value == 1;
    }
    std::string text() {
        const auto size = number();
        require(size <= kWorkerFieldLimit, "worker field exceeds limit");
        return raw(size);
    }
    std::vector<std::string> strings() {
        std::vector<std::string> result;
        const auto size = count();
        for (std::size_t i = 0; i < size; ++i) result.push_back(text());
        return result;
    }
    void header(const char* magic) {
        require(raw(8) == std::string(magic, 8), "unsupported worker protocol");
        require(text() == toolVersion(), "worker build identity mismatch");
    }
    void finish() { require(position_ == bytes_.size(), "trailing worker data"); }
private:
    const std::string& bytes_;
    std::size_t position_ = 0;
};

WorkerPhase phase(std::uint32_t value) {
    require(value <= static_cast<std::uint32_t>(WorkerPhase::Analyze), "invalid worker phase");
    return static_cast<WorkerPhase>(value);
}

FindingKind kind(std::uint32_t value) {
    require(value <= static_cast<std::uint32_t>(FindingKind::GenericResourceLeak),
            "invalid worker finding kind");
    return static_cast<FindingKind>(value);
}

void writeCoverage(Writer& writer, const SourceCoverage& source) {
    writer.text(source.file);
    require(source.status >= SourceStatus::Analyzed && source.status <= SourceStatus::Failed,
            "invalid worker source status");
    writer.number(static_cast<std::uint32_t>(source.status));
    writer.text(source.reason);
    writer.count(source.commands);
    writer.count(source.analyzed_commands);
    writer.count(source.skipped_commands);
    writer.count(source.failed_commands);
    writer.count(source.recovery_commands);
    writer.text(source.prepass_status);
    writer.text(source.prepass_reason);
    writer.count(source.prepass_recovery_commands);
}

SourceCoverage readCoverage(Reader& reader) {
    SourceCoverage source;
    source.file = reader.text();
    const auto status = reader.number();
    require(status <= static_cast<std::uint32_t>(SourceStatus::Failed), "invalid worker source status");
    source.status = static_cast<SourceStatus>(status);
    source.reason = reader.text();
    source.commands = reader.count();
    source.analyzed_commands = reader.count();
    source.skipped_commands = reader.count();
    source.failed_commands = reader.count();
    source.recovery_commands = reader.count();
    source.prepass_status = reader.text();
    source.prepass_reason = reader.text();
    source.prepass_recovery_commands = reader.count();
    return source;
}

void writeDiagnostic(Writer& writer, const Diagnostic& diagnostic) {
    require(diagnostic.severity >= Severity::Info && diagnostic.severity <= Severity::Error,
            "invalid worker severity");
    writer.number(static_cast<std::uint32_t>(diagnostic.severity));
    writer.text(diagnostic.file);
    writer.number(diagnostic.line);
    writer.number(diagnostic.column);
    writer.text(diagnostic.rule_id);
    writer.text(diagnostic.message);
    writer.text(diagnostic.function);
    writer.count(diagnostic.notes.size());
    for (const auto& note : diagnostic.notes) {
        writer.text(note.file);
        writer.number(note.line);
        writer.number(note.column);
        writer.text(note.message);
    }
    writer.text(diagnostic.fingerprint);
    writer.number(static_cast<std::uint32_t>(kind(static_cast<std::uint32_t>(diagnostic.kind))));
    writer.count(diagnostic.additional_kinds.size());
    for (auto value : diagnostic.additional_kinds)
        writer.number(static_cast<std::uint32_t>(kind(static_cast<std::uint32_t>(value))));
    writer.text(diagnostic.baseline_function);
}

Diagnostic readDiagnostic(Reader& reader) {
    Diagnostic diagnostic{};
    const auto severity = reader.number();
    require(severity <= static_cast<std::uint32_t>(Severity::Error), "invalid worker severity");
    diagnostic.severity = static_cast<Severity>(severity);
    diagnostic.file = reader.text();
    diagnostic.line = reader.number();
    diagnostic.column = reader.number();
    diagnostic.rule_id = reader.text();
    require(!diagnostic.rule_id.empty(), "missing worker finding rule");
    diagnostic.message = reader.text();
    diagnostic.function = reader.text();
    const auto notes = reader.count();
    for (std::size_t i = 0; i < notes; ++i) {
        TraceNote note;
        note.file = reader.text();
        note.line = reader.number();
        note.column = reader.number();
        note.message = reader.text();
        diagnostic.notes.push_back(std::move(note));
    }
    diagnostic.fingerprint = reader.text();
    diagnostic.kind = kind(reader.number());
    const auto kinds = reader.count();
    for (std::size_t i = 0; i < kinds; ++i) diagnostic.additional_kinds.push_back(kind(reader.number()));
    diagnostic.baseline_function = reader.text();
    return diagnostic;
}

void validateCoverage(const WorkerResponse& response, const WorkerRequest& request) {
    const auto& source = response.coverage;
    require(source.file == request.source && source.commands == request.commands.size(),
            "worker source/command identity mismatch");
    require(!source.reason.empty() && source.commands > 0, "missing worker coverage");
    require(source.analyzed_commands + source.skipped_commands + source.failed_commands == source.commands,
            "inconsistent worker command totals");
    require(source.recovery_commands <= source.analyzed_commands, "inconsistent worker recovery");
    const auto expected = source.failed_commands ? SourceStatus::Failed :
                          source.skipped_commands ? SourceStatus::Skipped : SourceStatus::Analyzed;
    require(source.status == expected, "inconsistent worker source status");
    if (source.status == SourceStatus::Analyzed) {
        require(source.reason == (source.recovery_commands ? "error_recovery_ast" : "analyzed"),
                "inconsistent worker analysis reason");
    } else if (source.status == SourceStatus::Skipped) {
        require(source.reason == "broken_translation_unit", "inconsistent worker skipped reason");
    } else {
        require(source.reason == "frontend_failed" || source.reason == "ast_not_produced" ||
                source.reason == "analysis_not_completed", "inconsistent worker failure reason");
    }
    const bool recovery_requested = std::find(request.arguments.begin(), request.arguments.end(),
                                              "--analyze-broken-tus") != request.arguments.end();
    require(recovery_requested || source.recovery_commands == 0, "unrequested worker recovery");
    require(!recovery_requested || source.skipped_commands == 0, "unexpected worker skip in recovery mode");
    require(source.prepass_status == "not_requested" && source.prepass_reason.empty() &&
            source.prepass_recovery_commands == 0, "worker cannot claim another phase");
    require(request.phase != WorkerPhase::Harvest || response.diagnostics.empty(),
            "harvest worker returned findings");
}

} // namespace

std::string encodeWorkerRequest(const WorkerRequest& request) {
    Writer writer;
    writer.header("CSWKREQ1");
    writer.number(request.ordinal);
    writer.number(static_cast<std::uint32_t>(phase(static_cast<std::uint32_t>(request.phase))));
    writer.text(request.source);
    writer.text(request.build_directory);
    writer.flag(request.synthetic);
    writer.count(request.commands.size());
    for (const auto& command : request.commands) {
        writer.text(command.Directory);
        writer.text(command.Filename);
        writer.text(command.Output);
        writer.strings(command.CommandLine);
    }
    writer.strings(request.arguments);
    writer.strings(request.producers);
    writer.strings(request.selected_families);
    writer.text(request.global_summaries);
    writer.flag(request.harvest);
    writer.number(request.memory_mb);
    return std::move(writer.bytes);
}

bool decodeWorkerRequest(const std::string& packet, WorkerRequest& request, std::string& error) {
    try {
        Reader reader(packet);
        reader.header("CSWKREQ1");
        WorkerRequest candidate;
        candidate.ordinal = reader.number();
        candidate.phase = phase(reader.number());
        candidate.source = reader.text();
        candidate.build_directory = reader.text();
        require(!candidate.source.empty() && !candidate.build_directory.empty(), "missing worker input identity");
        require(candidate.source.find('\0') == std::string::npos &&
                candidate.build_directory.find('\0') == std::string::npos &&
                std::filesystem::path(candidate.source).is_absolute(), "invalid worker input path");
        candidate.synthetic = reader.flag();
        const auto commands = reader.count();
        require(commands > 0, "worker has no compile commands");
        require(!candidate.synthetic || commands == 1, "synthetic worker requires one command");
        for (std::size_t i = 0; i < commands; ++i) {
            clang::tooling::CompileCommand command;
            command.Directory = reader.text();
            command.Filename = reader.text();
            command.Output = reader.text();
            command.CommandLine = reader.strings();
            require(!command.Directory.empty() && !command.Filename.empty() && !command.CommandLine.empty(),
                    "incomplete worker compile command");
            require(command.Directory.find('\0') == std::string::npos &&
                    command.Filename.find('\0') == std::string::npos &&
                    command.Output.find('\0') == std::string::npos &&
                    std::all_of(command.CommandLine.begin(), command.CommandLine.end(),
                        [](const std::string& value) { return value.find('\0') == std::string::npos; }),
                    "NUL in worker compile command");
            candidate.commands.push_back(std::move(command));
        }
        candidate.arguments = reader.strings();
        candidate.producers = reader.strings();
        candidate.selected_families = reader.strings();
        candidate.global_summaries = reader.text();
        candidate.harvest = reader.flag();
        candidate.memory_mb = reader.number();
        require(validWorkerLimits({1, candidate.memory_mb}), "invalid worker memory limit");
        reader.finish();
        request = std::move(candidate);
        error.clear();
        return true;
    } catch (const std::exception& failure) {
        error = failure.what();
        return false;
    }
}

std::string encodeWorkerResponse(const WorkerResponse& response) {
    Writer writer;
    writer.header("CSWKRES1");
    writer.text(response.request_digest);
    writer.number(response.ordinal);
    writer.number(static_cast<std::uint32_t>(phase(static_cast<std::uint32_t>(response.phase))));
    writeCoverage(writer, response.coverage);
    writer.count(response.diagnostics.size());
    for (const auto& diagnostic : response.diagnostics) writeDiagnostic(writer, diagnostic);
    writer.count(response.gaps.size());
    for (const auto& gap : response.gaps) {
        writer.text(gap.function);
        require(gap.gap == CoverageGap::NonConvergence || gap.gap == CoverageGap::CfgUnavailable,
                "invalid worker coverage gap");
        writer.number(static_cast<std::uint32_t>(gap.gap));
    }
    writer.text(response.global_summaries);
    return std::move(writer.bytes);
}

bool decodeWorkerResponse(const std::string& packet, const WorkerRequest& request,
                          const std::string& request_digest, WorkerResponse& response,
                          std::string& error) {
    try {
        Reader reader(packet);
        reader.header("CSWKRES1");
        WorkerResponse candidate;
        candidate.request_digest = reader.text();
        candidate.ordinal = reader.number();
        candidate.phase = phase(reader.number());
        require(candidate.request_digest == request_digest && candidate.ordinal == request.ordinal &&
                candidate.phase == request.phase, "worker request identity mismatch");
        candidate.coverage = readCoverage(reader);
        const auto diagnostics = reader.count();
        for (std::size_t i = 0; i < diagnostics; ++i) candidate.diagnostics.push_back(readDiagnostic(reader));
        const auto gaps = reader.count();
        for (std::size_t i = 0; i < gaps; ++i) {
            CoverageEntry entry;
            entry.function = reader.text();
            const auto gap = reader.number();
            require(gap <= static_cast<std::uint32_t>(CoverageGap::CfgUnavailable), "invalid worker coverage gap");
            entry.gap = static_cast<CoverageGap>(gap);
            candidate.gaps.push_back(std::move(entry));
        }
        candidate.global_summaries = reader.text();
        reader.finish();
        validateCoverage(candidate, request);
        response = std::move(candidate);
        error.clear();
        return true;
    } catch (const std::exception& failure) {
        error = failure.what();
        return false;
    }
}

std::string workerRequestDigest(const std::string& packet) {
    const auto digest = llvm::SHA256::hash(llvm::ArrayRef<std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(packet.data()), packet.size()));
    static constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for (auto byte : digest) { result += hex[byte >> 4]; result += hex[byte & 15]; }
    return result;
}

bool readWorkerPacket(const std::string& path, std::string& packet, std::string& error) {
    try {
        require(std::filesystem::is_regular_file(std::filesystem::symlink_status(path)),
                "worker input is not a regular non-symlink file");
        const auto size = std::filesystem::file_size(path);
        require(size <= kWorkerPacketLimit, "worker packet exceeds limit");
        std::ifstream input(path, std::ios::binary);
        require(input.is_open(), "cannot open worker packet");
        std::string candidate(static_cast<std::size_t>(size), '\0');
        input.read(candidate.data(), static_cast<std::streamsize>(size));
        require(input.gcount() == static_cast<std::streamsize>(size), "truncated worker file");
        require(input.peek() == std::char_traits<char>::eof() && !input.bad(), "growing or unreadable worker file");
        packet = std::move(candidate);
        error.clear();
        return true;
    } catch (const std::exception& failure) {
        error = failure.what();
        return false;
    }
}

bool writeWorkerPacket(const std::string& path, const std::string& packet, std::string& error) {
    try {
        require(packet.size() <= kWorkerPacketLimit, "worker packet exceeds limit");
        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        require(output.is_open(), "cannot open worker output");
        output.write(packet.data(), static_cast<std::streamsize>(packet.size()));
        output.flush();
        output.close();
        require(!output.fail(), "cannot complete worker output");
        error.clear();
        return true;
    } catch (const std::exception& failure) {
        error = failure.what();
        return false;
    }
}

} // namespace codeskeptic
