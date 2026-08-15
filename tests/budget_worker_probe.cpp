#include "analyzer/WorkerProtocol.h"
#include "analyzer/UnitEvidenceStore.h"
#include "core/ResourceWorkerControl.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace codeskeptic;

namespace {

constexpr int kMemoryLimitExitCode = 86;

int consumeMemory() {
    try {
        std::vector<std::unique_ptr<unsigned char[]>> blocks;
        for (unsigned i = 0; i < 1024; ++i) {
            auto block = std::make_unique<unsigned char[]>(1u << 20);
            for (std::size_t offset = 0; offset < (1u << 20);
                 offset += 4096)
                block[offset] = static_cast<unsigned char>(i);
            blocks.push_back(std::move(block));
        }
    } catch (const std::bad_alloc&) {
        return kMemoryLimitExitCode;
    }
    return 0;
}

DependencyManifest dependenciesFor(const std::string& source,
                                   std::string& error) {
    DependencyManifest manifest;
    manifest.toolchain_identity_sha256 = std::string(64, 'f');
    DependencyEvidence evidence;
    evidence.canonical_path = source;
    evidence.content_sha256 = sha256RegularFileStreaming(source, error);
    if (evidence.content_sha256.empty()) return {};
    const std::string sidecar = source + ".csk";
    if (std::filesystem::is_regular_file(sidecar)) {
        evidence.sidecar_exists = true;
        evidence.sidecar_sha256 =
            sha256RegularFileStreaming(sidecar, error);
        if (evidence.sidecar_sha256.empty()) return {};
    }
    manifest.files.push_back(std::move(evidence));
    manifest.sha256 = dependencyManifestSha256(manifest);
    return manifest;
}

bool sourceContains(const std::string& path, const std::string& marker) {
    std::ifstream input(path, std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(input)),
                           std::istreambuf_iterator<char>());
    return text.find(marker) != std::string::npos;
}

bool firstTimeoutAttempt(const std::string& source) {
    const std::filesystem::path marker =
        std::filesystem::path(source).string() + ".timeout-once-observed";
    std::error_code ec;
    if (std::filesystem::is_regular_file(marker, ec)) return false;
    std::ofstream output(marker, std::ios::binary | std::ios::trunc);
    output << "observed\n";
    output.flush();
    return output.good();
}

void applyTestDelay(const WorkerRequest& request) {
    unsigned delay_ms = 0;
    if (request.phase == TranslationUnitPhase::DependencyProbe) {
        if (sourceContains(request.unit.canonical_path,
                           "SLOW_DEPENDENCY_PROBE"))
            delay_ms = 700;
        std::ifstream input(request.unit.canonical_path + ".probe-delay");
        unsigned configured = 0;
        if (input >> configured) delay_ms = configured;
    } else if (sourceContains(request.unit.canonical_path,
                              "SLOW_ANALYSIS_WORKER")) {
        delay_ms = 700;
    }
    if (delay_ms > 0)
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
}

void maybeCreateSidecarAfterSecondProbe(const WorkerRequest& request) {
    if (request.phase != TranslationUnitPhase::DependencyProbe ||
        !sourceContains(request.unit.canonical_path,
                        "SIDECAR_AFTER_SECOND_PROBE"))
        return;
    const std::filesystem::path counter =
        request.unit.canonical_path + ".probe-count";
    unsigned count = 0;
    {
        std::ifstream input(counter);
        input >> count;
    }
    ++count;
    {
        std::ofstream output(counter, std::ios::trunc);
        output << count << '\n';
    }
    if (count == 2) {
        std::ofstream sidecar(request.unit.canonical_path + ".csk",
                              std::ios::binary | std::ios::trunc);
        sidecar << "# appeared after dependency probe\n";
    }
}

} // anonymous namespace

int main(int argc, char** argv) {
    std::string resource_error;
    if (codeskeptic::initializeResourceWorker(argc, argv, resource_error) ==
        codeskeptic::ResourceWorkerInitialization::Failed)
        return 70;
    if (argc != 3 || std::string(argv[1]) != "--internal-tu-worker")
        return 70;

    WorkerRequest request;
    std::string error;
    if (!readWorkerRequest(argv[2], request, error)) return 70;

    applyTestDelay(request);

    const std::string filename =
        std::filesystem::path(request.unit.canonical_path).filename().string();
    const bool timeout_once =
        request.phase != TranslationUnitPhase::DependencyProbe &&
        sourceContains(request.unit.canonical_path, "TIMEOUT_ONCE") &&
        firstTimeoutAttempt(request.unit.canonical_path);
    if (request.phase != TranslationUnitPhase::DependencyProbe &&
        (filename.find("timeout") != std::string::npos || timeout_once ||
         (sourceContains(request.unit.canonical_path, "TIMEOUT") &&
          !sourceContains(request.unit.canonical_path, "TIMEOUT_ONCE")))) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        return 0;
    }
    if (filename.find("memory") != std::string::npos)
        return consumeMemory();

    WorkerResponse response;
    response.request_id = request.request_id;
    response.canonical_path = request.unit.canonical_path;
    response.compile_command_sha256 = request.unit.compile_command_sha256;
    response.command_ordinal = request.unit.command_ordinal;
    response.phase = request.phase;
    response.analysis.attempted_tus = 1;
    response.analysis.analyzed_tus = 1;
    response.dependency_manifest =
        dependenciesFor(request.unit.canonical_path, error);
    if (response.dependency_manifest.files.empty()) return 72;
    maybeCreateSidecarAfterSecondProbe(request);
    if (!writeWorkerResponse(request.response_path, response, error)) return 71;
    return 0;
}
