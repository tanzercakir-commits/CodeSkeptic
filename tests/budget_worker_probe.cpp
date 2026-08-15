#include "analyzer/WorkerProtocol.h"
#include "core/ResourceWorkerControl.h"

#include <chrono>
#include <filesystem>
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

    const std::string filename =
        std::filesystem::path(request.unit.canonical_path).filename().string();
    if (filename.find("timeout") != std::string::npos) {
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
    if (!writeWorkerResponse(request.response_path, response, error)) return 71;
    return 0;
}
