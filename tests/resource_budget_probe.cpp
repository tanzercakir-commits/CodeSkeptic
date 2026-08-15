#include "core/ResourceWorkerControl.h"

#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>
#include <vector>

int main(int argc, char** argv) {
    std::string resource_error;
    if (codeskeptic::initializeResourceWorker(argc, argv, resource_error) ==
        codeskeptic::ResourceWorkerInitialization::Failed)
        return 70;
    if (argc < 2) return 2;
    const std::string mode = argv[1];
    if (mode == "complete") return 0;
    if (mode == "exit-without-done") std::_Exit(0);
    if (argc < 3) return 2;

    const unsigned amount = static_cast<unsigned>(std::strtoul(argv[2],
                                                                nullptr, 10));
    if (mode == "sleep") {
        std::this_thread::sleep_for(std::chrono::seconds(amount));
        return 0;
    }
    if (mode == "allocate") {
        try {
            std::vector<std::unique_ptr<unsigned char[]>> blocks;
            for (unsigned i = 0; i < amount; ++i) {
                auto block = std::make_unique<unsigned char[]>(1u << 20);
                for (std::size_t offset = 0; offset < (1u << 20);
                     offset += 4096)
                    block[offset] = static_cast<unsigned char>(i);
                blocks.push_back(std::move(block));
            }
        } catch (const std::bad_alloc&) {
            return 86;
        }
        return 0;
    }
    return 2;
}
