#include "server/McpServer.h"

#include <llvm/Support/Error.h>
#include <llvm/Support/JSON.h>

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    if (size > 65536) return 0;
    const std::string input(reinterpret_cast<const char*>(data), size);
    const std::string first = codeskeptic::validateMcpMessage(input);
    const std::string second = codeskeptic::validateMcpMessage(input);
    if (first != second) std::abort();
    if (!first.empty()) {
        auto parsed = llvm::json::parse(first);
        if (!parsed) {
            llvm::consumeError(parsed.takeError());
            std::abort();
        }
    }
    return 0;
}
