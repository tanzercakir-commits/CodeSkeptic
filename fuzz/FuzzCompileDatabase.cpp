#include "source_manager/SourceManager.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    if (size > 65536) return 0;
    const std::string input(reinterpret_cast<const char*>(data), size);
    std::string firstError;
    std::string secondError;
    const bool first =
        codeskeptic::validateCompilationDatabaseText(input, firstError);
    const bool second =
        codeskeptic::validateCompilationDatabaseText(input, secondError);
    if (first != second || firstError != secondError ||
        (first && (!firstError.empty() || !secondError.empty())))
        std::abort();
    return 0;
}
