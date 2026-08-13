#include "config/Config.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace {

codeskeptic::Config sentinelConfig() {
    codeskeptic::Config config;
    config.setSourcePath("sentinel.cpp");
    if (!config.addFunctions("sentinel") || !config.addLines("7"))
        std::abort();
    return config;
}

} // anonymous namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    if (size > 65536) return 0;
    const std::string input(reinterpret_cast<const char*>(data), size);

    auto first = sentinelConfig();
    auto second = sentinelConfig();
    const auto before = first;
    const bool firstAccepted =
        first.loadFromText(input, "<fuzz-config>", false);
    const bool secondAccepted =
        second.loadFromText(input, "<fuzz-config>", false);
    if (firstAccepted != secondAccepted || first != second) std::abort();
    if (!firstAccepted) {
        if (first != before || second != before) std::abort();
    }
    return 0;
}
