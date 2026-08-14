#include "engine/FunctionSummary.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <string>

namespace {

using SummaryMap = std::map<
    std::string, codeskeptic::SummaryRegistry::FunctionSummary>;

bool sameSummary(
    const codeskeptic::SummaryRegistry::FunctionSummary& lhs,
    const codeskeptic::SummaryRegistry::FunctionSummary& rhs) {
    return lhs.returnNullness == rhs.returnNullness &&
           lhs.returnZeroness == rhs.returnZeroness &&
           lhs.returnOwnership == rhs.returnOwnership &&
           lhs.params == rhs.params &&
           lhs.paramAccesses == rhs.paramAccesses &&
           lhs.paramOwnerships == rhs.paramOwnerships &&
           lhs.paramFieldWrites == rhs.paramFieldWrites &&
           lhs.paramPreconditions == rhs.paramPreconditions &&
           lhs.paramPostconditions == rhs.paramPostconditions &&
           lhs.paramAllocatorSizes == rhs.paramAllocatorSizes &&
           lhs.zeroFromParam == rhs.zeroFromParam &&
           lhs.nullFromParam == rhs.nullFromParam &&
           lhs.returnAliasParam == rhs.returnAliasParam &&
           lhs.nullCondParam == rhs.nullCondParam &&
           lhs.nullCondRange == rhs.nullCondRange;
}

bool sameMaps(const SummaryMap& lhs, const SummaryMap& rhs) {
    if (lhs.size() != rhs.size()) return false;
    auto left = lhs.begin();
    auto right = rhs.begin();
    for (; left != lhs.end(); ++left, ++right) {
        if (left->first != right->first ||
            !sameSummary(left->second, right->second))
            return false;
    }
    return true;
}

SummaryMap sentinelMap() {
    SummaryMap summaries;
    codeskeptic::SummaryRegistry::FunctionSummary sentinel;
    sentinel.returnNullness =
        codeskeptic::SummaryRegistry::ReturnNullness::NeverNull;
    sentinel.returnZeroness =
        codeskeptic::SummaryRegistry::ReturnZeroness::NeverZero;
    sentinel.returnOwnership =
        codeskeptic::SummaryRegistry::ReturnOwnership::Borrowed;
    summaries.emplace("sentinel/0", std::move(sentinel));
    return summaries;
}

} // anonymous namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    if (size > 65536) return 0;
    const std::string input(reinterpret_cast<const char*>(data), size);
    auto first = sentinelMap();
    auto second = sentinelMap();
    const auto before = first;
    const bool firstAccepted =
        codeskeptic::SummaryRegistry::parseSummaryText(input, first);
    const bool secondAccepted =
        codeskeptic::SummaryRegistry::parseSummaryText(input, second);
    if (firstAccepted != secondAccepted) std::abort();
    if (firstAccepted && !sameMaps(first, second)) std::abort();
    if (!firstAccepted) {
        if (!sameMaps(first, before) || !sameMaps(second, before)) std::abort();
    }
    return 0;
}
