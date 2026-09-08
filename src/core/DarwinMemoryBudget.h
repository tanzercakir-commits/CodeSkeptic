#ifndef CODESKEPTIC_DARWIN_MEMORY_BUDGET_H
#define CODESKEPTIC_DARWIN_MEMORY_BUDGET_H

#include <algorithm>
#include <cstdint>
#include <limits>

namespace codeskeptic::darwin_memory {

// Internal, allocation-free calculation and injectable native-call sequence.
// The snapshot is MACH_TASK_BASIC_INFO.virtual_size, not RSS or a promise of
// equality with XNU's raw map counter. Never rebaseline or retry upward.
struct Limits { std::uint64_t soft = 0, hard = 0; };
struct Snapshot {
    std::uint64_t bytes = 0;
    unsigned count = 0, expected_count = 0;
};
enum class Stage {
    Ready, InvalidAllowance, ReadInherited, ReadSnapshot, InvalidSnapshot,
    InvalidLimits, Overflow, BelowSnapshot, Install, Readback, Mismatch, Applied
};
struct Attempt {
    Stage stage = Stage::ReadInherited;
    Limits inherited{}, observed{};
    Snapshot snapshot{};
    std::uint64_t target = 0;
};

inline Stage ceiling(std::uint64_t baseline, std::uint64_t memory_mb,
                     Limits inherited, std::uint64_t native_max,
                     std::uint64_t infinity, std::uint64_t& target) {
    constexpr std::uint64_t mib = 1024 * 1024;
    constexpr auto widest = std::numeric_limits<std::uint64_t>::max();
    if (memory_mb == 0 || memory_mb > widest / mib) return Stage::InvalidAllowance;
    if (baseline == 0 || baseline > native_max || baseline >= infinity)
        return Stage::InvalidSnapshot;
    const auto valid = [=](std::uint64_t value) {
        return value == infinity || (value <= native_max && value < infinity);
    };
    if (!valid(inherited.soft) || !valid(inherited.hard) || inherited.soft > inherited.hard)
        return Stage::InvalidLimits;
    const auto allowance = memory_mb * mib;
    if (allowance > native_max || baseline > native_max - allowance)
        return Stage::Overflow;
    auto candidate = baseline + allowance;
    if (candidate >= infinity) return Stage::Overflow;
    if (inherited.soft != infinity) candidate = std::min(candidate, inherited.soft);
    if (inherited.hard != infinity) candidate = std::min(candidate, inherited.hard);
    if (candidate < baseline) return Stage::BelowSnapshot;
    target = candidate;
    return Stage::Ready;
}

template<class Native>
Attempt install(Native& native, std::uint64_t memory_mb,
                std::uint64_t native_max, std::uint64_t infinity) {
    Attempt result;
    if (!native.readLimits(result.inherited)) return result;
    result.stage = Stage::ReadSnapshot;
    if (!native.readSnapshot(result.snapshot)) return result;
    if (result.snapshot.expected_count == 0 ||
        result.snapshot.count != result.snapshot.expected_count) {
        result.stage = Stage::InvalidSnapshot;
        return result;
    }
    result.stage = ceiling(result.snapshot.bytes, memory_mb, result.inherited,
                           native_max, infinity, result.target);
    if (result.stage != Stage::Ready) return result;
    result.stage = Stage::Install;
    if (!native.writeLimits({result.target, result.target})) return result;
    result.stage = Stage::Readback;
    if (!native.readLimits(result.observed)) return result;
    result.stage = result.observed.soft == result.target && result.observed.hard == result.target
        ? Stage::Applied : Stage::Mismatch;
    return result;
}

} // namespace codeskeptic::darwin_memory
#endif
