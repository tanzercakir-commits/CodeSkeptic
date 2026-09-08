#ifndef CODESKEPTIC_CHECKPOINT_TIME_H
#define CODESKEPTIC_CHECKPOINT_TIME_H

#include <algorithm>
#include <limits>
#include <string>

namespace codeskeptic {

// Keep the clock's full integral representation. libc++ file-clock ticks can
// be wider than the standard std::to_string overloads; narrowing would alias
// distinct checkpoint inputs. Ordinary signed-64 decimal bytes stay unchanged.
template<class Rep>
std::string checkpointTickIdentity(Rep ticks) {
    static_assert(std::numeric_limits<Rep>::is_integer,
                  "checkpoint clock ticks must have an integral representation");
    const bool negative = ticks < 0;
    std::string result;
    do {
        // A remainder is between -9 and 9, even for the minimum signed value.
        // Never negate the full tick count (which could overflow).
        const int digit = static_cast<int>(ticks % 10);
        result.push_back(static_cast<char>('0' + (digit < 0 ? -digit : digit)));
        ticks /= 10;
    } while (ticks != 0);
    if (negative) result.push_back('-');
    std::reverse(result.begin(), result.end());
    return result;
}

} // namespace codeskeptic

#endif
