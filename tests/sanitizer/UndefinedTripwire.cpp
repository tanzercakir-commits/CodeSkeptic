#include <climits>

int main() {
    volatile int largest = INT_MAX;
    volatile int one = 1;
    return largest + one;
}
