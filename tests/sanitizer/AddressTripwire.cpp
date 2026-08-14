#include <cstddef>

int main() {
    volatile std::size_t outside = 1;
    int* values = new int[1];
    values[outside] = 42;
    const int result = values[0];
    delete[] values;
    return result;
}
