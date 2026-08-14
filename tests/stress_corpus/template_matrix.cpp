template <typename T>
int template_clean(T divisor) {
    if (divisor == 0) return 0;
    return 100 / divisor;
}

template <typename T>
int template_seeded(T input) {
    T divisor = 0;
    return input + 100 / divisor;
}

int template_entry(int value) {
    return template_clean<int>(value) + template_seeded<int>(value);
}
