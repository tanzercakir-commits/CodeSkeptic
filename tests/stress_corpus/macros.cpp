// Repeated nested statement/expression expansion, with a guarded divisor.
#define STEP(z) do { if ((z) == 0) return 0; } while (0)
#define TWICE(z) STEP(z); STEP(z)
#define FOUR(z) TWICE(z); TWICE(z)
#define EIGHT(z) FOUR(z); FOUR(z)
#define SIXTEEN(z) EIGHT(z); EIGHT(z)
#define DIVIDE(x, z) ((x) / (z))
int macro_stress(int divisor) {
    SIXTEEN(divisor);
#if STRESS_BUG
    int zero = 0;
    return DIVIDE(100, zero);
#else
    return DIVIDE(100, divisor);
#endif
}
