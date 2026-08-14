#define CS_VALUE(x) (x)
#define CS_DIVIDE(x) (100 / CS_VALUE(x))
#define CS_SAFE_DIVIDE(x) (CS_VALUE(x) == 0 ? 0 : CS_DIVIDE(x))

int macro_clean(int divisor) { return CS_SAFE_DIVIDE(divisor); }

int macro_seeded() {
    int divisor = 0;
    return CS_DIVIDE(divisor);
}
