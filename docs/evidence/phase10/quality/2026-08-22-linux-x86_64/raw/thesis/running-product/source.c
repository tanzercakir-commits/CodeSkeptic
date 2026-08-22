// GROUND_TRUTH_CLEAN
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s n1 n2 ...\n", argv[0]);
        return 0;
    }
    long product = 1;
    for (int i = 1; i < argc; i++) {
        long v = atol(argv[i]);
        product *= v;
    }
    printf("product = %ld\n", product);
    return 0;
}
