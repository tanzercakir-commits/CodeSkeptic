// GROUND_TRUTH_CLEAN
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    int size = 10;
    if (argc > 1)
        size = atoi(argv[1]);

    int *data = calloc(size, sizeof(int));
    if (!data) {
        fprintf(stderr, "alloc failed\n");
        return 1;
    }

    for (int i = 0; i < size; i++)
        data[i] = (i + 1) * (i + 1);

    long sum = 0;
    for (int i = 0; i < size; i++)
        sum += data[i];

    printf("sum = %ld\n", sum);
    free(data);
    return 0;
}
