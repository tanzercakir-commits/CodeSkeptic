// GROUND_TRUTH_CLEAN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    int rows = 3, cols = 4;
    int *m = malloc(rows * cols * sizeof(int));
    for (int i = 0; i < rows * cols; i++)
        m[i] = i;

    int r = 2;
    int *row = malloc(cols * sizeof(int));
    memcpy(row, m + r * cols, cols * sizeof(int));

    for (int i = 0; i < cols; i++)
        printf(" %d", row[i]);
    printf("\n");
    free(m);
    free(row);
    return 0;
}
