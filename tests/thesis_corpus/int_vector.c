#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int cap = 4, len = 0;
    int *v = malloc(cap * sizeof(int));

    int x;
    while (scanf("%d", &x) == 1) {
        if (len == cap) {
            cap *= 2;
            v = realloc(v, cap * sizeof(int)); // GROUND_TRUTH_BUG: realloc result unchecked
        }
        v[len++] = x;
    }

    for (int i = 0; i < len; i++)
        printf(" %d", v[i]);
    printf("\n");
    free(v);
    return 0;
}
