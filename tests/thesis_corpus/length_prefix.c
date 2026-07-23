#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int count;
    if (scanf("%d", &count) != 1)
        return 1;

    double *items = malloc(count * sizeof(double));
    if (!items)
        return 1;

    double total = 0;
    for (int i = 0; i <= count; i++) { // GROUND_TRUTH_BUG: should be i < count; items[count] is one past the end
        scanf("%lf", &items[i]);
        total += items[i];
    }

    printf("sum = %.2f\n", total);
    free(items);
    return 0;
}
