#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int n;
    printf("How many values? ");
    if (scanf("%d", &n) != 1)
        return 1;

    int *arr = malloc(n * sizeof(int)); // GROUND_TRUTH_BUG: no null check after malloc
    for (int i = 0; i < n; i++)
        arr[i] = 2 * i + 1;

    long sum = 0;
    for (int i = 0; i < n; i++)
        sum += arr[i];

    printf("Sum = %ld\n", sum);
    free(arr);
    return 0;
}
