// read N integers and print each scaled by a factor
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int n;
    printf("how many numbers? ");
    scanf("%d", &n);

    int *nums = malloc(n);  // GROUND_TRUTH_BUG: should be malloc(n * sizeof(int)); heap overflow
    for (int i = 0; i < n; i++) {
        scanf("%d", &nums[i]);
    }

    int factor = 3;
    for (int i = 0; i < n; i++) {
        printf("%d\n", nums[i] * factor);
    }

    free(nums);
    return 0;
}
