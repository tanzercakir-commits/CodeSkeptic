// average of numbers read from stdin
#include <stdio.h>

int main(void) {
    int n;
    printf("How many numbers? ");
    scanf("%d", &n);

    double sum = 0;
    for (int i = 0; i < n; i++) {
        double x;
        scanf("%lf", &x);
        sum += x;
    }

    double avg = sum / n;  // GROUND_TRUTH_BUG: division by zero when n == 0
    printf("Average: %.2f\n", avg);
    return 0;
}
