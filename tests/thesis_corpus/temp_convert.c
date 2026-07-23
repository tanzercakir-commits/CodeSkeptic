// read a temperature and convert between Celsius and Fahrenheit
#include <stdio.h>

int main(void) {
    double temp;
    char scale;

    printf("enter temperature and scale (e.g. 100 C): ");
    scanf("%lf%c", &temp, &scale);  // GROUND_TRUTH_BUG: no space before %c; scale captures whitespace

    if (scale == 'C') {
        printf("%.1f F\n", temp * 9.0 / 5.0 + 32.0);
    } else if (scale == 'F') {
        printf("%.1f C\n", (temp - 32.0) * 5.0 / 9.0);
    } else {
        printf("unknown scale '%c'\n", scale);
    }
    return 0;
}
