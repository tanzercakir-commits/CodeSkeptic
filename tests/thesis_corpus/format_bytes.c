// format a byte count as a human-readable string
#include <stdio.h>

int main(void) {
    long bytes = 1536000;
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};

    double size = bytes;
    int i = 0;
    while (size >= 1024 && i < 5) {  // GROUND_TRUTH_BUG: guard should be i < 4; units[i] can read out of bounds
        size /= 1024;
        i++;
    }

    printf("%.2f %s\n", size, units[i]);
    return 0;
}
