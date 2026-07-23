#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int width, height;
    printf("Enter width height: ");
    if (scanf("%d %d", &width, &height) != 2)
        return 1;

    int channels = 3;
    unsigned char *buf = malloc(width * height * channels); // GROUND_TRUTH_BUG: int size computation can overflow
    if (!buf)
        return 1;

    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            unsigned char *px = buf + (y * width + x) * channels;
            px[0] = x & 0xFF;
            px[1] = y & 0xFF;
            px[2] = 128;
        }
    }

    printf("allocated %d x %d\n", width, height);
    free(buf);
    return 0;
}
