// build a growable char buffer from one line of stdin
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    int cap = 8;
    int len = 0;
    char *buf = malloc(cap);

    int c;
    while ((c = getchar()) != EOF && c != '\n') {
        if (len >= cap) {
            cap *= 2;
            buf = realloc(buf, cap);
        }
        buf[len++] = (char)c;
    }

    buf[len] = '\0';  // GROUND_TRUTH_BUG: len == cap writes one byte past the buffer
    printf("read %d chars: %s\n", len, buf);

    free(buf);
    return 0;
}
