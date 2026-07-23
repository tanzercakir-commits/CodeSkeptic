// GROUND_TRUTH_CLEAN
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *concat(const char *a, const char *b) {
    size_t la = strlen(a);
    size_t lb = strlen(b);
    char *out = malloc(la + lb + 1);
    if (!out)
        return NULL;
    memcpy(out, a, la);
    memcpy(out + la, b, lb + 1);
    return out;
}

int main(void) {
    char *s = concat("foo/", "bar.txt");
    printf("%s\n", s);
    free(s);
    return 0;
}
