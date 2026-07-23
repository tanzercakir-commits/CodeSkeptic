#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *my_strdup(const char *s) {
    size_t len = strlen(s);
    char *copy = malloc(len); // GROUND_TRUTH_BUG: needs len+1 for the terminator
    for (size_t i = 0; i < len; i++)
        copy[i] = s[i];
    copy[len] = '\0';
    return copy;
}

int main(int argc, char **argv) {
    const char *src = argc > 1 ? argv[1] : "hello world";
    char *dup = my_strdup(src);
    printf("copy: %s\n", dup);
    free(dup);
    return 0;
}
