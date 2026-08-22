// GROUND_TRUTH_CLEAN
// djb2 string hash
#include <stdio.h>

unsigned long hash_str(const char *s) {
    unsigned long h = 5381;
    int c;
    while ((c = (unsigned char)*s++) != 0) {
        h = ((h << 5) + h) + c;
    }
    return h;
}

int main(void) {
    const char *words[] = {"apple", "banana", "cherry"};
    for (int i = 0; i < 3; i++) {
        printf("%-8s %lu\n", words[i], hash_str(words[i]));
    }
    return 0;
}
