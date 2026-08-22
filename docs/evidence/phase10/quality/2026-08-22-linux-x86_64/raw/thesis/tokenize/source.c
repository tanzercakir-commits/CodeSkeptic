// GROUND_TRUTH_CLEAN
// split a string into whitespace-separated tokens
#include <stdio.h>
#include <string.h>

int main(void) {
    char str[] = "the quick brown fox jumps";
    int count = 0;

    char *tok = strtok(str, " ");
    while (tok != NULL) {
        printf("token %d: %s\n", count, tok);
        count++;
        tok = strtok(NULL, " ");
    }

    printf("total tokens: %d\n", count);
    return 0;
}
