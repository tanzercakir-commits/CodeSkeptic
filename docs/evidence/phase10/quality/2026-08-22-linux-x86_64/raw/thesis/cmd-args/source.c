// GROUND_TRUTH_CLEAN
// minimal command-line argument handler (-v flag, -f <file>)
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    int verbose = 0;
    const char *file = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (strcmp(argv[i], "-f") == 0) {
            file = argv[i + 1];
            i++;
        } else {
            printf("unknown arg: %s\n", argv[i]);
        }
    }

    if (verbose) printf("verbose on\n");
    if (file) printf("file: %s\n", file);
    return 0;
}
