#include <stdlib.h>
#include <string.h>

/* An AI-drafted config helper: looks right, reads wrong. */
char *load_setting(const char *name) {
    char *val = getenv(name);              /* may be NULL when unset   */
    char *copy = malloc(strlen(val) + 1);  /* strlen(NULL) if unset    */
    strcpy(copy, val);                     /* and copy has no null chk */
    return copy;
}

int buffer_size(const char *s) {
    int n = atoi(s);          /* untrusted, unbounded */
    return n * 4096;          /* signed overflow      */
}
