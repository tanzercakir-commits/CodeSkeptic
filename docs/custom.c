#include <string.h>

/* our OWN function that can return NULL — not a known libc call */
char *my_lookup(int key) {
    if (key == 0) return 0;        /* NULL on some path */
    static char buf[8];
    return buf;
}

/* case A: result passed to strlen (a __nonnull libc param) */
unsigned long via_libc(int key) {
    char *v = my_lookup(key);
    return strlen(v);
}

/* case B: result dereferenced directly (no libc attribute crutch) */
char direct(int key) {
    char *v = my_lookup(key);
    return v[0];
}
