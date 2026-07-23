#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { char *base; size_t size; size_t used; } Pool;

void pool_init(Pool *p, size_t size) {
    p->base = malloc(size);
    p->size = size;
    p->used = 0;
}

void *pool_alloc(Pool *p, size_t n) {
    if (p->used + n > p->size)
        return NULL;
    void *ptr = p->base + p->used; // GROUND_TRUTH_BUG: no alignment of returned pointers
    p->used += n;
    return ptr;
}

int main(void) {
    Pool p;
    pool_init(&p, 64);
    char *a = pool_alloc(&p, 10);
    strcpy(a, "hello");
    printf("a = %s\n", a);
    free(p.base);
    return 0;
}
