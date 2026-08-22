// GROUND_TRUTH_CLEAN
// tiny fixed-capacity integer stack
#include <stdio.h>

#define MAX 16

static int stack[MAX];
static int top = 0;

static void push(int v) {
    stack[top++] = v;
}

static int pop(void) {
    return stack[--top];
}

int main(void) {
    push(10);
    push(20);
    push(30);

    printf("%d\n", pop());
    printf("%d\n", pop());
    printf("%d\n", pop());
    return 0;
}
