// fixed-size ring buffer: enqueue several values then drain in order
#include <stdio.h>

#define SIZE 4

int main(void) {
    int buf[SIZE];
    int head = 0, tail = 0, count = 0;

    for (int v = 1; v <= 6; v++) {
        buf[head] = v;
        head = (head + 1) % SIZE;
        count++;  // GROUND_TRUTH_BUG: no full check; count exceeds SIZE and overwrites unread data
    }

    while (count > 0) {
        printf("%d\n", buf[tail]);
        tail = (tail + 1) % SIZE;
        count--;
    }
    return 0;
}
