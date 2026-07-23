#include <stdio.h>
#include <stdlib.h>

typedef struct Node { int value; struct Node *next; } Node;

Node *build(int *vals, int n) {
    Node *head = NULL, *tail = NULL;
    for (int i = 0; i < n; i++) {
        Node *node = malloc(sizeof(Node));
        node->value = vals[i];
        node->next = NULL;
        if (!head)
            head = tail = node;
        else {
            tail->next = node;
            tail = node;
        }
    }
    return head;
}

int main(void) {
    int vals[] = {3, 1, 4, 1, 5, 9};
    int n = sizeof(vals) / sizeof(vals[0]);

    Node *head = build(vals, n);
    for (Node *cur = head; cur; cur = cur->next)
        printf("%d ", cur->value);
    printf("\n");

    Node *cur = head;
    while (cur) {
        free(cur);
        cur = cur->next; // GROUND_TRUTH_BUG: use-after-free; cur->next read after free
    }
    return 0;
}
