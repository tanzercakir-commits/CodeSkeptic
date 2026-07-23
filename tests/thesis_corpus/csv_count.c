// count the number of fields in a CSV line
#include <stdio.h>

int main(void) {
    char line[256];
    printf("enter CSV line: ");
    if (!fgets(line, sizeof(line), stdin))
        return 1;

    int fields = 0;
    for (char *p = line; *p; p++) {
        if (*p == ',')
            fields++;
    }

    printf("fields: %d\n", fields);  // GROUND_TRUTH_BUG: this is the comma count; fields = commas + 1
    return 0;
}
