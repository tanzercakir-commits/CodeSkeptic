// GROUND_TRUTH_CLEAN
// parse a "key=value" config line from stdin
#include <stdio.h>
#include <string.h>

int main(void) {
    char line[128];
    printf("Enter config (key=value): ");
    if (!fgets(line, sizeof(line), stdin))
        return 1;

    char *eq = strchr(line, '=');
    if (!eq) {
        printf("no '=' in input\n");
        return 1;
    }

    *eq = '\0';
    char *key = line;
    char *value = eq + 1;
    value[strcspn(value, "\n")] = '\0';

    printf("key='%s' value='%s'\n", key, value);
    return 0;
}
