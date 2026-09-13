/* CodeSkeptic-owned reference specimen, not an independent quota example.
 * The mapping assumes argc >= 2, argv[1][0] != 0 and snprintf returns 1.
 * Failure branches remain outside that selected path, not certified safe.
 */
#include <stdio.h>

static char *render(char *out, const char *input)
{
    int count = snprintf(out, 4, "%s", input);
    if (count != 1)
        return NULL;
    return out;
}

static int inspect_first(const char *text)
{
    return (unsigned char)text[0];
}

int main(int argc, char **argv)
{
    if (argc < 2 || argv[1][0] == '\0')
        return 0;
    char input[2] = {argv[1][0], '\0'};
    char out[4] = {0};
    char *alias = out;
    char *formatted = render(alias, input);
    if (formatted == NULL)
        return 1;
    return inspect_first(formatted);
}
