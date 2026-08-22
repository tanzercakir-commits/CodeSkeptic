// GROUND_TRUTH_CLEAN
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 1;
    }

    long port = strtol(argv[1], NULL, 10);
    if (port < 0 || port > 65535) {
        fprintf(stderr, "port out of range\n");
        return 1;
    }

    unsigned short p = (unsigned short) port;
    unsigned char hi = p >> 8;
    unsigned char lo = p & 0xFF;

    printf("port %u -> %02x %02x\n", p, hi, lo);
    return 0;
}
