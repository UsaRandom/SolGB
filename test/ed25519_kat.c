#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "compat.h"
#include "../src/crypto/ed25519.h"

static void print_hex(const uint8_t *p, int n) {
    int i;
    for (i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(void) {
    static const uint8_t seed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    };
    static const uint8_t msg[6] = { 's', 'o', 'l', 'a', 'n', 'a' };
    uint8_t pub[32];
    uint8_t sig[64];

    ed25519_public(seed, pub);
    print_hex(pub, 32);
    if (!ed25519_sign(seed, pub, 0, 0, sig)) return 1;
    print_hex(sig, 64);
    if (!ed25519_sign(seed, pub, msg, 6, sig)) return 2;
    print_hex(sig, 64);
    return 0;
}
