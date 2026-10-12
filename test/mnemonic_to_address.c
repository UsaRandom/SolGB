#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Include compatibility header first
#include "compat.h"

// Include crypto headers
#include "../src/crypto/mnemonic.h"
#include "../src/crypto/hd_wallet.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s \"mnemonic phrase\"\n", argv[0]);
        return 1;
    }

    const char* mnemonic = argv[1];

    uint8_t seed[64];
    uint8_t privkey[32];
    uint8_t pubkey[32];
    char    address[45];
    mnemonic_to_seed(mnemonic, seed);

    seed_to_addresses(seed, address, privkey, pubkey);

    printf("%s\n", address);

    return 0;
}
