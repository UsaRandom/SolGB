#pragma bank 4

#include "hd_wallet.h"
#include "hmac.h"
#include "ed25519.h"
#include "b58.h"
#include "progress.h"
#include <string.h>

static void copy32(uint8_t *dest, const uint8_t *src) {
    uint8_t i;
    for (i = 0; i < 32u; i++) dest[i] = src[i];
}

void seed_to_addresses(
    const uint8_t *seed,
    char *address_out,
    uint8_t privkey_out[32],
    uint8_t pubkey_out[32]
) BANKED {
    uint8_t I[64];
    uint8_t key[32];
    uint8_t chain[32];
    uint8_t data[37];
    uint8_t pub[32];
    /* 44', 501', 0', 0'. All hardened. 501 is Solana's coin type. */
    static const uint32_t path[4] = {
        0x8000002Cu, 0x800001F5u, 0x80000000u, 0x80000000u
    };
    uint8_t level;

    address_out[0] = 0;
    hmac_sha512(I, (const uint8_t *)"ed25519 seed", 12, seed, 64);
    copy32(key, I);
    copy32(chain, I + 32);

    for (level = 0; level < 4u; level++) {
        uint32_t index = path[level];
        data[0] = 0;
        copy32(data + 1, key);
        data[33] = (uint8_t)(index >> 24);
        data[34] = (uint8_t)(index >> 16);
        data[35] = (uint8_t)(index >> 8);
        data[36] = (uint8_t)index;
        hmac_sha512(I, chain, 32, data, 37);
        copy32(key, I);
        copy32(chain, I + 32);
    }

    ed25519_public(key, pub);
    if (!b58_encode(pub, 32, address_out, 45)) {
        address_out[0] = 0;
        memset(key, 0, sizeof key);
        memset(I, 0, sizeof I);
        return;
    }
    add_progress(WEIGHT_ADDR_ENCODE);
    copy32(privkey_out, key);
    copy32(pubkey_out, pub);
    memset(key, 0, sizeof key);
    memset(chain, 0, sizeof chain);
    memset(I, 0, sizeof I);
    memset(data, 0, sizeof data);
}
