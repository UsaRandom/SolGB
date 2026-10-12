#include <gb/gb.h>
#include <stdint.h>
#include <string.h>

#include "hd_wallet.h"
#include "pbkdf2.h"
#include "sha512.h"
#include "ed25519.h"

/*
 * Mailbox the harness reads by symbol.
 * magic: 0 idle, 0x11 entered main, 0x22 test running, 0xA5 done.
 * test id is the SRAM byte the harness wrote before boot.
 */
volatile uint8_t result[256];
volatile uint16_t ticks;

/* BIP39 abandon x11 + about. 93 bytes, empty passphrase. */
static const char MNEMONIC[] =
    "abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon about";

static void finish(uint8_t test, const uint8_t *data, uint16_t len) {
    uint16_t i;

    if (len > 250) {
        len = 250;
    }
    result[1] = test;
    result[2] = (uint8_t)(len & 0xFF);
    result[3] = (uint8_t)(len >> 8);
    for (i = 0; i < len; i++) {
        result[4 + i] = data[i];
    }
    /* Written last so a frame boundary cannot observe a short buffer. */
    result[0] = 0xA5;
}

static uint8_t sram_at(uint16_t offset) {
    /* MBC5 RAM enable, then the battery RAM window. */
    *((volatile uint8_t *)0x0000) = 0x0A;
    return ((volatile uint8_t *)0xA000)[offset];
}

static void run_sha512(void) {
    static SHA512_CTX ctx;
    static uint8_t digest[64];
    static const uint8_t msg[3] = {'a', 'b', 'c'};

    sha512_init(&ctx);
    sha512_update(&ctx, msg, 3);
    sha512_final(&ctx, digest);
    finish(1, digest, 64);
}

/* RFC 8032 test 1. One public key, no PBKDF2. */
extern uint8_t ed_test_reduce(uint8_t s[64]) BANKED;

/* Four reductions: 0, L, 2^256, and 64 bytes of 0xff. */
static void run_reduce(void) {
    static const uint8_t order[32] = {
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
    };
    static uint8_t s[64];
    static uint8_t out[128];
    uint8_t n;
    uint8_t i;

    for (n = 0; n < 4u; n++) {
        memset(s, 0, 64);
        if (n == 1u) memcpy(s, order, 32);
        else if (n == 2u) s[32] = 1u;
        else if (n == 3u) memset(s, 0xff, 64);
        if (!ed_test_reduce(s)) {
            finish(0xE5, 0, 0);
            return;
        }
        for (i = 0; i < 32u; i++) out[n * 32u + i] = s[i];
    }
    finish(5, out, 128);
}

static void run_sign(void) {
    static const uint8_t seed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    };
    static uint8_t pub[32];
    static uint8_t sig[64];

    ed25519_public(seed, pub);
    if (!ed25519_sign(seed, pub, 0, 0, sig)) {
        finish(0xE6, 0, 0);
        return;
    }
    finish(6, sig, 64);
}

static void run_ed25519(void) {
    static const uint8_t seed[32] = {
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60
    };
    static uint8_t pub[32];

    ed25519_public(seed, pub);
    finish(2, pub, 32);
}

static void run_pbkdf2(uint32_t iterations, uint8_t test) {
    static uint8_t seed[64];
    static const uint8_t salt[8] = {
        'm', 'n', 'e', 'm', 'o', 'n', 'i', 'c'
    };

    pbkdf2_hmac_sha512(seed, (const uint8_t *)MNEMONIC, 93, salt, 8, iterations);
    finish(test, seed, 64);
}

static void run_address(void) {
    static uint8_t seed[64];
    static uint8_t privkey[32];
    static uint8_t pubkey[32];
    static char address[45];
    static uint8_t packed[141];
    static const uint8_t salt[8] = {
        'm', 'n', 'e', 'm', 'o', 'n', 'i', 'c'
    };

    memset(address, 0, 45);
    memset(packed, 0, sizeof packed);

    pbkdf2_hmac_sha512(seed, (const uint8_t *)MNEMONIC, 93, salt, 8, 2048);
    seed_to_addresses(seed, address, privkey, pubkey);

    memcpy(packed, address, 45);
    memcpy(packed + 45, seed, 64);
    memcpy(packed + 109, pubkey, 32);
    finish(4, packed, 141);
}

void main(void) {
    uint8_t id;
    uint8_t mark;

    /* Crypto does not wait on vblank. Skip the interrupt tax. */
    __asm__("di");

    result[0] = 0x11;
    id = sram_at(0);
    mark = sram_at(1);
    result[1] = id;

    if (mark != 0x5A) {
        finish(0xEE, 0, 0);
        while (1) { }
    }

    result[0] = 0x22;

    if (id == 1) {
        run_sha512();
    } else if (id == 2) {
        run_ed25519();
    } else if (id == 3) {
        run_pbkdf2(1, 3);
    } else if (id == 4) {
        run_address();
    } else if (id == 5) {
        run_reduce();
    } else if (id == 6) {
        run_sign();
    } else {
        finish(id, 0, 0);
    }

    while (1) { }
}
