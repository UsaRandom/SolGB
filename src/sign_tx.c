#pragma bank 15

#include "sign_tx.h"
#include "ed25519.h"
#include "pbkdf2.h"
#include "wallet_sram.h"

#include <stddef.h>
#include <string.h>

extern uint8_t pin_hash[32];

/* Walk the encrypted slot once and keep only the key. The rest of the
   slot, including the mnemonic, is not stored. SRAM is left as it was. */
static uint8_t load_slot_key(uint8_t slot, uint8_t priv[32], uint8_t pub[32]) {
    uint16_t i;
    uint16_t lcg;
    uint16_t len;
    uint16_t priv_at;
    uint16_t pub_at;
    volatile uint8_t *data;
    const uint8_t *key;

    if (slot < 1u || slot > MAX_SLOTS) return 0;
    ENABLE_RAM_MBC5;
    SWITCH_RAM_MBC5(0);
    if (slots[slot - 1u].used != SLOT_USED_MARKER) {
        DISABLE_RAM_MBC5;
        return 0;
    }
    key = pin_hash;
    lcg = (uint16_t)((uint16_t)key[0] | ((uint16_t)key[1] << 8));
    data = (volatile uint8_t *)slots[slot - 1u].address;
    len = (uint16_t)(sizeof(SaveSlot) - offsetof(SaveSlot, address));
    priv_at = (uint16_t)(offsetof(SaveSlot, private_key) - offsetof(SaveSlot, address));
    pub_at = (uint16_t)(offsetof(SaveSlot, public_key) - offsetof(SaveSlot, address));
    for (i = 0; i < len; i++) {
        uint8_t b = (uint8_t)(data[i] ^ key[lcg & 0x1Fu] ^ (uint8_t)(lcg >> 8));
        lcg = (uint16_t)(lcg * 5u + 1u);
        if (i >= priv_at && i < (uint16_t)(priv_at + 32u))
            priv[(uint16_t)(i - priv_at)] = b;
        else if (i >= pub_at && i < (uint16_t)(pub_at + PUB_KEY_LEN))
            pub[(uint16_t)(i - pub_at)] = b;
    }
    DISABLE_RAM_MBC5;
    return 1;
}

static uint8_t all_zero(const uint8_t *p, uint8_t n) {
    uint8_t i;
    for (i = 0; i < n; i++) {
        if (p[i]) return 0u;
    }
    return 1u;
}

/* SysvarRecentB1ockHashes11111111111111111111. The 1 in B1ock is
   part of the address. */
static const uint8_t SYSVAR_RECENT[32] = {
    0x06, 0xa7, 0xd5, 0x17, 0x19, 0x2c, 0x56, 0x8e,
    0xe0, 0x8a, 0x84, 0x5f, 0x73, 0xd2, 0x97, 0x88,
    0xcf, 0x03, 0x5c, 0x31, 0x45, 0xb2, 0x1a, 0xb3,
    0x44, 0xd8, 0x06, 0x2e, 0xa9, 0x40, 0x00, 0x00
};
static const uint8_t SYSTEM_PROGRAM[32] = {0};

typedef struct {
    const uint8_t *pub;
    uint8_t signer;
    uint8_t writable;
} Acc;

static void acc_add(Acc *keys, uint8_t *n, const uint8_t *pub,
                    uint8_t signer, uint8_t writable) {
    uint8_t i;
    for (i = 0; i < *n; i++) {
        if (memcmp(keys[i].pub, pub, 32) != 0) continue;
        if (signer) keys[i].signer = 1u;
        if (writable) keys[i].writable = 1u;
        return;
    }
    keys[*n].pub = pub;
    keys[*n].signer = signer;
    keys[*n].writable = writable;
    (*n)++;
}

static void take_bucket(const Acc *in, uint8_t n, Acc *out, uint8_t *m,
                        uint8_t signer, uint8_t writable) {
    uint8_t i;
    for (i = 0; i < n; i++) {
        if (in[i].signer == signer && in[i].writable == writable)
            out[(*m)++] = in[i];
    }
}

static uint8_t acc_at(const Acc *keys, uint8_t n, const uint8_t *pub) {
    uint8_t i;
    for (i = 0; i < n; i++) {
        if (memcmp(keys[i].pub, pub, 32) == 0) return i;
    }
    return 0xffu;
}

/* Legacy durable-nonce transfer. AdvanceNonceAccount is first. The
   recent-blockhash field is the nonce value. At most 224 bytes.
   Returns the length, or 0. */
static uint16_t build_message(uint8_t msg[224], const uint8_t pub[32],
                              const uint8_t dest[32], const uint8_t lamports[8],
                              const uint8_t nonce_acc[32], const uint8_t nonce[32]) {
    Acc raw[5];
    Acc ord[5];
    uint8_t n = 0;
    uint8_t m = 0;
    uint8_t i;
    uint8_t nsign = 0;
    uint8_t nro_sign = 0;
    uint8_t nro = 0;
    uint8_t prog;
    uint8_t nonce_ix;
    uint8_t sys_ix;
    uint8_t auth_ix;
    uint8_t from_ix;
    uint8_t to_ix;
    uint16_t o = 0;

    acc_add(raw, &n, nonce_acc, 0, 1);
    acc_add(raw, &n, SYSVAR_RECENT, 0, 0);
    acc_add(raw, &n, pub, 1, 1);
    acc_add(raw, &n, SYSTEM_PROGRAM, 0, 0);
    acc_add(raw, &n, dest, 0, 1);
    take_bucket(raw, n, ord, &m, 1, 1);
    take_bucket(raw, n, ord, &m, 1, 0);
    take_bucket(raw, n, ord, &m, 0, 1);
    take_bucket(raw, n, ord, &m, 0, 0);
    for (i = 0; i < m; i++) {
        if (ord[i].signer) nsign++;
        if (ord[i].signer && !ord[i].writable) nro_sign++;
        if (!ord[i].signer && !ord[i].writable) nro++;
    }
    prog = acc_at(ord, m, SYSTEM_PROGRAM);
    nonce_ix = acc_at(ord, m, nonce_acc);
    sys_ix = acc_at(ord, m, SYSVAR_RECENT);
    auth_ix = acc_at(ord, m, pub);
    from_ix = auth_ix;
    to_ix = acc_at(ord, m, dest);
    if (prog == 0xffu || nonce_ix == 0xffu || sys_ix == 0xffu ||
        auth_ix == 0xffu || to_ix == 0xffu) return 0;

    msg[o++] = nsign;
    msg[o++] = nro_sign;
    msg[o++] = nro;
    msg[o++] = m;
    for (i = 0; i < m; i++) {
        memcpy(msg + o, ord[i].pub, 32);
        o = (uint16_t)(o + 32u);
    }
    memcpy(msg + o, nonce, 32);
    o = (uint16_t)(o + 32u);
    msg[o++] = 2;
    msg[o++] = prog;
    msg[o++] = 3;
    msg[o++] = nonce_ix;
    msg[o++] = sys_ix;
    msg[o++] = auth_ix;
    msg[o++] = 4;
    msg[o++] = 4;
    msg[o++] = 0;
    msg[o++] = 0;
    msg[o++] = 0;
    msg[o++] = prog;
    msg[o++] = 2;
    msg[o++] = from_ix;
    msg[o++] = to_ix;
    msg[o++] = 12;
    msg[o++] = 2;
    msg[o++] = 0;
    msg[o++] = 0;
    msg[o++] = 0;
    memcpy(msg + o, lamports, 8);
    o = (uint16_t)(o + 8u);
    return o;
}

uint8_t sign_payment(uint8_t slot, const uint8_t dest[32],
                     const uint8_t lamports[8], const uint8_t nonce_acc[32],
                     const uint8_t nonce[32], uint16_t *blob_len) BANKED {
    uint8_t priv[32];
    uint8_t pub[32];
    uint8_t msg[224];
    uint8_t sig[64];
    uint16_t len = 0;
    uint16_t mlen;
    uint8_t *base;

    if (blob_len) *blob_len = 0;
    if (!dest || !lamports || !nonce_acc || !nonce) return 0;
    if (all_zero(dest, 32) || all_zero(lamports, 8) ||
        all_zero(nonce_acc, 32) || all_zero(nonce, 32)) return 0;
    if (!load_slot_key(slot, priv, pub)) return 0;
    mlen = build_message(msg, pub, dest, lamports, nonce_acc, nonce);
    if (!mlen || !ed25519_sign(priv, pub, msg, mlen, sig)) {
        memset(priv, 0, sizeof priv);
        memset(pub, 0, sizeof pub);
        memset(msg, 0, sizeof msg);
        memset(sig, 0, sizeof sig);
        return 0;
    }

    base = kdf_scratch(&len);
    if (!base || len < 96u) {
        memset(priv, 0, sizeof priv);
        memset(pub, 0, sizeof pub);
        memset(msg, 0, sizeof msg);
        memset(sig, 0, sizeof sig);
        return 0;
    }
    memcpy(base, pub, 32);
    memcpy(base + 32, sig, 64);
    if (blob_len) *blob_len = 96;
    memset(priv, 0, sizeof priv);
    memset(pub, 0, sizeof pub);
    memset(msg, 0, sizeof msg);
    memset(sig, 0, sizeof sig);
    return 1;
}
