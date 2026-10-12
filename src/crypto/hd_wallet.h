#ifndef HD_WALLET_H
#define HD_WALLET_H

#include <stdint.h>
#include <gb/gb.h>

/* SLIP-0010 ed25519, path m/44'/501'/0'/0'. address_out is base58 of the
   32-byte public key. privkey_out is the 32-byte seed. */
void seed_to_addresses(
    const uint8_t *seed,
    char *address_out,
    uint8_t privkey_out[32],
    uint8_t pubkey_out[32]
) BANKED;

#endif
