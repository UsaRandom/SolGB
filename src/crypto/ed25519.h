#ifndef ED25519_H
#define ED25519_H

#include <stdint.h>
#include <gb/gb.h>

/* seed is the 32-byte SLIP-0010 key. pub is the raw ed25519 point.
   Solana addresses are base58 of that point, with no checksum. */
void ed25519_public(const uint8_t seed[32], uint8_t pub[32]) BANKED;

/* Deterministic RFC 8032 signature of msg. sig is R || S, 64 bytes.
   Returns 0 when the scratch block is too small. */
uint8_t ed25519_sign(const uint8_t seed[32], const uint8_t pub[32],
                     const uint8_t *msg, uint16_t len, uint8_t sig[64]) BANKED;

#endif
