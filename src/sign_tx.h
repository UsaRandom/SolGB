#ifndef SIGN_TX_H
#define SIGN_TX_H

#include <stdint.h>
#include <gb/gb.h>

/* Decrypt the slot key and sign one durable-nonce Solana transfer.
   dest is the 32-byte recipient. lamports is unsigned little-endian.
   nonce_acc is the nonce account. nonce is its stored value, used as
   the recent-blockhash field. Returns 0 if the slot, the destination,
   the amount, the nonce, or the signature is unusable.
   The key is wiped before return. On success the start of the scratch
   holds 32-byte pubkey then 64-byte signature. *blob_len is 96.
   The caller wipes the scratch when it is done showing the codes. */
uint8_t sign_payment(uint8_t slot, const uint8_t dest[32],
                     const uint8_t lamports[8], const uint8_t nonce_acc[32],
                     const uint8_t nonce[32], uint16_t *blob_len) BANKED;

#endif
