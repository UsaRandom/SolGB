#ifndef B58_H
#define B58_H

#include <stdint.h>
#include <gb/gb.h>

/* Bitcoin base58. out receives a NUL. Returns 0 if out_cap is too small
   or in_len is 0. A 32-byte key fits in 45 bytes, including the NUL. */
uint8_t b58_encode(const uint8_t *in, uint8_t in_len, char *out, uint8_t out_cap) BANKED;

/* 1 when text is the base58 form of exactly 32 bytes. */
uint8_t b58_is_key(const char *text) BANKED;

#endif
