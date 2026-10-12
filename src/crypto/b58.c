#pragma bank 17

#include "b58.h"
#include <string.h>

static const char ALPHA[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static int8_t alpha_of(char c) {
    uint8_t i;
    for (i = 0; i < 58u; i++) {
        if (ALPHA[i] == c) return (int8_t)i;
    }
    return -1;
}

uint8_t b58_encode(const uint8_t *in, uint8_t in_len, char *out, uint8_t out_cap) BANKED {
    uint8_t digits[46];
    uint8_t n = 0;
    uint8_t z = 0;
    uint8_t i;
    uint8_t j;
    uint8_t need;

    if (!in || !out || in_len == 0u || out_cap < 2u) return 0u;
    while (z < in_len && in[z] == 0u) z++;
    memset(digits, 0, sizeof digits);
    for (i = 0; i < in_len; i++) {
        uint16_t carry = in[i];
        for (j = 0; j < n; j++) {
            carry = (uint16_t)(carry + ((uint16_t)digits[j] << 8));
            digits[j] = (uint8_t)(carry % 58u);
            carry = (uint16_t)(carry / 58u);
        }
        while (carry) {
            if (n >= sizeof digits) return 0u;
            digits[n++] = (uint8_t)(carry % 58u);
            carry = (uint16_t)(carry / 58u);
        }
    }
    need = (uint8_t)(z + n + 1u);
    if (need > out_cap) return 0u;
    for (i = 0; i < z; i++) out[i] = '1';
    for (i = 0; i < n; i++) out[z + i] = ALPHA[digits[n - 1u - i]];
    out[z + n] = 0;
    return 1u;
}

uint8_t b58_is_key(const char *text) BANKED {
    uint8_t acc[32];
    uint8_t n = 0;
    uint8_t z = 0;
    uint8_t chars = 0;
    const char *s;

    if (!text || text[0] == 0) return 0u;
    s = text;
    while (*s == '1') {
        z++;
        s++;
        chars++;
    }
    memset(acc, 0, sizeof acc);
    while (*s) {
        int8_t a = alpha_of(*s);
        uint16_t carry;
        uint8_t i;
        if (a < 0) return 0u;
        chars++;
        if (chars > 44u) return 0u;
        carry = (uint16_t)a;
        for (i = 0; i < n; i++) {
            carry = (uint16_t)(carry + (uint16_t)acc[i] * 58u);
            acc[i] = (uint8_t)carry;
            carry >>= 8;
        }
        while (carry) {
            if (n >= 32u) return 0u;
            acc[n++] = (uint8_t)carry;
            carry >>= 8;
        }
        s++;
    }
    return (uint8_t)(z + n) == 32u;
}
