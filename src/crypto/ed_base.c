#pragma bank 0

#include "ed_base.h"
#include <gb/gb.h>
#include <string.h>

/* tools/gen_ed_base.py. One row is 8 points, 96 bytes each. */
extern const uint8_t ed_base_lo[];
extern const uint8_t ed_base_hi[];

void ed_base_select(uint8_t dest[96], uint8_t pos, uint8_t digit_abs) {
    uint8_t saved;
    uint8_t k;
    uint8_t i;
    const uint8_t *row;

    saved = _current_bank;
    memset(dest, 0, 96);
    dest[31] = 1;
    dest[63] = 1;
    if (digit_abs == 0 || digit_abs > 8 || pos > 31) return;

    if (pos < 16) {
        SWITCH_ROM(18);
        row = ed_base_lo + (uint16_t)pos * 768u;
    } else {
        SWITCH_ROM(19);
        row = ed_base_hi + (uint16_t)(pos - 16u) * 768u;
    }
    for (k = 1; k <= 8; k++) {
        uint8_t m = (uint8_t)-(digit_abs == k);
        const uint8_t *src = row + (uint16_t)(k - 1u) * 96u;
        for (i = 0; i < 96; i++) dest[i] ^= (uint8_t)(m & (dest[i] ^ src[i]));
    }
    SWITCH_ROM(saved);
}
