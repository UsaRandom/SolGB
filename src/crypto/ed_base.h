#ifndef ED_BASE_H
#define ED_BASE_H

#include <stdint.h>

/* Precomp for digit_abs * 256^pos * B. digit_abs is 0..8.
   0 leaves the identity. dest is y+x, y-x, 2*d*x*y, 32 bytes each.
   Runs from the home bank so it can switch to the table. */
void ed_base_select(uint8_t dest[96], uint8_t pos, uint8_t digit_abs);

#endif
