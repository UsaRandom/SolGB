#include <gb/gb.h>
#include <stdbool.h>

void add_progress(uint16_t weight) BANKED;

void show_progress_page() BANKED;

void prepare_rom_check_bar(void) BANKED;
void update_progress(uint8_t progress) BANKED;
void use_coin_bar_color(void) BANKED;

/* Boot check: label on row 7, bar on rows 9-10. */
#define BOOT_BAR_Y 9
#define BOOT_CHECK_TEXT_Y 7

/* Address gen has no title band. Title, timer, and bar are one
   centered stack with a blank row between each. */
#define ADDR_TITLE_Y 6
#define ADDR_ETA_Y 8

/* CRC32 over the same banks as the boot word sum. */
bool rom_verify_integrity(void) BANKED;

/* ETA, and a coin on each side of the timer. spread is extra pixels
   between each coin and the text. Address gen uses 0. Signing uses 8. */
void progress_ride_begin(uint8_t spread) BANKED;
void progress_ride_tick(unsigned long done, unsigned long total) BANKED;
void progress_ride_end(void) BANKED;

/* The first address generation derives the known wallet in this
   buffer, then the caller's mnemonic. Later calls return at once.
   Returns 0 when the known address does not match. */
uint8_t run_known_addr_check(uint8_t *seed, uint8_t *priv, uint8_t *pub,
                             char *address) BANKED;

/* Weights are GBC milliseconds.
   One PBKDF2 iteration is 263 ms (2048 of them).
   One public key is ED_MULS field multiplies. The SM83 test ROM
   measured that key at 28.6 s, GBC double speed, so one multiply
   is 38 ms.
   Address encoding is 586 ms. The address check is 293 ms.
   One CRC bank is 235 ms.
   The address page budgets the CRC plus one derivation.
   The first address generation adds the known-wallet derivation.
   The boot splash does not use these weights. */
#define WEIGHT_PBKDF2       263u
#define WEIGHT_ADDR_ENCODE  586u
#define WEIGHT_ADDR_CHECK   293u
#define WEIGHT_CRC_BANK     235u
#define ED_MULS             744u
#define WEIGHT_ED_MUL        38u

#define ADDRESS_WORK_UL (2048UL * WEIGHT_PBKDF2 \
    + (unsigned long)ED_MULS * (unsigned long)WEIGHT_ED_MUL \
    + (unsigned long)WEIGHT_ADDR_ENCODE \
    + (unsigned long)WEIGHT_ADDR_CHECK)

/* One signature is one scalarbase. The public key is already stored.
   The group-order reduction is a short table multiply, outside this budget. */
#define SIGN_WORK_UL ((unsigned long)ED_MULS * (unsigned long)WEIGHT_ED_MUL)

void show_sign_progress(void) BANKED;
