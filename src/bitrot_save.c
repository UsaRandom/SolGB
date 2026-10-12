
#include "bitrot_save.h"
#include "b58.h"
#include "progress.h"

#pragma bank 4

/* A Solana address is base58 of exactly 32 bytes. No version, no checksum. */
bool validate_checksum(char* address) BANKED {
    if (address[0] == '\0') return false;
    if (!b58_is_key(address)) return false;
    add_progress(WEIGHT_ADDR_CHECK);
    return true;
}