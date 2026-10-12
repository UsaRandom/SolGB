

#include <gb/gb.h>
#include <stdio.h>
#include <string.h>
#include <menu.h>
#include <wallet.h>
#include "states.h"
#include "draw.h"

#pragma bank 1

extern AppState current_state;
extern uint8_t current_slot;
extern char words[12][9];
extern uint8_t gen_type;
extern wallet current_wallet;
extern char temp_buffer[32];

void handle_slot_selection(void) {
    char slot_display[MAX_SLOTS][SLOT_DISPLAY_LEN];

    list_slots(slot_display);

    const char* menu_options[MAX_SLOTS + 4] = {
        slot_display[0],
        slot_display[1],
        slot_display[2],
        slot_display[3],
        slot_display[4],
        slot_display[5],
        slot_display[6],
        slot_display[7],
        "",
        "[PUMP IT]",
        "",
        "[Set PIN]"
    };

    int8_t slot = show_menu("SolGB", menu_options, MAX_SLOTS + 4);
    if (slot >= 0 && slot < MAX_SLOTS) {
        current_slot = slot + 1;

        if(slot_display[slot][0] != 'E') {
            wallet result;
            get_wallet(current_slot, &result);
            
            current_wallet = result;

            current_state = STATE_WALLET_MENU;
        } else {
            current_state = STATE_GEN_TYPE_SELECTION;
        }
    }

    if(slot == MAX_SLOTS + 1) {
        current_state = STATE_BONKTIME_GAME;
    }

    if(slot == MAX_SLOTS + 3) {
        current_state = STATE_SET_PIN;
    }
}

void handle_gen_type_selection(void) BANKED {
    char* genTypes[] = {
        "New Wallet",
        "Load Wallet"
    };

    sprintf(temp_buffer, "Wallet Slot #%d", current_slot);
    int8_t selected_type = show_menu(temp_buffer, genTypes, 2);
    if (selected_type >= 0) {
        gen_type = selected_type;
        memset(words, 0, sizeof(words));
        if (gen_type == 0) {
            current_state = STATE_BONKTIME_ENTROPY;
        } else {
            current_state = STATE_SHOW_GENERATED_WORDS;
        }
    }
    else {
        current_state = STATE_SLOT_SELECTION;
    }
}
