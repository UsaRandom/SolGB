PROJECT_NAME = SolGB
CC = ./gbdk/bin/lcc

# Compiler flags
CFLAGS = -msm83:gb \
         -Wl-yt0x1B \
         -Wl-yo512 \
         -Wl-ya1 \
         -Wb-ext=.rel \
         -Wm-yC \
         -Wl-m \
         -I. \
         -Ibuild \
         -Isrc/crypto \
         -Iqr \
         -Isrc

# Optimization flags (passed via -Wf)
OPTFLAGS = # -Wf--opt-code-speed \
           #-Wf--max-allocs-per-node1000

# Source files
SRC = src/main.c \
      src/qr/qrcodegen.c \
      src/qr/qr_wrapper.c \
      src/states_slot.c \
      src/states_bonk.c \
      src/states_generation.c \
      src/states_wallet_menu.c \
      src/states_wordtest.c \
      src/states_pin.c \
      src/assets/progress_bar.c \
      src/assets/keyboard.c \
      src/assets/keyboard_lightgrey.c \
      src/assets/keyboard_base58.c \
      src/assets/sollogo.c \
      src/assets/sol_idle.c \
      src/assets/sol_bonk.c \
      src/assets/sol_selfbonk.c \
      src/assets/abutton.c \
      src/assets/bbutton.c \
      src/assets/dpadbutton_up.c \
      src/assets/dpadbutton_down.c \
      src/assets/dpadbutton_left.c \
      src/assets/dpadbutton_right.c \
      src/assets/solcoin.c \
      src/assets/chksum.c \
      src/assets/nophotos.c \
      src/assets/offlineonly.c \
      src/splash.c \
      src/wallet.c \
      src/bonktime.c \
      src/word_input.c \
      src/sign_input.c \
      src/sign_review.c \
      src/sign_tx.c \
      src/menu.c \
      src/pin.c \
      src/draw.c \
      src/progress.c \
      src/progress_ride.c \
      src/crypto/bip39_wordlist.c \
      src/crypto/bip39_words_1.c \
      src/crypto/bip39_words_2.c \
      src/crypto/sha256.c \
      src/crypto/mnemonic.c \
      src/crypto/pbkdf2.c \
      src/crypto/sha512.c \
      src/crypto/sha_block.s \
      src/crypto/sha512_transform.c \
      src/crypto/sha512_constants.c \
      src/crypto/hd_wallet.c \
      src/crypto/ed25519.c \
      src/crypto/ed_base.c \
      src/crypto/ed_base_lo.s \
      src/crypto/ed_base_hi.s \
      src/crypto/bn_mul.s \
      src/crypto/mul_tables.s \
      src/crypto/b58.c \
      src/crypto/hmac.c \
      src/crypto/entropy_data.c \
      src/bitrot_rom.c \
      src/bitrot_sum.s \
      src/bitrot_crc.s \
      src/bitrot_save.c

.PHONY: entropy test clean postclean assets savedata all sol asm-test
.DEFAULT_GOAL := sol

bank = 6

savedata:
	mkdir -p build
	$(CC) -Wf-ba0 -c -o build/wallet_sram.o src/wallet_sram.c

assets:
	./gbdk/bin/png2asset ./raw_assets/sol_idle.png -map -noflip -tile_origin 243 -b $(bank) -o ./src/assets/sol_idle.c
	./gbdk/bin/png2asset ./raw_assets/sol_bonk.png -map -noflip -tile_origin 137 -b $(bank) -o ./src/assets/sol_bonk.c
	./gbdk/bin/png2asset ./raw_assets/sol_selfbonk.png -map -noflip -tile_origin 202 -b $(bank) -o ./src/assets/sol_selfbonk.c
	./gbdk/bin/png2asset ./raw_assets/abutton.png -map -noflip -tile_origin 186 -b $(bank) -o ./src/assets/abutton.c
	./gbdk/bin/png2asset ./raw_assets/bbutton.png -map -noflip -tile_origin 190 -b $(bank) -o ./src/assets/bbutton.c
	./gbdk/bin/png2asset ./raw_assets/dpadbutton_up.png -map -noflip -tile_origin 194 -b $(bank) -o ./src/assets/dpadbutton_up.c
	./gbdk/bin/png2asset ./raw_assets/dpadbutton_down.png -map -noflip -tile_origin 80 -b $(bank) -o ./src/assets/dpadbutton_down.c
	./gbdk/bin/png2asset ./raw_assets/dpadbutton_right.png -map -noflip -tile_origin 198 -b $(bank) -o ./src/assets/dpadbutton_right.c
	./gbdk/bin/png2asset ./raw_assets/dpadbutton_left.png -map -noflip -tile_origin 85 -b $(bank) -o ./src/assets/dpadbutton_left.c
	./gbdk/bin/png2asset ./raw_assets/keyboard.png -map -noflip -tile_origin 88 -b 5 -use_map_attributes -o ./src/assets/keyboard.c
	./gbdk/bin/png2asset ./raw_assets/keyboard_lightgrey.png -map -noflip -tile_origin 160 -b 5 -use_map_attributes -o ./src/assets/keyboard_lightgrey.c
	./gbdk/bin/png2asset ./raw_assets/keyboard_base58.png -map -noflip -tile_origin 0 -b 13 -use_map_attributes -o ./src/assets/keyboard_base58.c
	./gbdk/bin/png2asset ./raw_assets/solcoin.png -tile_origin 202 -b 1 -o ./src/assets/solcoin.c
	./gbdk/bin/png2asset ./raw_assets/sollogo.png -use_map_attributes -map -noflip -tile_origin 0 -b 7 -o ./src/assets/sollogo.c
	./gbdk/bin/png2asset ./raw_assets/offlineonly.png -use_map_attributes -map -noflip -tile_origin 0 -b 7 -o ./src/assets/offlineonly.c
	./gbdk/bin/png2asset ./raw_assets/chksum.png -map -noflip -tile_origin 150 -b 1 -o ./src/assets/chksum.c
	./gbdk/bin/png2asset ./raw_assets/nophotos.png -map -noflip -tile_origin 150 -b 1 -o ./src/assets/nophotos.c

test:
	cd test && make
	python3 test/test_crypto.py 30

# SM83 ROM vs Python. Default is the short crypto checks.
# `make asm-test ADDRESS=1` runs the full address generation.
asm-test:
	python3 test/emu/check.py $(if $(ADDRESS),address,quick)

entropy:
	python3 tools/generate_entropy.py

clean:
	rm -f build/SolGB.gb *.map *.sym *.noi *.ihx *.lk *.adb

postclean:
	rm build/*.asm build/*.lst build/*.o build/*.sym

build/SolGB.gb: $(SRC) build/wallet_sram.o
	$(CC) $(CFLAGS) $(OPTFLAGS) -o $@ $^
	python3 tools/patch_bitrot.py $@

sol: test savedata build/SolGB.gb

all: clean test savedata build/SolGB.gb postclean