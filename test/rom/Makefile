# SM83 crypto ROM. Same lcc flags as the wallet, without the UI.
ROOT := ../..
LCC := $(ROOT)/gbdk/bin/lcc

CFLAGS := -msm83:gb \
	-Wl-yt0x1B \
	-Wl-yo512 \
	-Wl-ya1 \
	-Wb-ext=.rel \
	-Wl-m -Wl-j -Wl-w \
	-Wf-DED_TEST_REDUCE \
	-I$(ROOT) \
	-I$(ROOT)/src \
	-I$(ROOT)/src/crypto

CRYPTO := \
	$(ROOT)/src/crypto/pbkdf2.c \
	$(ROOT)/src/crypto/sha512.c \
	$(ROOT)/src/crypto/sha_block.s \
	$(ROOT)/src/crypto/sha512_transform.c \
	$(ROOT)/src/crypto/sha512_constants.c \
	$(ROOT)/src/crypto/hmac.c \
	$(ROOT)/src/crypto/hd_wallet.c \
	$(ROOT)/src/crypto/ed25519.c \
	$(ROOT)/src/crypto/ed_base.c \
	$(ROOT)/src/crypto/ed_base_lo.s \
	$(ROOT)/src/crypto/ed_base_hi.s \
	$(ROOT)/src/crypto/bn_mul.s \
	$(ROOT)/src/crypto/mul_tables.s \
	$(ROOT)/src/crypto/b58.c

OUTDIR := build
ROM := $(OUTDIR)/crypto_test.gb

.PHONY: all clean

all: $(ROM)

$(ROM): main.c progress_stub.c $(CRYPTO)
	mkdir -p $(OUTDIR)
	$(LCC) $(CFLAGS) -o $@ main.c progress_stub.c $(CRYPTO)
	python3 $(ROOT)/tools/patch_bitrot.py $@

clean:
	rm -rf $(OUTDIR)
	rm -f *.rel *.asm *.lst *.sym *.noi *.map *.ihx *.adb *.cdb *.rst *.lk
