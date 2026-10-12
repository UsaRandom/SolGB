CC = gcc
CFLAGS = -I. -I.. -I../build -std=c99 -w -DTEST_MODE

# All crypto source files
CRYPTO_SRC = ../src/crypto/mnemonic.c ../src/crypto/hd_wallet.c ../src/crypto/pbkdf2.c \
             ../src/crypto/sha256.c ../src/crypto/sha512.c \
             ../src/crypto/bip39_wordlist.c \
             ../src/crypto/bip39_words_1.c ../src/crypto/bip39_words_2.c \
             ../src/crypto/entropy_data.c \
             ../src/crypto/hmac.c \
             ../src/crypto/sha512_constants.c ../src/crypto/sha512_transform.c \
             ../src/crypto/ed25519.c ../src/crypto/b58.c progress.c ed_base_embed.c

ED_SRC = ../src/crypto/ed25519.c ../src/crypto/sha512.c ../src/crypto/pbkdf2.c \
         ../src/crypto/sha512_constants.c ../src/crypto/sha512_transform.c progress.c \
         ed_base_embed.c

mnemonic_to_address: mnemonic_to_address.c compat.c $(CRYPTO_SRC)
	$(CC) $(CFLAGS) -o $@ $^

ed25519_kat: ed25519_kat.c compat.c $(ED_SRC)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f mnemonic_to_address ed25519_kat

.PHONY: clean
