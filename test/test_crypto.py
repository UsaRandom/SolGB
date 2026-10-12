#!/usr/bin/env python3
"""
Test script that generates random mnemonics, computes expected addresses,
runs the C app, and compares results for statistical validation.
"""

import subprocess
import sys
import os
import hashlib
import hmac

import base58
from mnemonic import Mnemonic
import nacl.signing

def generate_random_mnemonic():
    """Generate a random 12-word BIP39 mnemonic"""
    mnemo = Mnemonic("english")
    entropy = os.urandom(16)  # 128 bits
    return mnemo.to_mnemonic(entropy)

# Phantom / Solflare default. All four steps are hardened.
SOLANA_PATH = (0x8000002C, 0x800001F5, 0x80000000, 0x80000000)
KNOWN_MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon about"
)
KNOWN_ADDRESS = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"


def slip10_ed25519(seed):
    """SLIP-0010 master and m/44'/501'/0'/0'."""
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    key, chain = digest[:32], digest[32:]
    for index in SOLANA_PATH:
        data = b"\x00" + key + index.to_bytes(4, "big")
        digest = hmac.new(chain, data, hashlib.sha512).digest()
        key, chain = digest[:32], digest[32:]
    return key


def python_mnemonic_to_address(mnemonic):
    """Solana address: base58 of the ed25519 public key. No checksum."""
    seed = Mnemonic("english").to_seed(mnemonic, passphrase="")
    key = slip10_ed25519(seed)
    pub = nacl.signing.SigningKey(key).verify_key.encode()
    return base58.b58encode(pub).decode("ascii")

def c_mnemonic_to_address(mnemonic):
    """Run C app to compute address"""
    try:
        result = subprocess.run(
            ['./test/mnemonic_to_address', mnemonic],
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return result.stdout.strip()
        else:
            print(f"C app failed: {result.stderr}")
            return None
    except subprocess.TimeoutExpired:
        print("C app timed out")
        return None
    except FileNotFoundError:
        print("C app not found - compile it first")
        return None

def main():
    if len(sys.argv) != 2:
        print("Usage: python test_crypto.py <num_tests>")
        sys.exit(1)

    num_tests = int(sys.argv[1])
    passed = 0

    print(f"Running {num_tests} crypto validation tests...")
    print("=" * 50)

    known_py = python_mnemonic_to_address(KNOWN_MNEMONIC)
    known_c = c_mnemonic_to_address(KNOWN_MNEMONIC)
    if known_py != KNOWN_ADDRESS or known_c != KNOWN_ADDRESS:
        print("abandon address mismatch")
        print(f"  python {known_py}")
        print(f"  c      {known_c}")
        print(f"  want   {KNOWN_ADDRESS}")
        return 1
    print(f"abandon address {KNOWN_ADDRESS}")

    for i in range(num_tests):
        # Generate random mnemonic
        mnemonic = generate_random_mnemonic()

        # Compute expected address with Python
        expected = python_mnemonic_to_address(mnemonic)

        # Compute address with C app
        actual = c_mnemonic_to_address(mnemonic)

        if actual is None:
            continue


        if expected == actual:
            passed += 1

    print(f"Results: {passed}/{num_tests} tests passed ({100*passed/num_tests:.1f}%)")

    if passed == num_tests:
        print("✓ All tests passed! Crypto implementation is correct.")
        return 0
    else:
        print("✗ Some tests failed. Check implementation.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
