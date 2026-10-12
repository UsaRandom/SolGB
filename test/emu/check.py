#!/usr/bin/env python3
"""Run the SM83 crypto ROM and compare it to Python.

The ROM is the same GBDK compile of the wallet crypto, with no UI.
Peanut-GB runs it with the LCD and audio compiled out, so a test takes
as long as the CPU math takes on this machine. gbc_sec in the harness
output is an estimate of Game Boy Color double-speed time.

Quick checks (seconds):

    python3 test/emu/check.py

The full address generation (about 10 minutes on GBC: the 2048 SHA-512
rounds, then the ed25519 public key):

    python3 test/emu/check.py address
"""

import hashlib
import hmac
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROM_DIR = ROOT / "test" / "rom"
EMU_DIR = ROOT / "test" / "emu"
RUNNER = EMU_DIR / "build" / "run_crypto_test"
ROM = ROM_DIR / "build" / "crypto_test.gb"
NOI = ROM_DIR / "build" / "crypto_test.noi"

MNEMONIC = (
    "abandon abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon about"
)

# Vector pinned in src/progress.c. SLIP-0010 m/44'/501'/0'/0'.
KNOWN_ADDRESS = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
RFC_PUB = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def build():
    subprocess.check_call(["make", "-C", str(ROM_DIR)])
    subprocess.check_call(["make", "-C", str(EMU_DIR)])


def run_rom(test_id, timeout):
    proc = subprocess.run(
        [str(RUNNER), str(ROM), str(NOI), str(test_id), str(timeout)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=None,
    )
    fields = {}
    for line in proc.stdout.splitlines():
        key, _, value = line.partition(" ")
        fields[key] = value
    fields["_returncode"] = proc.returncode
    return fields


def expect_hex(fields, expected, label):
    got = fields.get("hex", "")
    gbc = fields.get("gbc_sec", "?")
    host = fields.get("host_sec", "?")
    frames = fields.get("frames", "?")
    print(f"{label}: host {host}s, gbc est {gbc}s, frames {frames}")
    if fields.get("ok") != "1" or got != expected:
        print(f"  got  {got}")
        print(f"  want {expected}")
        print(f"  runner status {fields.get('status')} exit {fields.get('_returncode')}")
        return False
    print("  match")
    return True


def python_address(mnemonic):
    import base58
    from mnemonic import Mnemonic
    import nacl.signing

    seed = Mnemonic("english").to_seed(mnemonic, passphrase="")
    digest = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    key, chain = digest[:32], digest[32:]
    for index in (0x8000002C, 0x800001F5, 0x80000000, 0x80000000):
        data = b"\x00" + key + index.to_bytes(4, "big")
        digest = hmac.new(chain, data, hashlib.sha512).digest()
        key, chain = digest[:32], digest[32:]
    pubkey = nacl.signing.SigningKey(key).verify_key.encode()
    address = base58.b58encode(pubkey).decode("ascii")
    return address, seed, pubkey


def check_sha512():
    expected = hashlib.sha512(b"abc").hexdigest()
    return expect_hex(run_rom(1, 60), expected, "sha512 abc")


def check_ed25519():
    return expect_hex(run_rom(2, 300), RFC_PUB, "ed25519 pubkey")


def check_pbkdf2_once():
    expected = hashlib.pbkdf2_hmac("sha512", MNEMONIC.encode(), b"mnemonic", 1).hex()
    return expect_hex(run_rom(3, 120), expected, "pbkdf2 x1")


def check_address():
    address, seed, pubkey = python_address(MNEMONIC)
    if address != KNOWN_ADDRESS:
        print("python reference does not match the pinned abandon address")
        print(address)
        return False

    fields = run_rom(4, 7200)
    raw = bytes.fromhex(fields.get("hex", ""))
    if fields.get("ok") != "1" or len(raw) < 141:
        print(f"address run failed status {fields.get('status')} len {len(raw)}")
        return False

    got = raw[0:45].split(b"\x00", 1)[0].decode()
    got_seed = raw[45:109]
    got_pub = raw[109:141]
    gbc = float(fields.get("gbc_sec", "nan"))
    host = fields.get("host_sec", "?")
    print(f"address: host {host}s, gbc est {gbc / 60:.1f} min, frames {fields.get('frames')}")
    ok = True
    if got != KNOWN_ADDRESS:
        print(f"  address got  {got}")
        print(f"  address want {KNOWN_ADDRESS}")
        ok = False
    else:
        print(f"  address {got}")
    if got_seed != seed:
        print("  seed mismatch")
        ok = False
    if got_pub != pubkey:
        print("  pubkey mismatch")
        ok = False
    return ok


def main():
    which = sys.argv[1] if len(sys.argv) > 1 else "quick"
    build()
    if which == "address":
        tests = [check_address]
    elif which == "quick":
        tests = [check_sha512, check_ed25519, check_pbkdf2_once]
    elif which == "all":
        tests = [check_sha512, check_ed25519, check_pbkdf2_once, check_address]
    else:
        print("usage: check.py [quick|address|all]")
        return 1

    failed = 0
    for test in tests:
        if not test():
            failed += 1
    if failed:
        print(f"{failed} failed")
        return 1
    print("all matched")
    return 0


if __name__ == "__main__":
    sys.exit(main())
