#!/usr/bin/env python3
"""Fixed-base Ed25519 table for the Game Boy.

base[i][j] = (j + 1) * 256^i * B, stored as (y+x, y-x, 2*d*x*y).
Each field element is 32 bytes, big-endian, fully reduced.
Positions 0..15 fill bank 18. Positions 16..31 fill bank 19.
The byte field here is the same reduction the ROM uses.
"""

import hashlib
from pathlib import Path

import nacl.signing

ROOT = Path(__file__).resolve().parents[1]
CRYPTO = ROOT / "src" / "crypto"

P = 2**255 - 19
D = (-121665 * pow(121666, -1, P)) % P
P_BYTES = P.to_bytes(32, "big")


def enc(n):
    return n.to_bytes(32, "big")


def dec(b):
    return int.from_bytes(b, "big")


def sub_p(a):
    if a < P_BYTES:
        return a
    br = 0
    out = bytearray(32)
    for i in range(31, -1, -1):
        diff = a[i] - P_BYTES[i] - br
        if diff < 0:
            diff += 256
            br = 1
        else:
            br = 0
        out[i] = diff
    return bytes(out)


def fe_fold(raw):
    """64-byte big-endian product -> 32-byte field element."""
    o = [0] * 32
    c = 0
    for i in range(32):
        v = raw[63 - i] + 38 * raw[31 - i] + c
        o[31 - i] = v & 255
        c = v >> 8
    extra = 38 * c
    c2 = 0
    for i in range(31, -1, -1):
        v = o[i] + (extra & 255) + c2
        o[i] = v & 255
        c2 = v >> 8
        extra >>= 8
    if c2:
        extra = 38
        c2 = 0
        for i in range(31, -1, -1):
            v = o[i] + (extra & 255) + c2
            o[i] = v & 255
            c2 = v >> 8
            extra >>= 8
        if c2:
            raise SystemExit("fold carried twice")
    o = bytes(o)
    o = sub_p(o)
    o = sub_p(o)
    if o >= P_BYTES:
        raise SystemExit("fold still >= p")
    return o


def mul_be(a, b):
    prod = [0] * 64
    for i in range(31, -1, -1):
        carry = 0
        for j in range(31, -1, -1):
            sum_ = prod[i + j + 1] + a[i] * b[j] + carry
            prod[i + j + 1] = sum_ & 255
            carry = sum_ >> 8
        k = i
        while k >= 0:
            sum_ = prod[k] + carry
            prod[k] = sum_ & 255
            carry = sum_ >> 8
            if carry == 0:
                break
            k -= 1
    return bytes(prod)


def fe_add(a, b):
    tmp = [0] * 32
    c = 0
    for i in range(31, -1, -1):
        c = c + a[i] + b[i]
        tmp[i] = c & 255
        c >>= 8
    if c:
        extra = 38 * c
        c2 = 0
        for i in range(31, -1, -1):
            c2 = tmp[i] + (extra & 255) + c2
            tmp[i] = c2 & 255
            c2 >>= 8
            extra >>= 8
    o = sub_p(bytes(tmp))
    o = sub_p(o)
    return o


def ge_bytes(a, b):
    return a >= b


def fe_sub(a, b):
    if ge_bytes(a, b):
        br = 0
        tmp = [0] * 32
        for i in range(31, -1, -1):
            diff = a[i] - b[i] - br
            if diff < 0:
                diff += 256
                br = 1
            else:
                br = 0
            tmp[i] = diff
        return bytes(tmp)
    br = 0
    diffb = [0] * 32
    for i in range(31, -1, -1):
        diff = b[i] - a[i] - br
        if diff < 0:
            diff += 256
            br = 1
        else:
            br = 0
        diffb[i] = diff
    br = 0
    tmp = [0] * 32
    for i in range(31, -1, -1):
        diff = P_BYTES[i] - diffb[i] - br
        if diff < 0:
            diff += 256
            br = 1
        else:
            br = 0
        tmp[i] = diff
    return bytes(tmp)


def fe0():
    return bytes(32)


def fe1():
    return bytes(31) + bytes([1])


TICKS = 0


def fe_mul(a, b):
    global TICKS
    TICKS += 1
    return fe_fold(mul_be(a, b))


def fe_sq(a):
    return fe_mul(a, a)


def fe_sq2(a):
    s = fe_sq(a)
    return fe_add(s, s)


def check_field():
    samples = [0, 1, 2, P - 1, P - 2, 2**200, 2**254 - 19, 123456789]
    for a in samples:
        for b in samples:
            aa, bb = enc(a), enc(b)
            if dec(fe_fold(mul_be(aa, bb))) != (a * b) % P:
                raise SystemExit(f"mul {a}*{b}")
            if dec(fe_add(aa, bb)) != (a + b) % P:
                raise SystemExit(f"add {a}+{b}")
            if dec(fe_sub(aa, bb)) != (a - b) % P:
                raise SystemExit(f"sub {a}-{b}")
    z = enc(2**200 + 7)
    got = dec(fe_invert(z))
    if got != pow(dec(z), P - 2, P):
        raise SystemExit("invert")


def fe_invert(z):
    t0 = fe_sq(z)
    t1 = fe_sq(t0)
    t1 = fe_sq(t1)
    t1 = fe_mul(z, t1)
    t0 = fe_mul(t0, t1)
    t2 = fe_sq(t0)
    t1 = fe_mul(t1, t2)
    t2 = fe_sq(t1)
    for _ in range(4):
        t2 = fe_sq(t2)
    t1 = fe_mul(t2, t1)
    t2 = fe_sq(t1)
    for _ in range(9):
        t2 = fe_sq(t2)
    t2 = fe_mul(t2, t1)
    t3 = fe_sq(t2)
    for _ in range(19):
        t3 = fe_sq(t3)
    t2 = fe_mul(t3, t2)
    t2 = fe_sq(t2)
    for _ in range(9):
        t2 = fe_sq(t2)
    t1 = fe_mul(t2, t1)
    t2 = fe_sq(t1)
    for _ in range(49):
        t2 = fe_sq(t2)
    t2 = fe_mul(t2, t1)
    t3 = fe_sq(t2)
    for _ in range(99):
        t3 = fe_sq(t3)
    t2 = fe_mul(t3, t2)
    t2 = fe_sq(t2)
    for _ in range(49):
        t2 = fe_sq(t2)
    t1 = fe_mul(t2, t1)
    t1 = fe_sq(t1)
    for _ in range(4):
        t1 = fe_sq(t1)
    return fe_mul(t1, t0)


def fe_tobytes(h):
    return bytes(reversed(h))


def fe_isneg(h):
    return h[31] & 1


class P3:
    def __init__(self):
        self.X = fe0()
        self.Y = fe1()
        self.Z = fe1()
        self.T = fe0()


class P2:
    def __init__(self):
        self.X = fe0()
        self.Y = fe0()
        self.Z = fe0()


class P1:
    def __init__(self):
        self.X = fe0()
        self.Y = fe0()
        self.Z = fe0()
        self.T = fe0()


class Pre:
    def __init__(self):
        self.yplusx = fe1()
        self.yminusx = fe1()
        self.xy2d = fe0()


def ge_madd(p, q):
    r = P1()
    r.X = fe_add(p.Y, p.X)
    r.Y = fe_sub(p.Y, p.X)
    r.Z = fe_mul(r.X, q.yplusx)
    r.Y = fe_mul(r.Y, q.yminusx)
    r.T = fe_mul(q.xy2d, p.T)
    t0 = fe_add(p.Z, p.Z)
    r.X = fe_sub(r.Z, r.Y)
    r.Y = fe_add(r.Z, r.Y)
    r.Z = fe_add(t0, r.T)
    r.T = fe_sub(t0, r.T)
    return r


def to_p2(p):
    r = P2()
    r.X = fe_mul(p.X, p.T)
    r.Y = fe_mul(p.Y, p.Z)
    r.Z = fe_mul(p.Z, p.T)
    return r


def to_p3(p):
    r = P3()
    r.X = fe_mul(p.X, p.T)
    r.Y = fe_mul(p.Y, p.Z)
    r.Z = fe_mul(p.Z, p.T)
    r.T = fe_mul(p.X, p.Y)
    return r


def p2_dbl(p):
    r = P1()
    r.X = fe_sq(p.X)
    r.Z = fe_sq(p.Y)
    r.T = fe_sq2(p.Z)
    r.Y = fe_add(p.X, p.Y)
    t0 = fe_sq(r.Y)
    r.Y = fe_add(r.Z, r.X)
    r.Z = fe_sub(r.Z, r.X)
    r.X = fe_sub(t0, r.Y)
    r.T = fe_sub(r.T, r.Z)
    return r


def p3_dbl(p):
    q = P2()
    q.X, q.Y, q.Z = p.X, p.Y, p.Z
    return p2_dbl(q)


def pack(h):
    recip = fe_invert(h.Z)
    x = fe_mul(h.X, recip)
    y = fe_mul(h.Y, recip)
    out = bytearray(fe_tobytes(y))
    out[31] ^= fe_isneg(x) << 7
    return bytes(out)


def base_point():
    y = (4 * pow(5, -1, P)) % P
    x2 = ((y * y - 1) * pow(D * y * y + 1, -1, P)) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x) % P != x2:
        x = (x * pow(2, (P - 1) // 4, P)) % P
    if x & 1:
        x = P - x
    if (x * x) % P != x2:
        raise SystemExit("base x")
    if (-x * x + y * y - 1 - D * x * x * y * y) % P:
        raise SystemExit("base curve")
    return x, y


def ed_add(p1, p2):
    x1, y1 = p1
    x2, y2 = p2
    dxy = (D * x1 * x2 * y1 * y2) % P
    x3 = ((x1 * y2 + y1 * x2) * pow(1 + dxy, -1, P)) % P
    y3 = ((y1 * y2 + x1 * x2) * pow(1 - dxy, -1, P)) % P
    return x3, y3


def precomp_of(pt):
    x, y = pt
    return enc((y + x) % P), enc((y - x) % P), enc((2 * D * x * y) % P)


def build_table(b):
    table = []
    point = b
    for _i in range(32):
        row = []
        acc = point
        for _j in range(8):
            row.append(precomp_of(acc))
            acc = ed_add(acc, point)
        table.append(row)
        for _ in range(8):
            point = ed_add(point, point)
    return table


def select(table, pos, digit):
    t = Pre()
    if digit < 0:
        absd = -digit
        neg = True
    else:
        absd = digit
        neg = False
    if absd:
        ypx, ymx, xy = table[pos][absd - 1]
        t.yplusx, t.yminusx, t.xy2d = ypx, ymx, xy
    if neg:
        t.yplusx, t.yminusx = t.yminusx, t.yplusx
        t.xy2d = fe_sub(fe0(), t.xy2d)
    return t


def scalarbase(table, scalar):
    e = [0] * 64
    for i in range(32):
        e[2 * i] = scalar[i] & 15
        e[2 * i + 1] = (scalar[i] >> 4) & 15
    carry = 0
    for i in range(63):
        e[i] += carry
        carry = (e[i] + 8) >> 4
        e[i] -= carry << 4
    e[63] += carry
    h = P3()
    for i in range(1, 64, 2):
        t = select(table, i // 2, e[i])
        h = to_p3(ge_madd(h, t))
    r = p3_dbl(h)
    s = to_p2(r)
    r = p2_dbl(s)
    s = to_p2(r)
    r = p2_dbl(s)
    s = to_p2(r)
    r = p2_dbl(s)
    h = to_p3(r)
    for i in range(0, 64, 2):
        t = select(table, i // 2, e[i])
        h = to_p3(ge_madd(h, t))
    return pack(h)


def pubkey(table, seed):
    h = hashlib.sha512(seed).digest()
    a = bytearray(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    return scalarbase(table, bytes(a))


def write_host(path, blob):
    lines = [
        "/* Generated by tools/gen_ed_base.py. Host stand-in for the ROM table. */",
        "#include <stdint.h>",
        "#include <string.h>",
        "",
        "static const uint8_t ed_base_all[24576] = {",
    ]
    for off in range(0, len(blob), 16):
        chunk = blob[off:off + 16]
        lines.append("    " + ", ".join(f"0x{b:02X}" for b in chunk) + ",")
    lines.append("};")
    lines.append("")
    lines.append("void ed_base_select(uint8_t dest[96], uint8_t pos, uint8_t digit_abs) {")
    lines.append("    uint8_t k, i;")
    lines.append("    const uint8_t *row;")
    lines.append("    memset(dest, 0, 96);")
    lines.append("    dest[31] = 1;")
    lines.append("    dest[63] = 1;")
    lines.append("    if (digit_abs == 0 || digit_abs > 8 || pos > 31) return;")
    lines.append("    row = ed_base_all + (unsigned)pos * 768u;")
    lines.append("    for (k = 1; k <= 8; k++) {")
    lines.append("        uint8_t m = (uint8_t)-(digit_abs == k);")
    lines.append("        const uint8_t *src = row + (unsigned)(k - 1u) * 96u;")
    lines.append("        for (i = 0; i < 96; i++) dest[i] ^= (uint8_t)(m & (dest[i] ^ src[i]));")
    lines.append("    }")
    lines.append("}")
    lines.append("")
    path.write_text("\n".join(lines))


def write_bank(path, module, area, symbol, blob):
    lines = [
        f"        .module {module}",
        f"        .area {area}",
        "",
        "        ; Generated by tools/gen_ed_base.py. Do not edit by hand.",
        "        ; (y+x, y-x, 2*d*x*y) for (j+1)*256^i*B, big-endian.",
        "",
        f"        .globl _{symbol}",
        f"_{symbol}::",
    ]
    for off in range(0, len(blob), 16):
        chunk = blob[off:off + 16]
        lines.append("        .db " + ", ".join(f"0x{b:02X}" for b in chunk))
    lines.append("")
    path.write_text("\n".join(lines))


def main():
    global TICKS
    check_field()
    b = base_point()
    packed = bytearray(enc(b[1])[::-1])
    if b[0] & 1:
        packed[31] |= 0x80
    expect = bytes.fromhex("58" + "66" * 31)
    if bytes(packed) != expect:
        raise SystemExit(f"base pack {packed.hex()}")
    table = build_table(b)
    # One public key, then the tick count is the bar's curve budget.
    TICKS = 0
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    got = pubkey(table, seed)
    want = nacl.signing.SigningKey(seed).verify_key.encode()
    if got != want:
        raise SystemExit(f"rfc {got.hex()} != {want.hex()}")
    print(f"rfc ok, field ops {TICKS}")
    for n in (1, 2, 7, 9):
        trial = bytes([n]) + bytes(31)
        got = nacl.signing.SigningKey(trial).verify_key.encode()
        if pubkey(table, trial) != got:
            raise SystemExit(f"seed {n} mismatch")
    lo = bytearray()
    hi = bytearray()
    for pos, row in enumerate(table):
        raw = b"".join(ypx + ymx + xy for ypx, ymx, xy in row)
        if len(raw) != 768:
            raise SystemExit("row size")
        if pos < 16:
            lo += raw
        else:
            hi += raw
    if len(lo) != 12288 or len(hi) != 12288:
        raise SystemExit("table size")
    write_bank(CRYPTO / "ed_base_lo.s", "ed_base_lo", "_CODE_18", "ed_base_lo", lo)
    write_bank(CRYPTO / "ed_base_hi.s", "ed_base_hi", "_CODE_19", "ed_base_hi", hi)
    write_host(ROOT / "test" / "ed_base_embed.c", lo + hi)
    print("wrote ed_base_lo.s, ed_base_hi.s, and test/ed_base_embed.c")


if __name__ == "__main__":
    main()
