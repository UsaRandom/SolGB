#pragma bank 16

#include "ed25519.h"
#include "ed_base.h"
#include "sha512.h"
#include "pbkdf2.h"
#include "progress.h"
#include <string.h>

/* Field elements are 32 bytes, big-endian, reduced mod 2^255-19.
   The multiply is the ROM product table (bn_mul256_asm). A public
   key is the ref10 fixed-base schedule: 64 mixed adds and 4 doubles,
   not a 256-step ladder. One field multiply moves the bar. */

typedef struct { uint8_t X[32], Y[32], Z[32], T[32]; } ge_p3;
typedef struct { uint8_t X[32], Y[32], Z[32], T[32]; } ge_p1p1;
typedef struct { uint8_t X[32], Y[32], Z[32]; } ge_p2;
typedef struct { uint8_t yplusx[32], yminusx[32], xy2d[32]; } ge_precomp;

typedef struct {
    ge_p3 h;
    ge_p1p1 r;
    ge_p2 s;
    ge_p2 q;
    ge_precomp pc;
    uint8_t k0[32];
    uint8_t i0[32];
    uint8_t i1[32];
    uint8_t i2[32];
    uint8_t i3[32];
} EdWork;

static EdWork *W;

static const uint8_t P25519[32] = {
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed
};

static const uint8_t L[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
    0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
};

#ifdef __SDCC
extern uint8_t *bn_mul_pa;
extern uint8_t *bn_mul_pb;
extern uint8_t bn_mul_prod[64];
extern uint8_t bn_saved_bank;
void bn_mul256_asm(void);
void bn_sqr256_asm(void);
#endif

static int64_t asr64(int64_t x, uint8_t n) {
    if (x >= 0) return x >> n;
    return (int64_t)~((uint64_t)~(uint64_t)x >> n);
}

static int64_t mul32u(uint32_t a, uint32_t b) {
    uint16_t al = (uint16_t)a;
    uint16_t ah = (uint16_t)(a >> 16);
    uint16_t bl = (uint16_t)b;
    uint16_t bh = (uint16_t)(b >> 16);
    uint32_t p0 = (uint32_t)al * (uint32_t)bl;
    uint32_t p1 = (uint32_t)al * (uint32_t)bh;
    uint32_t p2 = (uint32_t)ah * (uint32_t)bl;
    uint32_t p3 = (uint32_t)ah * (uint32_t)bh;
    uint32_t mid = (p0 >> 16) + (p1 & 0xffffu) + (p2 & 0xffffu);
    uint32_t lo = (p0 & 0xffffu) | ((mid & 0xffffu) << 16);
    uint32_t hi = p3 + (p1 >> 16) + (p2 >> 16) + (mid >> 16);
    return ((int64_t)hi << 32) | (int64_t)lo;
}

static int64_t mul32s(int32_t a, int32_t b) {
    int64_t p = mul32u((uint32_t)a, (uint32_t)b);
    if (a < 0) p -= (int64_t)(uint32_t)b << 32;
    if (b < 0) p -= (int64_t)(uint32_t)a << 32;
    return p;
}

static int64_t mul64(int64_t a, int64_t b) {
    uint32_t al = (uint32_t)a;
    uint32_t bl = (uint32_t)b;
    uint32_t ah = (uint32_t)asr64(a, 32);
    uint32_t bh = (uint32_t)asr64(b, 32);
    uint32_t cross = (uint32_t)mul32u(al, bh) + (uint32_t)mul32u(ah, bl);
    return mul32u(al, bl) + ((int64_t)cross << 32);
}

static void fe_0(uint8_t *o) { memset(o, 0, 32); }

static void fe_1(uint8_t *o) {
    fe_0(o);
    o[31] = 1;
}

static void fe_copy(uint8_t *o, const uint8_t *a) { memcpy(o, a, 32); }

static uint8_t ge_bytes(const uint8_t *a, const uint8_t *b) {
    uint8_t i;
    for (i = 0; i < 32; i++) {
        if (a[i] != b[i]) return (uint8_t)(a[i] > b[i]);
    }
    return 1;
}

static void sub_p(uint8_t *a) {
    int i;
    int16_t br;
    if (!ge_bytes(a, P25519)) return;
    br = 0;
    for (i = 31; i >= 0; i--) {
        int16_t d = (int16_t)a[i] - (int16_t)P25519[i] - br;
        if (d < 0) { d += 256; br = 1; }
        else br = 0;
        a[i] = (uint8_t)d;
    }
}

static void fe_fold(uint8_t *o, const uint8_t *raw) {
    uint16_t c = 0;
    uint16_t extra;
    uint16_t c2;
    int i;
    for (i = 0; i < 32; i++) {
        uint16_t v = (uint16_t)raw[63 - i] + (uint16_t)(38u * raw[31 - i]) + c;
        o[31 - i] = (uint8_t)v;
        c = (uint16_t)(v >> 8);
    }
    extra = (uint16_t)(38u * c);
    c2 = 0;
    for (i = 31; i >= 0; i--) {
        uint16_t v = (uint16_t)o[i] + (extra & 255u) + c2;
        o[i] = (uint8_t)v;
        c2 = (uint16_t)(v >> 8);
        extra >>= 8;
    }
    if (c2) {
        extra = 38;
        c2 = 0;
        for (i = 31; i >= 0; i--) {
            uint16_t v = (uint16_t)o[i] + (extra & 255u) + c2;
            o[i] = (uint8_t)v;
            c2 = (uint16_t)(v >> 8);
            extra >>= 8;
        }
    }
    sub_p(o);
    sub_p(o);
}

#ifndef __SDCC
static void mul_be(uint8_t prod[64], const uint8_t *a, const uint8_t *b) {
    int i, j, k;
    memset(prod, 0, 64);
    for (i = 31; i >= 0; i--) {
        uint32_t carry = 0;
        for (j = 31; j >= 0; j--) {
            uint32_t sum = (uint32_t)prod[i + j + 1] + (uint32_t)a[i] * b[j] + carry;
            prod[i + j + 1] = (uint8_t)sum;
            carry = sum >> 8;
        }
        k = i;
        while (k >= 0) {
            uint32_t sum = (uint32_t)prod[k] + carry;
            prod[k] = (uint8_t)sum;
            carry = sum >> 8;
            if (carry == 0) break;
            k--;
        }
    }
}
#endif

static void fe_mul(uint8_t *o, const uint8_t *a, const uint8_t *b) {
    uint8_t tmp[32];
#ifdef __SDCC
    bn_mul_pa = (uint8_t *)a;
    bn_mul_pb = (uint8_t *)b;
    bn_saved_bank = _current_bank;
    bn_mul256_asm();
    fe_fold(tmp, bn_mul_prod);
#else
    uint8_t prod[64];
    mul_be(prod, a, b);
    fe_fold(tmp, prod);
#endif
    memcpy(o, tmp, 32);
    add_progress(WEIGHT_ED_MUL);
}

static void fe_sq(uint8_t *o, const uint8_t *a) {
    uint8_t tmp[32];
#ifdef __SDCC
    bn_mul_pa = (uint8_t *)a;
    bn_saved_bank = _current_bank;
    bn_sqr256_asm();
    fe_fold(tmp, bn_mul_prod);
#else
    uint8_t prod[64];
    mul_be(prod, a, a);
    fe_fold(tmp, prod);
#endif
    memcpy(o, tmp, 32);
    add_progress(WEIGHT_ED_MUL);
}

static void fe_add(uint8_t *o, const uint8_t *a, const uint8_t *b) {
    uint8_t tmp[32];
    uint16_t c = 0;
    int i;
    for (i = 31; i >= 0; i--) {
        c = (uint16_t)(c + a[i] + b[i]);
        tmp[i] = (uint8_t)c;
        c >>= 8;
    }
    if (c) {
        uint16_t extra = (uint16_t)(38u * c);
        uint16_t c2 = 0;
        for (i = 31; i >= 0; i--) {
            c2 = (uint16_t)(tmp[i] + (extra & 255u) + c2);
            tmp[i] = (uint8_t)c2;
            c2 >>= 8;
            extra >>= 8;
        }
    }
    sub_p(tmp);
    sub_p(tmp);
    memcpy(o, tmp, 32);
}

static void fe_sub(uint8_t *o, const uint8_t *a, const uint8_t *b) {
    uint8_t tmp[32];
    int i;
    int16_t br = 0;
    if (ge_bytes(a, b)) {
        for (i = 31; i >= 0; i--) {
            int16_t d = (int16_t)a[i] - (int16_t)b[i] - br;
            if (d < 0) { d += 256; br = 1; }
            else br = 0;
            tmp[i] = (uint8_t)d;
        }
    } else {
        uint8_t diff[32];
        for (i = 31; i >= 0; i--) {
            int16_t d = (int16_t)b[i] - (int16_t)a[i] - br;
            if (d < 0) { d += 256; br = 1; }
            else br = 0;
            diff[i] = (uint8_t)d;
        }
        br = 0;
        for (i = 31; i >= 0; i--) {
            int16_t d = (int16_t)P25519[i] - (int16_t)diff[i] - br;
            if (d < 0) { d += 256; br = 1; }
            else br = 0;
            tmp[i] = (uint8_t)d;
        }
    }
    memcpy(o, tmp, 32);
}

static void fe_sq2(uint8_t *o, const uint8_t *a) {
    fe_sq(o, a);
    fe_add(o, o, o);
}

static void fe_invert(uint8_t *out, const uint8_t *z) {
    uint8_t *t0 = W->i0;
    uint8_t *t1 = W->i1;
    uint8_t *t2 = W->i2;
    uint8_t *t3 = W->i3;
    uint8_t i;

    fe_sq(t0, z);
    fe_sq(t1, t0);
    fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0);
    fe_mul(t1, t1, t2);
    fe_sq(t2, t1);
    for (i = 1; i < 5; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (i = 1; i < 20; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (i = 1; i < 100; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 1; i < 5; i++) fe_sq(t1, t1);
    fe_mul(out, t1, t0);
}

static void fe_tobytes(uint8_t *s, const uint8_t *h) {
    uint8_t i;
    for (i = 0; i < 32; i++) s[i] = h[31 - i];
}

static uint8_t fe_isneg(const uint8_t *h) {
    return (uint8_t)(h[31] & 1u);
}

static void ge_p3_0(ge_p3 *h) {
    fe_0(h->X);
    fe_1(h->Y);
    fe_1(h->Z);
    fe_0(h->T);
}

static void ge_madd(ge_p1p1 *r, const ge_p3 *p, const ge_precomp *q) {
    fe_add(r->X, p->Y, p->X);
    fe_sub(r->Y, p->Y, p->X);
    fe_mul(r->Z, r->X, q->yplusx);
    fe_mul(r->Y, r->Y, q->yminusx);
    fe_mul(r->T, q->xy2d, p->T);
    fe_add(W->k0, p->Z, p->Z);
    fe_sub(r->X, r->Z, r->Y);
    fe_add(r->Y, r->Z, r->Y);
    fe_add(r->Z, W->k0, r->T);
    fe_sub(r->T, W->k0, r->T);
}

static void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
}

static void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p) {
    fe_mul(r->X, p->X, p->T);
    fe_mul(r->Y, p->Y, p->Z);
    fe_mul(r->Z, p->Z, p->T);
    fe_mul(r->T, p->X, p->Y);
}

static void ge_p2_dbl(ge_p1p1 *r, const ge_p2 *p) {
    fe_sq(r->X, p->X);
    fe_sq(r->Z, p->Y);
    fe_sq2(r->T, p->Z);
    fe_add(r->Y, p->X, p->Y);
    fe_sq(W->k0, r->Y);
    fe_add(r->Y, r->Z, r->X);
    fe_sub(r->Z, r->Z, r->X);
    fe_sub(r->X, W->k0, r->Y);
    fe_sub(r->T, r->T, r->Z);
}

static void ge_p3_dbl(ge_p1p1 *r, const ge_p3 *p) {
    fe_copy(W->q.X, p->X);
    fe_copy(W->q.Y, p->Y);
    fe_copy(W->q.Z, p->Z);
    ge_p2_dbl(r, &W->q);
}

static void precomp_neg(ge_precomp *p) {
    uint8_t tmp[32];
    memcpy(tmp, p->yplusx, 32);
    memcpy(p->yplusx, p->yminusx, 32);
    memcpy(p->yminusx, tmp, 32);
    fe_0(W->k0);
    fe_sub(p->xy2d, W->k0, p->xy2d);
}

static void ge_pack(uint8_t *out, const ge_p3 *h) {
    fe_invert(W->i0, h->Z);
    fe_mul(W->i1, h->X, W->i0);
    fe_mul(W->i2, h->Y, W->i0);
    fe_tobytes(out, W->i2);
    out[31] ^= (uint8_t)(fe_isneg(W->i1) << 7);
}

static void scalarbase(uint8_t out[32], const uint8_t scalar[32]) {
    int8_t e[64];
    int8_t carry;
    uint8_t i;
    uint8_t absd;

#ifndef TEST_MODE
    __asm__("di");
#endif
    for (i = 0; i < 32; i++) {
        e[2 * i] = (int8_t)(scalar[i] & 15);
        e[2 * i + 1] = (int8_t)((scalar[i] >> 4) & 15);
    }
    carry = 0;
    for (i = 0; i < 63; i++) {
        e[i] = (int8_t)(e[i] + carry);
        carry = (int8_t)((e[i] + 8) >> 4);
        e[i] = (int8_t)(e[i] - (int8_t)(carry << 4));
    }
    e[63] = (int8_t)(e[63] + carry);

    ge_p3_0(&W->h);
    for (i = 1; i < 64; i = (uint8_t)(i + 2)) {
        absd = (uint8_t)(e[i] < 0 ? -e[i] : e[i]);
        ed_base_select(W->pc.yplusx, (uint8_t)(i / 2), absd);
        if (e[i] < 0) precomp_neg(&W->pc);
        ge_madd(&W->r, &W->h, &W->pc);
        ge_p1p1_to_p3(&W->h, &W->r);
    }
    ge_p3_dbl(&W->r, &W->h);
    ge_p1p1_to_p2(&W->s, &W->r);
    ge_p2_dbl(&W->r, &W->s);
    ge_p1p1_to_p2(&W->s, &W->r);
    ge_p2_dbl(&W->r, &W->s);
    ge_p1p1_to_p2(&W->s, &W->r);
    ge_p2_dbl(&W->r, &W->s);
    ge_p1p1_to_p3(&W->h, &W->r);
    for (i = 0; i < 64; i = (uint8_t)(i + 2)) {
        absd = (uint8_t)(e[i] < 0 ? -e[i] : e[i]);
        ed_base_select(W->pc.yplusx, (uint8_t)(i / 2), absd);
        if (e[i] < 0) precomp_neg(&W->pc);
        ge_madd(&W->r, &W->h, &W->pc);
        ge_p1p1_to_p3(&W->h, &W->r);
    }
    ge_pack(out, &W->h);
}

static void modL(uint8_t *r, int64_t x[64]) {
    int i;
    int j;
    for (i = 63; i >= 32; i--) {
        int64_t carry = 0;
        for (j = i - 32; j < i - 12; j++) {
            x[j] += carry - mul64(x[i], (int64_t)(16 * (int)L[j - (i - 32)]));
            carry = asr64(x[j] + 128, 8);
            x[j] -= carry << 8;
        }
        x[j] += carry;
        x[i] = 0;
    }
    {
        int64_t carry = 0;
        for (j = 0; j < 32; j++) {
            x[j] += carry - mul64(asr64(x[31], 4), (int64_t)L[j]);
            carry = asr64(x[j], 8);
            x[j] &= 255;
        }
        for (j = 0; j < 32; j++) x[j] -= mul64(carry, (int64_t)L[j]);
    }
    for (i = 0; i < 32; i++) {
        x[i + 1] += asr64(x[i], 8);
        r[i] = (uint8_t)(x[i] & 255);
    }
}

static void reduce(uint8_t r[64]) {
    int64_t *x = (int64_t *)W;
    uint8_t i;
    for (i = 0; i < 64u; i++) x[i] = r[i];
    memset(r, 0, 64);
    modL(r, x);
}

static uint8_t ed_begin(void) {
    uint16_t len = 0;
    uint8_t *p = kdf_scratch(&len);
    if (!p || len < sizeof(EdWork) || len < 64u * sizeof(int64_t)) return 0u;
    memset(p, 0, len);
    W = (EdWork *)p;
    return 1u;
}

static void ed_wipe(void) {
    uint16_t len = 0;
    uint8_t *p = kdf_scratch(&len);
    if (p && len) memset(p, 0, len);
    W = 0;
}

static void clamp(uint8_t d[32]) {
    d[0] &= 248;
    d[31] &= 127;
    d[31] |= 64;
}

void ed25519_public(const uint8_t seed[32], uint8_t pub[32]) BANKED {
    SHA512_CTX ctx;
    uint8_t d[64];

    memset(pub, 0, 32);
    if (!ed_begin()) return;
    sha512_init(&ctx);
    sha512_update(&ctx, seed, 32);
    sha512_final(&ctx, d);
    clamp(d);
    scalarbase(pub, d);
    memset(d, 0, sizeof d);
    memset(&ctx, 0, sizeof ctx);
    ed_wipe();
}

uint8_t ed25519_sign(const uint8_t seed[32], const uint8_t pub[32],
                     const uint8_t *msg, uint16_t len, uint8_t sig[64]) BANKED {
    SHA512_CTX ctx;
    uint8_t d[64];
    uint8_t r[64];
    uint8_t h[64];
    int64_t *x;
    uint8_t i;
    uint8_t j;

    memset(sig, 0, 64);
    if (!seed || !pub || (len && !msg) || !ed_begin()) return 0u;

    sha512_init(&ctx);
    sha512_update(&ctx, seed, 32);
    sha512_final(&ctx, d);
    clamp(d);

    sha512_init(&ctx);
    sha512_update(&ctx, d + 32, 32);
    if (len) sha512_update(&ctx, msg, len);
    sha512_final(&ctx, r);
    reduce(r);
    scalarbase(sig, r);

    sha512_init(&ctx);
    sha512_update(&ctx, sig, 32);
    sha512_update(&ctx, pub, 32);
    if (len) sha512_update(&ctx, msg, len);
    sha512_final(&ctx, h);
    reduce(h);

    x = (int64_t *)W;
    memset(x, 0, 64u * sizeof(int64_t));
    for (i = 0; i < 32u; i++) x[i] = r[i];
    for (i = 0; i < 32u; i++) {
        for (j = 0; j < 32u; j++) x[i + j] += (int64_t)((uint16_t)h[i] * (uint16_t)d[j]);
    }
    modL(sig + 32, x);

    memset(d, 0, sizeof d);
    memset(r, 0, sizeof r);
    memset(h, 0, sizeof h);
    memset(&ctx, 0, sizeof ctx);
    ed_wipe();
#ifndef TEST_MODE
    __asm__("ei");
#endif
    return 1u;
}
