#include <gb/gb.h>
#include <gb/cgb.h>
#include <string.h>
#include "src/crypto/sha256.h"
#include "src/draw.h"
#include "wallet.h"
#include "menu.h"
#include "sign_review.h"
#include "sign_tx.h"
#include "progress.h"
#include "pbkdf2.h"
#include "b58.h"
#include "bonktime.h"
#include "src/qr/qr_wrapper.h"

#pragma bank 14

static const char ALPHA[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static const uint8_t HASH_CHARS[7] = {7, 6, 12, 11, 10, 9, 8};
static const uint8_t HASH_BYTES[7] = {5, 4, 8, 8, 7, 6, 5};
static const uint8_t SPIN[12] = {1, 2, 3, 2, 1, 0, 1, 2, 3, 2, 1, 0};

enum {
    T_BLANK, T_TO, T_TOADDR, T_PAY, T_NONCELBL, T_NONCE, T_SIGN, T_CANCEL
};
enum { S_NONE, S_TO, S_PAY, S_NONCE, S_SIGN, S_CANCEL };

/* Header is rows 0-2. The list starts on row 4 so that band stays 24px. */
#define VIEW_Y 4u
#define VIEW_H 14u

/* Scratch for the decode and the on-screen text are the same bytes.
   Separate buffers pushed WRAM up into the stack, and the menu and
   the QR then drew whatever tiles that collision left behind. */
static union {
    struct {
        uint8_t raw[204];
        SHA256_CTX sha;
    } scratch;
    struct {
        char to_short[13];
        char nonce_short[13];
        char pay_list[20];
        char pay_full[24];
        uint8_t row_kind[20];
        uint8_t row_arg[20];
        uint8_t stop_row[12];
        uint8_t stop_code[12];
        uint8_t stop_arg[12];
    } view;
} mem;

#define to_short    mem.view.to_short
#define nonce_short mem.view.nonce_short
#define pay_list    mem.view.pay_list
#define pay_full    mem.view.pay_full
#define row_kind    mem.view.row_kind
#define row_arg     mem.view.row_arg
#define stop_row    mem.view.stop_row
#define stop_code   mem.view.stop_code
#define stop_arg    mem.view.stop_arg

/* These sit outside the union. The decode finishes before they are read
   back, and the view text overwrites the payload. */
static uint8_t lamports[8];
static uint8_t dest_pub[32];
static uint8_t nonce_acc[32];
static uint8_t nonce[32];
static char to_full[45];
static char nonce_full[45];
static char nonce_acc_full[45];
static uint8_t ready;
static uint8_t nrows;
static uint8_t nstop;
static uint8_t si;
static uint8_t top;
static uint8_t spin_frame;
static uint8_t spin_hold;

extern wallet current_wallet;

static uint8_t alpha_of(char c) {
    uint8_t i;
    for (i = 0; i < 58u; i++) {
        if (ALPHA[i] == c) return i;
    }
    return 0xffu;
}

static uint8_t group_delta(const char g[8]) {
    uint8_t i;
    uint16_t sum = 0;
    uint8_t check;
    for (i = 0; i < 7u; i++) {
        uint8_t a = alpha_of(g[i]);
        if (a == 0xffu) return 0xffu;
        sum = (uint16_t)(sum + a);
    }
    check = alpha_of(g[7]);
    if (check == 0xffu) return 0xffu;
    return (uint8_t)((check + 58u - (sum % 58u)) % 58u);
}

static uint8_t is_zero(const uint8_t *n, uint8_t len) {
    uint8_t i;
    for (i = 0; i < len; i++) {
        if (n[i]) return 0u;
    }
    return 1u;
}

static uint8_t div10(uint8_t *n, uint8_t len) {
    uint16_t rem = 0;
    uint8_t i;
    for (i = 0; i < len; i++) {
        rem = (uint16_t)((rem << 8) | n[i]);
        n[i] = (uint8_t)(rem / 10u);
        rem = (uint16_t)(rem % 10u);
    }
    return (uint8_t)rem;
}

/* lamports are little-endian. Nine decimal places. */
static void format_amount(const uint8_t le[8], char *list, char *full) {
    uint8_t tmp[8];
    char digs[24];
    uint8_t n = 0;
    uint8_t frac;
    uint8_t intn;
    uint8_t i;
    uint8_t w = 0;
    for (i = 0; i < 8u; i++) tmp[i] = le[7u - i];
    do {
        digs[n++] = (char)('0' + div10(tmp, 8));
    } while (!is_zero(tmp, 8) && n < 24u);
    while (n < 9u) digs[n++] = '0';
    frac = 9u;
    while (frac > 0u && digs[9u - frac] == '0') frac--;
    intn = (n > 9u) ? (uint8_t)(n - 9u) : 0u;
    if (intn == 0u) full[w++] = '0';
    for (i = 0; i < intn; i++) full[w++] = digs[n - 1u - i];
    if (frac) {
        full[w++] = '.';
        for (i = 0; i < frac; i++) full[w++] = digs[8u - i];
    }
    full[w] = 0;
    if (w >= 20u) strcpy(list, ">99999999999");
    else strcpy(list, full);
}

static void shorten(const char *full, char *out) {
    uint8_t n = (uint8_t)strlen(full);
    uint8_t i;
    if (n < 9u) {
        strcpy(out, full);
        return;
    }
    for (i = 0; i < 5u; i++) out[i] = full[i];
    out[5] = '.';
    out[6] = '.';
    out[7] = '.';
    for (i = 0; i < 4u; i++) out[8u + i] = full[n - 4u + i];
    out[12] = 0;
}

static uint8_t muladd58(uint8_t *n, uint8_t len, uint8_t add) {
    uint16_t carry = add;
    uint8_t i;
    for (i = len; i > 0u; i--) {
        carry = (uint16_t)(carry + (uint16_t)n[i - 1u] * 58u);
        n[i - 1u] = (uint8_t)carry;
        carry >>= 8;
    }
    return carry != 0u;
}

static uint8_t decode_fixed(const char *text, uint8_t nchars, uint8_t *out, uint8_t nbytes) {
    uint8_t i;
    memset(out, 0, nbytes);
    for (i = 0; i < nchars; i++) {
        uint8_t a = alpha_of(text[i]);
        if (a == 0xffu) return 0u;
        if (muladd58(out, nbytes, a)) return 0u;
    }
    return 1u;
}

static uint8_t absorb(uint8_t *le, uint8_t *nle, char c) {
    uint16_t carry = alpha_of(c);
    uint8_t j;
    if (carry == 0xffu) return 0u;
    for (j = 0; j < *nle; j++) {
        carry = (uint16_t)(carry + (uint16_t)le[j] * 58u);
        le[j] = (uint8_t)carry;
        carry >>= 8;
    }
    while (carry) {
        if (*nle >= 204u) return 0u;
        le[(*nle)++] = (uint8_t)carry;
        carry >>= 8;
    }
    return 1u;
}

/* Data characters are the first 7 of each payment group and the first
   r of the end group. They decode straight into scratch.raw. */
static uint8_t decode_groups(char groups[][8], uint8_t end, uint8_t r, uint8_t *plen) {
    uint8_t *le = mem.scratch.raw;
    uint8_t nle = 0;
    uint16_t z = 0;
    uint8_t g;
    uint8_t i;
    uint8_t started = 0;
    uint16_t k;
    for (g = 0; g < end; g++) {
        for (i = 0; i < 7u; i++) {
            char c = groups[g][i];
            if (!started && c == '1') { z++; continue; }
            started = 1u;
            if (!absorb(le, &nle, c)) return 0u;
        }
    }
    for (i = 0; i < r; i++) {
        char c = groups[end][i];
        if (!started && c == '1') { z++; continue; }
        started = 1u;
        if (!absorb(le, &nle, c)) return 0u;
    }
    if ((uint16_t)z + nle > 204u) return 0u;
    for (i = 0; i < (uint8_t)(nle / 2u); i++) {
        uint8_t t = le[i];
        le[i] = le[nle - 1u - i];
        le[nle - 1u - i] = t;
    }
    if (z) {
        for (k = nle; k > 0u; k--) le[z + k - 1u] = le[k - 1u];
        for (k = 0; k < z; k++) le[k] = 0;
    }
    *plen = (uint8_t)(z + nle);
    return 1u;
}

static void append7(char *dst, uint16_t *n, const char *src, uint8_t from, uint8_t to) {
    uint8_t i;
    for (i = from; i < to; i++) dst[(*n)++] = src[i];
}

/* Payload is 105 bytes: version 0x02, u64 lamports LE, 32-byte
   destination, 32-byte nonce account, 32-byte nonce value. */
static uint8_t parse(char groups[][8], uint8_t count, uint8_t r) {
    char hash[16];
    uint16_t hlen = 0;
    uint8_t end;
    uint8_t g;
    uint8_t *payload;
    uint8_t plen = 0;
    uint8_t got[8];
    uint8_t digest[32];
    ready = 0;
    if (r > 6u || count == 0u) return 0u;
    end = (r >= 2u) ? (uint8_t)(count - 2u) : (uint8_t)(count - 1u);
    if (end >= count) return 0u;
    for (g = 0; g < end; g++) {
        if (group_delta(groups[g]) != 0u) return 0u;
    }
    if (group_delta(groups[end]) != (uint8_t)(r + 1u)) return 0u;
    append7(hash, &hlen, groups[end], r, 7);
    if (r >= 2u) {
        if (group_delta(groups[end + 1u]) != 0u) return 0u;
        append7(hash, &hlen, groups[end + 1u], 0, 7);
    }
    if (hlen != HASH_CHARS[r]) return 0u;
    if (!decode_groups(groups, end, r, &plen)) return 0u;
    payload = mem.scratch.raw;
    if (!decode_fixed(hash, hlen, got, HASH_BYTES[r])) return 0u;
    sha256_init(&mem.scratch.sha);
    sha256_update(&mem.scratch.sha, payload, plen);
    sha256_final(&mem.scratch.sha, digest);
    sha256_init(&mem.scratch.sha);
    sha256_update(&mem.scratch.sha, digest, 32);
    sha256_final(&mem.scratch.sha, digest);
    if (memcmp(digest, got, HASH_BYTES[r]) != 0) return 0u;

    if (plen != 105u || payload[0] != 0x02u) return 0u;
    memcpy(lamports, payload + 1, 8);
    memcpy(dest_pub, payload + 9, 32);
    memcpy(nonce_acc, payload + 41, 32);
    memcpy(nonce, payload + 73, 32);
    if (is_zero(lamports, 8) || is_zero(dest_pub, 32)) return 0u;
    if (is_zero(nonce_acc, 32) || is_zero(nonce, 32)) return 0u;
    /* All three encodes finish before shorten. shorten writes the view
       union, and that union shares the scratch the payload was in. */
    if (!b58_encode(dest_pub, 32, to_full, 45)) return 0u;
    if (!b58_encode(nonce, 32, nonce_full, 45)) return 0u;
    if (!b58_encode(nonce_acc, 32, nonce_acc_full, 45)) return 0u;
    shorten(to_full, to_short);
    shorten(nonce_full, nonce_short);
    format_amount(lamports, pay_list, pay_full);
    ready = 1u;
    return 1u;
}

static void add_row(uint8_t kind, uint8_t arg, uint8_t stop) {
    row_kind[nrows] = kind;
    row_arg[nrows] = arg;
    if (stop != S_NONE) {
        stop_row[nstop] = nrows;
        stop_code[nstop] = stop;
        stop_arg[nstop] = arg;
        nstop++;
    }
    nrows++;
}

static void build_rows(void) {
    nrows = 0;
    nstop = 0;
    add_row(T_TO, 0, S_NONE);
    add_row(T_TOADDR, 0, S_TO);
    add_row(T_PAY, 0, S_PAY);
    add_row(T_BLANK, 0, S_NONE);
    add_row(T_NONCELBL, 0, S_NONE);
    add_row(T_NONCE, 0, S_NONCE);
    add_row(T_BLANK, 0, S_NONE);
    add_row(T_SIGN, 0, S_SIGN);
    add_row(T_CANCEL, 0, S_CANCEL);
}

static void draw_at(uint8_t y, uint8_t x, const char *s) {
    uint8_t tiles[20];
    uint8_t n = 0;
    if (y >= 18u) return;
    while (s[n] && n < 20u && (uint8_t)(x + n) < 20u) {
        tiles[n] = (uint8_t)(s[n] - 32);
        n++;
    }
    if (n) set_bkg_tiles(x, y, n, 1, tiles);
}

static void draw_center(uint8_t y, const char *s) {
    uint8_t n = (uint8_t)strlen(s);
    uint8_t x = (n >= 20u) ? 0u : (uint8_t)((20u - n) / 2u);
    draw_at(y, x, s);
}

static void draw_right(uint8_t y, const char *s) {
    uint8_t n = (uint8_t)strlen(s);
    uint8_t x = (n >= 20u) ? 0u : (uint8_t)(20u - n);
    if (x == 0u && n < 20u) x = 1u;
    draw_at(y, x, s);
}

static void draw_band(const char *title) {
    if (_cpu == CGB_TYPE) {
        VBK_REG = 1;
        fill_bkg_rect(0, 0, 20, 3, 1);
        VBK_REG = 0;
    }
    draw_center(1, title);
}

/* Palette 1 across the whole row. The label sits on the left. */
static void draw_bar(uint8_t y, const char *s) {
    uint8_t tiles[20];
    uint8_t n = 0;
    uint8_t i;
    if (y >= 18u) return;
    for (i = 0; i < 20u; i++) tiles[i] = 0;
    while (s[n] && n < 20u) {
        tiles[n] = (uint8_t)(s[n] - 32);
        n++;
    }
    set_bkg_tiles(0, y, 20, 1, tiles);
    if (_cpu != CGB_TYPE) return;
    VBK_REG = 1;
    fill_bkg_rect(0, y, 20, 1, 1);
    VBK_REG = 0;
}

static void draw_row(uint8_t i, uint8_t y) {
    switch (row_kind[i]) {
    case T_TO: draw_bar(y, "To:"); break;
    case T_TOADDR: draw_right(y, to_short); break;
    case T_PAY: draw_right(y, pay_list); break;
    case T_NONCELBL: draw_bar(y, "Nonce:"); break;
    case T_NONCE: draw_right(y, nonce_short); break;
    case T_SIGN: draw_at(y, 7, "[Sign]"); break;
    case T_CANCEL: draw_at(y, 6, "[Cancel]"); break;
    default: break;
    }
}

static void place_coin(void) {
    uint8_t row = stop_row[si];
    uint8_t screen = (uint8_t)(row - top + VIEW_Y);
    uint8_t y = (uint8_t)(screen * 8u + 16u);
    uint8_t tile = (spin_frame == 0u) ? 0u : SPIN[spin_frame - 1u];
    set_sprite_tile(0, tile);
    set_sprite_prop(0, 0);
    if (stop_code[si] == S_SIGN || stop_code[si] == S_CANCEL) {
        /* One blank tile between each coin and the centered label. */
        uint8_t len = (stop_code[si] == S_SIGN) ? 6u : 8u;
        uint8_t x0 = (uint8_t)((20u - len) / 2u);
        set_sprite_tile(1, tile);
        set_sprite_prop(1, 0);
        move_sprite(0, (uint8_t)((x0 - 2u) * 8u + 8u), y);
        move_sprite(1, (uint8_t)((x0 + len + 1u) * 8u + 8u), y);
    } else {
        move_sprite(0, 8, y);
        move_sprite(1, 0, 0);
    }
}

static void step_spin(void) {
    spin_hold++;
    if (spin_frame == 0u) {
        if (spin_hold >= 120u) {
            spin_hold = 0;
            spin_frame = 1u;
        }
    } else if (spin_hold >= 10u) {
        spin_hold = 0;
        spin_frame++;
        if (spin_frame > 12u) spin_frame = 0u;
    }
    place_coin();
}

static void draw_review(void) {
    uint8_t i;
    clear_screen();
    draw_band("Review TX");
    for (i = top; i < nrows && (uint8_t)(i - top) < VIEW_H; i++) {
        draw_row(i, (uint8_t)(i - top + VIEW_Y));
    }
    place_coin();
}

static void follow(void) {
    uint8_t row = stop_row[si];
    if (nrows <= VIEW_H) top = 0;
    else if (row < top) top = row;
    else if (row >= (uint8_t)(top + VIEW_H)) top = (uint8_t)(row + 1u - VIEW_H);
}

static void draw_amount_block(uint8_t y, const char *full) {
    uint8_t n = (uint8_t)strlen(full);
    char hi[16];
    char lo[16];
    uint8_t i;
    uint8_t dot = 0xffu;
    if (n <= 20u) {
        draw_right(y, full);
        return;
    }
    for (i = 0; i < n; i++) {
        if (full[i] == '.') dot = i;
    }
    if (dot == 0xffu || dot >= 16u) {
        draw_right(y, full);
        return;
    }
    memcpy(hi, full, dot);
    hi[dot] = 0;
    lo[0] = '.';
    strcpy(lo + 1, full + dot + 1);
    draw_right(y, hi);
    draw_right((uint8_t)(y + 1u), lo);
}

/* Up to three lines of 20. A Solana address is 32 to 44 characters. */
static void draw_address_block(uint8_t y, const char *full) {
    uint8_t n = (uint8_t)strlen(full);
    char line[21];
    uint8_t off = 0;
    uint8_t row = 0;
    while (off < n && row < 3u) {
        uint8_t take = (uint8_t)(n - off);
        if (take > 20u) take = 20u;
        memcpy(line, full + off, take);
        line[take] = 0;
        draw_at((uint8_t)(y + row), 0, line);
        off = (uint8_t)(off + take);
        row++;
    }
}

static uint8_t amount_lines(const char *full) {
    uint8_t n = (uint8_t)strlen(full);
    uint8_t i;
    if (n <= 20u) return 1u;
    for (i = 0; i < n; i++) {
        if (full[i] == '.') return 2u;
    }
    return 1u;
}

static uint8_t addr_lines(const char *full) {
    uint8_t n = (uint8_t)strlen(full);
    if (n <= 20u) return 1u;
    if (n <= 40u) return 2u;
    return 3u;
}

/* Two blocks share rows 3-16. Back stays on row 17. */
static void block_y(uint8_t h1, uint8_t h2, uint8_t *y1, uint8_t *y2) {
    uint8_t space = (uint8_t)(14u - h1 - h2);
    uint8_t g = (uint8_t)(space / 3u);
    uint8_t extra = (uint8_t)(space % 3u);
    uint8_t y = (uint8_t)(3u + g + (extra > 0u));
    *y1 = y;
    *y2 = (uint8_t)(y + h1 + g + (extra > 1u));
}

/* The coin sits in the column before the B. The pair is centered. */
static void draw_back(void) {
    draw_at(17, 8, "Back");
    set_sprite_tile(0, 0);
    set_sprite_prop(0, 0);
    move_sprite(0, 64, 152);
    move_sprite(1, 0, 0);
    SHOW_SPRITES;
}

static void show_detail(uint8_t code) {
    uint8_t prev;
    uint8_t y1;
    uint8_t y2;
    move_sprite(0, 0, 0);
    move_sprite(1, 0, 0);
    clear_screen();
    if (code == S_TO) {
        draw_band("To");
        block_y((uint8_t)(1u + addr_lines(to_full)),
                (uint8_t)(1u + amount_lines(pay_full)), &y1, &y2);
        draw_bar(y1, "Address:");
        draw_address_block((uint8_t)(y1 + 1u), to_full);
        draw_bar(y2, "Value:");
        draw_amount_block((uint8_t)(y2 + 1u), pay_full);
    } else if (code == S_PAY) {
        draw_band("Amount");
        block_y((uint8_t)(1u + amount_lines(pay_full)), 0, &y1, &y2);
        draw_bar(y1, "Value:");
        draw_amount_block((uint8_t)(y1 + 1u), pay_full);
    } else if (code == S_NONCE) {
        draw_band("Nonce");
        block_y((uint8_t)(1u + addr_lines(nonce_full)),
                (uint8_t)(1u + addr_lines(nonce_acc_full)), &y1, &y2);
        draw_bar(y1, "Nonce:");
        draw_address_block((uint8_t)(y1 + 1u), nonce_full);
        draw_bar(y2, "Account:");
        draw_address_block((uint8_t)(y2 + 1u), nonce_acc_full);
    }
    draw_back();
    prev = joypad();
    while (1) {
        uint8_t j;
        uint8_t np;
        wait_vbl_done();
        j = joypad();
        np = (uint8_t)(j & (uint8_t)~prev);
        prev = j;
        if (np) break;
    }
    move_sprite(0, 0, 0);
    move_sprite(1, 0, 0);
    draw_review();
}

/* Two bytes of header, then a slice of the export. Version 3 holds 53. */
#define QR_CAP 53u
#define QR_DATA 51u

static uint8_t qr_pages(uint16_t n) {
    uint8_t c = 0;
    if (n == 0u) return 1u;
    while (n) {
        c++;
        if (n > QR_DATA) n = (uint16_t)(n - QR_DATA);
        else n = 0;
    }
    return c;
}

static void draw_page_num(uint8_t page) {
    char s[3];
    s[0] = (char)('0' + page / 10u);
    s[1] = (char)('0' + page % 10u);
    s[2] = 0;
    draw_at(0, 9, s);
    draw_at(17, 9, s);
}

static void draw_sig_page(const uint8_t *blob, uint16_t blob_len, uint8_t page, uint8_t count) {
    uint8_t buf[QR_CAP];
    uint16_t off = (uint16_t)page * QR_DATA;
    uint16_t n = 0;
    uint16_t i;
    buf[0] = page;
    buf[1] = count;
    if (off < blob_len) n = (uint16_t)(blob_len - off);
    if (n > QR_DATA) n = QR_DATA;
    for (i = 0; i < n; i++) buf[2u + i] = blob[off + i];
    qr_generate((char *)buf, (uint16_t)(2u + n));
    qr_render();
    draw_page_num(page);
    draw_qr_sides();
}

static uint8_t ask_sure(void) {
    char title[14];
    char opt_no[3];
    char opt_yes[4];
    const char *opts[2];
    /* Copied to the stack. menu.c is another bank, so a ROM literal
       would unmap before it is drawn. */
    strcpy(title, "Are you sure?");
    strcpy(opt_no, "No");
    strcpy(opt_yes, "Yes");
    opts[0] = opt_no;
    opts[1] = opt_yes;
    init_draw();
    return show_menu(title, opts, 2u) == 1;
}

static void show_sig_qrs(const uint8_t *blob, uint16_t blob_len) {
    uint8_t page = 0;
    uint8_t count = qr_pages(blob_len);
    uint8_t prev;
    HIDE_SPRITES;
    draw_sig_page(blob, blob_len, page, count);
    prev = joypad();
    while (1) {
        uint8_t j;
        uint8_t np;
        wait_vbl_done();
        j = joypad();
        np = (uint8_t)(j & (uint8_t)~prev);
        prev = j;
        if (np & (J_B | J_START)) {
            if (ask_sure()) return;
            draw_sig_page(blob, blob_len, page, count);
            prev = joypad();
            continue;
        }
        if ((np & J_LEFT) && page > 0u) {
            page--;
            draw_sig_page(blob, blob_len, page, count);
        } else if ((np & J_RIGHT) && (uint8_t)(page + 1u) < count) {
            page++;
            draw_sig_page(blob, blob_len, page, count);
        }
    }
}

static void wipe_scratch(void) {
    uint16_t n = 0;
    uint8_t *p = kdf_scratch(&n);
    if (p && n) memset(p, 0, n);
}

/* 1 when the signature screens were left. The scratch is already clear. */
static uint8_t begin_sign(void) {
    uint16_t blob_len = 0;
    uint16_t scratch_len = 0;
    uint8_t *base;
    uint8_t leave = 0;
    if (!ready) return 0u;
    if (current_wallet.slotNum < 1u || current_wallet.slotNum > MAX_SLOTS) return 0u;
    move_sprite(0, 0, 0);
    move_sprite(1, 0, 0);
    HIDE_SPRITES;
    show_sign_progress();
    sign_payment(current_wallet.slotNum, dest_pub, lamports, nonce_acc, nonce, &blob_len);
    progress_ride_end();
    base = kdf_scratch(&scratch_len);
    if (blob_len == 96u && base && scratch_len >= 96u) {
        show_sig_qrs(base, blob_len);
        leave = 1;
    }
    wipe_scratch();
    if (leave) {
        move_sprite(0, 0, 0);
        move_sprite(1, 0, 0);
        HIDE_SPRITES;
        return 1u;
    }
    init_draw();
    init_cursor_sprite();
    follow();
    draw_review();
    return 0u;
}

static void move_stop(int8_t dir) {
    if (dir < 0) {
        if (si > 0u) si--;
    } else if (si + 1u < nstop) {
        si++;
    }
    follow();
    draw_review();
}

static void focus_sign(void) {
    uint8_t i;
    for (i = 0; i < nstop; i++) {
        if (stop_code[i] == S_SIGN) {
            si = i;
            break;
        }
    }
    follow();
    draw_review();
}

static uint8_t confirm_cancel(void) {
    move_sprite(0, 0, 0);
    move_sprite(1, 0, 0);
    if (ask_sure()) {
        move_sprite(0, 0, 0);
        move_sprite(1, 0, 0);
        HIDE_SPRITES;
        return 1u;
    }
    init_cursor_sprite();
    follow();
    draw_review();
    return 0u;
}

uint8_t sign_review_open(char groups[][8], uint8_t count, uint8_t r) BANKED {
    uint8_t prev;
    if (!parse(groups, count, r)) return 0u;
    build_rows();
    si = 0;
    top = 0;
    spin_frame = 0;
    spin_hold = 0;
    init_cursor_sprite();
    follow();
    draw_review();
    prev = joypad();
    while (1) {
        uint8_t j;
        uint8_t np;
        wait_vbl_done();
        step_spin();
        j = joypad();
        np = (uint8_t)(j & (uint8_t)~prev);
        prev = j;
        if (np & J_UP) move_stop(-1);
        if (np & J_DOWN) move_stop(1);
        if (np & J_START) {
            if (stop_code[si] == S_SIGN) {
                if (begin_sign()) return 2u;
            } else focus_sign();
            prev = joypad();
        } else if (np & J_A) {
            uint8_t code = stop_code[si];
            if (code == S_TO || code == S_PAY || code == S_NONCE)
                show_detail(code);
            else if (code == S_SIGN) {
                if (begin_sign()) return 2u;
            } else if (code == S_CANCEL && confirm_cancel())
                return 1u;
            prev = joypad();
        }
    }
}
