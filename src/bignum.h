/* Minimal fixed-width bignum: enough for RSASSA-PKCS1-v1_5 signature
 * verification with keys up to 4096 bits.  Slow-but-simple bitwise
 * schoolbook modmul; a handful of RSA ops per run so speed is irrelevant.
 * Header-only, no allocations, no dependencies. */
#ifndef GENPE_BIGNUM_H
#define GENPE_BIGNUM_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#define BN_WORDS 160                 /* 160*32 = 5120 bits of headroom */

typedef struct {
    uint32_t w[BN_WORDS];            /* little-endian */
    int n;                           /* significant word count */
} bn_t;

static void bn_norm(bn_t *a)
{
    while (a->n > 0 && a->w[a->n - 1] == 0) a->n--;
}

static void bn_zero(bn_t *a) { a->n = 0; }

static int bn_is_zero(const bn_t *a) { return a->n == 0; }

static void bn_from_be(bn_t *a, const unsigned char *p, size_t len)
{
    size_t i;
    bn_zero(a);
    memset(a->w, 0, sizeof(a->w));
    for (i = 0; i < len; i++) {
        size_t bit = (len - 1 - i) * 8;
        a->w[bit >> 5] |= (uint32_t)p[i] << (bit & 31);
    }
    a->n = (int)((len * 8 + 31) / 32);
    if (a->n > BN_WORDS) a->n = BN_WORDS;
    bn_norm(a);
}

static void bn_to_be(const bn_t *a, unsigned char *p, size_t len)
{
    size_t i;
    memset(p, 0, len);
    for (i = 0; i < len; i++) {
        size_t bit = (len - 1 - i) * 8;
        if ((bit >> 5) < (size_t)a->n)
            p[i] = (unsigned char)(a->w[bit >> 5] >> (bit & 31));
    }
}

static int bn_bit(const bn_t *a, int i)
{
    if (i < 0 || (i >> 5) >= a->n) return 0;
    return (a->w[i >> 5] >> (i & 31)) & 1;
}

static int bn_bitlen(const bn_t *a)
{
    int i;
    if (!a->n) return 0;
    i = a->n * 32 - 1;
    while (i >= 0 && !bn_bit(a, i)) i--;
    return i + 1;
}

static int bn_cmp(const bn_t *a, const bn_t *b)
{
    int i;
    if (a->n != b->n) return a->n < b->n ? -1 : 1;
    for (i = a->n - 1; i >= 0; i--)
        if (a->w[i] != b->w[i]) return a->w[i] < b->w[i] ? -1 : 1;
    return 0;
}

/* a += b ; returns carry out (caller guarantees space) */
static uint32_t bn_add(bn_t *a, const bn_t *b)
{
    uint64_t c = 0;
    int i;
    while (a->n < b->n) a->w[a->n++] = 0;   /* zero-extend a to b's width */
    for (i = 0; i < b->n; i++) {
        c += (uint64_t)a->w[i] + b->w[i];
        a->w[i] = (uint32_t)c;
        c >>= 32;
    }
    for (; c && i < BN_WORDS; i++) {
        c += i < a->n ? a->w[i] : 0;   /* words past a->n are garbage */
        a->w[i] = (uint32_t)c;
        c >>= 32;
    }
    if (i > a->n) a->n = i < BN_WORDS ? i : BN_WORDS;
    return (uint32_t)c;
}

/* a -= b ; requires a >= b */
static void bn_sub(bn_t *a, const bn_t *b)
{
    uint64_t c = 0;
    int i;
    for (i = 0; i < b->n; i++) {
        uint64_t d = (uint64_t)a->w[i] - b->w[i] - c;
        a->w[i] = (uint32_t)d;
        c = d >> 63;
    }
    for (; c && i < a->n; i++) {
        uint64_t d = (uint64_t)a->w[i] - c;
        a->w[i] = (uint32_t)d;
        c = d >> 63;
    }
    bn_norm(a);
}

/* r = (a + b) mod m  (a,b < m assumed) */
static void bn_addmod(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m)
{
    *r = *a;
    bn_add(r, b);
    if (bn_cmp(r, m) >= 0) bn_sub(r, m);
}

/* r = (a << 1) mod m */
static void bn_dblmod(bn_t *r, const bn_t *a, const bn_t *m)
{
    bn_addmod(r, a, a, m);
}

/* a = a mod m  (shift-subtract; only used to reduce inputs < 2^4096) */
static void bn_mod(bn_t *a, const bn_t *m)
{
    bn_t t;
    int shift;
    if (bn_cmp(a, m) < 0 || bn_is_zero(m)) return;
    shift = bn_bitlen(a) - bn_bitlen(m);
    t = *m;
    /* align t = m << shift */
    {
        int ws = shift >> 5, bs = shift & 31, i;
        uint64_t c = 0;
        for (i = t.n; i > 0; i--)
            if (i + ws < BN_WORDS) t.w[i + ws] = t.w[i - 1];
        for (i = 0; i < ws && i < BN_WORDS; i++) t.w[i] = 0;
        t.n += ws;
        if (t.n > BN_WORDS) t.n = BN_WORDS;
        if (bs) {
            for (i = 0; i < t.n; i++) {
                c |= (uint64_t)t.w[i] << bs;
                t.w[i] = (uint32_t)c;
                c >>= 32;
            }
            if (c) t.w[t.n++] = (uint32_t)c;
        }
    }
    for (; shift >= 0; shift--) {
        if (bn_cmp(a, &t) >= 0) bn_sub(a, &t);
        /* t >>= 1 */
        {
            int i;
            for (i = 0; i < t.n; i++) {
                t.w[i] >>= 1;
                if (i + 1 < t.n) t.w[i] |= t.w[i + 1] << 31;
            }
            bn_norm(&t);
        }
    }
}

/* r = a * b mod m — bitwise double-and-add */
static void bn_modmul(bn_t *r, const bn_t *a, const bn_t *b, const bn_t *m)
{
    bn_t res, aa;
    int i, blen;
    if (bn_is_zero(a) || bn_is_zero(b)) { bn_zero(r); return; }
    aa = *a;
    bn_mod(&aa, m);
    bn_zero(&res);
    blen = bn_bitlen(b);
    for (i = 0; i < blen; i++) {
        if (bn_bit(b, i)) bn_addmod(&res, &res, &aa, m);
        if (i + 1 < blen) bn_dblmod(&aa, &aa, m);
    }
    *r = res;
}

/* r = base^exp mod m — square and multiply over big-endian exp bytes */
static void bn_modexp(bn_t *r, const bn_t *base,
                      const unsigned char *exp, size_t explen,
                      const bn_t *m)
{
    bn_t res, bb;
    int i, bits;
    bn_zero(&res);
    res.w[0] = 1; res.n = 1;
    if (bn_cmp(&res, m) >= 0) bn_mod(&res, m);
    bb = *base;
    bn_mod(&bb, m);
    bits = (int)explen * 8;
    for (i = bits - 1; i >= 0; i--) {
        /* bit i of the big-endian number: byte explen-1-i/8, bit i%8 */
        int bit = (exp[explen - 1 - ((size_t)i >> 3)] >> (i & 7)) & 1;
        bn_t t;
        /* skip leading zero bits */
        if (res.n == 1 && res.w[0] == 1 && !bit) continue;
        bn_modmul(&t, &res, &res, m);
        res = t;
        if (bit) { bn_modmul(&t, &res, &bb, m); res = t; }
    }
    *r = res;
}

/* DigestInfo DER prefixes for PKCS#1 v1.5 */
static const unsigned char DI_SHA1[]   = {0x30,0x21,0x30,0x09,0x06,0x05,
    0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14};
static const unsigned char DI_SHA256[] = {0x30,0x31,0x30,0x0d,0x06,0x09,
    0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
static const unsigned char DI_SHA384[] = {0x30,0x41,0x30,0x0d,0x06,0x09,
    0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30};
static const unsigned char DI_SHA512[] = {0x30,0x51,0x30,0x0d,0x06,0x09,
    0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40};

/* verify RSASSA-PKCS1-v1_5: sig^e mod n == 00 01 FF.. 00 || DigestInfo||digest
 * returns 1 on valid signature */
static int rsa_pkcs1_verify(const unsigned char *n, size_t nlen,
                            const unsigned char *e, size_t elen,
                            const unsigned char *sig, size_t siglen,
                            const unsigned char *di_prefix, size_t diplen,
                            const unsigned char *digest, size_t dglen)
{
    bn_t M, S, R;
    unsigned char *em;
    size_t k, tlen = diplen + dglen, i;
    int ok = 0;

    while (nlen > 1 && n[0] == 0) { n++; nlen--; }   /* INTEGER pad zero */
    while (elen > 1 && e[0] == 0) { e++; elen--; }
    k = nlen;
    if (nlen > BN_WORDS * 4 || siglen != nlen || k < tlen + 11) return 0;
    bn_from_be(&M, n, nlen);
    bn_from_be(&S, sig, siglen);
    if (bn_cmp(&S, &M) >= 0) return 0;
    bn_modexp(&R, &S, e, elen, &M);

    em = malloc(k);
    if (!em) return 0;
    bn_to_be(&R, em, k);

    if (em[0] == 0x00 && em[1] == 0x01) {
        size_t ps = k - tlen - 1;
        ok = 1;
        for (i = 2; i < ps; i++)
            if (em[i] != 0xff) { ok = 0; break; }
        if (em[ps] != 0x00) ok = 0;
        if (ok && (memcmp(em + ps + 1, di_prefix, diplen) ||
                   memcmp(em + ps + 1 + diplen, digest, dglen)))
            ok = 0;
    }
    free(em);
    return ok;
}

#endif
