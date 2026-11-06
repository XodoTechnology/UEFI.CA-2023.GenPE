/* Minimal public-domain-style SHA-1 (single-shot, enough for cert
 * thumbprints).  Implementation follows FIPS 180-1. */
#ifndef GENPE_SHA1_H
#define GENPE_SHA1_H

#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t h[5];
    uint64_t len;
    unsigned char buf[64];
    size_t buflen;
} sha1_ctx;

static void sha1_block(sha1_ctx *c, const unsigned char *p)
{
    uint32_t w[80], a, b, d, e, f, k, t;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
               (uint32_t)p[i * 4 + 2] << 8 | p[i * 4 + 3];
    for (i = 16; i < 80; i++) {
        t = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = t << 1 | t >> 31;
    }
    a = c->h[0]; b = c->h[1]; t = c->h[2]; d = c->h[3]; e = c->h[4];
    for (i = 0; i < 80; i++) {
        if (i < 20)      { f = (b & t) | (~b & d);       k = 0x5a827999; }
        else if (i < 40) { f = b ^ t ^ d;                k = 0x6ed9eba1; }
        else if (i < 60) { f = (b & t) | (b & d) | (t & d); k = 0x8f1bbcdc; }
        else             { f = b ^ t ^ d;                k = 0xca62c1d6; }
        f += ((a << 5) | (a >> 27)) + e + k + w[i];
        e = d; d = t; t = b << 30 | b >> 2; b = a; a = f;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += t; c->h[3] += d; c->h[4] += e;
}

static void sha1_init(sha1_ctx *c)
{
    c->h[0] = 0x67452301; c->h[1] = 0xefcdab89; c->h[2] = 0x98badcfe;
    c->h[3] = 0x10325476; c->h[4] = 0xc3d2e1f0;
    c->len = 0; c->buflen = 0;
}

static void sha1_update(sha1_ctx *c, const void *data, size_t n)
{
    const unsigned char *p = (const unsigned char *)data;
    c->len += n;
    while (n) {
        size_t take = 64 - c->buflen;
        if (take > n) take = n;
        memcpy(c->buf + c->buflen, p, take);
        c->buflen += take; p += take; n -= take;
        if (c->buflen == 64) { sha1_block(c, c->buf); c->buflen = 0; }
    }
}

static void sha1_final(sha1_ctx *c, unsigned char out[20])
{
    uint64_t bits = c->len * 8;
    unsigned char pad = 0x80;
    int i;
    sha1_update(c, &pad, 1);
    pad = 0;
    while (c->buflen != 56) sha1_update(c, &pad, 1);
    for (i = 7; i >= 0; i--) {
        unsigned char b = (unsigned char)(bits >> (i * 8));
        sha1_update(c, &b, 1);
    }
    for (i = 0; i < 5; i++) {
        out[i * 4]     = (unsigned char)(c->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(c->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(c->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)c->h[i];
    }
}

static void sha1(const void *data, size_t n, unsigned char out[20])
{
    sha1_ctx c;
    sha1_init(&c);
    sha1_update(&c, data, n);
    sha1_final(&c, out);
}

#endif
