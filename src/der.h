/* Minimal DER (ASN.1) reader - just enough to walk X.509 certs and
 * PKCS#7/CMS SignedData.  No allocations; all views into the input. */
#ifndef GENPE_DER_H
#define GENPE_DER_H

#include <stdint.h>
#include <string.h>

typedef struct {
    int tag;                       /* tag byte (single-byte tags only) */
    const unsigned char *hdr;      /* start of the element */
    size_t hlen;                   /* header length (tag+len bytes) */
    const unsigned char *val;      /* content octets */
    size_t vlen;                   /* content length */
    size_t total;                  /* hlen + vlen */
} der_t;

/* read one DER element at *pp (< end); advances *pp past it.  returns 1 ok */
static int der_read(const unsigned char **pp, const unsigned char *end,
                    der_t *t)
{
    const unsigned char *p = *pp;
    size_t len, nb;
    if (p >= end || p + 2 > end) return 0;
    t->hdr = p;
    t->tag = *p++;
    if (t->tag == 0 || (t->tag & 0x1f) == 0x1f) {
        /* multi-byte tags unused here */
        return 0;
    }
    len = *p++;
    if (len & 0x80) {
        nb = len & 0x7f;
        if (nb == 0 || nb > sizeof(size_t) || p + nb > end) return 0;
        len = 0;
        while (nb--) len = len << 8 | *p++;
    }
    if (p + len > end) return 0;
    t->val = p;
    t->vlen = len;
    t->hlen = (size_t)(p - t->hdr);
    t->total = t->hlen + len;
    *pp = p + len;
    return 1;
}

/* read first child of a constructed element (SEQ/SET/[n]) */
static int der_first(const der_t *parent, der_t *child)
{
    const unsigned char *p = parent->val;
    return der_read(&p, parent->val + parent->vlen, child);
}

/* sibling walk: iterate within [p,end) region */
static int der_iter(const unsigned char **pp, const unsigned char *end,
                    der_t *t)
{
    return der_read(pp, end, t);
}


/* compare OID content bytes with a literal DER OID content (no tag/len) */
static int der_oid_eq(const der_t *t, const unsigned char *oid, size_t n)
{
    return t->tag == 0x06 && t->vlen == n && !memcmp(t->val, oid, n);
}

/* INTEGER as raw content bytes (unsigned compare) */
static int der_int_eq(const der_t *a, const unsigned char *b, size_t bn)
{
    const unsigned char *av = a->val;
    size_t an = a->vlen;
    if (a->tag != 0x02) return 0;
    while (an > 1 && av[0] == 0) { av++; an--; }   /* strip pad zeros */
    while (bn > 1 && b[0] == 0) { b++; bn--; }
    return an == bn && !memcmp(av, b, an);
}

/* pull a CN (2.5.4.3) string out of a Name (SEQUENCE of SET of SEQ{oid,str});
 * last match wins (mirrors cert_cn behaviour).  Returns utf8-ish length or 0. */
static int der_name_cn(const der_t *name, char *out, size_t cap)
{
    const unsigned char *p = name->val, *end = name->val + name->vlen;
    der_t set, ava, oid, str;
    int found = 0;
    if (name->tag != 0x30) return 0;
    while (der_iter(&p, end, &set)) {
        const unsigned char *q, *qe;
        if (set.tag != 0x31 || !der_first(&set, &ava) || ava.tag != 0x30)
            continue;
        q = ava.val; qe = ava.val + ava.vlen;
        if (!der_iter(&q, qe, &oid) || !der_iter(&q, qe, &str)) continue;
        if (der_oid_eq(&oid, (const unsigned char *)"\x55\x04\x03", 3)) {
            size_t n, i;
            if (str.tag == 0x1e) {       /* BMPString -> latin1 */
                n = str.vlen / 2 < cap - 1 ? str.vlen / 2 : cap - 1;
                for (i = 0; i < n; i++)
                    out[i] = (char)str.val[i * 2 + 1];
            } else {
                n = str.vlen < cap - 1 ? str.vlen : cap - 1;
                memcpy(out, str.val, n);
            }
            out[n] = 0;
            found = 1;
        }
    }
    return found;
}

#endif
