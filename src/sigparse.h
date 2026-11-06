/* EFI_SIGNATURE_LIST parsing, X509 CN heuristic, SHA-1 cert matching and
 * PK -> KEK update map lookup.  Header-only so tests can link it natively. */
#ifndef GENPE_SIGPARSE_H
#define GENPE_SIGPARSE_H
/* ------------------------------------------------------------------ */
/* EFI_SIGNATURE_LIST parsing                                          */
/* ------------------------------------------------------------------ */

static const unsigned char SIG_X509[16]   = {0xa1,0x59,0xc0,0xa5,0xe4,0x94,
    0xa7,0x4a,0x87,0xb5,0xab,0x15,0x5c,0x2b,0xf0,0x72};
static const unsigned char SIG_SHA256[16] = {0x26,0x16,0xc4,0xc1,0x4c,0x50,
    0x92,0x40,0xac,0xa9,0x41,0xf9,0x36,0x93,0x43,0x28};
static const unsigned char SIG_SHA1[16]   = {0x12,0xa5,0x6c,0x82,0x6d,0xcf,
    0x9b,0x4e,0xb8,0x5b,0x59,0x2d,0x64,0x96,0xb4,0xbc};
static const unsigned char SIG_RSA[16]    = {0xe8,0x66,0x57,0x3c,0x9c,0x26,
    0x34,0x4e,0xaa,0x14,0xed,0x77,0x6e,0x85,0xb3,0xb6};

static uint32_t rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static const char *sigtype_name(const unsigned char *t)
{
    if (!memcmp(t, SIG_X509, 16))   return "x509";
    if (!memcmp(t, SIG_SHA256, 16)) return "sha256";
    if (!memcmp(t, SIG_SHA1, 16))   return "sha1";
    if (!memcmp(t, SIG_RSA, 16))    return "rsa2048";
    return "other";
}

typedef void (*sig_cb)(const unsigned char *type, const unsigned char *owner,
                       const unsigned char *data, unsigned int dlen, void *ctx);

static void for_each_sig(const unsigned char *buf, unsigned int len,
                         sig_cb cb, void *ctx)
{
    unsigned int off = 0;
    while (off + 28 <= len) {
        uint32_t lsz = rd32(buf + off + 16);
        uint32_t hsz = rd32(buf + off + 20);
        uint32_t ssz = rd32(buf + off + 24);
        unsigned int ent, end;
        if (lsz < 28 || (uint64_t)off + lsz > len || ssz < 16 || hsz > lsz - 28)
            break;
        ent = off + 28 + hsz;
        end = off + lsz;
        while (ent + ssz <= end) {
            cb(buf + off, buf + ent, buf + ent + 16, ssz - 16, ctx);
            ent += ssz;
        }
        off += lsz;
    }
}

/* subject CN heuristic: last id-at-commonName OID (2.5.4.3 -> 55 04 03);
 * issuer DN precedes subject DN in the TBSCertificate so the last match
 * is normally the subject's CN. */
static int cert_cn(const unsigned char *der, unsigned int len,
                   WCHAR *out, unsigned int cap)
{
    unsigned int i;
    WCHAR best[80];
    int found = 0;
    best[0] = 0;

    for (i = 0; i + 7 < len; i++) {
        unsigned int j, slen, n;
        unsigned char tag;
        if (der[i] != 0x06 || der[i + 1] != 0x03 || der[i + 2] != 0x55 ||
            der[i + 3] != 0x04 || der[i + 4] != 0x03)
            continue;
        j = i + 5;
        tag = der[j++];
        if (j >= len) break;
        slen = der[j++];
        if (slen & 0x80) {
            unsigned int k, nb = slen & 0x7f;
            if (nb > 2 || j + nb > len) continue;
            slen = 0;
            for (k = 0; k < nb; k++) slen = slen << 8 | der[j++];
        }
        if (j + slen > len || slen == 0 || slen > 64) continue;
        if (tag == 0x0c || tag == 0x13 || tag == 0x14 || tag == 0x16) {
            for (n = 0; n < slen && n < 79; n++) {
                unsigned char c = der[j + n];
                if (c < 0x20 || c > 0x7e) break;
                best[n] = c;
            }
            best[n] = 0;
            if (n == slen) found = 1;
        } else if (tag == 0x1e) { /* BMPString */
            for (n = 0; n * 2 + 1 < slen && n < 79; n++)
                best[n] = (WCHAR)(der[j + n * 2] << 8 | der[j + n * 2 + 1]);
            best[n] = 0;
            found = 1;
        }
    }
    if (found && out) {
        wcsncpy(out, best, cap - 1);
        out[cap - 1] = 0;
    }
    return found;
}

static const char *known_cert_name(const unsigned char sha[20])
{
    unsigned int i;
    for (i = 0; i < KNOWN_CERT_COUNT; i++)
        if (!memcmp(sha, g_known_certs[i].sha1, 20))
            return g_known_certs[i].name;
    return NULL;
}

struct has_ctx { unsigned char sha[20]; int found; };
static void has_cb(const unsigned char *t, const unsigned char *o,
                   const unsigned char *d, unsigned int n, void *ctx)
{
    struct has_ctx *c = ctx;
    unsigned char h[20];
    (void)o;
    if (memcmp(t, SIG_X509, 16)) return;
    sha1(d, n, h);
    if (!memcmp(h, c->sha, 20)) c->found = 1;
}

static int var_has_cert(const unsigned char *buf, unsigned int len,
                        const unsigned char sha[20])
{
    struct has_ctx c;
    memcpy(c.sha, sha, 20);
    c.found = 0;
    for_each_sig(buf, len, has_cb, &c);
    return c.found;
}

static int var_has_named_cert(const unsigned char *buf, unsigned int len,
                              const char *name)
{
    unsigned int i;
    for (i = 0; i < KNOWN_CERT_COUNT; i++)
        if (!strcmp(g_known_certs[i].name, name) &&
            var_has_cert(buf, len, g_known_certs[i].sha1))
            return 1;
    return 0;
}

struct pk_ctx { const kek_entry_t *match; WCHAR cn[80]; unsigned char sha[20]; int saw_cert; };
static void pk_cb(const unsigned char *t, const unsigned char *o,
                  const unsigned char *d, unsigned int n, void *ctx)
{
    struct pk_ctx *c = ctx;
    unsigned char h[20];
    unsigned int i;
    (void)o;
    if (memcmp(t, SIG_X509, 16) || c->saw_cert) return;
    c->saw_cert = 1;
    sha1(d, n, h);
    memcpy(c->sha, h, 20);
    cert_cn(d, n, c->cn, 80);
    for (i = 0; i < KEK_MAP_COUNT; i++)
        if (!memcmp(h, g_kek_map[i].sha1, 20)) {
            c->match = &g_kek_map[i];
            return;
        }
}

static const kek_entry_t *find_kek_update(const unsigned char *pkbuf,
                                          unsigned int len,
                                          struct pk_ctx *info)
{
    struct pk_ctx c;
    memset(&c, 0, sizeof(c));
    for_each_sig(pkbuf, len, pk_cb, &c);
    if (info) *info = c;
    return c.match;
}

#endif
