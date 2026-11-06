/* Authenticode / PKCS#7 signature verification for PE files.
 *
 * Verifies, cryptographically:
 *   1. the SignedData signature over the authenticated attributes
 *      (RSASSA-PKCS1-v1_5, sha1/sha256),
 *   2. messageDigest == hash(eContent),
 *   3. the eContent embeds the Authenticode hash of *this* PE image
 *      (signature is bound to the file, not copied from another),
 *   4. the signer's certificate chains - RSA signature per hop - up to a
 *      certificate accepted by the caller's anchor callback (in practice:
 *      a CA whose cert is enrolled in the device's Secure Boot db, or in
 *      the embedded known-2023-CA table).
 *
 * Header-only.  Depends on der.h, bignum.h, sha1.h, sha256.h.
 */
#ifndef GENPE_SIGCHECK_H
#define GENPE_SIGCHECK_H

#include "der.h"
#include "bignum.h"
#include "sha1.h"
#include "sha256.h"

static uint32_t sc_rd32(const unsigned char *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* digest algorithm ids */
#define DG_SHA1   0
#define DG_SHA256 1
#define DG_NONE   (-1)

/* returns CA display name if der is an acceptable trust anchor, else NULL */
typedef const char *(*anchor_cb)(const unsigned char *der, size_t len,
                                 void *ctx);

/* ---- digest helpers ------------------------------------------------ */

static int dg_alg_from_oid(const der_t *oid)
{
    static const unsigned char O_SHA1[]   = {0x2b,0x0e,0x03,0x02,0x1a};
    static const unsigned char O_SHA256[] = {0x60,0x86,0x48,0x01,0x65,0x03,
                                             0x04,0x02,0x01};
    if (der_oid_eq(oid, O_SHA1, sizeof(O_SHA1)))   return DG_SHA1;
    if (der_oid_eq(oid, O_SHA256, sizeof(O_SHA256))) return DG_SHA256;
    return DG_NONE;
}

static int dg_alg_from_sigoid(const der_t *oid)
{
    /* rsaEncryption family: 1.2.840.113549.1.1.{5,11,12,13} */
    if (oid->tag == 0x06 && oid->vlen == 9 &&
        !memcmp(oid->val, "\x2a\x86\x48\x86\xf7\x0d\x01\x01", 8)) {
        switch (oid->val[8]) {
        case 0x05: return DG_SHA1;
        case 0x0b: return DG_SHA256;
        }
    }
    return DG_NONE;
}

static const unsigned char *dg_prefix(int alg, size_t *len)
{
    if (alg == DG_SHA1)   { *len = sizeof(DI_SHA1);   return DI_SHA1; }
    if (alg == DG_SHA256) { *len = sizeof(DI_SHA256); return DI_SHA256; }
    return NULL;
}

static size_t dg_len(int alg) { return alg == DG_SHA1 ? 20 : 32; }

static void dg_compute(int alg, const void *data, size_t n, unsigned char *out)
{
    if (alg == DG_SHA1) sha1(data, n, out);
    else                sha256(data, n, out);
}

/* ---- PE / Authenticode -------------------------------------------- */

struct pe_sig {
    const unsigned char *p7;      /* PKCS#7 blob */
    size_t p7len;
    uint32_t secva, secsz;
    int ispe;
};

/* locate the WIN_CERTIFICATE / PKCS7 blob.  1 on success */
static int pe_signature_blob(const unsigned char *f, size_t n,
                             struct pe_sig *s)
{
    uint32_t eoff, dd;
    unsigned int magic;
    if (n < 0x40 || f[0] != 'M' || f[1] != 'Z') return 0;
    eoff = sc_rd32(f + 0x3c);
    if ((uint64_t)eoff + 0x98 >= n || memcmp(f + eoff, "PE\0\0", 4)) return 0;
    magic = f[eoff + 24] | f[eoff + 25] << 8;
    dd = eoff + 24 + (magic == 0x20b ? 112 : magic == 0x10b ? 96 : 0);
    if (!dd || dd + 40 > n) return 0;
    s->secva = sc_rd32(f + dd + 32);
    s->secsz = sc_rd32(f + dd + 36);
    if (!s->secva || s->secsz < 16 || (uint64_t)s->secva + s->secsz > n)
        return 0;
    /* WIN_CERTIFICATE: dwLength, wRevision(0x0200), wCertificateType */
    if ((f[s->secva + 4] | f[s->secva + 5] << 8) != 0x0200) return 0;
    s->p7 = f + s->secva + 8;
    s->p7len = s->secsz - 8;
    if (sc_rd32(f + s->secva) < s->p7len) s->p7len = sc_rd32(f + s->secva) - 8;
    s->ispe = 1;
    return 1;
}

/* Authenticode digest of the image: hash all bytes except the CheckSum
 * field, the security-directory entry and the certificate table itself. */
static int pe_authcode_digest(const unsigned char *f, size_t n, int alg,
                              unsigned char *out)
{
    uint32_t eoff, dd, cksum, secva, secsz;
    unsigned int magic;
    size_t hash_end;
    sha256_ctx c256;
    sha1_ctx c1;
    void *c;
    void (*upd)(void *, const void *, size_t);
    void (*fin)(void *, unsigned char *);

    if (n < 0x40 || f[0] != 'M' || f[1] != 'Z') return 0;
    eoff = sc_rd32(f + 0x3c);
    if ((uint64_t)eoff + 0x98 >= n || memcmp(f + eoff, "PE\0\0", 4)) return 0;
    magic = f[eoff + 24] | f[eoff + 25] << 8;
    dd = eoff + 24 + (magic == 0x20b ? 112 : magic == 0x10b ? 96 : 0);
    if (!dd || dd + 40 > n) return 0;
    cksum = eoff + 24 + 64;
    secva = sc_rd32(f + dd + 32);
    secsz = sc_rd32(f + dd + 36);
    if (!secva || !secsz || secsz > n) return 0;
    hash_end = n - secsz;
    if (hash_end <= (size_t)dd + 40) return 0;

    if (alg == DG_SHA1) {
        sha1_init(&c1); c = &c1;
        upd = (void (*)(void *, const void *, size_t))sha1_update;
        fin = (void (*)(void *, unsigned char *))sha1_final;
    } else {
        sha256_init(&c256); c = &c256;
        upd = (void (*)(void *, const void *, size_t))sha256_update;
        fin = (void (*)(void *, unsigned char *))sha256_final;
    }
    upd(c, f, cksum);
    upd(c, f + cksum + 4, (dd + 32) - (cksum + 4));   /* to security dir entry */
    upd(c, f + dd + 40, hash_end - (dd + 40));        /* to end minus cert tbl */
    fin(c, out);
    return 1;
}

/* ---- X.509 ---------------------------------------------------------- */

typedef struct {
    const unsigned char *der;   size_t derlen;
    const unsigned char *tbs;   size_t tbslen;
    const unsigned char *sig;   size_t siglen;   /* BIT STRING bits */
    const unsigned char *n, *e; size_t nlen, elen;
    const unsigned char *serial; size_t serlen;
    der_t subj_name, iss_name;                    /* Name SEQUENCEs in tbs */
    int sig_alg;
    int verified_by;                              /* cert index or -1 */
    int trusted;
    char subj_cn[96];
} xcrt_t;

static int x509_parse(const unsigned char *der, size_t n, xcrt_t *c)
{
    const unsigned char *p = der, *end = der + n;
    der_t cert, tbs, el, bs, seq, ni, ei;
    int idx;

    memset(c, 0, sizeof(*c));
    c->verified_by = -1;
    if (!der_iter(&p, end, &cert) || cert.tag != 0x30 ||
        cert.hdr + cert.total != end)
        return 0;
    if (!der_first(&cert, &tbs) || tbs.tag != 0x30) return 0;
    c->der = der; c->derlen = n;
    c->tbs = tbs.hdr; c->tbslen = tbs.total;

    /* walk TBSCertificate children; SEQ siblings are told apart by their
     * first child's tag: 0x31 SET -> Name, 0x06 OID -> sig algorithm,
     * 0x17/0x18 time -> validity, 0x30 SEQ -> subjectPublicKeyInfo */
    p = tbs.val; end = tbs.val + tbs.vlen;
    for (idx = 0; p < end && der_iter(&p, end, &el); idx++) {
        der_t k;
        if (el.tag == 0xa0 || el.tag == 0xa1 || el.tag == 0xa2 ||
            el.tag == 0xa3)
            continue;                                 /* version/extensions */
        if (el.tag == 0x02 && !c->serial) {
            c->serial = el.val; c->serlen = el.vlen;
            continue;
        }
        if (el.tag != 0x30 || !der_first(&el, &k)) continue;
        if (k.tag == 0x31 && !c->iss_name.tag) c->iss_name = el;
        else if (k.tag == 0x31 && !c->subj_name.tag) c->subj_name = el;
        else if (k.tag == 0x30 && c->subj_name.tag) {
            /* subjectPublicKeyInfo: SEQ{alg SEQ, BIT STRING} */
            const unsigned char *q = el.val, *qe = el.val + el.vlen;
            if (der_iter(&q, qe, &seq) && der_iter(&q, qe, &bs) &&
                bs.tag == 0x03 && bs.vlen > 1) {
                const unsigned char *r = bs.val + 1,
                                    *re = bs.val + bs.vlen;
                der_t pk;
                if (der_iter(&r, re, &pk) && pk.tag == 0x30) {
                    const unsigned char *s = pk.val,
                                        *se = pk.val + pk.vlen;
                    if (der_iter(&s, se, &ni) && der_iter(&s, se, &ei)) {
                        c->n = ni.val; c->nlen = ni.vlen;
                        c->e = ei.val; c->elen = ei.vlen;
                    }
                }
            }
        }
    }
    if (!c->iss_name.tag || !c->subj_name.tag || !c->n) return 0;
    der_name_cn(&c->subj_name, c->subj_cn, sizeof(c->subj_cn));

    /* signatureAlgorithm + signatureValue (siblings after tbs) */
    {
        const unsigned char *q = tbs.hdr + tbs.total,
                            *qe = der + n;
        der_t algseq, oid, sigb;
        if (der_iter(&q, qe, &algseq) && algseq.tag == 0x30) {
            const unsigned char *r = algseq.val,
                                *re = algseq.val + algseq.vlen;
            if (der_iter(&r, re, &oid))
                c->sig_alg = dg_alg_from_sigoid(&oid);
            else c->sig_alg = DG_NONE;
        } else c->sig_alg = DG_NONE;
        if (der_iter(&q, qe, &sigb) && sigb.tag == 0x03 && sigb.vlen > 1) {
            c->sig = sigb.val + 1;             /* skip unused-bits byte */
            c->siglen = sigb.vlen - 1;
        }
    }
    return 1;
}

static int x509_verify_sig(const xcrt_t *subject, const xcrt_t *issuer)
{
    unsigned char h[32];
    const unsigned char *di;
    size_t dil;
    if (!subject->sig || !issuer->n || subject->sig_alg == DG_NONE) return 0;
    di = dg_prefix(subject->sig_alg, &dil);
    if (!di) return 0;
    dg_compute(subject->sig_alg, subject->tbs, subject->tbslen, h);
    return rsa_pkcs1_verify(issuer->n, issuer->nlen, issuer->e, issuer->elen,
                          subject->sig, subject->siglen,
                          di, dil, h, dg_len(subject->sig_alg));
}

static int name_eq(const der_t *a, const der_t *b)
{
    return a->vlen == b->vlen && !memcmp(a->val, b->val, a->vlen);
}

/* ---- PKCS#7 SignedData ---------------------------------------------- */

#define MAX_BUNDLE_CERTS 8

static const char *sc_why;
static const char *sigcheck_last_error(void)
{ return sc_why ? sc_why : "ok"; }
#define SCFAIL(r) do { sc_why = (r); return NULL; } while (0)

static const char *pkcs7_verify(const unsigned char *p7, size_t n,
                                const unsigned char *pefile, size_t pelen,
                                anchor_cb anchor, void *ctx)
{
    static const unsigned char O_SIGNED[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,
                                             0x01,0x07,0x02};
    der_t top, a0, sdata, el, ci, certs, sinfos, si, attr, aoid, aval;
    const unsigned char *p, *end;
    xcrt_t xc[MAX_BUNDLE_CERTS];
    int ncert = 0, i, j;
    der_t econt;
    int have_econt = 0;
    int dg_alg = DG_NONE;
    const unsigned char *s_sig = NULL, *aattr = NULL, *md = NULL;
    size_t s_siglen = 0, aattr_len = 0, mdlen = 0, aattr_hdr = 0;
    der_t si_issuer, si_serial;
    int signer_i = -1;
    unsigned char content_hash[32], pe_hash[32], attr_hash[32];
    unsigned char set_hdr[8];
    const unsigned char *di;
    size_t dil;

    memset(xc, 0, sizeof(xc));
    memset(&si_issuer, 0, sizeof(si_issuer));
    memset(&si_serial, 0, sizeof(si_serial));
    memset(&econt, 0, sizeof(econt));
    memset(&certs, 0, sizeof(certs));
    memset(&sinfos, 0, sizeof(sinfos));
    sc_why = NULL;

    /* ContentInfo { oid signedData, [0] SignedData } */
    p = p7; end = p7 + n;
    if (!der_iter(&p, end, &top) || top.tag != 0x30)
        SCFAIL("bad ContentInfo");
    {
        const unsigned char *q = top.val, *qe = top.val + top.vlen;
        der_t oid;
        if (!der_iter(&q, qe, &oid) ||
            !der_oid_eq(&oid, O_SIGNED, sizeof(O_SIGNED)))
            SCFAIL("not signedData");
        if (!der_iter(&q, qe, &a0) || a0.tag != 0xa0 ||
            !der_first(&a0, &sdata) || sdata.tag != 0x30)
            SCFAIL("no SignedData");
    }

    /* SignedData: version, digestAlgs, contentInfo, [0]certs?, [1]crls?,
     * signerInfos */
    p = sdata.val; end = sdata.val + sdata.vlen;
    if (!der_iter(&p, end, &el)) SCFAIL("no version");
    if (!der_iter(&p, end, &el)) SCFAIL("no digestAlgs");
    if (!der_iter(&p, end, &ci) || ci.tag != 0x30) SCFAIL("no contentInfo");
    {
        const unsigned char *q = ci.val, *qe = ci.val + ci.vlen;
        der_t oid, ec;
        if (der_iter(&q, qe, &oid) && der_iter(&q, qe, &ec) &&
            ec.tag == 0xa0 && der_first(&ec, &econt))
            have_econt = 1;
    }
    while (p < end && der_iter(&p, end, &el)) {
        if (el.tag == 0xa0) certs = el;
        else if (el.tag == 0x31) sinfos = el;
    }
    if (!certs.val || !sinfos.val) SCFAIL("no certs/signerInfos");
    if (!have_econt) SCFAIL("detached signature (no eContent)");

    p = certs.val; end = certs.val + certs.vlen;
    while (p < end && ncert < MAX_BUNDLE_CERTS) {
        const unsigned char *certp = p;
        if (!der_iter(&p, end, &el) || el.tag != 0x30) break;
        if (x509_parse(certp, el.total, &xc[ncert])) ncert++;
    }
    if (!ncert) SCFAIL("no parseable certificates");

    if (!der_first(&sinfos, &si) || si.tag != 0x30)
        SCFAIL("bad signerInfo");
    p = si.val; end = si.val + si.vlen;
    if (!der_iter(&p, end, &el)) SCFAIL("no si version");
    if (!der_iter(&p, end, &el) || el.tag != 0x30)
        SCFAIL("no issuerAndSerial");
    {
        const unsigned char *q = el.val, *qe = el.val + el.vlen;
        if (!der_iter(&q, qe, &si_issuer) || si_issuer.tag != 0x30 ||
            !der_iter(&q, qe, &si_serial))
            SCFAIL("bad issuerAndSerial");
    }
    if (!der_iter(&p, end, &el) || el.tag != 0x30)
        SCFAIL("no digestAlg");
    {
        der_t oid;
        const unsigned char *q = el.val, *qe = el.val + el.vlen;
        if (!der_iter(&q, qe, &oid)) SCFAIL("bad digestAlg");
        dg_alg = dg_alg_from_oid(&oid);
        if (dg_alg == DG_NONE) SCFAIL("unsupported digest algorithm");
    }
    while (p < end) {
        if (!der_iter(&p, end, &el)) SCFAIL("si parse error");
        if (el.tag == 0xa0) {
            aattr = el.val; aattr_len = el.vlen; aattr_hdr = el.hlen;
        } else if (el.tag == 0x04) {
            s_sig = el.val; s_siglen = el.vlen;
        }
    }
    if (!aattr || !s_sig) SCFAIL("no signedAttrs/signature");

    /* messageDigest attribute */
    {
        static const unsigned char O_MD[] = {0x2a,0x86,0x48,0x86,0xf7,0x0d,
                                             0x01,0x09,0x04};
        const unsigned char *q = aattr, *qe = aattr + aattr_len;
        while (q < qe && der_iter(&q, qe, &attr)) {
            const unsigned char *r = attr.val, *re = attr.val + attr.vlen;
            if (attr.tag != 0x30 || !der_iter(&r, re, &aoid)) continue;
            if (der_oid_eq(&aoid, O_MD, sizeof(O_MD)) &&
                der_iter(&r, re, &aval) && aval.tag == 0x31 &&
                der_first(&aval, &aoid) && aoid.tag == 0x04 &&
                aoid.vlen == dg_len(dg_alg)) {
                md = aoid.val; mdlen = aoid.vlen;
            }
        }
    }
    if (!md || mdlen != dg_len(dg_alg)) SCFAIL("no messageDigest");

    /* messageDigest == hash(eContent): OCTET STRING hashes octets only,
     * other element types hash the whole DER element */
    if (econt.tag == 0x04)
        dg_compute(dg_alg, econt.val, econt.vlen, content_hash);
    else
        dg_compute(dg_alg, econt.hdr, econt.total, content_hash);
    if (memcmp(content_hash, md, mdlen))
        SCFAIL("messageDigest mismatch");

    /* Authenticode binding: the PE image hash must be inside the signed
     * content (SpcIndirectDataContent digest) */
    if (pefile) {
        size_t i2;
        int ok = 0;
        if (!pe_authcode_digest(pefile, pelen, dg_alg, pe_hash))
            SCFAIL("cannot compute PE hash");
        for (i2 = 0; i2 + mdlen <= econt.vlen; i2++)
            if (!memcmp(econt.val + i2, pe_hash, mdlen)) { ok = 1; break; }
        if (!ok) SCFAIL("signature not bound to this image");
    }

    /* signer cert: the issuerAndSerialNumber names the cert's ISSUER and
     * the cert's own serial */
    for (i = 0; i < ncert; i++) {
        der_t nm = xc[i].iss_name;
        if (name_eq(&nm, &si_issuer) &&
            der_int_eq(&si_serial, xc[i].serial, xc[i].serlen)) {
            signer_i = i; break;
        }
    }
    if (signer_i < 0) SCFAIL("signer cert not in bundle");

    /* RSASSA signature over authenticated attributes (SET-tagged DER) */
    if (aattr_hdr > sizeof(set_hdr)) SCFAIL("attr header too long");
    set_hdr[0] = 0x31;
    memcpy(set_hdr + 1, aattr - aattr_hdr + 1, aattr_hdr - 1);
    {
        void *c;
        sha1_ctx c1; sha256_ctx c256;
        void (*upd)(void *, const void *, size_t);
        void (*fin)(void *, unsigned char *);
        if (dg_alg == DG_SHA1) {
            sha1_init(&c1); c = &c1;
            upd = (void (*)(void *, const void *, size_t))sha1_update;
            fin = (void (*)(void *, unsigned char *))sha1_final;
        } else {
            sha256_init(&c256); c = &c256;
            upd = (void (*)(void *, const void *, size_t))sha256_update;
            fin = (void (*)(void *, unsigned char *))sha256_final;
        }
        upd(c, set_hdr, aattr_hdr);
        upd(c, aattr, aattr_len);
        fin(c, attr_hash);
    }
    di = dg_prefix(dg_alg, &dil);
    if (!di || !rsa_pkcs1_verify(xc[signer_i].n, xc[signer_i].nlen,
                          xc[signer_i].e, xc[signer_i].elen,
                          s_sig, s_siglen, di, dil,
                          attr_hash, dg_len(dg_alg)))
        SCFAIL("signature verification failed");

    /* chain: verify each cert against candidate issuers, then propagate
     * trust down from anchors */
    for (i = 0; i < ncert; i++)
        for (j = 0; j < ncert; j++)
            if (i != j && name_eq(&xc[i].iss_name, &xc[j].subj_name) &&
                x509_verify_sig(&xc[i], &xc[j]))
                xc[i].verified_by = j;
    for (i = 0; i < ncert; i++)
        xc[i].trusted = anchor(xc[i].der, xc[i].derlen, ctx) != NULL;
    for (;;) {
        int changed = 0;
        for (i = 0; i < ncert; i++)
            if (!xc[i].trusted && xc[i].verified_by >= 0 &&
                xc[xc[i].verified_by].trusted) {
                xc[i].trusted = 1; changed = 1;
            }
        if (!changed) break;
    }
    if (!xc[signer_i].trusted) SCFAIL("no chain to trusted anchor");

    {
        int cur = signer_i, hops = 0;
        const char *nm;
        while (hops++ < MAX_BUNDLE_CERTS) {
            nm = anchor(xc[cur].der, xc[cur].derlen, ctx);
            if (nm) return nm;
            if (xc[cur].verified_by < 0) break;
            cur = xc[cur].verified_by;
        }
    }
    return "verified CA";
}

/* top level: verify the embedded Authenticode signature of a PE file.
 * Returns anchor CA name on success, NULL otherwise. */
static const char *efi_sig_verify(const unsigned char *pefile, size_t pelen,
                                  anchor_cb anchor, void *ctx)
{
    struct pe_sig s;
    if (!pe_signature_blob(pefile, pelen, &s)) return NULL;
    return pkcs7_verify(s.p7, s.p7len, pefile, pelen, anchor, ctx);
}

#endif
