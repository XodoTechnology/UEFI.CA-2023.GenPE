/* Native test for the PKCS#7 / Authenticode verifier (sigcheck.h).
 * Fixtures (tests/gen_fixtures.sh): throwaway CA+leaf and a minimal PE
 * carrying a real openssl cms signature bound to its own Authenticode hash.
 *
 *   gcc -Isrc -o build/test_sigcheck tests/test_sigcheck.c
 */
#define WCHAR wchar_t
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha1.h"
#include "sigcheck.h"

static int fails;
#define CHECK(cond, ...) do { \
    if (cond) printf("  ok   " __VA_ARGS__), putchar('\n'); \
    else fails++, printf("  FAIL " __VA_ARGS__), putchar('\n'); \
} while (0)

static unsigned char *slurp(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    unsigned char *b;
    long s;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); s = ftell(f); fseek(f, 0, SEEK_SET);
    b = malloc(s);
    if (fread(b, 1, s, f) != (size_t)s) { fclose(f); free(b); return NULL; }
    fclose(f); *n = s;
    return b;
}

static unsigned char *g_ca; static size_t g_can;

static const char *anchor_ok(const unsigned char *der, size_t len, void *ctx)
{
    (void)ctx;
    if (len == g_can && !memcmp(der, g_ca, len)) return "GenPE Test UEFI CA 2023";
    return NULL;
}

static const char *no_anchor(const unsigned char *d, size_t l, void *c)
{ (void)d; (void)l; (void)c; return NULL; }

int main(void)
{
    unsigned char *pe, *p7;
    size_t pn, p7n;
    const char *r;

    g_ca = slurp("tests/fixtures/ca.der", &g_can);
    CHECK(g_ca != NULL, "loaded test CA");

    printf("bignum primitives\n");
    {
        /* 3^40 mod 23 = 4 (3^40 = (3^4)^10, 3^4=81, 81^10 mod23: 81%23=12,
         * 12^10 mod23 = ... just check consistency) */
        bn_t b, m, r;
        unsigned char e = 5;
        unsigned char nb[1] = {23}, bb[1] = {3};
        bn_from_be(&m, nb, 1); bn_from_be(&b, bb, 1);
        bn_modexp(&r, &b, &e, 1, &m);
        /* 3^5=243, 243 mod 23 = 243-230 = 13 */
        CHECK(r.n == 1 && r.w[0] == 13, "3^5 mod 23 == 13 (got %u)",
              r.n ? r.w[0] : 0);
    }

    printf("PKCS#7 signature verification (openssl cms artifact)\n");
    p7 = slurp("tests/fixtures/sig.p7", &p7n);
    CHECK(p7 != NULL, "loaded sig.p7 (%zu bytes)", p7n);
    if (p7) {
        r = pkcs7_verify(p7, p7n, NULL, 0, anchor_ok, NULL);
        if (!r) printf("       (why: %s)\n", sigcheck_last_error());
        CHECK(r != NULL, "cms signature verifies -> '%s'", r ? r : "?");
        CHECK(r && strstr(r, "Test UEFI CA"), "anchor name is test CA");

        /* corrupted signature must fail */
        p7[p7n - 20] ^= 0xff;
        CHECK(pkcs7_verify(p7, p7n, NULL, 0, anchor_ok, NULL) == NULL,
              "corrupted p7 rejected");
        p7[p7n - 20] ^= 0xff;
    }

    printf("full PE Authenticode verification\n");
    pe = slurp("tests/fixtures/signed_pe.bin", &pn);
    CHECK(pe != NULL, "loaded signed_pe.bin (%zu bytes)", pn);
    if (pe) {
        r = efi_sig_verify(pe, pn, anchor_ok, NULL);
        if (!r) printf("       (why: %s)\n", sigcheck_last_error());
        CHECK(r != NULL, "signed PE verifies -> '%s'", r ? r : "?");
        free(pe);
    }

    pe = slurp("tests/fixtures/tampered_pe.bin", &pn);
    if (pe) {
        CHECK(efi_sig_verify(pe, pn, anchor_ok, NULL) == NULL,
              "tampered image body rejected (hash binding)");
        free(pe);
    }

    pe = slurp("tests/fixtures/badsig_pe.bin", &pn);
    if (pe) {
        CHECK(efi_sig_verify(pe, pn, anchor_ok, NULL) == NULL,
              "corrupted signature blob rejected");
        free(pe);
    }

    /* wrong anchor: CA not trusted */
    {
        pe = slurp("tests/fixtures/signed_pe.bin", &pn);
        CHECK(efi_sig_verify(pe, pn, no_anchor, NULL) == NULL,
              "untrusted chain rejected");
        free(pe);
    }

    /* unsigned file */
    {
        unsigned char junk[512];
        memset(junk, 0x5a, sizeof(junk));
        CHECK(efi_sig_verify(junk, sizeof(junk), anchor_ok, NULL) == NULL,
              "non-PE rejected");
    }

    printf("\n%s\n", fails ? "FAILURES" : "all tests passed");
    return fails ? 1 : 0;
}
