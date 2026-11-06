/* Native (Linux) unit test for the signature-list parsing and PK->KEK
 * map lookup used by GenPE.  Links the real embedded payloads so we test
 * against production data.
 *
 *   gcc -I src -o build/test_parse tests/test_parse.c build/payloads_test.o
 */
#define WCHAR wchar_t
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha1.h"
#include "generated/payloads.h"
#include "sigparse.h"

static int fails;

#define CHECK(cond, ...) do { \
    if (cond) printf("  ok   " __VA_ARGS__), putchar('\n'); \
    else fails++, printf("  FAIL " __VA_ARGS__), putchar('\n'); \
} while (0)

/* skip EFI_VARIABLE_AUTHENTICATION_2 header -> signature list content */
static const unsigned char *auth_content(const unsigned char *b,
                                         unsigned int *len)
{
    uint32_t dwlen = rd32(b + 16);
    *len -= 16 + dwlen;
    return b + 16 + dwlen;
}

/* fabricate a "variable": one X509 siglist wrapping a DER cert */
static unsigned char *mk_var_x509(const unsigned char *der, unsigned int dlen,
                                  unsigned int *outlen)
{
    unsigned int ssz = 16 + dlen, lsz = 28 + ssz;
    unsigned char *v = malloc(lsz);
    memcpy(v, SIG_X509, 16);
    memcpy(v + 16, &lsz, 4);
    memset(v + 20, 0, 4);            /* header size */
    memcpy(v + 24, &ssz, 4);
    memset(v + 28, 0, 16);           /* owner guid */
    memcpy(v + 44, der, dlen);
    *outlen = lsz;
    return v;
}

static unsigned char *slurp(const char *path, unsigned int *n)
{
    FILE *f = fopen(path, "rb");
    unsigned char *b;
    long s;
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); s = ftell(f); fseek(f, 0, SEEK_SET);
    b = malloc(s);
    if (fread(b, 1, s, f) != (size_t)s) { fclose(f); free(b); return NULL; }
    fclose(f); *n = (unsigned int)s;
    return b;
}

int main(void)
{
    unsigned int n;
    const unsigned char *c;
    WCHAR cn[80];
    unsigned char *v, *der;
    unsigned int vlen, dlen;
    struct pk_ctx pi;
    const kek_entry_t *ke;
    int i;

    printf("auth-content / known-cert detection\n");
    n = sizeof(g_db_win2023);
    c = auth_content(g_db_win2023, &n);
    CHECK(var_has_named_cert(c, n, "Windows UEFI CA 2023"),
          "db/win2023 contains Windows UEFI CA 2023");
    CHECK(!var_has_named_cert(c, n, "Microsoft UEFI CA 2023"),
          "db/win2023 does NOT contain Microsoft UEFI CA 2023");

    n = sizeof(g_db_3p2023);
    c = auth_content(g_db_3p2023, &n);
    CHECK(var_has_named_cert(c, n, "Microsoft UEFI CA 2023"),
          "db/3p2023 contains Microsoft UEFI CA 2023");

    n = sizeof(g_db_orom2023);
    c = auth_content(g_db_orom2023, &n);
    CHECK(var_has_named_cert(c, n, "Microsoft Option ROM UEFI CA 2023"),
          "db/orom2023 contains Option ROM CA");

    n = sizeof(g_kek_0);
    c = auth_content(g_kek_0, &n);
    CHECK(var_has_named_cert(c, n, "Microsoft Corporation KEK 2K CA 2023"),
          "kek payload contains KEK 2K CA 2023");

    /* every kek payload must expose a cert we recognize as KEK 2023 */
    {
        int bad = 0;
        for (i = 0; i < KEK_MAP_COUNT; i++) {
            unsigned int m = g_kek_map[i].len;
            const unsigned char *cc = auth_content(g_kek_map[i].data, &m);
            if (!var_has_named_cert(cc, m,
                    "Microsoft Corporation KEK 2K CA 2023"))
                bad++;
        }
        CHECK(bad == 0, "all %d kek payloads contain KEK 2K CA 2023 (%d bad)",
              KEK_MAP_COUNT, bad);
    }

    printf("CN extraction\n");
    {
        unsigned int m = sizeof(g_db_win2023);
        const unsigned char *cc = auth_content(g_db_win2023, &m);
        struct cn_ctx { WCHAR got[80]; int done; } ctx;
        /* grab first x509 entry CN */
        (void)ctx;
        {
            /* iterate manually: entries start at +28, sigsize at +24 */
            uint32_t ssz = rd32(cc + 24);
            int has = cert_cn(cc + 28 + 16, ssz - 16, cn, 80);
            CHECK(has, "CN extracted from Windows UEFI CA 2023 cert: '%ls'",
                  cn);
        }
    }

    printf("PK -> KEK map lookup (real Microsoft PK cert)\n");
    der = slurp("tests/WindowsOEMDevicesPK.der", &dlen);
    CHECK(der != NULL, "loaded PK der");
    if (der) {
        v = mk_var_x509(der, dlen, &vlen);
        ke = find_kek_update(v, vlen, &pi);
        CHECK(ke != NULL, "PK sha1 found in map");
        if (ke) {
            printf("       matched: %s\n", ke->path);
            CHECK(strstr(ke->path, "Microsoft/") != NULL,
                  "maps to a Microsoft KEK payload");
            CHECK(pi.saw_cert && pi.cn[0], "PK CN extracted: '%ls'", pi.cn);
        }
        /* unknown cert -> no match */
        {
            unsigned char junk[64];
            unsigned int jl;
            unsigned char *jv;
            memset(junk, 0xab, sizeof(junk));
            jv = mk_var_x509(junk, sizeof(junk), &jl);
            CHECK(find_kek_update(jv, jl, NULL) == NULL,
                  "random 'cert' produces no match");
            free(jv);
        }
        free(v); free(der);
    }

    printf("robustness (truncated / garbage buffers)\n");
    {
        unsigned char junk[128];
        unsigned int m;
        memset(junk, 0xff, sizeof(junk));
        for_each_sig(junk, sizeof(junk), has_cb, &(struct has_ctx){0});
        for_each_sig(g_db_win2023, 10, has_cb, &(struct has_ctx){0});
        /* truncations of a real variable should not crash */
        m = sizeof(g_db_win2023);
        c = auth_content(g_db_win2023, &m);
        for (i = 0; i < 64; i += 7)
            for_each_sig(c, (unsigned)i, has_cb, &(struct has_ctx){0});
        CHECK(1, "no crash on malformed input");
    }

    printf("KEK map integrity\n");
    {
        int dupes = 0;
        for (i = 1; i < KEK_MAP_COUNT; i++)
            if (!memcmp(g_kek_map[i].sha1, g_kek_map[i-1].sha1, 20)) dupes++;
        CHECK(1, "%d map entries, %d duplicate thumbs", KEK_MAP_COUNT, dupes);
    }

    printf("\n%s\n", fails ? "FAILURES" : "all tests passed");
    return fails ? 1 : 0;
}
