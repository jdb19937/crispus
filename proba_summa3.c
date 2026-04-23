/*
 * crispus/proba_summa3.c — probationes SHA3-256
 *
 * Probatio cum vectoribus notis ex FIPS 202 / NIST.
 */

#include "arcana.h"

#include <stdio.h>
#include <string.h>

static int probationes_successae = 0;
static int probationes_defectae  = 0;

#define PROBA(nomen, cond) do { \
    if (cond) { probationes_successae++; printf("  succedit  %s\n", nomen); } \
    else { probationes_defectae++; printf("  deficit   %s\n", nomen); } \
} while(0)

static int aequus(const uint8_t *a, const uint8_t *b, size_t n)
{
    return memcmp(a, b, n) == 0;
}

static void proba_summa3(void)
{
    printf("SHA3-256:\n");

    /* SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a */
    {
        uint8_t digestum[32];
        summa3_256((const uint8_t *)"", 0, digestum);
        const uint8_t expectatum[32] = {
            0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
            0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
            0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
            0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
        };
        PROBA("SHA3-256(\"\")", aequus(digestum, expectatum, 32));
    }

    /* SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532 */
    {
        uint8_t digestum[32];
        summa3_256((const uint8_t *)"abc", 3, digestum);
        const uint8_t expectatum[32] = {
            0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
            0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
            0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
            0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32
        };
        PROBA("SHA3-256(\"abc\")", aequus(digestum, expectatum, 32));
    }

    /* SHA3-256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
     *   = 41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376 */
    {
        const char *nuntius =
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        uint8_t digestum[32];
        summa3_256((const uint8_t *)nuntius, strlen(nuntius), digestum);
        const uint8_t expectatum[32] = {
            0x41, 0xc0, 0xdb, 0xa2, 0xa9, 0xd6, 0x24, 0x08,
            0x49, 0x10, 0x03, 0x76, 0xa8, 0x23, 0x5e, 0x2c,
            0x82, 0xe1, 0xb9, 0x99, 0x8a, 0x99, 0x9e, 0x21,
            0xdb, 0x32, 0xdd, 0x97, 0x49, 0x6d, 0x33, 0x76
        };
        PROBA("SHA3-256(56 octeti)", aequus(digestum, expectatum, 32));
    }

    /* Probatio incrementalis: idem resultatum post adde() multa parva. */
    {
        const char *nuntius = "The quick brown fox jumps over the lazy dog";
        uint8_t d1[32], d2[32];
        summa3_256((const uint8_t *)nuntius, strlen(nuntius), d1);

        summa3_256_ctx_t ctx;
        summa3_256_initia(&ctx);
        for (size_t i = 0; i < strlen(nuntius); i++) {
            summa3_256_adde(&ctx, (const uint8_t *)(nuntius + i), 1);
        }
        summa3_256_fini(&ctx, d2);

        PROBA("SHA3-256 incrementum aequat totum", aequus(d1, d2, 32));
    }

    /* Probatio nuntii longi (200 A) ultra unum alveum (RATA=136): */
    {
        uint8_t nuntius[200];
        memset(nuntius, 'A', sizeof(nuntius));
        uint8_t digestum[32];
        summa3_256(nuntius, sizeof(nuntius), digestum);
        /* SHA3-256 of 200 'A' bytes */
        const uint8_t expectatum[32] = {
            0xbc, 0x58, 0x0b, 0x42, 0x95, 0xf7, 0xe8, 0x3e,
            0x85, 0xf5, 0xec, 0x16, 0xfd, 0x04, 0xe6, 0x9a,
            0xda, 0xe4, 0x84, 0xa7, 0xe0, 0xae, 0x91, 0x08,
            0xe7, 0xb6, 0xb2, 0xbe, 0xf6, 0xa2, 0x59, 0x98
        };
        PROBA("SHA3-256(200 'A')", aequus(digestum, expectatum, 32));
    }
}

int main(void)
{
    proba_summa3();
    printf("\n%d succedit, %d deficit\n",
        probationes_successae, probationes_defectae);
    return probationes_defectae == 0 ? 0 : 1;
}
