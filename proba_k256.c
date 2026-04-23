/*
 * proba_k256.c — probationes ECDSA secp256k1
 */

#include "arcana.h"

#include <stdio.h>
#include <string.h>

static int successae = 0;
static int defectae  = 0;

#define PROBA(nomen, cond) do { \
    if (cond) { successae++; printf("  succedit  %s\n", nomen); } \
    else { defectae++; printf("  deficit   %s\n", nomen); } \
} while(0)

/* Verifica quod G est super curvam: G.y^2 == G.x^3 + 7 mod p.
 * Adhibemus nm_modmul directe. */
static int g_super_curvam(void)
{
    const curva_t *k = &CURVA_SECP256K1;
    nm_t y2, x2, x3, dextra, septem;

    nm_modmul(&y2, &k->G.y, &k->G.y, &k->p);
    nm_modmul(&x2, &k->G.x, &k->G.x, &k->p);
    nm_modmul(&x3, &x2,     &k->G.x, &k->p);

    nm_ex_nihilo(&septem);
    septem.v[0] = 7;
    septem.n = 1;

    nm_adde(&dextra, &x3, &septem);
    if (nm_compara(&dextra, &k->p) >= 0) {
        nm_subtrahe(&dextra, &dextra, &k->p);
    }

    return nm_compara(&y2, &dextra) == 0;
}

static void proba(void)
{
    printf("k256:\n");

    /* G est super curvam */
    PROBA("G super secp256k1", g_super_curvam());

    /* n*G = infinitum */
    {
        ec_punctum_t r;
        ec_multiplica_curva(&r, &CURVA_SECP256K1.n, &CURVA_SECP256K1.G, &CURVA_SECP256K1);
        PROBA("n*G = O (infinitum)", r.infinitum);
    }

    /* 1*G = G */
    {
        ec_punctum_t r;
        nm_t unum;
        nm_ex_nihilo(&unum);
        unum.v[0] = 1;
        unum.n = 1;
        ec_multiplica_curva(&r, &unum, &CURVA_SECP256K1.G, &CURVA_SECP256K1);
        PROBA("1*G = G",
            !r.infinitum &&
            nm_compara(&r.x, &CURVA_SECP256K1.G.x) == 0 &&
            nm_compara(&r.y, &CURVA_SECP256K1.G.y) == 0
        );
    }

    /* 2*G != G */
    {
        ec_punctum_t r;
        nm_t duo;
        nm_ex_nihilo(&duo);
        duo.v[0] = 2;
        duo.n = 1;
        ec_multiplica_curva(&r, &duo, &CURVA_SECP256K1.G, &CURVA_SECP256K1);
        PROBA("2*G != G", !r.infinitum && nm_compara(&r.x, &CURVA_SECP256K1.G.x) != 0);
    }

    /* Sign + verify round-trip */
    {
        /* privata = 42 */
        nm_t d;
        nm_ex_nihilo(&d);
        d.v[0] = 42;
        d.n = 1;

        ec_punctum_t Q;
        k256_publica(&Q, &d);
        PROBA("Q = 42*G non infinitum", !Q.infinitum);

        uint8_t digestum[32];
        summa256((const uint8_t *)"salve mundi", 11, digestum);

        uint8_t sig[64];
        k256_ecdsa_signa(sig, &d, digestum);

        PROBA("signatura verificat", k256_ecdsa_verifica(&Q, digestum, sig) == 1);

        /* Prava digestum = non verificat */
        uint8_t pravum[32];
        memcpy(pravum, digestum, 32);
        pravum[0] ^= 0x01;
        PROBA("digestum pravum non verificat",
              k256_ecdsa_verifica(&Q, pravum, sig) == 0);

        /* Prava signatura = non verificat */
        uint8_t pravaSig[64];
        memcpy(pravaSig, sig, 64);
        pravaSig[0] ^= 0x01;
        PROBA("signatura prava non verificat",
              k256_ecdsa_verifica(&Q, digestum, pravaSig) == 0);
    }

    /* Signaturae variae ab eodem digesto (k aleatorium) */
    {
        nm_t d;
        nm_ex_nihilo(&d);
        d.v[0] = 12345;
        d.n = 1;

        ec_punctum_t Q;
        k256_publica(&Q, &d);

        uint8_t digestum[32];
        summa256((const uint8_t *)"iterum", 6, digestum);

        uint8_t s1[64], s2[64];
        k256_ecdsa_signa(s1, &d, digestum);
        k256_ecdsa_signa(s2, &d, digestum);

        PROBA("duae signaturae verificant ambae",
              k256_ecdsa_verifica(&Q, digestum, s1) &&
              k256_ecdsa_verifica(&Q, digestum, s2));
        /* Debent differre quia k aleatorium */
        PROBA("duae signaturae differunt (k aleatorium)", memcmp(s1, s2, 64) != 0);
    }
}

int main(void)
{
    proba();
    printf("\n%d succedit, %d deficit\n", successae, defectae);
    return defectae == 0 ? 0 : 1;
}
