/*
 * k256.c — ECDSA super curva elliptica secp256k1
 *
 * Clavis publica: punctum Q = d*G super curva.
 * Clavis privata: scalar d in [1, n-1].
 * Signatura: par (r, s), octeti 64 (r || s) big-endian.
 *
 * Dependet a curva_t CURVA_SECP256K1 et nm_*, ec_*_curva functionibus.
 */

#include "arcana.h"

#include <string.h>

/* Helper localis (nm_est_nihil in numerus.c est static). */
static int est_nihil(const nm_t *a)
{
    for (int i = 0; i < a->n; i++) {
        if (a->v[i] != 0)
            return 0;
    }
    return 1;
}
#define nm_est_nihil est_nihil

/* --- publica ex privata --- */

void k256_publica(ec_punctum_t *publica, const nm_t *privata)
{
    ec_multiplica_curva(publica, privata, &CURVA_SECP256K1.G, &CURVA_SECP256K1);
}

/* --- reductio modulo n --- */

static void reduce_mod_n(nm_t *r, const nm_t *a)
{
    const nm_t *n = &CURVA_SECP256K1.n;
    if (nm_compara(a, n) < 0) {
        *r = *a;
    } else {
        nm_modulo(r, a, n);
    }
}

/* Inversio modulo n per theorema Fermati: a^(-1) = a^(n-2) mod n. */
static void inversa_mod_n(nm_t *r, const nm_t *a)
{
    nm_t n_minus_2, duo;
    nm_ex_nihilo(&duo);
    duo.v[0] = 2;
    duo.n    = 1;
    nm_subtrahe(&n_minus_2, &CURVA_SECP256K1.n, &duo);
    nm_modpot(r, a, &n_minus_2, &CURVA_SECP256K1.n);
}

static void mulmod_n(nm_t *r, const nm_t *a, const nm_t *b)
{
    nm_modmul(r, a, b, &CURVA_SECP256K1.n);
}

static void addmod_n(nm_t *r, const nm_t *a, const nm_t *b)
{
    nm_adde(r, a, b);
    if (nm_compara(r, &CURVA_SECP256K1.n) >= 0) {
        nm_subtrahe(r, r, &CURVA_SECP256K1.n);
    }
}

/* --- verifica signaturam --- */

int k256_ecdsa_verifica(
    const ec_punctum_t *publica,
    const uint8_t digestum[32],
    const uint8_t signatura[64]
)
{
    const nm_t *n = &CURVA_SECP256K1.n;
    nm_t r, s, z;

    nm_ex_octis(&r, signatura, 32);
    nm_ex_octis(&s, signatura + 32, 32);

    /* Valida: 1 <= r, s < n */
    if (nm_est_nihil(&r))
        return 0;
    if (nm_est_nihil(&s))
        return 0;
    if (nm_compara(&r, n) >= 0)
        return 0;
    if (nm_compara(&s, n) >= 0)
        return 0;

    /* z = digestum (32 oct big-endian) mod n */
    nm_t z_raw;
    nm_ex_octis(&z_raw, digestum, 32);
    reduce_mod_n(&z, &z_raw);

    /* w = s^-1 mod n */
    nm_t w;
    inversa_mod_n(&w, &s);

    /* u1 = z*w, u2 = r*w */
    nm_t u1, u2;
    mulmod_n(&u1, &z, &w);
    mulmod_n(&u2, &r, &w);

    /* R' = u1*G + u2*Q */
    ec_punctum_t pt1, pt2, R;
    ec_multiplica_curva(&pt1, &u1, &CURVA_SECP256K1.G, &CURVA_SECP256K1);
    ec_multiplica_curva(&pt2, &u2, publica, &CURVA_SECP256K1);
    ec_adde_curva(&R, &pt1, &pt2, &CURVA_SECP256K1);

    if (R.infinitum)
        return 0;

    /* v = R.x mod n; valida si v == r */
    nm_t v;
    reduce_mod_n(&v, &R.x);
    return nm_compara(&v, &r) == 0;
}

/* --- signa digestum --- */

void k256_ecdsa_signa(
    uint8_t signatura[64],
    const nm_t *privata,
    const uint8_t digestum[32]
)
{
    const nm_t *n = &CURVA_SECP256K1.n;

    nm_t z_raw, z;
    nm_ex_octis(&z_raw, digestum, 32);
    reduce_mod_n(&z, &z_raw);

    for (;;) {
        /* genera k aleatorium in [1, n-1] */
        uint8_t k_bytes[32];
        int rc = alea_imple(k_bytes, 32);
        if (rc != 0) {
            /* alea defecit — nitere iterum */
            continue;
        }
        nm_t k;
        nm_ex_octis(&k, k_bytes, 32);
        if (nm_est_nihil(&k))
            continue;
        if (nm_compara(&k, n) >= 0) {
            nm_modulo(&k, &k, n);
            if (nm_est_nihil(&k))
                continue;
        }

        /* R = k*G */
        ec_punctum_t R;
        ec_multiplica_curva(&R, &k, &CURVA_SECP256K1.G, &CURVA_SECP256K1);
        if (R.infinitum)
            continue;

        nm_t r;
        reduce_mod_n(&r, &R.x);
        if (nm_est_nihil(&r))
            continue;

        /* s = k^-1 * (z + r*d) mod n */
        nm_t rd, zrd, k_inv, s;
        mulmod_n(&rd, &r, privata);
        addmod_n(&zrd, &z, &rd);
        inversa_mod_n(&k_inv, &k);
        mulmod_n(&s, &k_inv, &zrd);
        if (nm_est_nihil(&s))
            continue;

        /* output (r || s) big-endian */
        nm_ad_octos(&r, signatura,      32);
        nm_ad_octos(&s, signatura + 32, 32);
        return;
    }
}
