/*
 * summa3.c — SHA3-256 (FIPS 202)
 *
 * Implementatio Keccak-f[1600] cum suffixo paddationis SHA-3 (0x06).
 * Rata (rate) 136 octetorum, capacitas 64 octetorum (512 bita).
 * Sine dependentiis externis.
 */

#include "arcana.h"
#include <string.h>

/* --- constantiae Keccak-f[1600] --- */

static const uint64_t ROTUNDAE[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

static const unsigned ROTATIONES[25] = {
    0,  1, 62, 28, 27,
    36, 44,  6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21,  8,
    18,  2, 61, 56, 14
};

#define SINISTRO(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define RATA 136    /* 1088 bits */

/* --- lector/scriptor parva endiana --- */

static uint64_t lege64_le(const uint8_t *p)
{
    uint64_t x = 0;
    for (int i = 0; i < 8; i++) {
        x |= ((uint64_t)p[i]) << (i * 8);
    }
    return x;
}

static void scribe64_le(uint8_t *p, uint64_t x)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(x >> (i * 8));
    }
}

/* --- permutatio Keccak-f[1600] --- */

static void keccak_f(uint64_t A[25])
{
    uint64_t C[5], D[5], B[25];
    for (int rotunda = 0; rotunda < 24; rotunda++) {
        /* theta */
        for (int x = 0; x < 5; x++) {
            C[x] = A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20];
        }
        for (int x = 0; x < 5; x++) {
            D[x] = C[(x + 4) % 5] ^ SINISTRO(C[(x + 1) % 5], 1);
        }
        for (int i = 0; i < 25; i++) {
            A[i] ^= D[i % 5];
        }

        /* rho et pi */
        for (int x = 0; x < 5; x++) {
            for (int y = 0; y < 5; y++) {
                int i = x + 5 * y;
                unsigned r = ROTATIONES[i];
                uint64_t v = (r == 0) ? A[i] : SINISTRO(A[i], r);
                int nx = y;
                int ny = (2 * x + 3 * y) % 5;
                B[nx + 5 * ny] = v;
            }
        }

        /* chi */
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                A[x + 5 * y] = B[x + 5 * y] ^
                    ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y]);
            }
        }

        /* iota */
        A[0] ^= ROTUNDAE[rotunda];
    }
}

/* --- absorptio alvei pleni in statum --- */

static void absorbe(uint64_t status[25], const uint8_t alveus[RATA])
{
    /* RATA / 8 = 17 lanae */
    for (int i = 0; i < 17; i++) {
        status[i] ^= lege64_le(alveus + i * 8);
    }
    keccak_f(status);
}

/* --- interfaz --- */

void summa3_256_initia(summa3_256_ctx_t *ctx)
{
    memset(ctx->status, 0, sizeof(ctx->status));
    memset(ctx->alveus, 0, sizeof(ctx->alveus));
    ctx->index_alvei = 0;
}

void summa3_256_adde(summa3_256_ctx_t *ctx, const uint8_t *data, size_t longitudo)
{
    for (size_t i = 0; i < longitudo; i++) {
        ctx->alveus[ctx->index_alvei++] = data[i];
        if (ctx->index_alvei == RATA) {
            absorbe(ctx->status, ctx->alveus);
            ctx->index_alvei = 0;
        }
    }
}

void summa3_256_fini(summa3_256_ctx_t *ctx, uint8_t digestum[32])
{
    /* paddatio SHA-3: 0x06 ad indicem, 0x80 ad finem ratae (XOR) */
    memset(ctx->alveus + ctx->index_alvei, 0, RATA - ctx->index_alvei);
    ctx->alveus[ctx->index_alvei] ^= 0x06;
    ctx->alveus[RATA - 1] ^= 0x80;
    absorbe(ctx->status, ctx->alveus);

    /* extractio primorum 32 octetorum (4 lanae) parva endiana */
    for (int i = 0; i < 4; i++) {
        scribe64_le(digestum + i * 8, ctx->status[i]);
    }

    memset(ctx->status, 0, sizeof(ctx->status));
    memset(ctx->alveus, 0, sizeof(ctx->alveus));
    ctx->index_alvei = 0;
}

void summa3_256(const uint8_t *data, size_t longitudo, uint8_t digestum[32])
{
    summa3_256_ctx_t ctx;
    summa3_256_initia(&ctx);
    summa3_256_adde(&ctx, data, longitudo);
    summa3_256_fini(&ctx, digestum);
}
