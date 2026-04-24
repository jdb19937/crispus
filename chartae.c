/*
 * chartae.c — hex et base64
 */

#include "chartae.h"

#include <string.h>

/* --- hex --- */

void hex_ad(char *hex, const uint8_t *octeti, size_t n)
{
    const char *CHARS = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        hex[2*i    ] = CHARS[(octeti[i] >> 4) & 0xF];
        hex[2*i + 1] = CHARS[ octeti[i]       & 0xF];
    }
}

static int valor_hex(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

int hex_ex(uint8_t *octeti, size_t n, const char *hex)
{
    size_t scripti = 0;
    int hi = -1;
    for (const char *p = hex; *p != '\0'; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') continue;
        int v = valor_hex(*p);
        if (v < 0) return -1;
        if (hi < 0) {
            hi = v;
        } else {
            if (scripti >= n) return -1;
            octeti[scripti++] = (uint8_t)((hi << 4) | v);
            hi = -1;
        }
    }
    if (hi >= 0) return -1;
    if (scripti != n) return -1;
    return 0;
}

/* --- base64 --- */

static const char *B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t base64_longitudo_output(size_t n)
{
    return ((n + 2) / 3) * 4;
}

size_t base64_ad(char *out, const uint8_t *octeti, size_t n)
{
    size_t scripti = 0;
    size_t i = 0;
    while (i + 3 <= n) {
        uint32_t v = ((uint32_t)octeti[i] << 16)
                   | ((uint32_t)octeti[i+1] << 8)
                   |  (uint32_t)octeti[i+2];
        out[scripti++] = B64_CHARS[(v >> 18) & 0x3F];
        out[scripti++] = B64_CHARS[(v >> 12) & 0x3F];
        out[scripti++] = B64_CHARS[(v >>  6) & 0x3F];
        out[scripti++] = B64_CHARS[ v        & 0x3F];
        i += 3;
    }
    size_t residua = n - i;
    if (residua == 1) {
        uint32_t v = (uint32_t)octeti[i] << 16;
        out[scripti++] = B64_CHARS[(v >> 18) & 0x3F];
        out[scripti++] = B64_CHARS[(v >> 12) & 0x3F];
        out[scripti++] = '=';
        out[scripti++] = '=';
    } else if (residua == 2) {
        uint32_t v = ((uint32_t)octeti[i] << 16) | ((uint32_t)octeti[i+1] << 8);
        out[scripti++] = B64_CHARS[(v >> 18) & 0x3F];
        out[scripti++] = B64_CHARS[(v >> 12) & 0x3F];
        out[scripti++] = B64_CHARS[(v >>  6) & 0x3F];
        out[scripti++] = '=';
    }
    return scripti;
}

static int valor_b64(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return 26 + (c - 'a');
    if (c >= '0' && c <= '9') return 52 + (c - '0');
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

int base64_ex(uint8_t *out, size_t n, const char *in)
{
    size_t scripti = 0;
    int quatuor[4];
    int qn = 0;

    for (const char *p = in; *p != '\0'; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') continue;
        if (*p == '=') break;
        int v = valor_b64(*p);
        if (v < 0) return -1;
        quatuor[qn++] = v;
        if (qn == 4) {
            uint32_t x = ((uint32_t)quatuor[0] << 18)
                       | ((uint32_t)quatuor[1] << 12)
                       | ((uint32_t)quatuor[2] <<  6)
                       |  (uint32_t)quatuor[3];
            if (scripti + 3 > n) return -1;
            out[scripti++] = (uint8_t)((x >> 16) & 0xFF);
            out[scripti++] = (uint8_t)((x >>  8) & 0xFF);
            out[scripti++] = (uint8_t)( x        & 0xFF);
            qn = 0;
        }
    }
    if (qn == 2) {
        uint32_t x = ((uint32_t)quatuor[0] << 18) | ((uint32_t)quatuor[1] << 12);
        if (scripti + 1 > n) return -1;
        out[scripti++] = (uint8_t)((x >> 16) & 0xFF);
    } else if (qn == 3) {
        uint32_t x = ((uint32_t)quatuor[0] << 18)
                   | ((uint32_t)quatuor[1] << 12)
                   | ((uint32_t)quatuor[2] <<  6);
        if (scripti + 2 > n) return -1;
        out[scripti++] = (uint8_t)((x >> 16) & 0xFF);
        out[scripti++] = (uint8_t)((x >>  8) & 0xFF);
    } else if (qn != 0) {
        return -1;
    }
    (void)memset;  /* silentia monitiones */
    if (scripti != n) return -1;
    return 0;
}
