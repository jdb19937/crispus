/*
 * proba_chartae.c — probationes hex et base64
 */

#include "chartae.h"

#include <stdio.h>
#include <string.h>

static int successae = 0;
static int defectae  = 0;

#define PROBA(nomen, cond) do { \
    if (cond) { successae++; printf("  succedit  %s\n", nomen); } \
    else { defectae++; printf("  deficit   %s\n", nomen); } \
} while(0)

static void proba(void)
{
    printf("chartae:\n");

    /* hex round-trip */
    {
        uint8_t orig[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34 };
        char hex[13];
        hex_ad(hex, orig, 6);
        hex[12] = '\0';
        PROBA("hex scripta == 'deadbeef1234'", strcmp(hex, "deadbeef1234") == 0);

        uint8_t rursus[6];
        int rc = hex_ex(rursus, 6, hex);
        PROBA("hex_ex successit", rc == 0);
        PROBA("hex round-trip", memcmp(orig, rursus, 6) == 0);
    }

    /* base64 casus regulares */
    {
        uint8_t orig[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
        char out[16];
        size_t n = base64_ad(out, orig, 6);
        out[n] = '\0';

        uint8_t rursus[6];
        int rc = base64_ex(rursus, 6, out);
        PROBA("base64 ex successit", rc == 0);
        PROBA("base64 round-trip", memcmp(orig, rursus, 6) == 0);
    }

    /* casus residui 1 octeti */
    {
        uint8_t orig[] = { 0xFF };
        char out[8];
        size_t n = base64_ad(out, orig, 1);
        out[n] = '\0';
        uint8_t rursus[1];
        int rc = base64_ex(rursus, 1, out);
        PROBA("base64 unus octetum", rc == 0 && rursus[0] == 0xFF);
    }

    /* casus residui 2 octetorum */
    {
        uint8_t orig[] = { 0xAB, 0xCD };
        char out[8];
        size_t n = base64_ad(out, orig, 2);
        out[n] = '\0';
        uint8_t rursus[2];
        int rc = base64_ex(rursus, 2, out);
        PROBA("base64 duo octeti", rc == 0 && rursus[0] == 0xAB && rursus[1] == 0xCD);
    }

    /* vector notus RFC 4648: 'Man' -> 'TWFu' */
    {
        uint8_t orig[] = { 'M', 'a', 'n' };
        char out[8];
        size_t n = base64_ad(out, orig, 3);
        out[n] = '\0';
        PROBA("base64('Man') == 'TWFu'", strcmp(out, "TWFu") == 0);
    }
}

int main(void)
{
    proba();
    printf("\n%d succedit, %d deficit\n", successae, defectae);
    return defectae == 0 ? 0 : 1;
}
