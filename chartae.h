/*
 * chartae.h — codificationes chartarum (hex et base64)
 */

#ifndef CHARTAE_H
#define CHARTAE_H

#include <stddef.h>
#include <stdint.h>

/* Hex — minusculae, sine prefixo. Alvea:
 *   hex_ad: longitudo[in] = 2 * longitudo octetorum, sine terminatore nullo.
 *   Pro scripturis '\0', adde locum tu. */
void hex_ad(char *hex, const uint8_t *octeti, size_t n);

/* Redit 0 si successit, -1 si prava. Spatia et terminatores nulli ignorantur. */
int hex_ex(uint8_t *octeti, size_t n, const char *hex);

/* Base64 standardum (cum '+' et '/'), sine paddatione obligatoria.
 * Scribe in alveum. Terminator nullus additus. Redit longitudo scripta. */
size_t base64_ad(char *out, const uint8_t *octeti, size_t n);
size_t base64_longitudo_output(size_t n);   /* ceil(n/3) * 4 */

/* Decode. Longitudo exitus expectata. Spatia ignorantur.
 * Redit 0 si successit, -1 si prava. */
int base64_ex(uint8_t *out, size_t n, const char *in);

#endif /* CHARTAE_H */
