/*
 * utilia.h — functiones auxiliares retis et serializationis
 *
 * Scribere et legere numeros big-endian,
 * mittere et legere plene per descriptorem plicae.
 *
 * Sine dependentiis externis.
 */

#ifndef UTILIA_H
#define UTILIA_H

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>

/* --- serializatio big-endian --- */

static inline void scr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void scr24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}

static inline uint16_t leg16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | p[1]);
}

static inline uint32_t leg24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

/* --- lectio et scriptio plena --- */

static inline int mitte_plene(int fd, const uint8_t *data, size_t mag)
{
    size_t scriptum = 0;
    while (scriptum < mag) {
        ssize_t r = write(fd, data + scriptum, mag - scriptum);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        scriptum += (size_t)r;
    }
    return 0;
}

static inline int lege_plene(int fd, uint8_t *alveus, size_t mag)
{
    size_t lectum = 0;
    while (lectum < mag) {
        ssize_t r = read(fd, alveus + lectum, mag - lectum);
        if (r <= 0) {
            if (r < 0 && errno == EINTR)
                continue;
            return -1;
        }
        lectum += (size_t)r;
    }
    return 0;
}

#endif /* UTILIA_H */
