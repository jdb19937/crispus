/*
 * crispe — instrumentum lineae mandatorum ad petitiones HTTPS
 *          mittendas, bibliothecam libcrispus demonstrans.
 *
 * Usus: crispe [optiones] <url>
 *
 *   -s            silentium (nulla nuntia erroris)
 *   -v            modus verbosus
 *   -L            sequere redirectiones
 *   -d <data>     corpus petitionis (POST)
 *   -H <caput>    adde caput HTTP (iterabile)
 *   -o <lima>     scribe responsum in limam
 *   -X <methodus> methodus HTTP (GET, POST)
 *   -t <secunda>  tempus maximum (secunda)
 *   -h            auxilium
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "crispus.h"

/* --- structura responsi --- */

typedef struct {
    char   *corpus;
    size_t  magnitudo;
} responsum_t;

/* --- functio scribendi (callback) --- */

static size_t
recipe_data(void *data, size_t magnitudo, size_t numerus, void *ctx)
{
    size_t longitudo  = magnitudo * numerus;
    responsum_t *resp = (responsum_t *)ctx;

    char *novum = realloc(resp->corpus, resp->magnitudo + longitudo + 1);
    if (!novum)
        return 0;

    resp->corpus = novum;
    memcpy(resp->corpus + resp->magnitudo, data, longitudo);
    resp->magnitudo += longitudo;
    resp->corpus[resp->magnitudo] = '\0';

    return longitudo;
}

/* --- auxilium --- */

static void
scribe_auxilium(const char *nomen)
{
    fprintf(
        stderr,
        "Usus: %s [optiones] <url>\n"
        "\n"
        "  -s            silentium (nulla nuntia erroris)\n"
        "  -v            modus verbosus\n"
        "  -L            sequere redirectiones\n"
        "  -d <corpus>   corpus petitionis (methodus POST)\n"
        "  -H <caput>    adde caput HTTP (iterabile)\n"
        "  -o <lima>     scribe responsum in limam\n"
        "  -X <methodus> methodus HTTP (GET, POST)\n"
        "  -t <secunda>  tempus maximum (secunda)\n"
        "  -h            hoc auxilium\n",
        nomen
    );
}

/* --- functio principalis --- */

int
main(int numerus_arg, char *argumenta[])
{
    int          silentium     = 0;
    int          verbosus      = 0;
    int          sequere       = 0;
    const char  *corpus_postae = NULL;
    const char  *lima_exitus   = NULL;
    const char  *methodus      = NULL;
    long         tempus_max    = 60;

    struct crispus_slist *capita = NULL;

    int opt;
    while ((opt = getopt(numerus_arg, argumenta, "svLd:H:o:X:t:h")) != -1) {
        switch (opt) {
        case 's':
            silentium = 1;
            break;
        case 'v':
            verbosus = 1;
            break;
        case 'L':
            sequere = 1;
            break;
        case 'd':
            corpus_postae = optarg;
            break;
        case 'H':
            capita = crispus_slist_adde(capita, optarg);
            break;
        case 'o':
            lima_exitus = optarg;
            break;
        case 'X':
            methodus = optarg;
            break;
        case 't':
            tempus_max = atol(optarg);
            if (tempus_max <= 0) {
                if (!silentium)
                    fprintf(stderr, "crispe: tempus invalidum: %s\n", optarg);
                return 1;
            }
            break;
        case 'h':
            scribe_auxilium(argumenta[0]);
            return 0;
        default:
            scribe_auxilium(argumenta[0]);
            return 1;
        }
    }

    if (optind >= numerus_arg) {
        if (!silentium)
            fprintf(stderr, "crispe: URL deest\n");
        scribe_auxilium(argumenta[0]);
        return 1;
    }

    const char *url = argumenta[optind];

    /* si -d datum est sed -X non, methodus est POST */
    if (corpus_postae && !methodus)
        methodus = "POST";

    /* si methodus POST sed -d non datum, mone */
    if (methodus && strcmp(methodus, "POST") == 0 && !corpus_postae) {
        corpus_postae = "";
    }

    /* --- initia orbis --- */

    CRISPUScode rc = crispus_orbis_initia(CRISPUS_GLOBAL_DEFAULT);
    if (rc != CRISPUSE_OK) {
        if (!silentium)
            fprintf(
                stderr, "crispe: orbis initia defecit: %s\n",
                crispus_facilis_error(rc)
            );
        return 1;
    }

    /* --- para manubrium --- */

    CRISPUS *manubrium = crispus_facilis_initia();
    if (!manubrium) {
        if (!silentium)
            fprintf(stderr, "crispe: manubrium creare non potuit\n");
        crispus_orbis_fini();
        return 1;
    }

    crispus_facilis_pone(manubrium, CRISPUSOPT_URL, url);
    crispus_facilis_pone(manubrium, CRISPUSOPT_TEMPUS, tempus_max);

    if (sequere)
        crispus_facilis_pone(manubrium, CRISPUSOPT_SEQUERE, 1);

    if (corpus_postae)
        crispus_facilis_pone(manubrium, CRISPUSOPT_CAMPI_POSTAE, corpus_postae);

    if (capita)
        crispus_facilis_pone(manubrium, CRISPUSOPT_CAPITA_HTTP, capita);

    responsum_t resp = { NULL, 0 };
    crispus_facilis_pone(manubrium, CRISPUSOPT_FUNCTIO_SCRIBENDI, recipe_data);
    crispus_facilis_pone(manubrium, CRISPUSOPT_DATA_SCRIBENDI, &resp);

    /* --- modus verbosus: ostende petitionem --- */

    if (verbosus) {
        const char *m = methodus ? methodus : "GET";
        fprintf(stderr, "> %s %s\n", m, url);
        if (corpus_postae)
            fprintf(stderr, "> Corpus: %s\n", corpus_postae);
        struct crispus_slist *iter = capita;
        while (iter) {
            fprintf(stderr, "> %s\n", iter->data);
            iter = iter->proximus;
        }
        fprintf(stderr, ">\n");
    }

    /* --- mitte petitionem --- */

    rc = crispus_facilis_age(manubrium);

    if (rc != CRISPUSE_OK) {
        if (!silentium)
            fprintf(
                stderr, "crispe: petitio defecit: %s\n",
                crispus_facilis_error(rc)
            );
        free(resp.corpus);
        crispus_facilis_fini(manubrium);
        crispus_slist_libera(capita);
        crispus_orbis_fini();
        return 1;
    }

    /* --- codex responsi --- */

    long codex_responsi = 0;
    crispus_facilis_info(manubrium, CRISPUSINFO_CODEX_RESPONSI, &codex_responsi);

    if (verbosus)
        fprintf(
            stderr, "< HTTP codex: %ld\n< Magnitudo: %zu octeti\n",
            codex_responsi, resp.magnitudo
        );

    /* --- scribe responsum --- */

    int status = 0;

    if (lima_exitus) {
        FILE *lima = fopen(lima_exitus, "wb");
        if (!lima) {
            if (!silentium)
                fprintf(
                    stderr, "crispe: limam aperire non potuit: %s\n",
                    lima_exitus
                );
            status = 1;
        } else {
            if (resp.corpus && resp.magnitudo > 0)
                fwrite(resp.corpus, 1, resp.magnitudo, lima);
            fclose(lima);
        }
    } else {
        if (resp.corpus && resp.magnitudo > 0)
            fwrite(resp.corpus, 1, resp.magnitudo, stdout);
    }

    /* --- purga --- */

    free(resp.corpus);
    crispus_facilis_fini(manubrium);
    crispus_slist_libera(capita);
    crispus_orbis_fini();

    return status;
}
