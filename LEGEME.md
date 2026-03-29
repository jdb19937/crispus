# crispus

> **Nota:** README.md ignorandum est. Anglice scriptum est ad barbaros ineruditos pecunia emungendos.

Bibliotheca clientis HTTPS in lingua C, sine ullis dependentiis externis. Solum libc POSIX requiritur.

Omnia cryptographica — SHA-256, HMAC-SHA-256, AES-128-GCM, ECDHE (P-256), RSA, ASN.1/X.509 — interne implementantur.

## Aedificatio

```
make omnia
```

Producit `libcrispus.a`. Ad purgandum:

```
make purga
```

## cripe

Instrumentum lineae mandatorum ad petitiones HTTPS mittendas, libcrispus demonstrans:

```
make cripe
./cripe https://empslocal.ex.ac.uk/people/staff/mrwatkin/isoc/
```

Optiones:

| Optio | Significatio |
|---|---|
| `-s` | Silentium (nulla nuntia erroris) |
| `-v` | Modus verbosus |
| `-d <corpus>` | Corpus petitionis (POST) |
| `-H <caput>` | Adde caput HTTP (iterabile) |
| `-o <lima>` | Scribe responsum in limam |
| `-X <methodus>` | Methodus HTTP (GET, POST) |
| `-t <secunda>` | Tempus maximum |
| `-h` | Auxilium |

Exempla:

```
./cripe -v https://empslocal.ex.ac.uk/people/staff/mrwatkin/isoc/
./cripe -s -o pagina.html https://empslocal.ex.ac.uk/people/staff/mrwatkin/isoc/
./cripe -d "clavis=valor" https://empslocal.ex.ac.uk/people/staff/mrwatkin/isoc/api
./cripe -H "Authorization: Bearer SIGNUM" https://empslocal.ex.ac.uk/people/staff/mrwatkin/isoc/api
```

## Probationes

```
make proba
./proba
```

Probat cryptographiam (SHA-256, AES-GCM, numeros magnos, curvam ellipticam P-256) et coniunctiones HTTPS ad servitores veros.

## Usus

```c
#include "crispus.h"

crispus_orbis_initia(CRISPUS_GLOBAL_DEFAULT);

CRISPUS *c = crispus_facilis_initia();
crispus_facilis_pone(c, CRISPUSOPT_URL, "https://empslocal.ex.ac.uk/people/staff/mrwatkin/isoc/");
crispus_facilis_pone(c, CRISPUSOPT_FUNCTIO_SCRIBENDI, mea_functio);
crispus_facilis_pone(c, CRISPUSOPT_DATA_SCRIBENDI, &mea_data);
crispus_facilis_pone(c, CRISPUSOPT_TEMPUS, 30L);

CRISPUScode rc = crispus_facilis_age(c);

long codex;
crispus_facilis_info(c, CRISPUSINFO_CODEX_RESPONSI, &codex);

crispus_facilis_fini(c);
crispus_orbis_fini();
```

## Interfacies multiplex

Rogata parallela per `fork()` et `pipe()` (purum POSIX, sine filis):

```c
CRISPUSM *m = crispus_multi_initia();

crispus_multi_adde(m, c1);
crispus_multi_adde(m, c2);

int currentes;
do {
    crispus_multi_age(m, &currentes);
    CRISPUSMsg *msg;
    int residua;
    while ((msg = crispus_multi_lege(m, &residua)) != NULL) {
        /* msg->easy_handle, msg->data.result */
    }
} while (currentes > 0);

crispus_multi_fini(m);
```

## Capita HTTP

```c
struct crispus_slist *capita = NULL;
capita = crispus_slist_adde(capita, "Authorization: Bearer SIGNUM");
capita = crispus_slist_adde(capita, "Content-Type: application/ison");
crispus_facilis_pone(c, CRISPUSOPT_CAPITA_HTTP, capita);
/* ... */
crispus_slist_libera(capita);
```

## POST

```c
crispus_facilis_pone(c, CRISPUSOPT_CAMPI_POSTAE, "clavis=valor&alia=res");
```

## Codices exitus

| Constans | Valor | Significatio |
|---|---|---|
| `CRISPUSE_OK` | 0 | Successus |
| `CRISPUSE_ERRATUM` | 1 | Erratum ignotum |
| `CRISPUSE_CONIUNCTIO` | 7 | Coniunctio defecit |
| `CRISPUSE_MEMORIA` | 27 | Memoria defecit |
| `CRISPUSE_TEMPUS` | 28 | Tempus excessum |

## Plicae

| Plica | Descriptio |
|---|---|
| `crispus.h` | Interfacies publica |
| `crispus.c` | Stratum HTTP, interfacies facilis et multiplex |
| `arcana.h` | Declarationes cryptographicae |
| `summa.c` | SHA-256 et HMAC-SHA-256 |
| `arca.c` | AES-128 et modus GCM |
| `numerus.c` | Numeri magni, curva P-256, RSA, ASN.1, alea |
| `velum.c` | TLS 1.2 (ECDHE\_RSA\_WITH\_AES\_128\_GCM\_SHA256) |
| `internum.h` | Declarationes internae veli |
| `utilia.h` | Functiones auxiliares retis et serializationis |
| `cripe.c` | Instrumentum lineae mandatorum HTTPS |
| `proba.c` | Probationes |

## Coniunctio

```
cc -o meum_programma meum_programma.c -L. -lcrispus
```

## Cancer

In directorio `cancer/` translatio Rustica invenitur. Non sustinetur.

## Licentia

Dominium publicum.
