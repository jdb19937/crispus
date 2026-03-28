# Makefile — libcrispus.a
# Bibliotheca retis HTTPS sine dependentiis externis.

CC      = cc
CFLAGS  = -Wall -Wextra -pedantic -std=c11 -O2
AR      = ar
ARFLAGS = rcs

FONTES  = crispus.c velum.c summa.c arca.c numerus.c
OBIECTA = $(FONTES:.c=.o)

BIBLIOTHECA = libcrispus.a

omnia: $(BIBLIOTHECA) cripe

$(BIBLIOTHECA): $(OBIECTA)
	$(AR) $(ARFLAGS) $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

cripe: $(BIBLIOTHECA) cripe.o
	$(CC) $(CFLAGS) -o $@ cripe.o -L. -lcrispus

cripe.o: cripe.c crispus.h
	$(CC) $(CFLAGS) -c -o $@ $<

proba: $(BIBLIOTHECA) proba.o
	$(CC) $(CFLAGS) -o $@ proba.o -L. -lcrispus

proba.o: proba.c proba.h crispus.h internum.h arcana.h
	$(CC) $(CFLAGS) -c -o $@ $<

purga:
	rm -f $(OBIECTA) proba.o cripe.o $(BIBLIOTHECA) proba cripe

.PHONY: omnia purga proba cripe
