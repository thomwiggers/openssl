#ifndef LIBCSIDH_H
#define LIBCSIDH_H

#include <stdint.h>

#define num_primes 74

typedef struct {
    int8_t e[num_primes]; /* packed int4_t */
} csidh_private_key;
typedef struct {
    uint8_t c[64];
} csidh_public_key;

int csidh_derive(csidh_public_key *parameter, csidh_public_key const *base, csidh_private_key const *key);
int csidh_generate(csidh_private_key *key);

extern const csidh_public_key csidh_base;
#endif
