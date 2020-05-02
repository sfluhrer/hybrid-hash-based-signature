/*
 * This is the code that implements the one-time-signature part of the LMS hash
 * based signatures
 */
#include "lm_ots_common.h"

unsigned lm_ots_coef(const unsigned char *Q, unsigned i, unsigned w) {
    unsigned index = (i * w) / 8;    /* Which byte holds the coefficient */
                                     /* we want */
    unsigned digits_per_byte = 8/w;
    unsigned shift = w * (~i & (digits_per_byte-1)); /* Where in the byte */
                                     /* the coefficient is */
    unsigned mask = (1<<w) - 1;      /* How to mask off the parts we're not */
                                     /* interested in */

    return (Q[index] >> shift) & mask;
}

/* This returns the Winternitz checksum to append to the hash */
unsigned lm_ots_compute_checksum(const unsigned char *Q, unsigned Q_len,
                                 unsigned w, unsigned ls) {
    unsigned sum = 0;
    unsigned i;
    unsigned u = 8 * Q_len / w;
    unsigned max_digit = (1<<w) - 1;
    for (i=0; i<u; i++) {
        sum += max_digit - lm_ots_coef( Q, i, w );
    }
    return sum << ls;
}
