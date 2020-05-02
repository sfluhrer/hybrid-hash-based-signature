#include "wots.h"

/* This assumes a fixed Winternitz parameter w=4 */
/* This also assumes that there is between 8 and 127 bytes of hash */
int expand_wots_digits( unsigned char *digits, int digit_buffer_size,
                               const unsigned char *hash, int hash_len ) {
    if (digit_buffer_size < 2*hash_len) return 0;

    int i;
    int csum = 0;
    for (i=0; i<hash_len; i++) {
        int x = *hash++;
        int d = (x >> 4);
        csum += 15 - d;
        *digits++ = d;
        d = (x & 0xf);
        csum += 15 - d;
        *digits++ = d;
        digit_buffer_size -= 2;
    }
    int total_digits = 2 * hash_len;

    /* We assume that csum is represented by 3 digits */
    if (digit_buffer_size < 3) return 0;
    int d = (csum >> 8) & 0x0f;
    *digits++ = d;
    d = (csum >> 4) & 0x0f;
    *digits++ = d;
    d = (csum     ) & 0x0f;
    *digits   = d;
    total_digits += 3;

    return total_digits;
}

