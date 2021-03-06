#include <stdint.h>
#include "endian.h"

void put_bigendian( void *target, uint_fast64_t value, size_t bytes ) {
    unsigned char *b = target;
    int i;

    for (i = bytes-1; i >= 0; i--) {
        b[i] = value & 0xff;
        value >>= 8;
    }
}
    
uint_fast64_t get_bigendian( const void *target, size_t bytes ) {
    const unsigned char *b = target;
    uint_fast64_t result = 0;
    int i;

    for (i=0; i<bytes; i++) {
        result = 256 * result + (b[i] & 0xff);
    }

    return result;
}
