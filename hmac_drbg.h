#if !defined( HMAC_DRBG_H_ )
#define HMAC_DRBG_H_

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct hmac_drbg {
    unsigned char v[32];
    unsigned char key[32];
    uint_fast64_t reseed_counter;
};

bool seed_drbg( struct hmac_drbg *drbg, bool (*rand)(void *buffer, 
                size_t len_buffer ) );
bool read_drbg( void *buffer, size_t len_buffer, struct hmac_drbg *drbg );

#endif /* HMAC_DRBG_H_ */
