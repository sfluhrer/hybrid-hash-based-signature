#include "hmac_drbg.h"
#include "hmac.h"
#include "zeroize.h"
#include <string.h>
#include <stddef.h>

/*
 * Note that this isn't precisely the FIPS approved DRBG, as it doesn't include
 * the self-tests that FIPS mandates
 */
 
static void update_drbg( struct hmac_drbg *drbg, const void *data,
                         unsigned len_data ) {
    struct hmac_engine engine;
    init_hmac( &engine, drbg->key, 32 );
    update_hmac( &engine, drbg->v, 32 );
    update_hmac( &engine, "\0", 1 );
    if (data) {
        update_hmac( &engine, data, len_data );
    }
    final_hmac( drbg->key, &engine, drbg->key, 32 );

    init_hmac( &engine, drbg->key, 32 );
    update_hmac( &engine, drbg->v, 32 );
    final_hmac( drbg->v, &engine, drbg->key, 32 );

    if (data) {
        init_hmac( &engine, drbg->key, 32 );
        update_hmac( &engine, drbg->v, 32 );
        update_hmac( &engine, "\1", 1 );
        update_hmac( &engine, data, len_data );
        final_hmac( drbg->key, &engine, drbg->key, 32 );

        init_hmac( &engine, drbg->key, 32 );
        update_hmac( &engine, drbg->v, 32 );
        final_hmac( drbg->v, &engine, drbg->key, 32 );
    }

    zeroize( &engine, sizeof engine );
}

bool seed_drbg( struct hmac_drbg *drbg,
                bool (*rand)(void *buffer, size_t len_buffer ) ) {
    /*
     * 48 bytes are:
     * - 32 bytes entropy input
     * - 16 bytes of nonce
     * Since the DRBG will just concatinate them, we just load them that way
     */
    unsigned entropy[48];
    if (!rand( entropy, 48 )) return false;

    memset(drbg->key, 0, 32);
    memset(drbg->v, 1, 32);
    update_drbg( drbg, entropy, 48 );
    drbg->reseed_counter = 1;

    zeroize( entropy, sizeof entropy );

    return true;
}

bool read_drbg( void *buffer, size_t len_buffer, struct hmac_drbg *drbg ) {
    /* In practice, we'll never hit this limit */
    if (drbg->reseed_counter >= (1ULL<<48)) return false;

    unsigned char *p = buffer;
    struct hmac_engine engine;
    while (len_buffer) {
        init_hmac( &engine, drbg->key, 32 );
        update_hmac( &engine, drbg->v, 32 );
        final_hmac( drbg->v, &engine, drbg->key, 32 );

        int len = len_buffer;
        if (len > 32) len = 32;
        memcpy( p, drbg->v, len );
        p += len;
        len_buffer -= len;
    }
    zeroize( &engine, sizeof engine );

    update_drbg( drbg, 0, 0 );
    drbg->reseed_counter += 1;

    return true;
}
