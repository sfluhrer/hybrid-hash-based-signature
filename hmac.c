#include "hmac.h"
#include <string.h>
#include "sha256.h"
#include "zeroize.h"

/*
 * This is a simple-minded implementation of HMAC-SHA256
 * The only change to the common implmentation is that we have the caller
 * pass the key during finalization; the callers we have always have that
 * handy and have no particular reason to store it
 * We also assume that key_len <= 64 (also always true for us)
 */

void init_hmac( struct hmac_engine *engine, const void *key, int key_len ) {
    SHA256_Init(&engine->ctx);
    unsigned char buffer[64];
    memset( buffer, 0x36, 64 );
    int i;
    const unsigned char *p = key;
    /* We assume key_len <= 64 here */
    for (i=0; i<key_len; i++) {
        buffer[i] ^= p[i];
    }
    SHA256_Update(&engine->ctx, buffer, 64);   
    zeroize(buffer, sizeof buffer);
}

void update_hmac( struct hmac_engine *engine,
                         const void *data, unsigned len_data) {
    SHA256_Update(&engine->ctx, data, len_data); 
}

void final_hmac( void *output, struct hmac_engine *engine,
                        const void *key, int key_len ) {
    unsigned char buffer[64+32];
    SHA256_Final(&buffer[64], &engine->ctx);
    memset( buffer, 0x5c, 64 );
    const unsigned char *p = key;
    int i;
    for (i=0; i<key_len; i++) {
        buffer[i] ^= p[i];
    }
        /* We reuse the same ctx, because that's one less thing to zeroize */
    SHA256_Init(&engine->ctx);
    SHA256_Update(&engine->ctx, buffer, 64+32);   
    SHA256_Final(output, &engine->ctx);
    zeroize(buffer, sizeof buffer);
}
