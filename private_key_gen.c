#include "private_key_gen.h"
#if KEYGEN_STRATEGY
#include <openssl/aes.h>
#else
#include "sha256.h"
#endif
#include <string.h>
#include "zeroize.h"

/*
 * This is the engine that produces XMSS and LMS private keys
 *
 * In AES mode, this is effectively a CBC-MAC of the adr structure (for
 * XMSS) or a 16 byte structure containing the leaf/digit index (for
 * LMS). To generate 24 byte keys, we go into OFB mode for bytes 16-23
 *
 * In SHA-256 mode, this is effectively two hashes; the first of the
 * key and the first 16 bytes of the adr structure (for XMSS); then
 * we hash that along with the last 16 byts of the (or the LMS
 * identifier); we then truncate the 32 byte hash to 24 bytes for the
 * caller.
 *
 * We can use AES, rather than relying on our hash function, because
 * AES gives us the security properties we want (indistinguishable
 * from random output, assuming a secret key), and it's faster
 * than our hash function; it ends up giving perhaps 5% faster load
 * times in my expirements
 */

void init_private_key_gen( struct private_key_generator *gen, 
             const void *secret_key, int len_secret_key,
             const void *extra, int len_extra ) {
#if KEYGEN_STRATEGY
    if (len_secret_key >= 32) {
        AES_set_encrypt_key( secret_key, 256, &gen->expanded_key );
     } else {
        /* We could go with AES-192 to handle 24 byte secrets */
        /* Instead, we opt to stay with AES-256, and fix 64 bits */
        unsigned char real_key[32] = { 0 };
        memcpy( real_key, secret_key, len_secret_key );
        AES_set_encrypt_key( real_key, 256, &gen->expanded_key );
        zeroize( real_key, len_secret_key );
    }

    memset( gen->init, 0, 16 );
    const unsigned char *pc_extra = extra;
    for (; len_extra > 0; ) {
        int i;
        for (i = 0; i < 16 && len_extra > 0; i++, len_extra--) {
            gen->init[i] ^= *pc_extra++;
        }
        AES_encrypt( gen->init, gen->init, &gen->expanded_key );
    }
#else
    /*
     * What we would like is the have the do_private_key_gen compute
     * Hash( secret || extra || state ).  However, secret || extra || state
     * can be as long as 56 bytes, and that would mean two hash compression
     * operations -> slow.  Now, we could make sure that secret || extra had
     * some extra padding, so that it is 64 bytes long (and so we could
     * precompute the SHA256 internal state after 64 bytes); however to take
     * advantage of that, we would need a restartable SHA256 implementation
     * (OpenSSL doesn't have an API that does that, and we don't need that
     * anywhere else.  So, what we actually do is:
     * Hash( Hash( secret || extra ) || state ); that keeps the
     * do_private_key_gen time to one hash compression operation (plus one
     * here, but we don't do that that often)
     */
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, secret_key, len_secret_key );
    if (len_extra) {
        SHA256_Update(&ctx, extra, len_extra );
    }
    SHA256_Final( gen->hash, &ctx );
    zeroize( &ctx, sizeof ctx );
#endif
}

#if KEYGEN_STRATEGY
static void do_xor( unsigned char *dest, const unsigned char *a,
                    const unsigned char *b, int len) {
    while (len--) {
        *dest++ = *a++ ^ *b++;
    }
}
#endif

void do_private_key_gen( void *dest, int n, 
             const struct private_key_generator *gen, const void *state ) {
#if KEYGEN_STRATEGY
    unsigned char *pc_dest = dest;

    unsigned char buffer[16]; 
    do_xor( buffer, state, gen->init, 16 );
    int i;
    for (i = 0; n > 0; i++) {
        AES_encrypt( buffer, buffer, &gen->expanded_key );
        int this_len;
        if (n > 16) this_len = 16; else this_len = n;
        memcpy( pc_dest, buffer, this_len );
        pc_dest += this_len;
        n -= this_len;
    }
    zeroize( buffer, sizeof buffer );
#else
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, gen->hash, 32 );
    SHA256_Update(&ctx, state, 16 );
    unsigned char buffer[32];
    SHA256_Final( buffer, &ctx );
    zeroize( &ctx, sizeof ctx );
    memcpy( dest, buffer, n );  /* We assume n <= 32 */
    zeroize( buffer, sizeof buffer );
#endif 
}
