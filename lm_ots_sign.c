/*
 * This is the code that implements the one-time-signature part of the LMS hash
 * based signatures
 */
#include <string.h>
#include "hash.h"
#include "sha256.h"
#include "lms_common_defs.h"
#include "endian.h"
#include "private_key_gen.h"
#include "zeroize.h"
#include "lm_ots_common.h"
#include "lm_ots_param.h"

/*
 * Note: this includes the bottom level leaf hash that's technically in
 * the LMS merkle tree
 */
void lm_ots_generate_public_key(
    const unsigned char *I, /* Public key identifier */
    unsigned q,             /* Diversification string, 4 bytes value */
    const void *seed,
    unsigned char *public_key) {

    /* Look up the parameter set */
    /* We'll use a fixed parameter set */
    unsigned n = 24;
    unsigned w = LM_OTS_W;
    unsigned p = LM_OTS_P;

    /* Start the hash that computes the final value */
    SHA256_CTX public_ctx;
    SHA256_Init( &public_ctx );
    {
        unsigned char prehash_prefix[ PBLC_PREFIX_LEN ];
        memcpy( prehash_prefix + PBLC_I, I, I_LEN );
        put_bigendian( prehash_prefix + PBLC_Q, q, 4 );
        SET_D( prehash_prefix + PBLC_D, D_PBLC );
        SHA256_Update(&public_ctx, prehash_prefix,
                                PBLC_PREFIX_LEN );
    }

    /* Now generate the public key */
    int i, j;

    unsigned char buf[ ITER_MAX_LEN ];
    memcpy( buf + ITER_I, I, I_LEN );
    put_bigendian( buf + ITER_Q, q, 4 );
    SHA256_CTX ctx;

    /* set up the private key generator */
    struct private_key_generator priv_gen;
    init_private_key_gen( &priv_gen, seed, 32, 0, 0 );
    uint32_t priv_image[4] = { 0 };
    put_bigendian( (void*)&priv_image[0], q, 4);

    for (i=0; i<p; i++) {
        priv_image[1] = i | (i << 24);  /* Same on little and big endian */
        do_private_key_gen( buf + ITER_PREV, n, &priv_gen, priv_image );
        put_bigendian( buf + ITER_K, i, 2 );
        /* We'll place j in the buffer below */
        for (j=0; j < (1<<w) - 1; j++) {
            buf[ITER_J] = j;
            SHA256_Init( &ctx );
            SHA256_Update( &ctx, buf, ITER_LEN(n) );
            SHA256_Final( buf + ITER_PREV, &ctx );  /* Note: this will */
                /* write an extra 8 bytes; we've allocated buf long */
                /* enough that those extra bytes are harmless */
        }
        /* Include that in the hash */
        SHA256_Update( &public_ctx, buf + ITER_PREV, n );
    }

    /* And the result of the running hash is the public key */
    unsigned char temp[32];
    SHA256_Final( temp, &public_ctx );
    memcpy( public_key, temp, n );
    zeroize( temp, sizeof temp );

    zeroize( &priv_gen, sizeof priv_gen );
    zeroize( buf, sizeof buf );

    /* Perform the bottom level hash that appears in the Merkle tree */
    int h = 20;
    unsigned char ots_sig[LEAF_MAX_LEN];
    memcpy( ots_sig + LEAF_I, I, I_LEN );
    put_bigendian( ots_sig + LEAF_R, q + (1<<h), 4 );
    SET_D( ots_sig + LEAF_D, D_LEAF );
    memcpy( ots_sig + LEAF_PK, public_key, n );
    SHA256_Init( &ctx );
    SHA256_Update( &ctx, ots_sig, LEAF_LEN(n) );
    SHA256_Final(public_key, &ctx);

    zeroize( &ctx, sizeof ctx );
    zeroize( ots_sig, sizeof ots_sig );
}

int lm_ots_generate_signature(
    const unsigned char *I,  /* Public key identifier */
    unsigned q,             /* Diversification string, 4 bytes value */
    const void *seed,
    const void *message,
    size_t message_len,
    unsigned char *signature) {

    int n = 24;    /* The fixed LMS parameters we use */
    int w = LM_OTS_W;
    int ls = LM_OTS_LS;
    int p = LM_OTS_P;

    /* Set up the secret sauce that generates the private keys */
    struct private_key_generator priv_gen;
    init_private_key_gen( &priv_gen, seed, 32, 0, 0 );
    uint32_t priv_image[4] = { 0 };
    put_bigendian( (void*)&priv_image[0], q, 4);

    /* Export the parameter set to the signature */
    put_bigendian( signature, LM_OTS_PARAM_ID, 4 );

    /* Select the randomizer */
    priv_image[2] = ~0; /* Make sure it doesn't collide with other uses */
                        /* of priv_gen */
    do_private_key_gen( signature+4, n, &priv_gen, priv_image );
    priv_image[2] = 0;
    
    SHA256_CTX ctx;

    /* Compute the initial hash */
    unsigned char Q[MAX_HASH_LEN + 2];
    SHA256_Init(&ctx);

    /* First, we hash the message prefix */
    unsigned char prefix[MESG_PREFIX_MAXLEN];
    memcpy( prefix + MESG_I, I, I_LEN );
    put_bigendian( prefix + MESG_Q, q, 4 );
    SET_D( prefix + MESG_D, D_MESG );
    memcpy( prefix + MESG_C, signature+4, n );
    SHA256_Update(&ctx, prefix, MESG_PREFIX_LEN(n) );

    /* And the message */
    SHA256_Update(&ctx, message, message_len );
    SHA256_Final( Q, &ctx );

    /* Append the checksum to the randomized hash */
    put_bigendian( &Q[n], lm_ots_compute_checksum(Q, n, w, ls), 2 );

    int i;
    unsigned char tmp[ITER_MAX_LEN];

    /* Preset the parts of tmp that don't change */
    memcpy( tmp + ITER_I, I, I_LEN );
    put_bigendian( tmp + ITER_Q, q, 4 );
    
    for (i=0; i<p; i++) {
        put_bigendian( tmp + ITER_K, i, 2 );
        priv_image[1] = i | (i << 24);  /* Same on little and big endian */
        do_private_key_gen( tmp + ITER_PREV, n, &priv_gen, priv_image );
        unsigned a = lm_ots_coef( Q, i, w );
        unsigned j;
        for (j=0; j<a; j++) {
            tmp[ITER_J] = j;
            SHA256_Init( &ctx );
            SHA256_Update( &ctx, tmp, ITER_LEN(n) );
            SHA256_Final( tmp + ITER_PREV, &ctx );  /* Note: this will */
                /* write an extra 8 bytes; we've allocated buf long */
                /* enough that those extra bytes are harmless */
        }
        memcpy( &signature[ 4 + n + n*i ], tmp + ITER_PREV, n );
    }

    /* Get rid of the incrimidating evidence */
    zeroize( &ctx, sizeof ctx );
    zeroize( &priv_gen, sizeof priv_gen );

    return 4 + n + p*n;  /* Return the signature length */
}
