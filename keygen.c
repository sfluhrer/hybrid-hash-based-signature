#include "sphincs-hybrid.h"
#include <stdbool.h>
#include <stddef.h>
#include "hash.h"
#include "build_merkle.h"
#include "param.h"

/*
 * This generates a new public/private keypair
 *
 * Parameters:
 * hash_function - hash function to use: 
 *                 0 -> SHAKE256, 1 -> SHA256, 2 -> HARAKA
 * hash_size - length of the hash function to use (in bytes)
 *                 Must be one of: 128, 192, 256
 * time_space - where to do an F or an S parameter set of Sphincs+
 *                 0 -> use fast version (with large signatures)
 *                 1 -> use short version (with large signing times)
 * (Note: it is likely that we will fix hash_function and time_space
 *  to SHA256/slow in the future; those are what makes sense in the
 *  hybrid context)
 * do_rand - function to call when this needs randomness
 * sk_buffer - where to place the secret key
 * len_sk_buffer - length of the above buffer
 * size_sk - where to write the actual length of the secret key
 * pk_buffer - where to place the public key
 * len_pk_buffer - length of the above buffer
 * size_pk - where to write the actual length of the public key
 */
bool sh_keygen( int hash_function, int hash_size, int time_space,
                bool (*do_rand)( void *buffer, size_t len_buffer ),
                void *sk_buffer, size_t len_sk_buffer, size_t *size_sk, 
                void *pk_buffer, size_t len_pk_buffer, size_t *size_pk) {
    /* Do parameter validation, look up the hash function */
    hash_t hash = 0;
    switch (hash_function) {
//    case 0: hash = HASH_TYPE_SHAKE256; break;
    case 1: hash = HASH_TYPE_SHA256; break;
//    case 2: hash = HASH_TYPE_HARAKA; break;
    default: return false;  /* Unrecognized hash */
    }
    switch (hash_size) {
//    case 128: hash |= HASH_LEN_128; break;
    case 192: hash |= HASH_LEN_192; break;
//    case 256: hash |= HASH_LEN_256; break;
    default: return false;  /* Unsupported hash length */
    }

    bool fast;
    switch (time_space) {
//    case 0: fast = true; break;
    case 1: fast = false; break;
    default: return false;  /* Unsupported time/space tradeoff */
    }

    int n = hash_size / 8;  /* hash_size validated above */

    int d, tree_height;
    if (!lookup_hypertree_geometry( n, fast, &d, &tree_height )) return false;

    /* The lengths of the secret keys and the public keys */
    /* These are 4 bytes longer than what the Sphincs+ doc claims, as we */
    /* also record the parameter set */
    size_t sk_len = 4 + 4*n;
    size_t pk_len = 4 + 2*n;

    /* Make sure that the passed buffers are long enough */ 
    if (sk_len > len_sk_buffer) return false;
    if (pk_len > len_pk_buffer) return false;

    /* If asked, return the actual sizes */
    if (size_sk) *size_sk = sk_len;
    if (size_pk) *size_pk = pk_len;

    /* Write out the public and private keys */
    unsigned char *sk_param_set = sk_buffer;
    unsigned char *sk_seed = sk_param_set + 4;
    unsigned char *sk_prf = sk_seed + n;
    unsigned char *sk_pk_seed = sk_prf + n;
    unsigned char *sk_pk_root = sk_pk_seed + n;
    unsigned char *pk_param_set = pk_buffer;
    unsigned char *pk_seed = pk_param_set + 4;
    unsigned char *pk_root = pk_seed + n;

    sk_param_set[0] = pk_param_set[0] = hash_function;
    sk_param_set[1] = pk_param_set[1] = n;
    sk_param_set[2] = pk_param_set[2] = fast;
    sk_param_set[3] = pk_param_set[3] = hash;

    if (!do_rand) goto failed;
    if (!do_rand( sk_seed, 3*n )) goto failed;

    memcpy( pk_seed, sk_pk_seed, n );

    /* Now, the hard part; compute the root */
    struct build_merkle_state state;
    if (!init_build_merkle( &state, sk_seed, sk_pk_seed,
        hash, tree_height, 
        d-1, 0,
        0, 0, pk_root)) goto failed;

    while (!step_build_merkle( &state, 0 )) {
        ;
    }

    /* The private key gets a copy of the root */
    memcpy( sk_pk_root, pk_root, n );

    return true;
failed:
    memset( sk_buffer, 0, sk_len );
    memset( pk_buffer, 0, pk_len );
    return false;
}

/* Return the length of the public key, assuming the specified setting */
size_t sh_pubkey_len( int hash_function, int hash_size, int time_space ) {
    return LEN_PUBKEY_192;  /* 192 is the only hash length we currently support */
}

/* Return the length of the private key, assuming the specified setting */
size_t sh_privkey_len( int hash_function, int hash_size, int time_space ) {
    return LEN_PRIVKEY_192;  /* 192 is the only hash length we currently support */
}
