#include "sphincs-hybrid.h"
#include "sh_signer.h"
#include "hmac_drbg.h"
#include "zeroize.h"
#include "tune.h"
#include <stdlib.h>
#include <string.h>
#include "sha256.h"

#if DUMP_SIG
#include <stdio.h>
static void dump( FILE *f, const char *name,
                  const void *data, size_t len_data );
#endif

/*
 * This loads a private key into memory, and gets it ready for use (generates
 * a fresh LMS public/private keypair, and signs it with the Sphincs+ key).
 * This takes several seconds; however one it is done, we're ready to start
 * signing
 */
struct sh_signer *sh_load_signer( const void *sk_buffer,
                bool (*do_rand)( void *buffer, size_t len_buffer ) ) {

    struct sh_signer *signer = malloc( sizeof *signer );
    if (!signer) return false;
    signer->initialized = false;
    signer->got_fatal_error = false;

    /* Initialize the rng */
    if (!seed_drbg( &signer->drbg, do_rand )) {
        free(signer);
        return false;
    }

    /* Read stuff from the secret key */
    const unsigned char *sk = sk_buffer; 
    signer->hash = sk[3];
    unsigned n;
    signer->n = n = hash_len(signer->hash);
    if (!n) { free(signer); return false; }

    memcpy( signer->sk_seed, &sk[4],   n );
    memcpy( signer->sk_prf,  &sk[4+n], n );
    memcpy( signer->pk_seed, &sk[4+2*n], n );
    memcpy( signer->root,    &sk[4+3*n], n );

    SHA256_set_first_block( &signer->pk_seed_pre, signer->pk_seed, n );

    // Init the LMS structures
    signer->current_lms_top_subtree = signer->lms_top_1;
    signer->next_lms_top_subtree = signer->lms_top_2;
    signer->current_lms_bottom_subtree = signer->lms_bottom_1;
    signer->next_lms_bottom_subtree = signer->lms_bottom_2;

    // And the Sphincs+ structures */
    signer->current_sphincs_sig = signer->sph_sig_1;
    signer->next_sphincs_sig = signer->sph_sig_2;

    signer->build_state = b_init;

    /* Ok, wack at the build process until it's completely rebuilt */
    /* the initial LMS tree and the Sphincs signature */
    /* If profiling is enabled, we're also turn on the dummy waits (so */
    /* that the profiled time taken is representative of what they'd be */
    /* while we are generating signatures */
    while (!step_next( signer, PROFILE )) {
        ;
    }

#if DUMP_SIG
    /*
     * Now that we've created the initial Sphincs+ signature, write out the
     * siganture (and the public key and the message we signed) to a file
     */
    FILE *f = fopen( "sphincs-test.h", "w" );
    if (!f) {
        free(signer);
        return false;
    }

    /* We pull the Sphincs+ public key out of the private key */
    fprintf( f, "/* This is the Sphincs+ public key */\n" );
    dump( f, "public_key", &sk[4+2*n], 2*n );

    /* Dump the message that is signed */
    fprintf( f, "/* This is the message signed by Sphincs+ */\n" );
    dump( f, "signed_message", signer->current_lms_pub_key,
                                            LEN_LMS_PUBLIC_KEY );

    /* Dump the signature (last because it is so long) */
    fprintf( f, "/* This is the the Sphincs+ signature */\n" );
    dump( f, "signature", signer->current_sphincs_sig,
                                            LEN_SPHINCS_SIG );

    fclose(f);
#endif

    signer->initialized = true;
    return signer;
}

void sh_delete_signer(struct sh_signer *signer) {
    if (signer) {
        zeroize( signer, sizeof *signer );
        free( signer );
    }
}

#if DUMP_SIG
static void dump( FILE *f, const char *name,
                  const void *data, size_t len_data ) {
    fprintf( f, "unsigned char %s[%ld] = {", name, (unsigned long)len_data );

    const unsigned char *p = data;
    size_t i;
    for (i=0; i<len_data; i++) {
        if (i % 8 == 0) fprintf( f, "\n    " );
        fprintf( f, "0x%02x,", p[i] );
    }
    fprintf( f, "\n};\n" );
}
#endif
