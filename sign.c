/*
 * This generates a Sphincs-hybrid signature
 */
#include "sphincs-hybrid.h"
#include "sh_signer.h"
#include "lm_ots_sign.h"
#include "endian.h"
#include "lms_compute.h"
#include "lm_ots_param.h"
#include <string.h>

#define swap( a, b, T ) {  \
    T temp = a;            \
             a = b;        \
                 b = temp; \
    }

bool sh_sign( void *signature, size_t len_signature_buf,
              struct sh_signer *signer,
              const void *message, size_t len_message ) {
    /* Error checking */
    if (!signature) return false;
    if (!signer || !signer->initialized || signer->got_fatal_error) {
        goto failed;
    }

    /* Parse where we'll place the three parts of the signature */
    size_t off_sphincs_sig = 0;    /* Where the Sphincs+ signature will go */
    size_t off_lm_pk = off_sphincs_sig + LEN_SPHINCS_SIG; /* Where the LMS */
                                   /* public key will go; immediately */
                                   /* after the Sphincs+ signature */
    size_t off_lm_sig = off_lm_pk + LEN_LMS_PUBLIC_KEY; /* Where the LMS */
                                   /* signature will go; immediately after */
                                   /* the LMS public key */
                                   /* The end of the entire signature */
    size_t off_end = off_lm_sig + 12 + 24 * (1 + LM_OTS_P) + 4 + 24 * 20;

    if  (len_signature_buf < off_end) {
        goto failed;   /* Oops, doesn't fit in the buffer we're given */
    }

    /* We made sure everything fits; now compute the pointers */
    unsigned char *sphincs_sig = signature + off_sphincs_sig;
    unsigned char *lm_pk = signature + off_lm_pk;
    unsigned char *lm_sig = signature + off_lm_sig;

    /* And start with the LMS signature */
    put_bigendian( lm_sig, 0, 4 ); lm_sig += 4; /* Number of signed */
                                             /* public keys in the LMS sig */
    put_bigendian( lm_sig, signer->current_lms_index, 4 ); lm_sig += 4;
                                             /* The current index */
        /* Then comes the OTS signature */
    int ots_sig_len = lm_ots_generate_signature(signer->current_lms_I,
                      signer->current_lms_index, signer->current_lms_seed,
                      message, len_message, lm_sig);
    if (ots_sig_len == 0) goto failed;
    lm_sig += ots_sig_len;

    /* And the Merkle tree part of the LMS signature */
    int n = 24;   /* Fixed hash size */
                                      /* 0xe0000028 means "N=24, H=20" */
    put_bigendian( lm_sig, 0xe0000028, 4 ); lm_sig += 4;

    /* And insert the authentication path (which we need to pull from */
    /* multiple sources */

    /* Take part of the auth path from the lower subtree */
    int which = 1 & (signer->current_lms_index >> LMS_BOTTOM);
    {
        int node_offset =
               (signer->current_lms_index & ((1 << LMS_BOTTOM) - 1)) +
                 (1 << LMS_BOTTOM) - 2;
        int i;
        for (i = 0; i < LMS_BOTTOM; i++, node_offset = (node_offset>>1) - 1) {
            int node_index = node_offset^1^which;
            memcpy( lm_sig,
                      signer->current_lms_bottom_subtree + n*node_index, n );
            lm_sig += n;
        }
    }
    /* Take part of the auth path from the top subtree */
    {
        int node_offset = (signer->current_lms_index >> LMS_BOTTOM) +
                (1 << LMS_TOP) - 2;
        int i;
        for (i = 0; i < LMS_TOP; i++, node_offset = (node_offset>>1) - 1) {
            int node_index = node_offset^1;
            memcpy( lm_sig,
                      signer->current_lms_top_subtree + n*node_index, n );
            lm_sig += n;
        }
    }
#if LMS_FAKE
    /* Include the fake part of the authentication path */
    memcpy( lm_sig, signer->current_fake, LMS_FAKE * n );
    lm_sig += LMS_FAKE * n;
#endif
    /* That's the full LMS signature */

    /* Now, include the LMS public key */
    memcpy( lm_pk, signer->current_lms_pub_key, LEN_LMS_PUBLIC_KEY );

    /* Now, include the Sphincs+ signature */
    memcpy( sphincs_sig, signer->current_sphincs_sig, LEN_SPHINCS_SIG );

    /*
     * And that completes the signature.  Now, we go set things up for the
     * next signature
     */

    /* Update the current_lms_next_subtree subtree */
    {
            /* We're doing the leaf that's 1<<LMS_BOTTOM positions from */
            /* what we just used to sign */
        unsigned leaf = signer->current_lms_index + (1 << LMS_BOTTOM);

            /* Create that OTS public key (and perform the D_LEAF hash) */
        unsigned char buffer[24];
        lm_ots_generate_public_key( signer->current_lms_I, leaf,
                       signer->current_lms_seed, buffer );

        unsigned q = leaf | (1 << LMS_H);  /* The node index we tell the */
                         /* combiner function */
        /* This is the index of current node (not including the which flag) */
        unsigned index = (leaf & ((1 << LMS_BOTTOM) - 1)) +
                                                  (1 << LMS_BOTTOM) - 2;
        for (;;) {

                /* Store this node in its position in the subtree */
            memcpy( signer->current_lms_bottom_subtree + 24 * (index ^ which ^ 1),
                                                              buffer, 24 );

            if ((index & 1) == 0) break;  /* We're the left node; we can't */
                                         /* go any further up */
            if (index <= 1) break; /* We're at the top of the bottom tree, */
                                   /* no point in going hihger */
                /* We're the right node, combine it with the previously */
                /* computed left node */
            const unsigned char *left = signer->current_lms_bottom_subtree +
                                                  24 * (index ^ which);
            q >>= 1;
            lms_combine_internal_nodes( buffer, left, buffer,
                                        signer->current_lms_I, 24, q );
            index = (index >> 1) - 1;
        }
    }

    /* Step to the next LMS index */
    signer->current_lms_index += 1;

    /* One last task; incrementally build the next LMS tree/Sphincs sig */
    /* This looks simple; however, most of the complexity is here */
    (void)step_next(signer, true);
    /* When the step function completes the entire 'build the next tree */
    /* and signature' process, it'll automatically switch us to the next */
    /* Sphincs+ signature and LMS tree.  Hence, we can ignore the return */
    /* value (which tells us when that happens), because we don't care */

    return true;   /* The signature the caller asked for has been */
                   /* successfully constructed */
failed:
    memset( signature, 0, len_signature_buf );
    return false;  /* Oops, something went wrong */
}

/*
 * This returns the length of the hybrid signature
 * Currently, it's a function of parameters from tune.h
 */
size_t sh_sig_len( struct sh_signer *signer ) {
    return LEN_SPHINCS_SIG +  /* Size of the Sphincs+ signature */
           LEN_LMS_PUBLIC_KEY + /* Size of the LMS public key */
           12 + 24 * (1 + LM_OTS_P) + 4 + 24 * 20; /* Size of LMS signature */
}
