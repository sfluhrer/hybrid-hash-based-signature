#include <stdbool.h>
#include "sphincs-hybrid.h"
#include "endian.h"
#include "sphincs_hash.h"
#include "sha256.h"
#include "lms_common_defs.h"
#include "lm_ots_common.h"
#include "lm_ots_param.h"
#include "adr.h"
#include "wots.h"

/*
 * Verify a signature
 */
bool sh_verify( const void *message, size_t len_message,
                const void *signature, size_t len_signature,
                const void *public_key ) {

    /* Parse where the components are in the signature */
    size_t off_sphincs_sig = 0;    /* Where the Sphincs+ signature is */
    size_t off_lm_pk = off_sphincs_sig + 17064; /* Where the LMS public key */
                                   /* is */
        /* Check on the parameter set this signature uses */
    if (len_signature < off_lm_pk + 12) return false;
    unsigned n = 24;  /* All defined parameter sets currently use n=24 */
    unsigned w;
    unsigned p;
    unsigned ls;
    unsigned type;
    switch (get_bigendian(signature + off_lm_pk + 8, 4)) {
    case LM_OTS_W4_PARAM_ID:
        type = LM_OTS_W4_PARAM_ID;
        w = LM_OTS_W4_W;
        p = LM_OTS_W4_P;
        ls = LM_OTS_W4_LS;
        break;
    case LM_OTS_W2_PARAM_ID:
        type = LM_OTS_W2_PARAM_ID;
        w = LM_OTS_W2_W;
        p = LM_OTS_W2_P;
        ls = LM_OTS_W2_LS;
        break;
    default:
        return false;   /* Unrecognized parameter set */
    }
#define LMS_H   20  /* We always use a height 20 LMS tree */

    size_t off_ots_sig = off_lm_pk + 52; /* Where the OTS signature is */
    size_t off_lm_sig = off_ots_sig + 12 + 24 * (1 + p); /* There the LM */
                                       /* portion of the LMS signature is */
    size_t off_end = off_lm_sig + 4 + 24 * LMS_H; /* The end of the signature */

    if  (len_signature < off_end) {
        return false;    /* Oops, signature not long enough */
    }

        /* Everything's there (or at least, some bits are there, we */
        /* haven't validated the bits yet) */
        /* Now divvy up the signature into its component parts */
        /* The Sphincs+ signature */
    const unsigned char *sphincs_sig = signature + off_sphincs_sig;
        /* The LMS public key */
    const unsigned char *lm_pk = signature + off_lm_pk;
        /* The OTS portion of the LMS signature (and the LMS signature */
        /* header) */
    const unsigned char *lm_ots_sig = signature + off_ots_sig;
       /* The Merkle tree portion of the LMS signature*/
    const unsigned char *lm_sig = signature + off_lm_sig;

    const unsigned char *I = lm_pk + 12;
    const unsigned lm_type = 0xe0000028; /* How we say 'SHA-256/192, H=20 */

    /* Check the various green bytes to make sure they're the expected values */
    if (0    != get_bigendian( lm_ots_sig + 0, 4 ) ||
        type != get_bigendian( lm_ots_sig + 8, 4 ) ||
        lm_type != get_bigendian( lm_sig + 0, 4 ) ||
        1    != get_bigendian( lm_pk + 0, 4 ) ||
        lm_type != get_bigendian( lm_pk + 4, 4 )) {
        return false;  /* Parameter set not what we expect */
    }

    unsigned char buffer[ MAX_HASH_LEN + 2 ];
    SHA256_CTX ctx;

    /* Compute the randomized hash of the message */
    SHA256_Init(&ctx);

    unsigned lms_leaf;
    {
        /* First, we hash the message prefix */
        unsigned char prefix[MESG_PREFIX_MAXLEN];
        memcpy( prefix + MESG_I, I, I_LEN );
        lms_leaf = get_bigendian( lm_ots_sig + 4, 4 );
        if (lms_leaf >= (1 << LMS_H)) return 0;  /* Index out of range */
        put_bigendian( prefix + MESG_Q, lms_leaf, 4 );
        SET_D( prefix + MESG_D, D_MESG );
        memcpy( prefix + MESG_C, lm_ots_sig + 12, n );
        SHA256_Update(&ctx, prefix, MESG_PREFIX_LEN(n) );

        /* And the message */
        SHA256_Update(&ctx, message, len_message );
        SHA256_Final( buffer, &ctx );
    }

    /* Now, reconstruct the putative OTS public key */
    /* Append the checksum to the randomized hash */
    put_bigendian( &buffer[n], lm_ots_compute_checksum(buffer, n, w, ls), 2 );

    {
        /* This is the OTS top level hash */
        SHA256_CTX final_ctx;
        SHA256_Init(&final_ctx);
  
        unsigned char prehash_prefix[ PBLC_PREFIX_LEN ];
        memcpy( prehash_prefix + PBLC_I, I, I_LEN );
        put_bigendian( prehash_prefix + PBLC_Q, lms_leaf, 4 );
        SET_D( prehash_prefix + PBLC_D, D_PBLC );
        SHA256_Update(&final_ctx, prehash_prefix,
                                PBLC_PREFIX_LEN );

        int i;
        unsigned char tmp[ITER_MAX_LEN];

        /* Preset the parts of tmp that don't change */
        memcpy( tmp + ITER_I, I, I_LEN );
        put_bigendian( tmp + ITER_Q, lms_leaf, 4 );

        unsigned max_digit = (1<<w) - 1;
        const unsigned char *y = lm_ots_sig + 12 + n;
        for (i=0; i<p; i++) {
            put_bigendian( tmp + ITER_K, i, 2 );
            memcpy( tmp + ITER_PREV, y + i*n, n );
            unsigned a = lm_ots_coef( buffer, i, w );
            unsigned j;
            for (j=a; j<max_digit; j++) {
                tmp[ITER_J] = j;
                SHA256_Init(&ctx);
                SHA256_Update(&ctx, tmp, ITER_LEN(n) );
                SHA256_Final(tmp + ITER_PREV, &ctx);
            }

            SHA256_Update(&final_ctx, tmp + ITER_PREV, n );
        }

        /* Ok, finalize the public key hash */
        SHA256_Final( buffer, &final_ctx );
    }

    /* Now, step up through the Merkle tree to get the putative LMS pk */
    {
        const unsigned char *y = lm_sig + 4;
        unsigned node_num = lms_leaf + (1<<LMS_H);

        /* The lowest level leaf hash */
        unsigned char ots_sig[LEAF_MAX_LEN];
        memcpy( ots_sig + LEAF_I, I, I_LEN );
        put_bigendian( ots_sig + LEAF_R, node_num, 4 );
        SET_D( ots_sig + LEAF_D, D_LEAF );
        memcpy( ots_sig + LEAF_PK, buffer, n );
        SHA256_Init( &ctx );
        SHA256_Update( &ctx, ots_sig, LEAF_LEN(n) );
        SHA256_Final(buffer, &ctx);

        /* Now, walk up the authentication path */
        unsigned char prehash[ INTR_MAX_LEN ];
        memcpy( prehash + INTR_I, I, I_LEN );
        SET_D( prehash + INTR_D, D_INTR );
        while (node_num > 1) {
            if (node_num % 2) {
                memcpy( prehash + INTR_PK + 0, y, n );
                memcpy( prehash + INTR_PK + n, buffer, n );
            } else {
                memcpy( prehash + INTR_PK + 0, buffer, n );
                memcpy( prehash + INTR_PK + n, y, n );
            }
            y += n;
            node_num /= 2;
            put_bigendian( prehash + INTR_R, node_num, 4 );
            SHA256_Init( &ctx );
            SHA256_Update( &ctx, prehash, INTR_LEN(n) );
            SHA256_Final(buffer, &ctx);
        }
    }

    /*
     * The LMS part of the signature passes if the computed public key
     * agrees with the root in the LMS public key
     */
    const unsigned char *lms_root_hash = lm_pk + 28;
    if (0 != memcmp( buffer, lms_root_hash, n )) {
        return false;   /* The LMS signature did not verify */
    }

    /*
     * Now, start on the verification of the Sphincs+ signature of the
     * LMS public key
     */
    const unsigned char *r = sphincs_sig + 0;  /* The randomizer used to */
                /* hash the message that was signed (the LMS public key) */
    sphincs_sig += n;
    const unsigned char *s_pk_seed = (unsigned char *)public_key + 4;
    SHA256_FIRSTBLOCK pk_seed_pre;
    SHA256_set_first_block( &pk_seed_pre, s_pk_seed, n );
    
    const unsigned char *s_root = (unsigned char *)public_key + 4 + n;
    /* We use the 192-S parameter set, summarized by these settings */
#define SPH_K    14   /* Number of FORS trees */
#define SPH_A    16   /* Height of each FORS tree */
#define SPH_H    64   /* Total hypertree height */
#define SPH_D     8   /* Number of tree layers */
#define SPH_T    (SPH_H / SPH_D) /* Height of each Merkle tree */
#define SPH_DLEN (SPH_D * 51) /* Total number of hashes in the WOTS sigs */
#define LEN_LMS_PUBLIC_KEY (4 + 4 + 4 + 16 + 24)
    uint32_t buffer2[SPH_K];
    uint64_t idx_tree;
    unsigned idx_leaf;

    /* Convert the message (and the random vector r) into the set of */
    /* revealed FORS digits, and the exact branch in the hypertree that */
    /* the FORS trees hang off of */
    do_compute_digest_index( buffer2, &idx_tree, &idx_leaf,
               24, r, s_pk_seed, s_root,
               lm_pk, LEN_LMS_PUBLIC_KEY,
               SPH_K, SPH_A, SPH_H, SPH_D);

    /* Now, walk up the FORS trees */
    {
        uint32_t fors_roots[SPH_K*(24/4)];
        unsigned char adr[LEN_ADR];
        set_layer_address( adr, 0 );
        set_tree_address( adr, idx_tree );
        set_type( adr, FORS_TREE_ADDRESS );
        set_key_pair_address( adr, idx_leaf );
        int i;
        for (i=0; i < SPH_K; i++) {
            int node = buffer2[i];
            node += (i << SPH_A);
            uint32_t *buffer = &fors_roots[ i * 24/4 ];
            set_tree_index( adr, node );
            set_tree_height( adr, 0 );
            do_F( buffer, HASH_TYPE_SHA256 | HASH_LEN_192, &pk_seed_pre, adr,
                 sphincs_sig );
            sphincs_sig += 24;
            int level;
            for (level = 0; level < SPH_A; level++, node >>= 1) {
                set_tree_index( adr, node >> 1 );
                set_tree_height( adr, level+1 );
                if (node & 1) {
                    do_H( buffer, HASH_TYPE_SHA256 | HASH_LEN_192,
                          &pk_seed_pre, adr, sphincs_sig, buffer );
                } else {
                    do_H( buffer, HASH_TYPE_SHA256 | HASH_LEN_192,
                          &pk_seed_pre, adr, buffer, sphincs_sig );
                }
                sphincs_sig += n;
             }
         }

         /* Hash all the roots together to come up with the FORS public key */
         set_type( adr, FORS_TREE_ROOT_COMPRESS );
         set_key_pair_address( adr, idx_leaf );
         do_thash( buffer, HASH_TYPE_SHA256 | HASH_LEN_192,
                      &pk_seed_pre, adr, fors_roots, SPH_K * 24 );
    }

        /* Now, step up the hypertree */
    {
        int level;
        unsigned char adr[LEN_ADR];
        for (level = 0; level < SPH_D; level++) {
            unsigned char digits[51];
            expand_wots_digits( digits, 51, buffer, 24 );

            set_layer_address( adr, level );
            set_tree_address( adr, idx_tree );
            set_type( adr, WOTS_HASH_ADDRESS );
            set_key_pair_address( adr, idx_leaf );
            uint32_t wots_root[51 * 24/4];
            int i;
            for (i = 0; i<51; i++) {
                uint32_t *p = &wots_root[ i * 24/4 ];
                memcpy( p, sphincs_sig, 24 );
                sphincs_sig += 24;
                set_chain_address( adr, i );
                int j;
                for (j = digits[i]; j < 15; j++) {
                    set_hash_address( adr, j );
                    do_F( p, HASH_TYPE_SHA256|HASH_LEN_192,
                          &pk_seed_pre, adr, p );
                }
            }
            set_type( adr, WOTS_KEY_COMPRESSION );
            set_key_pair_address( adr, idx_leaf );
            do_thash( buffer, HASH_TYPE_SHA256|HASH_LEN_192, &pk_seed_pre,
                      adr, wots_root, 24 * 51 );

            set_type( adr, HASH_TREE_ADDRESS );
            for (i = 0; i < SPH_D; i++, idx_leaf >>= 1) {
                set_tree_height(adr, i+1 );
                set_tree_index(adr, idx_leaf >> 1 );
                if (idx_leaf & 1) {
                    do_H(buffer, HASH_TYPE_SHA256|HASH_LEN_192, &pk_seed_pre,
                             adr, sphincs_sig, buffer );
                } else {
                    do_H(buffer, HASH_TYPE_SHA256|HASH_LEN_192, &pk_seed_pre,
                             adr, buffer, sphincs_sig );
                }
                sphincs_sig += 24;
             }

             idx_leaf = (unsigned)idx_tree & ((1 << SPH_T) - 1);
             idx_tree >>= SPH_T;
        }
    }

    /*
     * Now, check if the top level Merkle root we computed matches what's in
     * the Sphincs+ public key
     */
    if (0 == memcmp( buffer, s_root, 24)) {
        return true;   /* Both the LMS signature of the message, and the */
                       /* Sphinc+ signature of the LMS public key */
                       /* validates; everything checks out */
    } else {
        return false;  /* Oops, something's wrong */
    }
}

