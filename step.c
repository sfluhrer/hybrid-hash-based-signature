/*
 * This file contains the logic that will incrementally construct the next
 * LMS tree and Sphincs+ signature of that LMS public key
 */

#include "sphincs-hybrid.h"
#include "sh_signer.h"
#include "hmac_drbg.h"
#include "lm_ots_sign.h"
#include "lms_compute.h"
#include "endian.h"
#include "hmac.h"
#include "hmac.h"
#include "private_key_gen.h"
#include "zeroize.h"
#include "wots.h"
#include "lm_ots_param.h"
#include "tune.h"

#if PROFILE
#include <stdio.h>
#endif

#define LMS_LEAF_PER_ITER 2  /* During the LMS build phase, create two */
                             /* leaf nodes per step */

/*
 * Helper function that looks up where we keep the intermediate LMS
 * nodes during the rebuild process
 * Returns 0 if we this decides we don't need to store the intermediate node
 * (for_write == true only)
 */
static unsigned char *lms_storage(struct sh_signer *sign, unsigned hash_len,
        int height, int orig_leaf, int node_id, int for_write) {
    if (height < LMS_BOTTOM) {
        /* We're in the bottom subtree */
        if (orig_leaf < (1 << LMS_BOTTOM)) {
            /* We're still within the initial subtree */
            return sign->next_lms_bottom_subtree + hash_len * (
                    node_id + (1 << (LMS_BOTTOM-height)) - 2);
        } else {
            /* We're currently building nodes in the upper subtree, and so */
            /* the node we currently have would be stored in the stack. */
            /* Now, if we're writing, and this is a right-side node, we */
            /* skip the write (as that location in the stack currently */
            /* holds the left side node, which we'll need shortly) */
            /* The bitwise & below checks for this; we return 0 if */
            /* for_write == 1 AND the lsbit of node_id is 1 */
            if ((node_id & for_write) != 0) return 0;

            /* Ok, point to the location in the stack where this node is */
            /* stored */
            return &sign->temp.do_lms.stack[ hash_len * height ];
        }
    }

    height -= LMS_BOTTOM;
    if (height < LMS_TOP) {
        /* We're in the top subtree */
        return sign->next_lms_top_subtree + hash_len * (
                    node_id + (1 << (LMS_TOP-height)) - 2);
    }

    /* We're the root */
    return sign->next_lms_root;
}

#define swap( a, b, T ) {  \
    T temp = a;            \
             a = b;        \
                 b = temp; \
    }

/*
 * Some of our steps are cheaper than others.  We might not want to have
 * some signatures to be generated significantly faster than others. For
 * those cheaper steps, we call the below function with the number of
 * hash compression computations we are short (approximately).  So, if
 * we do care about equalizing the signature operations (DUMMY_LOAD = true)
 * then we waste the appropriate amount of time
 * If we don't care (DUMMY_LOAD = false), then this quickly does nothing 
 */
#define DUMMY_TARGET  (LMS_LEAF_PER_ITER * (LM_OTS_P << LM_OTS_W))
    /* The target number of hash compression operations per step */
    /* based on the approximate cost of an LMS step */
static void dummy_load( int steps ) {
#if DUMMY_LOAD
    int i;
    for (i = 0; i<steps; i++) {
        SHA256_CTX ctx;
        SHA256_Init( &ctx );
        unsigned char c = i & 0xff;
        SHA256_Update( &ctx, &c, 1 );
        unsigned char buffer[32];
        SHA256_Final( buffer, &ctx );
    }
#endif
}

/*
 * The goal of this function is to perform the next step of the process
 * of creating a signed LMS public key
 * We try to make each step approximately equal time
 * This returns true if either we've completed the new signed LMS key, or
 * if we hit a fatal error (and there's no point in trying to continue)
 *
 * do_dummy is set if we might care about equalizing the step size by
 * introducing busy work (during the load process, we don't care; we just
 * want this done as soon as possible)
 */
bool step_next( struct sh_signer *signer, bool do_dummy ) {
    if (signer->got_fatal_error) return true;

#if PROFILE
    extern long hash_compression_count; /* Most of the work is done */
                                 /* computing hashes, hence we use that */
                                 /* as the metric we try to balance */
    long start_hc = hash_compression_count; /* Remember the count */
                                 /* at the begining of the step */
    static int count[b_count];   /* Note: the profiling logic currently */
    static long total[b_count];  /* assumes we are running one signer */
    static long max_seen[b_count];
    int start_state = signer->build_state;
#endif

    switch (signer->build_state) {
    case b_init:   /* We start building a fresh LMS tree and Sphincs+ */
                   /* signature in this state */
#if PROFILE
        memset( count, 0, sizeof count ); /* This is a new run */
        memset( total, 0, sizeof total ); /* Zero out the counts */
        memset( max_seen, 0, sizeof max_seen );
#endif
        /* We're just kicking off the process */

        /* Pick the new LMS private key */
        if (!read_drbg( signer->next_lms_seed, 32, &signer->drbg ) ||
            !read_drbg( signer->next_lms_I, 16, &signer->drbg )) {
            goto failure_state;
        }
        signer->build_state = b_do_lms;
        signer->temp.do_lms.leaf = 0;
            /* The above took hardly any time; start on the first leaves */
            /* of the LMS tree */
        /* FALLTHROUGH */
    case b_do_lms: {  /* We're building the next LMS tree */
        int i;
        for (i=0; i<LMS_LEAF_PER_ITER; i++) {
            int leaf = signer->temp.do_lms.leaf++;

            unsigned char buffer[24];
            lm_ots_generate_public_key( signer->next_lms_I, leaf,
                       signer->next_lms_seed, buffer );

            int level;
            unsigned node = leaf;
            unsigned q = node | (1 << LMS_H);
            for (level = 0;; level++, node >>= 1, q >>= 1) {
                /* Check if we need to store this node */
                unsigned char *dest = lms_storage(signer, 24, level,
                               leaf, node, 1);
                if (dest) {
                    memcpy(dest, buffer, 24);
                }
                /* Check if we've reached a left node for this branch */
                if ((node & 1) == 0) {
                    if (level == LMS_H - LMS_FAKE) {
                        /* We've completed this tree */
                        signer->build_state = b_lms_finished;
                        i = LMS_LEAF_PER_ITER-1; /* This will cause us to */
                                                 /* abort the outer loop */
                    }
                    break;
                }
                /* We're a right node */
                /* Get the corresponding left node */
                unsigned char *left = lms_storage(signer, 24, level,
                               leaf, node^1, 0);
                /* Combine them */
                lms_combine_internal_nodes( buffer, left, buffer,
                               signer->next_lms_I, 24, q>>1);
            }
        }
        break;
    }
    case b_lms_finished: {  /* We're putting the last touches on the */
                            /* next LMS tree */
            /* We can do our computations in place (we won't need the */
            /* original root value after this) */
        unsigned char *buffer = signer->next_lms_root;
#if LMS_FAKE
        /*
         * Pick arbitrary values for the faked portion of the authentication
         * path.  Literally any values would work here (including a fixed
         * 'all-zero' pattern), we pick random values mostly to avoid awkward
         * questions (and we have plenty of time in this step)
         */
        (void)read_drbg( signer->next_fake, 24 * LMS_FAKE, &signer->drbg );

        /* Walk up the faked auth path to form the real root key */ 
        int height;
        for (height = LMS_FAKE-1; height >= 0; height--) {
            lms_combine_internal_nodes( buffer, buffer,
                             &signer->next_fake[ (LMS_FAKE-1-height) * 24 ],
                             signer->next_lms_I, 24, 1 << height);
        }
#endif
        /* Now, build the LMS public key */
        put_bigendian( &signer->next_lms_pub_key[0], 1, 4 );
        put_bigendian( &signer->next_lms_pub_key[4], 0xe0000028, 4 );
        put_bigendian( &signer->next_lms_pub_key[8], LM_OTS_PARAM_ID, 4 );
        memcpy( &signer->next_lms_pub_key[12], signer->next_lms_I, 16 );
        memcpy( &signer->next_lms_pub_key[12+16], buffer, 24 );

        /* We now start building the Sphincs+ signature of the LMS public */
        /* key.  It would make sense to step to another build_state to */
        /* mark the total change of direction; however since we are */
        /* nowhere close to the time limit on this one, we don't */

        /* We start by generating the R value.  We use the method from */
        /* the Sphincs+ doc, even though it is overkill in our case (both */
        /* because we have a seeded DRBG at our disposal, and we really */
        /* don't need the protection that R gives, as we don't need to */
        /* worry about collision attacks).  However, we have plenty of */
        /* time, so we might as well do things by the book */
        struct hmac_engine hmac;
        init_hmac( &hmac, signer->sk_prf, 24 );
        unsigned char r[32];
        (void)read_drbg( r, 24, &signer->drbg );
        update_hmac( &hmac, r, 24 );
        update_hmac( &hmac, signer->next_lms_pub_key, LEN_LMS_PUBLIC_KEY );
        final_hmac( r, &hmac, signer->sk_prf, 24 );

        /* write r to the Sphincs signature */
        memcpy( signer->next_sphincs_sig, r, 24 );
        signer->sphincs_sig_index = 24;

        /* expand it to the digit index that Sphincs+ expects */
        do_compute_digest_index( signer->temp.do_fors.md,
               &signer->idx_tree, &signer->idx_leaf,
               24, r, signer->pk_seed, signer->root,
               signer->next_lms_pub_key, LEN_LMS_PUBLIC_KEY,
               SPH_K, SPH_A, SPH_H, SPH_D);
        /* And now we arrange the next step to start building the FORS */
        /* public keys */
        signer->temp.do_fors.tree = 0;
        signer->temp.do_fors.leaf = 0;
        signer->temp.do_fors.redundant_pass = false;
        signer->build_state = b_fors;

        /* This step was fairly cheap, add a dummy load */
        if (do_dummy) dummy_load( DUMMY_TARGET - 50 );
        break;
    }
    case b_fors: {    /* We're working on the FORS part of the Sphincs+ */
                      /* signature */
        unsigned char adr[LEN_ADR];
        set_layer_address( adr, 0 );
        set_tree_address( adr, signer->idx_tree );
        set_type( adr, FORS_TREE_ADDRESS );
        struct private_key_generator gen;
        init_private_key_gen( &gen, signer->sk_seed, 24, adr,
                              ADR_CONST_FOR_TREE );

        unsigned leaf = signer->temp.do_fors.leaf;
        unsigned target = signer->temp.do_fors.md[ signer->temp.do_fors.tree ];
        int i;
        set_key_pair_address( adr, signer->idx_leaf );
        unsigned char buffer[32];
#if SPEED_SETTING
#define FORS_LEAFS_PER_ITER 220  /* Generating this many FORS leaves takes */
           /* approximately the same time as the LMS step with W=2 */
#else
#define FORS_LEAFS_PER_ITER 410  /* Generating this many FORS leaves takes */
           /* approximately the same time as the LMS step with W=4 */
#endif
        for (i = 0; i < FORS_LEAFS_PER_ITER; i++) {
            set_tree_height( adr, 0 );
            set_tree_index( adr, 0 );
            unsigned node = leaf;
            unsigned full_node_name = leaf +
                                       (signer->temp.do_fors.tree << SPH_A);
            set_tree_index( adr, full_node_name );

            do_private_key_gen(buffer, 24, &gen, &adr[LEN_ADR-16] );
            if (leaf == target) {
                /* We're talking about the leaf we reveal */
                memcpy( &signer->next_sphincs_sig[signer->sphincs_sig_index],
                        buffer, 24 );
            }
            do_F( buffer, HASH_TYPE_SHA256 | HASH_LEN_192,
                       &signer->pk_seed_pre, adr, buffer );
            int level;
            for (level = 0; level < SPH_A; ) {
                if ((node^1) == (target >> level)) {
                    /* This node is on the authentication path */
                    int write_index = signer->sphincs_sig_index + 24*(1+level);
                    memcpy( &signer->next_sphincs_sig[ write_index ],
                        buffer, 24 );
                }
                if (node & 1) {
                    /* This is the right node, combine it with the left node */
                    /* we have previous computed */
                    node >>= 1;
                    full_node_name >>= 1;
                    set_tree_index( adr, full_node_name );
                    set_tree_height( adr, level+1 );
                    do_H( buffer, HASH_TYPE_SHA256 | HASH_LEN_192,
                          &signer->pk_seed_pre, adr,
                          &signer->temp.do_fors.stack[level * 24], buffer );
                    level++;
                } else {
                    /* This is the left node, store so we can combine it */
                    /* later iwith the right node */ 
                    memcpy(&signer->temp.do_fors.stack[level * 24], buffer, 24);
                    break;
                }
            }
            leaf++;
            if (leaf == (1 << SPH_A)) {
                /* We hit the root */
                void *target = &signer->temp.do_fors.fors_roots[
                         (24/4) * signer->temp.do_fors.tree ];
                leaf = 0; /* We're always restart at the beginning (either */
                          /* this FORS tree or the next) */
#if FAULT_STRATEGY
                if (!signer->temp.do_fors.redundant_pass) {
                    /* This is the first pass; rerun with the second */
                    memcpy( target, buffer, 24 );
                    signer->temp.do_fors.redundant_pass = true;
                    break;
                }
                /* This is the second pass; check if we got the same */
                /* result as the first time */
                if (0 != memcmp( target, buffer, 24 )) {
#if FAULT_STRATEGY == 2
                    /* We miscomputed, try again */
                    signer->temp.do_fors.redundant_pass = false;
                    break;
#else
                    /* We miscomputed, give up */
                    goto failure_state; 
#endif
                }
#else
                /* Save this FORS root */
                memcpy( target, buffer, 24 );
#endif

                /* Step to the next tree */
                signer->temp.do_fors.tree++;
                signer->sphincs_sig_index += 24 * (1 + SPH_A);
                signer->temp.do_fors.redundant_pass = false;
                break;
            }
        }
        signer->temp.do_fors.leaf = leaf;
        zeroize( buffer, sizeof buffer );
        zeroize( &gen, sizeof gen );

        if (signer->temp.do_fors.tree == SPH_K) {
            /* We've gone through all the FORS trees */
            /* Next step: combine the roots to form the top level value */
            signer->build_state = b_complete_fors;
        }
        break;
    }
    case b_complete_fors: {  /* We've computed all the roots of the FORS */
                             /* trees, now complete the process of */
                             /* computing the FORS public key */
        /* Combine the roots to form the top level value */
        unsigned char adr[LEN_ADR];
        set_layer_address( adr, 0 );
        set_tree_address( adr, signer->idx_tree );
        set_type( adr, FORS_TREE_ROOT_COMPRESS );
        set_key_pair_address( adr, signer->idx_leaf );
        unsigned char buffer[ MAX_HASH_LEN ];
        do_thash( buffer, HASH_TYPE_SHA256 | HASH_LEN_192,
                  &signer->pk_seed_pre, adr,
                  signer->temp.do_fors.fors_roots, SPH_K * 24 );

        /* Now, compute it again, and see if we come up with the same answer */
        /* We do this even if we're not in redundant mode, because it's */
        /* so cheap */
        unsigned char buffer2[ MAX_HASH_LEN ];
        do_thash( buffer2, HASH_TYPE_SHA256 | HASH_LEN_192,
                  &signer->pk_seed_pre, adr,
                  signer->temp.do_fors.fors_roots, SPH_K * 24 );

        if (0 != memcmp( buffer, buffer2, 24 )) {
#if FAULT_STRATEGY == 2
            /* They did't match; rerun this step again */
            break;
#else
            /* They did't match; declare that we give up */
            goto failure_state;
#endif
        }

        /* Next step; start in on the hypertree */
        memcpy( signer->temp.do_hyper.prev_root, buffer, 24 );
        signer->temp.do_hyper.level = 0;
        signer->temp.do_hyper.do_tree = 0;
        signer->build_state = b_hypertree;

        /* This step was fairly cheap, add a dummy load */
        if (do_dummy) dummy_load( DUMMY_TARGET - 50 );
        break;
    }
    case b_hypertree:  /* We're building the Sphincs+ hypertree */
        if (signer->temp.do_hyper.do_tree == 0) {
            int hc_done_so_far = 0; /* Count of the number of hash */
                                    /* computations we've done */
            /* We're working on a WOTS+ signature within the hypertree */
            signer->temp.do_hyper.save_sphincs_sig_index =
                  signer->sphincs_sig_index; /* In case we need to restart */
            /*
             * Note that we don't compute the WOTS+ signature redundantly;
             * that's because we don't use this OTS signature to compute the
             * next root; hence a failure here doesn't allow anyone to forge
             */
            unsigned char digits[51];
            
            if (51 != expand_wots_digits( digits, 51,
                                signer->temp.do_hyper.prev_root, 24 )) {
                goto failure_state;
            }
            unsigned char adr[LEN_ADR];
            set_layer_address( adr, signer->temp.do_hyper.level );
            set_tree_address( adr, signer->idx_tree );
            set_type( adr, WOTS_HASH_ADDRESS );
            set_key_pair_address( adr, signer->idx_leaf );

            int i;
            unsigned char *target = &signer->next_sphincs_sig[
                                               signer->sphincs_sig_index ];
            struct private_key_generator gen;
            init_private_key_gen( &gen, signer->sk_seed, 24, adr,
                                  ADR_CONST_FOR_TREE );
            hc_done_so_far += 1; /* init_key_gen does about 1 hash comp */

            /* Compute the WOTS signature */
            for (i=0; i<51; i++) {
                set_chain_address( adr, i );
                set_hash_address( adr, 0 );
                do_private_key_gen( target, 24, &gen, &adr[LEN_ADR-16] );
                hc_done_so_far += 1; /* private_key_gen does 1 hash comp */
                int j;
                for (j=0; j<digits[i]; j++) {
                    set_hash_address( adr, j );
                    do_F( target, HASH_TYPE_SHA256|HASH_LEN_192,
                             &signer->pk_seed_pre, adr, target );
                    hc_done_so_far += 1; /* F does 1 hash comp */
                }
                target += 24;
            }

            zeroize( &gen, sizeof gen );

            /* This step was cheaper than our goal; even it out */
            if (do_dummy) dummy_load( DUMMY_TARGET - hc_done_so_far );

            /* We've generated the OTS; now start on the auth path */
            signer->sphincs_sig_index += 51 * 24;
            signer->temp.do_hyper.do_tree = 1;

            init_build_merkle( &signer->temp.do_hyper.merk,
                               signer->sk_seed, signer->pk_seed,
                               HASH_TYPE_SHA256|HASH_LEN_192,
                               SPH_T,
                               signer->temp.do_hyper.level,
                               signer->idx_tree,
                               signer->idx_leaf,
                               &signer->next_sphincs_sig[
                                          signer->sphincs_sig_index],
                               signer->temp.do_hyper.next_root);
            break;
        } else {
            int hc_done_so_far = 0;
            /* We're working on a Merkle tree itself within the hypertree */
            bool completed_merkle = step_build_merkle(
                             &signer->temp.do_hyper.merk, &hc_done_so_far );

            if (do_dummy) dummy_load( DUMMY_TARGET - hc_done_so_far );

            if (completed_merkle) {
                /* We're done with this tree */
#if FAULT_STRATEGY
                /* Note: if we're the very top tree, we don't have to */
                /* confirm it (as there is no higher level WOTS signature */
                /* Currently, we check it anyways (as skipping the check */
                /* would save only circa 1% on load time) */
 
                if (signer->temp.do_hyper.do_tree == 1) {
                    /* Start recomputing the tree */
                    signer->temp.do_hyper.do_tree = 2;
                    init_build_merkle( &signer->temp.do_hyper.merk,
                               signer->sk_seed, signer->pk_seed,
                               HASH_TYPE_SHA256|HASH_LEN_192,
                               SPH_T,
                               signer->temp.do_hyper.level,
                               signer->idx_tree,
                               signer->idx_leaf,
                               NULL,
                               signer->temp.do_hyper.redundant_root);
                    break;
                }
                /* Check if we came up with the same answer */
                if (0 != memcmp( signer->temp.do_hyper.next_root,
                                 signer->temp.do_hyper.redundant_root,
                                 24 )) {
#if FAULT_STRATEGY == 2
                    /* Came up with two different answers: restart */
                    /* This is the easiest way to restart */
                    signer->sphincs_sig_index = 
                         signer->temp.do_hyper.save_sphincs_sig_index;
                    signer->temp.do_hyper.do_tree = 0;
                    break;
#else
                    /* Came up with two different answers: error */
                    goto failure_state;
#endif

                }
#endif
                /* Accept this root */
                memcpy( signer->temp.do_hyper.prev_root,
                        signer->temp.do_hyper.next_root, 24 );

                /* Step to the next higher layer */
                signer->sphincs_sig_index += SPH_T * 24;
                signer->idx_leaf = signer->idx_tree & ((1 << SPH_T) - 1);
                signer->idx_tree >>= SPH_T;
                signer->temp.do_hyper.do_tree = 0;
                signer->temp.do_hyper.level++;
                if (signer->temp.do_hyper.level == SPH_D) {
                    /* There are no higher levels; we've generated the */
                    /* full signature */
                    signer->build_state = b_done;
                }
            }
        }
        break;
    case b_done:    /* And, we've done the work, now we have a new LMS */
                    /* tree, and the Sphincs+ signature of that tree.  Now */
                    /* switch to using those (so that the next signature */
                    /* operation will use them) */
#if PROFILE
       /* We're at the end of the run */
       /* Print out the statistics */
       {
           int i;
           for (i=0; i<b_count; i++)
               if (count[i])
                   printf( "%d: count = %d average = %ld max = %ld\n",
                          i, count[i], total[i]/count[i], max_seen[i] );
       }
#endif
        /* Everything's in place; now switch to the newly generated */
        /* LMS tree and signature */
        memcpy( signer->current_lms_seed, signer->next_lms_seed, 32 );
        memcpy( signer->current_lms_I, signer->next_lms_I, 16 );
        swap( signer->current_lms_top_subtree, signer->next_lms_top_subtree,
                                                           unsigned char *);
        swap( signer->current_lms_bottom_subtree,
                          signer->next_lms_bottom_subtree, unsigned char *);
         
        swap( signer->current_sphincs_sig, signer->next_sphincs_sig, 
                                                          unsigned char *);
        memcpy( signer->current_lms_pub_key, signer->next_lms_pub_key,
                                                       LEN_LMS_PUBLIC_KEY );
#if LMS_FAKE
        memcpy( signer->current_fake, signer->next_fake, 24 * LMS_FAKE );
#endif
            /* We're starting at the begining of the new LMS tree */
        signer->current_lms_index = 0;
            /* And the next time, we start all over with creating a new */
            /* Merkle tree and signature (our work is never done) */
        signer->build_state = b_init;

        /* This step was quite cheap, add a dummy load */
        if (do_dummy) dummy_load( DUMMY_TARGET - 20 );
      
        return true;   /* Yes, the new LMS public key and Sphincs+ */
                       /* signature are ready to use */
    default:
    case b_count:
        goto failure_state;
    }
#if PROFILE
    /* Update the profile stats */
    long this_hc = hash_compression_count - start_hc; /* # of hash */
                       /* compression operations computed during this step */
    count[start_state] += 1;
    total[start_state] += this_hc;
    if (this_hc > max_seen[start_state]) max_seen[start_state] = this_hc;
#endif

    return false;  /* We have more work to do */

failure_state:
        /* Come here if something horrible happened */
    signer->got_fatal_error = true;
    return true;   /* Signal that we might as well give up if we're in */
                   /* the initialization phase */
}
