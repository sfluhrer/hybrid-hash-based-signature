#include "build_merkle.h"
#include "sphincs_hash.h"
#include "adr.h"
#include "private_key_gen.h"
#include "zeroize.h"

/*
 * This is the object that incrementally builds a Merkle tree, and produces
 * the authentication path to the specified node (target_node) and the
 * root value
 * This does it incrementally, because we want to be able to spread the work
 * over a number of signature generation requests
 * This is split out of the full step procedure because the public key
 * generation process also uses this (and also to limit the size of the
 * step function, which is already too huge)
 *
 * The point of this object is to place the results into auth_path and root
 * If auth_path is non-NULL, then the authentication path for target_node
 *   is placed there
 * If root is non-NULL, then the root node value is placed there
 */

bool init_build_merkle( struct build_merkle_state *state,
        const void *sk_seed, const void *pk_seed,
        hash_t hash, int tree_height,
        unsigned layer, uint_fast64_t tree,
        int target_node, unsigned char *auth_path,
        unsigned char *root) {
    state->sk_seed = sk_seed;
    state->pk_seed = pk_seed;
    SHA256_set_first_block(&state->pk_seed_pre, pk_seed, hash_len(hash));
    state->hash = hash;
    state->n = hash_len(hash);
    switch (hash_len( hash )) {
    case 16: state->wots_digits = 32 + 3; break;
    case 24: state->wots_digits = 48 + 3; break;
    case 32: state->wots_digits = 64 + 3; break;
    default: return false;
    }
    state->tree_height = tree_height;
    state->target_node = target_node;
    set_layer_address( state->adr, layer );
    set_tree_address( state->adr, tree );
    /* The rest of adr will be initialized later */
    state->auth_path = auth_path;
    state->root = root;
    state->current_node = 0;

    return true;
}

/* 
 * This performs the next step in producing the authentication path and/or
 * the root 
 * This returns TRUE if we're done
 * If ret_hc is non-NULL, we place the number of hash compression operations
 * we've done there
 */
bool step_build_merkle(struct build_merkle_state *state,
                       int *ret_hc) {

    int hc_done_so_far = 0; /* Count of the number of hash */
                            /* computations we've done */

#if SPEED_SETTING
#define MERKLE_CHAINS_PER_ITER 1   /* generating 1 OTS public key takes */
                               /* about as long as the LMS step with W=2 */
#else
#define MERKLE_CHAINS_PER_ITER 2   /* generating 2 OTS public keys takes */
                               /* about as long as the LMS step with W=4 */
#endif
    int m;
    struct private_key_generator gen;
    bool all_done_flag = false;

    for (m=0; m<MERKLE_CHAINS_PER_ITER; m++) {
        int current_node = state->current_node;
        if (current_node >= (1 << state->tree_height)) {
            /* We're done */
            all_done_flag = true;
            break;
        }

        /* Fire up the engine that'll produce private WOTS keys */
        init_private_key_gen( &gen, state->sk_seed, state->n, state->adr,
                              ADR_CONST_FOR_TREE );
        hc_done_so_far += 1; /* This does about 1 hash compression operation */
    
        /* Build a WOTS public key */
        int i;
        set_type( state->adr, WOTS_HASH_ADDRESS );
        set_key_pair_address( state->adr, current_node );
        int n = state->n;
    
        uint32_t wots_buffer[MAX_HASH_LEN/4 * MAX_WOTS_DIGITS]; /* We store */
                                 /* the tops of the WOTS+ chains here */
        for (i = 0; i < 51; i++) {
            set_chain_address( state->adr, i );
    
            /* Create the private WOTS+ key */
            set_hash_address( state->adr, 0 );
            void *digit = &wots_buffer[ (n/4)*i ];
            do_private_key_gen( digit, n, &gen, &state->adr[LEN_ADR-16] );
    
            /* Now, advance it to the top of the WOTS+ chain */
            int j;
            for (j=0; j<15; j++) {
                set_hash_address( state->adr, j );
                do_F(digit, state->hash, &state->pk_seed_pre, state->adr,
                                                                     digit);
            }
        }
            /* The number of hash compression operations we've done in the */
            /* above loop */
        hc_done_so_far += 51 * (1 + 15);
    
        /* We've computing all the public WOTS digits */
        /* Now, compress the hashes into a single value */
        set_type( state->adr, WOTS_KEY_COMPRESSION );
        set_key_pair_address( state->adr, current_node );
        unsigned char buffer[ MAX_HASH_LEN ];
    
        do_thash( buffer, state->hash, &state->pk_seed_pre, state->adr,
                  wots_buffer, n * state->wots_digits );\
            /* The approximate number of hashes in the above t-hash */
        hc_done_so_far += (n * state->wots_digits) / 16 + 1 +
                          (n * state->wots_digits) / 32;
    
        /* We've put the full WOTS public key */
        /* Now, walk up the Merkle tree to combine it with previous computed */
        /* WOTS public keys */
        int h;
        for (h = 0;; h++) {
            if (state->auth_path) {
                /* If this node is on the authentication path (that is, */
                /* adjacent to the path from the root to the target node), */
                /* write it out */
                if ((state->target_node^current_node) >> h == 1) {
                    memcpy( state->auth_path + h*n, buffer, n );
                }
            }
            /* Check which child we are to the node immediately above us */
            if (current_node & (1<<h)) {
                /* We're the right child at this node */
                /* Combine it with the corresponding left child */
                set_type(state->adr, HASH_TREE_ADDRESS);
                set_tree_height(state->adr, h+1 );
                set_tree_index(state->adr, current_node >> (h+1));
                do_H(buffer, state->hash, &state->pk_seed_pre, state->adr,
                     state->stack + h*n, buffer );
                hc_done_so_far += 2;  /* a do_H does 2 hash compressios */
            } else {
                if (h == state->tree_height) {
                    /* Actually, there is no node above us; we're at the top */
                    /* of the tree (aka the root) */
                    if (state->root) memcpy( state->root, buffer, n );
                    all_done_flag = true;  /* We built the entire tree */
                } else {
                    /* We're the left child at this node */
                    /* Store it for when we have computed the right child */
                    memcpy( state->stack + h*n, buffer, n );
                }
                break;
            }
        }

        /* On the next iteration, start working on the next WOTS leaf */
        state->current_node += 1;
    }

    zeroize( &gen, sizeof gen );  /* There's private data here */

    if (ret_hc) *ret_hc = hc_done_so_far;
    return all_done_flag;
}
