#if !defined( BUILD_MERKLE_H_ )
#define BUILD_MERKLE_H_

#include <stdbool.h>
#include <stdint.h>
#include "sphincs_hash.h"
#include "adr.h"
#include "sha256.h"

#define MAX_WOTS_DIGITS 51   /* Need to move this somewhere else */
#define MAX_XMSS_HEIGHT 8    /* The maximum height of a single XMSS tree */

struct build_merkle_state {
    const void *sk_seed, *pk_seed;
    SHA256_FIRSTBLOCK pk_seed_pre;

    hash_t hash; int n;
    int wots_digits;         /* Number of digits we compute for each leaf */
    int tree_height;         /* The height of the XMSS tree */
    int target_node;         /* If we're generating an authentication path */
                             /* then this is node the auth path is for */
    unsigned char adr[LEN_ADR];
    unsigned char *auth_path; /* Where to place the authentication path */
    unsigned char *root;     /* Where to place the computed root */
    int current_node;        /* Which XMSS leaf we're working on */
    unsigned char stack[MAX_HASH_LEN * MAX_XMSS_HEIGHT]; /* Stack used to */
                             /* compute the internal XMSS tree nodes */
};

/*
 * Initialize the computation of the Merkle tree, including where to
 * return the authentication path and the computed root
 */
bool init_build_merkle( struct build_merkle_state *state,
        const void *sk_seed, const void *pk_seed,
        hash_t hash, int tree_height,
        unsigned layer, uint_fast64_t tree,
        int target_node, unsigned char *auth_path,
        unsigned char *root);

/*
 * Perform the next step in the computation of the Merkle tree.  Returns
 * true when we have completed the computation.
 * If ret_hc is non-NULL, the number of hash computations performed is
 * written there
 */
bool step_build_merkle(struct build_merkle_state *state,
        int *ret_hc);

#endif /* BUILD_MERKLE_H_ */
