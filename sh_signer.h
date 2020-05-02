#if !defined(SH_SIGNER_H_)
#define SH_SIGNER_H_

#include "sphincs_hash.h"
#include "hmac_drbg.h"
#include "build_merkle.h"
#include "tune.h"
#include "lms_common_defs.h"
#include "sha256.h"
#include <stdbool.h>

/* These defines are about the LMS architecture */
#define LMS_H     20   /* Total of 20 LMS levels */

/*
 * We have a nominal 13 level actual tree, except:
 * - If we're in fast mode, we need to bump up the level by one (because we
 *   need more steps to make sure the next Sphincs+ sig is ready, as each
 *   step does about half as much work) 
 * - If we're in fault tolerant mode, we need to bump up the level by one
 *   (because we essentially need to compute everything twice); if we're
 *   attempting fault recovery, we bump by 2 (to make sure that, on a
 *   fault, we have enough spare time left to redo our work)
 * Set LMS_FAKE to the number of levels we don't need (taking the above
 * into account)
 * As a future optimization, we could notice that we never need LMS_FAKE > 4;
 * in that case, we could always decrease LMS_H by 5.  This would shrink the
 * signature by 120 bytes.
 */
#define LMS_FAKE   (7 - (SPEED_SETTING != 0) - FAULT_STRATEGY)

#define LMS_ACTUAL (LMS_H - LMS_FAKE)
#define LMS_TOP    ((LMS_ACTUAL+1)/2)  /* Number of levels in the top subtree */
#define LMS_BOTTOM (LMS_ACTUAL/2) /* In the bottom subtrees */

#define LEN_LMS_PUBLIC_KEY (4 + 4 + 4 + 16 + 24)

/* This specific Sphincs+ parameter set (Sphincs+-192s-simple) that we support */
#define SPH_K    14   /* Number of FORS trees */
#define SPH_A    16   /* Height of each FORS tree */
#define SPH_H    64   /* Total hypertree height */
#define SPH_D     8   /* Number of tree layers */
#define SPH_T    (SPH_H / SPH_D) /* Height of each Merkle tree */
#define SPH_DLEN (SPH_D * 51) /* Total number of hashes in the WOTS sigs */
#define LEN_SPHINCS_SIG (24 * (1 + SPH_K*(SPH_A+1) + (SPH_H + SPH_DLEN) ))

struct sh_signer {
    bool initialized;
    bool got_fatal_error;
    struct hmac_drbg drbg;   /* For when we need more randomness */

    hash_t hash; 
    unsigned n;
    unsigned char sk_seed[MAX_HASH_LEN];
    unsigned char pk_seed[MAX_HASH_LEN];
    SHA256_FIRSTBLOCK pk_seed_pre;  /* Preprocessed version of pk_seed */
    unsigned char sk_prf[MAX_HASH_LEN];
    unsigned char root[MAX_HASH_LEN];

    /* This is where we are in the build process for the next LMS */
    /* tree/Sphincs signature */
    enum {
        b_init,    /* We start here */
        b_do_lms,  /* We're constructing the LMS tree */
        b_lms_finished, /* Intermediate step when we've built the */
                   /* entire LMS tree */
        b_fors,    /* We're building the FORS signature */
        b_complete_fors, /* We're finishing up the FORS signature */
        b_hypertree, /* We're building the hypertree signature */
        b_done,    /* Winner, winner, chicken dinner */
        b_count    /* Number of states total */
    } build_state;

    uint64_t idx_tree; /* The tree and leaf of the hypertree we are building */
    unsigned idx_leaf; /* Shared between between the b_fors, */
                       /* b_complete_fors, b_hypertree states */
    /*
     * Temp data used during the building process.  This union contains data
     * that we need to track during the processing of a state, but we no 
     * longer need once that state is completed
     */
    union {
        struct {
            int leaf;
            unsigned char stack[LMS_BOTTOM*24];
        } do_lms;  /* The b_do_lms step */
        struct {
            unsigned md[ SPH_K ];
            int tree;   /* Which FORS tree are we working on */
            int leaf;   /* Which leaf in the FORS tree are we working on */
            bool redundant_pass;  /* In redundant mode, are we redoing */
                                  /* the computation? */
            unsigned char stack[SPH_A*24];
            uint32_t fors_roots[SPH_K*(24/4)]; /* The computed root */
                                  /* values for all the FORS trees */
        } do_fors;  /* The b_fors step */
        struct {
            unsigned char prev_root[ MAX_HASH_LEN ]; /* The value that */
                                  /* this Merkle tree is signing (which */
                                  /* is either the FORS roots, or the */
                                  /* previous Merkle root value */
            unsigned char next_root[ MAX_HASH_LEN ]; /* The root value */
                                  /* for this Merkle tree */
#if FAULT_STRATEGY
            unsigned char redundant_root[ MAX_HASH_LEN ]; /* In redundant */
                                  /* mode, where we place the recomputed */
                                  /* Merkle tree root */
#endif
            int level;     /* The current tree level in the hypertree */
            int do_tree;   /* 0 -> currently working on the WOTS sig */
                           /* 1 -> currently working on the Merkle tree */
                           /* 2 -> currently recomputnig on the Merkle */
                           /*      tree (for fault tolerance) */
            unsigned save_sphincs_sig_index; /* In case we need to restart */
            struct build_merkle_state merk;
        } do_hyper;  /* The b_hypertree step */
    } temp;

/* This is the LMS section */
    merkle_index_t current_lms_index;  /* The number of LMS signatures we */
                                  /* have generated from the current tree */
        /* The seed (secret values to generate secret values) for this */
        /* LMS tree and the next */
    unsigned char current_lms_seed[32], next_lms_seed[32];
        /* The I values (public key identifier) for this LMS tree and */
        /* the next */
    unsigned char current_lms_I[16], next_lms_I[16];
        /* These are the subtrees for both the current LMS tree, and the */
        /* next one that we are building incrementally */
    unsigned char *current_lms_top_subtree;
    unsigned char *current_lms_bottom_subtree;
    unsigned char *next_lms_top_subtree;
    unsigned char *next_lms_bottom_subtree;
        /* The public keys for the current and next LMS trees */
    unsigned char current_lms_pub_key[ LEN_LMS_PUBLIC_KEY ];
    unsigned char next_lms_pub_key[ LEN_LMS_PUBLIC_KEY ];
    unsigned char next_lms_root[ 24 ];
#if LMS_FAKE
        /* The faked parts of the LMS trees */
    unsigned char current_fake[ LMS_FAKE * 24 ];
    unsigned char next_fake[ LMS_FAKE * 24 ];
#endif

/* This is the Sphincs+ section */
    unsigned char *current_sphincs_sig;
    unsigned char *next_sphincs_sig;
    unsigned sphincs_sig_index;  /* Where we are in the process of writing */
                                 /* the next_sphincs_sig */

/* These are storage areas for large components, where we need to */
/* switch between current and next; we'd prefer not to do a large copy */
/* and so we just swap pointers */
    unsigned char lms_top_1[ 24 * ((2 << LMS_TOP)-2) ];
    unsigned char lms_top_2[ 24 * ((2 << LMS_TOP)-2) ];
    unsigned char lms_bottom_1[ 24 * ((2 << LMS_BOTTOM)-2) ];
    unsigned char lms_bottom_2[ 24 * ((2 << LMS_BOTTOM)-2) ];
    unsigned char sph_sig_1[LEN_SPHINCS_SIG];
    unsigned char sph_sig_2[LEN_SPHINCS_SIG];
};

/* Advance the generation of the next LMS tree and Sphnics+ sig one step */
bool step_next( struct sh_signer *signer, bool do_dummy );

#endif /* SH_SIGNER_H_ */
