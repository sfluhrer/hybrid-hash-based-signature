#if !defined( SPHINCS_HASH_H_ )
#define SPHINCS_HASH_H_

/*
 * These are the Sphincs+ random functions
 */
#include "adr.h"
#include "hash.h"
#include <stdbool.h>
#include <string.h>
#include "sha256.h"

bool do_F( void *dest, hash_t hash, const SHA256_FIRSTBLOCK *pk_seed,
           adr_t adr, const void *m ); 
bool do_H( void *dest, hash_t hash, const SHA256_FIRSTBLOCK *pk_seed,
           adr_t adr, const void *m1, const void *m2 );
bool do_thash( unsigned char *dest, hash_t hash, 
           const SHA256_FIRSTBLOCK *pk_seed, adr_t adr,
           const uint32_t *in, size_t in_len );

void do_compute_digest_index( uint32_t *md, uint64_t *idx_tree, 
            unsigned *idx_leaf,
            int n, const unsigned char *r, const unsigned char *seed,
            const unsigned char *root, const void *message, size_t len_message,
            int k, int a, int h, int d);

#endif /* SPHINCS_HASH_H_ */
