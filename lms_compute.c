#include <string.h>
#include "sha256.h"
#include "lms_compute.h"
#include "lms_common_defs.h"
#include "endian.h"

/*
 * Combine adjacent left and right nodes within the Merkle tree
 * together 
 */
void lms_combine_internal_nodes( unsigned char *dest,
        const unsigned char *left_node, const unsigned char *right_node,
        const unsigned char *I, unsigned hash_size,
        unsigned node_num) {
    unsigned char hash_val[ INTR_MAX_LEN ];
    memcpy( hash_val + INTR_I, I, I_LEN );
    put_bigendian( hash_val + INTR_R, node_num, 4 );
    SET_D( hash_val + INTR_D, D_INTR );

    memcpy( hash_val + INTR_PK,             left_node,  hash_size );
    memcpy( hash_val + INTR_PK + hash_size, right_node, hash_size );
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, hash_val, INTR_LEN(hash_size));
    SHA256_Final(hash_val, &ctx);
    memcpy( dest, hash_val, hash_size );
}
