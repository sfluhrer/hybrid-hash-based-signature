#if !defined(ADR_H_)
#define ADR_H_
#include <stdint.h>

typedef unsigned char *adr_t;
#define LEN_ADR 22            /* The lenght of a compressed ADR structure */

#define ADR_CONST_FOR_TREE 9  /* The first 9 bytes of the ADR are constant */
                              /* for all ADRs for a specific Merkle tree */

/* The various type of hashes that Sphincs+ computes */
enum adr_type {
   WOTS_HASH_ADDRESS = 0,
   WOTS_KEY_COMPRESSION = 1,
   HASH_TREE_ADDRESS = 2,
   FORS_TREE_ADDRESS = 3,
   FORS_TREE_ROOT_COMPRESS = 4
};

void set_layer_address( adr_t adr, unsigned layer_address );
void set_tree_address( adr_t adr, uint_fast64_t tree_address );
void set_type( adr_t adr, enum adr_type type );
void set_key_pair_address( adr_t adr, unsigned key_pair_address );
void set_chain_address( adr_t adr, unsigned chain_address );
void set_hash_address( adr_t adr, unsigned hash_address );
void set_tree_height( adr_t adr, unsigned tree_height );
void set_tree_index( adr_t adr, uint_fast32_t tree_index );

#endif /* ADR_H_ */
