#include "adr.h"
#include "endian.h"
#include <string.h>

/*
 * Here's the layout of the compressed ADRS structure
 * (The Sphincs+ specification doesn't give it explicitly)
 */
#define LAYER_ADDRESS   0   /* 1 byte */
#define TREE_ADDRESS    1   /* 8 bytes */
#define TYPE            9   /* 1 byte */
#define KEY_PAIR       10   /* 4 bytes */
#define CHAIN_ADDRESS  14   /* 4 bytes */
#define HASH_ADDRESS   18   /* 4 bytes */
#define TREE_HEIGHT    14   /* 4 bytes */
#define TREE_INDEX     18   /* 4 bytes */

/* This sets which layer of Merkle trees within the hypertree we are */
/* working on; 0 is the bottom most */
void set_layer_address( adr_t adr, unsigned layer_address ) {
    adr[LAYER_ADDRESS] = layer_address;
}

/* This sets which tree within a layer we are working on */
/* 0 is the leftmost */
void set_tree_address( adr_t adr, uint_fast64_t tree_address ) {
    put_bigendian( adr+TREE_ADDRESS, tree_address, 8 );
}

/* This sets the type of hash we're doing */
/* See enum adr_type for the various possible types */
/* This also implicitly clears out the remaining values (the ones other */
/* than layer address and tree address) */
void set_type( adr_t adr, enum adr_type type ) {
    adr[TYPE] = type;
    memset( &adr[TYPE+1], 0, LEN_ADR-(TYPE+1) );
}

/* This sets which WOTS leaf within the tree we're working on */
/* 0 is the leftmost */
/* This assumes that we've already called set_type */
void set_key_pair_address( adr_t adr, unsigned key_pair_address ) {
    adr[KEY_PAIR+3] = key_pair_address;
}

/* This sets which WOTS digit we're working on */
/* 0 is the leftmost */
/* This assumes that we've already called set_type */
void set_chain_address( adr_t adr, unsigned chain_address ) {
    adr[CHAIN_ADDRESS+3] = chain_address; /* We never have 256 digits in */
                                          /* a WOTS */
}

/* This sets where in the WOTS chain we're working on */
/* 0 is the lowest */
/* This assumes that we've already called set_type */
void set_hash_address( adr_t adr, unsigned hash_address ) {
    adr[HASH_ADDRESS+1] = adr[HASH_ADDRESS+2] = 0; /* We might have called */
                                                  /* set_tree_index earler */
    adr[HASH_ADDRESS+3] = hash_address; /* We never have W > 8 */
}

/* This sets the height of the Merkle node within the tree */
/* 0 is the leaf, 1 is the lowest binary node in the tree */
/* This assumes that we've already called set_type */
void set_tree_height( adr_t adr, unsigned tree_height ) {
    adr[TREE_HEIGHT+3] = tree_height; /* We never have more than 8 levels */
                                      /* within a tree */
}

/* This sets the index of the FORS node or the Merkle node within the tree */
/* For FORS, the higher order bits indicate the FORS tree # */
/* 0 is the leftmost */
/* This assumes that we've already called set_type */
void set_tree_index( adr_t adr, uint_fast32_t tree_index ) {
    adr[TREE_INDEX+1] = tree_index >> 16;
    adr[TREE_INDEX+2] = tree_index >> 8;
    adr[TREE_INDEX+3] = tree_index;
}
