#if !defined(SHA256_H_)
#define SHA256_H_

#include "tune.h"
#include <stdint.h>

/* Length of a SHA256 hash */
#define SHA256_LEN		32

#if USE_OPENSSL

#include <openssl/sha.h>

#else

/* SHA256 context. */
typedef struct {
  uint_fast32_t h[8];            /* state; this is in the CPU native format */
  uint_fast32_t Nl, Nh;          /* number of bits processed so far */
  unsigned num;                  /* number of bytes within the below */
                                 /* buffer */
  unsigned char data[64];        /* input buffer.  This is in byte vector format */
} SHA256_CTX;

void SHA256_Init(SHA256_CTX *);  /* context */

void SHA256_Update(SHA256_CTX *, /* context */
                  const void *, /* input block */ 
                  unsigned int);/* length of input block */

void SHA256_Final(unsigned char *,
                 SHA256_CTX *);
#endif

/*
 * Also define the first block context
 * This is used if we generate a series of hashes all with the
 * same initial 64 byte block
 * Our first block just saves the initial SHA256_CTX after processing
 * the first block - by assuming the contents of the SHA256_CTX, we could do
 * with about a third of the memory copying
 */
typedef struct {
    SHA256_CTX ctx;
} SHA256_FIRSTBLOCK;

void SHA256_set_first_block( SHA256_FIRSTBLOCK *first,
                        const unsigned char *data, unsigned data_len );
void SHA256_init_first_block_ctx( SHA256_CTX *ctx,
                        const SHA256_FIRSTBLOCK *first );

#endif /* ifdef(SHA256_H_) */

