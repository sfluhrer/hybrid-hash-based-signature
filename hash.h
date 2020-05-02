#if !defined( HASH_H_ )
#define HASH_H_

typedef unsigned hash_t;
#define HASH_LEN_128  0x00
#define HASH_LEN_192  0x01
#define HASH_LEN_256  0x02
#define HASH_LEN_MASK 0x03
#define HASH_TYPE_SHAKE256 0x00
#define HASH_TYPE_SHA256   0x04
#define HASH_TYPE_HARAKA   0x08
#define HASH_TYPE_SHIFT  2

int hash_len( hash_t hash );
#define MAX_HASH_LEN 32

#endif /* HASH_H_ */
