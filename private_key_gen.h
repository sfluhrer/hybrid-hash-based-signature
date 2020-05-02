#if !defined( PRIVATE_KEY_GEN_H_ )
#define PRIVATE_KEY_GEN_H_

#include "tune.h"

/*
 * This is the engine that produces XMSS and LMS private keys
 *
 * It is important that:
 * - We're able to reconstruct the secret key for any node at
 *   will (as we'll need it to rebuild parts of the tree)
 * - No one else will have a clue what the keys are, even if
 *   we reveal other keys (which we will in some of our
 *   signatures)
 *
 * Here is how it is used: it takes a secret (24 or 32 byte)
 * secret key, and a 16 or 32 byte identifier (which is assumed
 * to be public) and converts them into an 'n' byte (in practice
 * 24 byte) key.  The idea is that someone who doesn't know the
 * secret key cannot predict the values produced.
 *
 * For XMSS private keys, this identifier is the adr structure
 * associated with the node; the first 16 bytes are fixed for all
 * the nodes we'll be deriving from a single private_key_generator
 * structure; the second 16 bytes will all be different for each
 * derived key.  So, what we do is pass the first 16 bytes during
 * init_private_key_gen time; when we derive a specific key, we
 * pass the second 16 bytes to do_private_key_gen
 *
 * For LMS private keys, this identifier is a 16 byte encoding of
 * the node position; it is different for every private key.  So
 * we pass nothing during the init_private_key_gen time, and we
 * pass the entire 16 byte structure during do_private_key_gen
 *
 * See private_key_gen.c for details about what we actually do
 * with the identifier
 */

#if KEYGEN_STRATEGY
#include <openssl/aes.h>
#endif

struct private_key_generator {
#if KEYGEN_STRATEGY
    unsigned char init[16];
    AES_KEY expanded_key;
#else
    unsigned char hash[32];
#endif
};

void init_private_key_gen( struct private_key_generator *gen, 
             const void *secret_key, int len_secret_key,
             const void *extra, int len_extra );

void do_private_key_gen( void *dest, int n, 
             const struct private_key_generator *gen, const void *state );

#endif /* PRIVATE_KEY_GEN_H_ */
