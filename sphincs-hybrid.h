#if !defined( SPHINCS_HYBRID_ )
#define SPHINCS_HYBRID_

#include <stdbool.h>
#include <stddef.h>

/*
 * This generates a new public/private keypair
 *
 * Parameters:
 * hash_function - hash function to use: 
 *                 0 -> SHAKE256, 1 -> SHA256, 2 -> HARAKA
 * hash_size - length of the hash function to use (in bytes)
 *                 Must be one of: 128, 192, 256
 * time_space - where to do an F or an S parameter set of Sphincs+
 *                 0 -> use fast version (with large signatures)
 *                 1 -> use short version (with large signing times)
 * (Note: it is likely that we will fix hash_function and time_space
 *  to SHA256/slow in the future; those are what makes sense in the
 *  hybrid context)
 * do_rand - function to call when this needs randomness
 * sk_buffer - where to place the secret key
 * len_sk_buffer - length of the above buffer
 * size_sk - where to write the actual length of the secret key
 * pk_buffer - where to place the public key
 * len_pk_buffer - length of the above buffer
 * size_pk - where to write the actual length of the public key
 */
bool sh_keygen( int hash_function, int hash_size, int time_space,
                bool (*do_rand)( void *buffer, size_t len_buffer ),
                void *sk_buffer, size_t len_sk_buffer, size_t *size_sk, 
                void *pk_buffer, size_t len_pk_buffer, size_t *size_pk); 

/* Return the length of the public key, assuming the specified setting */
size_t sh_pubkey_len( int hash_function, int hash_size, int time_space );
/* Length of a public key, assuming a 192 bit hash function */
#define LEN_PUBKEY_192 (4 + 2*24)  /* 52 total */

/* Return the length of the private key, assuming the specified setting */
size_t sh_privkey_len( int hash_function, int hash_size, int time_space );
/* Length of a private key, assuming a 192 bit hash function */
#define LEN_PRIVKEY_192 (4 + 4*24)  /* 100 total */

/*
 * This loads a private key in memory, and gets it ready to sign
 * Warning: this takes a few seconds
 *
 * Parameters:
 * sk_buffer - the secret key
 * do_rand - function to call when this needs randomness
 */
struct sh_signer;
struct sh_signer *sh_load_signer( const void *sk_buffer,
                bool (*do_rand)( void *buffer, size_t len_buffer ) );

/*
 * Remove (and zeroize) the loaded key
 */
void sh_delete_signer(struct sh_signer *signer);

/*
 * Generate a signature from a loaded signature key
 */
bool sh_sign( void *signature, size_t len_signature_buf,
              struct sh_signer *signer,
              const void *message, size_t len_message );
size_t sh_sig_len( struct sh_signer *signer );

/* The length of a signature in 192 bit slow mode */
#define LEN_SIG_192_SLOW (17064 + 52 + 1744)  /* 18860 total */

/* The length of a signature in 192 bit fast mode */
#define LEN_SIG_192_FAST (17064 + 52 + 2944)  /* 20060 total */

/*
 * Verify a signature
 */
bool sh_verify( const void *message, size_t len_message,
                const void *signature, size_t len_signature,
                const void *public_key );

#endif /* SPHINCS_HYBRID_ */
