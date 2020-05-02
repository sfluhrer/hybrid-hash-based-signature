#include <stddef.h>

void lm_ots_generate_public_key(
    const unsigned char *I, /* Public key identifier */
    unsigned q,             /* Diversification string, 4 bytes value */
    const void *seed,
    unsigned char *public_key);
int lm_ots_generate_signature(
    const unsigned char *I,  /* Public key identifier */
    unsigned q,             /* Diversification string, 4 bytes value */
    const void *seed,
    const void *message,
    size_t message_len,
    unsigned char *signature);
      
