#if !defined( HMAC_H_ )
#define HMAC_H_
 
#include "sha256.h"

struct hmac_engine {
    SHA256_CTX ctx;
};

void init_hmac( struct hmac_engine *engine, const void *key, int key_len );
void update_hmac( struct hmac_engine *engine, const void *data,
                  unsigned len_data);
void final_hmac( void *output, struct hmac_engine *engine,
                        const void *key, int key_len );

#endif /* HMAC_H_ */
