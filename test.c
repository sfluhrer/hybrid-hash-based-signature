#include "sphincs-hybrid.h"
#include <stdio.h>
#include <stdbool.h>

static bool do_rand( void *buffer, size_t len_buffer ) {
    unsigned char *p = buffer;
    int i;
    for (i=0; i<len_buffer; i++) *p++ = i;
    return true;
}

int main(void) {
    unsigned char sk_buffer[1024]; size_t len_sk;
    unsigned char pk_buffer[1024]; size_t len_pk;
    bool flag =  sh_keygen( 1, 192, 1, do_rand,
                    sk_buffer, sizeof sk_buffer, &len_sk,
                    pk_buffer, sizeof pk_buffer, &len_pk);
    if (!flag) { printf( "It failed\n" ); return 0; }

#if 0
    int i;
    printf( "secret key:\n" );
    for (i = 0; i<len_sk; i++) {
        printf( "%02x%c", sk_buffer[i], (i%16) == 15 ? '\n' : ' ' );
    }
    printf( "\npublic key:\n" );
    for (i = 0; i<len_pk; i++) {
        printf( "%02x%c", pk_buffer[i], (i%16) == 15 ? '\n' : ' ' );
    }
    printf( "\n" );
#endif

    printf( "Loading signer\n" );
    struct sh_signer *sign = sh_load_signer( sk_buffer, do_rand );
    if (!sign) { printf( "Loading signer failed\n" ); return 0; }
    printf( "Loaded signer\n" );

    int count;
    const char *did_verify = "";
    for (count = 0; count < 1000000; count++) {
        unsigned char sig[LEN_SIG_192_FAST];
        int r = sh_sign( sig, sizeof sig, sign, "Hello", 5 );
        if (!r) { printf( "Signature %d failed\n", count ); return 0; }

#if 0
        r = sh_verify( "Hello", 5, sig, sizeof sig, pk_buffer );
        if (!r) { printf( "Verify %d failed\n", count ); return 0; }
        did_verify = "and verified ";
#endif
    }
    printf( "Generated %s%d signatures\n", did_verify, count );

    sh_delete_signer(sign);

    return 0;
}
