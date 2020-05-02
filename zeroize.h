#if !defined( ZEROIZE_H_ )
#define ZEROIZE_H_

#include <stdlib.h>

/* Zeroize an area, that is, scrub it from holding any potentially secret */
/* information */
void zeroize( void *area, size_t len );

#endif /* ZEROIZE_H_ */
