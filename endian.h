#if !defined( ENDIAN_H_ )
#define ENDIAN_H_

#include <stddef.h>
#include <stdint.h>

void put_bigendian( void *target, uint_fast64_t value, size_t bytes );
uint_fast64_t get_bigendian( const void *target, size_t bytes );

#endif /* ENDIAN_H_ */
