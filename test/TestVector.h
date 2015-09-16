/*
 * TestVector.h:
 *
 * Copyright (c) 2015 Masashi Fujita
 */
#ifndef	testvector_h__618b59b34535a8a541907188170282ec
#define	testvector_h__618b59b34535a8a541907188170282ec	1

#include <stdint.h>

namespace TestVector {
    const size_t	NUM_BLAKE2_TEST = 256 ;
    const size_t	DIGEST_SIZE = 64 ;
    extern const uint8_t	BLAKE2 [NUM_BLAKE2_TEST][DIGEST_SIZE] ;
}	/* end of [namespace TestVector] */

#endif	/* testvector_h__618b59b34535a8a541907188170282ec */
/*
 * [END OF FILE]
 */
