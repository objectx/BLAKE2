/*
 * BLAKE2.h: The BLAKE2 Hash function.
 *
 * Author(s): objectx
 */
#ifndef	blake2_h__4a9213114a5fd6c034b25abd47c90326
#define	blake2_h__4a9213114a5fd6c034b25abd47c90326

#include <sys/types.h>
#include <stdint.h>
#include <stdlib.h>
#include <memory.h>

namespace BLAKE2 {

    class Parameter {
    private:
	uint64_t	p_ [8] ;
    public:
	Parameter () {
	    ::memset (p_, 0, sizeof (p_)) ;
	}
	uint_fast8_t	GetDigestLength () const {
	    return GetByte (0) ;
	}
	Parameter &	SetDigestLength (uint8_t value) {
	    return SetByte (0, value) ;
	}
	uint_fast8_t	GetKeyLength () const {
	    return GetByte (1) ;
	}
	Parameter &	SetKeyLength (uint8_t value) {
	    return SetByte (1, value) ;
	}
	uint_fast8_t	GetFanout () const {
	    return GetByte (2) ;
	}
	Parameter &	SetFanout (uint8_t value) {
	    return SetByte (2, value) ;
	}
	uint_fast8_t	GetDepth () const {
	    return GetByte (3) ;
	}
	Parameter &	SetDepth (uint8_t value) {
	    return SetByte (3, value) ;
	}
	uint_fast32_t	GetLeafLength () const {
	    return static_cast<uint_fast32_t> (p_ [0] >> 32) ;
	}
	Parameter &	SetLeafLength (uint32_t value) {
	    uint_fast64_t	mask = 0xFFFFFFFFu ;
	    p_ [0] = (p_ [0] & ~(mask << 32)) | (static_cast<uint_fast64_t> (value) << 32) ;
	    return *this ;
	}
	uint_fast8_t	GetNodeDepth () const {
	    return GetByte (16) ;
	}
	Parameter &	SetNodeDepth (uint8_t value) {
	    return SetByte (16, value) ;
	}
    private:
	uint_fast8_t	GetByte (size_t offset) const ;
	Parameter &	SetByte (size_t offset, uint8_t value) ;
    } ;

    class Digest {
    private:
	uint64_t	h_ [8] ;

    };
}	/* end of [namespace BLAKE2] */

#endif	/* blake2_h__4a9213114a5fd6c034b25abd47c90326 */
/*
 * [END OF FILE]
 */
