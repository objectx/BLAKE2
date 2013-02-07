/*
 * BLAKE2.h: The BLAKE2 Hash function.
 *
 * Author(s): objectx
 */
#ifndef	blake2_h__4a9213114a5fd6c034b25abd47c90326
#define	blake2_h__4a9213114a5fd6c034b25abd47c90326

#include <sys/types.h>
#include <stdint.h>

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
	Parameter &
	uint_fast32_t	GetLeafLength () const {
	}
    private:
	uint_fast8_t	GetByte (size_t offset) const {
	    size_t	off = offset >> 3 ;
	    size_t	rem = offset & 0x7u ;
	    return static_cast<uint_fast8_t> (p_ [off] >> (8 * rem)) ;
	}
	Parameter &	SetByte (size_t offset, uint8_t value) {
	    size_t	off = offset >> 3 ;
	    size_t	rem = offset & 0x7u ;
	    const uint_fast64_t	mask = 0xFFu ;
	    const size_t	shift = 8 * rem ;
	    p_ [off] = p_ [off] & ~(mask << shift) | (static_cast<uint_fast64_t> (value) << shift) ;
	    return *this ;
	}
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
