/*
 * BLAKE2.cpp:
 *
 * Author(s): objectx
 */
#include <BLAKE2.h>

namespace BLAKE2 {

    uint_fast8_t	Parameter::GetByte (size_t offset) const {
	size_t	off = offset >> 3 ;
	size_t	rem = offset & 0x7u ;
	return static_cast<uint_fast8_t> (p_ [off] >> (8 * rem)) ;
    }
    Parameter &	Parameter::SetByte (size_t offset, uint8_t value) {
	size_t	off = offset >> 3 ;
	size_t	rem = offset & 0x7u ;
	const uint_fast64_t	mask = 0xFFu ;
	const size_t	shift = 8 * rem ;
	p_ [off] = p_ [off] & ~(mask << shift) | (static_cast<uint_fast64_t> (value) << shift) ;
	return *this ;
    }
}	/* end of [namespace BLAKE2] */
/*
 * [END OF FILE]
 */
