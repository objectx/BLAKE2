/*
 * BLAKE2.cpp:
 *
 * Author(s): objectx
 */
#include <algorithm>
#include <BLAKE2.h>

static const size_t	SALT_LENGTH = 16 ;
static const size_t	PERSONALIZATION_INFO_LENGTH = 16 ;

namespace BLAKE2 {

    Parameter::Parameter () {
	::memset (p_, 0, sizeof (p_)) ;
	SetDigestLength (64).SetFanout (1).SetDepth (1) ;
    }
    void	Parameter::GetSalt (void *buffer, size_t buffer_length) {
	::memcpy (buffer, &p_ [4], std::min (SALT_LENGTH, buffer_length)) ;
    }
    Parameter &	Parameter::SetSalt (const void *data, size_t length) {
	::memset (&p_ [4], 0, SALT_LENGTH) ;
	::memcpy (&p_ [4], data, std::min (length, SALT_LENGTH)) ;
	return *this ;
    }
    void	Parameter::GetPersonalizationData (void *buffer, size_t buffer_length) {
	::memcpy (buffer, &p_ [6], std::min (PERSONALIZATION_INFO_LENGTH, buffer_length)) ;
    }
    Parameter &	Parameter::SetPersonalizationData (const void *data, size_t length) {
	::memset (&p_ [6], 0, PERSONALIZATION_INFO_LENGTH) ;
	::memcpy (&p_ [6], data, std::min (length, PERSONALIZATION_INFO_LENGTH)) ;
	return *this ;
    }
    void	Parameter::GetBytes (void *buffer, size_t buffer_length) const {
        auto	p = static_cast<uint8_t *> (buffer) ;
        for (int_fast32_t i = 0 ; i < buffer_length ; ++i) {
            p [i] = GetByte (i) ;
        }
    }
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

    Digest	Apply (const void *key, size_t key_length, const void *data, size_t data_length) {
        return Digest () ;
    }

}	/* end of [namespace BLAKE2] */
/*
 * [END OF FILE]
 */
