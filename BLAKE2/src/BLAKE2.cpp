/*
 * BLAKE2.cpp:
 *
 * Author(s): objectx
 */
#include <algorithm>
#include <BLAKE2.h>

static const size_t	SALT_LENGTH = 16 ;
static const size_t	PERSONALIZATION_INFO_LENGTH = 16 ;

#define	ARRAY_SIZE(X_)	(sizeof (X_) / sizeof ((X_) [0]))

namespace BLAKE2 {

    uint_fast8_t	GetByte (const parameter_t &P, size_t offset) {
	size_t	off = offset >> 3 ;
	size_t	rem = offset & 0x7u ;
	assert (off < ARRAY_SIZE (P)) ;
	return static_cast<uint_fast8_t> (P [off] >> (8 * rem)) ;
    }

    parameter_t &	SetByte (parameter_t &P, size_t offset, uint8_t value) {
	size_t	off = offset >> 3 ;
	size_t	rem = offset & 0x7u ;
	assert (off < ARRAY_SIZE (P)) ;

	const uint_fast64_t	mask = 0xFFu ;
	const size_t	shift = 8 * rem ;
	P [off] = P [off] & ~(mask << shift) | (static_cast<uint_fast64_t> (value) << shift) ;
	return P ;
    }

    ParameterView::ParameterView (parameter_t &p) : p_ (&p) {
	::memset (*p_, 0, sizeof (*p_)) ;
	SetDigestLength (64).SetFanout (1).SetDepth (1) ;
    }
    void	ParameterView::GetSalt (void *buffer, size_t buffer_length) {
	parameter_t &	P = *p_ ;
	::memcpy (buffer, &P [4], std::min (SALT_LENGTH, buffer_length)) ;
    }
    ParameterView &	ParameterView::SetSalt (const void *data, size_t length) {
	parameter_t &	P = *p_ ;
	::memset (&P [4], 0, SALT_LENGTH) ;
	::memcpy (&P [4], data, std::min (length, SALT_LENGTH)) ;
	return *this ;
    }
    void	ParameterView::GetPersonalizationData (void *buffer, size_t buffer_length) {
	::memcpy (buffer, &(*p_) [6], std::min (PERSONALIZATION_INFO_LENGTH, buffer_length)) ;
    }
    ParameterView &	ParameterView::SetPersonalizationData (const void *data, size_t length) {
	parameter_t &	P = *p_ ;
	::memset (&P [6], 0, PERSONALIZATION_INFO_LENGTH) ;
	::memcpy (&P [6], data, std::min (length, PERSONALIZATION_INFO_LENGTH)) ;
	return *this ;
    }
    void	ParameterView::GetBytes (void *buffer, size_t buffer_length) const {
	parameter_t &	P = *p_ ;
	auto	p = static_cast<uint8_t *> (buffer) ;
        for (int_fast32_t i = 0 ; i < buffer_length ; ++i) {
            P [i] = GetByte (P, i) ;
        }
    }
    Digest	Apply (const void *key, size_t key_length, const void *data, size_t data_length) {
        return Digest () ;
    }

}	/* end of [namespace BLAKE2] */
/*
 * [END OF FILE]
 */
