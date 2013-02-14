/*
 * BLAKE2.h: The BLAKE2 Hash function.
 *
 * Author(s): objectx
 */
#ifndef	blake2_h__4a9213114a5fd6c034b25abd47c90326
#define	blake2_h__4a9213114a5fd6c034b25abd47c90326

#include <sys/types.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <memory.h>

namespace BLAKE2 {
    class Digest ;

    class Parameter {
	friend Digest	Apply (const void *key, size_t key_length, const void *data, size_t data_length) ;
    public:
	static size_t const	SIZE = 8 * 8 ;
    private:
	uint64_t	p_ [8] ;
    public:
	Parameter () ;
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
	uint_fast64_t	GetNodeOffset () const {
	    return p_ [1] ;
	}
	Parameter &	SetNodeOffset (uint64_t offset) {
	    p_ [1] = offset ;
	    return *this ;
	}
	uint_fast8_t	GetNodeDepth () const {
	    return GetByte (16) ;
	}
	Parameter &	SetNodeDepth (uint8_t value) {
	    return SetByte (16, value) ;
	}
	uint_fast8_t	GetInnerLength () const {
	    return GetByte (17) ;
	}
	Parameter &	SetInnerLength (uint8_t value) {
	    return SetByte (17, value) ;
	}
	void	GetSalt (void *buffer, size_t buffer_length) ;
	Parameter &	SetSalt (const void *data, size_t length) ;
	void	GetPersonalizationData (void *buffer, size_t buffer_length) ;
	Parameter &	SetPersonalizationData (const void *data, size_t length) ;

	void	GetBytes (void *buffer, size_t buffer_length) const ;
    private:
	uint_fast8_t	GetByte (size_t offset) const ;
	Parameter &	SetByte (size_t offset, uint8_t value) ;
    } ;

    /**
     * 512bits digest value.
     */
    class Digest {
	friend Digest	Apply (const void *key, size_t key_length, const void *data, size_t data_length) ;
    public:
	static size_t const	SIZE = 8 * 8 ;
    private:
	uint64_t	h_ [8] ;
    public:
        Digest () {
            ::memset (h_, 0, sizeof (h_)) ;
        }
        Digest (const Digest &src) {
            ::memcpy (h_, src.h_, sizeof (h_)) ;
        }
        Digest &	Assign (const Digest &src) {
            ::memcpy (h_, src.h_, sizeof (h_)) ;
            return *this ;
        }
        Digest &	operator = (const Digest &src) {
            return Assign (src) ;
        }
	static bool	IsEqual (const Digest &a, const Digest &b) {
	    return ::memcmp (a.h_, b.h_, sizeof (a.h_)) == 0 ;
	}
	void	GetBytes (void *buffer, size_t buffer_length) ;

	uint_fast8_t	GetByte (size_t offset) {
	    size_t	off = offset / 8 ;
	    size_t	rem = offset % 8 ;
	    assert (off < 8) ;
	    uint_fast64_t	v = h_ [off] ;
	    return static_cast<uint8_t> (v >> (8 * rem)) ;
	}
    } ;

    Digest	Apply (const void *key, size_t key_length, const void *data, size_t data_size) ;
}	/* end of [namespace BLAKE2] */

inline bool	operator == (const BLAKE2::Digest &a, const BLAKE2::Digest &b) {
    return BLAKE2::Digest::IsEqual (a, b) ;
}

#endif	/* blake2_h__4a9213114a5fd6c034b25abd47c90326 */
/*
 * [END OF FILE]
 */
