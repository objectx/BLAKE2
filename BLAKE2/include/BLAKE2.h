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

    const size_t	BLOCK_SIZE = 64 ;

    class Digest ;

    typedef uint64_t	parameter_t [8] ;

    uint_fast8_t	GetByte (const parameter_t &P, size_t offset) ;
    parameter_t &	SetByte (parameter_t &P, size_t offset, uint8_t value) ;

    class ParameterView {
	friend Digest	Apply (const void *key, size_t key_length, const void *data, size_t data_length) ;
    public:
	static size_t const	SIZE = 8 * 8 ;
    private:
	parameter_t *	p_ ;
    public:
	ParameterView (parameter_t &p) ;
	ParameterView &	Attach (parameter_t &p) {
	    p_ = &p ;
	}
	uint_fast8_t	GetDigestLength () const {
	    return GetByte (*p_, 0) ;
	}
	ParameterView &	SetDigestLength (uint8_t value) {
	    SetByte (*p_, 0, value) ;
	    return *this ;
	}
	uint_fast8_t	GetKeyLength () const {
	    return GetByte (*p_, 1) ;
	}
	ParameterView &	SetKeyLength (uint8_t value) {
	    SetByte (*p_, 1, value) ;
	    return *this ;
	}
	uint_fast8_t	GetFanout () const {
	    return GetByte (*p_, 2) ;
	}
	ParameterView &	SetFanout (uint8_t value) {
	    SetByte (*p_, 2, value) ;
	    return *this ;
	}
	uint_fast8_t	GetDepth () const {
	    return GetByte (*p_, 3) ;
	}
	ParameterView &	SetDepth (uint8_t value) {
	    SetByte (*p_, 3, value) ;
	    return *this ;
	}
	uint_fast32_t	GetLeafLength () const {
	    return static_cast<uint_fast32_t> ((*p_) [0] >> 32) ;
	}
	ParameterView &	SetLeafLength (uint32_t value) {
	    uint_fast64_t	mask = 0xFFFFFFFFu ;
	    parameter_t &	P = *p_ ;
	    P [0] = (P [0] & ~(mask << 32)) | (static_cast<uint_fast64_t> (value) << 32) ;
	    return *this ;
	}
	uint_fast64_t	GetNodeOffset () const {
	    return (*p_) [1] ;
	}
	ParameterView &	SetNodeOffset (uint64_t offset) {
	    (*p_) [1] = offset ;
	    return *this ;
	}
	uint_fast8_t	GetNodeDepth () const {
	    return GetByte (*p_, 16) ;
	}
	ParameterView &	SetNodeDepth (uint8_t value) {
	    SetByte (*p_, 16, value) ;
	    return *this ;
	}
	uint_fast8_t	GetInnerLength () const {
	    return GetByte (*p_, 17) ;
	}
	ParameterView &	SetInnerLength (uint8_t value) {
	    SetByte (*p_, 17, value) ;
	    return *this ;
	}
	void		GetSalt (void *buffer, size_t buffer_length) ;
	ParameterView &	SetSalt (const void *data, size_t length) ;
	void		GetPersonalizationData (void *buffer, size_t buffer_length) ;
	ParameterView &	SetPersonalizationData (const void *data, size_t length) ;

	void	GetBytes (void *buffer, size_t buffer_length) const ;
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

    class State {
    private:
	Digest		d_ ;
	uint64_t	t_ [2] ;
	uint64_t	f_ [2] ;
	uint8_t		buf_ [BLOCK_SIZE] ;
	bool		finalized_ ;
    public:
	State () ;
	State &	Update (const void *data, size_t length) ;
	Digest	Finalize () ;
	bool	IsFinalized () const ;
    } ;
}	/* end of [namespace BLAKE2] */

inline bool	operator == (const BLAKE2::Digest &a, const BLAKE2::Digest &b) {
    return BLAKE2::Digest::IsEqual (a, b) ;
}

#endif	/* blake2_h__4a9213114a5fd6c034b25abd47c90326 */
/*
 * [END OF FILE]
 */
