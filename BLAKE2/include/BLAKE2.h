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

    const size_t	BLOCK_SIZE = 128 ;	// Messages are processed per BLOCK_SIZE unit.

    class Digest ;

    typedef uint64_t	parameter_t [8] ;

    uint_fast8_t	GetByte (const parameter_t &P, size_t offset) ;
    parameter_t &	SetByte (parameter_t &P, size_t offset, uint8_t value) ;

    /**
     * Gets/Sets BLAKE2 parameters.
     */
    class ParameterView {
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
	friend class Generator ;
    private:
	uint64_t	h_ [8] ;
    public:
        Digest () {
            ::memset (h_, 0, sizeof (h_)) ;
        }
	Digest (uint64_t h0, uint64_t h1, uint64_t h2, uint64_t h3,
		uint64_t h4, uint64_t h5, uint64_t h6, uint64_t h7) {
	    h_ [0] = h0 ;
	    h_ [1] = h1 ;
	    h_ [2] = h2 ;
	    h_ [3] = h3 ;
	    h_ [4] = h4 ;
	    h_ [5] = h5 ;
	    h_ [6] = h6 ;
	    h_ [7] = h7 ;
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

    class Generator {
    private:
	enum {
	    BIT_FINALIZED = 0,
	    BIT_LAST_NODE = 1
	} ;
	static const size_t	BUFFER_SIZE = 2 * BLOCK_SIZE ;
    private:
	uint64_t	h_ [8] ;
	uint64_t	t0_ ;
	uint64_t	t1_ ;
	int32_t		used_ ;
	uint32_t	flags_ ;
	uint8_t *	buffer_ ;
	/*
	 * buffer_ --> +----------------+
	 *             |                |
	 *             :    128bytes    :
	 *             |                |
	 *             +----------------+
	 *             |                |
	 *             :    128bytes    :
	 *             |                |
	 *             +----------------+
         * Note: Due to last block compression scheme, we must hold the last message.
	 */
    public:
	~Generator () ;
	Generator (const parameter_t &param) ;
	Generator (const parameter_t &param, const void *key, size_t key_len) ;
	Generator &	Update (const void *data, size_t size) ;
	Digest	Finalize () ;
    private:
	bool	IsFinalized () const {
	    return (flags_ & (1u << BIT_FINALIZED)) != 0 ;
	}
	bool	IsLastNode () const {
	    return (flags_ & (1u << BIT_LAST_NODE)) != 0 ;
	}
    } ;
    void	InitializeChain (uint64_t *chain) ;
    void	InitializeChain (uint64_t *chain, const parameter_t &param) ;
    void	Compress (uint64_t *chain, const void *message, uint64_t t0, uint64_t t1, uint64_t f0, uint64_t f1) ;
}	/* end of [namespace BLAKE2] */

inline bool	operator == (const BLAKE2::Digest &a, const BLAKE2::Digest &b) {
    return BLAKE2::Digest::IsEqual (a, b) ;
}

#endif	/* blake2_h__4a9213114a5fd6c034b25abd47c90326 */
/*
 * [END OF FILE]
 */
