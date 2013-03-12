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

    parameter_t &	SetDefault (parameter_t &P) ;

    uint_fast8_t	GetUInt8 (const parameter_t &P, size_t offset) ;
    parameter_t &	SetUInt8 (parameter_t &P, size_t offset, uint8_t value) ;

    struct proxy8 {
	parameter_t &	p_ ;
	size_t		off_ ;
	proxy8 (parameter_t &p, size_t off) : p_ (p), off_ (off) {
	    /* NO-OP */
	}
	uint_fast8_t	GetValue () const {
	    return GetUInt8 (p_, off_) ;
	}
	void	SetValue (uint8_t value) {
	    SetUInt8 (p_, off_, value) ;
	}
	operator uint_fast8_t () const {
	    return GetValue () ;
	}
	void	operator = (uint8_t value) {
	    return SetValue (value) ;
	}
    } ;

    inline const proxy8	DigestLength (const parameter_t &p) {
	return proxy8 (const_cast<parameter_t &> (p), 0) ;
    }
    inline       proxy8	DigestLength (parameter_t &p) {
	return proxy8 (p, 0) ;
    }
    inline const proxy8	KeyLength (const parameter_t &p) {
	return proxy8 (const_cast<parameter_t &> (p), 1) ;
    }
    inline       proxy8	KeyLength (parameter_t &p) {
	return proxy8 (p, 1) ;
    }
    inline const proxy8	Fanout (const parameter_t &p) {
	return proxy8 (const_cast<parameter_t &> (p), 2) ;
    }
    inline       proxy8	Fanout (parameter_t &p) {
	return proxy8 (p, 2) ;
    }
    inline const proxy8	Depth (const parameter_t &p) {
	return proxy8 (const_cast<parameter_t &> (p), 3) ;
    }
    inline       proxy8	Depth (parameter_t &p) {
	return proxy8 (p, 3) ;
    }
    inline const proxy8	NodeDepth (const parameter_t &p) {
	return proxy8 (const_cast<parameter_t &> (p), 16) ;
    }
    inline       proxy8	NodeDepth (parameter_t &p) {
	return proxy8 (p, 16) ;
    }
    inline const proxy8	InnerLength (const parameter_t &p) {
	return proxy8 (const_cast<parameter_t &> (p), 17) ;
    }
    inline       proxy8	InnnerLength (parameter_t &p) {
	return proxy8 (p, 17) ;
    }

    inline uint_fast32_t	GetLeafLength (const parameter_t &p) {
	    return static_cast<uint_fast32_t> (p [0] >> 32) ;
    }
    inline void	SetLeafLength (parameter_t &p, uint32_t value) {
	uint_fast64_t	mask = 0xFFFFFFFFu ;
	p [0] = (p [0] & ~(mask << 32)) | (static_cast<uint_fast64_t> (value) << 32) ;
    }
    inline uint_fast64_t	GetNodeOffset (const parameter_t &p) {
	return p [1] ;
    }
    inline void	SetNodeOffset (parameter_t &p, uint64_t value) {
	p [1] = value ;
    }

    void	GetSalt (const parameter_t &p, void *buffer, size_t buffer_length) ;
    void	SetSalt (parameter_t &p, const void *data, size_t length) ;
    void	GetPersonalizationData (const parameter_t &p, void *buffer, size_t buffer_length) ;
    void	SetPersonalizationData (parameter_t &p, const void *buffer, size_t buffer_length) ;
    void	GetBytes (const parameter_t &p, void *buffer, size_t buffer_length) ;

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
