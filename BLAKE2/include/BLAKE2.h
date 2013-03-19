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
#include <string.h>

namespace BLAKE2 {

    const size_t	BLOCK_SIZE = 128 ;	// Messages are processed per BLOCK_SIZE unit.

    class Digest ;

    typedef uint8_t	parameter_block_t [64] ;

    class Parameter {
    public:
	typedef Parameter	self_t ;
	static const size_t	  OFF_DIGEST_LENGTH   =  0
				, OFF_KEY_LENGTH      =  1
				, OFF_FANOUT_COUNT    =  2
				, OFF_DEPTH           =  3
				, OFF_LEAF_LENGTH     =  4
				, OFF_NODE_OFFSET     =  8
				, OFF_NODE_DEPTH      = 16
				, OFF_INNER_LENGTH    = 17
				, OFF_SALT            = 32
				, OFF_PERSONALIZATION = 48 ;
	static const size_t	MAX_SALT_LENGTH = 16 ;
	static const size_t	MAX_PERSONALIZATION_LENGTH = 16 ;
    private:
	parameter_block_t	p_ ;
    public:
	Parameter () ;
	Parameter (const Parameter &param) ;
	Parameter (const parameter_block_t &param) ;

	uint_fast8_t	GetDigestLength () const {
	    return p_ [OFF_DIGEST_LENGTH] ;
	}
	self_t &	SetDigestLength (uint8_t value) {
	    p_ [OFF_DIGEST_LENGTH] = value ;
	    return *this ;
	}
	uint_fast8_t	GetKeyLength () const {
	    return p_ [OFF_KEY_LENGTH] ;
	}
	self_t &	SetKeyLength (uint8_t value) {
	    p_ [OFF_KEY_LENGTH] = value ;
	    return *this ;
	}
	uint_fast8_t	GetFanoutCount () const {
	    return p_ [OFF_FANOUT_COUNT] ;
	}
	self_t &	SetFanoutCount (uint8_t value) {
	    p_ [OFF_FANOUT_COUNT] = value ;
	    return *this ;
	}
	uint_fast8_t	GetDepth () const {
	    return p_ [OFF_DEPTH] ;
	}
	self_t &	SetDepth (uint8_t value) {
	    p_ [OFF_DEPTH] = value ;
	    return *this ;
	}
	uint_fast32_t	GetLeafLength () const {
	    return ((static_cast<uint32_t> (p_ [OFF_LEAF_LENGTH + 0]) <<  0) |
		    (static_cast<uint32_t> (p_ [OFF_LEAF_LENGTH + 1]) <<  8) |
		    (static_cast<uint32_t> (p_ [OFF_LEAF_LENGTH + 2]) << 16) |
		    (static_cast<uint32_t> (p_ [OFF_LEAF_LENGTH + 3]) << 24)) ;
	}
	self_t &	SetLeafLength (uint32_t value) {
	    p_ [OFF_LEAF_LENGTH + 0] = static_cast<uint8_t> (value >>  0) ;
	    p_ [OFF_LEAF_LENGTH + 1] = static_cast<uint8_t> (value >>  8) ;
	    p_ [OFF_LEAF_LENGTH + 2] = static_cast<uint8_t> (value >> 16) ;
	    p_ [OFF_LEAF_LENGTH + 3] = static_cast<uint8_t> (value >> 24) ;
	    return *this ;
	}
	uint_fast64_t	GetNodeOffset () const {
	    return ((static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 0]) <<  0) |
		    (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 1]) <<  8) |
		    (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 2]) << 16) |
		    (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 3]) << 24) |
		    (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 4]) << 32) |
		    (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 5]) << 40) |
		    (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 6]) << 48) |
		    (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 7]) << 56)) ;
	}
	self_t &	SetNodeOffset (uint64_t value) {
	    p_ [OFF_NODE_OFFSET + 0] = static_cast<uint8_t> (value >>  0) ;
	    p_ [OFF_NODE_OFFSET + 1] = static_cast<uint8_t> (value >>  8) ;
	    p_ [OFF_NODE_OFFSET + 2] = static_cast<uint8_t> (value >> 16) ;
	    p_ [OFF_NODE_OFFSET + 3] = static_cast<uint8_t> (value >> 24) ;
	    p_ [OFF_NODE_OFFSET + 4] = static_cast<uint8_t> (value >> 32) ;
	    p_ [OFF_NODE_OFFSET + 5] = static_cast<uint8_t> (value >> 40) ;
	    p_ [OFF_NODE_OFFSET + 6] = static_cast<uint8_t> (value >> 48) ;
	    p_ [OFF_NODE_OFFSET + 7] = static_cast<uint8_t> (value >> 56) ;
	    return *this ;
	}
	uint_fast8_t	GetNodeDepth () const {
	    return p_ [OFF_NODE_DEPTH] ;
	}
	self_t &	SetNodeDepth (uint8_t value) {
	    p_ [OFF_NODE_DEPTH] = value ;
	    return *this ;
	}
	const void *	GetSalt () const {
	    return &p_ [OFF_SALT] ;
	}
	self_t &	SetSalt (const void *salt, size_t length) ;
	const void *	GetPersonalization () const {
	    return &p_ [OFF_PERSONALIZATION] ;
	}
	self_t &	SetPersonalization (const void *data, size_t length) ;

	const parameter_block_t &	GetParameterBlock () const {
	    return p_ ;
	}
	void	CopyTo (parameter_block_t &param) const ;

	operator const parameter_block_t & () const {
	    return p_ ;
	}
    } ;
    /**
     * 512bits digest value.
     */
    class Digest {
	friend class Generator ;
    public:
	static const size_t	SIZE = 64 ;	// # of bytes in digest.
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
	uint_fast64_t	At (size_t idx) const {
	    return h_ [idx] ;
	}
	uint_fast64_t	operator [] (size_t idx) const {
	    return h_ [idx] ;
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
	Generator (const parameter_block_t &param) ;
	Generator (const parameter_block_t &param, const void *key, size_t key_len) ;
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
    void	InitializeChain (uint64_t *chain, const parameter_block_t &param) ;
    void	Compress (uint64_t *chain, const void *message, uint64_t t0, uint64_t t1, uint64_t f0, uint64_t f1) ;

    /**
     * Convenience function for generating a digest.
     *
     * @param key Key to apply
     * @param key_length Key length
     * @param data Data to compute digest
     * @param data_length Data length
     *
     * @return Computed digest
     */
    Digest	Apply (const void *key, size_t key_length, const void *data, size_t data_length) ;
    /**
     * Convenience function for generating a digest.
     *
     * @param param Generation parameters
     * @param key Key to apply
     * @param key_length Key length
     * @param data Data to compute digest
     * @param data_length Data length
     *
     * @return Computed digest.
     */
    Digest	Apply (const parameter_block_t &param, const void *key, size_t key_length, const void *data, size_t data_length) ;
}	/* end of [namespace BLAKE2] */

inline bool	operator == (const BLAKE2::Digest &a, const BLAKE2::Digest &b) {
    return BLAKE2::Digest::IsEqual (a, b) ;
}

#endif	/* blake2_h__4a9213114a5fd6c034b25abd47c90326 */
/*
 * [END OF FILE]
 */
