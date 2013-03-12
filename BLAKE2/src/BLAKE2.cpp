/*
 * BLAKE2.cpp:
 *
 * Author(s): objectx
 */
#include <algorithm>
#include <BLAKE2.h>

static const size_t	SALT_LENGTH = 16 ;
static const size_t	PERSONALIZATION_INFO_LENGTH = 16 ;
static const size_t	MAX_KEY_LENGTH = 64 ;

static const uint8_t	sigma [12][16] = {
  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
  { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
  {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
  {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
  {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
  { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
  { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
  {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
  { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,

  {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,	// Same as sigma [0]
  { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
} ;

static const uint64_t	IV0 = 0x6a09e667f3bcc908ULL ;
static const uint64_t	IV1 = 0xbb67ae8584caa73bULL ;
static const uint64_t	IV2 = 0x3c6ef372fe94f82bULL ;
static const uint64_t	IV3 = 0xa54ff53a5f1d36f1ULL ;
static const uint64_t	IV4 = 0x510e527fade682d1ULL ;
static const uint64_t	IV5 = 0x9b05688c2b3e6c1fULL ;
static const uint64_t	IV6 = 0x1f83d9abfb41bd6bULL ;
static const uint64_t	IV7 = 0x5be0cd19137e2179ULL ;

#define	ARRAY_SIZE(X_)	(sizeof (X_) / sizeof ((X_) [0]))

namespace BLAKE2 {

    /**
     * Increments 128bits counter by V.
     */
    static inline void	inc_counter (uint64_t &t0, uint64_t &t1, size_t v) {
	t0 += v ;
	if (t0 < v) {
	    ++t1 ;
	}
    }

    uint_fast8_t	GetUInt8 (const parameter_t &P, size_t offset) {
	size_t	off = offset >> 3 ;
	size_t	rem = offset & 0x7u ;
	assert (off < ARRAY_SIZE (P)) ;
	return static_cast<uint_fast8_t> (P [off] >> (8 * rem)) ;
    }

    parameter_t &	SetUInt8 (parameter_t &P, size_t offset, uint8_t value) {
	size_t	off = offset >> 3 ;
	size_t	rem = offset & 0x7u ;
	assert (off < ARRAY_SIZE (P)) ;

	const uint_fast64_t	mask = 0xFFu ;
	const size_t	shift = 8 * rem ;
	P [off] = P [off] & ~(mask << shift) | (static_cast<uint_fast64_t> (value) << shift) ;
	return P ;
    }

    parameter_t &	SetDefault (parameter_t &P) {
	::memset (&P, 0, sizeof (parameter_t)) ;
	P [0] = ((64uLL <<  0) |	// Digest Length
		 ( 1uLL << 16) |	// Fanout
		 ( 1uLL << 24)) ;	// Depth
	return P ;
    }

    void	GetSalt (const parameter_t &p, void *buffer, size_t buffer_length) {
	::memcpy (buffer, &p [4], std::min (SALT_LENGTH, buffer_length)) ;
    }

    void	SetSalt (parameter_t &p, const void *data, size_t length) {
	::memset (&p [4], 0, SALT_LENGTH) ;
	::memcpy (&p [4], data, std::min (length, SALT_LENGTH)) ;
    }

    void	GetPersonalizationData (const parameter_t &p, void *buffer, size_t buffer_length) {
	::memcpy (buffer, &p [6], std::min (PERSONALIZATION_INFO_LENGTH, buffer_length)) ;
    }

    void	SetPersonalizationData (parameter_t &p, const void *data, size_t length) {
	::memset (&p [6], 0, PERSONALIZATION_INFO_LENGTH) ;
	::memcpy (&p [6], data, std::min (length, PERSONALIZATION_INFO_LENGTH)) ;
    }

    void	GetBytes (const parameter_t &p, void *buffer, size_t buffer_length) {
	uint8_t *	P = static_cast<uint8_t *> (buffer) ;
	for (size_t i = 0 ; i < buffer_length ; ++i) {
	    P [i] = GetUInt8 (p, i) ;
	}
    }

    void	InitializeChain (uint64_t *chain) {
	chain [0] = IV0 ;
	chain [1] = IV1 ;
	chain [2] = IV2 ;
	chain [3] = IV3 ;
	chain [4] = IV4 ;
	chain [5] = IV5 ;
	chain [6] = IV6 ;
	chain [7] = IV7 ;
    }

    void	InitializeChain (uint64_t *chain, const parameter_t &param) {
	chain [0] = IV0 ^ param [0] ;
	chain [1] = IV1 ^ param [1] ;
	chain [2] = IV2 ^ param [2] ;
	chain [3] = IV3 ^ param [3] ;
	chain [4] = IV4 ^ param [4] ;
	chain [5] = IV5 ^ param [5] ;
	chain [6] = IV6 ^ param [6] ;
	chain [7] = IV7 ^ param [7] ;
    }

    static inline uint64_t	load64 (const void *start) {
	const uint8_t *	p = static_cast<const uint8_t *> (start) ;
	return ((static_cast<uint64_t> (p [0]) <<  0) |
		(static_cast<uint64_t> (p [1]) <<  8) |
		(static_cast<uint64_t> (p [2]) << 16) |
		(static_cast<uint64_t> (p [3]) << 24) |
		(static_cast<uint64_t> (p [4]) << 32) |
		(static_cast<uint64_t> (p [5]) << 40) |
		(static_cast<uint64_t> (p [6]) << 48) |
		(static_cast<uint64_t> (p [7]) << 56)) ;
    }

    static inline uint_fast64_t	rotr (uint64_t value, int cnt) {
#if defined (_MSC_VER) && (1200 <= _MSC_VER)
	return _rotr64 (value, cnt) ;
#else
	return (value >> cnt) | (value << (64 - cnt)) ;
#endif
    }


    void	Compress (uint64_t *chain, const void *message, uint64_t t0, uint64_t t1, uint64_t f0, uint64_t f1) {
	const uint8_t *	msg = static_cast<const uint8_t *> (message) ;

	uint64_t	m [16] ;
	m [ 0] = load64 (msg + 8 *  0) ;
	m [ 1] = load64 (msg + 8 *  1) ;
	m [ 2] = load64 (msg + 8 *  2) ;
	m [ 3] = load64 (msg + 8 *  3) ;
	m [ 4] = load64 (msg + 8 *  4) ;
	m [ 5] = load64 (msg + 8 *  5) ;
	m [ 6] = load64 (msg + 8 *  6) ;
	m [ 7] = load64 (msg + 8 *  7) ;
	m [ 8] = load64 (msg + 8 *  8) ;
	m [ 9] = load64 (msg + 8 *  9) ;
	m [10] = load64 (msg + 8 * 10) ;
	m [11] = load64 (msg + 8 * 11) ;
	m [12] = load64 (msg + 8 * 12) ;
	m [13] = load64 (msg + 8 * 13) ;
	m [14] = load64 (msg + 8 * 14) ;
	m [15] = load64 (msg + 8 * 15) ;

	uint_fast64_t	v00 = chain [0] ;
	uint_fast64_t	v01 = chain [1] ;
	uint_fast64_t	v02 = chain [2] ;
	uint_fast64_t	v03 = chain [3] ;
	uint_fast64_t	v04 = chain [4] ;
	uint_fast64_t	v05 = chain [5] ;
	uint_fast64_t	v06 = chain [6] ;
	uint_fast64_t	v07 = chain [7] ;

	uint_fast64_t	v08 = IV0 ;
	uint_fast64_t	v09 = IV1 ;
	uint_fast64_t	v10 = IV2 ;
	uint_fast64_t	v11 = IV3 ;
	uint_fast64_t	v12 = IV4 ^ t0 ;
	uint_fast64_t	v13 = IV5 ^ t1 ;
	uint_fast64_t	v14 = IV6 ^ f0 ;
	uint_fast64_t	v15 = IV7 ^ f1 ;

#define	G(R_, I_, A_, B_, C_, D_)	do {			\
	uint_fast64_t	m0 = m [sigma [R_][2 * (I_) + 0]] ;	\
	uint_fast64_t	m1 = m [sigma [R_][2 * (I_) + 1]] ;	\
	(A_) = (A_) + (B_) + m0 ;				\
	(D_) = rotr ((D_) ^ (A_), 32) ;				\
	(C_) = (C_) + (D_) ;					\
	(B_) = rotr ((B_) ^ (C_), 24) ;				\
	(A_) = (A_) + (B_) + m1 ;				\
	(D_) = rotr ((D_) ^ (A_), 16) ;				\
	(C_) = (C_) + (D_) ;					\
	(B_) = rotr ((B_) ^ (C_), 63) ;				\
    } while (0)

#define	ROUND(R_)	do {			\
	G ((R_), 0, v00, v04, v08, v12) ;	\
	G ((R_), 1, v01, v05, v09, v13) ;	\
	G ((R_), 2, v02, v06, v10, v14) ;	\
	G ((R_), 3, v03, v07, v11, v15) ;	\
	G ((R_), 4, v00, v05, v10, v15) ;	\
	G ((R_), 5, v01, v06, v11, v12) ;	\
	G ((R_), 6, v02, v07, v08, v13) ;	\
	G ((R_), 7, v03, v04, v09, v14) ;	\
    } while (0)

	ROUND ( 0) ;
	ROUND ( 1) ;
	ROUND ( 2) ;
	ROUND ( 3) ;
	ROUND ( 4) ;
	ROUND ( 5) ;
	ROUND ( 6) ;
	ROUND ( 7) ;
	ROUND ( 8) ;
	ROUND ( 9) ;
	ROUND (10) ;
	ROUND (11) ;

	chain [0] ^= v00 ^ v08 ;
	chain [1] ^= v01 ^ v09 ;
	chain [2] ^= v02 ^ v10 ;
	chain [3] ^= v03 ^ v11 ;
	chain [4] ^= v04 ^ v12 ;
	chain [5] ^= v05 ^ v13 ;
	chain [6] ^= v06 ^ v14 ;
	chain [7] ^= v07 ^ v15 ;
    }

    Generator::~Generator () {
	free (buffer_) ;
    }

    Generator::Generator (const parameter_t &param)
        : t0_ (0)
        , t1_ (0)
        , used_ (0)
        , flags_ (0)
        , buffer_ (0) {
	buffer_ = static_cast<uint8_t *> (malloc (BUFFER_SIZE)) ;
	InitializeChain (h_, param) ;
    }

    Generator::Generator (const parameter_t &param, const void *key, size_t key_len)
	: t0_ (0)
        , t1_ (0)
        , used_ (0)
        , flags_ (0)
        , buffer_ (0) {
	buffer_ = static_cast<uint8_t *> (malloc (BUFFER_SIZE)) ;

	if (key == 0 || key_len == 0) {
	    InitializeChain (h_, param) ;
	}
	else {
	    uint8_t	k_len = static_cast<uint8_t> (std::min (key_len, MAX_KEY_LENGTH)) ;

	    parameter_t &	tmp_param = *(reinterpret_cast<parameter_t *> (buffer_)) ;
	    memcpy (tmp_param, param, sizeof (parameter_t)) ;


            KeyLength (tmp_param) = k_len ;

	    InitializeChain (h_, tmp_param) ;

	    memset (buffer_, 0, BLOCK_SIZE) ;
	    memcpy (buffer_, key, k_len) ;
	    used_ = BLOCK_SIZE ;
	}
    }

    Generator &	Generator::Update (const void *data, size_t size) {
	if (0 < size) {
	    const uint8_t *	src = static_cast<const uint8_t *> (data) ;

	    while (true) {
		size_t	remain = BUFFER_SIZE - used_ ;

		if (size <= remain) {
		    memcpy (buffer_ + used_, src, size) ;
		    used_ += static_cast<int32_t> (size) ;
		    break ;
		}
		// 0 < (size - remain)
		memcpy (buffer_ + used_, src, remain) ;
		inc_counter (t0_, t1_, BLOCK_SIZE) ;
		Compress (h_, buffer_, t0_, t1_, 0, 0) ;
		memcpy (buffer_, buffer_ + BLOCK_SIZE, BLOCK_SIZE) ;
		used_ = BLOCK_SIZE ;
		src += remain ;
		size -= remain ;
	    }
	}
	return *this ;
    }

    Digest	Generator::Finalize () {
	if (BLOCK_SIZE < used_) {
	    inc_counter (t0_, t1_, BLOCK_SIZE) ;
	    Compress (h_, buffer_, t0_, t1_, 0, 0) ;
	    used_ -= BLOCK_SIZE ;
	    memcpy (buffer_, buffer_ + BLOCK_SIZE, used_) ;
	}
	inc_counter (t0_, t1_, used_) ;
	memset (buffer_ + used_, 0, BUFFER_SIZE - used_) ;	// 0 padding.
	Compress (h_, buffer_, t0_, t1_, ~0uLL, 0) ;
	flags_ |= (1u << BIT_FINALIZED) ;
	return Digest (h_ [0], h_ [1], h_ [2], h_ [3], h_ [4], h_ [5], h_ [6], h_ [7]) ;
    }

    Digest	Apply (const void *key, size_t key_length, const void *data, size_t data_length) {
	parameter_t	param ;
	uint64_t	H [8] ;
	uint_fast64_t	t0 = 0 ;
	uint_fast64_t	t1 = 0 ;
	uint8_t		buffer [BLOCK_SIZE] ;
	size_t		cnt_blocks = (data_length + BLOCK_SIZE - 1) / BLOCK_SIZE ;
	size_t		sz = 0 ;
	const uint8_t *	src = static_cast<const uint8_t *> (data) ;

	SetDefault (param) ;
#if	0
	if (key == 0 || key_length == 0) {
	    InitializeChain (H, param) ;
	    if (cnt_blocks == 0) {
		// TODO: Check this case.
		Compress (H, buffer, ~0uLL, 0) ;
		return Digest (H [0], H [1], H [2], H [3], H [4], H [5], H [6], H [7]) ;
	    }
	}
	else {
	    uint8_t	k_len = static_cast<uint8_t> (std::min (key_len, MAX_KEY_LENGTH)) ;

	    KeyLength (param) = k_len ;
	    InitializeChain (H, param) ;
	    memset (buffer, 0, BLOCK_SIZE) ;
	    memcpy (buffer, key, k_len) ;
	    inc_counter (t0, t1, BLOCK_SIZE) ;
	    if (cnt_blocks == 0) {
		// Only key was supplied.
		Compress (H, buffer, ~0uLL, 0) ;
		return Digest (H [0], H [1], H [2], H [3], H [4], H [5], H [6], H [7]) ;
	    }
	    Compress (H, buffer, 0, 0) ;
	}
	for (size_t i = 0 ; i < (cnt_blocks - 1) ; ++i) {

	}
#endif
	return Digest () ;
    }

}	/* end of [namespace BLAKE2] */
/*
 * [END OF FILE]
 */
