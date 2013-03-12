/*
 * main.cpp:
 *
 * Author(s): objectx
 */
#include "common.h"
#include "manips.h"
#include <BLAKE2.h>
#include "TestVector.h"

static std::ostream &	operator << (std::ostream &out, const BLAKE2::parameter_t &p) {
#define	P_(OFF_)	put_hex (BLAKE2::GetUInt8 (p, (OFF_)), 2)
    for (int_fast32_t i = 0 ; i < sizeof (p) ; i += 16) {
        if (0 < i) {
            out << ' ' ;
        }
	out << P_ (i +  0) << P_ (i +  1) << P_ (i +  2) << P_ (i +  3) << ' '
	    << P_ (i +  4) << P_ (i +  5) << P_ (i +  6) << P_ (i +  7) << ' '
	    << P_ (i +  8) << P_ (i +  9) << P_ (i + 10) << P_ (i + 11) << ' '
	    << P_ (i + 12) << P_ (i + 13) << P_ (i + 14) << P_ (i + 15) ;
    }
#undef	P_
    return out ;
}

static std::string	dump_parameter (const BLAKE2::parameter_t &p) {
    std::ostringstream	out ;
    out << p << std::endl ;
    return out.str () ;
}

static void	Test_Parameter () {
    {
	BLAKE2::parameter_t	P ;
	BLAKE2::SetDefault (P) ;
        auto	result (dump_parameter (P)) ;
        auto	expected = ("40000101 00000000 00000000 00000000 "
			    "00000000 00000000 00000000 00000000 "
			    "00000000 00000000 00000000 00000000 "
			    "00000000 00000000 00000000 00000000\n") ;
	std::cerr << result ;
        assert (result.compare (expected) == 0) ;
    }
    {
	uint8_t	salt [16] ;
	uint8_t	personal [16] ;
        BLAKE2::parameter_t P ;
        BLAKE2::SetDefault (P) ;
	BLAKE2::KeyLength (P) = 256 / 8 ;

	memset (salt    , 0x55, sizeof (salt)) ;
	memset (personal, 0xee, sizeof (personal)) ;

        BLAKE2::SetSalt (P, salt, sizeof (salt)) ;
        BLAKE2::SetPersonalizationData (P, personal, sizeof (personal)) ;
	auto	result (dump_parameter (P)) ;
	auto	expected = ("40200101 00000000 00000000 00000000 "
			    "00000000 00000000 00000000 00000000 "
			    "55555555 55555555 55555555 55555555 "
			    "eeeeeeee eeeeeeee eeeeeeee eeeeeeee\n") ;
	std::cerr << result ;
	assert (result.compare (expected) == 0) ;
    }
}

static void	TestCompress () {
    uint64_t	h [8] ;

    BLAKE2::InitializeChain (h) ;
    uint8_t	buf [128] ;
    memset (buf, 0, sizeof (buf)) ;
    BLAKE2::Compress (h, buf, 0, 0, 0, 0) ;

    assert (h [0] == 0xf1328a1c44f7815eULL) ;
    assert (h [1] == 0xe74854a9ee8dec9cULL) ;
    assert (h [2] == 0x45680670cfd760afULL) ;
    assert (h [3] == 0x72b4b75c361f952eULL) ;
    assert (h [4] == 0xbf991808bb1a78d5ULL) ;
    assert (h [5] == 0x4c5e16e9e8953d52ULL) ;
    assert (h [6] == 0xdcd05c126f1b89f8ULL) ;
    assert (h [7] == 0x641fbc18b236fef4ULL) ;
    std::cerr << put_hex (h [0], 16) ;
    for (int_fast32_t i = 1 ; i < 8 ; ++i) {
        std::cerr << ' ' << put_hex (h [i], 16) ;
    }
    std::cerr << std::endl ;

    memset (buf, 0, sizeof (buf)) ;
    for (int_fast32_t i = 0 ; i < sizeof (buf) ; ++i) {
        buf [i] = i & 0xFFu ;
    }

    BLAKE2::InitializeChain (h) ;
    BLAKE2::Compress (h, buf, 0, 0, 0, 0) ;
    assert (h [0] == 0x2a097e2ae10e82f0ULL) ;
    assert (h [1] == 0xab2851c5c554f980ULL) ;
    assert (h [2] == 0x8dbdc34bf0ce0684ULL) ;
    assert (h [3] == 0x13a21e79fc146b71ULL) ;
    assert (h [4] == 0xe7acaa395c23cd9fULL) ;
    assert (h [5] == 0x33d34266df5d3f1dULL) ;
    assert (h [6] == 0x7b79d5db78ca092dULL) ;
    assert (h [7] == 0xd60484e4b41d6ab6ULL) ;
    std::cerr << put_hex (h [0], 16) ;
    for (int_fast32_t i = 1 ; i < 8 ; ++i) {
        std::cerr << ' ' << put_hex (h [i], 16) ;
    }
    std::cerr << std::endl ;
}

void	TestBLAKE2 () {
    uint8_t	key [64] ;
    uint8_t	buf [256] ;

    for (size_t i = 0 ; i < sizeof (key) ; ++i) {
        key [i] = static_cast<uint8_t> (i & 0xFF) ;
    }
    for (size_t i = 0 ; i < sizeof (buf) ; ++i) {
        buf [i] = static_cast<uint8_t> (i & 0xFF) ;
    }
    BLAKE2::parameter_t	param ;
    BLAKE2::SetDefault (param) ;

    for (size_t i = 0 ; i < TestVector::NUM_BLAKE2_TEST ; ++i) {
        BLAKE2::Generator	gen (param, key, sizeof (key)) ;

        gen.Update (buf, i) ;
        BLAKE2::Digest	D (gen.Finalize ()) ;

        for (size_t j = 0 ; j < 64 ; ++j) {
            assert (D.GetByte (j) == TestVector::BLAKE2 [i][j]) ;
        }
    }
}

int	main (int argc, char **argv) {
    Test_Parameter () ;
    TestCompress () ;
    TestBLAKE2 () ;
    if (IsDebuggerPresent ()) {
        DebugBreak () ;
    }
    return 0 ;
}

/*
 * [END OF FILE]
 */
