/*
 * main.cpp:
 *
 * Author(s): objectx
 */
#include "common.h"
#include "manips.h"
#include <BLAKE2.h>

static std::ostream &	operator << (std::ostream &out, const BLAKE2::parameter_t &p) {
#define	P_(OFF_)	put_hex (BLAKE2::GetByte (p, (OFF_)), 2)
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
	BLAKE2::ParameterView	param (P);
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
	memset (salt    , 0x55, sizeof (salt)) ;
	memset (personal, 0xee, sizeof (personal)) ;
	BLAKE2::ParameterView	param (P) ;
	param.SetKeyLength (256 / 8)
	     .SetSalt (salt, sizeof (salt))
	     .SetPersonalizationData (personal, sizeof (personal)) ;
	auto	result (dump_parameter (P)) ;
	auto	expected = ("40200101 00000000 00000000 00000000 "
			    "00000000 00000000 00000000 00000000 "
			    "55555555 55555555 55555555 55555555 "
			    "eeeeeeee eeeeeeee eeeeeeee eeeeeeee\n") ;
	std::cerr << result ;
	assert (result.compare (expected) == 0) ;
    }
}

int	main (int argc, char **argv) {
    Test_Parameter () ;
    if (IsDebuggerPresent ()) {
        DebugBreak () ;
    }
    return 0 ;
}

/*
 * [END OF FILE]
 */
