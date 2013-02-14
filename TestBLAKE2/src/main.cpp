/*
 * main.cpp:
 *
 * Author(s): objectx
 */
#include "common.h"
#include "manips.h"
#include <BLAKE2.h>

static std::string	dump_parameter (const BLAKE2::Parameter &parameter) {
    std::ostringstream	out ;
    uint8_t	b [BLAKE2::Parameter::SIZE] ;
    parameter.GetBytes (b, sizeof (b)) ;

    for (int_fast32_t i = 0 ; i < sizeof (b) ; i += 16) {
	out << put_hex (b [i +  0], 2) << put_hex (b [i +  1], 2) << put_hex (b [i +  2], 2) << put_hex (b [i +  3], 2) << ' '
	    << put_hex (b [i +  4], 2) << put_hex (b [i +  5], 2) << put_hex (b [i +  6], 2) << put_hex (b [i +  7], 2) << ' '
	    << put_hex (b [i +  8], 2) << put_hex (b [i +  9], 2) << put_hex (b [i + 10], 2) << put_hex (b [i + 11], 2) << ' '
	    << put_hex (b [i + 12], 2) << put_hex (b [i + 13], 2) << put_hex (b [i + 14], 2) << put_hex (b [i + 15], 2) << std::endl ;
    }
    return out.str () ;
}

static void	Test_Parameter () {
    {
	BLAKE2::Parameter	param ;
        auto	result (dump_parameter (param)) ;
        auto	expected = ("40000101 00000000 00000000 00000000\n"
			    "00000000 00000000 00000000 00000000\n"
			    "00000000 00000000 00000000 00000000\n"
			    "00000000 00000000 00000000 00000000\n") ;
        assert (result.compare (expected) == 0) ;
	std::cerr << result ;
    }
    {
	uint8_t	salt [16] ;
	uint8_t	personal [16] ;
	memset (salt    , 0x55, sizeof (salt)) ;
	memset (personal, 0xee, sizeof (personal)) ;
	BLAKE2::Parameter	param ;
	param.SetKeyLength (256 / 8)
	     .SetSalt (salt, sizeof (salt))
	     .SetPersonalizationData (personal, sizeof (personal)) ;
	auto	result (dump_parameter (param)) ;
	auto	expected = ("40200101 00000000 00000000 00000000\n"
			    "00000000 00000000 00000000 00000000\n"
			    "55555555 55555555 55555555 55555555\n"
			    "eeeeeeee eeeeeeee eeeeeeee eeeeeeee\n") ;
	assert (result.compare (expected) == 0) ;
	std::cerr << result ;
    }
}

int	main (int argc, char **argv) {
    Test_Parameter () ;
    return 0 ;
}

/*
 * [END OF FILE]
 */
