/*
 * internal.h:
 *
 * Author(s): objectx
 */
#ifndef	internal_h__e09208934f0997617028d4b01e8561a9
#define	internal_h__e09208934f0997617028d4b01e8561a9	1

#include <sys/types.h>
#include <stdint.h>

namespace BLAKE2 { namespace Internal {

    class State {
    private:
	uint64_t	h_ [8] ;
	uint64_t	t_ [2] ;
    public:

    };
}}	/* end of [namespace BLAKE2::Internal] */

#endif	/* internal_h__e09208934f0997617028d4b01e8561a9 */
/*
 * [END OF FILE]
 */
