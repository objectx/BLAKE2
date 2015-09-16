/*
 * manips.h:
 *
 * Copyright (c) 2015 Masashi Fujita
 */

#ifndef	manips_h__7505e2954658cd40123cc4bf650bf20c
#define	manips_h__7505e2954658cd40123cc4bf650bf20c	1

#include <sys/types.h>
#include <stdint.h>
#include <iostream>

class put_hex {
private:
    const int32_t	w_ ;
    const uint64_t	v_ ;
public:
    put_hex (uint64_t v, size_t w) : w_ (static_cast<int32_t> (w)), v_ (v) { /* NO-OP */ }

    std::ostream &	write (std::ostream &out) const {
	auto mask = std::ios::basefield | std::ios::adjustfield ;
	auto flags = out.setf (std::ios::hex | std::ios::right, mask) ;
	char fill = out.fill ('0') ;
	out.width (w_) ;
	out << v_ ;
	out.setf (flags, mask) ;
	out.fill (fill) ;
	return out ;
    }
} ;

std::ostream &	operator << (std::ostream &out, const put_hex &manip) {
    return manip.write (out) ;
}

template <typename T_>
    class put_dec_ {
    private:
	const int32_t	w_ ;
	const T_	v_ ;
    public:
	put_dec_ (T_ v, size_t w) : w_ (static_cast<int32_t> (w)), v_ (v) {
	    /* NO-OP */
	}
	std::ostream &	write (std::ostream &out) {
            auto mask = std::ios::basefield | std::ios::adjustfield ;
            auto flags = out.setf (std::ios::dec | std::ios::right, mask) ;
            char fill = out.fill (' ') ;
            out.width (w_) ;
            out << v_ ;
            out.setf (flags, mask) ;
            out.fill (fill) ;
	    return out ;
	}
    } ;

template <typename T_>
    std::ostream &	operator << (std::ostream &out, const put_dec_<T_> &manip) {
        return manip.write (out) ;
    }

template <typename T_>
    put_dec_<T_>	put_dec (T_ v, size_t w) {
        return put_dec_<T_> (v, w) ;
    }

#endif	/* manips_h__7505e2954658cd40123cc4bf650bf20c */
/*
 * [END OF FILE]
 */
