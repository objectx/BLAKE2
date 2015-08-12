/*
 * main.cpp:
 *
 * Author(s): objectx
 */
#include "common.h"
#include "manips.h"
#include "TestVector.h"
#include <BLAKE2.h>

static std::ostream &   operator << (std::ostream &out, const BLAKE2::parameter_block_t &p) {
#define P_(OFF_)        put_hex (p [OFF_], 2)
    for (int_fast32_t i = 0 ; i < sizeof (p) ; i += 16) {
        if (0 < i) {
            out << ' ' ;
        }
        out << P_ (i +  0) << P_ (i +  1) << P_ (i +  2) << P_ (i +  3) << ' '
            << P_ (i +  4) << P_ (i +  5) << P_ (i +  6) << P_ (i +  7) << ' '
            << P_ (i +  8) << P_ (i +  9) << P_ (i + 10) << P_ (i + 11) << ' '
            << P_ (i + 12) << P_ (i + 13) << P_ (i + 14) << P_ (i + 15) ;
    }
#undef  P_
    return out ;
}

static std::string      dump_parameter (const BLAKE2::parameter_block_t &p) {
    std::ostringstream  out ;
    out << p << std::endl ;
    return out.str () ;
}

TEST_CASE ("Test Parameter", "[Parameter]") {
    SECTION ("Empty parameter") {
        BLAKE2::Parameter       P ;
        auto    result = dump_parameter (P.GetParameterBlock ()) ;
        auto    expected = std::string { "40000101 00000000 00000000 00000000 "
                                         "00000000 00000000 00000000 00000000 "
                                         "00000000 00000000 00000000 00000000 "
                                         "00000000 00000000 00000000 00000000\n" } ;
        // std::cerr << result ;
        REQUIRE (result.compare (expected) == 0) ;
    }
    SECTION ("Initialize parameter") {
        uint8_t salt [16] ;
        uint8_t personal [16] ;
        BLAKE2::Parameter       P ;
        P.SetKeyLength (256 / 8) ;

        memset (salt    , 0x55, sizeof (salt)) ;
        memset (personal, 0xee, sizeof (personal)) ;

        P.SetSalt (salt, sizeof (salt)) ;
        P.SetPersonalization (personal, sizeof (personal)) ;
        auto    result = dump_parameter (P) ;
        auto    expected = std::string { "40200101 00000000 00000000 00000000 "
                                         "00000000 00000000 00000000 00000000 "
                                         "55555555 55555555 55555555 55555555 "
                                         "eeeeeeee eeeeeeee eeeeeeee eeeeeeee\n" } ;
        REQUIRE (result.compare (expected) == 0) ;
    }
}

TEST_CASE ("Test Compression", "[Compress]") {
    SECTION ("Pass all 0 block") {
        uint64_t    h [8] ;
        uint8_t     buf [128] ;

        BLAKE2::InitializeChain (h) ;
        memset (buf, 0, sizeof (buf)) ;

        BLAKE2::Compress (h, buf, 0, 0, 0, 0) ;

        REQUIRE (h [0] == 0xf1328a1c44f7815eULL) ;
        REQUIRE (h [1] == 0xe74854a9ee8dec9cULL) ;
        REQUIRE (h [2] == 0x45680670cfd760afULL) ;
        REQUIRE (h [3] == 0x72b4b75c361f952eULL) ;
        REQUIRE (h [4] == 0xbf991808bb1a78d5ULL) ;
        REQUIRE (h [5] == 0x4c5e16e9e8953d52ULL) ;
        REQUIRE (h [6] == 0xdcd05c126f1b89f8ULL) ;
        REQUIRE (h [7] == 0x641fbc18b236fef4ULL) ;
    }

    SECTION ("Pass repeated sequence") {
        uint64_t    h [8] ;
        uint8_t     buf [128] ;

        memset (buf, 0, sizeof (buf)) ;
        for (int_fast32_t i = 0 ; i < sizeof (buf) ; ++i) {
            buf [i] = i & 0xFFu ;
        }

        BLAKE2::InitializeChain (h) ;
        BLAKE2::Compress (h, buf, 0, 0, 0, 0) ;
        REQUIRE (h [0] == 0x2a097e2ae10e82f0ULL) ;
        REQUIRE (h [1] == 0xab2851c5c554f980ULL) ;
        REQUIRE (h [2] == 0x8dbdc34bf0ce0684ULL) ;
        REQUIRE (h [3] == 0x13a21e79fc146b71ULL) ;
        REQUIRE (h [4] == 0xe7acaa395c23cd9fULL) ;
        REQUIRE (h [5] == 0x33d34266df5d3f1dULL) ;
        REQUIRE (h [6] == 0x7b79d5db78ca092dULL) ;
        REQUIRE (h [7] == 0xd60484e4b41d6ab6ULL) ;
    }
}

TEST_CASE ("Test BLAKE2", "[blake2]") {
    uint8_t     key [64] ;
    uint8_t     buf [256] ;

    for (size_t i = 0 ; i < sizeof (key) ; ++i) {
        key [i] = static_cast<uint8_t> (i & 0xFF) ;
    }
    for (size_t i = 0 ; i < sizeof (buf) ; ++i) {
        buf [i] = static_cast<uint8_t> (i & 0xFF) ;
    }
    BLAKE2::Parameter   param ;

    SECTION ("Parameter test using the test vector") {
        for (size_t i = 0 ; i < TestVector::NUM_BLAKE2_TEST ; ++i) {
            BLAKE2::Generator       gen { param, key, sizeof (key) } ;

            gen.Update (buf, i) ;
            BLAKE2::Digest  D { gen.Finalize () } ;

            for (size_t j = 0 ; j < 64 ; ++j) {
                REQUIRE (D [j] == TestVector::BLAKE2 [i][j]) ;
            }
            if (false) {
                std::cerr << "Digest: " << put_hex (D [0], 16) ;
                for (size_t k = 1 ; k < 8 ; ++k) {
                    std::cerr << ' ' << put_hex (D [k], 16) ;
                }
                std::cerr << std::endl ;
            }
            {
                BLAKE2::Digest      D2 { BLAKE2::Apply (param, key, sizeof (key), buf, i) } ;
                REQUIRE (BLAKE2::Digest::IsEqual (D, D2)) ;
            }
        }
    }
    SECTION ("Compare batch execution and incremental execution") {
        for (size_t i = 0 ; i < TestVector::NUM_BLAKE2_TEST ; ++i) {
            BLAKE2::Digest  expected { BLAKE2::Generator (param, key, sizeof (key)).Update (buf, i).Finalize () } ;
            BLAKE2::Digest  actual { BLAKE2::Apply (param, key, sizeof (key), buf, i) } ;

            REQUIRE (BLAKE2::Digest::IsEqual (actual, expected)) ;
        }
    }
    SECTION ("Use empty key") {
        for (size_t i = 0 ; i < TestVector::NUM_BLAKE2_TEST ; ++i) {
            BLAKE2::Digest  expected { BLAKE2::Generator (param).Update (buf, i).Finalize () } ;
            BLAKE2::Digest  actual { BLAKE2::Apply (0, 0, buf, i) } ;

            REQUIRE (BLAKE2::Digest::IsEqual (actual, expected)) ;
        }
    }
}

/*
 * [END OF FILE]
 */
