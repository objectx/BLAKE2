/*
 * BLAKE2.hpp: The BLAKE2 Hash function.
 *
 * Copyright (c) 2015-2016 Masashi Fujita
 */
#pragma once
#ifndef blake2_hpp__4a9213114a5fd6c034b25abd47c90326
#define blake2_hpp__4a9213114a5fd6c034b25abd47c90326    1

#include <cstddef>
#include <cstdint>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <array>
#include <memory>

namespace BLAKE2 {

    const size_t        BLOCK_SIZE = 128 ;      // Messages are processed per BLOCK_SIZE unit.

    class Digest ;

    using parameter_block_t = std::array<uint8_t, 64> ;

    const size_t OFF_DIGEST_LENGTH   =  0
               , OFF_KEY_LENGTH      =  1
               , OFF_FANOUT_COUNT    =  2
               , OFF_DEPTH           =  3
               , OFF_LEAF_LENGTH     =  4
               , OFF_NODE_OFFSET     =  8
               , OFF_NODE_DEPTH      = 16
               , OFF_INNER_LENGTH    = 17
               , OFF_SALT            = 32
               , OFF_PERSONALIZATION = 48 ;
    const size_t MAX_SALT_LENGTH = 16 ;
    const size_t MAX_PERSONALIZATION_LENGTH = 16 ;

    class Parameter {
    public:
        using self_t = Parameter ;
    private:
        parameter_block_t   p_ ;
    public:
        Parameter () ;

        Parameter (const Parameter &param) : Parameter { param.p_ } {
            /* NO-OP */
        }

        explicit Parameter (const parameter_block_t &param) ;

        uint_fast8_t    GetDigestLength () const {
            return p_ [OFF_DIGEST_LENGTH] ;
        }

        self_t &        SetDigestLength (uint8_t value) {
            p_ [OFF_DIGEST_LENGTH] = value ;
            return *this ;
        }

        uint_fast8_t    GetKeyLength () const {
            return p_ [OFF_KEY_LENGTH] ;
        }

        self_t &        SetKeyLength (uint8_t value) {
            p_ [OFF_KEY_LENGTH] = value ;
            return *this ;
        }

        uint_fast8_t    GetFanoutCount () const {
            return p_ [OFF_FANOUT_COUNT] ;
        }

        self_t &        SetFanoutCount (uint8_t value) {
            p_ [OFF_FANOUT_COUNT] = value ;
            return *this ;
        }

        uint_fast8_t    GetDepth () const {
            return p_ [OFF_DEPTH] ;
        }

        self_t &        SetDepth (uint8_t value) {
            p_ [OFF_DEPTH] = value ;
            return *this ;
        }

        uint_fast32_t   GetLeafLength () const {
            return ( (static_cast<uint32_t> (p_ [OFF_LEAF_LENGTH + 0]) <<  0)
                   | (static_cast<uint32_t> (p_ [OFF_LEAF_LENGTH + 1]) <<  8)
                   | (static_cast<uint32_t> (p_ [OFF_LEAF_LENGTH + 2]) << 16)
                   | (static_cast<uint32_t> (p_ [OFF_LEAF_LENGTH + 3]) << 24));
        }

        self_t &        SetLeafLength (uint32_t value) {
            p_ [OFF_LEAF_LENGTH + 0] = static_cast<uint8_t> (value >>  0) ;
            p_ [OFF_LEAF_LENGTH + 1] = static_cast<uint8_t> (value >>  8) ;
            p_ [OFF_LEAF_LENGTH + 2] = static_cast<uint8_t> (value >> 16) ;
            p_ [OFF_LEAF_LENGTH + 3] = static_cast<uint8_t> (value >> 24) ;
            return *this ;
        }

        uint_fast64_t GetNodeOffset () const {
            return ( (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 0]) <<  0)
                   | (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 1]) <<  8)
                   | (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 2]) << 16)
                   | (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 3]) << 24)
                   | (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 4]) << 32)
                   | (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 5]) << 40)
                   | (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 6]) << 48)
                   | (static_cast<uint64_t> (p_ [OFF_NODE_OFFSET + 7]) << 56));
        }

        self_t &        SetNodeOffset (uint64_t value) {
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

        uint_fast8_t    GetNodeDepth () const {
            return p_ [OFF_NODE_DEPTH] ;
        }

        self_t &        SetNodeDepth (uint8_t value) {
            p_ [OFF_NODE_DEPTH] = value ;
            return *this ;
        }

        const void *    GetSalt () const {
            return &p_ [OFF_SALT] ;
        }

        self_t &        SetSalt (const void *salt, size_t length) ;

        const void *    GetPersonalization () const {
            return &p_ [OFF_PERSONALIZATION] ;
        }

        self_t &        SetPersonalization (const void *data, size_t length) ;

        const parameter_block_t &       GetParameterBlock () const {
            return p_ ;
        }

        void    CopyTo (parameter_block_t &param) const ;

        operator const parameter_block_t & () const {
            return p_ ;
        }
    } ;

    /** Internal digest value (architecture agonistic).  */
    using hash_t = std::array<uint64_t, 8> ;

    /**
     * 512bits digest value (architecture agonostic).
     */
    class Digest {
    public:
        static constexpr size_t SIZE = sizeof (hash_t) ;     // # of bytes in digest.
    private:
        std::array<uint8_t, SIZE>   h_ ;
    public:
        Digest () {
            h_.fill (0) ;
        }

        Digest ( uint64_t h0, uint64_t h1, uint64_t h2, uint64_t h3
               , uint64_t h4, uint64_t h5, uint64_t h6, uint64_t h7) ;

        explicit Digest (const hash_t &h) : Digest { h [0], h [1], h [2], h [3]
                                                   , h [4], h [5], h [6], h [7] } {
            /* NO-OP */
        }

        Digest (const Digest &src) = default ;

        Digest &        Assign (const Digest &src) {
            h_ = src.h_ ;
            return *this ;
        }

        Digest &        operator = (const Digest &src) {
            return Assign (src) ;
        }

        void    CopyTo (void *buffer, size_t buffer_length) const ;

        const uint8_t * GetBytes () const {
            return h_.data () ;
        }

        const uint8_t * data () const {
            return h_.data () ;
        }

        constexpr size_t size () const {
            return h_.size () ;
        }

        uint_fast8_t    At (size_t offset) const {
            return h_ [offset] ;
        }

        uint_fast8_t    operator [] (size_t offset) const {
            return h_ [offset] ;
        }

        uint_fast64_t   GetUInt64 (size_t idx) const ;

        auto begin () const {
            return h_.begin () ;
        }

        auto end () const {
            return h_.end () ;
        }
    public:
        static constexpr size_t digestSize () {
            return SIZE ;
        }

        static bool     IsEqual (const Digest &a, const Digest &b) {
            return a.h_ == b.h_ ;
        }
    } ;

    class Generator {
    private:
        enum {
            BIT_FINALIZED = 0,
            BIT_LAST_NODE = 1
        } ;
        static const size_t     BUFFER_SIZE = 2 * BLOCK_SIZE ;
    private:
        hash_t      h_ ;
        uint64_t    t0_ ;
        uint64_t    t1_ ;
        int32_t     used_ ;
        uint32_t    flags_ ;
        std::unique_ptr<std::array<uint8_t, BUFFER_SIZE>>   buffer_ ;
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
        ~Generator () = default ;

        explicit Generator (const parameter_block_t &param) ;

        Generator (const parameter_block_t &param, const void *key, size_t key_len) ;

        Generator () = delete ;

        Generator (const Generator &) = delete ;

        Generator & operator = (const Generator &) = delete ;

        Generator & Update (const void *data, size_t size) ;

        Digest  Finalize () ;
    private:
        bool    IsFinalized () const {
            return (flags_ & (1u << BIT_FINALIZED)) != 0 ;
        }

        bool    IsLastNode () const {
            return (flags_ & (1u << BIT_LAST_NODE)) != 0 ;
        }
    } ;

    void    InitializeChain (hash_t &chain) ;
    void    InitializeChain (hash_t &chain, const parameter_block_t &param) ;

    void    Compress ( hash_t &     chain
                     , const void * message
                     , uint64_t     t0
                     , uint64_t     t1
                     , uint64_t     f0
                     , uint64_t     f1);

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
    Digest  Apply (const void *key, size_t key_length, const void *data, size_t data_length) ;

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
    Digest  Apply (const parameter_block_t &param, const void *key, size_t key_length, const void *data, size_t data_length) ;
}

inline bool operator == (const BLAKE2::Digest &a, const BLAKE2::Digest &b) {
    return BLAKE2::Digest::IsEqual (a, b) ;
}

inline bool operator != (const BLAKE2::Digest &a, const BLAKE2::Digest &b) {
    return (! BLAKE2::Digest::IsEqual (a, b)) ;
}

#endif  /* blake2_hpp__4a9213114a5fd6c034b25abd47c90326 */
