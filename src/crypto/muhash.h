// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_MUHASH_H
#define BITCOIN_CRYPTO_MUHASH_H

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <stdint.h>

struct Num3072 {
#ifdef HAVE___INT128
    typedef unsigned __int128 double_limb_t;
    typedef uint64_t limb_t;
    static constexpr int LIMBS = 48;
    static constexpr int LIMB_SIZE = 64;
#else
    typedef uint64_t double_limb_t;
    typedef uint32_t limb_t;
    static constexpr int LIMBS = 96;
    static constexpr int LIMB_SIZE = 32;
#endif
    limb_t limbs[LIMBS];
};

/** 2^3072 - 1103717, the next largest 3072-bit safe prime number, is used as the order of the group. */
constexpr Num3072::limb_t MAX_PRIME_DIFF = 1103717;

/** A class representing MuHash sets
 *
 * MuHash is a hashing algorithm that supports adding set elements in any
 * order but also deleting in any order. As a result, it can maintain a
 * running sum for a set of data as a whole, and add/subtract when data
 * is added to or removed from it. A downside of MuHash is that computing
 * an inverse is relatively expensive. This can be solved by representing
 * the running value as a fraction, and multiplying added elements into
 * the numerator and removed elements into the denominator. Only when the
 * final hash is desired, a single modular inverse and multiplication is
 * needed to combine the two.
 *
 * TODO: Represent running value as a fraction to allow for more intuitive
 * use (see above).
 *
 * As the update operations are also associative, H(a)+H(b)+H(c)+H(d) can
 * in fact be computed as (H(a)+H(b)) + (H(c)+H(d)). This implies that
 * all of this is perfectly parallellizable: each thread can process an
 * arbitrary subset of the update operations, allowing them to be
 * efficiently combined later.
 *
 * Muhash does not support checking if an element is already part of the
 * set. That is why this class does not enforce the use of a set as the
 * data it represents because there is no efficient way to do so..
 * It is possible to add elements more than once and also to remove
 * elements that have not been added before. However, this implementation
 * is intended to represent a set of elements.
 *
 * See also https://cseweb.ucsd.edu/~mihir/papers/inchash.pdf and
 * https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2017-May/014337.html.
 */
class MuHash3072
{
protected:
    Num3072 data;

    static constexpr size_t INPUT_SIZE = 32;
    static constexpr size_t OUTPUT_SIZE = 384;

public:
    /* The empty set. */
    MuHash3072() noexcept;

    /* A singleton with a single 32-byte key in it. */
    explicit MuHash3072(Span<const unsigned char> key32) noexcept;

    /* Multiply (resulting in a hash for the union of the sets) */
    MuHash3072& operator*=(const MuHash3072& add) noexcept;

    /* Divide (resulting in a hash for the difference of the sets) */
    MuHash3072& operator/=(const MuHash3072& sub) noexcept;

    /* Finalize into a 384-byte hash. Does not change this object's value. */
    void Finalize(Span<unsigned char> hash384) noexcept;
};

#endif // BITCOIN_CRYPTO_MUHASH_H
