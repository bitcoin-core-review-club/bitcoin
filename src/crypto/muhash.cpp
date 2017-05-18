// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/muhash.h>

#include <crypto/chacha20.h>
#include <crypto/common.h>

#include <assert.h>
#include <stdio.h>

#include <limits>

namespace {

using limb_t = Num3072::limb_t;
using double_limb_t = Num3072::double_limb_t;
constexpr int LIMB_SIZE = Num3072::LIMB_SIZE;
constexpr int LIMBS = Num3072::LIMBS;

// Sanity check for Num3072 constants
static_assert(LIMB_SIZE * LIMBS == 3072, "Num3072 isn't 3072 bits");
static_assert(sizeof(double_limb_t) == sizeof(limb_t) * 2, "bad size for double_limb_t");
static_assert(sizeof(limb_t) * 8 == LIMB_SIZE, "LIMB_SIZE is incorrect");

// Hard coded values in MuHash3072 constructor and Finalize
static_assert(sizeof(limb_t) == 4 || sizeof(limb_t) == 8, "bad size for limb_t");

/** Extract the lowest limb of [c0,c1,c2] into n, and left shift the number by 1 limb. */
inline void extract3(limb_t& c0, limb_t& c1, limb_t& c2, limb_t& n)
{
    n = c0;
    c0 = c1;
    c1 = c2;
    c2 = 0;
}

/** Extract the lowest limb of [c0,c1] into n, and left shift the number by 1 limb. */
inline void extract2(limb_t& c0, limb_t& c1, limb_t& n)
{
    n = c0;
    c0 = c1;
    c1 = 0;
}

/** [c0,c1] = a * b */
inline void mul(limb_t& c0, limb_t& c1, const limb_t& a, const limb_t& b)
{
    double_limb_t t = (double_limb_t)a * b;
    c1 = t >> LIMB_SIZE;
    c0 = t;
}

/* [c0,c1,c2] += n * [d0,d1,d2]. c2 is 0 initially */
inline void mulnadd3(limb_t& c0, limb_t& c1, limb_t& c2, limb_t& d0, limb_t& d1, limb_t& d2, const limb_t& n)
{
    double_limb_t t = (double_limb_t)d0 * n + c0;
    c0 = t;
    t >>= LIMB_SIZE;
    t += (double_limb_t)d1 * n + c1;
    c1 = t;
    t >>= LIMB_SIZE;
    c2 = t + d2 * n;
}

/* [c0,c1] *= n */
inline void muln2(limb_t& c0, limb_t& c1, const limb_t& n)
{
    double_limb_t t = (double_limb_t)c0 * n;
    c0 = t;
    t >>= LIMB_SIZE;
    t += (double_limb_t)c1 * n;
    c1 = t;
    t >>= LIMB_SIZE;
}

/** [c0,c1,c2] += a * b */
inline void muladd3(limb_t& c0, limb_t& c1, limb_t& c2, const limb_t& a, const limb_t& b)
{
    limb_t tl, th;
    {
        double_limb_t t = (double_limb_t)a * b;
        th = t >> LIMB_SIZE;
        tl = t;
    }
    c0 += tl;
    th += (c0 < tl) ? 1 : 0;
    c1 += th;
    c2 += (c1 < th) ? 1 : 0;
}

/** [c0,c1,c2] += 2 * a * b */
inline void muldbladd3(limb_t& c0, limb_t& c1, limb_t& c2, const limb_t& a, const limb_t& b)
{
    limb_t tl, th;
    {
        double_limb_t t = (double_limb_t)a * b;
        th = t >> LIMB_SIZE;
        tl = t;
    }
    c0 += tl;
    limb_t tt = th + ((c0 < tl) ? 1 : 0);
    c1 += tt;
    c2 += (c1 < tt) ? 1 : 0;
    c0 += tl;
    th += (c0 < tl) ? 1 : 0;
    c1 += th;
    c2 += (c1 < th) ? 1 : 0;
}

/** [c0,c1] += a */
inline void add2(limb_t& c0, limb_t& c1, limb_t& a)
{
    c0 += a;
    c1 += (c0 < a) ? 1 : 0;
}

bool IsOverflow(const Num3072* d)
{
    if (d->limbs[0] <= std::numeric_limits<limb_t>::max() - MAX_PRIME_DIFF) return false;
    for (int i = 1; i < LIMBS; ++i) {
        if (d->limbs[i] != std::numeric_limits<limb_t>::max()) return false;
    }
    return true;
}

void FullReduce(Num3072* d)
{
    limb_t c0 = MAX_PRIME_DIFF;
    for (int i = 0; i < LIMBS; ++i) {
        limb_t c1 = 0;
        add2(c0, c1, d->limbs[i]);
        extract2(c0, c1, d->limbs[i]);
    }
}

void Multiply(Num3072* in_out, const Num3072* a)
{
    limb_t c0 = 0, c1 = 0;
    Num3072 tmp;

    /* Compute limbs 0..N-2 of in_out*a into tmp, including one reduction. */
    for (int j = 0; j < LIMBS - 1; ++j) {
        limb_t d0 = 0, d1 = 0, d2 = 0, c2 = 0;
        mul(d0, d1, in_out->limbs[1 + j], a->limbs[LIMBS + j - (1 + j)]);
        for (int i = 2 + j; i < LIMBS; ++i) muladd3(d0, d1, d2, in_out->limbs[i], a->limbs[LIMBS + j - i]);
        mulnadd3(c0, c1, c2, d0, d1, d2, MAX_PRIME_DIFF);
        for (int i = 0; i < j + 1; ++i) muladd3(c0, c1, c2, in_out->limbs[i], a->limbs[j - i]);
        extract3(c0, c1, c2, tmp.limbs[j]);
    }
    /* Compute limb N-1 of a*b into tmp. */
    {
        limb_t c2 = 0;
        for (int i = 0; i < LIMBS; ++i) muladd3(c0, c1, c2, in_out->limbs[i], a->limbs[LIMBS - 1 - i]);
        extract3(c0, c1, c2, tmp.limbs[LIMBS - 1]);
    }
    /* Perform a second reduction. */
    muln2(c0, c1, MAX_PRIME_DIFF);
    for (int j = 0; j < LIMBS; ++j) {
        add2(c0, c1, tmp.limbs[j]);
        extract2(c0, c1, in_out->limbs[j]);
    }
#ifdef DEBUG
    assert(c1 == 0);
    assert(c0 == 0 || c0 == 1);
#endif
    /* Perform a potential third reduction. */
    if (c0) FullReduce(in_out);
}

void Square(Num3072* in_out)
{
    limb_t c0 = 0, c1 = 0;
    Num3072 tmp;

    /* Compute limbs 0..N-2 of in_out*in_out into tmp, including one reduction. */
    for (int j = 0; j < LIMBS - 1; ++j) {
        limb_t d0 = 0, d1 = 0, d2 = 0, c2 = 0;
        for (int i = 0; i < (LIMBS - 1 - j) / 2; ++i) muldbladd3(d0, d1, d2, in_out->limbs[i + j + 1], in_out->limbs[LIMBS - 1 - i]);
        if ((j + 1) & 1) muladd3(d0, d1, d2, in_out->limbs[(LIMBS - 1 - j) / 2 + j + 1], in_out->limbs[LIMBS - 1 - (LIMBS - 1 - j) / 2]);
        mulnadd3(c0, c1, c2, d0, d1, d2, MAX_PRIME_DIFF);
        for (int i = 0; i < (j + 1) / 2; ++i) muldbladd3(c0, c1, c2, in_out->limbs[i], in_out->limbs[j - i]);
        if ((j + 1) & 1) muladd3(c0, c1, c2, in_out->limbs[(j + 1) / 2], in_out->limbs[j - (j + 1) / 2]);
        extract3(c0, c1, c2, tmp.limbs[j]);
    }
    {
        limb_t c2 = 0;
        for (int i = 0; i < LIMBS / 2; ++i) muldbladd3(c0, c1, c2, in_out->limbs[i], in_out->limbs[LIMBS - 1 - i]);
        extract3(c0, c1, c2, tmp.limbs[LIMBS - 1]);
    }
    /* Perform a second reduction. */
    muln2(c0, c1, MAX_PRIME_DIFF);
    for (int j = 0; j < LIMBS; ++j) {
        add2(c0, c1, tmp.limbs[j]);
        extract2(c0, c1, in_out->limbs[j]);
    }
#ifdef DEBUG
    assert(c1 == 0);
    assert(c0 == 0 || c0 == 1);
#endif
    /* Perform a potential third reduction. */
    if (c0) FullReduce(in_out);
}

void Inverse(Num3072* out, const Num3072* a)
{
    // For fast exponentiation a sliding window exponentiation with repunit
    // precomputation is utilized. See "Fast Point Decompression for Standard
    // Elliptic Curves" (Brumley, Järvinen, 2008).

    Num3072 p[12]; // p[i] = a^(2^(2^i)-1)
    Num3072 x;

    p[0] = *a;

    for (int i = 0; i < 11; ++i) {
        p[i + 1] = p[i];
        for (int j = 0; j < (1 << i); ++j) Square(&p[i + 1]);
        Multiply(&p[i + 1], &p[i]);
    }

    x = p[11];

    for (int j = 0; j < 512; ++j) Square(&x);
    Multiply(&x, &p[9]);
    for (int j = 0; j < 256; ++j) Square(&x);
    Multiply(&x, &p[8]);
    for (int j = 0; j < 128; ++j) Square(&x);
    Multiply(&x, &p[7]);
    for (int j = 0; j < 64; ++j) Square(&x);
    Multiply(&x, &p[6]);
    for (int j = 0; j < 32; ++j) Square(&x);
    Multiply(&x, &p[5]);
    for (int j = 0; j < 8; ++j) Square(&x);
    Multiply(&x, &p[3]);
    for (int j = 0; j < 2; ++j) Square(&x);
    Multiply(&x, &p[1]);
    for (int j = 0; j < 1; ++j) Square(&x);
    Multiply(&x, &p[0]);
    for (int j = 0; j < 5; ++j) Square(&x);
    Multiply(&x, &p[2]);
    for (int j = 0; j < 3; ++j) Square(&x);
    Multiply(&x, &p[0]);
    for (int j = 0; j < 2; ++j) Square(&x);
    Multiply(&x, &p[0]);
    for (int j = 0; j < 4; ++j) Square(&x);
    Multiply(&x, &p[0]);
    for (int j = 0; j < 4; ++j) Square(&x);
    Multiply(&x, &p[1]);
    for (int j = 0; j < 3; ++j) Square(&x);
    Multiply(&x, &p[0]);

    *out = x;
}

} // namespace

MuHash3072::MuHash3072() noexcept
{
    data.limbs[0] = 1;
    for (int i = 1; i < LIMBS; ++i) data.limbs[i] = 0;
}

MuHash3072::MuHash3072(Span<const unsigned char> key32) noexcept
{
    assert(key32.size() == INPUT_SIZE);
    unsigned char tmp[OUTPUT_SIZE];
    ChaCha20(key32.data(), key32.size()).Keystream(tmp, OUTPUT_SIZE);
    for (int i = 0; i < LIMBS; ++i) {
        if (sizeof(limb_t) == 4) {
            data.limbs[i] = ReadLE32(tmp + 4 * i);
        } else if (sizeof(limb_t) == 8) {
            data.limbs[i] = ReadLE64(tmp + 8 * i);
        }
    }
}

void MuHash3072::Finalize(Span<unsigned char> hash384) noexcept
{
    assert(hash384.size() == OUTPUT_SIZE);
    if (IsOverflow(&data)) FullReduce(&data);
    for (int i = 0; i < LIMBS; ++i) {
        if (sizeof(limb_t) == 4) {
            WriteLE32(hash384.data() + i * 4, data.limbs[i]);
        } else if (sizeof(limb_t) == 8) {
            WriteLE64(hash384.data() + i * 8, data.limbs[i]);
        }
    }
}

MuHash3072& MuHash3072::operator*=(const MuHash3072& x) noexcept
{
    Multiply(&this->data, &x.data);
    return *this;
}

MuHash3072& MuHash3072::operator/=(const MuHash3072& x) noexcept
{
    Num3072 tmp;
    Inverse(&tmp, &x.data);
    Multiply(&this->data, &tmp);
    return *this;
}
