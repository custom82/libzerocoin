// Modified from Bitcoin's bignum wrapper.
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include <stdexcept>
#include <vector>
#include <string>
#include <cstdint>
#include <openssl/bn.h>

#include "uint256.h"

typedef long long int64;
typedef unsigned long long uint64;

/** Errors thrown by the bignum class */
class bignum_error : public std::runtime_error
{
public:
    explicit bignum_error(const std::string& str) : std::runtime_error(str) {}
};


/** RAII encapsulated BN_CTX (OpenSSL bignum context) */
class CAutoBN_CTX
{
protected:
    BN_CTX* pctx;
    BN_CTX* operator=(BN_CTX* pnew) { return pctx = pnew; }

public:
    CAutoBN_CTX()
    {
        pctx = BN_CTX_new_ex(nullptr);  // Updated for OpenSSL 3.x
        if (pctx == NULL)
            throw bignum_error("CAutoBN_CTX : BN_CTX_new_ex() returned NULL");
    }

    ~CAutoBN_CTX()
    {
        if (pctx != NULL)
            BN_CTX_free(pctx);
    }

    operator BN_CTX*() { return pctx; }
    BN_CTX& operator*() { return *pctx; }
    BN_CTX** operator&() { return &pctx; }
    bool operator!() { return (pctx == NULL); }
};

/** C++ wrapper for BIGNUM (OpenSSL bignum) */
class CBigNum
{
    friend class CAutoBN_CTX;

private:
    BIGNUM* bn;

public:
    CBigNum() : bn(BN_new()) {
        if (!bn) {
            throw bignum_error("CBigNum: BN_new() failed");
        }
    }

    CBigNum(const CBigNum& b) : bn(BN_new()) {
        if (!bn) {
            throw bignum_error("CBigNum::CBigNum(const CBigNum&) : BN_new failed");
        }
        if (!BN_copy(bn, b.bn)) {
            BN_free(bn);
            throw bignum_error("CBigNum::CBigNum(const CBigNum&) : BN_copy failed");
        }
    }

    CBigNum(CBigNum&& b) noexcept : bn(b.bn) {
        b.bn = nullptr;
    }

    CBigNum& operator=(const CBigNum& b) {
        if (this != &b) {
            if (!BN_copy(bn, b.bn)) {
                throw bignum_error("CBigNum::operator= : BN_copy failed");
            }
        }
        return *this;
    }

    CBigNum& operator=(CBigNum&& b) noexcept {
        if (this != &b) {
            if (bn) {
                BN_clear_free(bn);
            }
            bn = b.bn;
            b.bn = nullptr;
        }
        return *this;
    }

    ~CBigNum() {
        if (bn) {
            BN_clear_free(bn);
        }
    }

    // Constructors for various types
    CBigNum(signed char n) : bn(BN_new()) { setint64(n); }
    CBigNum(short n) : bn(BN_new()) { setint64(n); }
    CBigNum(int n) : bn(BN_new()) { setint64(n); }
    CBigNum(long n) : bn(BN_new()) { setint64(n); }
    CBigNum(long long n) : bn(BN_new()) { setint64(n); }
    CBigNum(unsigned char n) : bn(BN_new()) { setuint64(n); }
    CBigNum(unsigned short n) : bn(BN_new()) { setuint64(n); }
    CBigNum(unsigned int n) : bn(BN_new()) { setuint64(n); }
    CBigNum(unsigned long n) : bn(BN_new()) { setuint64(n); }
    CBigNum(unsigned long long n) : bn(BN_new()) { setuint64(n); }
    explicit CBigNum(const uint256& n) : bn(BN_new()) { setuint256(n); }
    explicit CBigNum(const std::vector<unsigned char>& vch) : bn(BN_new()) { setvch(vch); }

    // Generate random number
    static CBigNum randBignum(const CBigNum& range) {
        CBigNum ret;
        if (!BN_rand_range_ex(ret.bn, 0, range.bn)) {
            throw bignum_error("CBigNum::randBignum : BN_rand_range_ex failed");
        }
        return ret;
    }

    // Generate random k-bit number
    static CBigNum randKBitBignum(uint32_t k) {
        CBigNum ret;
        if (!BN_rand_ex(ret.bn, k, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY, 0, nullptr)) {
            throw bignum_error("CBigNum::randKBitBignum : BN_rand_ex failed");
        }
        return ret;
    }

    // Set from hex string
    void SetHex(const std::string& str);

    // Set from vector
    void setvch(const std::vector<unsigned char>& vch);

    // Get as vector
    std::vector<unsigned char> getvch() const;

    // Set methods
    void setuint64(uint64 n);
    void setint64(int64 n);
    void setuint256(const uint256& n);

    // Convert to string
    std::string ToString(int nBase=10) const;

    // Get as uint256 (if fits)
    uint256 getuint256() const;

    // Get bit length
    uint32_t bitSize() const { return BN_num_bits(bn); }

    // Get byte length
    uint32_t byteSize() const { return (BN_num_bits(bn) + 7) / 8; }

    // Check if zero
    bool isZero() const { return BN_is_zero(bn); }

    // Check if negative
    bool isNegative() const { return BN_is_negative(bn); }

    // Get sign
    int getSign() const { return BN_is_negative(bn) ? -1 : BN_is_zero(bn) ? 0 : 1; }

    // Comparison operators
    bool operator==(const CBigNum& b) const { return BN_cmp(bn, b.bn) == 0; }
    bool operator!=(const CBigNum& b) const { return !(*this == b); }
    bool operator<=(const CBigNum& b) const { return BN_cmp(bn, b.bn) <= 0; }
    bool operator>=(const CBigNum& b) const { return BN_cmp(bn, b.bn) >= 0; }
    bool operator<(const CBigNum& b) const { return BN_cmp(bn, b.bn) < 0; }
    bool operator>(const CBigNum& b) const { return BN_cmp(bn, b.bn) > 0; }

    // Arithmetic operators
    CBigNum operator-() const;
    CBigNum& operator+=(const CBigNum& b);
    CBigNum& operator-=(const CBigNum& b);
    CBigNum& operator*=(const CBigNum& b);
    CBigNum& operator/=(const CBigNum& b);
    CBigNum& operator%=(const CBigNum& b);
    CBigNum& operator<<=(unsigned int shift);
    CBigNum& operator>>=(unsigned int shift);

    // Modular arithmetic
    CBigNum pow_mod(const CBigNum& e, const CBigNum& m) const;
    CBigNum mul_mod(const CBigNum& b, const CBigNum& m) const;
    CBigNum add_mod(const CBigNum& b, const CBigNum& m) const;
    CBigNum sub_mod(const CBigNum& b, const CBigNum& m) const;
    CBigNum inverse(const CBigNum& m) const;

    // Prime operations
    static CBigNum generatePrime(uint32_t bits, bool safe = false);
    bool isPrime(int checks = 20, BN_GENCB* cb = nullptr) const;

    // GCD and LCM
    CBigNum gcd(const CBigNum& b) const;

    // Square root modulo prime
    CBigNum sqrt_mod(const CBigNum& p) const;

    // Conversion operators
    operator BIGNUM*() { return bn; }
    operator const BIGNUM*() const { return bn; }

    BIGNUM* get() { return bn; }
    const BIGNUM* get() const { return bn; }

private:
    void init() {
        if (bn) BN_clear_free(bn);
        bn = BN_new();
        if (!bn) throw bignum_error("CBigNum: BN_new failed");
    }
};

// Arithmetic operators
inline CBigNum operator+(const CBigNum& a, const CBigNum& b) {
    CBigNum r;
    if (!BN_add(r.get(), a.get(), b.get()))
        throw bignum_error("CBigNum::operator+ : BN_add failed");
    return r;
}

inline CBigNum operator-(const CBigNum& a, const CBigNum& b) {
    CBigNum r;
    if (!BN_sub(r.get(), a.get(), b.get()))
        throw bignum_error("CBigNum::operator- : BN_sub failed");
    return r;
}

inline CBigNum operator*(const CBigNum& a, const CBigNum& b) {
    CAutoBN_CTX ctx;
    CBigNum r;
    if (!BN_mul(r.get(), a.get(), b.get(), ctx))
        throw bignum_error("CBigNum::operator* : BN_mul failed");
    return r;
}

inline CBigNum operator/(const CBigNum& a, const CBigNum& b) {
    CAutoBN_CTX ctx;
    CBigNum r;
    if (!BN_div(r.get(), nullptr, a.get(), b.get(), ctx))
        throw bignum_error("CBigNum::operator/ : BN_div failed");
    return r;
}

inline CBigNum operator%(const CBigNum& a, const CBigNum& b) {
    CAutoBN_CTX ctx;
    CBigNum r;
    if (!BN_mod(r.get(), a.get(), b.get(), ctx))
        throw bignum_error("CBigNum::operator% : BN_mod failed");
    return r;
}

inline CBigNum operator<<(const CBigNum& a, unsigned int shift) {
    CBigNum r;
    if (!BN_lshift(r.get(), a.get(), shift))
        throw bignum_error("CBigNum::operator<< : BN_lshift failed");
    return r;
}

inline CBigNum operator>>(const CBigNum& a, unsigned int shift) {
    CBigNum r;
    if (!BN_rshift(r.get(), a.get(), shift))
        throw bignum_error("CBigNum::operator>> : BN_rshift failed");
    return r;
}

// Comparison operators
inline bool operator==(const CBigNum& a, const CBigNum& b) {
    return BN_cmp(a.get(), b.get()) == 0;
}

inline bool operator!=(const CBigNum& a, const CBigNum& b) {
    return !(a == b);
}

inline bool operator<(const CBigNum& a, const CBigNum& b) {
    return BN_cmp(a.get(), b.get()) < 0;
}

inline bool operator>(const CBigNum& a, const CBigNum& b) {
    return b < a;
}

inline bool operator<=(const CBigNum& a, const CBigNum& b) {
    return !(a > b);
}

inline bool operator>=(const CBigNum& a, const CBigNum& b) {
    return !(a < b);
}

#endif // BITCOIN_BIGNUM_H
