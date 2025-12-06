// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#if defined HAVE_CONFIG_H
#include "bitcoin-config.h"
#endif

#include <stdexcept>
#include <vector>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "serialize.h"
#include "uint256.h"
#include "version.h"

#include <boost/thread.hpp>

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
        pctx = BN_CTX_new();
        if (pctx == NULL)
            throw bignum_error("CAutoBN_CTX : BN_CTX_new() returned NULL");
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
};/** C++ wrapper for BIGNUM (OpenSSL bignum) */
class CBigNum
{
private:
    BIGNUM *bn;

    // Helper function for converting to BIGNUM*
    BIGNUM* get() { return bn; }
    const BIGNUM* get() const { return bn; }

public:
    // Constructors
    CBigNum()
    {
        bn = BN_new();
        if (bn == NULL)
            throw bignum_error("CBigNum::CBigNum() : BN_new failed");
    }

    CBigNum(const CBigNum& b)
    {
        bn = BN_new();
        if (bn == NULL)
            throw bignum_error("CBigNum::CBigNum(const CBigNum&) : BN_new failed");
        if (!BN_copy(bn, b.bn))
        {
            BN_free(bn);
            throw bignum_error("CBigNum::CBigNum(const CBigNum&) : BN_copy failed");
        }
    }

    CBigNum& operator=(const CBigNum& b)
    {
        if (!BN_copy(bn, b.bn))
            throw bignum_error("CBigNum::operator= : BN_copy failed");
        return *this;
    }

    ~CBigNum()
    {
        if (bn != NULL)
            BN_free(bn);
    }

    // Constructors from primitive types
    CBigNum(signed char n)      { bn = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(short n)            { bn = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(int n)              { bn = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(long n)             { bn = BN_new(); if (n >= 0) setulong(n); else setint64(n); }
    CBigNum(int64 n)            { bn = BN_new(); setint64(n); }
    CBigNum(unsigned char n)    { bn = BN_new(); setulong(n); }
    CBigNum(unsigned short n)   { bn = BN_new(); setulong(n); }
    CBigNum(unsigned int n)     { bn = BN_new(); setulong(n); }
    CBigNum(unsigned long n)    { bn = BN_new(); setulong(n); }
    CBigNum(uint64 n)           { bn = BN_new(); setuint64(n); }
    explicit CBigNum(uint256 n) { bn = BN_new(); setuint256(n); }

    explicit CBigNum(const std::vector<unsigned char>& vch)
    {
        bn = BN_new();
        setvch(vch);
    }    // Conversion operators for OpenSSL compatibility
    operator BIGNUM*() { return bn; }
    operator const BIGNUM*() const { return bn; }

    // Helper function to get pointer for OpenSSL functions
    BIGNUM** operator&() { return &bn; }
    const BIGNUM* operator&() const { return bn; }

    // Random number generation
    static CBigNum randBignum(const CBigNum& range) {
        CBigNum ret;
        if(!BN_rand_range(ret.get(), range.get())){
            throw bignum_error("CBigNum:rand element : BN_rand_range failed");
        }
        return ret;
    }

    static CBigNum RandKBitBigum(uint32_t k){
        CBigNum ret;
        if(!BN_rand(ret.get(), k, -1, 0)){
            throw bignum_error("CBigNum:rand element : BN_rand failed");
        }
        return ret;
    }

    // Bit operations
    int bitSize() const
    {
        return BN_num_bits(get());
    }

    void setulong(unsigned long n)
    {
        if (!BN_set_word(get(), n))
            throw bignum_error("CBigNum conversion from unsigned long : BN_set_word failed");
    }

    unsigned long getulong() const
    {
        return BN_get_word(get());
    }

    unsigned int getuint() const
    {
        return BN_get_word(get());
    }

    int getint() const
    {
        unsigned long n = BN_get_word(get());
        if (!BN_is_negative(get()))
            return (n > (unsigned long)std::numeric_limits<int>::max() ? std::numeric_limits<int>::max() : n);
        else
            return (n > (unsigned long)std::numeric_limits<int>::max() ? std::numeric_limits<int>::min() : -(int)n);
    }    void setint64(int64 n)
    {
        unsigned char pch[sizeof(n) + 6];
        unsigned char* p = pch + 4;
        bool fNegative = false;
        if (n < (int64)0)
        {
            n = -n;
            fNegative = true;
        }
        bool fLeadingZeroes = true;
        for (int i = 0; i < 8; i++)
        {
            unsigned char c = (n >> 56) & 0xff;
            n <<= 8;
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = (fNegative ? 0x80 : 0);
                else if (fNegative)
                    c |= 0x80;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        unsigned int nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, p - pch, get());
    }

    void setuint64(uint64 n)
    {
        unsigned char pch[sizeof(n) + 6];
        unsigned char* p = pch + 4;
        bool fLeadingZeroes = true;
        for (int i = 0; i < 8; i++)
        {
            unsigned char c = (n >> 56) & 0xff;
            n <<= 8;
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = 0;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        unsigned int nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, p - pch, get());
    }    void setuint256(uint256 n)
    {
        unsigned char pch[sizeof(n) + 6];
        unsigned char* p = pch + 4;
        bool fLeadingZeroes = true;
        unsigned char* pbegin = (unsigned char*)&n;
        unsigned char* psrc = pbegin + sizeof(n);
        while (psrc != pbegin)
        {
            unsigned char c = *(--psrc);
            if (fLeadingZeroes)
            {
                if (c == 0)
                    continue;
                if (c & 0x80)
                    *p++ = 0;
                fLeadingZeroes = false;
            }
            *p++ = c;
        }
        unsigned int nSize = p - (pch + 4);
        pch[0] = (nSize >> 24) & 0xff;
        pch[1] = (nSize >> 16) & 0xff;
        pch[2] = (nSize >> 8) & 0xff;
        pch[3] = (nSize) & 0xff;
        BN_mpi2bn(pch, p - pch, get());
    }

    uint256 getuint256() const
    {
        unsigned int nSize = BN_bn2mpi(get(), NULL);
        if (nSize < 4)
            return 0;
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(get(), &vch[0]);
        if (vch.size() > 4)
            vch[4] &= 0x7f;
        uint256 n = 0;
        for (unsigned int i = 0, j = vch.size()-1; i < sizeof(n) && j >= 4; i++, j--)
            ((unsigned char*)&n)[i] = vch[j];
        return n;
    }

    void setvch(const std::vector<unsigned char>& vch)
    {
        std::vector<unsigned char> vch2(vch.size() + 4);
        unsigned int nSize = vch.size();
        // BIGNUM's byte format is big endian
        vch2[0] = (nSize >> 24) & 0xff;
        vch2[1] = (nSize >> 16) & 0xff;
        vch2[2] = (nSize >> 8) & 0xff;
        vch2[3] = (nSize >> 0) & 0xff;
        // swap data to big endian
        reverse_copy(vch.begin(), vch.end(), vch2.begin() + 4);
        BN_mpi2bn(&vch2[0], vch2.size(), get());
    }

    std::vector<unsigned char> getvch() const
    {
        unsigned int nSize = BN_bn2mpi(get(), NULL);
        if (nSize <= 4)
            return std::vector<unsigned char>();
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(get(), &vch[0]);
        vch.erase(vch.begin(), vch.begin() + 4);
        reverse(vch.begin(), vch.end());
        return vch;
    }    std::string ToString(int nBase=10) const
    {
        CAutoBN_CTX pctx;
        CBigNum bnBase = nBase;
        CBigNum bn0 = 0;
        std::string str;
        CBigNum bn = *this;
        BN_set_negative(bn.get(), false);
        CBigNum dv;
        CBigNum rem;
        if (BN_cmp(bn.get(), bn0.get()) == 0)
            return "0";
        while (BN_cmp(bn.get(), bn0.get()) > 0)
        {
            if (!BN_div(dv.get(), rem.get(), bn.get(), bnBase.get(), pctx))
                throw bignum_error("CBigNum::ToString() : BN_div failed");
            bn = dv;
            unsigned int c = rem.getulong();
            str += "0123456789abcdef"[c];
        }
        if (BN_is_negative(get()))
            str += "-";
        reverse(str.begin(), str.end());
        return str;
    }

    CBigNum pow(const CBigNum& e) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_exp(ret.get(), get(), e.get(), pctx))
            throw bignum_error("CBigNum::pow : BN_exp failed");
        return ret;
    }

    CBigNum mul_mod(const CBigNum& b, const CBigNum& m) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_mod_mul(ret.get(), get(), b.get(), m.get(), pctx))
            throw bignum_error("CBigNum::mul_mod : BN_mod_mul failed");
        return ret;
    }

    CBigNum pow_mod(const CBigNum& e, const CBigNum& m) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if( e < 0){
            // g^-e = (g^-1)^e
            CBigNum inv = this->inverse(m);
            CBigNum posE = e * -1;
            if (!BN_mod_exp(ret.get(), inv.get(), posE.get(), m.get(), pctx))
                throw bignum_error("CBigNum::pow_mod: BN_mod_exp failed on negative exponent");
        } else {
            if (!BN_mod_exp(ret.get(), get(), e.get(), m.get(), pctx))
                throw bignum_error("CBigNum::pow_mod : BN_mod_exp failed");
        }
        return ret;
    }

    CBigNum inverse(const CBigNum& m) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_mod_inverse(ret.get(), get(), m.get(), pctx))
            throw bignum_error("CBigNum::inverse : BN_mod_inverse failed");
        return ret;
    }    static CBigNum generatePrime(unsigned int numBits, bool safe) {
        CBigNum ret;
        if(!BN_generate_prime_ex(ret.get(), numBits, (safe == true), NULL, NULL, NULL))
            throw bignum_error("CBigNum::generatePrime : BN_generate_prime_ex failed");
        return ret;
    }

    CBigNum gcd(const CBigNum& b) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_gcd(ret.get(), get(), b.get(), pctx))
            throw bignum_error("CBigNum::gcd : BN_gcd failed");
        return ret;
    }

    bool isPrime(int checks=BN_prime_checks) const {
        CAutoBN_CTX pctx;
        #if OPENSSL_VERSION_NUMBER >= 0x30000000L
        // OpenSSL 3.0+ uses BN_check_prime
        int ret = BN_check_prime(get(), pctx, NULL);
        return (ret == 1);
        #else
        // Legacy OpenSSL
        int ret = BN_is_prime_ex(get(), checks, pctx, NULL);
        return (ret == 1);
        #endif
    }

    bool isOne() const {
        return BN_is_one(get());
    }

    bool operator!() const
    {
        return BN_is_zero(get());
    }

    CBigNum& operator+=(const CBigNum& b)
    {
        if (!BN_add(get(), get(), b.get()))
            throw bignum_error("CBigNum::operator+= : BN_add failed");
        return *this;
    }

    CBigNum& operator-=(const CBigNum& b)
    {
        if (!BN_sub(get(), get(), b.get()))
            throw bignum_error("CBigNum::operator-= : BN_sub failed");
        return *this;
    }

    CBigNum& operator*=(const CBigNum& b)
    {
        CAutoBN_CTX pctx;
        if (!BN_mul(get(), get(), b.get(), pctx))
            throw bignum_error("CBigNum::operator*= : BN_mul failed");
        return *this;
    }

    CBigNum& operator/=(const CBigNum& b)
    {
        CAutoBN_CTX pctx;
        if (!BN_div(get(), NULL, get(), b.get(), pctx))
            throw bignum_error("CBigNum::operator/= : BN_div failed");
        return *this;
    }

    CBigNum& operator%=(const CBigNum& b)
    {
        CAutoBN_CTX pctx;
        if (!BN_nnmod(get(), get(), b.get(), pctx))
            throw bignum_error("CBigNum::operator%= : BN_nnmod failed");
        return *this;
    }

    CBigNum& operator<<=(unsigned int shift)
    {
        if (!BN_lshift(get(), get(), shift))
            throw bignum_error("CBigNum::operator<<= : BN_lshift failed");
        return *this;
    }

    CBigNum& operator>>=(unsigned int shift)
    {
        // Note: BN_rshift segfaults on 64-bit if 2^shift is greater than the number
        //   if built on ubuntu 9.04 or 9.10, probably depends on version of OpenSSL
        CBigNum a = 1;
        a <<= shift;
        if (BN_cmp(a.get(), get()) > 0)
        {
            *this = 0;
            return *this;
        }

        if (!BN_rshift(get(), get(), shift))
            throw bignum_error("CBigNum::operator>>= : BN_rshift failed");
        return *this;
    }

    CBigNum& operator++()
    {
        // prefix operator
        if (!BN_add(get(), get(), BN_value_one()))
            throw bignum_error("CBigNum::operator++ : BN_add failed");
        return *this;
    }

    const CBigNum operator++(int)
    {
        // postfix operator
        const CBigNum ret = *this;
        ++(*this);
        return ret;
    }

    CBigNum& operator--()
    {
        // prefix operator
        CBigNum r;
        if (!BN_sub(r.get(), get(), BN_value_one()))
            throw bignum_error("CBigNum::operator-- : BN_sub failed");
        *this = r;
        return *this;
    }

    const CBigNum operator--(int)
    {
        // postfix operator
        const CBigNum ret = *this;
        --(*this);
        return ret;
    }    friend inline const CBigNum operator+(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator-(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator-(const CBigNum& a);
    friend inline const CBigNum operator*(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator/(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator%(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator<<(const CBigNum& a, unsigned int shift);
    friend inline bool operator==(const CBigNum& a, const CBigNum& b);
    friend inline bool operator!=(const CBigNum& a, const CBigNum& b);
    friend inline bool operator<=(const CBigNum& a, const CBigNum& b);
    friend inline bool operator>=(const CBigNum& a, const CBigNum& b);
    friend inline bool operator<(const CBigNum& a, const CBigNum& b);
    friend inline bool operator>(const CBigNum& a, const CBigNum& b);
};

inline const CBigNum operator+(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;
    if (!BN_add(r.get(), a.get(), b.get()))
        throw bignum_error("CBigNum::operator+ : BN_add failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;
    if (!BN_sub(r.get(), a.get(), b.get()))
        throw bignum_error("CBigNum::operator- : BN_sub failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a)
{
    CBigNum r(a);
    BN_set_negative(r.get(), !BN_is_negative(a.get()));
    return r;
}

inline const CBigNum operator*(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_mul(r.get(), a.get(), b.get(), pctx))
        throw bignum_error("CBigNum::operator* : BN_mul failed");
    return r;
}

inline const CBigNum operator/(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_div(r.get(), NULL, a.get(), b.get(), pctx))
        throw bignum_error("CBigNum::operator/ : BN_div failed");
    return r;
}

inline const CBigNum operator%(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_nnmod(r.get(), a.get(), b.get(), pctx))
        throw bignum_error("CBigNum::operator% : BN_nnmod failed");
    return r;
}

inline const CBigNum operator<<(const CBigNum& a, unsigned int shift)
{
    CBigNum r;
    if (!BN_lshift(r.get(), a.get(), shift))
        throw bignum_error("CBigNum::operator<< : BN_lshift failed");
    return r;
}

inline bool operator==(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(a.get(), b.get()) == 0); }
inline bool operator!=(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(a.get(), b.get()) != 0); }
inline bool operator<=(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(a.get(), b.get()) <= 0); }
inline bool operator>=(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(a.get(), b.get()) >= 0); }
inline bool operator<(const CBigNum& a, const CBigNum& b)   { return (BN_cmp(a.get(), b.get()) < 0); }
inline bool operator>(const CBigNum& a, const CBigNum& b)   { return (BN_cmp(a.get(), b.get()) > 0); }

inline std::ostream& operator<<(std::ostream &strm, const CBigNum &b)
{
    return strm << b.ToString();
}

typedef CBigNum Bignum;

#endif // BITCOIN_BIGNUM_H
