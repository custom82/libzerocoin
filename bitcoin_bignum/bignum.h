// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#if defined(HAVE_CONFIG_H)
#include "bitcoin-config.h"
#endif

#include <stdexcept>
#include <vector>
#include <openssl/bn.h>
#include <openssl/opensslv.h>
#include <memory>
#include <cstring>
#include <string>
#include <sstream>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OPENSSL_VERSION_PRE_1_1
#endif

class bignum_error : public std::runtime_error
{
public:
    explicit bignum_error(const std::string& str) : std::runtime_error(str) {}
};

class uint256;

/** C++ wrapper for BIGNUM (OpenSSL bignum) */
class CBigNum
{
private:
    BIGNUM* bn;

public:
    CBigNum()
    {
        bn = BN_new();
        if (!bn)
            throw bignum_error("CBigNum::CBigNum() : BN_new failed");
        BN_zero(bn);
    }

    CBigNum(const CBigNum& b)
    {
        bn = BN_new();
        if (!bn)
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
        return (*this);
    }

    ~CBigNum()
    {
        if (bn)
            BN_free(bn);
    }

    // CBigNum(signed char n) is not portable. Use 'signed char' or 'unsigned char'.
    CBigNum(signed char n)      { bn = BN_new(); if (bn) { if (n >= 0) setulong(n); else setint64(n); } }
    CBigNum(short n)            { bn = BN_new(); if (bn) { if (n >= 0) setulong(n); else setint64(n); } }
    CBigNum(int n)              { bn = BN_new(); if (bn) { if (n >= 0) setulong(n); else setint64(n); } }
    CBigNum(long n)             { bn = BN_new(); if (bn) { if (n >= 0) setulong(n); else setint64(n); } }
    CBigNum(int64 n)            { bn = BN_new(); if (bn) setint64(n); }
    CBigNum(unsigned char n)    { bn = BN_new(); if (bn) setulong(n); }
    CBigNum(unsigned short n)   { bn = BN_new(); if (bn) setulong(n); }
    CBigNum(unsigned int n)     { bn = BN_new(); if (bn) setulong(n); }
    CBigNum(unsigned long n)    { bn = BN_new(); if (bn) setulong(n); }
    CBigNum(uint64 n)           { bn = BN_new(); if (bn) setuint64(n); }
    explicit CBigNum(uint256 n) { bn = BN_new(); if (bn) setuint256(n); }

    explicit CBigNum(const std::vector<unsigned char>& vch)
    {
        bn = BN_new();
        if (bn)
            setvch(vch);
    }

    static CBigNum  randBignum(const CBigNum& range) {
        CBigNum ret;
        if(!BN_rand_range(ret.bn, range.bn)){
            throw bignum_error("CBigNum:rand element : BN_rand_range failed");
        }
        return ret;
    }

    static CBigNum RandKBitBigum(uint32_t k){
        CBigNum ret;
        if(!BN_rand(ret.bn, k, -1, 0)){
            throw bignum_error("CBigNum:rand element : BN_rand failed");
        }
        return ret;
    }

    int bitSize() const{
        return  BN_num_bits(bn);
    }

    void setulong(unsigned long n)
    {
        if (!BN_set_word(bn, n))
            throw bignum_error("CBigNum conversion from unsigned long : BN_set_word failed");
    }

    unsigned long getulong() const
    {
        return BN_get_word(bn);
    }

    unsigned int getuint() const
    {
        return BN_get_word(bn);
    }

    int getint() const
    {
        unsigned long n = BN_get_word(bn);
        if (!BN_is_negative(bn))
            return (n > (unsigned long)std::numeric_limits<int>::max() ? std::numeric_limits<int>::max() : n);
        else
            return (n > (unsigned long)std::numeric_limits<int>::max() ? std::numeric_limits<int>::min() : -(int)n);
    }

    void setint64(int64 sn)
    {
        unsigned char pch[sizeof(sn) + 6];
        unsigned char* p = pch + 4;
        bool fNegative;
        uint64 n;

        if (sn < (int64)0)
        {
            n = -sn;
            fNegative = true;
        }
        else
        {
            n = sn;
            fNegative = false;
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
        BN_mpi2bn(pch, p - pch, bn);
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
        BN_mpi2bn(pch, p - pch, bn);
    }

    void setuint256(uint256 n)
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
        BN_mpi2bn(pch, p - pch, bn);
    }

    uint256 getuint256() const
    {
        unsigned int nSize = BN_bn2mpi(bn, NULL);
        if (nSize < 4)
            return 0;
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(bn, &vch[0]);
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
        vch2[0] = (nSize >> 24) & 0xff;
        vch2[1] = (nSize >> 16) & 0xff;
        vch2[2] = (nSize >> 8) & 0xff;
        vch2[3] = (nSize >> 0) & 0xff;
        reverse_copy(vch.begin(), vch.end(), vch2.begin() + 4);
        BN_mpi2bn(&vch2[0], vch2.size(), bn);
    }

    std::vector<unsigned char> getvch() const
    {
        unsigned int nSize = BN_bn2mpi(bn, NULL);
        if (nSize <= 4)
            return std::vector<unsigned char>();
        std::vector<unsigned char> vch(nSize);
        BN_bn2mpi(bn, &vch[0]);
        vch.erase(vch.begin(), vch.begin() + 4);
        reverse(vch.begin(), vch.end());
        return vch;
    }

    CBigNum& SetCompact(unsigned int nCompact)
    {
        unsigned int nSize = nCompact >> 24;
        std::vector<unsigned char> vch(4 + nSize);
        vch[3] = nSize;
        if (nSize >= 1) vch[4] = (nCompact >> 16) & 0xff;
        if (nSize >= 2) vch[5] = (nCompact >> 8) & 0xff;
        if (nSize >= 3) vch[6] = (nCompact >> 0) & 0xff;
        BN_mpi2bn(&vch[0], vch.size(), bn);
        return *this;
    }

    unsigned int GetCompact() const
    {
        unsigned int nSize = BN_bn2mpi(bn, NULL);
        std::vector<unsigned char> vch(nSize);
        nSize -= 4;
        BN_bn2mpi(bn, &vch[0]);
        unsigned int nCompact = nSize << 24;
        if (nSize >= 1) nCompact |= (vch[4] << 16);
        if (nSize >= 2) nCompact |= (vch[5] << 8);
        if (nSize >= 3) nCompact |= (vch[6] << 0);
        return nCompact;
    }

    void SetHex(const std::string& str)
    {
        const char* psz = str.c_str();
        bool fNegative = false;
        while (isspace(*psz))
            psz++;
        if (*psz == '-')
        {
            fNegative = true;
            psz++;
        }
        if (psz[0] == '0' && tolower(psz[1]) == 'x')
            psz += 2;
        while (isspace(*psz))
            psz++;

        static const signed char phexdigit[256] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0xa,0xb,0xc,0xd,0xe,0xf,0,0,0,0,0,0,0,0,0 };
        *this = 0;
        while (isxdigit(*psz))
        {
            *this = (*this << 4) | phexdigit[(unsigned char)*psz];
            psz++;
        }
        if (fNegative)
            *this = 0 - *this;
    }

    std::string ToString(int nBase=10) const
    {
        CAutoBN_CTX pctx;
        CBigNum bn0 = 0;
        std::string str;
        CBigNum bn = *this;
        BN_set_negative(bn.bn, false);
        CBigNum dv;
        CBigNum rem;
        if (BN_cmp(bn.bn, bn0.bn) == 0)
            return "0";
        while (BN_cmp(bn.bn, bn0.bn) > 0)
        {
            if (!BN_div(dv.bn, rem.bn, bn.bn, bnBase.bn, pctx))
                throw bignum_error("CBigNum::ToString() : BN_div failed");
            bn = dv;
            unsigned int c = rem.getulong();
            str += "0123456789abcdef"[c];
        }
        if (BN_is_negative(bn.bn))
            str += "-";
        reverse(str.begin(), str.end());
        return str;
    }

    std::string GetHex() const
    {
        return ToString(16);
    }

    std::string ToString() const
    {
        return ToString(10);
    }

    bool operator!() const
    {
        return BN_is_zero(bn);
    }

    CBigNum& operator+=(const CBigNum& b)
    {
        if (!BN_add(bn, bn, b.bn))
            throw bignum_error("CBigNum::operator+= : BN_add failed");
        return *this;
    }

    CBigNum& operator-=(const CBigNum& b)
    {
        *this = *this - b;
        return *this;
    }

    CBigNum& operator*=(const CBigNum& b)
    {
        CAutoBN_CTX pctx;
        if (!BN_mul(bn, bn, b.bn, pctx))
            throw bignum_error("CBigNum::operator*= : BN_mul failed");
        return *this;
    }

    CBigNum& operator/=(const CBigNum& b)
    {
        *this = *this / b;
        return *this;
    }

    CBigNum& operator%=(const CBigNum& b)
    {
        *this = *this % b;
        return *this;
    }

    CBigNum& operator<<=(unsigned int shift)
    {
        if (!BN_lshift(bn, bn, shift))
            throw bignum_error("CBigNum::operator<<= : BN_lshift failed");
        return *this;
    }

    CBigNum& operator>>=(unsigned int shift)
    {
        CBigNum a = 1;
        a <<= shift;
        if (BN_cmp(a.bn, bn.bn) > 0)
        {
            *this = 0;
            return *this;
        }

        if (!BN_rshift(bn, bn, shift))
            throw bignum_error("CBigNum::operator>>= : BN_rshift failed");
        return *this;
    }

    CBigNum& operator++()
    {
        if (!BN_add(bn, bn, BN_value_one()))
            throw bignum_error("CBigNum::operator++ : BN_add failed");
        return *this;
    }

    const CBigNum operator++(int)
    {
        const CBigNum ret = *this;
        ++(*this);
        return ret;
    }

    CBigNum& operator--()
    {
        CBigNum r;
        if (!BN_sub(r.bn, bn, BN_value_one()))
            throw bignum_error("CBigNum::operator-- : BN_sub failed");
        *this = r;
        return *this;
    }

    const CBigNum operator--(int)
    {
        const CBigNum ret = *this;
        --(*this);
        return ret;
    }

    friend inline const CBigNum operator-(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator/(const CBigNum& a, const CBigNum& b);
    friend inline const CBigNum operator%(const CBigNum& a, const CBigNum& b);

    CBigNum pow(const CBigNum& e) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_exp(ret.bn, bn, e.bn, pctx))
            throw bignum_error("CBigNum::pow : BN_exp failed");
        return ret;
    }

    CBigNum mul_mod(const CBigNum& b, const CBigNum& m) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_mod_mul(ret.bn, bn, b.bn, m.bn, pctx))
            throw bignum_error("CBigNum::mul_mod : BN_mod_mul failed");
        return ret;
    }

    CBigNum pow_mod(const CBigNum& e, const CBigNum& m) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (BN_cmp(e.bn, BN_value_one()) <= 0)
        {
            if (BN_is_negative(e.bn))
            {
                CBigNum inv = this->inverse(m);
                CBigNum posE = e * -1;
                if (!BN_mod_exp(ret.bn, inv.bn, posE.bn, m.bn, pctx))
                    throw bignum_error("CBigNum::pow_mod: BN_mod_exp failed for negative exponent");
            }
            else
            {
                if (!BN_mod_exp(ret.bn, bn, e.bn, m.bn, pctx))
                    throw bignum_error("CBigNum::pow_mod : BN_mod_exp failed");
            }
        }
        return ret;
    }

    CBigNum inverse(const CBigNum& m) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_mod_inverse(ret.bn, bn, m.bn, pctx))
            throw bignum_error("CBigNum::inverse : BN_mod_inverse failed");
        return ret;
    }

    static CBigNum generatePrime(unsigned int numBits, bool safe = false) {
        CBigNum ret;
        if(!BN_generate_prime_ex(ret.bn, numBits, (safe == true), NULL, NULL, NULL))
            throw bignum_error("CBigNum::generatePrime : BN_generate_prime_ex failed");
        return ret;
    }

    CBigNum gcd(const CBigNum& b) const {
        CAutoBN_CTX pctx;
        CBigNum ret;
        if (!BN_gcd(ret.bn, bn, b.bn, pctx))
            throw bignum_error("CBigNum::gcd : BN_gcd failed");
        return ret;
    }

    bool isPrime(int checks=BN_prime_checks) const {
        CAutoBN_CTX pctx;
        int ret = BN_is_prime_ex(bn, checks, pctx, NULL);
        if(ret < 0)
            throw bignum_error("CBigNum::isPrime : BN_is_prime failed");
        return ret;
    }

    bool isOne() const {
        return BN_is_one(bn);
    }

    bool operator!() const
    {
        return BN_is_zero(bn);
    }

    // Cast to basic types
    int64_t GetInt64() const {
        return static_cast<int64_t>(getuint64());
    }

    uint64_t GetUint64() const {
        uint64_t n = 0;
        const std::vector<unsigned char> vch = getvch();
        for (size_t i = 0; i < vch.size() && i < sizeof(n); i++) {
            n |= static_cast<uint64_t>(vch[i]) << (8 * i);
        }
        return n;
    }

private:
    static CBigNum bnBase;
    static CBigNum bn0;
};

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
            throw bignum_error("CAutoBN_CTX : BN_CTX_new failed");
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

inline const CBigNum operator+(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;
    if (!BN_add(r.bn, a.bn, b.bn))
        throw bignum_error("CBigNum::operator+ : BN_add failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a, const CBigNum& b)
{
    CBigNum r;
    if (!BN_sub(r.bn, a.bn, b.bn))
        throw bignum_error("CBigNum::operator- : BN_sub failed");
    return r;
}

inline const CBigNum operator-(const CBigNum& a)
{
    CBigNum r(a);
    BN_set_negative(r.bn, !BN_is_negative(r.bn));
    return r;
}

inline const CBigNum operator*(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_mul(r.bn, a.bn, b.bn, pctx))
        throw bignum_error("CBigNum::operator* : BN_mul failed");
    return r;
}

inline const CBigNum operator/(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_div(r.bn, NULL, a.bn, b.bn, pctx))
        throw bignum_error("CBigNum::operator/ : BN_div failed");
    return r;
}

inline const CBigNum operator%(const CBigNum& a, const CBigNum& b)
{
    CAutoBN_CTX pctx;
    CBigNum r;
    if (!BN_nnmod(r.bn, a.bn, b.bn, pctx))
        throw bignum_error("CBigNum::operator% : BN_nnmod failed");
    return r;
}

inline const CBigNum operator<<(const CBigNum& a, unsigned int shift)
{
    CBigNum r;
    if (!BN_lshift(r.bn, a.bn, shift))
        throw bignum_error("CBigNum::operator<< : BN_lshift failed");
    return r;
}

inline const CBigNum operator>>(const CBigNum& a, unsigned int shift)
{
    CBigNum r = a;
    r >>= shift;
    return r;
}

inline bool operator==(const CBigNum& a, const CBigNum& b) { return (BN_cmp(a.bn, b.bn) == 0); }
inline bool operator!=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(a.bn, b.bn) != 0); }
inline bool operator<=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(a.bn, b.bn) <= 0); }
inline bool operator>=(const CBigNum& a, const CBigNum& b) { return (BN_cmp(a.bn, b.bn) >= 0); }
inline bool operator<(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(a.bn, b.bn) < 0); }
inline bool operator>(const CBigNum& a, const CBigNum& b)  { return (BN_cmp(a.bn, b.bn) > 0); }

#endif // BITCOIN_BIGNUM_H
