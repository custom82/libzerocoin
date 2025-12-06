#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include <vector>
#include <string>
#include <stdint.h>
#include <stdexcept>
#include <openssl/bn.h>

#include "uint256.h"

// RAII wrapper per BN_CTX
class CAutoBN_CTX {
private:
    BN_CTX* ctx;

public:
    CAutoBN_CTX()
    {
        ctx = BN_CTX_new();
        if (!ctx)
            throw std::runtime_error("BN_CTX_new failed");
    }

    ~CAutoBN_CTX()
    {
        if (ctx)
            BN_CTX_free(ctx);
    }

    operator BN_CTX*() { return ctx; }
    operator BN_CTX*() const { return ctx; }
};

class CBigNum
{
private:
    BIGNUM* bn;

public:
    CBigNum();
    CBigNum(const CBigNum& b);
    CBigNum(int64_t n);
    CBigNum(const uint256& n);

    ~CBigNum();

    CBigNum& operator=(const CBigNum& b);

    operator BIGNUM*() { return bn; }
    operator const BIGNUM*() const { return bn; }
    BIGNUM* get() { return bn; }
    const BIGNUM* get() const { return bn; }

    std::string ToString(int base = 10) const;
    void SetHex(const std::string& hex);
    std::vector<unsigned char> getvch() const;
    void setvch(const std::vector<unsigned char>& v);

    void setuint64(uint64_t n);
    void setint64(int64_t n);
    void setuint256(const uint256& n);
    uint256 getuint256() const;

    CBigNum operator-() const;
    CBigNum& operator+=(const CBigNum& b);
    CBigNum& operator-=(const CBigNum& b);
    CBigNum& operator*=(const CBigNum& b);
    CBigNum& operator/=(const CBigNum& b);
    CBigNum& operator%=(const CBigNum& b);
    CBigNum& operator<<=(unsigned int shift);
    CBigNum& operator>>=(unsigned int shift);

    CBigNum pow_mod(const CBigNum& e, const CBigNum& m) const;
    CBigNum mul_mod(const CBigNum& b, const CBigNum& m) const;
    CBigNum add_mod(const CBigNum& b, const CBigNum& m) const;
    CBigNum sub_mod(const CBigNum& b, const CBigNum& m) const;
    CBigNum inverse(const CBigNum& m) const;

    static CBigNum generatePrime(uint32_t bits, bool safe = false);
    bool isPrime(int checks = 0, BN_GENCB* cb = nullptr) const;

    CBigNum gcd(const CBigNum& b) const;
    CBigNum sqrt_mod(const CBigNum& p) const;

    // ===== Zerocoin compatibility extensions =====

    // random Bignum modulo max
    static CBigNum randBignum(const CBigNum& max)
    {
        BN_CTX* ctx = BN_CTX_new();
        CBigNum r;
        BN_rand_range(r.bn, max.bn);
        BN_CTX_free(ctx);
        return r;
    }

    // bit size accessor
    int bitSize() const
    {
        return BN_num_bits(bn);
    }

    // slow exponentiation (sufficiente per p da ParamGeneration)
    CBigNum pow(unsigned int exp) const
    {
        CBigNum base = *this;
        CBigNum r(1);

        BN_CTX* ctx = BN_CTX_new();
        for (unsigned int i = 0; i < exp; i++) {
            BN_mul(r.bn, r.bn, base.bn, ctx);
        }
        BN_CTX_free(ctx);
        return r;
    }

    // multiplication operator
    CBigNum operator*(const CBigNum& other) const
    {
        CBigNum r;
        BN_CTX* ctx = BN_CTX_new();
        BN_mul(r.bn, bn, other.bn, ctx);
        BN_CTX_free(ctx);
        return r;
    }
};

#endif // BITCOIN_BIGNUM_H
