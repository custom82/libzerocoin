#ifndef BITCOIN_BIGNUM_H
#define BITCOIN_BIGNUM_H

#include <vector>
#include <string>
#include <stdint.h>
#include <stdexcept>
#include <openssl/bn.h>

#include "uint256.h"

// RAII wrapper BN_CTX per evitare leak
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
};

#endif // BITCOIN_BIGNUM_H
