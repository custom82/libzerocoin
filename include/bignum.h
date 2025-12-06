#ifndef BIGNUM_H
#define BIGNUM_H

#include <openssl/bn.h>
#include <vector>
#include <string>
#include <cstdint>

namespace libzerocoin {

    class CBigNum {
    private:
        BIGNUM* bignum;

    public:
        // Constructors
        CBigNum();
        CBigNum(const CBigNum& b);
        explicit CBigNum(long long n);
        ~CBigNum();

        // Assignment
        CBigNum& operator=(const CBigNum& b);

        // Arithmetic operators
        CBigNum operator+(const CBigNum& b) const;
        CBigNum operator-(const CBigNum& b) const;
        CBigNum operator*(const CBigNum& b) const;
        CBigNum operator/(const CBigNum& b) const;
        CBigNum operator%(const CBigNum& b) const;

        // Comparison operators (as friend functions)
        friend bool operator==(const CBigNum& a, const CBigNum& b);
        friend bool operator!=(const CBigNum& a, const CBigNum& b);
        friend bool operator<=(const CBigNum& a, const CBigNum& b);
        friend bool operator>=(const CBigNum& a, const CBigNum& b);
        friend bool operator<(const CBigNum& a, const CBigNum& b);
        friend bool operator>(const CBigNum& a, const CBigNum& b);

        // Static methods
        static CBigNum generatePrime(const unsigned int numBits, bool safe = false);
        static CBigNum randBignum(const CBigNum& range);
        static CBigNum randKBitBignum(const uint32_t k);

        // Methods
        CBigNum sha256() const;
        void setvch(const std::vector<unsigned char>& vch);
        std::vector<unsigned char> getvch() const;

        // Utility
        std::string ToString(int nBase = 10) const;

        // Access to internal BIGNUM
        const BIGNUM* getBN() const { return bignum; }
        BIGNUM* getBN() { return bignum; }

        // Static context (optional, for performance)
        static BN_CTX* ctx;
    };

    // Comparison operators
    bool operator==(const CBigNum& a, const CBigNum& b);
    bool operator!=(const CBigNum& a, const CBigNum& b);
    bool operator<=(const CBigNum& a, const CBigNum& b);
    bool operator>=(const CBigNum& a, const CBigNum& b);
    bool operator<(const CBigNum& a, const CBigNum& b);
    bool operator>(const CBigNum& a, const CBigNum& b);

} // namespace libzerocoin

#endif // BIGNUM_H
