#ifndef BIGNUM_H
#define BIGNUM_H

#include <openssl/bn.h>
#include <vector>
#include <string>
#include <cstdint>

class CBigNum {
private:
    BIGNUM* bn;

public:
    // Costruttori
    CBigNum();
    CBigNum(const CBigNum& b);
    CBigNum(signed char n);
    CBigNum(short n);
    CBigNum(int n);
    CBigNum(long n);
    CBigNum(long long n);
    CBigNum(unsigned char n);
    CBigNum(unsigned short n);
    CBigNum(unsigned int n);
    CBigNum(unsigned long n);
    CBigNum(unsigned long long n);
    CBigNum(const std::vector<unsigned char>& vch);
    ~CBigNum();

    // Operatori di assegnazione
    CBigNum& operator=(const CBigNum& b);

    // Operatori aritmetici
    CBigNum operator+(const CBigNum& b) const;
    CBigNum operator-(const CBigNum& b) const;
    CBigNum operator*(const CBigNum& b) const;
    CBigNum operator/(const CBigNum& b) const;
    CBigNum operator%(const CBigNum& b) const;
    CBigNum operator-() const;

    // Operatori composti
    CBigNum& operator+=(const CBigNum& b);
    CBigNum& operator-=(const CBigNum& b);
    CBigNum& operator*=(const CBigNum& b);
    CBigNum& operator/=(const CBigNum& b);
    CBigNum& operator%=(const CBigNum& b);
    CBigNum& operator<<=(unsigned int shift);
    CBigNum& operator>>=(unsigned int shift);

    // Operatori di confronto
    bool operator==(const CBigNum& b) const;
    bool operator!=(const CBigNum& b) const;
    bool operator<=(const CBigNum& b) const;
    bool operator>=(const CBigNum& b) const;
    bool operator<(const CBigNum& b) const;
    bool operator>(const CBigNum& b) const;

    // Operatori bitwise
    CBigNum operator<<(unsigned int shift) const;
    CBigNum operator>>(unsigned int shift) const;

    // Metodi di conversione
    void setuint64(uint64_t n);
    void setint64(int64_t n);
    void setvch(const std::vector<unsigned char>& vch);
    std::vector<unsigned char> getvch() const;
    void SetHex(const std::string& str);
    std::string GetHex() const;
    std::string ToString(int nBase=10) const;

    // Funzioni crittografiche
    static CBigNum randBignum(const CBigNum& range);
    static CBigNum generatePrime(unsigned int bits, bool safe=false);
    CBigNum pow_mod(const CBigNum& e, const CBigNum& m) const;
    CBigNum mul_mod(const CBigNum& b, const CBigNum& m) const;
    CBigNum add_mod(const CBigNum& b, const CBigNum& m) const;
    CBigNum sub_mod(const CBigNum& b, const CBigNum& m) const;
    CBigNum inverse(const CBigNum& m) const;
    CBigNum gcd(const CBigNum& b) const;
    CBigNum sqrt_mod(const CBigNum& p) const;

    // Test primalità
    bool isPrime(int checks=20) const;

    // Accesso alla struttura OpenSSL
    const BIGNUM* get_bn() const { return bn; }
    BIGNUM* mutable_bn() { return bn; }

    // Utility
    bool IsZero() const { return BN_is_zero(bn); }
    bool IsOne() const { return BN_is_one(bn); }
    bool IsNegative() const { return BN_is_negative(bn); }
    int bitSize() const { return BN_num_bits(bn); }
    int byteSize() const { return (bitSize() + 7) / 8; }
};

// Funzioni globali
bool operator==(uint64_t a, const CBigNum& b);
bool operator!=(uint64_t a, const CBigNum& b);
bool operator<=(uint64_t a, const CBigNum& b);
bool operator>=(uint64_t a, const CBigNum& b);
bool operator<(uint64_t a, const CBigNum& b);
bool operator>(uint64_t a, const CBigNum& b);

#endif
