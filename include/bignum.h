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
    // Costruttori (solo quelli essenziali per ora)
    CBigNum();
    CBigNum(const CBigNum& b);
    CBigNum(int n);
    CBigNum(unsigned int n);
    CBigNum(long n);
    CBigNum(unsigned long n);
    CBigNum(long long n);
    CBigNum(unsigned long long n);
    CBigNum(const std::vector<unsigned char>& vch);
    ~CBigNum();

    // Operatori di assegnazione
    CBigNum& operator=(const CBigNum& b);

    // Operatori aritmetici (solo quelli essenziali)
    CBigNum operator+(const CBigNum& b) const;
    CBigNum operator-(const CBigNum& b) const;
    CBigNum operator*(const CBigNum& b) const;
    CBigNum operator/(const CBigNum& b) const;
    CBigNum operator%(const CBigNum& b) const;

    // Operatori composti (solo quelli essenziali)
    CBigNum& operator+=(const CBigNum& b);
    CBigNum& operator-=(const CBigNum& b);

    // Operatori di confronto
    bool operator==(const CBigNum& b) const;
    bool operator!=(const CBigNum& b) const;
    bool operator<(const CBigNum& b) const;
    bool operator<=(const CBigNum& b) const;
    bool operator>(const CBigNum& b) const;
    bool operator>=(const CBigNum& b) const;

    // Metodi di conversione (solo quelli essenziali)
    void setuint64(uint64_t n);
    void setint64(int64_t n);
    void setvch(const std::vector<unsigned char>& vch);
    std::vector<unsigned char> getvch() const;  // SOLO UNA VOLTA!
    void SetHex(const std::string& str);
    std::string GetHex() const;
    std::string ToString(int nBase=10) const;

    // Funzioni crittografiche (solo quelle essenziali)
    static CBigNum randBignum(const CBigNum& range);

    // Accesso alla struttura OpenSSL
    const BIGNUM* get_bn() const { return bn; }
    BIGNUM* mutable_bn() { return bn; }

    // Utility
    bool IsZero() const { return BN_is_zero(bn); }
    bool IsOne() const { return BN_is_one(bn); }
    int bitSize() const { return BN_num_bits(bn); }
};

#endif
