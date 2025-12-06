// bitcoin_bignum/bignum.h - VERSIONE CORRETTA
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

class bignum_error : public std::runtime_error {
public:
    explicit bignum_error(const std::string& str) : std::runtime_error(str) {}
};

class CAutoBN_CTX {
protected:
    BN_CTX* pctx;
public:
    CAutoBN_CTX() {
        pctx = BN_CTX_new();
        if (!pctx) throw bignum_error("CAutoBN_CTX: BN_CTX_new failed");
    }
    ~CAutoBN_CTX() { if (pctx) BN_CTX_free(pctx); }
    operator BN_CTX*() { return pctx; }
};

class CBigNum {
private:
    BIGNUM* bn;

public:
    CBigNum() : bn(BN_new()) {
        if (!bn) throw bignum_error("CBigNum: BN_new failed");
        BN_zero(bn);
    }

    CBigNum(const CBigNum& b) : bn(BN_new()) {
        if (!bn) throw bignum_error("CBigNum copy: BN_new failed");
        if (!BN_copy(bn, b.bn)) {
            BN_free(bn);
            throw bignum_error("CBigNum copy: BN_copy failed");
        }
    }

    ~CBigNum() { if (bn) BN_free(bn); }

    // Costruttori semplici
    CBigNum(int n) : bn(BN_new()) { BN_set_word(bn, n); }
    CBigNum(unsigned int n) : bn(BN_new()) { BN_set_word(bn, n); }
    CBigNum(int64 n) : bn(BN_new()) {
        if (n >= 0) {
            BN_set_word(bn, static_cast<unsigned long>(n));
        } else {
            BN_set_word(bn, static_cast<unsigned long>(-n));
            BN_set_negative(bn, 1);
        }
    }

    // Operatori base
    CBigNum& operator=(const CBigNum& b) {
        if (this != &b) {
            if (!BN_copy(bn, b.bn))
                throw bignum_error("CBigNum assignment: BN_copy failed");
        }
        return *this;
    }

    bool operator==(const CBigNum& b) const { return BN_cmp(bn, b.bn) == 0; }
    bool operator!=(const CBigNum& b) const { return !(*this == b); }
    bool operator<(const CBigNum& b) const { return BN_cmp(bn, b.bn) < 0; }
    bool operator<=(const CBigNum& b) const { return BN_cmp(bn, b.bn) <= 0; }

    // Metodi essenziali
    std::string ToString(int base = 10) const {
        if (base == 10) {
            char* dec = BN_bn2dec(bn);
            std::string s(dec);
            OPENSSL_free(dec);
            return s;
        } else if (base == 16) {
            char* hex = BN_bn2hex(bn);
            std::string s(hex);
            OPENSSL_free(hex);
            return s;
        }
        throw bignum_error("Unsupported base");
    }

    void SetHex(const std::string& hex) {
        if (!BN_hex2bn(&bn, hex.c_str()))
            throw bignum_error("CBigNum::SetHex failed");
    }

    std::vector<unsigned char> getvch() const {
        std::vector<unsigned char> v(BN_num_bytes(bn));
        BN_bn2bin(bn, v.data());
        return v;
    }

    void setvch(const std::vector<unsigned char>& v) {
        BN_bin2bn(v.data(), v.size(), bn);
    }

    // Conversioni
    operator BIGNUM*() { return bn; }
    operator const BIGNUM*() const { return bn; }
    BIGNUM* get() { return bn; }
    const BIGNUM* get() const { return bn; }

    // Metodi statici
    static CBigNum randBignum(const CBigNum& range) {
        CBigNum result;
        if (!BN_rand_range(result.bn, range.bn))
            throw bignum_error("randBignum failed");
        return result;
    }
};

// Operatori inline
inline CBigNum operator+(const CBigNum& a, const CBigNum& b) {
    CBigNum r;
    if (!BN_add(r.get(), a.get(), b.get()))
        throw bignum_error("operator+ failed");
    return r;
}

inline CBigNum operator-(const CBigNum& a, const CBigNum& b) {
    CBigNum r;
    if (!BN_sub(r.get(), a.get(), b.get()))
        throw bignum_error("operator- failed");
    return r;
}

#endif // BITCOIN_BIGNUM_H
