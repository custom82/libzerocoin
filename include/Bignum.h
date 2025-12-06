#ifndef BIGNUM_H
#define BIGNUM_H

#include <openssl/bn.h>
#include <string>

class CBigNum {
public:
    CBigNum() { BN_init(&num); }
    ~CBigNum() { BN_free(&num); }

    void setHex(const std::string& hexStr) {
        BN_hex2bn(&num, hexStr.c_str());
    }

    std::string getHex() const {
        char* hex = BN_bn2hex(&num);
        std::string result(hex);
        OPENSSL_free(hex);
        return result;
    }

    CBigNum operator-(const CBigNum& other) const {
        CBigNum result;
        BN_sub(&result.num, &this->num, &other.num);
        return result;
    }

    // Altri operatori possono essere aggiunti come necessario (es. +, *, /)

private:
    BIGNUM num; // OpenSSL BIGNUM type for large numbers
};

#endif // BIGNUM_H
