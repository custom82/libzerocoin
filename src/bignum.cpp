#include "bignum.h"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <algorithm>
#include <sstream>
#include <iomanip>

// Costruttore default
CBigNum::CBigNum() : bn(BN_new()) {
    BN_zero(bn);
}

// Costruttore di copia
CBigNum::CBigNum(const CBigNum& b) : bn(BN_new()) {
    if (!BN_copy(bn, b.bn)) {
        BN_free(bn);
        throw std::runtime_error("CBigNum copy constructor failed");
    }
}

// Costruttori da tipi interi
CBigNum::CBigNum(int n) : bn(BN_new()) {
    if (n >= 0) {
        BN_set_word(bn, n);
    } else {
        BN_set_word(bn, -n);
        BN_set_negative(bn, 1);
    }
}

CBigNum::CBigNum(unsigned int n) : bn(BN_new()) {
    BN_set_word(bn, n);
}

CBigNum::CBigNum(long n) : CBigNum(static_cast<int>(n)) {
}

CBigNum::CBigNum(unsigned long n) : CBigNum(static_cast<unsigned int>(n)) {
}

CBigNum::CBigNum(long long n) : bn(BN_new()) {
    if (n >= 0) {
        BN_set_word(bn, static_cast<unsigned long>(n & 0xFFFFFFFF));
        if (n > 0xFFFFFFFF) {
            BIGNUM* temp = BN_new();
            BN_set_word(temp, static_cast<unsigned long>(n >> 32));
            BN_lshift(temp, temp, 32);
            BN_add(bn, bn, temp);
            BN_free(temp);
        }
    } else {
        BN_set_word(bn, static_cast<unsigned long>(-n & 0xFFFFFFFF));
        if (-n > 0xFFFFFFFF) {
            BIGNUM* temp = BN_new();
            BN_set_word(temp, static_cast<unsigned long>((-n) >> 32));
            BN_lshift(temp, temp, 32);
            BN_add(bn, bn, temp);
            BN_free(temp);
        }
        BN_set_negative(bn, 1);
    }
}

CBigNum::CBigNum(unsigned long long n) : bn(BN_new()) {
    BN_set_word(bn, static_cast<unsigned long>(n & 0xFFFFFFFF));
    if (n > 0xFFFFFFFF) {
        BIGNUM* temp = BN_new();
        BN_set_word(temp, static_cast<unsigned long>(n >> 32));
        BN_lshift(temp, temp, 32);
        BN_add(bn, bn, temp);
        BN_free(temp);
    }
}

// Costruttore da vettore di byte
CBigNum::CBigNum(const std::vector<unsigned char>& vch) : bn(BN_new()) {
    BN_bin2bn(vch.data(), vch.size(), bn);
}

// Distruttore
CBigNum::~CBigNum() {
    if (bn) {
        BN_free(bn);
    }
}

// Operatore di assegnazione
CBigNum& CBigNum::operator=(const CBigNum& b) {
    if (this != &b) {
        if (!BN_copy(bn, b.bn)) {
            throw std::runtime_error("CBigNum assignment operator failed");
        }
    }
    return *this;
}

// Operatori aritmetici
CBigNum CBigNum::operator+(const CBigNum& b) const {
    CBigNum result;
    if (!BN_add(result.bn, bn, b.bn)) {
        throw std::runtime_error("CBigNum addition failed");
    }
    return result;
}

CBigNum CBigNum::operator-(const CBigNum& b) const {
    CBigNum result;
    if (!BN_sub(result.bn, bn, b.bn)) {
        throw std::runtime_error("CBigNum subtraction failed");
    }
    return result;
}

CBigNum CBigNum::operator*(const CBigNum& b) const {
    CBigNum result;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");

    if (!BN_mul(result.bn, bn, b.bn, ctx)) {
        BN_CTX_free(ctx);
        throw std::runtime_error("CBigNum multiplication failed");
    }

    BN_CTX_free(ctx);
    return result;
}

CBigNum CBigNum::operator/(const CBigNum& b) const {
    CBigNum result;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");

    if (!BN_div(result.bn, nullptr, bn, b.bn, ctx)) {
        BN_CTX_free(ctx);
        throw std::runtime_error("CBigNum division failed");
    }

    BN_CTX_free(ctx);
    return result;
}

CBigNum CBigNum::operator%(const CBigNum& b) const {
    CBigNum result;
    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) throw std::runtime_error("BN_CTX_new failed");

    if (!BN_mod(result.bn, bn, b.bn, ctx)) {
        BN_CTX_free(ctx);
        throw std::runtime_error("CBigNum modulus failed");
    }

    BN_CTX_free(ctx);
    return result;
}

// Operatori composti
CBigNum& CBigNum::operator+=(const CBigNum& b) {
    if (!BN_add(bn, bn, b.bn)) {
        throw std::runtime_error("CBigNum += failed");
    }
    return *this;
}

CBigNum& CBigNum::operator-=(const CBigNum& b) {
    if (!BN_sub(bn, bn, b.bn)) {
        throw std::runtime_error("CBigNum -= failed");
    }
    return *this;
}

// Operatori di confronto
bool CBigNum::operator==(const CBigNum& b) const {
    return BN_cmp(bn, b.bn) == 0;
}

bool CBigNum::operator!=(const CBigNum& b) const {
    return BN_cmp(bn, b.bn) != 0;
}

bool CBigNum::operator<(const CBigNum& b) const {
    return BN_cmp(bn, b.bn) < 0;
}

bool CBigNum::operator<=(const CBigNum& b) const {
    return BN_cmp(bn, b.bn) <= 0;
}

bool CBigNum::operator>(const CBigNum& b) const {
    return BN_cmp(bn, b.bn) > 0;
}

bool CBigNum::operator>=(const CBigNum& b) const {
    return BN_cmp(bn, b.bn) >= 0;
}

// Metodi di conversione
void CBigNum::setuint64(uint64_t n) {
    BN_set_word(bn, static_cast<unsigned long>(n & 0xFFFFFFFF));
    if (n > 0xFFFFFFFF) {
        BIGNUM* temp = BN_new();
        BN_set_word(temp, static_cast<unsigned long>(n >> 32));
        BN_lshift(temp, temp, 32);
        BN_add(bn, bn, temp);
        BN_free(temp);
    }
}

void CBigNum::setint64(int64_t n) {
    if (n >= 0) {
        setuint64(static_cast<uint64_t>(n));
    } else {
        setuint64(static_cast<uint64_t>(-n));
        BN_set_negative(bn, 1);
    }
}

void CBigNum::setvch(const std::vector<unsigned char>& vch) {
    BN_bin2bn(vch.data(), vch.size(), bn);
}

std::vector<unsigned char> CBigNum::getvch() const {
    int size = BN_num_bytes(bn);
    std::vector<unsigned char> result(size);
    BN_bn2bin(bn, result.data());
    return result;
}

void CBigNum::SetHex(const std::string& str) {
    if (BN_hex2bn(&bn, str.c_str()) == 0) {
        throw std::runtime_error("CBigNum SetHex failed");
    }
}

std::string CBigNum::GetHex() const {
    char* hex = BN_bn2hex(bn);
    if (!hex) {
        throw std::runtime_error("CBigNum GetHex failed");
    }
    std::string result(hex);
    OPENSSL_free(hex);
    return result;
}

std::string CBigNum::ToString(int nBase) const {
    if (nBase == 16) {
        return GetHex();
    } else if (nBase == 10) {
        char* dec = BN_bn2dec(bn);
        if (!dec) {
            throw std::runtime_error("CBigNum ToString failed");
        }
        std::string result(dec);
        OPENSSL_free(dec);
        return result;
    } else {
        throw std::runtime_error("CBigNum: unsupported base");
    }
}

// Funzioni crittografiche
CBigNum CBigNum::randBignum(const CBigNum& range) {
    CBigNum result;
    if (!BN_rand_range(result.bn, range.bn)) {
        throw std::runtime_error("CBigNum randBignum failed");
    }
    return result;
}

// Funzioni globali (se necessario)
bool operator==(uint64_t a, const CBigNum& b) {
    CBigNum temp;
    temp.setuint64(a);
    return temp == b;
}

bool operator!=(uint64_t a, const CBigNum& b) {
    return !(a == b);
}

bool operator<(uint64_t a, const CBigNum& b) {
    CBigNum temp;
    temp.setuint64(a);
    return temp < b;
}

bool operator<=(uint64_t a, const CBigNum& b) {
    CBigNum temp;
    temp.setuint64(a);
    return temp <= b;
}

bool operator>(uint64_t a, const CBigNum& b) {
    CBigNum temp;
    temp.setuint64(a);
    return temp > b;
}

bool operator>=(uint64_t a, const CBigNum& b) {
    CBigNum temp;
    temp.setuint64(a);
    return temp >= b;
}
